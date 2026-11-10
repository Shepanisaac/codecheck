"""JavaScript frontend: a tree-sitter parse tree walked with the same taint model as the
Python analyzer (TAINT / DYN / RAW flags, per-scope environment, branch merging).

Requires the optional packages `tree-sitter` and `tree-sitter-javascript`.
Covers Node/Express and browser code, including JSX.
"""
from __future__ import annotations

from .core import (DYN, PROP, RAW, SAFE, TAINT, BaseAnalyzer, Finding, MissingDependency,
                   is_placeholder, join, looks_like_secret_name, merge_env)

_PARSER = None


def _parser():
    global _PARSER
    if _PARSER is None:
        try:
            import tree_sitter_javascript as tsj
            from tree_sitter import Language, Parser
        except ImportError as e:  # pragma: no cover - depends on environment
            raise MissingDependency(
                "JavaScript support needs: pip install tree-sitter tree-sitter-javascript") from e
        _PARSER = Parser(Language(tsj.language()))
    return _PARSER


# --------------------------------------------------------------------- catalogue
SOURCE_PATHS = {"process.argv", "location.search", "location.hash", "location.href",
                "location.pathname", "document.location", "document.URL",
                "document.cookie", "document.referrer", "window.name"}
SOURCE_CALLS = {"prompt", "window.prompt"}

SANITIZERS = {
    "parseInt", "parseFloat", "Number", "Boolean", "isNaN", "isFinite",
    "encodeURIComponent", "encodeURI", "escape", "path.basename",
    "validator.escape", "escapeHtml", "escape-html", "he.encode", "he.escape",
    "DOMPurify.sanitize", "dompurify.sanitize", "sanitizeHtml", "sanitize-html", "xss",
    "sqlstring.escape", "mysql.escape", "shell-escape", "shellescape", "lodash.escape",
}
BOOL_METHODS = {"test", "includes", "startsWith", "endsWith", "has", "isArray", "indexOf",
                "charCodeAt", "hasOwnProperty"}

SQL_METHODS = {"query", "execute", "raw", "queryRawUnsafe", "executeRawUnsafe"}
EXEC_FUNCS = {"child_process.exec", "child_process.execSync", "shelljs.exec", "execa.command"}
SPAWN_FUNCS = {"child_process.spawn", "child_process.spawnSync", "child_process.execFile",
               "child_process.execFileSync"}
FS_FUNCS = {"readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync",
            "createWriteStream", "appendFile", "appendFileSync", "unlink", "unlinkSync",
            "readdir", "readdirSync", "rm", "rmSync", "stat", "statSync", "access",
            "accessSync", "open", "openSync", "rename", "renameSync"}
HTTP_CALLS = ({"fetch", "axios", "got", "request", "node-fetch", "needle",
               "http.get", "http.request", "https.get", "https.request"}
              | {f"{lib}.{m}" for lib in ("axios", "got", "request", "needle", "superagent")
                 for m in ("get", "post", "put", "patch", "delete", "head")})
VM_FUNCS = {"vm.runInContext", "vm.runInNewContext", "vm.runInThisContext", "vm.compileFunction"}
JWT_FUNCS = {"jsonwebtoken.sign", "jsonwebtoken.verify", "jwt.sign", "jwt.verify"}
STR_TYPES = {"string", "template_string"}


# ------------------------------------------------------------------------ helpers
def text(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def named(n):
    return [c for c in n.named_children if c.type != "comment"] if n is not None else []


def str_value(n):
    """The literal text of a string / substitution-free template, else None."""
    if n is None:
        return None
    if n.type == "string":
        return "".join(text(c) for c in n.named_children
                       if c.type in ("string_fragment", "escape_sequence"))
    if n.type == "template_string" and not any(
            c.type == "template_substitution" for c in n.named_children):
        return text(n)[1:-1]
    return None


def is_const(n) -> bool:
    if n is None:
        return True
    if n.type in ("string", "number", "true", "false", "null", "undefined", "regex"):
        return True
    if n.type == "template_string":
        return str_value(n) is not None
    if n.type in ("array", "parenthesized_expression"):
        return all(is_const(c) for c in named(n))
    return False


_merge = merge_env


def _or(it) -> int:
    f = 0
    for x in it:
        f |= x
    return f


def _normalize_module(m: str) -> str:
    if m.startswith("node:"):
        m = m[5:]
    return "fs" if m == "fs/promises" else m


class JsAnalyzer(BaseAnalyzer):
    def __init__(self, source: str, filename: str = "<string>"):
        super().__init__(source, filename)
        self.aliases: dict[str, str] = {}
        self.env: dict[str, int] = {}

    def run(self) -> list[Finding]:
        tree = _parser().parse(self.source.encode("utf-8"))
        self.collect_imports(tree.root_node)
        self.ev(tree.root_node)
        return self.results()

    # ------------------------------------------------------------------ plumbing
    def rep(self, rule_id, node, message, severity=None, tainted=False):
        self.add(rule_id, node.start_point[0] + 1, node.start_point[1] + 1,
                 message, severity, tainted)

    def emit(self, rule_id, node, res):
        if res:
            sev, msg, tainted = res
            self.rep(rule_id, node, msg, sev, tainted)

    def collect_imports(self, root) -> None:
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type == "variable_declarator":
                self._require_alias(n)
            elif n.type == "import_statement":
                self._import_alias(n)

    @staticmethod
    def _require_target(v):
        """`require('m')` -> ('m', None); `require('m').x` -> ('m', 'x'); else None."""
        prop = None
        if v is not None and v.type == "member_expression":
            prop = text(v.child_by_field_name("property"))
            v = v.child_by_field_name("object")
        if v is not None and v.type == "call_expression":
            fn, args = v.child_by_field_name("function"), v.child_by_field_name("arguments")
            if fn is not None and text(fn) == "require" and args is not None:
                a = named(args)
                if a and str_value(a[0]) is not None:
                    return _normalize_module(str_value(a[0])), prop
        return None

    def _require_alias(self, n) -> None:
        name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
        target = self._require_target(value)
        if not target or name is None:
            return
        mod, prop = target
        if name.type == "identifier":
            self.aliases[text(name)] = mod if prop is None else f"{mod}.{prop}"
        elif name.type == "object_pattern":
            for c in named(name):
                if c.type == "shorthand_property_identifier_pattern":
                    self.aliases[text(c)] = f"{mod}.{text(c)}"
                elif c.type == "pair_pattern":
                    k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                    if v is not None and v.type == "identifier":
                        self.aliases[text(v)] = f"{mod}.{text(k)}"

    def _import_alias(self, n) -> None:
        src = str_value(n.child_by_field_name("source"))
        if src is None:
            return
        mod = _normalize_module(src)
        for clause in named(n):
            if clause.type != "import_clause":
                continue
            for d in named(clause):
                if d.type == "identifier":
                    self.aliases[text(d)] = mod
                elif d.type == "namespace_import":
                    for i in named(d):
                        if i.type == "identifier":
                            self.aliases[text(i)] = mod
                elif d.type == "named_imports":
                    for spec in named(d):
                        nm, al = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                        if nm is not None:
                            self.aliases[text(al or nm)] = f"{mod}.{text(nm)}"

    def dotted(self, n):
        parts = []
        while n is not None and n.type == "member_expression":
            parts.append(text(n.child_by_field_name("property")))
            n = n.child_by_field_name("object")
        if n is not None and n.type == "identifier":
            parts.append(self.aliases.get(text(n), text(n)))
            return ".".join(reversed(parts))
        if n is not None and n.type == "call_expression":  # require('m').fn(...)
            target = self._require_target(n)
            if target and target[1] is None:
                parts.append(target[0])
                return ".".join(reversed(parts))
        return None

    @staticmethod
    def root_ident(n):
        while n is not None and n.type in ("member_expression", "subscript_expression",
                                           "call_expression", "parenthesized_expression"):
            n = n.child_by_field_name("object") or n.child_by_field_name("function") \
                or (named(n)[0] if named(n) else None)
        return text(n) if n is not None and n.type == "identifier" else None

    # --------------------------------------------------------------------- walking
    def ev(self, n) -> int:
        if n is None:
            return 0
        h = getattr(self, "h_" + n.type, None)
        if h:
            return h(n)
        f = 0
        for c in n.named_children:
            f |= self.ev(c)
        return f & PROP

    def bind(self, p, flags: int) -> None:
        if p is None:
            return
        t = p.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            self.env[text(p)] = flags
        elif t == "pair_pattern":
            self.bind(p.child_by_field_name("value"), flags)
        elif t in ("assignment_pattern", "object_assignment_pattern"):
            self.bind(p.child_by_field_name("left"), flags)
        elif t in ("object_pattern", "array_pattern", "rest_pattern"):
            for c in named(p):
                self.bind(c, flags)

    # ---------------------------------------------------------------- expressions
    def h_identifier(self, n):
        name = text(n)
        if name in self.env:
            return self.env[name]
        if name in ("req", "request") and name not in self.aliases:
            return TAINT | RAW
        return 0

    h_shorthand_property_identifier = h_identifier

    def h_member_expression(self, n):
        d = self.dotted(n)
        if d and any(d == s or d.endswith("." + s) for s in SOURCE_PATHS):
            return TAINT | RAW
        return self.ev(n.child_by_field_name("object")) & PROP

    def h_subscript_expression(self, n):
        v = self.ev(n.child_by_field_name("object"))
        self.ev(n.child_by_field_name("index"))  # a tainted index into a table does not taint it
        return v & PROP

    def h_string(self, n):
        return 0

    def h_template_string(self, n):
        f, dyn = 0, False
        for c in n.named_children:
            if c.type == "template_substitution":
                for e in named(c):
                    fe = self.ev(e)
                    f |= fe & PROP
                    if not (is_const(e) or fe & SAFE):
                        dyn = True
        return f | (DYN if dyn else 0)

    def h_binary_expression(self, n):
        l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
        op = text(n.child_by_field_name("operator"))
        lf, rf = self.ev(l), self.ev(r)
        if op in ("&&", "||", "??"):
            return join(lf, rf)
        if op == "+":
            f = (lf | rf) & PROP
            stringy = l.type in STR_TYPES or r.type in STR_TYPES or (lf | rf) & DYN
            if stringy and not ((is_const(l) or lf & SAFE) and (is_const(r) or rf & SAFE)):
                f |= DYN
            return f
        return SAFE  # comparisons and arithmetic yield booleans / numbers

    def h_unary_expression(self, n):
        self.ev(n.child_by_field_name("argument"))
        return SAFE  # !x, -x, +x (number coercion), typeof x

    h_update_expression = h_unary_expression

    def h_ternary_expression(self, n):
        self.ev(n.child_by_field_name("condition"))
        return join(self.ev(n.child_by_field_name("consequence")),
                    self.ev(n.child_by_field_name("alternative")))

    def h_object(self, n):
        f = 0
        for c in named(n):
            if c.type == "pair":
                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                vf = self.ev(v)
                f |= vf
                key = str_value(k) if k.type == "string" else text(k)
                self.pair_checks(key, v, vf)
            else:
                f |= self.ev(c)
        return f & PROP

    def pair_checks(self, key, v, vf) -> None:
        if v is None or key is None:
            return
        if key in ("rejectUnauthorized", "strictSSL") and v.type == "false":
            self.rep("CS007", v, f"{key}: false disables TLS certificate validation")
        if key == "__html":
            self.emit("CS011", v, self.sev(
                vf, "Untrusted data in dangerouslySetInnerHTML (XSS)",
                "Dynamic HTML in dangerouslySetInnerHTML; sanitize it first"))
        if looks_like_secret_name(key):
            val = str_value(v)
            if val and not is_placeholder(val):
                self.rep("CS004", v, f"Hardcoded credential in '{key}'")

    def h_variable_declarator(self, n):
        name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
        f = self.ev(value) if value is not None else 0
        self.assign_checks(name, value)
        self.bind(name, f & (PROP | SAFE))
        return 0

    def assign_checks(self, name_node, value) -> None:
        if name_node is None or value is None:
            return
        if name_node.type == "identifier":
            name = text(name_node)
        elif name_node.type == "member_expression":
            name = text(name_node.child_by_field_name("property"))
        elif name_node.type == "subscript_expression":
            name = str_value(name_node.child_by_field_name("index"))
        else:
            return
        if not name or not looks_like_secret_name(name):
            return
        lit = str_value(value)
        if lit and not is_placeholder(lit):
            self.rep("CS004", value, f"Hardcoded credential assigned to '{name}'")
        elif value.type == "binary_expression" and text(value.child_by_field_name("operator")) in ("||", "??"):
            fb = str_value(value.child_by_field_name("right"))
            if fb and not is_placeholder(fb):
                self.rep("CS004", value, f"Hardcoded fallback value for secret '{name}'")
        stack = [value]
        while stack:
            c = stack.pop()
            stack.extend(c.children)
            if c.type == "call_expression" and self.dotted(c.child_by_field_name("function")) == "Math.random":
                self.rep("CS010", c, f"'{name}' is generated with Math.random(), which is not cryptographically secure")
                break

    def h_assignment_expression(self, n):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        f = self.ev(right)
        if left.type == "identifier":
            self.env[text(left)] = f
            self.assign_checks(left, right)
        elif left.type in ("member_expression", "subscript_expression"):
            self.assign_member(n, left, right, f)
        else:
            self.bind(left, f & PROP)
        return f

    def h_augmented_assignment_expression(self, n):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        f = self.ev(right)
        op = text(n.child_by_field_name("operator"))
        if left.type == "identifier":
            new = join(self.env.get(text(left), 0), f)
            if op == "+=" and not (is_const(right) or f & SAFE):
                new |= DYN
            self.env[text(left)] = new
        elif left.type in ("member_expression", "subscript_expression"):
            self.assign_member(n, left, right, f | (DYN if op == "+=" and not (is_const(right) or f & SAFE) else 0))
        return 0

    def assign_member(self, n, left, right, f) -> None:
        obj = left.child_by_field_name("object")
        self.ev(obj)
        if left.type == "member_expression":
            pname = text(left.child_by_field_name("property"))
        else:
            self.ev(left.child_by_field_name("index"))
            pname = str_value(left.child_by_field_name("index"))
        if pname in ("innerHTML", "outerHTML"):
            self.emit("CS011", n, self.sev(
                f, f"Untrusted data assigned to .{pname} (DOM XSS)",
                f"Dynamic HTML assigned to .{pname}; use textContent or sanitize first"))
        d = self.dotted(left)
        if d and d.endswith("NODE_TLS_REJECT_UNAUTHORIZED") and text(right).strip("'\"") == "0":
            self.rep("CS007", n, "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate validation")
        root = self.root_ident(obj)
        if root and f & TAINT:
            self.env[root] = self.env.get(root, 0) | (f & PROP)
        self.assign_checks(left, right)

    # -------------------------------------------------------------- control flow
    def func(self, n):
        saved, self.env = self.env, dict(self.env)
        params = n.child_by_field_name("parameters") or n.child_by_field_name("parameter")
        if params is not None:
            if params.type == "identifier":
                self.bind(params, 0)
            else:
                for c in named(params):
                    self.bind(c, 0)
            for name in ("req", "request"):  # Express/Fastify handler arguments
                if name in self.env and name not in self.aliases:
                    self.env[name] = TAINT | RAW
        self.ev(n.child_by_field_name("body"))
        self.env = saved
        return 0

    h_function_declaration = h_arrow_function = h_function_expression = func
    h_function = h_generator_function = h_generator_function_declaration = func
    h_method_definition = func

    def h_if_statement(self, n):
        self.ev(n.child_by_field_name("condition"))
        pre = self.env
        self.env = dict(pre)
        self.ev(n.child_by_field_name("consequence"))
        a = self.env
        self.env = dict(pre)
        self.ev(n.child_by_field_name("alternative"))
        self.env = _merge(a, self.env)
        return 0

    def _loop(self, n, setup=None, parts=("condition", "body", "increment")):
        pre = self.env
        self.env = dict(pre)
        for _ in range(2):  # second pass lets taint from later iterations flow back
            if setup:
                setup()
            for p in parts:
                self.ev(n.child_by_field_name(p))
        self.env = _merge(pre, self.env)
        return 0

    def h_for_statement(self, n):
        self.ev(n.child_by_field_name("initializer"))
        return self._loop(n)

    def h_for_in_statement(self, n):
        it = self.ev(n.child_by_field_name("right")) & PROP
        left = n.child_by_field_name("left")
        return self._loop(n, setup=lambda: self.bind(left, it), parts=("body",))

    def h_while_statement(self, n):
        return self._loop(n, parts=("condition", "body"))

    def h_do_statement(self, n):
        return self._loop(n, parts=("body", "condition"))

    def h_try_statement(self, n):
        pre = self.env
        self.env = dict(pre)
        self.ev(n.child_by_field_name("body"))
        after = self.env
        merged = after
        h = n.child_by_field_name("handler")
        if h is not None:
            self.env = _merge(pre, after)
            self.bind(h.child_by_field_name("parameter"), 0)
            self.ev(h.child_by_field_name("body"))
            merged = _merge(after, self.env)
        self.env = merged
        self.ev(n.child_by_field_name("finalizer"))
        return 0

    # ------------------------------------------------------------------- calls
    def h_new_expression(self, n):
        ctor, args = n.child_by_field_name("constructor"), n.child_by_field_name("arguments")
        arg_nodes = named(args)
        af = [self.ev(a) for a in arg_nodes]
        cname = self.dotted(ctor)
        if cname is None:
            self.ev(ctor)
        if cname == "Function" and arg_nodes and not all(is_const(a) for a in arg_nodes):
            f = _or(af)
            self.emit("CS001", n, ("high", "Untrusted data reaches new Function()", True) if f & TAINT
                      else ("medium", "new Function() builds code at runtime", False))
        return _or(af) & TAINT

    def h_call_expression(self, n):
        fn, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
        recv, attr = 0, None
        if fn.type == "member_expression":
            recv = self.ev(fn.child_by_field_name("object"))
            attr = text(fn.child_by_field_name("property"))
        elif fn.type != "identifier":
            self.ev(fn)  # IIFE or computed callee: still analyze its body
        name = self.dotted(fn)
        if args is None or args.type == "template_string":  # tagged template, e.g. sql`...${x}`
            self.ev(args)
            return 0
        arg_nodes = named(args)
        af = [self.ev(a) for a in arg_nodes]
        self.check_call(n, fn, name, attr, arg_nodes, af)

        if name in SANITIZERS or (name or "").startswith("Math.") or attr in BOOL_METHODS:
            return SAFE
        if (name == "String" and af and all(x & SAFE for x in af)) or (
                attr in ("toString", "toFixed") and recv & SAFE):
            return SAFE
        if name in SOURCE_CALLS:
            return TAINT | RAW
        allf = recv | _or(af)
        out = allf & TAINT
        if out and ((fn.type == "member_expression" and recv & RAW) or name == "String"):
            out |= allf & RAW  # .trim()/.toLowerCase()/String() keep it reflected text
        return out

    @staticmethod
    def _has_option(arg_nodes, key, value_type="true") -> bool:
        for a in arg_nodes:
            if a.type == "object":
                for p in named(a):
                    if p.type == "pair" and text(p.child_by_field_name("key")).strip("'\"") == key \
                            and p.child_by_field_name("value").type == value_type:
                        return True
        return False

    def check_call(self, n, fn, name, attr, nodes, af) -> None:
        def a(i):
            return af[i] if i < len(af) else 0

        # CS001 code injection
        if name in ("eval", "window.eval", "global.eval") and nodes and not is_const(nodes[0]):
            self.emit("CS001", n, ("high", "Untrusted data reaches eval()", True) if a(0) & TAINT
                      else ("medium", "eval() on a dynamic value can execute arbitrary code", False))
        if name in ("setTimeout", "setInterval") and nodes and nodes[0].type in (
                "string", "template_string", "binary_expression") and not is_const(nodes[0]):
            self.emit("CS001", n, ("high", f"Untrusted string passed to {name}() is evaluated as code", True)
                      if a(0) & TAINT else ("medium", f"String argument to {name}() is evaluated as code", False))
        if name in VM_FUNCS and nodes and not is_const(nodes[0]):
            self.emit("CS001", n, ("high", f"Untrusted data reaches {name}()", True) if a(0) & TAINT
                      else ("medium", f"{name}() runs dynamic code", False))

        # CS002 SQL
        if attr in SQL_METHODS and nodes and nodes[0].type != "object":
            self.emit("CS002", n, self.sev(
                a(0), "Untrusted data flows into a SQL query (SQL injection)",
                "SQL query built with string concatenation/templates; use placeholders"))

        # CS003 command injection
        if name in EXEC_FUNCS:
            self.emit("CS003", n, self.sev(
                a(0), f"Untrusted data flows into {name}() (command injection)",
                f"Shell command for {name}() built dynamically; use execFile/spawn with an argument array"))
        elif name in SPAWN_FUNCS:
            shell = self._has_option(nodes, "shell")
            if a(0) & TAINT or (shell and _or(af) & TAINT):
                self.rep("CS003", n, f"Untrusted data flows into {name}() (command injection)", "high", True)

        # CS004 hard-coded JWT secret
        if name in JWT_FUNCS and len(nodes) > 1:
            s = str_value(nodes[1])
            if s and not is_placeholder(s):
                self.rep("CS004", nodes[1], "Hardcoded JWT secret")

        # CS005 weak hash
        if name in ("crypto.createHash", "crypto.createHmac") and nodes:
            algo = (str_value(nodes[0]) or "").lower()
            if algo in ("md5", "sha1"):
                self.rep("CS005", n, f"{algo.upper()} is a weak hash algorithm")

        # CS006 deserialization
        if name == "node-serialize.unserialize":
            self.emit("CS006", n, ("high", "Untrusted data passed to node-serialize unserialize() (remote code execution)", True)
                      if a(0) & TAINT else ("medium", "node-serialize unserialize() can execute code in crafted input", False))

        # CS009 path traversal
        if name and name.split(".")[0] == "fs" and name.split(".")[-1] in FS_FUNCS:
            self.emit("CS009", n, self.sev(a(0), f"Untrusted data used as a file path in {name}() (path traversal)"))
        if attr in ("sendFile", "download") and nodes and not self._has_option(nodes, "root", "string"):
            self.emit("CS009", n, self.sev(a(0), f"Untrusted data used as a file path in .{attr}() (path traversal)"))

        # CS011 XSS
        if name in ("document.write", "document.writeln"):
            self.emit("CS011", n, self.sev(a(0), f"Untrusted data written with {name}() (DOM XSS)",
                                           f"Dynamic HTML written with {name}()"))
        if attr == "insertAdjacentHTML" and len(nodes) > 1:
            self.emit("CS011", n, self.sev(a(1), "Untrusted data passed to insertAdjacentHTML() (DOM XSS)",
                                           "Dynamic HTML passed to insertAdjacentHTML()"))
        if attr == "html" and nodes:
            self.emit("CS011", n, self.sev(a(0), "Untrusted data passed to .html() (DOM XSS)",
                                           "Dynamic HTML passed to .html(); escape or sanitize it"))
        if attr in ("send", "write", "end") and nodes and a(0) & RAW \
                and self.root_ident(fn.child_by_field_name("object")) in ("res", "response", "reply"):
            self.rep("CS011", n, "Reflected XSS: untrusted request data is written straight into the response",
                     "medium", True)

        # CS012 SSRF
        if name in HTTP_CALLS and nodes and nodes[0].type != "object":
            self.emit("CS012", n, self.sev(a(0), f"Untrusted URL passed to {name}() (SSRF)"))


def analyze_js(source: str, filename: str = "<string>") -> list[Finding]:
    return JsAnalyzer(source, filename).run()
