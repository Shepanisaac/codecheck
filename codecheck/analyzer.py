"""Analysis engine: AST walk + lightweight intra-procedural taint tracking.

Every expression evaluates to a small bit-set of "flags":
  TAINT  the value may be attacker-controlled (came from a source)
  DYN    the value is a string assembled at runtime (f-string, +, %, .format)

Variables carry flags in an environment that is updated in statement order and
merged at branches, so `q = "..." + user; cur.execute(q)` is tracked across lines.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, asdict

from .rules import RULES, SEVERITY_ORDER

TAINT = 1
DYN = 2
RAW = 4    # attacker text that has not passed through a transforming function (XSS-relevant)
PROP = TAINT | RAW

SOURCE_CALLS = {"input", "raw_input", "sys.stdin.read", "sys.stdin.readline"}

# Calls whose result is considered clean of attacker influence.
# (Deliberately coarse: a sanitizer is not tracked per vulnerability class.)
SANITIZERS = {
    "int", "float", "bool", "len", "round", "abs", "ord", "hash", "id",
    "uuid.UUID", "ipaddress.ip_address",
    "os.path.basename", "secure_filename", "werkzeug.utils.secure_filename",
    "shlex.quote", "pipes.quote", "html.escape", "escape", "markupsafe.escape",
    "flask.escape", "django.utils.html.escape", "bleach.clean", "re.escape",
    "urllib.parse.quote", "urllib.parse.quote_plus",
    # auto-escaping / JSON output sinks are safe for XSS purposes
    "render_template", "flask.render_template", "jsonify", "flask.jsonify",
}

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "mogrify"}
SUBPROCESS_FUNCS = {f"subprocess.{n}" for n in
                    ("call", "run", "Popen", "check_call", "check_output")}
OS_CMD_FUNCS = {"os.system", "os.popen", "subprocess.getoutput",
                "subprocess.getstatusoutput", "commands.getoutput"}
DESERIALIZERS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                 "dill.load", "dill.loads", "marshal.load", "marshal.loads",
                 "jsonpickle.decode", "yaml.unsafe_load"}
HTTP_FUNCS = {f"{lib}.{m}" for lib in ("requests", "httpx")
              for m in ("get", "post", "put", "patch", "delete", "head", "options")}
HTTP_FUNCS |= {"urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen"}
HTTP_REQUEST_FUNCS = {"requests.request", "httpx.request"}  # url is 2nd arg
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}

SECRET_RE = re.compile(
    r"(^|_)(pass|password|passwd|pwd|secret|api_?key|apikey|access_?key|"
    r"auth_?token|token|private_?key|client_secret|credentials?)($|_)")
NOT_A_SECRET_SUFFIX = {
    "type", "field", "name", "url", "path", "header", "label", "file", "len",
    "length", "expiry", "ttl", "endpoint", "env", "var", "prompt", "message",
    "msg", "help", "hint", "text", "placeholder", "format", "param", "key_name",
}
SUPPRESS_RE = re.compile(
    r"#\s*(?:nosec|codecheck:\s*ignore)(?:\[([A-Za-z0-9_,\s]+)\])?")


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    col: int
    snippet: str = ""
    tainted: bool = False

    @property
    def cwe(self) -> str:
        return RULES[self.rule_id].cwe

    @property
    def owasp(self) -> str:
        return RULES[self.rule_id].owasp

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cwe"], d["owasp"] = self.cwe, self.owasp
        return d


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def looks_like_secret_name(name: str) -> bool:
    s = _snake(name)
    return bool(SECRET_RE.search(s)) and s.split("_")[-1] not in NOT_A_SECRET_SUFFIX


def _is_str(n: ast.AST) -> bool:
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def _is_const(n: ast.AST) -> bool:
    if isinstance(n, ast.Constant):
        return True
    return isinstance(n, (ast.Tuple, ast.List)) and all(_is_const(e) for e in n.elts)


def _merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) | v
    return out


class Analyzer:
    def __init__(self, source: str, filename: str = "<string>"):
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.aliases: dict[str, str] = {}
        self.env: dict[str, int] = {}
        self.in_route = False
        self.found: dict[tuple, Finding] = {}

    # ------------------------------------------------------------------ public
    def run(self) -> list[Finding]:
        tree = ast.parse(self.source, filename=self.filename)
        self._collect_imports(tree)
        self.block(tree.body)
        return sorted(self.found.values(), key=lambda f: (f.line, f.col, f.rule_id))

    # ----------------------------------------------------------------- helpers
    def _collect_imports(self, tree: ast.AST) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        root = a.name.split(".")[0]
                        self.aliases[root] = root
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                for a in n.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = f"{n.module}.{a.name}"

    def dotted(self, node: ast.AST) -> str | None:
        """Resolve `a.b.c` to its fully-qualified dotted name through import aliases."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
            return ".".join(reversed(parts))
        return None

    def report(self, rule_id: str, node: ast.AST, message: str,
               severity: str | None = None, tainted: bool = False) -> None:
        line, col = node.lineno, node.col_offset + 1
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        m = SUPPRESS_RE.search(text)
        if m:
            ids = m.group(1)
            if not ids or rule_id in {i.strip() for i in ids.split(",")}:
                return
        severity = severity or RULES[rule_id].severity
        key = (rule_id, line, col)
        old = self.found.get(key)
        if old and SEVERITY_ORDER[old.severity] >= SEVERITY_ORDER[severity]:
            return
        self.found[key] = Finding(rule_id, severity, message, self.filename,
                                  line, col, text.strip(), tainted)

    def sev(self, flags: int, taint_msg: str, dyn_msg: str | None = None):
        """Pick (severity, message, tainted) from flags, or None if clean."""
        if flags & PROP:
            return "high", taint_msg, True
        if dyn_msg and flags & DYN:
            return "medium", dyn_msg, False
        return None

    # -------------------------------------------------------------- statements
    def block(self, stmts) -> None:
        for s in stmts:
            self.stmt(s)

    def generic(self, n: ast.AST) -> None:
        for c in ast.iter_child_nodes(n):
            if isinstance(c, ast.stmt):
                self.stmt(c)
            elif isinstance(c, ast.expr):
                self.expr(c)
            else:
                self.generic(c)

    def stmt(self, n: ast.stmt) -> None:
        if isinstance(n, (ast.Import, ast.ImportFrom, ast.Pass, ast.Break,
                          ast.Continue, ast.Global, ast.Nonlocal)):
            return
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self.funcdef(n)
        if isinstance(n, ast.ClassDef):
            for e in n.decorator_list + n.bases + [k.value for k in n.keywords]:
                self.expr(e)
            saved, self.env = self.env, dict(self.env)
            self.block(n.body)
            self.env = saved
            return
        if isinstance(n, ast.Assign):
            f = self.expr(n.value)
            for t in n.targets:
                self.assign_checks(t, n.value)
                self.bind(t, f)
            return
        if isinstance(n, ast.AnnAssign):
            if n.value is not None:
                f = self.expr(n.value)
                self.assign_checks(n.target, n.value)
                self.bind(n.target, f)
            return
        if isinstance(n, ast.AugAssign):
            f = self.expr(n.value)
            if isinstance(n.target, ast.Name):
                new = self.env.get(n.target.id, 0) | f
                if isinstance(n.op, (ast.Add, ast.Mod)) and not isinstance(n.value, ast.Constant):
                    new |= DYN
                self.env[n.target.id] = new
            else:
                self.expr(n.target)
            return
        if isinstance(n, ast.Expr):
            self.expr(n.value)
            return
        if isinstance(n, ast.Return):
            if n.value is not None:
                f = self.expr(n.value)
                if self.in_route and f & RAW and not isinstance(n.value, ast.Dict):
                    self.report("CS011", n,
                                "Reflected XSS: untrusted request data is returned directly in the response",
                                "medium", True)
            return
        if isinstance(n, ast.If):
            self.expr(n.test)
            pre = self.env
            self.env = dict(pre)
            self.block(n.body)
            a = self.env
            self.env = dict(pre)
            self.block(n.orelse)
            self.env = _merge(a, self.env)
            return
        if isinstance(n, (ast.For, ast.AsyncFor)):
            it = self.expr(n.iter)
            pre = self.env
            self.env = dict(pre)
            for _ in range(2):  # second pass lets taint from later iterations flow back
                self.bind(n.target, it & PROP)
                self.block(n.body)
            self.env = _merge(pre, self.env)
            self.block(n.orelse)
            return
        if isinstance(n, ast.While):
            pre = self.env
            self.env = dict(pre)
            for _ in range(2):
                self.expr(n.test)
                self.block(n.body)
            self.env = _merge(pre, self.env)
            self.block(n.orelse)
            return
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                f = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, f & PROP)
            self.block(n.body)
            return
        if isinstance(n, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            pre = self.env
            self.env = dict(pre)
            self.block(n.body)
            after = self.env
            outs = []
            for h in n.handlers:
                self.env = _merge(pre, after)
                if h.type is not None:
                    self.expr(h.type)
                if h.name:
                    self.env[h.name] = 0
                self.block(h.body)
                outs.append(self.env)
            self.env = after
            self.block(n.orelse)
            merged = self.env
            for o in outs:
                merged = _merge(merged, o)
            self.env = merged
            self.block(n.finalbody)
            return
        self.generic(n)

    def funcdef(self, n) -> None:
        for e in n.decorator_list:
            self.expr(e)
        a = n.args
        for d in a.defaults + [d for d in a.kw_defaults if d is not None]:
            self.expr(d)
        saved_env, saved_route = self.env, self.in_route
        self.in_route = any(self.is_route_decorator(d) for d in n.decorator_list)
        self.env = dict(saved_env)
        params = a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]
        for p in params:
            clean = (isinstance(p.annotation, ast.Name)
                     and p.annotation.id in {"int", "float", "bool", "UUID"})
            if p.arg == "request":
                self.env[p.arg] = TAINT | RAW
            elif p.arg in {"self", "cls"} or clean:
                self.env[p.arg] = 0
            else:
                # Web handler arguments (URL params) are attacker-controlled
                self.env[p.arg] = (TAINT | RAW) if self.in_route else 0
        self.block(n.body)
        self.env, self.in_route = saved_env, saved_route

    def is_route_decorator(self, d: ast.AST) -> bool:
        target = d.func if isinstance(d, ast.Call) else d
        return isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS

    def bind(self, target: ast.AST, flags: int) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = flags
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self.bind(e, flags)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, flags)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            self.expr(base)
            if isinstance(base, ast.Name) and flags & PROP:
                self.env[base.id] = self.env.get(base.id, 0) | TAINT

    def assign_checks(self, target: ast.AST, value: ast.AST) -> None:
        name = (target.id if isinstance(target, ast.Name)
                else target.attr if isinstance(target, ast.Attribute)
                else target.slice.value if isinstance(target, ast.Subscript)
                and _is_str(target.slice) else None)
        if not name:
            return
        if looks_like_secret_name(name):
            if _is_str(value) and value.value and not value.value.startswith(("<", "${", "{{")):
                self.report("CS004", value, f"Hardcoded credential assigned to '{name}'")
            for c in ast.walk(value):
                if isinstance(c, ast.Call) and (self.dotted(c.func) or "").startswith("random."):
                    self.report("CS010", c, f"'{name}' is generated with the non-cryptographic random module")
                    break
        if name == "DEBUG" and isinstance(value, ast.Constant) and value.value is True:
            self.report("CS008", value, "DEBUG = True; make sure this is disabled in production", "low")
        if name == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
            self.report("CS007", value, "TLS hostname verification disabled")

    # ------------------------------------------------------------- expressions
    def expr(self, n) -> int:
        if n is None:
            return 0
        m = getattr(self, "e_" + type(n).__name__, None)
        if m:
            return m(n)
        f = 0
        for c in ast.iter_child_nodes(n):
            if isinstance(c, ast.expr):
                f |= self.expr(c)
        return f & PROP

    def e_Constant(self, n):
        return 0

    def e_Name(self, n):
        if n.id in self.env:
            return self.env[n.id]
        if n.id == "request" or self.aliases.get(n.id) == "flask.request":
            return TAINT | RAW
        return 0

    def e_Attribute(self, n):
        d = self.dotted(n)
        if d == "sys.argv":
            return TAINT | RAW
        if d == "ssl.CERT_NONE":
            self.report("CS007", n, "ssl.CERT_NONE disables certificate validation")
        return self.expr(n.value) & PROP

    def e_Subscript(self, n):
        v = self.expr(n.value)
        self.expr(n.slice)  # visit for nested calls, but a tainted index does not taint the result
        return v & PROP

    def e_JoinedStr(self, n):
        f, dyn = 0, False
        for v in n.values:
            if isinstance(v, ast.FormattedValue):
                f |= self.expr(v.value) & PROP
                self.expr(v.format_spec)
                if not isinstance(v.value, ast.Constant):
                    dyn = True
        return f | (DYN if dyn else 0)

    def e_BinOp(self, n):
        l, r = self.expr(n.left), self.expr(n.right)
        f = (l | r) & PROP
        if isinstance(n.op, (ast.Add, ast.Mod)):
            stringy = (_is_str(n.left) or _is_str(n.right)
                       or isinstance(n.left, ast.JoinedStr) or isinstance(n.right, ast.JoinedStr)
                       or (l | r) & DYN)
            if stringy and not (_is_const(n.left) and _is_const(n.right)):
                f |= DYN
        return f

    def e_BoolOp(self, n):
        f = 0
        for v in n.values:
            f |= self.expr(v)
        return f

    def e_IfExp(self, n):
        self.expr(n.test)
        return self.expr(n.body) | self.expr(n.orelse)

    def e_Compare(self, n):
        self.expr(n.left)
        for c in n.comparators:
            self.expr(c)
        return 0

    def e_Lambda(self, n):
        return 0

    def e_NamedExpr(self, n):
        f = self.expr(n.value)
        self.bind(n.target, f)
        return f

    def e_Dict(self, n):
        f = 0
        for k, v in zip(n.keys, n.values):
            f |= self.expr(k) | self.expr(v)
            if _is_str(k) and _is_str(v) and v.value and looks_like_secret_name(k.value) \
                    and not v.value.startswith(("<", "${", "{{")):
                self.report("CS004", v, f"Hardcoded credential in key '{k.value}'")
        return f & PROP

    def _comp(self, n):
        saved, self.env = self.env, dict(self.env)
        f = 0
        for g in n.generators:
            it = self.expr(g.iter)
            self.bind(g.target, it & PROP)
            f |= it
            for c in g.ifs:
                self.expr(c)
        if isinstance(n, ast.DictComp):
            f |= self.expr(n.key) | self.expr(n.value)
        else:
            f |= self.expr(n.elt)
        self.env = saved
        return f & PROP

    e_ListComp = e_SetComp = e_GeneratorExp = e_DictComp = _comp

    def e_Call(self, n: ast.Call):
        func = n.func
        recv = 0
        if isinstance(func, ast.Attribute):
            recv = self.expr(func.value)
        elif not isinstance(func, ast.Name):
            recv = self.expr(func)
        af = [self.expr(a) for a in n.args]
        kf = {k.arg: self.expr(k.value) for k in n.keywords}
        name = self.dotted(func)
        self.check_call(n, name, af, kf)

        if name in SANITIZERS:
            return 0
        if name in SOURCE_CALLS:
            return TAINT | RAW
        out = (recv | _or(af) | _or(kf.values())) & TAINT
        if (isinstance(func, ast.Attribute) and recv & RAW) or name == "str":
            out |= (recv | _or(af)) & RAW  # .strip()/.lower()/str() keep it reflected-text
        if isinstance(func, ast.Attribute) and func.attr == "format":
            if any(not _is_const(a) for a in n.args + [k.value for k in n.keywords]):
                out |= DYN
        return out

    # ------------------------------------------------------------- call checks
    def check_call(self, n: ast.Call, name, af, kf) -> None:
        func = n.func
        attr = func.attr if isinstance(func, ast.Attribute) else None
        kw = {k.arg: k.value for k in n.keywords if k.arg}

        def arg(i, key=None):
            if i < len(af):
                return af[i]
            return kf.get(key, 0) if key else 0

        def arg_node(i, key=None):
            if i < len(n.args):
                return n.args[i]
            return kw.get(key) if key else None

        def emit(rule, res):
            if res:
                sev, msg, tainted = res
                self.report(rule, n, msg, sev, tainted)

        # CS001 eval / exec
        if name in {"eval", "exec"} and n.args and not isinstance(n.args[0], ast.Constant):
            f = arg(0)
            emit("CS001", ("high", f"Untrusted data reaches {name}()", True) if f & PROP
                 else ("medium", f"{name}() on a dynamic value can execute arbitrary code", False))

        # CS002 SQL
        if attr in SQL_METHODS and (n.args or "sql" in kw or "query" in kw):
            emit("CS002", self.sev(arg(0, "sql") | arg(0, "query"),
                                   "Untrusted data flows into a SQL query (SQL injection)",
                                   "SQL query built with string formatting; use parameterized queries"))

        # CS003 command injection
        if name in OS_CMD_FUNCS:
            emit("CS003", self.sev(arg(0), f"Untrusted data flows into {name}() (command injection)",
                                   f"Command string for {name}() built dynamically"))
        elif name in SUBPROCESS_FUNCS:
            sh = kw.get("shell")
            if isinstance(sh, ast.Constant) and sh.value is True:
                f = arg(0, "args")
                res = self.sev(f, f"Untrusted data flows into {name}(shell=True) (command injection)",
                               f"Command for {name}(shell=True) built dynamically")
                if not res and not _is_const(arg_node(0, "args") or ast.Constant(0)):
                    res = ("medium", f"{name}(shell=True) with a non-constant command", False)
                emit("CS003", res)

        # CS005 weak hash
        if name in {"hashlib.md5", "hashlib.sha1"} or (
                name == "hashlib.new" and n.args and _is_str(n.args[0])
                and n.args[0].value.lower() in {"md5", "sha1"}):
            uf = kw.get("usedforsecurity")
            if not (isinstance(uf, ast.Constant) and uf.value is False):
                emit("CS005", ("medium", f"{name} is a weak hash algorithm", False))

        # CS006 deserialization
        if name in DESERIALIZERS or name in {"yaml.load", "yaml.load_all"}:
            safe = False
            if name.startswith("yaml.load"):
                loader = arg_node(1, "Loader")
                safe = loader is not None and (self.dotted(loader) or "").split(".")[-1] in {
                    "SafeLoader", "CSafeLoader"}
            if not safe:
                f = arg(0, "stream")
                emit("CS006", ("high", f"Untrusted data deserialized with {name}() (remote code execution)", True)
                     if f & PROP else ("medium", f"{name}() can execute code from crafted input", False))

        # CS007 TLS
        v = kw.get("verify")
        if isinstance(v, ast.Constant) and v.value is False:
            emit("CS007", ("medium", "verify=False disables TLS certificate validation", False))
        if name == "ssl._create_unverified_context":
            emit("CS007", ("medium", "Unverified SSL context disables certificate validation", False))

        # CS008 debug
        d = kw.get("debug")
        if attr == "run" and isinstance(d, ast.Constant) and d.value is True:
            emit("CS008", ("medium", "Application started with debug=True (exposes an interactive debugger)", False))

        # CS009 path traversal
        if name in {"open", "io.open", "send_file", "flask.send_file"}:
            emit("CS009", self.sev(arg(0, "file") | arg(0, "path_or_file"),
                                   f"Untrusted data used as a file path in {name}() (path traversal)"))

        # CS011 XSS / SSTI
        if name in {"render_template_string", "flask.render_template_string"}:
            emit("CS011", self.sev(arg(0, "source"),
                                   "Untrusted data used as a template (server-side template injection / XSS)",
                                   "Template built dynamically; use render_template with variables instead"))
        elif name in {"Markup", "markupsafe.Markup", "flask.Markup", "mark_safe",
                      "django.utils.safestring.mark_safe"}:
            emit("CS011", self.sev(arg(0),
                                   f"Untrusted data marked safe with {name}() (XSS)",
                                   f"Dynamic string marked safe with {name}(); escape its parts first"))

        # CS012 SSRF
        if name in HTTP_FUNCS:
            emit("CS012", self.sev(arg(0, "url"), f"Untrusted URL passed to {name}() (SSRF)"))
        elif name in HTTP_REQUEST_FUNCS:
            emit("CS012", self.sev(arg(1, "url"), f"Untrusted URL passed to {name}() (SSRF)"))

        # CS004 credentials passed as keyword arguments
        for k in n.keywords:
            if (k.arg and looks_like_secret_name(k.arg) and _is_str(k.value) and k.value.value
                    and not k.value.value.startswith(("<", "${", "{{"))):
                self.report("CS004", k.value, f"Hardcoded credential passed as '{k.arg}='")


def _or(it) -> int:
    f = 0
    for x in it:
        f |= x
    return f


def analyze_source(source: str, filename: str = "<string>") -> list[Finding]:
    return Analyzer(source, filename).run()
