import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from codecheck import analyze_source, language_for  # noqa: E402
from codecheck.cli import main, scan_paths  # noqa: E402

try:
    import tree_sitter_javascript  # noqa: F401
    HAVE_TS = True
except ImportError:  # pragma: no cover
    HAVE_TS = False


def ids(src):
    return sorted(f.rule_id for f in analyze_source(src, "t.js"))


def sev(src, rule):
    return [f.severity for f in analyze_source(src, "t.js") if f.rule_id == rule]


def route(body):
    return "const app = require('express')();\napp.get('/x', (req, res) => {\n" + body + "\n});\n"


@unittest.skipUnless(HAVE_TS, "tree-sitter-javascript not installed")
class Positives(unittest.TestCase):
    def test_sql(self):
        self.assertEqual(sev(route("db.query('SELECT * FROM t WHERE a=' + req.query.a);"), "CS002"), ["high"])
        self.assertEqual(sev(route("db.query(`SELECT * FROM t WHERE a=${req.body.a}`);"), "CS002"), ["high"])
        self.assertEqual(sev("function f(t) { db.query(`SELECT * FROM ${t}`); }", "CS002"), ["medium"])

    def test_taint_through_variables_destructuring_and_branches(self):
        self.assertEqual(ids(route("const { id } = req.query;\ndb.query('SELECT ' + id);")), ["CS002"])
        self.assertEqual(ids(route("let q = 'a';\nif (req.query.x) { q = req.query.x; }\ndb.query('S ' + q);")), ["CS002"])

    def test_command_injection_with_require_and_import_aliases(self):
        self.assertEqual(ids(route("require('child_process').exec('ls ' + req.query.d);")), ["CS003"])
        self.assertEqual(ids("const cp = require('child_process');\ncp.exec('ls ' + process.argv[2]);"), ["CS003"])
        self.assertEqual(ids("import { exec as run } from 'child_process';\nrun('ls ' + location.hash);"), ["CS003"])
        self.assertEqual(ids("import * as cp from 'node:child_process';\ncp.execSync(`ls ${process.argv[2]}`);"), ["CS003"])
        self.assertEqual(ids("const { spawn } = require('child_process');\nspawn('sh', ['-c', process.argv[2]], { shell: true });"), ["CS003"])

    def test_eval_family(self):
        self.assertEqual(sev("eval(location.hash)", "CS001"), ["high"])
        self.assertEqual(sev("function f(x) { eval(x); }", "CS001"), ["medium"])
        self.assertEqual(sev("new Function('return ' + location.hash)", "CS001"), ["high"])
        self.assertEqual(sev("setTimeout('go(' + location.hash + ')', 1)", "CS001"), ["high"])

    def test_xss(self):
        self.assertEqual(ids("el.innerHTML = location.search;"), ["CS011"])
        self.assertEqual(ids("el.innerHTML += '<b>' + name + '</b>';"), ["CS011"])
        self.assertEqual(ids("document.write(location.hash);"), ["CS011"])
        self.assertEqual(ids("$('#a').html(location.hash);"), ["CS011"])
        self.assertEqual(ids("const e = <div dangerouslySetInnerHTML={{__html: location.hash}} />;"), ["CS011"])
        self.assertEqual(ids(route("res.send('<h1>' + req.query.n.trim() + '</h1>');")), ["CS011"])

    def test_path_ssrf_deserialization(self):
        self.assertEqual(ids("const fs = require('fs');\nfs.readFileSync(process.argv[2]);"), ["CS009"])
        self.assertEqual(ids("import fsp from 'fs/promises';\nfsp.readFile(process.argv[2]);"), ["CS009"])
        self.assertEqual(ids(route("res.download(req.params.f);")), ["CS009"])
        self.assertEqual(ids("const axios = require('axios');\naxios.get(location.search);"), ["CS012"])
        self.assertEqual(ids("fetch(location.hash.slice(1));"), ["CS012"])
        self.assertEqual(ids("const s = require('node-serialize');\ns.unserialize(process.argv[2]);"), ["CS006"])

    def test_secrets_and_crypto(self):
        self.assertEqual(ids("const apiKey = 'abc123';"), ["CS004"])
        self.assertEqual(ids("const password = process.env.PW || 'dev';"), ["CS004"])
        self.assertEqual(ids("const c = { host: 'h', password: 'hunter2' };"), ["CS004"])
        self.assertEqual(ids("const jwt = require('jsonwebtoken');\njwt.sign({}, 'secret123');"), ["CS004"])
        self.assertEqual(ids("const crypto = require('crypto');\ncrypto.createHash('sha1');"), ["CS005"])
        self.assertEqual(ids("const sessionToken = Math.random().toString(36);"), ["CS010"])
        self.assertEqual(ids("new https.Agent({ rejectUnauthorized: false });"), ["CS007"])
        self.assertEqual(ids("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"), ["CS007"])


@unittest.skipUnless(HAVE_TS, "tree-sitter-javascript not installed")
class Negatives(unittest.TestCase):
    def test_parameterized_and_tagged_sql(self):
        self.assertEqual(ids(route("db.query('SELECT * FROM t WHERE a = ?', [req.query.a]);")), [])
        self.assertEqual(ids(route("const r = await sql`SELECT * FROM t WHERE a = ${req.query.a}`;")), [])

    def test_sanitizers_and_numeric_coercion(self):
        self.assertEqual(ids(route("const id = parseInt(req.query.id, 10);\ndb.query(`SELECT * FROM t WHERE id = ${id}`);")), [])
        self.assertEqual(ids(route("db.query('SELECT * FROM t WHERE id = ' + Number(req.query.id));")), [])
        self.assertEqual(ids(route("db.query('SELECT * FROM t LIMIT ' + +req.query.n);")), [])
        self.assertEqual(ids("el.innerHTML = DOMPurify.sanitize(location.hash);"), [])
        self.assertEqual(ids("el.innerHTML = encodeURIComponent(location.hash);"), [])

    def test_sanitized_in_one_branch_only_is_still_dangerous(self):
        src = route("let id = parseInt(req.query.id);\nif (req.query.raw) { id = req.query.raw; }\ndb.query('S ' + id);")
        self.assertEqual(sev(src, "CS002"), ["high"])

    def test_safe_apis(self):
        self.assertEqual(ids("el.textContent = location.hash;"), [])
        self.assertEqual(ids(route("res.render('v', { n: req.query.n });")), [])
        self.assertEqual(ids(route("res.json({ n: req.query.n });")), [])
        self.assertEqual(ids("const { execFile } = require('child_process');\nexecFile('ls', ['-l', process.argv[2]]);"), [])
        self.assertEqual(ids("eval('1+1'); setTimeout(() => go(), 1);"), [])
        self.assertEqual(ids(route("res.sendFile(req.query.f, { root: '/srv' });")), [])
        self.assertEqual(ids("const crypto = require('crypto');\ncrypto.createHash('sha256');"), [])

    def test_non_secrets_and_lookup_tables(self):
        self.assertEqual(ids("const tokenType = 'bearer'; const passwordField = 'password'; const secret = '';"), [])
        self.assertEqual(ids("const password = process.env.PW;"), [])
        self.assertEqual(ids("fetch(u, { credentials: 'include' });"), [])
        self.assertEqual(ids("const CMDS = { a: 'ls' };\nconst { exec } = require('child_process');\nexec(CMDS[process.argv[2]]);"), [])

    def test_local_named_request_module_is_not_a_source(self):
        self.assertEqual(ids("const request = require('request');\nrequest('https://example.com');"), [])


@unittest.skipUnless(HAVE_TS, "tree-sitter-javascript not installed")
class Misc(unittest.TestCase):
    def test_suppression_comments(self):
        self.assertEqual(ids("const crypto = require('crypto');\ncrypto.createHash('md5'); // nosec"), [])
        self.assertEqual(ids("const crypto = require('crypto');\ncrypto.createHash('md5'); // codecheck: ignore[CS005]"), [])
        self.assertEqual(ids("const crypto = require('crypto');\ncrypto.createHash('md5'); // codecheck: ignore[CS002]"), ["CS005"])

    def test_syntax_errors_do_not_crash(self):
        analyze_source("const = ;;; function (", "broken.js")

    def test_language_detection_and_cli_mixed_project(self):
        self.assertEqual(language_for("a.mjs"), "javascript")
        self.assertEqual(language_for("a.bundle.js"), "javascript")
        self.assertIsNone(language_for("a.txt"))
        with tempfile.TemporaryDirectory() as d:
            for name, body in (("a.py", "import os\nos.system(input())\n"),
                               ("b.js", "eval(location.hash);\n"),
                               ("c.min.js", "eval(location.hash);\n")):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(body)
            findings, errors = scan_paths([d])
            self.assertEqual(sorted(os.path.basename(f.file) for f in findings), ["a.py", "b.js"])  # c.min.js skipped
            self.assertEqual(errors, [])
            explicit, _ = scan_paths([os.path.join(d, "c.min.js")])  # ...but scanned when named explicitly
            self.assertEqual(len(explicit), 1)
            out = os.path.join(d, "r.json")
            self.assertEqual(main([d, "-f", "json", "-o", out]), 1)
            self.assertEqual(len(json.load(open(out))["findings"]), 2)


class MissingParser(unittest.TestCase):
    def test_message_when_tree_sitter_missing(self):
        import codecheck.js_analyzer as js
        from codecheck.core import MissingDependency
        saved, js._PARSER = js._PARSER, None
        real = sys.modules.get("tree_sitter_javascript")
        sys.modules["tree_sitter_javascript"] = None  # makes `import` raise ImportError
        try:
            with self.assertRaises(MissingDependency):
                analyze_source("eval(x)", "t.js")
        finally:
            js._PARSER = saved
            if real is not None:
                sys.modules["tree_sitter_javascript"] = real
            else:
                sys.modules.pop("tree_sitter_javascript", None)


if __name__ == "__main__":
    unittest.main()
