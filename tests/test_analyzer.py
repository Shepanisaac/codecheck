import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from codecheck import analyze_source  # noqa: E402
from codecheck.cli import main  # noqa: E402
from codecheck.report import to_sarif  # noqa: E402


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def ids(src):
    return sorted(f.rule_id for f in analyze_source(src))


def sev(src, rule):
    return [f.severity for f in analyze_source(src) if f.rule_id == rule]


class Positives(unittest.TestCase):
    def test_sql_taint_across_lines(self):
        src = "q = 'SELECT * FROM t WHERE a=' + input()\ncur.execute(q)\n"
        self.assertEqual(ids(src), ["CS002"])
        self.assertEqual(sev(src, "CS002"), ["high"])

    def test_sql_fstring_without_taint_is_medium(self):
        src = "def f(table):\n    cur.execute(f'SELECT * FROM {table}')\n"
        self.assertEqual(sev(src, "CS002"), ["medium"])

    def test_sql_percent_and_format(self):
        self.assertEqual(ids("cur.execute('SELECT %s' % name)"), ["CS002"])
        self.assertEqual(ids("cur.execute('SELECT {}'.format(name))"), ["CS002"])

    def test_eval_exec(self):
        self.assertEqual(sev("eval(input())", "CS001"), ["high"])
        self.assertEqual(sev("def f(x):\n    exec(x)", "CS001"), ["medium"])

    def test_command_injection_alias_resolution(self):
        src = "import os as o\no.system('ls ' + input())\n"
        self.assertEqual(ids(src), ["CS003"])
        src = "from subprocess import run\nrun(f'ls {input()}', shell=True)\n"
        self.assertEqual(ids(src), ["CS003"])

    def test_taint_through_branches_and_loops(self):
        src = ("import os\nx = ''\nfor a in range(2):\n    if a:\n        x = input()\n"
               "os.system(x)\n")
        self.assertEqual(ids(src), ["CS003"])

    def test_flask_url_param_is_tainted(self):
        src = ("@app.route('/f/<name>')\ndef f(name):\n    return open(name).read()\n")
        self.assertEqual(ids(src), ["CS009"])

    def test_reflected_xss(self):
        src = ("from flask import request\n@app.route('/')\n"
               "def f():\n    return '<b>' + request.args['x']\n")
        self.assertEqual(ids(src), ["CS011"])

    def test_deserialization(self):
        self.assertEqual(sev("import pickle\npickle.loads(input())", "CS006"), ["high"])
        self.assertEqual(ids("import yaml\nyaml.load(open('c').read())"), ["CS006"])

    def test_hardcoded_secrets(self):
        self.assertEqual(ids("api_key = 'abc123'"), ["CS004"])
        self.assertEqual(ids("cfg = {'password': 'hunter2'}"), ["CS004"])
        self.assertEqual(ids("connect(host='h', password='hunter2')"), ["CS004"])
        self.assertEqual(ids("apiKey = 'abc123'"), ["CS004"])

    def test_misc_rules(self):
        self.assertEqual(ids("import hashlib\nhashlib.sha1(b'x')"), ["CS005"])
        self.assertEqual(ids("import requests\nrequests.get('u', verify=False)"), ["CS007"])
        self.assertEqual(ids("app.run(debug=True)"), ["CS008"])
        self.assertEqual(ids("import random\ntoken = random.random()"), ["CS010"])
        self.assertEqual(ids("import requests\nrequests.get(input())"), ["CS012"])
        self.assertEqual(ids("import ssl\nctx.verify_mode = ssl.CERT_NONE"), ["CS007"])


class Negatives(unittest.TestCase):
    def test_parameterized_sql_is_clean(self):
        self.assertEqual(ids("cur.execute('SELECT * FROM t WHERE a=?', (input(),))"), [])

    def test_sanitizers_clear_taint(self):
        self.assertEqual(ids("import os\nos.system('kill ' + str(int(input())))"), [])
        self.assertEqual(ids("import os, shlex\nos.system('ls ' + shlex.quote(input()))"), [])
        self.assertEqual(ids("n = int(input())\ncur.execute(f'SELECT * FROM t WHERE id = {n}')"), [])

    def test_sanitized_in_one_branch_only_is_still_dangerous(self):
        src = ("import os\nx = int(input())\nif cond:\n    x = input()\n"
               "os.system('kill ' + x)\n")
        self.assertEqual(sev(src, "CS003"), ["high"])
        src = "import os\nx = int(input()) if c else 'a'\nx2 = x or input()\nos.system('k ' + x2)\n"
        self.assertEqual(sev(src, "CS003"), ["high"])

    def test_safe_apis(self):
        self.assertEqual(ids("import yaml\nyaml.safe_load(input())"), [])
        self.assertEqual(ids("import yaml\nyaml.load(input(), Loader=yaml.SafeLoader)"), [])
        self.assertEqual(ids("import ast\nast.literal_eval(input())"), [])
        self.assertEqual(ids("import subprocess\nsubprocess.run(['ls', input()])"), [])
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)"), [])
        self.assertEqual(ids("eval('1+1')"), [])

    def test_non_secrets(self):
        self.assertEqual(ids("token_type = 'bearer'\npassword_field = 'password'\nsecret = ''"), [])
        self.assertEqual(ids("password = os.environ['PW']"), [])

    def test_xss_not_reported_for_escaped_or_templated(self):
        src = ("from flask import request, render_template, jsonify\nimport html\n"
               "@app.route('/')\ndef f():\n"
               "    a = render_template('x.html', v=request.args['v'])\n"
               "    return html.escape(request.args['x'])\n")
        self.assertEqual(ids(src), [])

    def test_int_annotated_route_param_is_clean(self):
        src = "@app.route('/f/<int:n>')\ndef f(n: int):\n    return open('f%d' % n).read()\n"
        self.assertEqual(ids(src), [])

    def test_tainted_index_into_lookup_table_is_clean(self):
        self.assertEqual(ids("import os\nCMDS = {'a': 'ls'}\nos.system(CMDS[input()])"), [])


class Suppression(unittest.TestCase):
    def test_nosec_and_scoped_ignore(self):
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x')  # nosec"), [])
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x')  # codecheck: ignore[CS005]"), [])
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x')  # codecheck: ignore[CS002]"), ["CS005"])


class Reporting(unittest.TestCase):
    def test_sarif_structure(self):
        fs = analyze_source("import os\nos.system(input())\n", "a.py")
        doc = json.loads(to_sarif(fs))
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        r = run["results"][0]
        self.assertEqual(r["ruleId"], "CS003")
        self.assertEqual(run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"], "CS003")
        self.assertEqual(r["locations"][0]["physicalLocation"]["region"]["startLine"], 2)

    def test_cli_exit_codes_and_syntax_error(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.py")
            ok = os.path.join(d, "ok.py")
            broken = os.path.join(d, "broken.py")
            write(bad, "import os\nos.system(input())\n")
            write(ok, "x = 1\n")
            write(broken, "def (:\n")
            out = os.path.join(d, "r.sarif")
            self.assertEqual(main([bad, "-f", "sarif", "-o", out]), 1)
            self.assertEqual(main([bad, "--fail-on", "never", "-f", "json", "-o", out]), 0)
            self.assertEqual(main([ok, "-o", out]), 0)
            self.assertEqual(main([broken, "-o", out]), 2)  # parse error is not silently clean


if __name__ == "__main__":
    unittest.main()
