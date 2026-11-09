"""Deliberately vulnerable Flask app used to demo CodeCheck. DO NOT deploy."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)
DB_PASSWORD = "hunter2-prod"                      # CS004 hardcoded credential
SECRET_KEY = os.environ.get("SECRET_KEY", "")     # fine: from environment


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")   # CS002 (tainted)
    return str(cur.fetchall())


@app.route("/user/<int:uid>")
def get_user_safe(uid: int):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))          # safe: parameterized
    return {"rows": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = subprocess.check_output(f"ping -c1 {host}", shell=True)    # CS003 (tainted)
    return out


@app.route("/calc")
def calc():
    return str(eval(request.form["expr"]))                           # CS001 (tainted)


@app.route("/hello")
def hello():
    return "<h1>Hello " + request.args.get("n", "") + "</h1>"        # CS011 reflected XSS


@app.route("/hello2")
def hello_safe():
    return render_template("hello.html", n=request.args.get("n"))    # safe: auto-escaped


@app.route("/page")
def page():
    tpl = "<p>" + request.args.get("t", "") + "</p>"
    return render_template_string(tpl)                               # CS011 SSTI


@app.route("/file")
def read_file():
    path = os.path.join("/srv/files", request.args["f"])
    with open(path) as fh:                                           # CS009 path traversal
        return fh.read()


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text      # CS012 SSRF + CS007


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)                                 # CS006 (tainted)
    cfg = yaml.load(request.data)                                    # CS006 (tainted)
    safe = yaml.safe_load(request.data)                              # safe
    return str((obj, cfg, safe))


def make_token():
    session_token = str(random.randint(0, 10**9))                    # CS010 weak randomness
    return session_token


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()                             # CS005 weak hash


def ok_suppressed(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # nosec - non-security checksum


if __name__ == "__main__":
    app.run(debug=True)                                              # CS008 debug mode
