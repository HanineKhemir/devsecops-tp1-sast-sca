import os
import re
import tempfile

import requests
import yaml
from flask import Flask, redirect, render_template, request, session, url_for

from vulnbank.db import get_connection, init_db
from vulnbank.security import hash_password, verify_password

app = Flask(__name__)
# FIX (secret): read from the environment instead of hardcoding it in source.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(24).hex()

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")
RATES_URL = "https://api.exchangerate.host/latest?base=TND"
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def load_config():
    with open(CONFIG_PATH) as handle:
        # FIX (yaml): safe_load cannot instantiate arbitrary Python objects.
        return yaml.safe_load(handle.read())


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html", user=session.get("username"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_connection()
    # FIX (SQLi): parameterized query — the value never becomes SQL syntax.
    row = conn.execute(
        "SELECT id, username, role, password FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row is None or not verify_password(row["password"], password):
        return render_template("index.html", error="Identifiants invalides"), 401

    session["username"] = row["username"]
    session["role"] = row["role"]
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/accounts")
def accounts():
    owner = request.args.get("owner", "")
    conn = get_connection()
    # FIX (SQLi): the LIKE pattern is passed as a bound parameter.
    rows = conn.execute(
        "SELECT owner, iban, balance FROM accounts WHERE owner LIKE ?",
        (f"%{owner}%",),
    ).fetchall()
    conn.close()
    return render_template("index.html", accounts=rows, user=session.get("username"))


@app.route("/comment", methods=["POST"])
def comment():
    message = request.form.get("message", "")
    # FIX (XSS): render through a template so Jinja2 auto-escapes the input.
    return render_template("comment.html", message=message)


@app.route("/export")
def export():
    account = request.args.get("account", "all")
    # FIX (command injection): validate input and dump via the DB API — no shell.
    if not ACCOUNT_NAME.match(account):
        return "Nom de compte invalide", 400
    export_path = os.path.join(
        tempfile.gettempdir(), f"vulnbank_export_{account}.sql"
    )
    conn = get_connection()
    with open(export_path, "w") as handle:
        for line in conn.iterdump():
            handle.write(line + "\n")
    conn.close()
    return f"Export de {account} termine", 200


@app.route("/rates")
def rates():
    # FIX (TLS): certificate validation stays enabled (default verify=True).
    response = requests.get(RATES_URL, timeout=10)
    return response.json()


if __name__ == "__main__":
    init_db()
    # FIX (debug/bind): both come from the environment; safe defaults for local.
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=5000, debug=debug)
