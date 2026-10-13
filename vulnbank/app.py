import hashlib
import os

import requests
import yaml
from flask import Flask, redirect, render_template, render_template_string, request, session, url_for

from vulnbank.db import DB_PATH, get_connection, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-dev-key-do-not-change-9f2b1a"

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")
RATES_URL = "https://api.exchangerate.host/latest?base=TND"


def load_config():
    with open(CONFIG_PATH) as handle:
        return yaml.load(handle.read())


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html", user=session.get("username"))

    username = request.form.get("username", "")
    password = hash_password(request.form.get("password", ""))

    conn = get_connection()
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    row = conn.execute(query).fetchone()
    conn.close()

    if row is None:
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
    rows = conn.execute(
        "SELECT owner, iban, balance FROM accounts WHERE owner LIKE '%" + owner + "%'"
    ).fetchall()
    conn.close()
    return render_template("index.html", accounts=rows, user=session.get("username"))


@app.route("/comment", methods=["POST"])
def comment():
    message = request.form.get("message", "")
    page = f"""
    <html><body>
      <h2>Merci pour votre retour</h2>
      <div class="note">{message}</div>
      <a href="/">Retour</a>
    </body></html>
    """
    return render_template_string(page)


@app.route("/export")
def export():
    account = request.args.get("account", "all")
    os.system(f"sqlite3 {DB_PATH} '.dump accounts' > /tmp/vulnbank_export_{account}.sql")
    return f"Export de {account} termine", 200


@app.route("/rates")
def rates():
    response = requests.get(RATES_URL, verify=False, timeout=10)
    return response.json()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
