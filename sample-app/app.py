"""A deliberately vulnerable service: each flaw is planted for the scanners."""
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    db = sqlite3.connect("users.db")
    # PLANT sql-injection: user input concatenated into SQL.
    rows = db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # PLANT command-injection: user input in a shell command.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/config", methods=["POST"])
def config():
    # PLANT unsafe-deserialization: yaml.load without a safe loader.
    return {"config": yaml.load(request.data, Loader=yaml.Loader)}
