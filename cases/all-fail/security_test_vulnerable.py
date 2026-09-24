# INTENTIONALLY VULNERABLE - exists only for CI testing of the security pipeline.
# Proves the Phase 2 scanner and the release gate block a known SQL injection pattern.
# Adapted from vibe-code-engineering tools/phase2-security-scanner/tests/fixtures/vulnerable-python/app.py.
# Not imported or served by app.py; in-memory database only; no secrets. Do not reuse this code.
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    conn = sqlite3.connect(":memory:")
    user_id = request.args.get("id")
    return str(conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall())
