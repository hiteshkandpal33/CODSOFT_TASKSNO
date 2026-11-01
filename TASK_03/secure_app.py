"""
secure_app.py - the same service as vulnerable_app.py with every finding in REPORT.md fixed.
Standard library only.
"""
import ast
import hashlib
import hmac
import ipaddress
import json
import operator
import os
import re
import secrets
import sqlite3
import subprocess
from pathlib import Path

# Secrets come from the environment, never from source code.
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")   # hex of scrypt hash
ADMIN_SALT = os.environ.get("ADMIN_SALT", "")                     # hex salt
DB_PATH = os.environ.get("APP_DB_PATH", "users.db")
NOTES_DIR = Path(os.environ.get("APP_NOTES_DIR", "notes")).resolve()

ALLOWED_ROLES = {"user", "editor"}          # 'admin' can never be self-assigned
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
               "salt TEXT, password TEXT, role TEXT)")
    db.commit()
    return db


def hash_password(password, salt):
    # scrypt: memory-hard, salted, in the standard library
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def register(username, password, role="user"):
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("invalid username")
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    if role not in ALLOWED_ROLES:
        raise ValueError("invalid role")
    salt = secrets.token_bytes(16)
    db = get_db()
    db.execute("INSERT INTO users (username, salt, password, role) VALUES (?, ?, ?, ?)",
               (username, salt.hex(), hash_password(password, salt).hex(), role))
    db.commit()


def login(username, password):
    row = get_db().execute("SELECT id, username, role, salt, password FROM users WHERE username = ?",
                           (username,)).fetchone()
    if row is None:
        hash_password(password, b"\x00" * 16)          # keep timing similar for unknown users
        return None
    candidate = hash_password(password, bytes.fromhex(row[3]))
    if hmac.compare_digest(candidate, bytes.fromhex(row[4])):
        return row[:3]
    return None


def search_users(name):
    like = "%" + name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    return get_db().execute("SELECT id, username FROM users WHERE username LIKE ? ESCAPE '\\'",
                            (like,)).fetchall()


def ping_host(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME_RE.fullmatch(host) or host.startswith("-"):
            raise ValueError("invalid host")
    # argument list, no shell, '--' stops option injection
    return subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, timeout=10, check=False).returncode


def read_note(filename):
    path = (NOTES_DIR / filename).resolve()
    if NOTES_DIR not in path.parents:                  # must stay inside the notes directory
        raise PermissionError("access denied")
    return path.read_text()


def load_session(blob):
    data = json.loads(blob)                            # data only, no code execution
    if not isinstance(data, dict):
        raise ValueError("invalid session")
    return data


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.USub: operator.neg, ast.UAdd: operator.pos}


def calculate(expression):
    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.operand))
        raise ValueError("unsupported expression")
    if len(expression) > 200:
        raise ValueError("expression too long")
    return ev(ast.parse(expression, mode="eval"))


def reset_token():
    return secrets.token_urlsafe(32)                   # cryptographically secure


def check_admin(password):
    if not ADMIN_PASSWORD_HASH or not ADMIN_SALT:
        return False
    cand = hash_password(password, bytes.fromhex(ADMIN_SALT))
    return hmac.compare_digest(cand, bytes.fromhex(ADMIN_PASSWORD_HASH))
