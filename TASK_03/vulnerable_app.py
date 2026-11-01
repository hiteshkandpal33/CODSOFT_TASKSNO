"""
vulnerable_app.py - a small user/notes service written WITH COMMON FLAWS ON PURPOSE.
It is the target of the security assessment in REPORT.md. Do not deploy it.
"""
import hashlib
import os
import pickle
import random
import sqlite3

SECRET_KEY = "supersecret123"            # hard-coded secret
ADMIN_PASSWORD = "admin@123"             # hard-coded credential
DB_PATH = "users.db"
NOTES_DIR = "notes/"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    db.commit()
    return db


def register(username, password, role="user"):
    pw_hash = hashlib.md5(password.encode()).hexdigest()          # weak, unsalted hash
    db = get_db()
    db.execute(f"INSERT INTO users (username, password, role) VALUES ('{username}', '{pw_hash}', '{role}')")  # SQL injection
    db.commit()


def login(username, password):
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{pw_hash}'"  # SQL injection
    return get_db().execute(query).fetchone()


def search_users(name):
    return get_db().execute("SELECT id, username FROM users WHERE username LIKE '%" + name + "%'").fetchall()  # SQL injection


def ping_host(host):
    return os.system("ping -c 1 " + host)                          # OS command injection


def read_note(filename):
    with open(NOTES_DIR + filename) as f:                          # path traversal
        return f.read()


def load_session(blob):
    return pickle.loads(blob)                                      # insecure deserialisation


def calculate(expression):
    return eval(expression)                                        # arbitrary code execution


def reset_token():
    return str(random.randint(100000, 999999))                     # predictable token


def check_admin(password):
    return password == ADMIN_PASSWORD                              # hard-coded, non-constant-time compare
