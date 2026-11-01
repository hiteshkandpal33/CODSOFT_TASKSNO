"""Proves each finding: the attack works on vulnerable_app and is blocked in secure_app.
Run:  python3 -m unittest -v test_security.py
Only harmless proof-of-concept inputs are used, inside a temporary directory."""
import importlib
import os
import pickle
import tempfile
import unittest
from pathlib import Path


def fresh(modname, tmp):
    os.environ["APP_DB_PATH"] = str(Path(tmp) / "t.db")
    os.environ["APP_NOTES_DIR"] = str(Path(tmp) / "notes")
    (Path(tmp) / "notes").mkdir(exist_ok=True)
    (Path(tmp) / "notes" / "ok.txt").write_text("hello")
    (Path(tmp) / "secret.txt").write_text("TOP-SECRET")
    mod = importlib.import_module(modname)
    mod = importlib.reload(mod)
    if modname == "vulnerable_app":
        mod.DB_PATH = str(Path(tmp) / "t.db")
        mod.NOTES_DIR = str(Path(tmp) / "notes") + "/"
    return mod


class Base:
    mod_name = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.m = fresh(self.mod_name, self.tmp.name)
        self.m.init_db()

    def tearDown(self):
        self.tmp.cleanup()


class TestVulnerable(Base, unittest.TestCase):
    mod_name = "vulnerable_app"

    def test_sql_injection_login_bypass(self):
        self.m.register("alice", "correct-horse")
        self.assertIsNotNone(self.m.login("alice' --", "wrong"))          # bypass works

    def test_privilege_escalation_via_role(self):
        self.m.register("mallory", "pw", role="admin")
        self.assertEqual(self.m.login("mallory", "pw")[2], "admin")

    def test_path_traversal(self):
        self.assertEqual(self.m.read_note("../secret.txt"), "TOP-SECRET")

    def test_eval_executes_code(self):
        self.assertEqual(self.m.calculate("__import__('os').getpid() > 0"), True)

    def test_pickle_executes_code(self):
        class P:
            def __reduce__(self):
                return (len, ("pwned",))                                # harmless callable
        self.assertEqual(self.m.load_session(pickle.dumps(P())), 5)

    def test_md5_unsalted(self):
        self.m.register("a", "same")
        self.m.register("b", "same")
        rows = self.m.get_db().execute("SELECT password FROM users").fetchall()
        self.assertEqual(rows[0], rows[1])                              # identical hashes


class TestSecure(Base, unittest.TestCase):
    mod_name = "secure_app"

    def test_login_ok_and_sqli_blocked(self):
        self.m.register("alice", "correct-horse-battery")
        self.assertIsNotNone(self.m.login("alice", "correct-horse-battery"))
        self.assertIsNone(self.m.login("alice' --", "wrong"))
        self.assertIsNone(self.m.login("alice", "wrong-password"))

    def test_role_cannot_be_admin(self):
        with self.assertRaises(ValueError):
            self.m.register("mallory", "long-enough-pw", role="admin")

    def test_invalid_username_rejected(self):
        with self.assertRaises(ValueError):
            self.m.register("x'; DROP TABLE users;--", "long-enough-pw")

    def test_salted_hashes_differ(self):
        self.m.register("aaa", "same-password-1")
        self.m.register("bbb", "same-password-1")
        rows = self.m.get_db().execute("SELECT password FROM users").fetchall()
        self.assertNotEqual(rows[0], rows[1])

    def test_search_escapes_wildcards(self):
        self.m.register("alice", "long-enough-pw")
        self.assertEqual(self.m.search_users("%"), [])
        self.assertEqual(len(self.m.search_users("ali")), 1)

    def test_path_traversal_blocked(self):
        self.assertEqual(self.m.read_note("ok.txt"), "hello")
        for bad in ("../secret.txt", "/etc/passwd", "..%2f..%2fsecret.txt"):
            with self.assertRaises((PermissionError, FileNotFoundError)):
                self.m.read_note(bad)

    def test_calculator_safe(self):
        self.assertEqual(self.m.calculate("2 + 3 * 4"), 14)
        for bad in ("__import__('os').getpid()", "open('x')", "().__class__"):
            with self.assertRaises((ValueError, SyntaxError)):
                self.m.calculate(bad)

    def test_json_session_only(self):
        self.assertEqual(self.m.load_session('{"u": 1}'), {"u": 1})
        with self.assertRaises(Exception):
            self.m.load_session(pickle.dumps({"u": 1}))

    def test_ping_rejects_injection(self):
        for bad in ("127.0.0.1; id", "$(id)", "-f", "a b", "x|y"):
            with self.assertRaises(ValueError):
                self.m.ping_host(bad)

    def test_tokens_random_and_long(self):
        t = {self.m.reset_token() for _ in range(50)}
        self.assertEqual(len(t), 50)
        self.assertTrue(all(len(x) >= 40 for x in t))

    def test_admin_closed_without_config(self):
        self.assertFalse(self.m.check_admin("admin@123"))


if __name__ == "__main__":
    unittest.main()
