# Secure Code Assessment Report

**Project:** CodSoft Cyber Security Internship – Task 3
**Target:** `vulnerable_app.py` (Python 3, ~70 lines: user registration/login, user search, ping utility, notes reader, session loader, calculator, reset tokens)
**Method:** (1) automated static analysis with `static_scan.py` (a stdlib AST scanner written because Bandit could not be installed in the build environment), and (2) a manual line-by-line security review against the OWASP Top 10 and CWE Top 25.
**Verification:** `test_security.py` – 17 automated tests. Each exploit is demonstrated against the vulnerable code and shown to be blocked in `secure_app.py`.

## 1. Summary

| Severity | Count | Issues |
|---|---|---|
| High | 9 | SQL injection ×3, OS command injection, insecure deserialisation, `eval` code execution, hard-coded secrets ×2, broken access control (role self-assignment) |
| Medium | 5 | Weak/unsalted MD5 password hashing ×2, path traversal, predictable reset token, no password/input policy |
| Low | 3 | Non-constant-time secret comparison, user-enumeration timing, unclosed DB connections |

The static scanner reported 13 findings (8 High, 4 Medium, 1 Low). The remaining items (role self-assignment, missing validation, timing, resource handling) required manual review – a good example of why automated tools alone are not enough.

After remediation `secure_app.py` has **0** scanner findings and all attack tests fail as intended.

## 2. Findings and fixes

### F1 – SQL Injection (High) · CWE-89 · OWASP A03 Injection
**Where:** `register()`, `login()`, `search_users()`
**Problem:** SQL is assembled with f-strings/concatenation, so input like `alice' --` comments out the password check and logs in as `alice` without the password (proved in `test_sql_injection_login_bypass`).
**Fix:** parameterised queries (`WHERE username = ?`), strict username validation, and escaping of `LIKE` wildcards.
```python
# before
f"SELECT ... WHERE username = '{username}' AND password = '{pw_hash}'"
# after
db.execute("SELECT id, username, role, salt, password FROM users WHERE username = ?", (username,))
```

### F2 – OS Command Injection (High) · CWE-78 · A03
**Where:** `ping_host()` – `os.system("ping -c 1 " + host)`
**Problem:** `127.0.0.1; <command>` runs a second command through the shell.
**Fix:** validate the host as an IP/hostname, reject leading `-`, call `subprocess.run([...], shell=False)` with an argument list and `--`, and apply a timeout.

### F3 – Insecure Deserialisation (High) · CWE-502 · A08 Software & Data Integrity Failures
**Where:** `load_session()` – `pickle.loads(blob)`
**Problem:** pickle can run arbitrary code while loading. A malicious session blob gives remote code execution (test uses a harmless callable to prove the call is executed).
**Fix:** use `json.loads` (data only) and validate the result's type; sign sessions (e.g. HMAC) if they travel through the client.

### F4 – Arbitrary Code Execution via `eval()` (High) · CWE-95 · A03
**Where:** `calculate()`
**Problem:** any Python expression runs, e.g. `__import__('os')...`.
**Fix:** parse with `ast` and evaluate only an allow-list of numeric nodes and arithmetic operators; limit input length.

### F5 – Hard-coded Credentials / Secrets (High) · CWE-798 · A07 Identification & Authentication Failures
**Where:** `SECRET_KEY`, `ADMIN_PASSWORD`
**Problem:** anyone with the source (or repository history) knows the admin password.
**Fix:** load secrets from environment variables / a secrets manager, store only a salted scrypt hash for the admin credential, and fail closed when not configured (`check_admin` returns `False`). Rotate the exposed values and add `.env` to `.gitignore`.

### F6 – Broken Access Control: self-assigned role (High) · CWE-269 / CWE-285 · A01 Broken Access Control
**Where:** `register(username, password, role="user")`
**Problem:** the caller chooses the role, so anyone can register as `admin` (`test_privilege_escalation_via_role`).
**Fix:** allow-list of self-service roles (`user`, `editor`); admin accounts are created only through a separate, trusted process.

### F7 – Weak Password Storage (Medium) · CWE-327 / CWE-916 · A02 Cryptographic Failures
**Where:** `register()`, `login()` – unsalted MD5
**Problem:** identical passwords give identical hashes (`test_md5_unsalted`), and MD5 is extremely fast to brute-force or look up in rainbow tables.
**Fix:** per-user random salt and a memory-hard KDF (`hashlib.scrypt`; Argon2id or bcrypt are equally good with a library). Minimum password length enforced.

### F8 – Path Traversal (Medium) · CWE-22 · A01
**Where:** `read_note()`
**Problem:** `../secret.txt` escapes the notes directory and reads other files (`test_path_traversal`).
**Fix:** resolve the final path and require that it stays inside the base directory; reject everything else.

### F9 – Predictable Reset Token (Medium) · CWE-330 · A02
**Where:** `reset_token()` – `random.randint(100000, 999999)`
**Problem:** the Mersenne Twister is not cryptographically secure and the space is only 900,000 values.
**Fix:** `secrets.token_urlsafe(32)`; store only a hash of the token, set a short expiry, make it single-use.

### F10 – Missing Input Validation & Password Policy (Medium) · CWE-20 · A04 Insecure Design
**Problem:** no limits on usernames, password length, or expression size.
**Fix:** regex allow-list for usernames, 10-character minimum password, size limits.

### F11 – Non-constant-time Comparison & User Enumeration (Low) · CWE-208
**Problem:** `password == ADMIN_PASSWORD` leaks timing information; `login()` returns faster for unknown users than for wrong passwords.
**Fix:** `hmac.compare_digest`; hash a dummy value for unknown users to even out timing.

### F12 – Resource Handling (Low) · CWE-404
**Problem:** database connections are opened for every call and never closed (visible as `ResourceWarning`s in tests).
**Fix:** use `with sqlite3.connect(...)` / a connection pool in a production version.

## 3. Secure coding practices recommended

1. **Never trust input** – validate with allow-lists, encode/escape on output.
2. **Parameterise** all database queries; never build SQL, shell commands or file paths from raw input.
3. **Avoid dangerous functions:** `eval`, `exec`, `pickle`, `os.system`, `shell=True`.
4. **Least privilege & deny by default** for roles and file access; enforce authorisation on the server.
5. **Use proven crypto:** `secrets` for randomness, scrypt/Argon2/bcrypt for passwords, no home-made schemes.
6. **Keep secrets out of code** – environment/secret manager, rotate when leaked, scan commits (e.g. gitleaks).
7. **Fail closed** and avoid leaking details in error messages; log security events.
8. **Automate checks in CI:** Bandit/Semgrep for static analysis, `pip-audit` for dependencies, plus unit tests for abuse cases (like `test_security.py`).
9. **Review and test** – peer code review and periodic penetration tests.

## 4. How to reproduce

```bash
python3 static_scan.py vulnerable_app.py     # 13 findings
python3 static_scan.py secure_app.py         # 0 findings
python3 -W ignore -m unittest -v test_security.py   # 17 tests pass
```

## 5. Limitations

- The scanner is a small heuristic tool; it can miss issues and produce false positives. Use Bandit/Semgrep on real projects.
- The sample is a small teaching application; real applications would also need authentication/session management, rate limiting and account lockout, HTTPS, CSRF/XSS protection, dependency scanning and logging, which are out of scope here.
- `ping_host` was validated by unit tests for rejected input only; it was not exercised against a network.
