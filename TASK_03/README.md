# Task 3 – Secure Code Assessment

| File | Purpose |
|---|---|
| `vulnerable_app.py` | Target application – contains common flaws **on purpose** (do not deploy) |
| `static_scan.py` | Small stdlib AST-based static analyser (flags CWE-mapped issues) |
| `REPORT.md` | **The assessment report**: findings, severity, CWE/OWASP mapping, fixes, secure-coding recommendations |
| `secure_app.py` | Remediated version of the application |
| `test_security.py` | 17 tests: attacks succeed on the vulnerable app, fail on the secure one |

```bash
python3 static_scan.py vulnerable_app.py          # 13 findings
python3 static_scan.py secure_app.py              # 0 findings
python3 -W ignore -m unittest -v test_security.py # 17 tests pass
```

For real projects, also run industry tools such as **Bandit** (`pip install bandit && bandit -r .`) or **Semgrep**.
