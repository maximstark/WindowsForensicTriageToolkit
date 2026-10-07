# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this toolkit, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private reporting: open this repository's **Security** tab, then choose **Report a vulnerability**.

Include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact
- A suggested fix if you have one

## Scope

Security issues we care about include:
- The toolkit modifying the target system (violating the read-only guarantee)
- Tampering with the embedded scripts between extraction and execution, or bypassing the integrity check
- Content in a scanned machine's data (task names, history lines, file paths) that executes or injects when a report is opened
- False negatives: failing to detect a known forensic indicator
- Information disclosure in report output that could aid an attacker

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

Versions before 2.0 extracted scripts to the user's `%TEMP%` before running them elevated, and did not HTML-encode finding text. Please upgrade.

## Verification

All release binaries include `checksums.json`, with the SHA-256 of every embedded script. The same hashes are compiled into the exe, which verifies its scripts before each module runs. The result is shown on the app's About page. For maximum trust, build from source with `.\build.ps1` and compare `checksums.json`.

Each scan folder ends with a `manifest.json` holding the SHA-256 of every report file, so a copied evidence folder can be checked with **Export ▸ Verify folder**.
