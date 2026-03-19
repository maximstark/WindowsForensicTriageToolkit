# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this toolkit, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: [YOUR_EMAIL_HERE]

Include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact
- A suggested fix if you have one

You should receive a response within 72 hours. We take security issues seriously — this is a security tool, after all.

## Scope

Security issues we care about include:
- The toolkit inadvertently modifying the target system (violating read-only guarantee)
- The .exe wrapper extracting scripts to an insecure location where they could be tampered with
- False negatives — failing to detect a known forensic indicator
- Information disclosure in report output that could aid an attacker

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | Yes       |
| < 1.5   | No        |

## Verification

All release binaries include `checksums.json` with SHA256 hashes of embedded scripts. Always verify downloads against these checksums, and ideally build from source for maximum trust.
