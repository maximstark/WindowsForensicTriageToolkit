# Contributing to Windows Forensic Triage Toolkit

Thank you for considering contributing. This guide explains how to get involved.

## How to Contribute

### Reporting False Positives
The most valuable contributions are false positive reports. If a module flags something that is normal Windows behavior, please open an issue with:
- The module number and finding title
- The Windows version (e.g., Windows 11 24H2)
- Why the finding is a false positive (e.g., "Event 4648 from SYSTEM account is routine")
- A suggested fix if you have one

### Adding Detection Rules
If you know of a forensic indicator the toolkit should check for, open an issue describing the indicator, which event log or registry key it lives in, why it matters, and what "normal" looks like for that indicator.

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b fix/module02-false-positive`
3. Make your changes in the `src/` directory
4. Test by running the affected module(s) on at least one Windows 10 or 11 machine
5. Run the build script to verify compilation: `.\build.ps1`
6. Submit a pull request with a clear description of what changed and why

### Code Style
- PowerShell modules use `PascalCase` for functions, `$camelCase` for local variables, `$UPPER_CASE` for constants
- Every finding must include `WhyItMatters` and `WhyMightBeNormal` explanations
- Severity levels must be justified — RED is for things that are almost always malicious, YELLOW for things that warrant investigation, INFO for context

### Testing
- Test on both Windows 10 and Windows 11 if possible
- Test with and without Administrator privileges
- Test on machines with non-English locales if you can (encoding edge cases)
- Verify the build script produces a working .exe

## What We're Looking For

- False positive fixes (highest priority)
- New detection modules or checks within existing modules
- Improvements to the HTML report styling and usability
- Documentation improvements
- GitHub Actions CI/CD improvements
- Code signing setup documentation

## What We Won't Accept

- Any change that writes to the registry, modifies files, or installs software on the target system
- Network calls beyond reverse DNS lookups for IP identification
- Dependencies on external tools or software that must be installed separately
- Obfuscated or minified code — everything must be readable and auditable

## Code of Conduct

Be respectful, constructive, and security-conscious. This tool is used in sensitive contexts and contributions should reflect that responsibility.
