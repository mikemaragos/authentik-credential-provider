# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it privately.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead:

1. **Email:** Send details to the project maintainer
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Status Updates:** Every week until resolved
- **Fix Timeline:** Depends on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Security Best Practices

When using this credential provider:

1. **Always use HTTPS** - Never disable SSL validation in production
2. **Keep updated** - Use the latest version
3. **Validate configuration** - Use strong settings
4. **Monitor logs** - Check for suspicious activity
5. **Limit access** - Only authorized administrators should configure
6. **Use strong credentials** - For Authentik server access
7. **Regular audits** - Review security settings periodically

### Known Security Considerations

#### Version 2.0+
- ✅ SSL certificate validation enabled
- ✅ Input validation and sanitization
- ✅ Rate limiting for brute force protection
- ✅ Secure password handling

#### Version 1.0 (DEPRECATED - DO NOT USE)
- ❌ SSL certificate validation disabled
- ❌ No rate limiting
- ❌ Insecure password handling

**UPGRADE TO 2.0+ IMMEDIATELY IF STILL USING 1.0**

### Security Features

This credential provider implements:

- **SSL/TLS validation** - Proper certificate chain validation
- **Input sanitization** - Protection against injection attacks
- **Rate limiting** - Configurable brute force protection
- **Secure memory** - Automatic password zeroing (SecureZeroMemory)
- **DPAPI encryption** - Windows Data Protection API for sensitive config

### Threat Model

**In Scope:**
- Credential interception
- Brute force attacks
- Code injection
- Memory dumps
- Configuration tampering

**Out of Scope:**
- Physical access to machine
- Compromised Authentik server
- Kernel-level attacks
- Side-channel attacks

### Compliance

This project aims to comply with:
- OWASP Secure Coding Practices
- Microsoft Security Development Lifecycle
- CWE Top 25 Most Dangerous Software Weaknesses

## Hall of Fame

Security researchers who responsibly disclosed vulnerabilities:

*None yet - be the first!*

## Contact

For security concerns: Check repository for contact information

Thank you for helping keep this project secure! 🔒
