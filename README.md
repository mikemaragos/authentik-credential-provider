# Authentik Credential Provider for Windows

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.0-blue.svg)]()

Windows Credential Provider that integrates with Authentik for OTP-based domain authentication.

## 🚀 Features

- ✅ Two-step OTP authentication (Username/Password → OTP)
- ✅ Integration with Authentik authentication server  
- ✅ Support for TOTP, SMS, Email, and other OTP methods
- ✅ Windows domain authentication
- ✅ **Production-ready security:**
  - SSL/TLS certificate validation
  - Input validation and sanitization
  - Rate limiting and brute force protection
  - Secure password handling
  - DPAPI encryption for sensitive configuration

## 📋 Status

- **Current Version:** 2.0
- **Status:** Active Development
- **Platform:** Windows 10/11, Server 2019/2022

## 📚 Documentation

- [Executive Summary](docs/EXECUTIVE_SUMMARY.md)
- [Implementation Guide](docs/development/IMPLEMENTATION_GUIDE.md)
- [Knowledge Base](KNOWLEDGE_BASE.md)
- [Quick Start](QUICKSTART.md)

## 🛠️ Building

```bash
git clone https://github.com/mikemaragos/authentik-credential-provider.git
cd authentik-credential-provider
# Open src/AuthentikCredentialProvider.sln in Visual Studio
# Build → Build Solution (Release, x64)
```

## 📦 Installation

```powershell
# Run as Administrator
.\tools\Setup-GitHubRepository.ps1
```

See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.

## 🗺️ Roadmap

- [x] Phase 1: Security Hardening
- [ ] Phase 2: Quality Improvements  
- [ ] Phase 3: Enterprise Features
- [ ] Phase 4: Advanced Features

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

**Version 2.0** | [Changelog](CHANGELOG.md) | [Docs](docs/)
