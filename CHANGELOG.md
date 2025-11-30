# Changelog

All notable changes to the Authentik Credential Provider project.

## [Unreleased] - November 2025

### Major Discovery
- **Software KSP does NOT work for PKINIT** - Windows Kerberos SSP requires smart card-compatible providers
- **TPM Virtual Smart Card is the solution** - Emulates real smart card, enables true PKINIT

### Added
- `VSC-PKINIT-GUIDE.md` - Complete guide for TPM Virtual Smart Card authentication
- `KNOWLEDGE_BASE.md` - Comprehensive project knowledge documentation
- Important warning header in `CertificateHelper.cpp` about software KSP limitation
- Domain/username parsing from credential fields
- Microsoft Passport KSP support (experimental, doesn't work for PKINIT)

### Changed
- Updated `README.md` with current project status and VSC approach
- `CertificateHelper.cpp` - Added Passport KSP fallback, empty card/reader names

### Technical Findings
- `KERB_CERTIFICATE_LOGON` requires smart card KSP
- Certificate must have UPN in Subject Alternative Name for AD mapping
- VSC operations require console access (fail over RDP)
- TPM Virtual Smart Card recognized by Windows as legitimate smart card

### Tested Approaches (Results)
| Approach | Works for PKINIT |
|----------|------------------|
| Microsoft Software KSP | ❌ No |
| Microsoft Passport KSP | ❌ No |
| Custom AuthentikKSP | ❌ No |
| TPM Virtual Smart Card | ✅ Yes |

## [0.1.0] - November 2025 (Initial Development)

### Added
- Initial credential provider implementation
- Authentik API integration for OTP authentication
- Certificate helper for PKINIT structures
- Custom KSP project (AuthentikKSP) - experimental
- Build system and Visual Studio solution
- Documentation framework

### Infrastructure
- GitHub repository setup
- CI/CD workflow configuration
- Deployment scripts
