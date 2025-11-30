# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik/PrivacyIDEA Windows Credential Provider OTP authentication project. Use this as the single source of truth when starting a new project or resuming this one.

**Last Updated:** November 30, 2025  
**Project Status:** ✅ PKINIT Smart Card Authentication WORKING  
**Current Implementation:** True passwordless authentication via TPM Virtual Smart Card

---

## 🎉 MAJOR MILESTONE: PKINIT Smart Card Login Working!

As of November 30, 2025, we have achieved true passwordless Windows domain authentication using:
- TPM Virtual Smart Card (VSC)
- Certificate-based PKINIT authentication
- No password required for domain logon

**See [PKINIT_SMARTCARD_GUIDE.md](PKINIT_SMARTCARD_GUIDE.md) for complete implementation details.**

---

## Key Project Information

### Critical Success Factors

#### For OTP-based Authentication (Original Implementation)
1. **Credential Packing**: MUST use CoTaskMemAlloc for COM compatibility
2. **UNICODE_STRING**: Length is in BYTES (multiply by sizeof(WCHAR))
3. **State Management**: Two-step flow requires careful state tracking
4. **Debug Logging**: Essential for troubleshooting credential providers
5. **Windows Password**: Required for Kerberos - no true passwordless without certificates

#### For PKINIT Smart Card Authentication (NEW - Working!)
1. **UPN in SAN**: Certificate MUST have User Principal Name in Subject Alternative Name extension
2. **Single Certificate**: Only ONE certificate should exist on VSC to avoid selection issues
3. **Template Flag**: `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (0x02000000) is CRITICAL
4. **VSC Recreation**: Destroy and recreate VSC when changing certificates
5. **KB5014754 Compliance**: Strong certificate mapping requires UPN in SAN

### Architecture Overview

#### OTP Authentication Flow
- **Client**: Windows Credential Provider DLL (C++/COM)
- **Server**: Authentik (Python/Django) with LDAP backend
- **Domain**: Active Directory for user management and Kerberos

#### PKINIT Smart Card Flow (Recommended)
```
User → PIN → TPM VSC → Certificate → KDC (PKINIT) → TGT → Domain Logon
```
No password transmitted or required!

### Authentication Flows

#### Flow 1: OTP Authentication (Original)
1. User enters username + password
2. Credential Provider validates with Authentik
3. Authentik triggers OTP challenge
4. User enters OTP
5. Authentik validates OTP
6. Credential Provider packs username + password
7. Windows performs Kerberos authentication
8. User logged in

#### Flow 2: PKINIT Smart Card (NEW - Recommended)
1. User selects smart card login
2. User enters smart card PIN
3. TPM VSC provides certificate and signs challenge
4. Windows sends PKINIT AS-REQ to KDC
5. KDC validates certificate and maps to AD user
6. KDC issues TGT
7. User logged in (NO PASSWORD!)

### Critical Files

#### Credential Provider (OTP)
- **CredentialPacking.cpp** - KERB_INTERACTIVE_LOGON serialization
- **AuthentikCredential.cpp** - Two-step authentication logic
- **AuthentikAPI.cpp** - HTTP communication with Authentik
- **Dll.cpp** - COM registration and class factory

#### PowerShell Tools (PKINIT)
- **tools/Configure-SmartCardTemplate.ps1** - Certificate template configuration
- **tools/Enroll-SmartCardCertificate.ps1** - VSC certificate enrollment
- **tools/Diagnose-SmartCardAuth.ps1** - Troubleshooting diagnostics

### Working Configurations

#### OTP Configuration
```registry
HKLM\SOFTWARE\AuthentikCredentialProvider
ServerUrl = "authentik.test.local"
ServerPort = 443 (DWORD)
FlowSlug = "windows-otp-auth"
UseHttps = 1 (DWORD)
```

#### PKINIT Configuration
| Setting | Value |
|---------|-------|
| Template Name | AuthentikSmartcard |
| msPKI-Certificate-Name-Flag | 0x62000000 |
| Certificate Subject | E=user@domain, CN=user |
| Certificate SAN | Principal Name=user@domain |
| VSC Provider | Microsoft Base Smart Card Crypto Provider |
| Key Length | 2048 |
| EKUs | Smart Card Logon, Client Authentication |

### Common Issues & Solutions

#### OTP Issues

**Issue: LNK2019 errors**
- Solution: Add Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib

**Issue: Credential provider doesn't appear**
- Solution: Reboot after registration, check registry, verify x64 architecture

**Issue: LogonUI crashes**
- Solution: Validate KERB_INTERACTIVE_LOGON structure, check memory alignment

**Issue: SSL errors**
- Solution: Use valid certificate OR import self-signed cert to Trusted Root

#### PKINIT Issues

**Issue: Event 39 "Certificate could not be mapped to user"**
- Cause: Certificate doesn't have UPN in Subject Alternative Name
- Solution: Configure template with `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` flag

**Issue: Kerberos 0x19 with empty Client Realm/Name**
- Cause: Certificate not on smart card provider, PKINIT not being used
- Solution: Ensure certificate is on VSC, not software KSP

**Issue: "Credentials could not be verified" after PIN accepted**
- Cause: Multiple certificates on VSC, KDC selecting wrong one
- Solution: Destroy VSC and recreate with single certificate

**Issue: "The parameter is incorrect" after "Welcome" flash**
- Cause: Authentication succeeded but logon session failed
- Solution: Check for profile issues, verify single certificate

**Issue: tpmvscmgr fails over RDP**
- Cause: Terminal Services restriction
- Solution: Run from physical console or Proxmox VM console

### Security Checklist

#### OTP Implementation
- [ ] Enable SSL certificate validation in production
- [ ] Remove SECURITY_FLAG_IGNORE_* flags
- [ ] Use SecureZeroMemory for password cleanup
- [ ] Implement certificate pinning
- [ ] Set proper file/registry ACLs
- [ ] Code sign the DLL
- [ ] Encrypt API tokens with DPAPI

#### PKINIT Implementation
- [x] Certificate has UPN in SAN
- [x] Template uses AD-sourced subject information
- [x] Single certificate on VSC
- [x] Strong certificate mapping enabled (KB5014754)
- [ ] Consider altSecurityIdentities for explicit mapping
- [ ] Implement certificate lifecycle management
- [ ] Plan for certificate renewal automation

### Future Enhancements Priority

1. ~~Certificate-based authentication (PKINIT) - True passwordless~~ ✅ DONE!
2. **Authentik Integration** - API to request certificates from AD CS
3. **Auto-enrollment** - Automatic VSC provisioning via Authentik
4. Offline authentication support - Pre-fetched OTP codes
5. Proper JSON parsing library - Replace string matching
6. Enhanced logging - Windows Event Log integration
7. Biometric integration - Windows Hello support

### Testing Procedure

#### OTP Testing
1. Build: `msbuild /p:Configuration=Release /p:Platform=x64`
2. Copy: `copy AuthentikCredentialProvider.dll C:\Windows\System32\`
3. Register: `regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll`
4. Configure registry settings
5. Reboot
6. Test with DebugView running
7. Verify in Event Viewer

#### PKINIT Testing
1. Configure template: `.\Configure-SmartCardTemplate.ps1`
2. Create VSC (from console): `tpmvscmgr create /name "VSC" /pin PROMPT /adminkey random /generate`
3. Enroll certificate: `.\Enroll-SmartCardCertificate.ps1 -Username shop -CAConfig "DC\CA"`
4. Lock workstation: Win+L
5. Select smart card, enter PIN
6. If fails, run: `.\Diagnose-SmartCardAuth.ps1 -Target Both`

### Deployment Options
- Manual: Copy + regsvr32 (OTP) or PowerShell scripts (PKINIT)
- Group Policy: MSI deployment via GPO
- PowerShell: Deploy-AuthentikCP.ps1 script
- SCCM/Intune: Application deployment
- **Authentik Integration**: Future auto-provisioning

### Critical Lessons Learned

#### General
1. Always use CoTaskMemAlloc for COM interfaces
2. Windows caches credential providers - reboot after changes
3. DebugView is essential for troubleshooting
4. Start simple then enhance
5. Study reference implementations before writing code
6. Build security in from the start
7. Test on real hardware, not just VMs
8. Keep recovery plan (Safe Mode access)
9. Document everything - future you will thank present you

#### PKINIT Specific
10. **UPN in SAN is mandatory** - KB5014754 requires it for certificate mapping
11. **Single certificate per VSC** - Multiple certs cause selection issues
12. **Template flags matter** - `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` is critical
13. **VSC operations require console** - RDP/Terminal Services blocks tpmvscmgr
14. **Ghost certificates** - Reboot to clear cached entries
15. **Event 39 is your friend** - Check DC System log for mapping failures

### Test Environment Details

| Component | Value |
|-----------|-------|
| Domain | test.local |
| Domain Controller | WIN-6DP39D0OLI8.test.local |
| Certificate Authority | test-WIN-6DP39D0OLI8-CA |
| Workstation | TEST10 |
| Test User | shop@test.local |
| VSC PIN | 12345678 |

### Resources
- Microsoft: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows
- Authentik: https://goauthentik.io/docs/
- PrivacyIDEA: https://github.com/privacyidea/privacyidea-credential-provider
- Sample Code: https://github.com/Microsoft/Windows-classic-samples/tree/master/Samples/CredentialProvider
- KB5014754: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers

---

For complete details on PKINIT implementation, see [PKINIT_SMARTCARD_GUIDE.md](PKINIT_SMARTCARD_GUIDE.md).

**Document Version:** 2.0  
**Last Updated:** November 30, 2025  
**Status:** ✅ PKINIT Working

This knowledge base ensures no knowledge is lost when resuming or restarting this project.
