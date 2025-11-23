# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik/PrivacyIDEA Windows Credential Provider OTP authentication project. Use this as the single source of truth when starting a new project or resuming this one.

**Last Updated:** November 2025  
**Project Status:** Working prototype with fixed credential packing  
**Current Implementation:** Two-step OTP authentication with Authentik backend

---

**Due to length constraints, this is a summary. The full knowledge base is being created as a separate comprehensive document.**

## Key Project Information

### Critical Success Factors
1. **Credential Packing**: MUST use CoTaskMemAlloc for COM compatibility
2. **UNICODE_STRING**: Length is in BYTES (multiply by sizeof(WCHAR))
3. **State Management**: Two-step flow requires careful state tracking
4. **Debug Logging**: Essential for troubleshooting credential providers
5. **Windows Password**: Required for Kerberos - no true passwordless without certificates

### Architecture Overview
- **Client**: Windows Credential Provider DLL (C++/COM)
- **Server**: Authentik (Python/Django) with LDAP backend
- **Domain**: Active Directory for user management and Kerberos

### Authentication Flow
1. User enters username + password
2. Credential Provider validates with Authentik
3. Authentik triggers OTP challenge
4. User enters OTP
5. Authentik validates OTP
6. Credential Provider packs username + password
7. Windows performs Kerberos authentication
8. User logged in

### Critical Files
- **CredentialPacking.cpp** - KERB_INTERACTIVE_LOGON serialization (most critical)
- **AuthentikCredential.cpp** - Two-step authentication logic
- **AuthentikAPI.cpp** - HTTP communication with Authentik
- **Dll.cpp** - COM registration and class factory

### Known Working Configuration
```registry
HKLM\SOFTWARE\AuthentikCredentialProvider
ServerUrl = "authentik.test.local"
ServerPort = 443 (DWORD)
FlowSlug = "windows-otp-auth"
UseHttps = 1 (DWORD)
```

### Common Issues & Solutions

**Issue: LNK2019 errors**
- Solution: Add Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib

**Issue: Credential provider doesn't appear**
- Solution: Reboot after registration, check registry, verify x64 architecture

**Issue: LogonUI crashes**
- Solution: Validate KERB_INTERACTIVE_LOGON structure, check memory alignment

**Issue: SSL errors**
- Solution: Use valid certificate OR import self-signed cert to Trusted Root

### Security Checklist
- [ ] Enable SSL certificate validation in production
- [ ] Remove SECURITY_FLAG_IGNORE_* flags
- [ ] Use SecureZeroMemory for password cleanup
- [ ] Implement certificate pinning
- [ ] Set proper file/registry ACLs
- [ ] Code sign the DLL
- [ ] Encrypt API tokens with DPAPI

### Future Enhancements Priority
1. Certificate-based authentication (PKINIT) - True passwordless
2. Offline authentication support - Pre-fetched OTP codes
3. Proper JSON parsing library - Replace string matching
4. Enhanced logging - Windows Event Log integration
5. Biometric integration - Windows Hello support

### Testing Procedure
1. Build: `msbuild /p:Configuration=Release /p:Platform=x64`
2. Copy: `copy AuthentikCredentialProvider.dll C:\Windows\System32\`
3. Register: `regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll`
4. Configure registry settings
5. Reboot
6. Test with DebugView running
7. Verify in Event Viewer

### Deployment Options
- Manual: Copy + regsvr32
- Group Policy: MSI deployment via GPO
- PowerShell: Deploy-AuthentikCP.ps1 script
- SCCM/Intune: Application deployment

### Critical Lessons Learned
1. Always use CoTaskMemAlloc for COM interfaces
2. Windows caches credential providers - reboot after changes
3. DebugView is essential for troubleshooting
4. Start simple (concatenated) then enhance (two-step)
5. Study reference implementations before writing code
6. Build security in from the start, not later
7. Test on real hardware, not just VMs
8. Keep recovery plan (Safe Mode access)
9. Document everything - future you will thank present you

### Resources
- Microsoft: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows
- Authentik: https://goauthentik.io/docs/
- PrivacyIDEA: https://github.com/privacyidea/privacyidea-credential-provider
- Sample Code: https://github.com/Microsoft/Windows-classic-samples/tree/master/Samples/CredentialProvider

---

For complete details on implementation, architecture, security, deployment, and troubleshooting, refer to the full documentation in README.md and source code comments.

**Document Version:** 1.0  
**Last Updated:** November 22, 2025  

This knowledge base ensures no knowledge is lost when resuming or restarting this project.
