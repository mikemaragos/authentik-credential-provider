# Frequently Asked Questions (FAQ)

**Authentik Credential Provider - Common Questions**

---

## 🔐 Authentication & API

### Q: Do I need an API token to use the credential provider?

**A: NO!** ✅ 

The flow executor API (`/api/v3/flows/executor/{flow_slug}/`) is **public and requires no authentication**.

**Why?**
- The flow executor IS the authentication endpoint itself
- It would be impossible to authenticate if you needed to be authenticated first!
- You send credentials (username/password/OTP) TO this endpoint
- The endpoint validates them and returns success/failure

**What the credential provider sends:**
```http
POST /api/v3/flows/executor/windows-otp-auth/
Content-Type: application/json

{
  "uid_field": "username",
  "password": "password"
}
```

**NO authentication header, NO API token, NO bearer token needed!**

---

### Q: When DO I need API tokens in Authentik?

**A:** You need API tokens for **administrative operations**:

- Creating/modifying users: `/api/v3/core/users/`
- Creating/modifying groups: `/api/v3/core/groups/`
- Managing flows: `/api/v3/flows/`
- Admin operations: `/api/v3/admin/*`

**The credential provider does NOT use these endpoints**, so no tokens needed.

---

### Q: How do I test if the API is accessible?

**A:** Use PowerShell:

```powershell
# Test GET (should return flow info)
Invoke-RestMethod -Uri "https://authentik.test.local/api/v3/flows/executor/windows-otp-auth/"

# Test POST with credentials (should authenticate)
$body = @{
    uid_field = "testuser"
    password = "testpassword"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://authentik.test.local/api/v3/flows/executor/windows-otp-auth/" `
                   -Method POST `
                   -Body $body `
                   -ContentType "application/json"
```

**No authentication needed in these requests!**

---

## 🔧 Installation Issues

### Q: regsvr32 says "module could not be found" - what's wrong?

**A:** You're missing the **Visual C++ Redistributable**.

**Fix:**
```powershell
# Download and install
$url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\vc_redist.x64.exe"
Start-Process "$env:TEMP\vc_redist.x64.exe" -Args "/install /quiet /norestart" -Wait

# Try regsvr32 again
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

**This is the #1 most common installation issue!**

---

### Q: The credential provider tile doesn't appear on the lock screen

**A:** Check these in order:

1. **DLL registered?**
   ```powershell
   reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s
   # Look for: {8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}
   ```

2. **Registry configured?**
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider"
   ```

3. **Reboot?**
   Windows caches credential providers - you MUST reboot after installation.

4. **Check Event Viewer:**
   Look for errors in: Application and Services Logs → Microsoft → Windows → User Device Registration

---

### Q: How do I uninstall the credential provider?

**A:**
```powershell
# Run as Administrator
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll
del C:\Windows\System32\AuthentikCredentialProvider.dll

# Reboot
Restart-Computer
```

---

## 🌐 Network & Connectivity

### Q: I get SSL certificate errors - what do I do?

**A:** You have three options:

**Option 1: Disable SSL validation (TESTING ONLY):**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "IgnoreSslErrors" -Value 1 -Type DWord
```

**Option 2: Import self-signed certificate:**
```powershell
Import-Certificate -FilePath "authentik.cer" `
                   -CertStoreLocation "Cert:\LocalMachine\Root"
```

**Option 3: Use valid SSL certificate (PRODUCTION):**
Get a certificate from Let's Encrypt or your CA.

**⚠️ NEVER use IgnoreSslErrors=1 in production!**

---

### Q: Connection timeout when testing API

**A:** Check network connectivity:

```powershell
# Test DNS
Resolve-DnsName authentik.test.local

# Test TCP connection
Test-NetConnection -ComputerName authentik.test.local -Port 443

# Check firewall
# Ensure port 443 (or your configured port) is open
```

**Common causes:**
- Firewall blocking port 443
- DNS not resolving
- Authentik server not running
- Wrong port in registry

---

## 🔄 Authentik Configuration

### Q: How do I find my flow slug?

**A:** In Authentik Admin UI:

1. Go to **Flows & Stages** → **Flows**
2. Click on your flow (e.g., "Windows OTP Authentication")
3. Look at the **Slug** field (e.g., `windows-otp-auth`)
4. **This MUST match the registry setting exactly!**

```powershell
# Set in Windows registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "windows-otp-auth"
```

---

### Q: I get "Page not found" when accessing the flow URL

**A:** The flow doesn't exist or the slug is wrong.

**Check:**
1. Flow exists in Authentik (Flows & Stages → Flows)
2. Flow slug matches registry exactly (case-sensitive!)
3. Flow designation is "Authentication"
4. Flow is published/active

**Test in browser:**
```
https://your-authentik-server/if/flow/windows-otp-auth/
```

Should show login page, NOT 404.

---

### Q: Users can't enroll OTP - what's wrong?

**A:** OTP setup stage not configured.

**Fix:**
1. Create **Authenticator Setup Stage** (TOTP)
2. In **Authenticator Validation Stage**, set:
   - Configuration stage: (select the setup stage)
   - Not configured action: "Configure"
3. Users will be prompted to enroll on first login

---

## 👤 User Authentication

### Q: User authentication fails with "Invalid password"

**A:** Check:
- Password is correct (test in Authentik web UI)
- User exists in Authentik (Directory → Users)
- LDAP sync is working (Directory → Federation & Social login)
- User account is active/enabled

**Debug:**
Check Authentik logs:
```bash
docker-compose logs -f worker
```

---

### Q: OTP validation fails even with correct code

**A:** Time synchronization issue (TOTP requires accurate time).

**Fix:**
```powershell
# On Windows client
w32tm /resync

# Verify time
Get-Date
```

**Also check:**
- Time zone is correct
- NTP is configured
- Time matches Authentik server (within 30 seconds)

---

### Q: Can users log in without OTP?

**A:** Yes, if you configure it that way.

**Remove OTP requirement:**
1. Remove OTP validation stage from flow
2. Or make OTP optional in stage configuration

**But why would you want to?** OTP adds critical security!

---

## 🧪 Testing & Debugging

### Q: How do I see what's happening during authentication?

**A:** Use **DebugView** (from Sysinternals):

1. Download: https://docs.microsoft.com/sysinternals/downloads/debugview
2. Run as Administrator
3. Capture → Enable "Capture Win32" and "Capture Global Win32"
4. Filter: `AuthentikCP*`
5. Lock screen and try to log in
6. Watch the logs in real-time!

---

### Q: How do I test the API without locking the screen?

**A:** Use the PowerShell testing scripts:

```powershell
# Quick interactive test
.\Quick-Test-Auth.ps1

# Comprehensive test
.\Test-AuthentikAPI.ps1 -Username "test" -Password "pass"
```

Available in `/tools` directory or download from GitHub.

---

### Q: Authentication works via PowerShell but not on lock screen

**A:** Compare DebugView logs:

1. Run PowerShell test (note the response)
2. Run DebugView
3. Try lock screen authentication
4. Compare the responses in DebugView

**Common issues:**
- Different credentials being used
- Registry not read correctly by DLL
- DLL using cached/wrong configuration

**Fix:** Reboot after changing registry settings.

---

## 🔐 Security

### Q: Is it safe to use IgnoreSslErrors=1?

**A: NO!** Only for testing in isolated environments.

**Security risks:**
- Vulnerable to man-in-the-middle attacks
- Accepts any certificate (expired, wrong hostname, self-signed)
- Passwords could be intercepted

**Production alternative:**
- Use valid SSL certificate from trusted CA
- Or import self-signed CA to Windows Trusted Root

---

### Q: Are passwords sent securely?

**A:** Only if using HTTPS:
- **UseHttps=1** (default): Passwords encrypted via TLS ✅
- **UseHttps=0**: Passwords sent in PLAIN TEXT ❌ NEVER use in production!

**Always use HTTPS in production!**

---

### Q: Where are passwords stored?

**A:** **Nowhere!**

- Passwords are sent directly to Authentik
- Briefly cached in memory during two-step OTP flow
- Cleared with `SecureZeroMemory` after use
- Never written to disk
- Never logged (except in debug builds for troubleshooting)

---

## 📦 Deployment

### Q: Can I deploy this via Group Policy?

**A:** Yes!

**Method 1: Direct deployment:**
1. Copy DLL to `\\domain\SYSVOL\...\AuthentikCredentialProvider.dll`
2. Create GPO startup script:
   ```cmd
   copy \\domain\SYSVOL\...\AuthentikCredentialProvider.dll C:\Windows\System32\
   regsvr32 /s C:\Windows\System32\AuthentikCredentialProvider.dll
   ```
3. Configure registry via GPO preferences
4. Require reboot

**Method 2: MSI package (better):**
- Create MSI with install script
- Deploy via GPO Software Installation
- Automatic registry configuration

---

### Q: Can I use this with non-domain computers?

**A:** Yes! 

You need:
- User accounts in Authentik (not necessarily in AD)
- Authentik LDAP source OR native Authentik users
- Local admin to install credential provider
- Network access to Authentik server

**Works on:**
- Domain-joined computers ✅
- Workgroup computers ✅
- Azure AD joined ✅
- Home/personal computers ✅

---

### Q: Does this work with Azure AD / Entra ID?

**A:** Partially.

**What works:**
- Credential provider tile appears
- User authenticates with Authentik
- Local Windows login succeeds

**What doesn't work:**
- Azure AD SSO integration (requires different auth flow)
- Azure AD group policy
- Azure AD conditional access

**Recommendation:** 
Use native Azure AD MFA or Windows Hello for Azure AD joined machines.
Use this credential provider for hybrid/on-prem environments.

---

## 🎯 General

### Q: What Windows versions are supported?

**A:**
- ✅ Windows 10 (1903 or later)
- ✅ Windows 11 (all versions)
- ✅ Windows Server 2019
- ✅ Windows Server 2022
- ❌ Windows 8.1 or earlier (not tested)

**Architecture:**
- ✅ x64 (64-bit) - fully supported
- ❌ x86 (32-bit) - not supported
- ❌ ARM - not tested

---

### Q: Can I customize the tile appearance?

**A:** Limited customization:

**What you can change:**
- Tile title: Edit `FID_LARGE_TEXT` in source code
- Tile description: Edit `FID_SMALL_TEXT` in source code
- Then rebuild and redeploy

**What you can't change (without major code changes):**
- Logo/icon
- Colors/theme
- Layout

---

### Q: Can I contribute to this project?

**A: YES!** 🎉

**How to contribute:**
1. Fork the repository on GitHub
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Areas that need work:**
- Certificate-based authentication (PKINIT)
- Proper JSON parsing library
- Enhanced error messages
- Multi-domain support
- Biometric integration

---

### Q: Where can I get help?

**A:**

**Documentation:**
- Read all docs in `/docs` directory
- Start with AUTHENTIK_SETUP_GUIDE.md

**Testing:**
- Use `Quick-Test-Auth.ps1` to test API
- Use DebugView to see logs
- Check Windows Event Viewer

**Community:**
- GitHub Issues: https://github.com/mikemaragos/authentik-credential-provider/issues
- Authentik Discord: https://goauthentik.io/discord

**Before asking:**
- [ ] Read documentation
- [ ] Run PowerShell test scripts
- [ ] Capture DebugView logs
- [ ] Check Authentik server logs
- [ ] Verify registry configuration

---

## 📊 Status & Roadmap

### Q: Is this production-ready?

**A:** **Yes, with caveats:**

**Production-ready features:**
- ✅ Two-step OTP authentication
- ✅ LDAP/AD integration
- ✅ Configurable via registry
- ✅ Proper credential packing
- ✅ Secure password handling

**Known limitations:**
- Password still required (can't do true passwordless without certificates)
- No offline authentication
- Simple JSON parsing (string matching)
- SSL validation can be disabled (should only be used for testing)

**Production checklist:**
- [ ] Use valid SSL certificate
- [ ] Don't use IgnoreSslErrors=1
- [ ] Test thoroughly in lab first
- [ ] Have rollback plan ready
- [ ] Train helpdesk staff
- [ ] Monitor logs after deployment

---

### Q: What's planned for future versions?

**A:** Potential enhancements:

**High Priority:**
- Certificate-based authentication (PKINIT) - true passwordless
- Proper JSON parsing library
- Offline OTP validation

**Medium Priority:**
- Enhanced error messages
- Windows Hello integration
- Password synchronization service
- Multi-domain support

**Low Priority:**
- Custom branding/theming
- Biometric support
- Smart card integration

**Want to help?** Contributions welcome!

---

**Document Version:** 1.0  
**Last Updated:** November 23, 2025

**Still have questions?** Check the full documentation or open a GitHub issue!
