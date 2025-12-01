# Authentik Credential Provider - Session Summary
## Date: November 30, 2025

---

## 🎉 MAJOR ACCOMPLISHMENTS THIS SESSION

### 1. Certificate Issuer Service - FULLY WORKING ✅
- REST API on port 8443 running as Windows Service
- Successfully issues certificates from AD CS
- Auto-starts on boot via NSSM

**Service Location:** `C:\ProgramData\Authentik\CertIssuer\`
**Main Script:** `FullCertService.ps1`
**Config:** `config.json`

**API Token:** `dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC`

**Test Commands:**
```powershell
# Health check
Invoke-RestMethod http://localhost:8443/health

# Issue certificate
$headers = @{ Authorization = "Bearer dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC" }
$body = @{ username = "shop" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8443/api/v1/issue-certificate" -Method POST -Headers $headers -Body $body -ContentType "application/json"
```

### 2. Credential Provider DLL - BUILT SUCCESSFULLY ✅
- Compiles in Visual Studio 2022
- Registered on TEST10 workstation
- Shows up at logon screen
- Debug output visible in DebugView

**Build:** Release | x64
**Output:** `x64\Release\AuthentikCredentialProvider.dll`

### 3. VSC Created on TEST10 ✅
- TPM Virtual Smart Card created
- Device: `ROOT\SMARTCARDREADER\0001`
- PIN: `12345678`

### 4. Authentik Flow Created (Partial) ⚠️
- Flow `windows-smartcard-auth` needs to be configured
- Need identification stage + OTP validation stage
- User `shop` needs TOTP device configured

---

## CURRENT STATUS

| Component | Status |
|-----------|--------|
| Certificate Template (AuthentikSmartcard) | ✅ Working |
| Certificate Issuer Service | ✅ Running on DC |
| Credential Provider DLL | ✅ Built & Registered |
| Registry Settings | ✅ Configured on TEST10 |
| VSC on TEST10 | ✅ Created |
| Authentik Flow | ⚠️ Needs configuration |
| TOTP for shop user | ⚠️ Needs setup |
| End-to-end test | ❌ Not yet |

---

## TEST ENVIRONMENT

| Component | Value |
|-----------|-------|
| Domain | test.local |
| DC | WIN-6DP39D0OLI8.test.local |
| CA | test-WIN-6DP39D0OLI8-CA |
| Workstation | TEST10 |
| Test User | shop@test.local |
| VSC PIN | 12345678 |
| Cert Issuer Port | 8443 |
| API Token | dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC |
| Authentik Server | authentik.test.local (192.168.1.114) |

---

## REGISTRY SETTINGS (on TEST10)

Path: `HKLM\SOFTWARE\AuthentikCredentialProvider`

```
ServerUrl = authentik.test.local
ServerPort = 443 (DWORD)
FlowSlug = windows-smartcard-auth
UseHttps = 1 (DWORD)
CertIssuerUrl = WIN-6DP39D0OLI8.test.local
CertIssuerPort = 8443 (DWORD)
CertIssuerToken = dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC
Domain = test.local
UPNSuffix = @test.local
```

---

## KNOWN ISSUES TO FIX

### 1. Username Field Shows Label
- Field shows "Username" text instead of being empty
- User has to delete before typing
- Need to fix field initialization in AuthentikCredential.cpp

### 2. Missing Logo/Icon
- Authentik icon not displaying on logon tile
- Need to verify resource.rc and icon embedding

### 3. Authentik Flow Not Responding
- Flow `windows-smartcard-auth` returns error
- Need to complete Authentik configuration

---

## NEXT STEPS FOR NEXT SESSION

### Priority 1: Complete Authentik Configuration
1. Create/verify flow `windows-smartcard-auth`
2. Add Identification Stage (username only)
3. Add Authenticator Validation Stage (TOTP)
4. Configure shop user with TOTP device
5. Test flow via API

### Priority 2: Fix Credential Provider Issues
1. Fix username field initialization (empty by default)
2. Fix icon/logo display
3. Test full authentication flow

### Priority 3: End-to-End Test
1. Lock workstation (Win+L)
2. Select Authentik tile
3. Enter username → OTP → PIN
4. Verify certificate issuance and PKINIT login

---

## FILES IN GITHUB REPOSITORY

https://github.com/mikemaragos/authentik-credential-provider

### Source Files (src/AuthentikCredentialProvider/)
- AuthentikAPI.cpp/h - API client
- AuthentikCredential.cpp/h - Credential tile
- AuthentikCredentialProvider.cpp/h - Main provider
- SmartCardHelper.cpp/h - VSC operations
- FieldDescriptors.h - UI fields
- Dll.cpp - DLL entry points
- guid.h/cpp - GUIDs
- authentik.ico - Logo icon

### Tools
- FullCertService.ps1 - Certificate issuer service
- AuthentikCertService.ps1 - NSSM wrapper
- Install-CertIssuerNative.ps1 - Native installer
- Configure-SmartCardTemplate.ps1 - Template setup
- Diagnose-SmartCardAuth.ps1 - Troubleshooting

### Documentation
- KNOWLEDGE_BASE.md - Complete project knowledge
- PKINIT_SMARTCARD_GUIDE.md - PKINIT configuration
- TODO.md - Task tracking
- README.md - Project overview

---

## AUTHENTIK FLOW CONFIGURATION NEEDED

### Flow: windows-smartcard-auth

**Stage 1: Identification**
- Type: Identification Stage
- Name: windows-identification
- User fields: Username only
- Order: 10

**Stage 2: OTP Validation**
- Type: Authenticator Validation Stage
- Name: windows-otp-validation
- Device classes: TOTP Authenticators
- Not configured action: Deny
- Order: 20

### User Setup
- User: shop
- Needs: TOTP authenticator device configured
- Use: Google Authenticator, Authy, etc.

---

## QUICK START FOR NEXT SESSION

```powershell
# On DC - Verify cert issuer is running
Get-Service AuthentikCertIssuer
Invoke-RestMethod http://localhost:8443/health

# On TEST10 - Verify VSC exists
certutil -scinfo

# On TEST10 - Test credential provider
taskkill /f /im LogonUI.exe
# Then press Win+L

# View debug output
# Run DebugView as admin, filter for "AuthentikPwdlessCP"
```

---

## CONTACT/CONTEXT

- User: Mike (approaching retirement, Windows enterprise specialist)
- Project: Passwordless domain authentication via Authentik + Smart Cards
- Goal: Username → OTP → Certificate → PIN → PKINIT login (no password)
- Repository: https://github.com/mikemaragos/authentik-credential-provider

---

*Session ended due to context limit. Continue in next conversation.*
