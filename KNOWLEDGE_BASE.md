# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik Windows Credential Provider OTP authentication project.

**Last Updated:** December 6, 2025  
**Project Status:** Phase 1 Complete, Phase 2 In Progress  
**Architecture:** Custom KSP with OTP-based certificate unlock

---

## Project Phases

### Phase 1: Infrastructure Validation ✅ COMPLETE
- TPM Virtual Smart Card working
- Certificate enrollment to VSC working  
- PKINIT authentication to AD working
- Auto UPN mapping (StrongCertificateBindingEnforcement=0)

### Phase 2: Custom KSP Implementation 🔄 IN PROGRESS
- Custom Key Storage Provider (AuthentikKSP)
- OTP validation replaces PIN verification
- User enters username + OTP only
- No stored secrets

---

## Architecture (Phase 2)

```
User: [Username] [OTP Code]
         │
         ▼
┌─────────────────────┐
│ Credential Provider │ → OTP passed as "PIN"
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐      ┌─────────────┐
│   AuthentikKSP      │─────>│  Authentik  │
│   (Custom KSP)      │      │  Validate   │
│                     │<─────│  OTP        │
│   NCryptSignHash    │      └─────────────┘
│   intercepts PIN    │
└──────────┬──────────┘
           │ If OTP Valid
           ▼
┌─────────────────────┐      ┌─────────────┐
│   Sign PKINIT       │─────>│   Domain    │
│   Pre-Auth Data     │      │ Controller  │
└─────────────────────┘      │   TGT ✓     │
                             └─────────────┘
```

### Why OTP = Unlock?

| Old Approach | New Approach |
|--------------|--------------|
| Store random PIN in Authentik | No secrets stored |
| Retrieve PIN after OTP | OTP IS the unlock |
| Two round trips | Single validation |
| PIN could leak | OTP is one-time |

---

## Environment Configuration

### Domain
| Component | Value |
|-----------|-------|
| Domain | test.local |
| DC | WIN-6DP39D0OLI8 |
| CA | test-WIN-6DP39D0OLI8-CA |
| CA Config | `WIN-6DP39D0OLI8\test-WIN-6DP39D0OLI8-CA` |

### Certificate Template: AuthentikSmartcard
- EKU: Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
- EKU: Client Authentication (1.3.6.1.5.5.7.3.2)
- SAN: User Principal Name
- Key: 2048-bit RSA, AT_KEYEXCHANGE

### DC Registry
```powershell
# Auto UPN mapping (no manual altSecurityIdentities needed)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
    -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord
```

---

## Custom KSP Technical Details

### CNG Interface

```cpp
// Key function - validates OTP before signing
SECURITY_STATUS WINAPI KSPSignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID *pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    // Get OTP from key context (was set via NCRYPT_PIN_PROPERTY)
    std::wstring otp = GetKeyOTP(hKey);
    std::wstring username = GetKeyUsername(hKey);
    
    // Validate with Authentik
    if (!ValidateOTPWithAuthentik(username, otp))
    {
        return NTE_BAD_KEYSET;
    }
    
    // OTP valid - perform signature
    return ActualSignHash(...);
}
```

### KSP Registration

```registry
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider]
"Image Path"="C:\\Windows\\System32\\AuthentikKSP.dll"
"Type"=dword:00000001
```

### KERB_CERTIFICATE_LOGON Structure

```cpp
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon = 13
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;                   // ← OTP goes here!
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;                       // KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON;
```

### KERB_SMARTCARD_CSP_INFO Structure

```cpp
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;       // 1
    DWORD flags;
    DWORD KeySpec;           // AT_KEYEXCHANGE = 1
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;    // "Authentik Key Storage Provider"
    TCHAR bBuffer[];
} KERB_SMARTCARD_CSP_INFO;
```

---

## API Integration

### CertIssuer API
- **URL:** certissuer.test.local:8443
- **Token:** dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC
- **Purpose:** Certificate enrollment

### Authentik API
- **URL:** authentik.test.local:443
- **Flow:** windows-otp-auth
- **Purpose:** OTP validation

---

## File Structure (Target)

```
authentik-credential-provider/
├── CredentialProvider/
│   ├── AuthentikCredential.cpp/.h
│   ├── AuthentikCredentialProvider.cpp/.h
│   ├── CertificateLogonPacking.cpp/.h
│   ├── FieldDescriptors.h
│   └── Dll.cpp
│
├── AuthentikKSP/
│   ├── AuthentikKSP.cpp
│   ├── KSPProvider.cpp/.h
│   ├── KSPKey.cpp/.h
│   ├── OTPValidator.cpp/.h
│   └── AuthentikKSP.def
│
├── Shared/
│   ├── AuthentikAPI.cpp/.h
│   └── Logger.h
│
└── Docs/
    ├── KNOWLEDGE_BASE.md
    └── Phase2-Architecture-OTP-Unlock.md
```

---

## Diagnostic Commands

### Workstation
```powershell
# View certificates on smart card/VSC
certutil -scinfo

# View user certificates
certutil -user -store My

# Check TPM
Get-Tpm
```

### Domain Controller
```powershell
# Verify KDC certificate
certutil -dcinfo verify

# Check NTAuth store
certutil -viewstore -enterprise NTAuth

# View auth events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4771} -MaxEvents 10
```

---

## Common Issues

### KDC_ERR_CLIENT_NOT_TRUSTED (0x42)
- **Cause:** Certificate mapping issue
- **Fix:** Enable auto UPN mapping or add altSecurityIdentities

### NTE_BAD_KEYSET
- **Cause:** VSC corrupted or OTP invalid (in our KSP)
- **Fix:** Recreate VSC or check OTP

### Template Not Visible
- **Cause:** Wrong CA config or firewall
- **Fix:** Use `SERVER\CA-Name` format, check RPC ports

---

## Security Notes

### Production Checklist
- [ ] Re-evaluate StrongCertificateBindingEnforcement
- [ ] Enable HTTPS certificate validation
- [ ] Implement certificate pinning
- [ ] Add rate limiting for OTP validation
- [ ] Enable audit logging
- [ ] Code sign all DLLs

### OTP Security
- One-time use (TOTP/HOTP)
- 30-60 second validity
- Server-side validation only
- Never stored locally

---

## Next Steps

1. **Implement AuthentikKSP** - CNG key storage provider
2. **OTP interception** - Capture PIN, validate with Authentik
3. **Update Credential Provider** - Remove password, add OTP field
4. **Certificate enrollment** - Auto-enroll via CertIssuer
5. **End-to-end testing** - Full login flow

---

**Version:** 3.0  
**Last Updated:** December 6, 2025
