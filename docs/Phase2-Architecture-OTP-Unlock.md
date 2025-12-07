# Phase 2: Custom KSP with OTP-Based Certificate Unlock

## Overview

Phase 2 implements true passwordless OTP authentication using a custom Key Storage Provider (KSP) that intercepts PIN verification and validates OTP with Authentik instead.

**Key Innovation:** The user's OTP code IS the unlock mechanism. No PIN is ever stored or managed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OTP = CERTIFICATE UNLOCK                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┐                                                       │
│   │  Windows Login  │                                                       │
│   │                 │                                                       │
│   │  Username: mike │                                                       │
│   │  OTP: [123456]  │  ← User enters OTP as "PIN"                          │
│   │                 │                                                       │
│   └────────┬────────┘                                                       │
│            │                                                                │
│            ▼                                                                │
│   ┌─────────────────┐                                                       │
│   │  Credential     │                                                       │
│   │  Provider       │                                                       │
│   │                 │                                                       │
│   │  Passes OTP as  │                                                       │
│   │  "PIN" to KSP   │                                                       │
│   └────────┬────────┘                                                       │
│            │                                                                │
│            ▼                                                                │
│   ┌─────────────────┐      ┌─────────────────┐                             │
│   │  Custom KSP     │─────>│  Authentik      │                             │
│   │  (AuthentikKSP) │      │                 │                             │
│   │                 │<─────│  Validate OTP   │                             │
│   │  Intercepts     │      │  Return ✓ or ✗  │                             │
│   │  NCryptSignHash │      │                 │                             │
│   └────────┬────────┘      └─────────────────┘                             │
│            │                                                                │
│            │ If OTP Valid                                                   │
│            ▼                                                                │
│   ┌─────────────────┐      ┌─────────────────┐                             │
│   │  Sign with      │─────>│  Domain         │                             │
│   │  Certificate    │      │  Controller     │                             │
│   │  (PKINIT)       │      │                 │                             │
│   │                 │      │  Validates Cert │                             │
│   │                 │      │  Issues TGT     │                             │
│   └─────────────────┘      └────────┬────────┘                             │
│                                     │                                       │
│                                     ▼                                       │
│                            ┌─────────────────┐                             │
│                            │  ✓ User Logged  │                             │
│                            │     In!         │                             │
│                            └─────────────────┘                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why This Is Better

| Aspect | Old (Stored PIN) | New (OTP = Unlock) |
|--------|------------------|-------------------|
| Secrets | Random PIN stored in Authentik | No secrets stored |
| Round trips | 2 (validate OTP, get PIN) | 1 (validate OTP) |
| Sync issues | PIN could get out of sync | Nothing to sync |
| Security | PIN could be compromised | OTP is one-time use |
| Complexity | PIN generation + storage | Simple validation |
| Revocation | Must delete stored PIN | Instant via Authentik |

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           COMPONENT STACK                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    AuthentikCredentialProvider.dll                   │   │
│  │  - Displays Username + OTP fields                                    │   │
│  │  - Builds KERB_CERTIFICATE_LOGON with OTP as "PIN"                  │   │
│  │  - Specifies AuthentikKSP as the CSP                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         AuthentikKSP.dll                             │   │
│  │  - Registered as Key Storage Provider                                │   │
│  │  - Stores certificate + private key                                  │   │
│  │  - Intercepts NCryptSignHash                                         │   │
│  │  - Validates OTP with Authentik before signing                       │   │
│  │  - If valid: performs cryptographic operation                        │   │
│  │  - If invalid: returns NTE_BAD_KEYSET                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Windows CNG / LSA                               │   │
│  │  - Routes to AuthentikKSP based on key container                     │   │
│  │  - Performs PKINIT with signed pre-auth data                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Custom KSP Implementation

### Required CNG Functions to Implement

```cpp
// KSP Registration and Info
NCRYPT_KEY_STORAGE_FUNCTION_TABLE AuthentikKSPFunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    KSPOpenProvider,
    KSPOpenKey,
    KSPCreatePersistedKey,
    KSPGetProviderProperty,
    KSPGetKeyProperty,
    KSPSetProviderProperty,
    KSPSetKeyProperty,
    KSPFinalizeKey,
    KSPDeleteKey,
    KSPFreeProvider,
    KSPFreeKey,
    KSPFreeBuffer,
    KSPEncrypt,
    KSPDecrypt,
    KSPIsAlgSupported,
    KSPEnumAlgorithms,
    KSPEnumKeys,
    KSPImportKey,
    KSPExportKey,
    KSPSignHash,              // ← KEY: Validate OTP here!
    KSPVerifySignature,
    KSPPromptUser,
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};
```

### Core OTP Validation Logic

```cpp
// KSPSignHash - Called when PKINIT needs to sign the pre-auth data
SECURITY_STATUS WINAPI KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in    PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __out   PBYTE pbSignature,
    __in    DWORD cbSignature,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    AUTHENTIK_KEY_CONTEXT* pKeyCtx = (AUTHENTIK_KEY_CONTEXT*)hKey;
    
    // Get the OTP that was passed as "PIN" during authentication
    std::wstring otp = pKeyCtx->currentOtp;
    std::wstring username = pKeyCtx->username;
    
    // Validate OTP with Authentik
    AuthentikAPI api;
    AuthentikResponse response = api.ValidateOTP(username, otp);
    
    if (!response.success)
    {
        LOG("OTP validation failed for user %S", username.c_str());
        return NTE_BAD_KEYSET;  // Or NTE_PERM, NTE_BAD_DATA
    }
    
    LOG("OTP validated successfully, performing signature");
    
    // OTP valid - perform actual cryptographic signature
    return PerformRSASignature(
        pKeyCtx->hActualKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        pcbResult,
        dwFlags);
}
```

### KSP Provider Structure

```cpp
// Provider context - one per NCryptOpenStorageProvider call
typedef struct _AUTHENTIK_PROVIDER_CONTEXT {
    DWORD cbLength;
    DWORD dwMagic;                    // Validation magic
    std::wstring authentikUrl;        // Authentik server URL
    std::wstring flowSlug;            // Authentication flow
    NCRYPT_PROV_HANDLE hBaseProvider; // Underlying MS Software KSP
} AUTHENTIK_PROVIDER_CONTEXT;

// Key context - one per key handle
typedef struct _AUTHENTIK_KEY_CONTEXT {
    DWORD cbLength;
    DWORD dwMagic;
    AUTHENTIK_PROVIDER_CONTEXT* pProvider;
    std::wstring keyName;
    std::wstring username;            // UPN from certificate
    std::wstring currentOtp;          // OTP passed as "PIN"
    NCRYPT_KEY_HANDLE hActualKey;     // Underlying key handle
} AUTHENTIK_KEY_CONTEXT;
```

---

## How OTP Gets to the KSP

### Option A: Via NCryptSetProperty with NCRYPT_PIN_PROPERTY

```cpp
// In Credential Provider - set the OTP as PIN before signing
NCryptSetProperty(
    hKey,
    NCRYPT_PIN_PROPERTY,
    (PBYTE)otpCode.c_str(),
    (DWORD)(otpCode.length() + 1) * sizeof(wchar_t),
    0);

// In KSP - intercept this property
SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags)
{
    if (wcscmp(pszProperty, NCRYPT_PIN_PROPERTY) == 0)
    {
        // Store OTP for later validation in SignHash
        AUTHENTIK_KEY_CONTEXT* pKeyCtx = (AUTHENTIK_KEY_CONTEXT*)hKey;
        pKeyCtx->currentOtp = std::wstring((LPCWSTR)pbInput);
        return ERROR_SUCCESS;
    }
    // ... handle other properties
}
```

### Option B: Via KERB_CERTIFICATE_LOGON PIN Field

The credential provider builds KERB_CERTIFICATE_LOGON with the OTP in the PIN field. Windows passes this to the KSP automatically.

```cpp
// Credential Provider builds:
KERB_CERTIFICATE_LOGON logon;
logon.MessageType = KerbCertificateLogon;
logon.Pin.Buffer = L"123456";  // OTP code
logon.Pin.Length = 12;         // bytes
// ... rest of structure
```

---

## Credential Provider Changes

### Field Changes

```cpp
// FieldDescriptors.h - No password field needed!
enum FIELD_ID
{
    FID_LOGO = 0,
    FID_LARGE_TEXT,
    FID_SMALL_TEXT,
    FID_USERNAME,
    FID_OTP,          // OTP code (was Password + OTP, now just OTP)
    FID_SUBMIT,
    FID_NUM_FIELDS
};
```

### GetSerialization Changes

```cpp
HRESULT CAuthentikCredential::GetSerialization(...)
{
    std::wstring username = _rgFieldStrings[FID_USERNAME];
    std::wstring otp = _rgFieldStrings[FID_OTP];
    
    // Build KERB_CERTIFICATE_LOGON with OTP as PIN
    return PackCertificateLogon(
        username,
        otp,                    // OTP goes in PIN field
        L"AuthentikKSP",        // Our custom KSP
        pcpgsr,
        pcpcs,
        ppwszOptionalStatusText,
        pcpsiOptionalStatusIcon);
}
```

---

## KSP Registration

### Registry Keys

```registry
; Register the KSP
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider]
"Image Path"="C:\\Windows\\System32\\AuthentikKSP.dll"
"Type"=dword:00000001

; KSP Configuration  
[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikKSP]
"ServerUrl"="authentik.test.local"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-otp-auth"
"UseHttps"=dword:00000001
```

### Installation Script

```powershell
# Install AuthentikKSP
Copy-Item AuthentikKSP.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikKSP.dll

# Or manual registration
$kspPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider"
New-Item -Path $kspPath -Force
Set-ItemProperty -Path $kspPath -Name "Image Path" -Value "C:\Windows\System32\AuthentikKSP.dll"
Set-ItemProperty -Path $kspPath -Name "Type" -Value 1
```

---

## Certificate Enrollment with Custom KSP

### Initial Certificate Enrollment

```powershell
# Create certificate request specifying AuthentikKSP
# INF file for certreq:
[NewRequest]
Subject = "CN=mike"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Authentik Key Storage Provider"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.4.1.311.20.2.2 ; Smart Card Logon
OID=1.3.6.1.5.5.7.3.2     ; Client Auth
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=mike@test.local"
```

### Enrollment via CertIssuer API

```cpp
// CertificateManager - enroll cert with our KSP
HRESULT CertificateManager::EnrollCertificate(const std::wstring& upn)
{
    // 1. Generate key pair in AuthentikKSP
    NCRYPT_PROV_HANDLE hProvider;
    NCryptOpenStorageProvider(&hProvider, L"Authentik Key Storage Provider", 0);
    
    NCRYPT_KEY_HANDLE hKey;
    NCryptCreatePersistedKey(hProvider, &hKey, BCRYPT_RSA_ALGORITHM, 
                             upn.c_str(), AT_KEYEXCHANGE, 0);
    NCryptFinalizeKey(hKey, 0);
    
    // 2. Create CSR
    // 3. Submit to CertIssuer API
    // 4. Import issued certificate
    
    return S_OK;
}
```

---

## Security Considerations

### OTP Security
- One-time use - cannot be replayed
- Short validity window (30-60 seconds for TOTP)
- Validated server-side by Authentik
- Never stored locally

### Key Security
- Private key generated in software (could use TPM backing)
- Key never exported
- Signing only after OTP validation

### Network Security
- All Authentik communication over HTTPS
- Certificate pinning recommended
- Timeout for OTP validation (prevent network delays being exploited)

### Failure Modes
- OTP timeout → login fails, user retries
- Authentik unreachable → fall back to other credential provider (if desired)
- Invalid OTP → NTE_BAD_KEYSET returned, login fails

---

## Implementation Plan

### Phase 2a: Custom KSP Foundation
1. Create KSP DLL project
2. Implement basic CNG interface (passthrough to MS Software KSP)
3. Register KSP on test system
4. Verify keys can be created and used

### Phase 2b: OTP Interception
1. Implement PIN capture in KSPSetKeyProperty
2. Implement OTP validation in KSPSignHash
3. Add Authentik API calls to KSP
4. Test with manual certificate + OTP

### Phase 2c: Credential Provider Integration
1. Modify credential provider to remove password field
2. Build KERB_CERTIFICATE_LOGON with OTP
3. Specify AuthentikKSP as provider
4. End-to-end testing

### Phase 2d: Certificate Lifecycle
1. Automatic enrollment on first login
2. Certificate renewal before expiry
3. Revocation handling

---

## File Structure

```
AuthentikCredentialProvider/
├── CredentialProvider/
│   ├── AuthentikCredential.cpp/.h
│   ├── AuthentikCredentialProvider.cpp/.h
│   ├── CertificateLogonPacking.cpp/.h   # KERB_CERTIFICATE_LOGON
│   ├── FieldDescriptors.h
│   ├── Dll.cpp
│   └── ...
│
├── AuthentikKSP/
│   ├── AuthentikKSP.cpp                  # Main KSP implementation
│   ├── KSPProvider.cpp/.h                # Provider functions
│   ├── KSPKey.cpp/.h                     # Key functions
│   ├── KSPCrypto.cpp/.h                  # Crypto operations
│   ├── OTPValidator.cpp/.h               # Authentik OTP validation
│   ├── AuthentikKSP.def                  # Exports
│   └── ...
│
├── Shared/
│   ├── AuthentikAPI.cpp/.h               # HTTP client (shared)
│   ├── Logger.h                          # Logging (shared)
│   └── Registry.cpp/.h                   # Config (shared)
│
└── Documentation/
    ├── KNOWLEDGE_BASE.md
    ├── Phase2-Architecture.md            # This file
    └── ...
```

---

## Testing Checklist

- [ ] KSP registers correctly
- [ ] Keys can be created in KSP
- [ ] Certificate enrollment works with KSP
- [ ] OTP is captured from PIN property
- [ ] Valid OTP allows signing
- [ ] Invalid OTP blocks signing with appropriate error
- [ ] Authentik timeout handled gracefully
- [ ] End-to-end login with username + OTP works
- [ ] Multiple users supported
- [ ] Certificate renewal works

---

**Version:** 2.0  
**Updated:** December 6, 2025  
**Architecture:** OTP = Certificate Unlock (Custom KSP)
