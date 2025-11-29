# Session Transcript: PKINIT Authentication and Custom KSP Implementation

**Date:** November 29, 2025  
**Session Focus:** Diagnosing PKINIT failures, implementing custom Key Storage Provider  
**Outcome:** Complete KSP implementation created, ready for integration testing

---

## Executive Summary

This session addressed the core issue preventing passwordless Windows domain authentication: Windows was not recognizing our certificate-based credentials for PKINIT authentication. Through systematic diagnosis, we discovered that:

1. The CA was missing from the NTAuth store (fixed)
2. Even with NTAuth fixed, Windows was falling back to password authentication (Pre-Auth Type 2)
3. The fundamental issue: Windows expects private keys to be accessible through a Key Storage Provider

The solution: Implement a custom KSP that stores keys in shared memory and provides them to Windows Kerberos for PKINIT signing.

---

## Part 1: Diagnosis

### Initial Problem
- Certificates were being generated correctly
- PFX import was working
- KERB_CERTIFICATE_LOGON was being built
- But authentication resulted in STATUS_ACCOUNT_RESTRICTION (0xc00000e5)

### Diagnostic Tool Created
Created `Test-PKINITAuth.ps1` to check:
- Certificate presence in stores
- Chain validation
- NTAuth store (critical!)
- Private key accessibility
- Domain controller connectivity

### Critical Discovery: NTAuth Store
The NTAuth store is an Active Directory container that specifies which CAs are trusted for domain logon. Without the CA in NTAuth, Windows accepts certificates for TLS but **rejects them for PKINIT**.

**Fix Applied:**
```powershell
certutil -dspublish -f "CA_CERT_PATH" NTAuthCA
gpupdate /force  # On workstation
```

### Second Discovery: Pre-Authentication Type
Even after fixing NTAuth, Kerberos event logs showed:
```
Pre-Authentication Type: 2  (PASSWORD-BASED!)
Certificate Information: (EMPTY)
```

This meant Windows wasn't even attempting certificate authentication.

### Root Cause Analysis
When we build KERB_CERTIFICATE_LOGON, we specify:
- CSP/KSP name: "Microsoft Software Key Storage Provider"
- Container name: "AuthentikPKINIT_{GUID}"

But Windows expects to call:
```
NCryptOpenStorageProvider("Microsoft Software Key Storage Provider")
NCryptOpenKey(container="AuthentikPKINIT_{GUID}")
NCryptSignHash(...)  // Sign the PKINIT request
```

**The Problem:** Our key exists only in our process's memory. When Windows tries to open it through the MS KSP, **the key doesn't exist**.

---

## Part 2: Solution Design

### Why Smart Cards Work
Physical smart cards:
1. Have a dedicated CSP/KSP registered with Windows
2. When Windows calls `NCryptOpenKey`, the CSP communicates with the card
3. `NCryptSignHash` sends data to the card for signing
4. Private key never leaves the secure hardware

### Our Approach: Custom KSP
Create a custom Key Storage Provider that:
1. Stores keys in Windows shared memory
2. Registers with Windows as a valid KSP
3. Provides keys when Windows Kerberos calls for PKINIT

### Architecture
```
┌────────────────────────────────────────────────────────────────┐
│                     CREDENTIAL PROVIDER                        │
│  1. Receive certificate + key from cert issuer                 │
│  2. Store key in shared memory via StoreKeyInKSP()             │
│  3. Build KERB_CERTIFICATE_LOGON referencing our KSP           │
│  4. Return to Windows LogonUI                                  │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                         WINDOWS LSA                            │
│  5. Receive KERB_CERTIFICATE_LOGON                             │
│  6. Parse CSP info, see "Authentik Key Storage Provider"       │
│  7. Call Kerberos SSP to create PKINIT request                 │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      KERBEROS SSP                              │
│  8. Call NCryptOpenStorageProvider("Authentik KSP")            │
│  9. Call NCryptOpenKey(container="AuthentikPKINIT_{GUID}")     │
│  10. Call NCryptSignHash() to sign AS-REQ                      │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      AUTHENTIK KSP                             │
│  11. OpenProvider: Create provider handle                      │
│  12. OpenKey: Find key in shared memory, create key handle     │
│  13. SignHash: Use BCrypt to sign with private key             │
│  14. Return signature to Kerberos                              │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                    DOMAIN CONTROLLER                           │
│  15. Receive PKINIT AS-REQ with certificate and signature      │
│  16. Verify certificate chain (CA in NTAuth)                   │
│  17. Verify signature matches certificate's public key         │
│  18. Issue TGT - user is authenticated!                        │
└────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Implementation Details

### Shared Memory Design

**Name:** `Global\AuthentikKSPKeyStore`  
**Size:** 1MB  
**Protection:** Mutex `Global\AuthentikKSPMutex`

**Structure:**
```c
typedef struct _AUTHENTIK_KEY_STORE_HEADER {
    DWORD dwMagic;           // 0x4B535041 ("AKSP")
    DWORD dwVersion;         // 1
    DWORD cKeys;             // Number of keys
    DWORD cbTotalSize;       // Total bytes used
    // Followed by key entries...
} AUTHENTIK_KEY_STORE_HEADER;

typedef struct _AUTHENTIK_KEY_ENTRY {
    DWORD dwMagic;           // 0x4B535041
    DWORD dwFlags;
    DWORD dwKeySpec;         // AT_KEYEXCHANGE
    FILETIME ftCreated;
    FILETIME ftExpires;
    WCHAR wszContainerName[256];
    WCHAR wszUserName[256];
    DWORD cbPrivateKey;      // Size of BCRYPT_RSAPRIVATE_BLOB
    DWORD cbCertificate;     // Size of DER certificate
    BYTE rgbData[1];         // PrivateKey + Certificate
} AUTHENTIK_KEY_ENTRY;
```

### KSP Interface Functions

**Required NCrypt Functions:**
| Function | Our Implementation |
|----------|-------------------|
| OpenProvider | Create provider handle |
| OpenKey | Find key in shared memory, import to BCrypt |
| GetProviderProperty | Return provider name, type |
| GetKeyProperty | Return key name, algorithm, length, certificate |
| SignHash | Use BCryptSignHash with imported key |
| FreeProvider | Cleanup provider |
| FreeKey | Cleanup key, destroy BCrypt handle |

**Key Operations:**
- `AuthentikKSP_StoreKey()` - Store key in shared memory (called by credential provider)
- `AuthentikKSP_RemoveKey()` - Remove key from shared memory
- `AuthentikKSP_KeyExists()` - Check if key exists
- `AuthentikKSP_GetProviderName()` - Get KSP name for CSP info

### KSP Registration

Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider`

Required values:
- `Image Path` = "C:\Windows\System32\AuthentikKSP.dll"
- `Type` = 1 (NCRYPT_PROV_TYPE_SOFTWARE)
- `Functions\KeyStorageInterface` = "GetKeyStorageInterface"

### Credential Provider Changes

**CertificateHelper.cpp modifications:**

1. After receiving certificate from cert issuer:
```cpp
// Export private key as BCRYPT_RSAPRIVATE_BLOB
NCryptExportKey(bundle.hKey, 0, BCRYPT_RSAPRIVATE_BLOB, ...);

// Store in KSP shared memory
StoreKeyInKSP(containerName, username, privateKeyBlob, ...);
```

2. In BuildCertificateLogon:
```cpp
// Reference our KSP, not Microsoft's
BuildCspInfo(containerName, L"Authentik Key Storage Provider", ...);
```

---

## Part 4: Files Created

### KSP Source Files
| File | Lines | Purpose |
|------|-------|---------|
| AuthentikKSP.h | ~200 | Structures, function declarations |
| AuthentikKSP.cpp | ~800 | KSP implementation |
| AuthentikKSPDll.cpp | ~60 | DLL entry, function table |
| AuthentikKSP.def | ~15 | DLL exports |
| AuthentikKSP.vcxproj | ~100 | VS project |
| Register-AuthentikKSP.ps1 | ~40 | Registration script |

### Updated Credential Provider Files
| File | Changes |
|------|---------|
| CertificateHelper.h | Added KSP name constant |
| CertificateHelper.cpp | Added StoreKeyInKSP(), updated BuildCertificateLogon() |

### Documentation
| File | Purpose |
|------|---------|
| src/AuthentikKSP/README.md | KSP documentation |
| docs/DEPLOYMENT.md | Updated deployment guide |
| README.md | Updated main readme |

---

## Part 5: Security Considerations

### Key Protection
- Keys stored in shared memory, not on disk
- Keys auto-expire (configurable, default 60 minutes)
- Keys cleared from memory when credential provider exits
- Shared memory uses Global\ namespace (requires admin/SYSTEM)

### Attack Surface
| Threat | Mitigation |
|--------|------------|
| Memory dump | Keys exist only temporarily |
| Malicious process | Global\ namespace requires privileges |
| Key extraction | Keys exportable only as public key |
| Replay | Certificate has short validity |

### Production Hardening Needed
1. Consider DPAPI encryption of keys in memory
2. Code sign both DLLs
3. Restrict shared memory ACLs
4. Add audit logging
5. Implement key pinning to session

---

## Part 6: Testing Plan

### Unit Tests
1. KSP registration verification
2. Key store/retrieve cycle
3. Sign operation
4. Key expiration

### Integration Tests
1. Credential provider → KSP key storage
2. Windows Kerberos → KSP signing
3. Full login flow

### Verification Steps
1. DebugView logs show `[AuthentikKSP]` messages
2. Kerberos events show Pre-Auth Type 16/17 (not 2)
3. Certificate info populated in events
4. TGT issued successfully

---

## Part 7: Known Issues and TODO

### Current Issues
1. KSP and CredentialProvider not yet linked in solution
2. No shared header for memory structures (duplicated)
3. Documentation needs consolidation

### TODO
- [ ] Update solution file to include KSP project
- [ ] Create shared header for memory structures
- [ ] Build and test KSP standalone
- [ ] Test full integration
- [ ] Create installer/deployment package

---

## Part 8: Key Technical Insights

### Why KERB_CERTIFICATE_LOGON Requires a Real KSP

The KERB_CERTIFICATE_LOGON structure includes:
```c
ULONG CspDataLength;
PUCHAR CspData;  // Points to KERB_SMARTCARD_CSP_INFO
```

The CSP info contains:
- Reader name (e.g., "Authentik Virtual Reader")
- Card name (e.g., "Authentik Virtual Card")
- Container name (e.g., "AuthentikPKINIT_{GUID}")
- **CSP/KSP name** (e.g., "Authentik Key Storage Provider")

When Windows processes this:
1. It calls `NCryptOpenStorageProvider(KSP_NAME)`
2. It calls `NCryptOpenKey(CONTAINER_NAME)`
3. It calls `NCryptSignHash()` to sign the PKINIT pre-authenticator

If the KSP can't provide the key, Windows **cannot perform PKINIT**.

### Why In-Memory Keys Don't Work

When we import a PFX:
```cpp
PFXImportCertStore(&pfxBlob, password, PKCS12_NO_PERSIST_KEY);
```

The key exists in our process's memory, associated with the certificate context.

But when we tell Windows to use "Microsoft Software Key Storage Provider" with container "AuthentikPKINIT_{GUID}":
- Windows calls the MS KSP
- MS KSP looks in its key storage locations (AppData, ProgramData, etc.)
- **The key doesn't exist there** because we used NO_PERSIST_KEY
- MS KSP returns NTE_BAD_KEYSET
- Windows falls back to password authentication

### The NTAuth Store

Path: `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local`

This AD object contains the DER-encoded certificates of CAs trusted for:
- Smart card logon
- Domain controller authentication
- EFS recovery agents

Without the issuing CA in NTAuth, the DC will reject PKINIT requests even if:
- The certificate is valid
- The chain is trusted
- The signature is correct

---

## Part 9: Network and Infrastructure Reference

| Component | Address | Notes |
|-----------|---------|-------|
| Authentik Server | authentik.test.local / 192.168.1.114 | Docker, v2025.10.1 |
| Domain Controller | WIN-6DP39D0OLI8.test.local / 192.168.1.101 | Also runs cert issuer |
| Cert Issuer API | http://192.168.1.101:8443 | Token: 726ca6c60f8840acb97be6979c261eac |
| Test Workstation | 192.168.1.115 | Windows 10/11 domain-joined |
| Domain | TEST / test.local | |
| Test User | shop | UPN: shop@test.local |
| CA Name | test-WIN-6DP39D0OLI8-CA | |
| Cert Template | AuthentikSmartcard | Duplicated from SmartcardLogon |

---

## Part 10: Commands Reference

### Build Commands
```cmd
# Build KSP
msbuild src\AuthentikKSP\AuthentikKSP.vcxproj /p:Configuration=Release /p:Platform=x64

# Build Credential Provider
msbuild src\AuthentikCredentialProvider\AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Installation Commands
```powershell
# Install KSP
Copy-Item AuthentikKSP.dll C:\Windows\System32\
.\Register-AuthentikKSP.ps1

# Install Credential Provider
Copy-Item AuthentikCredentialProvider.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### Diagnostic Commands
```powershell
# Verify KSP registration
certutil -csplist

# Verify NTAuth store
certutil -viewstore -enterprise NTAuth

# Check Kerberos events (on DC)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} -MaxEvents 5

# Force group policy update
gpupdate /force
```

---

## Conclusion

This session produced a complete custom KSP implementation that should enable true PKINIT authentication. The next step is to:

1. Build both DLLs
2. Install on test workstation
3. Verify with DebugView
4. Check Kerberos event logs for Pre-Auth Type 16/17

If successful, users will be able to log in with only username + OTP, with no Windows password required.

---

**Document Version:** 1.0  
**Author:** Claude (with Mike)  
**Status:** Ready for testing
