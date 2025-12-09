# Smart Card Credential Provider Research Summary

## Date: December 8, 2025
## Purpose: Proper implementation of PKINIT authentication in Windows Credential Provider

---

## Executive Summary

After thorough research of Microsoft documentation and working open-source implementations (IDRIX LsaSmartCardLogon samples), here are the key findings:

### Critical Findings

1. **There are TWO different approaches**, each with different structures
2. **The Microsoft documentation has a discrepancy** about MessageType values
3. **Credential Providers use BYTE OFFSETS**, not pointers, for UNICODE_STRING.Buffer
4. **KERB_SMARTCARD_CSP_INFO uses 1-byte packing** and CHARACTER offsets (not byte offsets)

---

## Approach 1: KERB_CERTIFICATE_LOGON (Recommended for Domain Logon)

### Structure Definition
```c
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // Must be KerbCertificateLogon (13)
    UNICODE_STRING DomainName;           // Optional - helps locate KDC
    UNICODE_STRING UserName;             // Optional - helps locate account
    UNICODE_STRING Pin;                  // Smart card PIN
    ULONG Flags;                         // Usually 0
    ULONG CspDataLength;                 // Size of CspData in bytes
    PUCHAR CspData;                      // Pointer to KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON;
```

### Key Points
- **MessageType = 13** (KerbCertificateLogon) for logon
- **MessageType = 15** (KerbCertificateUnlockLogon) for unlock
- UserName and DomainName are OPTIONAL - if empty, certificate is used to find user
- All data must be in **single contiguous memory block**
- **For Credential Providers**: UNICODE_STRING.Buffer is a **BYTE OFFSET from start of structure**
- UNICODE_STRING.Length is in **BYTES** (not including null terminator)

### Source
- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon
- IDRIX LsaSmartCardLogon.cpp (working sample)

---

## Approach 2: KERB_SMART_CARD_LOGON (Simpler, no username/domain)

### Structure Definition
```c
typedef struct _KERB_SMART_CARD_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // See note below!
    UNICODE_STRING Pin;
    ULONG CspDataLength;
    PUCHAR CspData;
} KERB_SMART_CARD_LOGON;
```

### MessageType Discrepancy!
- **Microsoft Documentation says**: "This member must be set to KerbInteractiveLogon" (2)
- **IDRIX working sample uses**: KerbSmartCardLogon (6)

This is a known documentation issue. The IDRIX sample works, suggesting MessageType should match the structure type.

### Source
- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_smart_card_logon
- IDRIX LsaSmartCardLogon2.cpp (working sample)

---

## KERB_SMARTCARD_CSP_INFO Structure (Critical)

### Full Structure (Vista+)
```c
#pragma pack(push, 1)  // CRITICAL: 1-byte packing!
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;       // Total size in BYTES
    DWORD MessageType;        // MUST be 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;  // For 32/64-bit compatibility
    };
    DWORD flags;              // Usually 0
    DWORD KeySpec;            // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    ULONG nCardNameOffset;    // Offset in CHARACTER COUNT
    ULONG nReaderNameOffset;  // Offset in CHARACTER COUNT
    ULONG nContainerNameOffset; // Offset in CHARACTER COUNT
    ULONG nCSPNameOffset;     // Offset in CHARACTER COUNT
    TCHAR bBuffer;            // Start of string buffer
} KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)
```

### CRITICAL POINTS:
1. **Uses 1-byte packing** (`#pragma pack(push, 1)`)
2. **MessageType MUST be 1** (not the logon type!)
3. **Offsets are in CHARACTER COUNT** (WCHAR units), not bytes!
4. **bBuffer** is just a placeholder - actual strings follow the structure
5. Size calculation: `sizeof(struct) - sizeof(TCHAR) + total_string_bytes`

### Simplified Structure (Windows 2000 compatibility)
```c
#pragma pack(push, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO_2 {
    DWORD dwCspInfoLen;
    DWORD dwUnknown;          // Usually 0
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO_2;
#pragma pack(pop)
```

---

## Credential Provider vs Direct LsaLogonUser

### Direct LsaLogonUser (IDRIX samples)
- Can use **actual memory pointers**
- Buffer stays in same process
- Simpler implementation

### Credential Provider (Our case)
- Buffer is serialized and sent to lsass.exe (different process)
- **MUST use BYTE OFFSETS** for UNICODE_STRING.Buffer
- From Microsoft sample helpers.cpp:
  > "WinLogon and LSA consume 'packed' KERB_INTERACTIVE_UNLOCK_LOGONs. In these, the PWSTR members of each UNICODE_STRING are not actually pointers but byte offsets into the overall buffer"

### Buffer Layout for Credential Provider
```
[KERB_CERTIFICATE_LOGON structure]
[Domain string (null-terminated)]
[Username string (null-terminated)]
[PIN string (null-terminated)]
[KERB_SMARTCARD_CSP_INFO + strings]
```

Each UNICODE_STRING.Buffer = byte offset from start of buffer to where string begins

---

## Working Code Examples

### From IDRIX LsaSmartCardLogon.cpp (KERB_CERTIFICATE_LOGON)
```c
// Calculate sizes
ULONG ulCspDataLen = sizeof(KERB_SMARTCARD_CSP_INFO) - sizeof(TCHAR) + 
    (wcslen(szCardName) + 1) * sizeof(WCHAR) +
    (wcslen(szCspName) + 1) * sizeof(WCHAR) +
    (wcslen(szContainerName) + 1) * sizeof(WCHAR) + 
    (wcslen(szReaderName) + 1) * sizeof(WCHAR);

ulAuthInfoLen = sizeof(KERB_CERTIFICATE_LOGON) + 
    ulDomainByteLen + sizeof(WCHAR) +
    ulUserByteLen + sizeof(WCHAR) +
    ulPinByteLen + sizeof(WCHAR) +       
    ulCspDataLen;

// Set message type
pKerbCertLogon->MessageType = KerbCertificateLogon;

// Set CSP info message type
pKerbCspInfo->MessageType = 1;  // MUST be 1!
pKerbCspInfo->KeySpec = AT_KEYEXCHANGE;

// Offsets are in CHARACTER COUNT (WCHAR units)
pKerbCspInfo->nCardNameOffset = 0;
pKerbCspInfo->nReaderNameOffset = pKerbCspInfo->nCardNameOffset + wcslen(szCardName) + 1;
pKerbCspInfo->nContainerNameOffset = pKerbCspInfo->nReaderNameOffset + wcslen(szReaderName) + 1;
pKerbCspInfo->nCSPNameOffset = pKerbCspInfo->nContainerNameOffset + wcslen(szContainerName) + 1;
```

---

## For Our Implementation

### Recommended Approach: KERB_CERTIFICATE_LOGON

1. Use **KERB_CERTIFICATE_LOGON** with MessageType = 13
2. Include **DomainName** (uppercase for Kerberos realm)
3. Include **UserName** (helps KDC find account)
4. Include **Pin** (VSC PIN)
5. Include **CspData** with KERB_SMARTCARD_CSP_INFO

### Critical Implementation Details

```c
// 1. KERB_SMARTCARD_CSP_INFO uses 1-byte packing
#pragma pack(push, 1)
typedef struct _MY_KERB_SMARTCARD_CSP_INFO { ... }
#pragma pack(pop)

// 2. CSP Info MessageType is ALWAYS 1
pCspInfo->MessageType = 1;

// 3. CSP Info offsets are CHARACTER COUNT, not bytes
pCspInfo->nReaderNameOffset = wcslen(cardName) + 1;  // NOT * sizeof(WCHAR)

// 4. For credential provider, UNICODE_STRING.Buffer is BYTE OFFSET
ULONG currentOffset = sizeof(KERB_CERTIFICATE_LOGON);
pLogon->DomainName.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
pLogon->DomainName.Length = (USHORT)(wcslen(domain) * sizeof(WCHAR));

// 5. Use Kerberos package directly
packageName.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;  // "Kerberos"
```

### VSC Info Required
- **Reader Name**: From smart card enumeration (e.g., "Microsoft Virtual Smart Card 0")
- **Container Name**: Certificate thumbprint/container (e.g., "te-{GUID}")
- **CSP Name**: "Microsoft Base Smart Card Crypto Provider"
- **Card Name**: Can be empty string

---

## Open Questions

1. Does the credential provider need to validate the certificate before packing?
2. Should we use the full KERB_SMARTCARD_CSP_INFO or the simplified version?
3. Do we need to handle WOW64 scenarios?

---

## References

1. Microsoft KERB_CERTIFICATE_LOGON: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon
2. Microsoft KERB_SMART_CARD_LOGON: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_smart_card_logon
3. Microsoft KERB_SMARTCARD_CSP_INFO: https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info
4. IDRIX LsaSmartCardLogon.cpp: http://www.idrix.fr/Root/Samples/LsaSmartCardLogon.cpp
5. IDRIX LsaSmartCardLogon2.cpp: http://www.idrix.fr/Root/Samples/LsaSmartCardLogon2.cpp
6. Microsoft Credential Provider Sample helpers.cpp: https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/helpers.cpp
7. Smart Card Architecture: https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture
