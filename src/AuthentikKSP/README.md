# Authentik Key Storage Provider (KSP)

A custom Windows Key Storage Provider that enables certificate-based (PKINIT) authentication for the Authentik Credential Provider.

## Overview

This KSP receives certificates and private keys from the Authentik Credential Provider via shared memory and provides them to Windows LSA for PKINIT authentication. This enables true passwordless Windows login using Authentik OTP + certificates.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Authentication Flow                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  User enters username → Authentik validates → User enters OTP       │
│                                                                      │
│                              │                                       │
│                              ▼                                       │
│           ┌─────────────────────────────────────┐                   │
│           │  Authentik returns certificate      │                   │
│           │  + private key after OTP valid      │                   │
│           └─────────────────────────────────────┘                   │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │              Credential Provider                            │    │
│  │  1. Receives certificate from Authentik                     │    │
│  │  2. Writes cert+key to shared memory                        │    │
│  │  3. Packs KERB_CERTIFICATE_LOGON                           │    │
│  │  4. Points to our KSP                                       │    │
│  └────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │              Authentik KSP                                  │    │
│  │  1. Reads cert+key from shared memory                       │    │
│  │  2. Provides certificate via NCRYPT_CERTIFICATE_PROPERTY    │    │
│  │  3. Signs authentication challenge with private key         │    │
│  └────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │              Windows LSA / Kerberos                         │    │
│  │  1. Gets certificate from KSP                               │    │
│  │  2. Performs PKINIT with Domain Controller                  │    │
│  │  3. Returns Kerberos TGT                                    │    │
│  └────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│                    USER LOGGED IN                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `AuthentikKSP.h` | Main header with NCrypt interface declarations |
| `AuthentikKSP.cpp` | KSP implementation - all NCrypt functions |
| `AuthentikKSP.def` | DLL export definitions |
| `AuthentikKSP.vcxproj` | Visual Studio project file |
| `KSPSharedMemory.h` | Shared memory helper for credential provider |
| `CertificateCredentialPacking.h` | KERB_CERTIFICATE_LOGON packing functions |
| `Register-AuthentikKSP.ps1` | PowerShell registration script |

## Building

### Prerequisites
- Visual Studio 2022
- Windows SDK 10.0.19041.0 or later
- x64 platform target

### Build Steps

1. Open `AuthentikKSP.vcxproj` in Visual Studio 2022
2. Select **Release | x64** configuration
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: `x64\Release\AuthentikKSP.dll`

### Command Line Build

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" AuthentikKSP.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation

### 1. Register the KSP

Run PowerShell as Administrator:

```powershell
.\Register-AuthentikKSP.ps1 -DllPath ".\x64\Release\AuthentikKSP.dll"
```

This will:
- Copy DLL to `C:\Windows\System32\`
- Create registry entries at `HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider`

### 2. Verify Registration

```powershell
# Check registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider"

# List CNG providers
certutil -csplist
```

### 3. Reboot

A reboot may be required for LSA to load the new KSP.

## Uninstallation

```powershell
.\Register-AuthentikKSP.ps1 -Unregister
```

## Integration with Credential Provider

### 1. Include Headers

Add to your credential provider project:
- `KSPSharedMemory.h` - For communicating with KSP
- `CertificateCredentialPacking.h` - For KERB_CERTIFICATE_LOGON

### 2. Send Certificate to KSP

```cpp
#include "KSPSharedMemory.h"

// In credential provider after OTP validation:
CKSPSharedMemory sharedMem;
HRESULT hr = sharedMem.Initialize();

if (SUCCEEDED(hr))
{
    // Set certificate and key received from Authentik
    hr = sharedMem.SetCertificateData(
        username,              // e.g., "shop"
        pbCertificate,         // DER-encoded certificate
        cbCertificate,
        pbPrivateKeyBlob,      // BCRYPT_RSAFULLPRIVATE_BLOB
        cbPrivateKeyBlob,
        AT_KEYEXCHANGE);
}
```

### 3. Pack Certificate Credentials

```cpp
#include "CertificateCredentialPacking.h"

// In _PackCredentialsAndReturn:
std::wstring containerName = L"AUTHENTIK_" + username;

HRESULT hr = PackKerbCertificateLogon(
    username,
    domain,
    L"",                               // Empty PIN - OTP was the auth
    AUTHENTIK_KSP_NAME,                // "Authentik Key Storage Provider"
    containerName,
    &pPackage,
    &cbPackage);
```

## Debugging

### Enable Debug Logging

The KSP outputs to DebugView. Run DebugView as Administrator and look for `[AuthentikKSP]` messages.

### Common Issues

**KSP not loading:**
- Check registry path is correct
- Verify DLL is in System32
- Check DLL dependencies with `dumpbin /dependents AuthentikKSP.dll`

**Shared memory not available:**
- Credential provider must create shared memory first
- Check security permissions on shared memory
- Run as SYSTEM for LSA access

**Certificate property not returned:**
- Verify certificate is DER-encoded
- Check KSPGetKeyProperty is being called

**Signing fails:**
- Verify private key blob format (BCRYPT_RSAFULLPRIVATE_BLOB)
- Check BCryptImportKeyPair succeeded

## Security Considerations

### Production Hardening

1. **Memory Protection:**
   - Private keys are cleared with SecureZeroMemory
   - Shared memory cleared after use

2. **Access Control:**
   - Shared memory uses default security (needs tightening for production)
   - Consider using explicit ACLs

3. **Logging:**
   - Debug logging should be disabled in production
   - Consider Windows Event Log for audit

4. **Certificate Validation:**
   - KSP trusts certificates from credential provider
   - Authentik should validate certificate before sending

## Certificate Requirements

For PKINIT to work, certificates must have:

- **Subject Alternative Name:** UPN (user@domain)
- **Enhanced Key Usage:**
  - Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
  - Client Authentication (1.3.6.1.5.5.7.3.2)
- **Key Usage:** Digital Signature
- **Private Key:** RSA 2048-bit or higher

## Testing

### Manual Test

1. Build and register KSP
2. Update credential provider to use certificate flow
3. Export test certificate as PFX
4. Convert PFX to DER + key blob for testing
5. Lock workstation and test login

### Automated Test

```cpp
// Test KSP loading
NCRYPT_PROV_HANDLE hProvider;
SECURITY_STATUS status = NCryptOpenStorageProvider(
    &hProvider,
    L"Authentik Key Storage Provider",
    0);
    
if (status == ERROR_SUCCESS)
{
    printf("KSP loaded successfully!\n");
    NCryptFreeObject(hProvider);
}
```

## Version History

- **1.0** - Initial implementation
  - NCrypt interface implementation
  - Shared memory communication
  - RSA signing support
  - Certificate property support

## References

- [CNG Key Storage Providers](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval)
- [PKINIT Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
- [KERB_CERTIFICATE_LOGON](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon)

## License

Part of the Authentik Credential Provider project.
