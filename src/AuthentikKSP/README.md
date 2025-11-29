# Authentik Key Storage Provider (KSP)

A Windows Key Storage Provider that enables PKINIT certificate-based authentication without a physical smart card.

## Overview

This KSP allows the Authentik Credential Provider to perform true passwordless authentication by:

1. Storing private keys in shared memory during the authentication flow
2. Providing these keys to Windows Kerberos for PKINIT pre-authentication
3. Signing the Kerberos AS-REQ with the certificate's private key

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Flow                           │
├─────────────────────────────────────────────────────────────────┤
│  1. User enters username + OTP                                   │
│  2. Authentik validates OTP                                      │
│  3. Cert Issuer generates certificate + private key              │
│  4. Credential Provider stores key via AuthentikKSP_StoreKey()   │
│  5. Credential Provider returns KERB_CERTIFICATE_LOGON           │
│     (referencing "Authentik Key Storage Provider")               │
│  6. Windows Kerberos opens our KSP                               │
│  7. Our KSP provides the key for PKINIT signing                  │
│  8. Authentication succeeds!                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites
- Visual Studio 2022 or later
- Windows SDK 10.0.19041.0 or later
- x64 platform target

### Build Steps

1. Open `AuthentikKSP.vcxproj` in Visual Studio
2. Select **Release | x64** configuration
3. Build the solution

## Installation

### 1. Copy the DLL

```cmd
copy x64\Release\AuthentikKSP.dll C:\Windows\System32\
```

### 2. Register the KSP

Run as Administrator:

```powershell
.\Register-AuthentikKSP.ps1
```

Or manually:

```powershell
$ProviderName = "Authentik Key Storage Provider"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

New-Item -Path $RegistryPath -Force
Set-ItemProperty -Path $RegistryPath -Name "Image Path" -Value "C:\Windows\System32\AuthentikKSP.dll"
Set-ItemProperty -Path $RegistryPath -Name "Type" -Value 1

$FunctionsPath = "$RegistryPath\Functions"
New-Item -Path $FunctionsPath -Force
Set-ItemProperty -Path $FunctionsPath -Name "KeyStorageInterface" -Value "GetKeyStorageInterface"
```

### 3. Verify Registration

```cmd
certutil -csplist
```

You should see "Authentik Key Storage Provider" in the list.

## Integration with Credential Provider

The credential provider needs to:

1. **Store the key** before returning the credential:
   ```cpp
   #include "AuthentikKSP.h"
   
   // After receiving certificate from cert issuer
   HRESULT hr = AuthentikKSP_StoreKey(
       L"AuthentikPKINIT_{GUID}",      // Container name
       L"username",                     // User name
       privateKeyBlob,                  // BCRYPT_RSAPRIVATE_BLOB
       cbPrivateKey,
       certificateDER,                  // DER-encoded certificate
       cbCertificate,
       AT_KEYEXCHANGE,                  // Key spec
       60);                             // Validity in minutes
   ```

2. **Reference our KSP** in the KERB_SMARTCARD_CSP_INFO:
   ```cpp
   // Use our provider name
   LPCWSTR providerName = AuthentikKSP_GetProviderName();
   // ... build KERB_SMARTCARD_CSP_INFO with this provider
   ```

## Security Considerations

### Key Storage
- Keys are stored in shared memory with a `Global\` namespace
- Keys automatically expire after the specified validity period
- Keys are cleared from memory when the credential provider process exits

### Recommendations for Production
- Consider encrypting keys in shared memory with DPAPI
- Implement key pinning to specific sessions
- Add audit logging for key operations
- Consider code signing the DLL

## Troubleshooting

### Enable Debug Logging

Build with `_DEBUG` defined to enable OutputDebugString logging.
Use DebugView to capture logs with filter: `[AuthentikKSP]`

### Common Issues

1. **NTE_BAD_KEYSET**: Key not found in shared memory
   - Ensure AuthentikKSP_StoreKey was called before authentication
   - Check key hasn't expired

2. **NTE_PROVIDER_DLL_FAIL**: Failed to initialize
   - Check DLL is in System32
   - Check registry registration
   - Run `regsvr32 /u` then re-register

3. **NTE_BAD_KEY**: Invalid key format
   - Ensure private key is BCRYPT_RSAPRIVATE_BLOB format
   - Check key blob size

## Files

- `AuthentikKSP.h` - Header with structures and function declarations
- `AuthentikKSP.cpp` - Main KSP implementation
- `AuthentikKSPDll.cpp` - DLL entry point and function table
- `AuthentikKSP.def` - Module definition for exports
- `AuthentikKSP.vcxproj` - Visual Studio project
- `Register-AuthentikKSP.ps1` - Registration script

## License

Part of the Authentik Credential Provider project.
