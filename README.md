# Authentik Credential Provider for Windows

A Windows Credential Provider that integrates with Authentik for OTP-based domain authentication.

## Overview

This credential provider allows users to authenticate to Windows using:
1. Username + Password + OTP (concatenated or two-step)
2. Integration with Authentik authentication server
3. Support for TOTP, SMS, Email, and other OTP methods

## Files Included

### Core Components
- **AuthentikCredentialProvider.cpp/h** - Main credential provider implementation
- **AuthentikCredential.cpp/h** - Individual credential tile logic
- **CredentialPacking.cpp/h** - KERB_INTERACTIVE_LOGON serialization (FIXED)
- **AuthentikAPI.cpp/h** - HTTP client for Authentik communication
- **Dll.cpp** - DLL entry point and COM registration
- **AuthentikCredentialProvider.def** - DLL export definitions

### Supporting Files
- **FieldDescriptors.h** - UI field definitions
- **guid.h** - GUID definitions
- **Logger.h** - Debug logging

## Building the Project

### Prerequisites
- Visual Studio 2019 or 2022
- Windows SDK 10.0.19041.0 or later
- x64 platform target

### Build Steps

1. **Create a new Visual Studio project:**
   - File â†’ New â†’ Project
   - Select "Dynamic-Link Library (DLL)"
   - Name: AuthentikCredentialProvider
   - Platform: x64

2. **Add all source files to the project**

3. **Configure project properties:**

   **General:**
   - Configuration Type: Dynamic Library (.dll)
   - Platform: x64
   - Windows SDK Version: 10.0 (latest installed)

   **C/C++:**
   - Additional Include Directories: (project directory)
   - Preprocessor Definitions: Add `WIN32_LEAN_AND_MEAN;UNICODE;_UNICODE`
   - Precompiled Headers: Not Using Precompiled Headers

   **Linker:**
   - Module Definition File: AuthentikCredentialProvider.def
   - Additional Dependencies: Add `Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib`
   - SubSystem: Windows

4. **Build the solution:**
   - Select "Release" configuration
   - Platform: x64
   - Build â†’ Build Solution

5. **Output:**
   - `AuthentikCredentialProvider.dll` will be in `x64/Release/`

## Installation

### 1. Copy DLL to System Directory

```cmd
copy AuthentikCredentialProvider.dll C:\Windows\System32\
```

### 2. Register the DLL

```cmd
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### 3. Configure Registry Settings

Create registry keys for configuration:

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="authentik.test.local"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-otp-auth"
"UseHttps"=dword:00000001
```

Save as `config.reg` and double-click to import.

## Configuration

### Registry Settings

Location: `HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider`

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| ServerUrl | REG_SZ | Authentik server hostname | `authentik.test.local` |
| ServerPort | REG_DWORD | Server port (443 for HTTPS) | `443` |
| FlowSlug | REG_SZ | Authentik flow slug | `windows-otp-auth` |
| UseHttps | REG_DWORD | Use HTTPS (1) or HTTP (0) | `1` |

### Authentik Flow Configuration

Create a flow in Authentik with these stages:
1. **Identification Stage** - Captures username
2. **Password Stage** - Validates password (optional)
3. **Authenticator Validation Stage** - Validates OTP

## Usage

### User Experience

**Two-Step Mode (Recommended):**
1. Enter username and password
2. Press Enter
3. Enter OTP code
4. Press Enter
5. Login completes

**Concatenated Mode:**
1. Enter username
2. Enter password + OTP concatenated (e.g., `MyPassword123456`)
3. Press Enter
4. Login completes

## Troubleshooting

### Enable Debug Logging

Debug builds automatically log to DebugView:
1. Download DebugView from Sysinternals
2. Run DebugView as Administrator
3. Look for `[AuthentikCP]` messages

### Common Issues

**DLL won't register:**
- Ensure you're running as Administrator
- Check DLL is for correct architecture (x64)
- Verify all dependencies are present

**Credential provider doesn't appear:**
- Check registry: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
- Reboot the machine
- Check Event Viewer for errors

**Authentication fails:**
- Verify Authentik server is reachable
- Check registry configuration
- Review DebugView logs
- Test Authentik flow manually

**Certificate errors:**
- For production, use valid SSL certificates
- Remove `SECURITY_FLAG_IGNORE_*` flags in AuthentikAPI.cpp
- Implement proper certificate validation

## Security Considerations

### Current Implementation (Testing)
- âš ï¸ SSL certificate validation is DISABLED
- âš ï¸ Password is cached in memory briefly
- âš ï¸ No certificate pinning

### For Production Use
1. **Enable SSL validation:**
   - Remove certificate ignore flags in `AuthentikAPI.cpp`
   - Use valid SSL certificates on Authentik server

2. **Implement certificate pinning:**
   - Pin Authentik server certificate
   - Prevent MITM attacks

3. **Secure password handling:**
   - Minimize password lifetime in memory
   - Use SecureZeroMemory to clear sensitive data
   - Consider using Windows Credential Manager

4. **API authentication:**
   - Store API tokens securely (not in registry plaintext)
   - Use Windows DPAPI for encryption
   - Rotate tokens regularly

## Known Limitations

1. **Password still required** - Windows domain auth needs password or certificate
2. **No offline support** - Requires network connectivity to Authentik
3. **Simple JSON parsing** - Uses string matching instead of proper JSON library
4. **No certificate-based auth** - Future enhancement for true passwordless

## Future Enhancements

- [ ] Certificate-based authentication (PKINIT)
- [ ] Offline OTP validation
- [ ] Proper JSON parsing library
- [ ] Enhanced error messages
- [ ] Group Policy configuration support
- [ ] Multi-domain support
- [ ] Password synchronization service
- [ ] Biometric integration

## Architecture Notes

### Key Fixes Applied

1. **Credential Packing:**
   - Fixed UNICODE_STRING initialization
   - Proper CoTaskMemAlloc usage for COM compatibility
   - Correct structure alignment

2. **Authentication Flow:**
   - Two-step authentication with transaction IDs
   - Proper state management
   - Secure password caching

3. **API Integration:**
   - WinHTTP for reliable HTTPS communication
   - Basic JSON response parsing
   - Error handling and logging

## References

- [Microsoft Credential Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Authentik Documentation](https://goauthentik.io/docs/)
- [PrivacyIDEA Credential Provider](https://github.com/privacyidea/privacyidea-credential-provider)

## License

This is sample code for educational and testing purposes.

## Support

For issues or questions:
- Review the DebugView logs
- Check Authentik server logs
- Verify network connectivity
- Test Authentik flow manually via web browser

## Version History

- **v1.0** - Initial release
  - Two-step OTP authentication
  - Authentik API integration
  - Fixed credential packing
  - Debug logging

---

**IMPORTANT:** This credential provider is for testing and development. 
For production use, implement all security recommendations above.
