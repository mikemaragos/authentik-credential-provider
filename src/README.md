# Source Code

This directory contains all source code for the Authentik Credential Provider.

## Structure

```
src/
├── AuthentikCredentialProvider/    # Main credential provider DLL
│   ├── AuthentikAPI.cpp           # Original API client
│   ├── AuthentikAPI_IMPROVED.cpp  # Production-ready API client (USE THIS)
│   ├── AuthentikCredential.cpp    # Individual credential tile
│   ├── AuthentikCredentialProvider.cpp  # Main provider
│   ├── CredentialPacking.cpp      # Credential serialization
│   ├── Dll.cpp                    # DLL entry point
│   ├── SecureString.h             # Secure password handling
│   ├── RateLimiter.h              # Brute force protection
│   ├── ConfigurationManager.h     # Configuration management
│   └── ...                        # Other source files
└── AuthentikCredentialProvider.sln  # Visual Studio solution

## Building

### Prerequisites
- Visual Studio 2019 or 2022
- Windows SDK 10.0.19041.0 or later

### Build Steps

1. **Open solution:**
   ```
   start AuthentikCredentialProvider.sln
   ```

2. **Select configuration:**
   - Configuration: Release
   - Platform: x64

3. **Build:**
   - Build → Build Solution (Ctrl+Shift+B)

4. **Output:**
   - `x64/Release/AuthentikCredentialProvider.dll`

## Key Files

### Core Components
- **AuthentikCredentialProvider.cpp/h** - Main provider implementation
- **AuthentikCredential.cpp/h** - Individual credential tile logic
- **AuthentikAPI_IMPROVED.cpp** - HTTP client (USE THIS - has security fixes)
- **CredentialPacking.cpp/h** - KERB_INTERACTIVE_LOGON serialization

### Security Enhancements (New in v2.0)
- **SecureString.h** - Secure password handling with automatic zeroing
- **RateLimiter.h** - Brute force protection
- **ConfigurationManager.h** - Centralized, validated configuration

### Supporting Files
- **FieldDescriptors.h** - UI field definitions
- **Logger.h** - Debug logging
- **guid.h** - GUID definitions
- **Dll.cpp** - DLL registration

## Development

See [Development Guide](../docs/development/) for detailed information.

## Testing

1. Build in Debug mode
2. Copy DLL to `C:\Windows\System32\`
3. Register: `regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll`
4. Run DebugView as Administrator
5. Lock screen (Win+L)
6. Check DebugView for `[AuthentikCP]` logs
