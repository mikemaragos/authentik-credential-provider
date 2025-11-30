# AuthentikKSP - Custom Key Storage Provider

## ⚠️ DEPRECATED - Does Not Work for PKINIT

**This custom KSP approach does NOT work for Windows domain PKINIT authentication.**

### Why It Doesn't Work

Windows Kerberos SSP validates that certificates used for PKINIT come from smart card-compatible providers. Custom KSPs, even when properly registered, are not recognized as smart card providers.

Evidence from testing:
- Kerberos debug logs show `Client Realm: (empty)` and `Client Name: (empty)`
- This indicates PKINIT was never attempted by the Kerberos SSP
- The certificate is rejected at the SSP level, before reaching the KDC

### What Works Instead

Use **TPM Virtual Smart Card** for PKINIT authentication:
- Generate key ON the VSC
- Get certificate signed by CA (with UPN in SAN)
- Import certificate to VSC
- Use standard Windows smart card logon

See [VSC-PKINIT-GUIDE.md](../../VSC-PKINIT-GUIDE.md) for complete instructions.

### Code Preservation

This code is preserved for reference purposes only. It demonstrates:
- CNG Key Storage Provider registration
- Shared memory communication between KSP and credential provider
- BCRYPT key blob handling

Do not use this for production PKINIT authentication.

---

## Original Description (Historical)

A custom Windows CNG Key Storage Provider that stores keys in shared memory for use by the Authentik Credential Provider.

### Files
- `AuthentikKSP.cpp` - Main KSP implementation
- `AuthentikKSP.h` - Header with shared memory structures
- `AuthentikKSPDll.cpp` - DLL entry points
- `Register-AuthentikKSP.ps1` - Registration script

### Registration (Not Recommended)
```powershell
.\Register-AuthentikKSP.ps1
```
