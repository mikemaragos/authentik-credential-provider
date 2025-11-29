# Quick Start Guide - Authentik Passwordless Credential Provider

## 5-Minute Setup (Development/Testing)

### Step 1: Build

```cmd
:: Open VS Developer Command Prompt, navigate to project directory
msbuild AuthentikPasswordlessCP.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Step 2: Install

```cmd
:: Run as Administrator
copy x64\Release\AuthentikPasswordlessCP.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikPasswordlessCP.dll
```

### Step 3: Configure

Edit registry or run this (adjust values for your environment):

```cmd
:: Run as Administrator
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerUrl /t REG_SZ /d "authentik.test.local" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerPort /t REG_DWORD /d 443 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v FlowSlug /t REG_SZ /d "windows-passwordless" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v UseHttps /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v Domain /t REG_SZ /d "TEST" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v DomainFQDN /t REG_SZ /d "test.local" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v IgnoreCertErrors /t REG_DWORD /d 1 /f
```

### Step 4: Reboot

```cmd
shutdown /r /t 0
```

### Step 5: Test

1. Start **DebugView** (as Administrator) before testing
2. Press **Win+L** to lock
3. Look for "**Authentik Passwordless Login**" tile
4. Enter username → click Sign In
5. Enter OTP code → click Verify
6. Watch DebugView for `[AuthentikPwdlessCP]` messages

## Troubleshooting Quick Reference

| Problem | Solution |
|---------|----------|
| Tile doesn't appear | Reboot. Check `regsvr32` succeeded |
| "Failed to connect" | Check `ServerUrl` in registry. Try `ping authentik.test.local` |
| OTP fails | Check Authentik flow is configured correctly |
| "No certificate" | Authentik must return certificate in response |
| Login fails after OTP | Check DC trusts CA. See README for NTAuth setup |

## Log Messages to Look For

```
✓ DLL_PROCESS_ATTACH - Authentik Passwordless Credential Provider
✓ CAuthentikProvider::SetUsageScenario - cpus=1
✓ Using Kerberos authentication package ID: X
✓ InitiateAuthentication: user=mike
✓ OTP required, transitioning to OTP step
✓ SubmitOTP
✓ OTP validated, certificate received
✓ Certificate credentials packed successfully
```

## Uninstall

```cmd
regsvr32 /u C:\Windows\System32\AuthentikPasswordlessCP.dll
del C:\Windows\System32\AuthentikPasswordlessCP.dll
shutdown /r /t 0
```

## Next Steps

1. **Configure Authentik** - Set up flow with certificate issuance
2. **Configure AD** - Trust Authentik CA in NTAuth store
3. **Disable `IgnoreCertErrors`** - Use real certificates for production
4. **Test thoroughly** - Always have recovery access (Safe Mode, local admin)

See **README.md** for full documentation.
