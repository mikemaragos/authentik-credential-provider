# API Testing Guide

**Testing Authentik API Connectivity**  
**Last Updated:** November 23, 2025

---

## 🎯 Purpose

These tools help you test the Authentik API endpoints that the credential provider uses. Use them to diagnose connection and authentication issues.

---

## 🛠️ Available Tools

### 1. Quick-Test-Auth.ps1 (Recommended for Quick Testing)

**What it does:**
- Reads configuration from registry automatically
- Tests the exact same API calls the DLL makes
- Interactive - prompts for username/password/OTP
- Shows full API responses

**When to use:**
- ✅ Quick test after configuring the credential provider
- ✅ Verify Authentik is reachable and responding
- ✅ Test your username/password/OTP flow
- ✅ See exactly what Authentik is returning

**How to run:**
```powershell
# Download from GitHub or use from project
cd C:\path\to\project\tools

# Run as Administrator
.\Quick-Test-Auth.ps1

# It will prompt for:
# - Username
# - Password
# - OTP (if required)
```

---

### 2. Test-AuthentikAPI.ps1 (Comprehensive Testing)

**What it does:**
- Tests network connectivity
- Tests HTTP(S) connection
- Tests flow endpoint
- Tests authentication
- Tests OTP validation
- Provides detailed diagnostics

**When to use:**
- ✅ Comprehensive troubleshooting
- ✅ Testing specific scenarios
- ✅ Automated testing with parameters
- ✅ Network/SSL diagnostics

**How to run:**
```powershell
# Basic test (uses registry configuration)
.\Test-AuthentikAPI.ps1

# Test with specific credentials
.\Test-AuthentikAPI.ps1 -Username "testuser" -Password "testpass"

# Test with OTP
.\Test-AuthentikAPI.ps1 -Username "testuser" -Password "testpass" -OTP "123456"

# Override configuration
.\Test-AuthentikAPI.ps1 -ServerUrl "authentik.company.com" `
                        -Port 443 `
                        -FlowSlug "my-flow" `
                        -Username "testuser" `
                        -Password "testpass"

# Test with HTTP (no SSL)
.\Test-AuthentikAPI.ps1 -UseHttp

# Ignore SSL errors
.\Test-AuthentikAPI.ps1 -IgnoreSslErrors
```

---

## 📋 Testing Workflow

### Step 1: Run Quick Test

```powershell
# Navigate to tools directory
cd C:\Projects\authentik-credential-provider\tools

# Run quick test
.\Quick-Test-Auth.ps1
```

**What to look for:**
```
✅ Configuration loaded from registry
   ServerUrl:        authentik.test.local
   ServerPort:       443
   FlowSlug:         windows-otp-auth
   UseHttps:         1
   IgnoreSslErrors:  1

API Endpoint: https://authentik.test.local:443/api/v3/flows/executor/windows-otp-auth/

Enter username: mike
Enter password: ********

✅ Response received!

Response Type: native
```

**Good signs:**
- ✅ Configuration loads
- ✅ API endpoint responds
- ✅ Response type is "native" or "redirect"
- ✅ OTP prompt appears if configured

**Bad signs:**
- ❌ "Could not read registry configuration"
- ❌ "Authentication FAILED"
- ❌ SSL/TLS errors
- ❌ Connection timeout

---

### Step 2: Analyze Response

#### Success Response (No OTP):
```json
{
  "type": "redirect",
  "to": "/if/flow/..."
}
```
**Meaning:** Authentication successful, no OTP required

---

#### OTP Required Response:
```json
{
  "type": "native",
  "component": "ak-stage-authenticator-validate",
  "flow_info": {
    "title": "Authenticate with OTP",
    ...
  }
}
```
**Meaning:** User/password correct, OTP validation needed

---

#### Error Response:
```json
{
  "type": "native",
  "component": "...",
  "response_errors": {
    "password": [{
      "string": "Invalid password",
      ...
    }]
  }
}
```
**Meaning:** Authentication failed (wrong credentials)

---

### Step 3: Compare with DebugView Logs

Run DebugView while testing to see what the credential provider is doing:

**What to look for in DebugView:**
```
[AuthentikCP] InitiateAuthentication: user=mike
[AuthentikCP] HTTP POST /api/v3/flows/executor/windows-otp-auth/
[AuthentikCP] Response received: 1234 bytes
[AuthentikCP] Parsed: OTP required, transaction=tx_12345
```

**Match PowerShell test with DLL behavior:**
- PowerShell gets OTP prompt → DLL should too
- PowerShell gets "redirect" → DLL should succeed
- PowerShell gets error → DLL should show error

---

## 🔍 Common Issues & Solutions

### Issue 1: SSL Certificate Error

**PowerShell Error:**
```
The underlying connection was closed: Could not establish trust relationship 
for the SSL/TLS secure channel.
```

**Solution:**
```powershell
# Option 1: Set IgnoreSslErrors in registry (testing only!)
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "IgnoreSslErrors" -Value 1 -Type DWord

# Option 2: Import certificate to Trusted Root
Import-Certificate -FilePath "authentik.cer" `
                   -CertStoreLocation "Cert:\LocalMachine\Root"

# Option 3: Use -IgnoreSslErrors parameter for testing
.\Test-AuthentikAPI.ps1 -IgnoreSslErrors
```

---

### Issue 2: Connection Timeout

**PowerShell Error:**
```
The operation has timed out.
```

**Diagnostics:**
```powershell
# Test TCP connectivity
Test-NetConnection -ComputerName authentik.test.local -Port 443

# Check DNS
Resolve-DnsName authentik.test.local

# Check firewall
Test-NetConnection -ComputerName authentik.test.local -Port 443 -DiagnoseRouting
```

**Common Causes:**
- Firewall blocking port 443
- DNS not resolving
- Authentik server not running
- Wrong port number

---

### Issue 3: Flow Not Found

**PowerShell Error:**
```
404 Not Found
```

**Solution:**
```powershell
# Check flow slug in Authentik Admin UI
# Admin → Flows → (Your Flow) → Slug

# Update registry if wrong
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "correct-flow-slug"
```

---

### Issue 4: Invalid Credentials

**PowerShell Response:**
```json
{
  "response_errors": {
    "password": [{
      "string": "Invalid password"
    }]
  }
}
```

**Solution:**
- Verify username exists in Authentik
- Verify password is correct
- Check if account is active/enabled
- Check Authentik audit logs

---

### Issue 5: OTP Not Working

**PowerShell Response:**
```json
{
  "response_errors": {
    "code": [{
      "string": "Invalid token"
    }]
  }
}
```

**Solution:**
- Check time synchronization (TOTP requires accurate time)
- Verify OTP device is enrolled
- Try a fresh OTP code
- Check Authentik device configuration

---

## 📊 Understanding API Responses

### Field: `type`

| Value | Meaning |
|-------|---------|
| `redirect` | Success - flow complete |
| `native` | Continue - more input needed |
| `challenge` | Challenge required |
| `denied` | Access denied |

### Field: `component`

| Value | Meaning |
|-------|---------|
| `ak-stage-authenticator-validate` | OTP validation required |
| `ak-stage-password` | Password required |
| `ak-stage-identification` | Username required |
| `xak-flow-redirect` | Flow complete, redirecting |

### Field: `response_errors`

Contains validation errors:
```json
{
  "response_errors": {
    "password": [{"string": "Invalid password"}],
    "code": [{"string": "Invalid token"}]
  }
}
```

---

## 🎯 Test Scenarios

### Scenario 1: Valid User, Correct Password, No OTP

**Expected:**
```
Response Type: redirect
✅ AUTHENTICATION SUCCESSFUL!
```

---

### Scenario 2: Valid User, Correct Password, OTP Required

**Expected:**
```
Step 1:
Response Type: native
Component: ak-stage-authenticator-validate

Step 2 (after OTP):
Response Type: redirect
✅ AUTHENTICATION SUCCESSFUL!
```

---

### Scenario 3: Invalid Password

**Expected:**
```
response_errors: {
  "password": [{"string": "Invalid password"}]
}
```

---

### Scenario 4: Invalid OTP

**Expected:**
```
response_errors: {
  "code": [{"string": "Invalid token"}]
}
```

---

## 🔧 Advanced Testing

### Test with Postman/Insomnia

**Endpoint:** `POST https://authentik.test.local:443/api/v3/flows/executor/windows-otp-auth/`

**Headers:**
```
Content-Type: application/json
```

**Body (Initial Auth):**
```json
{
  "uid_field": "mike",
  "password": "yourpassword"
}
```

**Body (OTP Validation):**
```json
{
  "code": "123456"
}
```

---

### Test with curl

```bash
# Initial authentication
curl -X POST https://authentik.test.local/api/v3/flows/executor/windows-otp-auth/ \
  -H "Content-Type: application/json" \
  -d '{"uid_field":"mike","password":"yourpassword"}' \
  -k

# OTP validation
curl -X POST https://authentik.test.local/api/v3/flows/executor/windows-otp-auth/ \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}' \
  -k
```

---

## 📝 Debugging Checklist

Before reporting issues, verify:

- [ ] Registry configuration is correct
- [ ] Network connectivity to Authentik server
- [ ] SSL certificate is valid (or IgnoreSslErrors=1 for testing)
- [ ] Flow slug exists and is published in Authentik
- [ ] User credentials are correct
- [ ] OTP device is enrolled (if using OTP)
- [ ] Time is synchronized (for TOTP)
- [ ] DebugView shows detailed logs
- [ ] PowerShell test script succeeds
- [ ] Authentik server logs checked

---

## 🆘 Getting Help

When asking for help, provide:

1. **PowerShell test output:**
   ```
   .\Test-AuthentikAPI.ps1 -Username "test" -Password "test" > test-output.txt
   ```

2. **DebugView logs:**
   - Filter: `AuthentikCP*`
   - Capture during authentication attempt

3. **Registry configuration:**
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider"
   ```

4. **Authentik server logs:**
   - Check authentik worker logs
   - Check audit logs for authentication attempts

---

**Document Version:** 1.0  
**Last Updated:** November 23, 2025

**Next Steps:**
1. Run `Quick-Test-Auth.ps1` to verify API connectivity
2. Check DebugView for credential provider logs
3. Test on lock screen (Win+L)
4. Report results with logs if issues persist
