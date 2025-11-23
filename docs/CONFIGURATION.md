# Configuration Reference

**Authentik Credential Provider - Registry Settings**  
**Last Updated:** November 23, 2025

---

## Registry Location

All settings are stored in:
```
HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider
```

---

## Registry Settings

### Required Settings

#### ServerUrl (REG_SZ)
**Description:** Hostname or IP address of your Authentik server  
**Type:** String (REG_SZ)  
**Required:** Yes  
**Example:** `authentik.yourdomain.com`

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" `
                 -Value "authentik.yourdomain.com"
```

**Notes:**
- Do NOT include `https://` or `http://` - just the hostname
- Do NOT include port number - use ServerPort setting for that
- Can be a hostname or IP address
- Must be reachable from the Windows machine

---

#### ServerPort (REG_DWORD)
**Description:** Port number for Authentik server  
**Type:** DWORD (32-bit number)  
**Required:** Yes  
**Default:** 443  
**Example:** `443` (for HTTPS)

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerPort" `
                 -Value 443 `
                 -Type DWord
```

**Common Values:**
- `443` - HTTPS (recommended)
- `80` - HTTP (not recommended for production)
- `9000` - Common Authentik development port
- `9443` - Common Authentik development HTTPS port

---

#### FlowSlug (REG_SZ)
**Description:** Authentik flow identifier/slug  
**Type:** String (REG_SZ)  
**Required:** Yes  
**Example:** `windows-otp-auth`

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" `
                 -Value "windows-otp-auth"
```

**Notes:**
- Must match the flow slug configured in Authentik exactly
- Case-sensitive
- No spaces or special characters
- Find this in Authentik Admin → Flows → Your Flow → Slug

---

#### UseHttps (REG_DWORD)
**Description:** Use HTTPS for communication with Authentik  
**Type:** DWORD (32-bit number)  
**Required:** Yes  
**Default:** 1 (enabled)  
**Values:** `0` = HTTP, `1` = HTTPS

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "UseHttps" `
                 -Value 1 `
                 -Type DWord
```

**Recommendations:**
- ✅ **Production:** MUST be `1` (HTTPS)
- ⚠️ **Development/Testing:** Can be `0` (HTTP) if testing locally
- ❌ **Never use HTTP in production** - passwords are sent in plain text!

---

### Optional Settings

#### IgnoreSslErrors (REG_DWORD)
**Description:** Ignore SSL certificate validation errors  
**Type:** DWORD (32-bit number)  
**Required:** No  
**Default:** 0 (validate certificates - secure)  
**Values:** `0` = Validate SSL (secure), `1` = Ignore SSL errors (insecure)

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "IgnoreSslErrors" `
                 -Value 1 `
                 -Type DWord
```

**⚠️ SECURITY WARNING:**  
When set to `1`, ALL SSL certificate validation is bypassed, including:
- Untrusted/self-signed certificates
- Expired certificates
- Wrong hostname certificates
- This makes you vulnerable to man-in-the-middle attacks!

**When to Use:**
- ✅ Development/testing with self-signed certificates
- ✅ Internal testing environment with self-signed CA
- ❌ **NEVER in production** - fix your certificates instead!

**Production Alternative:**
Instead of disabling SSL validation:
1. Use a valid SSL certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)
2. Or import your self-signed CA certificate to Windows Trusted Root store
3. Or use an internal CA and add it to domain trust

---

## Complete Configuration Examples

### Example 1: Production with Valid SSL Certificate

```powershell
# Production configuration
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" -Value "authentik.company.com"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerPort" -Value 443 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "windows-mfa-login"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "UseHttps" -Value 1 -Type DWord

# IgnoreSslErrors not set = secure by default
```

---

### Example 2: Development/Testing with Self-Signed Certificate

```powershell
# Development/Testing configuration
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" -Value "authentik.test.local"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerPort" -Value 9443 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "test-flow"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "UseHttps" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "IgnoreSslErrors" -Value 1 -Type DWord

Write-Host "⚠️  WARNING: SSL validation is disabled! Only for testing!"
```

---

### Example 3: Local Development (HTTP, No SSL)

```powershell
# Local development only - NO ENCRYPTION!
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" -Value "localhost"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerPort" -Value 9000 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "dev-test"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "UseHttps" -Value 0 -Type DWord

Write-Host "⚠️  WARNING: Using HTTP - passwords sent in PLAIN TEXT!"
Write-Host "⚠️  Only for local development on localhost!"
```

---

## Verification

### View Current Configuration

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" | 
  Select-Object ServerUrl, ServerPort, FlowSlug, UseHttps, IgnoreSslErrors
```

**Example Output:**
```
ServerUrl       : authentik.yourdomain.com
ServerPort      : 443
FlowSlug        : windows-otp-auth
UseHttps        : 1
IgnoreSslErrors : 0
```

---

### Test Network Connectivity

```powershell
# Get configuration
$config = Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider"

# Test connectivity
Test-NetConnection -ComputerName $config.ServerUrl -Port $config.ServerPort

# Test HTTPS
$protocol = if ($config.UseHttps -eq 1) { "https" } else { "http" }
$url = "$protocol`://$($config.ServerUrl):$($config.ServerPort)"
try {
    Invoke-WebRequest -Uri $url -UseBasicParsing
    Write-Host "✅ Connection successful!"
} catch {
    Write-Host "❌ Connection failed: $_"
}
```

---

## Registry File Templates

### Production Template (config-production.reg)

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="authentik.company.com"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-mfa-login"
"UseHttps"=dword:00000001
```

**To import:**
```cmd
reg import config-production.reg
```

---

### Development Template (config-development.reg)

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="authentik.test.local"
"ServerPort"=dword:000024eb
"FlowSlug"="test-flow"
"UseHttps"=dword:00000001
"IgnoreSslErrors"=dword:00000001
```

**To import:**
```cmd
reg import config-development.reg
```

---

## Troubleshooting

### Issue: "ServerUrl not configured in registry"

**Log Message:**
```
[AuthentikCP] ERROR: ServerUrl not configured in registry!
```

**Solution:**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" -Value "your-authentik-server.com"
```

---

### Issue: "FlowSlug not configured in registry"

**Log Message:**
```
[AuthentikCP] ERROR: FlowSlug not configured in registry!
```

**Solution:**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "your-flow-slug"
```

---

### Issue: SSL Certificate Errors

**Log Message:**
```
[AuthentikCP] WinHttpSendRequest failed: 12175
```

**Cause:** SSL certificate validation failed

**Solutions (in order of preference):**

1. **Use a valid certificate** (recommended):
   - Get a certificate from Let's Encrypt or your CA
   - Configure Authentik to use it

2. **Import self-signed cert to Windows**:
   ```powershell
   # Export cert from Authentik server, then:
   Import-Certificate -FilePath "authentik.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
   ```

3. **Disable validation for testing only**:
   ```powershell
   Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                    -Name "IgnoreSslErrors" -Value 1 -Type DWord
   ```

---

## Security Best Practices

### ✅ DO:
- Use HTTPS in production (`UseHttps=1`)
- Use valid SSL certificates from trusted CA
- Keep `IgnoreSslErrors` unset or `0` in production
- Document your configuration
- Test configuration before deployment
- Use registry permissions to protect settings

### ❌ DON'T:
- Use HTTP in production (`UseHttps=0`)
- Ignore SSL errors in production (`IgnoreSslErrors=1`)
- Use self-signed certificates without importing to trusted root
- Expose Authentik server to internet without proper security
- Share configuration files with sensitive data
- Forget to update documentation when changing settings

---

## Advanced Configuration

### Using Group Policy to Deploy Configuration

1. Create a GPO
2. Computer Configuration → Preferences → Windows Settings → Registry
3. New → Registry Item
4. Add each setting:
   - Hive: `HKEY_LOCAL_MACHINE`
   - Key Path: `SOFTWARE\AuthentikCredentialProvider`
   - Value name: (setting name)
   - Value type: (REG_SZ or REG_DWORD)
   - Value data: (your value)

5. Link GPO to appropriate OU
6. Force update: `gpupdate /force`

---

### Configuration Management with PowerShell

```powershell
# Function to configure Authentik CP
function Set-AuthentikCPConfiguration {
    param(
        [string]$ServerUrl,
        [int]$ServerPort = 443,
        [string]$FlowSlug,
        [switch]$UseHTTP,
        [switch]$IgnoreSslErrors
    )
    
    $regPath = "HKLM:\SOFTWARE\AuthentikCredentialProvider"
    New-Item -Path $regPath -Force | Out-Null
    
    Set-ItemProperty -Path $regPath -Name "ServerUrl" -Value $ServerUrl
    Set-ItemProperty -Path $regPath -Name "ServerPort" -Value $ServerPort -Type DWord
    Set-ItemProperty -Path $regPath -Name "FlowSlug" -Value $FlowSlug
    Set-ItemProperty -Path $regPath -Name "UseHttps" -Value $(if ($UseHTTP) { 0 } else { 1 }) -Type DWord
    
    if ($IgnoreSslErrors) {
        Set-ItemProperty -Path $regPath -Name "IgnoreSslErrors" -Value 1 -Type DWord
        Write-Warning "SSL validation disabled - only for testing!"
    }
    
    Write-Host "✅ Configuration applied successfully"
}

# Usage:
Set-AuthentikCPConfiguration -ServerUrl "authentik.company.com" -FlowSlug "windows-auth"
```

---

**Document Version:** 1.0  
**Last Updated:** November 23, 2025

For more information, see:
- [Installation Guide](INSTALLATION.md)
- [Deployment Prerequisites](DEPLOYMENT_PREREQUISITES.md)
- [Quick Install Guide](QUICK_INSTALL.md)
