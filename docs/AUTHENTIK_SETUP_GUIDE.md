# Authentik Server Setup Guide

**Configuring Authentik for Windows Credential Provider**  
**Last Updated:** November 23, 2025

---

## 📋 Prerequisites

### What You Need

- ✅ Authentik server installed and running
- ✅ Access to Authentik Admin interface
- ✅ Active Directory or LDAP (for user authentication)
- ✅ Admin credentials for Authentik

### Authentik Installation

If you don't have Authentik installed yet:

**Docker Compose (Recommended):**
```bash
# Download docker-compose.yml
wget https://goauthentik.io/docker-compose.yml

# Generate secret key
echo "PG_PASS=$(openssl rand -base64 36)" >> .env
echo "AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60)" >> .env

# Start Authentik
docker-compose up -d
```

**Default Access:**
- URL: `http://localhost:9000` or `https://localhost:9443`
- Initial setup will prompt for admin user creation

---

## 🎯 Overview

To use the Windows Credential Provider, you need to configure:

1. **LDAP Source** - Connect to Active Directory
2. **OTP Stage** - Configure OTP validation
3. **Authentication Flow** - Create the authentication flow
4. **Publish Flow** - Make it accessible via API

---

## Part 1: Configure LDAP/Active Directory Source

### Step 1: Create LDAP Source

1. **Log in to Authentik Admin:**
   ```
   https://your-authentik-server/if/admin/
   ```

2. **Navigate to Directory → Federation & Social login**

3. **Click "Create" → LDAP Source**

4. **Configure Source:**

   **Name:** `Active Directory`  
   **Slug:** `active-directory` (auto-generated)

   **LDAP Settings:**
   ```
   Server URI: ldap://dc.yourdomain.local:389
   # Or for LDAPS:
   # Server URI: ldaps://dc.yourdomain.local:636
   
   Bind CN: CN=authentik-bind,OU=Service Accounts,DC=yourdomain,DC=local
   Bind Password: <service account password>
   
   Base DN: DC=yourdomain,DC=local
   
   User Object Filter: (objectClass=person)
   User Group membership field: memberOf
   
   Group Object Filter: (objectClass=group)
   Group membership field: member
   ```

   **Sync Settings:**
   ```
   ✓ Sync users
   ✓ Sync groups
   Sync parent group: (leave empty or select a group)
   ```

5. **Click "Create"**

6. **Test Connection:**
   - Click "Test" button
   - Should show: "Connection successful"

7. **Run Initial Sync:**
   - Click "Run sync"
   - Wait for completion
   - Check: Directory → Users to verify users imported

---

### Example AD Service Account Setup

**In Active Directory:**

```powershell
# Create service account for Authentik
New-ADUser -Name "authentik-bind" `
           -SamAccountName "authentik-bind" `
           -UserPrincipalName "authentik-bind@yourdomain.local" `
           -Path "OU=Service Accounts,DC=yourdomain,DC=local" `
           -AccountPassword (ConvertTo-SecureString "SecurePassword123!" -AsPlainText -Force) `
           -Enabled $true `
           -PasswordNeverExpires $true

# Grant read permissions (minimum required)
# This account only needs read access to users and groups
```

---

## Part 2: Configure OTP/MFA

### Step 1: Create TOTP Setup Stage

1. **Navigate to Flows & Stages → Stages**

2. **Click "Create" → Authenticator Setup Stage**

   **Name:** `totp-setup`  
   **Device classes:** Select `TOTP` (Time-based)  
   **Friendly name:** `Authenticator App`

3. **Click "Create"**

### Step 2: Create OTP Validation Stage

1. **Navigate to Flows & Stages → Stages**

2. **Click "Create" → Authenticator Validation Stage**

   **Name:** `otp-validation`  
   **Device classes:** Select `TOTP`  
   **Configuration stage:** Select `totp-setup` (from Step 1)  
   **Not configured action:** Select `Configure`  
   **Web Authentication User Verification:** `Preferred`

3. **Click "Create"**

---

## Part 3: Create Authentication Flow

### Step 1: Create New Flow

1. **Navigate to Flows & Stages → Flows**

2. **Click "Create"**

   **Name:** `Windows OTP Authentication`  
   **Title:** `Windows Login`  
   **Slug:** `windows-otp-auth` ⭐ **(IMPORTANT - This must match registry!)**  
   **Designation:** `Authentication`  
   **Compatibility mode:** ✓ (check this)

3. **Click "Create"**

### Step 2: Add Stages to Flow

Now add stages in this **exact order**:

#### Stage 1: Identification

1. **Click "Bind Stage"**
2. **Stage:** `default-authentication-identification` (or create new)
   
   **If creating new Identification Stage:**
   - Name: `windows-identification`
   - User fields: ✓ `Username`, ✓ `Email`
   - Sources: Select your LDAP source (`Active Directory`)
   - Show matched user: ✓

3. **Order:** `10`
4. **Click "Create"**

#### Stage 2: Password Validation

1. **Click "Bind Stage"**
2. **Stage:** `default-authentication-password` (or create new)

   **If creating new Password Stage:**
   - Name: `windows-password`
   - Backends: ✓ Select your LDAP source
   
3. **Order:** `20`
4. **Click "Create"**

#### Stage 3: OTP Validation

1. **Click "Bind Stage"**
2. **Stage:** `otp-validation` (created earlier)
3. **Order:** `30`
4. **Click "Create"**

#### Stage 4: User Login

1. **Click "Bind Stage"**
2. **Stage:** `default-authentication-login` (or create new)

   **If creating new User Login Stage:**
   - Name: `windows-login`
   - Session duration: `hours=12`
   
3. **Order:** `40`
4. **Click "Create"**

### Step 3: Verify Flow

Your flow should look like this:

```
windows-otp-auth (Slug: windows-otp-auth)
├─ 10 │ Identification     (windows-identification)
├─ 20 │ Password           (windows-password)  
├─ 30 │ OTP Validation     (otp-validation)
└─ 40 │ User Login         (windows-login)
```

---

## Part 4: Configure Flow Executor API

### Important: Flow Must Be Accessible

The credential provider uses the **Flow Executor API** endpoint:
```
POST /api/v3/flows/executor/{flow_slug}/
```

### ❓ Do I Need an API Token?

**NO!** ✅ The flow executor API is **public and requires NO authentication**.

**Why?**
- This endpoint IS the authentication mechanism itself
- Users send credentials TO this endpoint to GET authenticated
- No API token, no bearer token, no authentication header needed
- Just POST username/password/OTP to the endpoint

**What DOES need tokens:**
- Authentik admin API (`/api/v3/core/*`, `/api/v3/flows/*`, etc.)
- Creating/managing users, groups, flows via API
- The credential provider does NOT use these endpoints

**This is automatically enabled** when you create a flow, but verify:

1. **Navigate to Flows & Stages → Flows**
2. **Click on your flow:** `windows-otp-auth`
3. **Check "Designation":** Must be `Authentication`
4. **Note the Slug:** `windows-otp-auth`

---

## Part 5: Test the Flow via Web Browser

Before testing with the credential provider, test the flow in a browser:

### Test URL:
```
https://your-authentik-server/if/flow/windows-otp-auth/
```

### Expected Flow:

1. **Page 1: Username Entry**
   - Enter username
   - Click "Continue"

2. **Page 2: Password Entry**
   - Enter password
   - Click "Continue"

3. **Page 3: OTP Setup (First Time Only)**
   - Scan QR code with authenticator app
   - Enter token to verify
   - Click "Continue"

4. **Page 4: OTP Validation (Subsequent Logins)**
   - Enter OTP code from app
   - Click "Continue"

5. **Success: Redirect**
   - Should redirect to Authentik dashboard
   - Or show "Authentication successful"

### If Flow Doesn't Work:

**Check:**
- [ ] All stages are bound in correct order
- [ ] LDAP source is working (users synced)
- [ ] User exists in Authentik
- [ ] User has OTP device enrolled

---

## Part 6: Test the API Endpoint

### Using PowerShell:

```powershell
# Set variables
$server = "authentik.test.local"
$port = 443
$flowSlug = "windows-otp-auth"
$url = "https://${server}:${port}/api/v3/flows/executor/${flowSlug}/"

# Test GET request (should return flow info)
Invoke-RestMethod -Uri $url -Method GET
```

**Expected Response:**
```json
{
  "type": "native",
  "component": "ak-stage-identification",
  "flow_info": {
    "title": "Windows Login",
    "background": "...",
    "cancel_url": "...",
    "layout": "stacked"
  }
}
```

### Test Authentication:

```powershell
# Test username/password
$body = @{
    uid_field = "testuser"
    password = "testpassword"
} | ConvertTo-Json

Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/json"
```

**Expected Response (if OTP required):**
```json
{
  "type": "native",
  "component": "ak-stage-authenticator-validate",
  "flow_info": {...}
}
```

---

## Part 7: User OTP Enrollment

### Method 1: Via Authentik Web UI

1. **User logs in to Authentik:**
   ```
   https://your-authentik-server/
   ```

2. **Navigate to user settings (top-right menu)**

3. **Click "MFA Devices" or "Security"**

4. **Click "Enroll new device"**

5. **Select "TOTP" (Time-based OTP)**

6. **Scan QR code with authenticator app:**
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - Any TOTP app

7. **Enter verification code**

8. **Device enrolled!**

### Method 2: During First Login

If OTP validation stage has "Configuration stage" set:

1. **User logs in with username/password**
2. **Authentik prompts for OTP setup**
3. **User scans QR code**
4. **User enters verification code**
5. **Setup complete, OTP required for future logins**

---

## Part 8: Registry Configuration on Windows

Now configure Windows to use this flow:

```powershell
# Run as Administrator
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerUrl" -Value "authentik.yourdomain.com"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "ServerPort" -Value 443 -Type DWord

# THIS MUST MATCH THE FLOW SLUG IN AUTHENTIK!
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "FlowSlug" -Value "windows-otp-auth"

Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "UseHttps" -Value 1 -Type DWord

# For testing with self-signed cert:
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" `
                 -Name "IgnoreSslErrors" -Value 1 -Type DWord
```

---

## 🔍 Troubleshooting

### Issue: "Page Not Found" When Accessing Flow URL

**URL Tried:**
```
https://authentik.test.local/api/v3/flows/executor/windows-otp-auth/
```

**Causes:**
1. **Flow doesn't exist** - Check slug in Authentik
2. **Wrong slug in URL** - Must match exactly
3. **Flow not published** - Check designation is "Authentication"

**Fix:**
```
1. Go to Flows & Stages → Flows
2. Find your flow
3. Verify slug: "windows-otp-auth"
4. Click "Export" to see full config
5. Ensure designation = "authentication"
```

---

### Issue: "Not Authenticated" Error

**Causes:**
1. **No authentication provided** - GET requests need session
2. **Wrong credentials** - Username/password incorrect
3. **User not in LDAP** - User not synced from AD
4. **LDAP source broken** - Check source connection

**Fix:**
```powershell
# Test with POST (not GET)
$body = @{
    uid_field = "testuser"
    password = "testpassword"
} | ConvertTo-Json

Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/json"
```

---

### Issue: User Cannot Enroll OTP

**Causes:**
1. **No OTP setup stage** - Create authenticator setup stage
2. **OTP stage not configured** - Check validation stage config
3. **User already has device** - Check user's MFA devices

**Fix:**
1. Ensure OTP validation stage has "Configuration stage" set
2. Set "Not configured action" to "Configure"
3. User will be prompted to enroll on first login

---

### Issue: LDAP Sync Not Working

**Check:**
```
1. Directory → Federation & Social login → Your LDAP source
2. Click "Test" - Should show success
3. Check "Bind DN" has read permissions
4. Check "Base DN" is correct
5. Check "Object filters" match your AD schema
6. Click "Run sync" manually
7. Check: Directory → Users - Should see AD users
```

**Common Errors:**
- **Invalid credentials** - Bind DN/password wrong
- **Can't reach server** - Network/firewall issue
- **No users found** - Base DN or filter wrong

---

## 📊 Complete Configuration Checklist

### Authentik Server:
- [ ] Authentik installed and running
- [ ] Admin access working
- [ ] LDAP/AD source configured
- [ ] LDAP sync successful (users imported)
- [ ] OTP setup stage created
- [ ] OTP validation stage created
- [ ] Authentication flow created with slug `windows-otp-auth`
- [ ] Flow stages bound in correct order (ID → PW → OTP → Login)
- [ ] Flow tested via web browser
- [ ] API endpoint tested via PowerShell
- [ ] At least one user has OTP enrolled

### Windows Client:
- [ ] Registry configured with correct ServerUrl
- [ ] Registry FlowSlug matches Authentik flow slug exactly
- [ ] IgnoreSslErrors=1 (if using self-signed cert)
- [ ] Network connectivity to Authentik verified
- [ ] PowerShell API test successful
- [ ] Credential provider DLL installed and registered

---

## 📚 Example Flow Configuration Export

You can export your flow to verify configuration:

**Expected Export (JSON):**
```json
{
  "pk": "...",
  "slug": "windows-otp-auth",
  "name": "Windows OTP Authentication",
  "title": "Windows Login",
  "designation": "authentication",
  "stages": [
    {
      "order": 10,
      "stage": "identification-stage-uuid"
    },
    {
      "order": 20,
      "stage": "password-stage-uuid"
    },
    {
      "order": 30,
      "stage": "otp-validation-stage-uuid"
    },
    {
      "order": 40,
      "stage": "login-stage-uuid"
    }
  ]
}
```

---

## 🎯 Quick Setup Summary

```
1. Create LDAP Source → Connect to AD
2. Create OTP Setup Stage → For device enrollment
3. Create OTP Validation Stage → For OTP verification
4. Create Flow (slug: windows-otp-auth) → Bind stages
5. Test flow in browser → Verify it works
6. Test API endpoint → Verify it responds
7. Enroll user OTP → Via web UI or first login
8. Configure Windows registry → Point to flow
9. Test credential provider → Lock screen (Win+L)
```

---

## 🆘 Need Help?

**Authentik Documentation:**
- https://goauthentik.io/docs/
- https://goauthentik.io/docs/flow/
- https://goauthentik.io/docs/sources/ldap/

**Authentik Community:**
- Discord: https://goauthentik.io/discord
- GitHub: https://github.com/goauthentik/authentik

**Check Logs:**
```bash
# Docker logs
docker-compose logs -f --tail=100 server worker

# Specific to authentik worker
docker-compose logs -f worker
```

---

**Document Version:** 1.0  
**Last Updated:** November 23, 2025

**Next Steps:**
1. Configure LDAP source in Authentik
2. Create the authentication flow
3. Test the flow via web browser
4. Test the API endpoint with PowerShell
5. Enroll a test user's OTP device
6. Test the Windows credential provider

Good luck! 🚀
