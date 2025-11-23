# Deployment Prerequisites

**Authentik Credential Provider for Windows**  
**Version:** 2.0  
**Last Updated:** November 23, 2025

---

## 📋 Pre-Deployment Checklist

Use this checklist to ensure your environment is ready before deploying the Authentik Credential Provider.

---

## ✅ System Requirements

### Operating System
- [ ] Windows 10 version 1903 or later
- [ ] Windows 11 (any version)
- [ ] Windows Server 2019
- [ ] Windows Server 2022

### Architecture
- [ ] 64-bit (x64) operating system
- [ ] **NOT** 32-bit (x86) - the credential provider is x64 only

### Access
- [ ] Local Administrator rights
- [ ] Ability to reboot the machine
- [ ] Access to Safe Mode (for recovery if needed)

---

## 🔧 Required Software Components

### 1. Visual C++ Redistributable (CRITICAL!)

**Package:** Microsoft Visual C++ 2015-2022 Redistributable (x64)

**Why Required:**
- The credential provider is compiled with Visual Studio 2022
- Requires runtime libraries: `vcruntime140.dll`, `msvcp140.dll`, `concrt140.dll`
- These DLLs are NOT included with Windows

**Download:**
- **Direct Link:** https://aka.ms/vs/17/release/vc_redist.x64.exe
- **File Size:** ~25 MB
- **Installation Time:** ~30 seconds

**Installation Command:**
```powershell
# Download and install
$url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$installer = "$env:TEMP\vc_redist.x64.exe"
Invoke-WebRequest -Uri $url -OutFile $installer
Start-Process -FilePath $installer -ArgumentList "/install", "/quiet", "/norestart" -Wait
```

**Verification:**
```powershell
# Check if installed
$vcRedist = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue
if ($vcRedist) {
    Write-Host "✅ VC++ Redistributable is installed"
    Write-Host "   Version: $($vcRedist.Major).$($vcRedist.Minor).$($vcRedist.Bld)"
} else {
    Write-Host "❌ VC++ Redistributable is NOT installed - MUST INSTALL!"
}
```

**What Happens Without It:**
- `regsvr32` will fail with "The specified module could not be found"
- The DLL won't load even though it exists in System32
- Windows can't find the runtime dependencies

**Deployment Note:**
- Must be installed on EVERY machine that will use the credential provider
- Can be deployed via Group Policy, SCCM, Intune, etc.
- Silent installation is supported (see command above)

---

### 2. Windows Updates

**Recommended:**
- [ ] All critical Windows updates installed
- [ ] Latest security patches
- [ ] .NET Framework 4.8 or later (usually pre-installed)

**Check for Updates:**
```powershell
# Check Windows Update status
Get-WindowsUpdate -MicrosoftUpdate
```

---

## 🌐 Network Requirements

### Authentik Server Connectivity

**Required:**
- [ ] Network path to Authentik server
- [ ] DNS resolution for Authentik hostname
- [ ] Firewall allows HTTPS (port 443) to Authentik
- [ ] Valid SSL certificate on Authentik (or planned workaround)

**Test Connectivity:**
```powershell
# Test DNS resolution
Resolve-DnsName authentik.yourdomain.com

# Test HTTPS connectivity
Test-NetConnection -ComputerName authentik.yourdomain.com -Port 443

# Test full HTTPS connection
Invoke-WebRequest -Uri "https://authentik.yourdomain.com" -UseBasicParsing
```

### Ports Required

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Windows Client | Authentik Server | 443 | HTTPS | Authentication API |

**Firewall Rules:**
- [ ] Outbound HTTPS allowed to Authentik server
- [ ] No proxy interference (or proxy configured)
- [ ] No SSL inspection breaking the connection

---

## 🔐 Active Directory / Domain

### Domain Requirements

**If using domain authentication:**
- [ ] Machine is joined to Active Directory domain
- [ ] Users exist in AD
- [ ] Domain controller is reachable
- [ ] DNS is properly configured

**Test Domain Connectivity:**
```powershell
# Check domain membership
(Get-WmiObject Win32_ComputerSystem).PartOfDomain

# Test domain controller connectivity
Test-ComputerSecureChannel -Verbose

# Check AD services
Get-Service -Name "ADWS", "DNS", "Netlogon" | Select-Object Name, Status
```

### User Requirements

For each user who will authenticate:
- [ ] Active Directory account exists
- [ ] Account exists in Authentik
- [ ] Username matches between AD and Authentik
- [ ] OTP device enrolled in Authentik (if using OTP)
- [ ] User has logged in to Authentik web interface at least once

---

## 🛠️ Development/Build Requirements

**Only needed if building from source:**

### Visual Studio 2022
- [ ] Visual Studio 2022 Community, Professional, or Enterprise
- [ ] Desktop development with C++ workload
- [ ] Windows 10 SDK (10.0.19041.0 or later)
- [ ] MSBuild tools
- [ ] Git for version control

### Build Tools
```powershell
# Verify Visual Studio installation
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
if (Test-Path $vsPath) {
    Write-Host "✅ Visual Studio 2022 installed"
} else {
    Write-Host "❌ Visual Studio 2022 NOT found"
}
```

---

## 📦 Deployment Package

### Files to Deploy

**Minimum deployment package:**
```
AuthentikCredentialProvider.dll  (542 KB - Release build)
vc_redist.x64.exe               (25 MB - VC++ Redistributable)
install.ps1                      (Installation script)
config.reg                       (Registry configuration)
```

**Optional files:**
```
README.md                        (Documentation)
INSTALLATION.md                  (Installation guide)
uninstall.ps1                    (Uninstall script)
```

### Registry Configuration File

**config.reg example:**
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="authentik.yourdomain.com"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-otp-auth"
"UseHttps"=dword:00000001
```

---

## 🧪 Testing Environment

### Pre-Production Testing

**Before deploying to production:**
- [ ] Test VM or physical test machine available
- [ ] Snapshot/backup taken before installation
- [ ] Test with at least 3 different user accounts
- [ ] Test wrong password scenario
- [ ] Test wrong OTP scenario
- [ ] Test network disconnection scenario
- [ ] Recovery procedure tested (uninstall, Safe Mode)

### Test Accounts

Create these test scenarios:
- [ ] User with OTP enrolled - should work
- [ ] User without OTP enrolled - should handle gracefully
- [ ] User with wrong password - should reject
- [ ] User not in Authentik - should reject

---

## 📊 Monitoring & Logging

### Logging Tools

**For troubleshooting:**
- [ ] DebugView installed (https://docs.microsoft.com/sysinternals/downloads/debugview)
- [ ] Windows Event Viewer configured
- [ ] Authentik server logs accessible

**Enable Debug Logging:**
```powershell
# DebugView captures OutputDebugString calls
# Run as Administrator
# Capture → Capture Win32
# Capture → Capture Global Win32
# Filter: AuthentikCP*
```

---

## 🚨 Backup & Recovery

### Before Installation

**Create restore points:**
- [ ] Windows System Restore point created
- [ ] Registry backup created
- [ ] Know how to boot to Safe Mode
- [ ] Have alternate admin account available

**Create System Restore Point:**
```powershell
# Enable System Restore if not enabled
Enable-ComputerRestore -Drive "C:\"

# Create restore point
Checkpoint-Computer -Description "Before Authentik CP Install" -RestorePointType "MODIFY_SETTINGS"
```

**Backup Registry:**
```powershell
# Export credential providers registry
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" `
           "$env:USERPROFILE\Desktop\CredentialProviders_Backup.reg"
```

### Safe Mode Access

**Know how to access Safe Mode:**
1. Hold Shift while clicking Restart
2. Troubleshoot → Advanced → Startup Settings → Restart
3. Press F4 for Safe Mode

**Or use bcdedit:**
```powershell
# Set Safe Mode for next boot
bcdedit /set {default} safeboot minimal
# Reboot, then remove Safe Mode:
bcdedit /deletevalue {default} safeboot
```

---

## 📝 Documentation Required

### For Deployment Team

- [ ] Installation guide (INSTALLATION.md)
- [ ] Configuration guide (registry settings)
- [ ] Troubleshooting guide
- [ ] Rollback procedure
- [ ] Contact information for support

### For End Users

- [ ] How to enroll OTP in Authentik
- [ ] How to use the new login screen
- [ ] What to do if locked out
- [ ] IT support contact information

---

## 🎯 Authentik Server Configuration

### Authentik Flow

**Required flow configuration:**
- [ ] Flow created in Authentik (e.g., "windows-otp-auth")
- [ ] Flow includes these stages:
  - [ ] Identification stage (username)
  - [ ] Password validation stage (optional if using SSO)
  - [ ] Authenticator validation stage (OTP)
  - [ ] User login stage
- [ ] Flow slug matches registry configuration exactly

**Test the Flow:**
- [ ] Flow works via Authentik web interface
- [ ] All stages execute correctly
- [ ] OTP validation works
- [ ] Flow returns success response

### Authentik API

**Verify API access:**
```powershell
# Test Authentik API endpoint
$url = "https://authentik.yourdomain.com/api/v3/flows/executor/windows-otp-auth/"
try {
    Invoke-WebRequest -Uri $url -UseBasicParsing
    Write-Host "✅ Authentik API is reachable"
} catch {
    Write-Host "❌ Cannot reach Authentik API: $_"
}
```

---

## 💾 Deployment Methods

### Manual Installation
**Suitable for:** 1-10 machines
- Copy DLL manually
- Run regsvr32
- Configure registry
- Reboot

### Group Policy Deployment
**Suitable for:** Enterprise
- Create MSI package
- Deploy via GPO
- Configure registry via GPO preferences
- Schedule reboot

### SCCM/Intune Deployment
**Suitable for:** Large enterprise
- Package as application
- Deploy to device collections
- Use PowerShell scripts
- Monitor deployment status

---

## ✅ Final Pre-Deployment Checklist

Before rolling out to production:

**Technical:**
- [ ] VC++ Redistributable installed on all target machines
- [ ] Credential provider DLL tested and working
- [ ] Registry configuration prepared
- [ ] Authentik server configured and tested
- [ ] Network connectivity verified
- [ ] Domain integration working

**Documentation:**
- [ ] Installation guide reviewed
- [ ] User guide created
- [ ] Support procedures documented
- [ ] Rollback plan tested

**Testing:**
- [ ] Pilot group identified (5-10 users)
- [ ] Test scenarios completed successfully
- [ ] Error scenarios handled correctly
- [ ] Recovery procedures tested

**Communication:**
- [ ] Users notified of changes
- [ ] IT support team trained
- [ ] Helpdesk prepared for calls
- [ ] Rollback window identified

**Safety:**
- [ ] Backups completed
- [ ] Restore points created
- [ ] Safe Mode access verified
- [ ] Alternate authentication method available

---

## 🆘 Emergency Contacts

**Before deploying, document:**

| Role | Contact | Phone | Email |
|------|---------|-------|-------|
| Project Lead | | | |
| Windows Admin | | | |
| Authentik Admin | | | |
| Network Team | | | |
| Helpdesk | | | |

---

## 📅 Recommended Deployment Schedule

### Phase 1: Pilot (Week 1)
- Install on 5-10 test machines
- Monitor closely for issues
- Collect feedback from pilot users
- Refine documentation

### Phase 2: Limited Rollout (Week 2-3)
- Deploy to one department or location
- Continue monitoring
- Provide enhanced support

### Phase 3: Full Rollout (Week 4+)
- Deploy to all target machines
- Standard support level
- Document lessons learned

---

**Document Version:** 1.0  
**Last Updated:** November 23, 2025  
**Status:** Production Ready

**Questions?** Review the Installation Guide or contact your deployment team.
