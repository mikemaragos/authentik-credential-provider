# Deployment Guide

## Prerequisites Checklist

### Domain Controller
- [ ] Windows Server 2019 or later
- [ ] AD CS role installed with Enterprise CA
- [ ] Certificate template created for smart card logon
- [ ] CertIssuer service installed
- [ ] `StrongCertificateBindingEnforcement` configured
- [ ] Firewall allows port 8443

### Workstation
- [ ] Windows 10/11 Pro
- [ ] Domain joined
- [ ] TPM 2.0 present and enabled
- [ ] Virtual Smart Card created
- [ ] Administrator access for installation

### Network
- [ ] Workstation can reach DC on port 8443 (CertIssuer)
- [ ] Workstation can reach DC on port 88 (Kerberos)
- [ ] DC can reach Authentik server

---

## Step 1: Domain Controller Setup

### Install CertIssuer Service

```powershell
# Copy certissuer folder to DC
Copy-Item -Path .\certissuer -Destination C:\CertIssuer -Recurse

# Install Python dependencies
cd C:\CertIssuer
pip install -r requirements.txt

# Configure
Copy-Item config.example.json config.json
# Edit config.json with your settings

# Install as Windows service
.\Install-CertIssuerService.ps1

# Start service
Start-Service CertIssuer
```

### Configure Registry

```powershell
# Allow compatibility mode for certificate mapping
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
    -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord

# Restart KDC
Restart-Service KDC
```

---

## Step 2: Workstation Setup

### Create Virtual Smart Card

```powershell
# Run as Administrator
tpmvscmgr.exe create /name "AuthentikVSC" /pin default /adminkey random /generate

# Verify
certutil -scinfo
```

### Install Credential Provider

```powershell
# Copy DLL
Copy-Item AuthentikCredentialProvider.dll C:\Windows\System32\

# Register
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll

# Configure
reg import phase2-config.reg

# Reboot
shutdown /r /t 0
```

---

## Step 3: Verify Installation

### On Workstation

1. Press **Win+L** to lock screen
2. Verify **Authentik OTP Login** tile appears
3. Run DebugView as Admin to monitor logs

### Test Authentication

1. Enter username
2. Enter OTP from Authentik
3. Click Sign in
4. Verify successful login

### Check DC Logs

```powershell
# View Kerberos authentication events
Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4768 -and $_.Message -like "*Pre-Auth Type*16*"
} | Select-Object -First 5
```

Pre-Auth Type 16 = PKINIT (certificate)
Pre-Auth Type 2 = Password (fallback)

---

## Rollback Procedure

If issues occur:

```powershell
# Boot to Safe Mode if needed

# Unregister DLL
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll

# Delete DLL
Remove-Item C:\Windows\System32\AuthentikCredentialProvider.dll

# Reboot
shutdown /r /t 0
```

---

## Production Hardening

Before production deployment:

1. **Enable certificate validation** - Remove SSL bypass in AuthentikAPI.cpp
2. **Use strong certificate mapping** - Configure SKI mapping
3. **Secure API tokens** - Store encrypted, rotate regularly
4. **Enable logging** - Configure Windows Event Log integration
5. **Test recovery** - Ensure Safe Mode access works
6. **Deploy via GPO** - Use Group Policy for consistent deployment
