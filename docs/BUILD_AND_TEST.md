# Build and Test Instructions

## Overview

The repository is now ready to build. You'll compile two DLLs:
1. **AuthentikKSP.dll** - Custom Key Storage Provider
2. **AuthentikCredentialProvider.dll** - Windows Credential Provider

---

## Step 1: Clone/Update Repository

On your build machine (with Visual Studio 2022):

```cmd
cd C:\Projects
git clone https://github.com/mikemaragos/authentik-credential-provider.git
cd authentik-credential-provider
```

Or if already cloned:
```cmd
cd C:\Projects\authentik-credential-provider
git pull origin main
```

---

## Step 2: Open Solution

1. Open Visual Studio 2022
2. File → Open → Project/Solution
3. Navigate to: `C:\Projects\authentik-credential-provider\src\AuthentikCredentialProvider.sln`

You should see:
- **AuthentikCredentialProvider** project
- **AuthentikKSP** project
- **Shared** folder (with SharedMemory.h)

---

## Step 3: Build Both Projects

### Option A: Build All (Recommended)
1. Select configuration: **Release | x64**
2. Build → Build Solution (Ctrl+Shift+B)

### Option B: Build Individually
```
Right-click AuthentikKSP → Build
Right-click AuthentikCredentialProvider → Build
```

### Expected Output
```
src\x64\Release\AuthentikKSP.dll
src\x64\Release\AuthentikCredentialProvider.dll
```

---

## Step 4: Copy to Test Workstation

Copy both DLLs to the test workstation (192.168.1.115):

```powershell
# From build machine
$source = "C:\Projects\authentik-credential-provider\src\x64\Release"
$dest = "\\192.168.1.115\c$\Temp\AuthentikCP"

New-Item -Path $dest -ItemType Directory -Force
Copy-Item "$source\AuthentikKSP.dll" $dest
Copy-Item "$source\AuthentikCredentialProvider.dll" $dest
```

---

## Step 5: Install on Workstation

On the test workstation (as Administrator):

```powershell
cd C:\Temp\AuthentikCP

# Copy DLLs to System32
Copy-Item AuthentikKSP.dll C:\Windows\System32\ -Force
Copy-Item AuthentikCredentialProvider.dll C:\Windows\System32\ -Force

# Register KSP
$KspPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider"
New-Item -Path $KspPath -Force
Set-ItemProperty -Path $KspPath -Name "Image Path" -Value "C:\Windows\System32\AuthentikKSP.dll"
Set-ItemProperty -Path $KspPath -Name "Type" -Value 1

$FuncPath = "$KspPath\Functions"
New-Item -Path $FuncPath -Force
Set-ItemProperty -Path $FuncPath -Name "KeyStorageInterface" -Value "GetKeyStorageInterface"

# Register Credential Provider
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll

# Configure settings (update values as needed)
$ConfigPath = "HKLM:\SOFTWARE\AuthentikCredentialProvider"
New-Item -Path $ConfigPath -Force
Set-ItemProperty -Path $ConfigPath -Name "ServerUrl" -Value "authentik.test.local"
Set-ItemProperty -Path $ConfigPath -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path $ConfigPath -Name "FlowSlug" -Value "windows-passwordless"
Set-ItemProperty -Path $ConfigPath -Name "UseHttps" -Value 1 -Type DWord
Set-ItemProperty -Path $ConfigPath -Name "CertIssuerUrl" -Value "http://192.168.1.101:8443"
Set-ItemProperty -Path $ConfigPath -Name "CertIssuerToken" -Value "726ca6c60f8840acb97be6979c261eac"
Set-ItemProperty -Path $ConfigPath -Name "Domain" -Value "TEST"
Set-ItemProperty -Path $ConfigPath -Name "DomainFQDN" -Value "test.local"

Write-Host "Installation complete - REBOOT REQUIRED" -ForegroundColor Yellow
```

---

## Step 6: Reboot

```powershell
Restart-Computer
```

---

## Step 7: Test and Debug

### Start DebugView
1. Download DebugView: https://docs.microsoft.com/sysinternals/downloads/debugview
2. Run as Administrator
3. Capture → Capture Global Win32
4. Filter (optional): `Authentik`

### Lock Screen and Test
1. Press Win+L
2. Look for "Authentik Passwordless Login" tile
3. Enter username: `shop`
4. Enter OTP from authenticator

### Watch Debug Output
You should see:
```
[AuthentikCP] Starting authentication...
[AuthentikCP] OTP validated successfully
[AuthentikCP] Requesting certificate...
[AuthentikCP] Certificate received, storing in KSP...
[AuthentikKSP] StoreKey: container=AuthentikPKINIT_..., keyLen=..., certLen=...
[AuthentikKSP] StoreKey: Success
[AuthentikCP] Building KERB_CERTIFICATE_LOGON...
[AuthentikKSP] OpenProvider: ...
[AuthentikKSP] OpenKey: ...
[AuthentikKSP] SignHash: ...
[AuthentikKSP] SignHash succeeded
```

---

## Step 8: Verify on Domain Controller

Check Kerberos event logs:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} -MaxEvents 5 |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[0].Value}}, 
                  @{N='PreAuthType';E={$_.Properties[11].Value}} |
    Format-Table
```

**Success indicators:**
- Pre-Authentication Type: **16** or **17** (PKINIT)
- Certificate Issuer Name: **test-WIN-6DP39D0OLI8-CA**
- Certificate Thumbprint: (populated)

**Failure indicators:**
- Pre-Authentication Type: **2** (password - KSP not being used)
- Certificate info empty

---

## Troubleshooting

### KSP Not Found
```powershell
# Verify KSP registration
certutil -csplist | Select-String "Authentik"

# Check registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik*"
```

### Key Not Found (NTE_BAD_KEYSET)
- Check DebugView for `StoreKey` messages
- Verify shared memory is created: `handle.exe -a Global\AuthentikKSPKeyStore`

### Build Errors
- Ensure Windows SDK 10.0 installed
- Use x64 platform (not x86)
- Check include paths in project properties

### Credential Provider Not Showing
```powershell
# Check registration
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" | 
    Where-Object { $_.PSChildName -like "*8B7C4F9E*" }
```

---

## Quick Uninstall

```powershell
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider" -Recurse -Force
Remove-Item C:\Windows\System32\AuthentikKSP.dll -Force
Remove-Item C:\Windows\System32\AuthentikCredentialProvider.dll -Force
Remove-Item "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Recurse -Force
Restart-Computer
```
