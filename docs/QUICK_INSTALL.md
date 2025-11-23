# Quick Installation Reference

**Authentik Credential Provider - Installation Cheat Sheet**

---

## ⚡ 5-Minute Install

### Step 1: Install VC++ Redistributable (REQUIRED!)

```powershell
# Run PowerShell as Administrator
$url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\vc_redist.x64.exe"
Start-Process "$env:TEMP\vc_redist.x64.exe" -Args "/install /quiet /norestart" -Wait
```

### Step 2: Install Credential Provider

```powershell
# Copy DLL
Copy-Item AuthentikCredentialProvider.dll C:\Windows\System32\ -Force

# Register
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### Step 3: Configure

```powershell
# Create registry settings
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerUrl" -Value "authentik.yourdomain.com"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "FlowSlug" -Value "windows-otp-auth"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "UseHttps" -Value 1 -Type DWord
```

### Step 4: Reboot

```powershell
Restart-Computer
```

---

## 🔧 Troubleshooting

### regsvr32 fails with "module could not be found"
→ Install VC++ Redistributable (Step 1)

### Tile doesn't appear on lock screen
→ Check registry, reboot

### Authentication fails  
→ Check Authentik server connectivity, verify flow configuration

---

## 📚 Full Documentation

- **Installation Guide:** [INSTALLATION.md](INSTALLATION.md)
- **Prerequisites:** [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md)
- **Project Info:** [README.md](README.md)

---

**Support:** Create an issue on GitHub
