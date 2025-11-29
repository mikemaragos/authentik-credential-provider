# Install-AuthentikCredentialProvider.ps1
# Complete installation script for Authentik Credential Provider and KSP
#
# This script installs both:
# - AuthentikKSP.dll - Custom Key Storage Provider
# - AuthentikCredentialProvider.dll - Windows Credential Provider
#
# Run as Administrator on the target workstation

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$AuthentikServer = "authentik.test.local",
    
    [Parameter(Mandatory=$false)]
    [int]$AuthentikPort = 443,
    
    [Parameter(Mandatory=$false)]
    [string]$FlowSlug = "windows-passwordless",
    
    [Parameter(Mandatory=$false)]
    [string]$CertIssuerUrl = "",
    
    [Parameter(Mandatory=$false)]
    [string]$CertIssuerToken = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DomainFQDN = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReboot
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Check Prerequisites
# ============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Authentik Credential Provider Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Check source files exist
$kspDll = Join-Path $SourcePath "AuthentikKSP.dll"
$cpDll = Join-Path $SourcePath "AuthentikCredentialProvider.dll"

if (-not (Test-Path $kspDll)) {
    Write-Error "AuthentikKSP.dll not found at: $kspDll"
    exit 1
}

if (-not (Test-Path $cpDll)) {
    Write-Error "AuthentikCredentialProvider.dll not found at: $cpDll"
    exit 1
}

Write-Host "Source files found:" -ForegroundColor Green
Write-Host "  KSP: $kspDll"
Write-Host "  CP:  $cpDll"
Write-Host ""

# ============================================================================
# Install KSP
# ============================================================================

Write-Host "Installing Key Storage Provider..." -ForegroundColor Yellow

# Copy DLL
$targetKsp = "$env:SystemRoot\System32\AuthentikKSP.dll"
Copy-Item $kspDll $targetKsp -Force
Write-Host "  Copied to: $targetKsp" -ForegroundColor Gray

# Register KSP
$ProviderName = "Authentik Key Storage Provider"
$KspRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

if (Test-Path $KspRegPath) {
    Remove-Item $KspRegPath -Recurse -Force
}

New-Item -Path $KspRegPath -Force | Out-Null
Set-ItemProperty -Path $KspRegPath -Name "Image Path" -Value $targetKsp -Type String
Set-ItemProperty -Path $KspRegPath -Name "Type" -Value 1 -Type DWord

$FunctionsPath = "$KspRegPath\Functions"
New-Item -Path $FunctionsPath -Force | Out-Null
Set-ItemProperty -Path $FunctionsPath -Name "KeyStorageInterface" -Value "GetKeyStorageInterface" -Type String

Write-Host "  KSP registered" -ForegroundColor Green

# ============================================================================
# Install Credential Provider
# ============================================================================

Write-Host ""
Write-Host "Installing Credential Provider..." -ForegroundColor Yellow

# Copy DLL
$targetCp = "$env:SystemRoot\System32\AuthentikCredentialProvider.dll"
Copy-Item $cpDll $targetCp -Force
Write-Host "  Copied to: $targetCp" -ForegroundColor Gray

# Register DLL
$regResult = & regsvr32 /s $targetCp 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to register credential provider: $regResult"
    exit 1
}
Write-Host "  Credential Provider registered" -ForegroundColor Green

# ============================================================================
# Configure Settings
# ============================================================================

Write-Host ""
Write-Host "Configuring settings..." -ForegroundColor Yellow

$ConfigPath = "HKLM:\SOFTWARE\AuthentikCredentialProvider"

if (-not (Test-Path $ConfigPath)) {
    New-Item -Path $ConfigPath -Force | Out-Null
}

# Authentik settings
Set-ItemProperty -Path $ConfigPath -Name "ServerUrl" -Value $AuthentikServer -Type String
Set-ItemProperty -Path $ConfigPath -Name "ServerPort" -Value $AuthentikPort -Type DWord
Set-ItemProperty -Path $ConfigPath -Name "FlowSlug" -Value $FlowSlug -Type String
Set-ItemProperty -Path $ConfigPath -Name "UseHttps" -Value 1 -Type DWord

Write-Host "  Authentik: https://${AuthentikServer}:${AuthentikPort}" -ForegroundColor Gray
Write-Host "  Flow: $FlowSlug" -ForegroundColor Gray

# Certificate issuer settings (if provided)
if ($CertIssuerUrl) {
    Set-ItemProperty -Path $ConfigPath -Name "CertIssuerUrl" -Value $CertIssuerUrl -Type String
    Write-Host "  Cert Issuer: $CertIssuerUrl" -ForegroundColor Gray
}

if ($CertIssuerToken) {
    Set-ItemProperty -Path $ConfigPath -Name "CertIssuerToken" -Value $CertIssuerToken -Type String
    Write-Host "  Cert Issuer Token: (configured)" -ForegroundColor Gray
}

# Domain settings
if ($Domain) {
    Set-ItemProperty -Path $ConfigPath -Name "Domain" -Value $Domain -Type String
    Write-Host "  Domain: $Domain" -ForegroundColor Gray
}

if ($DomainFQDN) {
    Set-ItemProperty -Path $ConfigPath -Name "DomainFQDN" -Value $DomainFQDN -Type String
    Write-Host "  Domain FQDN: $DomainFQDN" -ForegroundColor Gray
}

Write-Host "  Settings configured" -ForegroundColor Green

# ============================================================================
# Verify Installation
# ============================================================================

Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Yellow

# Check KSP
$kspCheck = & certutil -csplist 2>&1 | Select-String "Authentik"
if ($kspCheck) {
    Write-Host "  KSP: Registered" -ForegroundColor Green
} else {
    Write-Host "  KSP: Not found in csplist (may need reboot)" -ForegroundColor Yellow
}

# Check Credential Provider
$cpGuid = "{8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}"
$cpRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$cpGuid"
if (Test-Path $cpRegPath) {
    Write-Host "  Credential Provider: Registered" -ForegroundColor Green
} else {
    Write-Host "  Credential Provider: Not found" -ForegroundColor Red
}

# ============================================================================
# Complete
# ============================================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipReboot) {
    Write-Host "A reboot is required to complete installation." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Reboot now? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Rebooting in 5 seconds..."
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    } else {
        Write-Host "Please reboot manually to complete installation."
    }
} else {
    Write-Host "Reboot skipped. Please reboot manually to complete installation." -ForegroundColor Yellow
}
