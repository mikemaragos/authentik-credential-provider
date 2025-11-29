# Uninstall-AuthentikCredentialProvider.ps1
# Complete uninstallation script for Authentik Credential Provider and KSP
#
# Run as Administrator on the target workstation

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipReboot
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Authentik Credential Provider Uninstaller" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# ============================================================================
# Unregister Credential Provider
# ============================================================================

Write-Host "Unregistering Credential Provider..." -ForegroundColor Yellow

$cpDll = "$env:SystemRoot\System32\AuthentikCredentialProvider.dll"
if (Test-Path $cpDll) {
    $null = & regsvr32 /u /s $cpDll 2>&1
    Remove-Item $cpDll -Force -ErrorAction SilentlyContinue
    Write-Host "  Credential Provider unregistered and removed" -ForegroundColor Green
} else {
    Write-Host "  Credential Provider not found" -ForegroundColor Gray
}

# ============================================================================
# Unregister KSP
# ============================================================================

Write-Host ""
Write-Host "Unregistering Key Storage Provider..." -ForegroundColor Yellow

$ProviderName = "Authentik Key Storage Provider"
$KspRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

if (Test-Path $KspRegPath) {
    Remove-Item $KspRegPath -Recurse -Force
    Write-Host "  KSP registry entries removed" -ForegroundColor Green
} else {
    Write-Host "  KSP registry not found" -ForegroundColor Gray
}

$kspDll = "$env:SystemRoot\System32\AuthentikKSP.dll"
if (Test-Path $kspDll) {
    Remove-Item $kspDll -Force -ErrorAction SilentlyContinue
    Write-Host "  KSP DLL removed" -ForegroundColor Green
} else {
    Write-Host "  KSP DLL not found" -ForegroundColor Gray
}

# ============================================================================
# Remove Configuration
# ============================================================================

Write-Host ""
Write-Host "Removing configuration..." -ForegroundColor Yellow

$ConfigPath = "HKLM:\SOFTWARE\AuthentikCredentialProvider"
if (Test-Path $ConfigPath) {
    Remove-Item $ConfigPath -Recurse -Force
    Write-Host "  Configuration removed" -ForegroundColor Green
} else {
    Write-Host "  Configuration not found" -ForegroundColor Gray
}

# ============================================================================
# Complete
# ============================================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Uninstallation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipReboot) {
    Write-Host "A reboot is recommended." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Reboot now? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Rebooting in 5 seconds..."
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
}
