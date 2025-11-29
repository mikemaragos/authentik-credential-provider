# Register-AuthentikKSP.ps1
# Registers the Authentik Key Storage Provider with Windows

param(
    [string]$DllPath = "$env:SystemRoot\System32\AuthentikKSP.dll",
    [switch]$Unregister
)

$ErrorActionPreference = "Stop"

# Requires elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

$ProviderName = "Authentik Key Storage Provider"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

if ($Unregister) {
    Write-Host "Unregistering Authentik KSP..." -ForegroundColor Yellow
    
    if (Test-Path $RegistryPath) {
        Remove-Item -Path $RegistryPath -Recurse -Force
        Write-Host "Registry entries removed" -ForegroundColor Green
    }
    else {
        Write-Host "KSP not registered" -ForegroundColor Yellow
    }
    
    Write-Host "Note: You may need to manually delete $DllPath" -ForegroundColor Cyan
    exit 0
}

# Check if DLL exists
if (-not (Test-Path $DllPath)) {
    Write-Error "DLL not found at: $DllPath"
    exit 1
}

Write-Host "Registering Authentik KSP..." -ForegroundColor Cyan
Write-Host "DLL Path: $DllPath" -ForegroundColor Gray

# Create registry structure
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set provider properties
Set-ItemProperty -Path $RegistryPath -Name "Image Path" -Value $DllPath -Type String
Set-ItemProperty -Path $RegistryPath -Name "Type" -Value 1 -Type DWord  # Software provider
Set-ItemProperty -Path $RegistryPath -Name "SupportedAlgorithms" -Value @("RSA") -Type MultiString

# Create Functions subkey
$FunctionsPath = "$RegistryPath\Functions"
if (-not (Test-Path $FunctionsPath)) {
    New-Item -Path $FunctionsPath -Force | Out-Null
}

# Register the key storage interface
Set-ItemProperty -Path $FunctionsPath -Name "KeyStorageInterface" -Value "GetKeyStorageInterface" -Type String

Write-Host "KSP registered successfully" -ForegroundColor Green
Write-Host ""
Write-Host "Verify registration with:" -ForegroundColor Yellow
Write-Host "  certutil -csplist" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or test opening the provider:" -ForegroundColor Yellow
Write-Host '  $null = [System.Security.Cryptography.CngProvider]::new("Authentik Key Storage Provider")' -ForegroundColor Cyan
