# Register-AuthentikKSP.ps1
# Registers the Authentik Key Storage Provider with Windows
#
# Uses the correct CNG provider registration format with UM subkey
# Compatible with Windows 10/11 and Windows Server 2016+

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
$BasePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

if ($Unregister) {
    Write-Host "Unregistering Authentik KSP..." -ForegroundColor Yellow
    
    if (Test-Path $BasePath) {
        Remove-Item -Path $BasePath -Recurse -Force
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

# Remove any existing registration
if (Test-Path $BasePath) {
    Write-Host "Removing existing registration..." -ForegroundColor Yellow
    Remove-Item -Path $BasePath -Recurse -Force
}

# ============================================================================
# Create the correct CNG Provider registry structure
# This matches Microsoft's KSP registration format
# ============================================================================

# Create provider base key
New-Item -Path $BasePath -Force | Out-Null

# Create UM (User Mode) subkey
$UMPath = "$BasePath\UM"
New-Item -Path $UMPath -Force | Out-Null

# Set the Image value - just the DLL name, not full path
# Windows looks in System32 automatically
Set-ItemProperty -Path $UMPath -Name "Image" -Value "AuthentikKSP.dll" -Type String

# Create interface version subkey
# 00010001 = NCRYPT_KEY_STORAGE_INTERFACE_VERSION (1.1)
$InterfacePath = "$UMPath\00010001"
New-Item -Path $InterfacePath -Force | Out-Null

# Set interface properties
# (Default) = Interface type identifier
Set-ItemProperty -Path $InterfacePath -Name "(default)" -Value "CRYPT_KEY_STORAGE_INTERFACE" -Type String

# Flags = 0x00010000 (65536) = NCRYPT_REGISTER_NOTIFY_FLAG
Set-ItemProperty -Path $InterfacePath -Name "Flags" -Value 65536 -Type DWord

# Functions = Function group name
Set-ItemProperty -Path $InterfacePath -Name "Functions" -Value "KEY_STORAGE" -Type String

Write-Host "KSP registered successfully" -ForegroundColor Green
Write-Host ""
Write-Host "Registry structure created:" -ForegroundColor Cyan
Write-Host "  $BasePath" -ForegroundColor Gray
Write-Host "    \UM" -ForegroundColor Gray
Write-Host "      Image = AuthentikKSP.dll" -ForegroundColor Gray
Write-Host "      \00010001" -ForegroundColor Gray
Write-Host "        (default) = CRYPT_KEY_STORAGE_INTERFACE" -ForegroundColor Gray
Write-Host "        Flags = 65536" -ForegroundColor Gray
Write-Host "        Functions = KEY_STORAGE" -ForegroundColor Gray
Write-Host ""
Write-Host "Verify registration with:" -ForegroundColor Yellow
Write-Host "  certutil -csplist" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or check registry:" -ForegroundColor Yellow
Write-Host "  Get-ChildItem '$BasePath' -Recurse" -ForegroundColor Cyan
