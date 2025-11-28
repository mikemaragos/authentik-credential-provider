# Register-AuthentikKSP.ps1
# Registers the Authentik Key Storage Provider with Windows

param(
    [switch]$Unregister,
    [string]$DllPath = "$PSScriptRoot\AuthentikKSP.dll"
)

$ErrorActionPreference = "Stop"

# KSP registration information
$KspName = "Authentik Key Storage Provider"
$KspRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$KspName"

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Register-KSP {
    param([string]$DllPath)
    
    Write-Host "Registering Authentik KSP..." -ForegroundColor Cyan
    
    # Verify DLL exists
    if (-not (Test-Path $DllPath)) {
        throw "DLL not found: $DllPath"
    }
    
    # Get full path
    $FullDllPath = (Resolve-Path $DllPath).Path
    Write-Host "DLL Path: $FullDllPath"
    
    # Copy to System32 for reliability
    $SystemDllPath = "C:\Windows\System32\AuthentikKSP.dll"
    Copy-Item $FullDllPath $SystemDllPath -Force
    Write-Host "Copied DLL to: $SystemDllPath" -ForegroundColor Green
    
    # Create registry entries
    if (Test-Path $KspRegistryPath) {
        Remove-Item -Path $KspRegistryPath -Recurse -Force
    }
    
    New-Item -Path $KspRegistryPath -Force | Out-Null
    
    # Set Image Path
    Set-ItemProperty -Path $KspRegistryPath -Name "Image Path" -Value $SystemDllPath -Type String
    
    # Set provider type (0 = CNG Key Storage Provider)
    Set-ItemProperty -Path $KspRegistryPath -Name "Type" -Value 0 -Type DWord
    
    # Set the function table entry point
    Set-ItemProperty -Path $KspRegistryPath -Name "Functions" -Value "GetKeyStorageInterface" -Type String
    
    Write-Host "Registry entries created at: $KspRegistryPath" -ForegroundColor Green
    
    # Verify registration
    Write-Host "`nVerifying registration..." -ForegroundColor Cyan
    
    $regValues = Get-ItemProperty -Path $KspRegistryPath
    Write-Host "  Image Path: $($regValues.'Image Path')"
    Write-Host "  Type: $($regValues.Type)"
    Write-Host "  Functions: $($regValues.Functions)"
    
    # Test loading the KSP
    Write-Host "`nTesting KSP loading..." -ForegroundColor Cyan
    
    try {
        # This will attempt to load our KSP
        $providers = (certutil -csplist 2>&1) -join "`n"
        if ($providers -match "Authentik") {
            Write-Host "KSP loaded successfully!" -ForegroundColor Green
        } else {
            Write-Host "KSP registered but not showing in certutil yet. May need reboot." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Could not verify KSP loading: $_" -ForegroundColor Yellow
    }
    
    Write-Host "`nRegistration complete!" -ForegroundColor Green
    Write-Host "You may need to reboot for changes to take full effect." -ForegroundColor Yellow
}

function Unregister-KSP {
    Write-Host "Unregistering Authentik KSP..." -ForegroundColor Cyan
    
    # Remove registry entries
    if (Test-Path $KspRegistryPath) {
        Remove-Item -Path $KspRegistryPath -Recurse -Force
        Write-Host "Registry entries removed" -ForegroundColor Green
    } else {
        Write-Host "Registry entries not found" -ForegroundColor Yellow
    }
    
    # Remove DLL from System32
    $SystemDllPath = "C:\Windows\System32\AuthentikKSP.dll"
    if (Test-Path $SystemDllPath) {
        try {
            Remove-Item $SystemDllPath -Force
            Write-Host "DLL removed from System32" -ForegroundColor Green
        } catch {
            Write-Host "Could not remove DLL (may be in use): $_" -ForegroundColor Yellow
            Write-Host "Try again after reboot" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nUnregistration complete!" -ForegroundColor Green
}

# Main
if (-not (Test-Administrator)) {
    throw "This script requires Administrator privileges. Please run as Administrator."
}

if ($Unregister) {
    Unregister-KSP
} else {
    Register-KSP -DllPath $DllPath
}
