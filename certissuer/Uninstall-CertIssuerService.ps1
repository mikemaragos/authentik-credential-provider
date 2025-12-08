<#
.SYNOPSIS
    Uninstall CertIssuer Service
    
.DESCRIPTION
    Stops and removes the CertIssuer service and optionally removes all files.
    
.EXAMPLE
    .\Uninstall-CertIssuerService.ps1
    .\Uninstall-CertIssuerService.ps1 -RemoveFiles
#>

param(
    [string]$ServiceName = "CertIssuer",
    [string]$InstallPath = "C:\CertIssuer",
    [switch]$RemoveFiles
)

$ErrorActionPreference = "Stop"

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "CertIssuer Service Uninstaller" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Must run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Stop and remove service
Write-Host "`nChecking for service..." -ForegroundColor Yellow

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  Found service: $ServiceName (Status: $($service.Status))" -ForegroundColor White
    
    if ($service.Status -eq 'Running') {
        Write-Host "  Stopping service..." -ForegroundColor White
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    Write-Host "  Removing service..." -ForegroundColor White
    
    # Try NSSM
    $nssm = "$InstallPath\nssm.exe"
    if (Test-Path $nssm) {
        & $nssm remove $ServiceName confirm 2>$null
    }
    
    # Also try sc.exe
    & sc.exe delete $ServiceName 2>$null
    
    Write-Host "  Service removed" -ForegroundColor Green
} else {
    Write-Host "  No service found with name: $ServiceName" -ForegroundColor Gray
}

# Remove scheduled task if exists
Write-Host "`nChecking for scheduled task..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "  Removing scheduled task..." -ForegroundColor White
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    Write-Host "  Task removed" -ForegroundColor Green
} else {
    Write-Host "  No scheduled task found" -ForegroundColor Gray
}

# Remove URL ACL
Write-Host "`nRemoving URL ACL..." -ForegroundColor Yellow
& netsh http delete urlacl url=http://+:8443/ 2>$null
Write-Host "  Done" -ForegroundColor Green

# Remove files
if ($RemoveFiles) {
    Write-Host "`nRemoving installation files..." -ForegroundColor Yellow
    if (Test-Path $InstallPath) {
        Remove-Item -Path $InstallPath -Recurse -Force
        Write-Host "  Removed: $InstallPath" -ForegroundColor Green
    } else {
        Write-Host "  Path not found: $InstallPath" -ForegroundColor Gray
    }
} else {
    Write-Host "`nInstallation files preserved at: $InstallPath" -ForegroundColor Gray
    Write-Host "  Use -RemoveFiles to delete" -ForegroundColor Gray
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Uninstallation Complete" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan
