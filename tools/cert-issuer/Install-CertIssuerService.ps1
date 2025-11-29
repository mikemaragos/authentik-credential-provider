# Install-CertIssuerService.ps1
# Installs the Certificate Issuer as a Windows Service

param(
    [string]$ServiceName = "AuthentikCertIssuer",
    [string]$InstallPath = "C:\AuthentikCertIssuer",
    [int]$Port = 8443,
    [string]$ApiToken = "",
    [string]$CAConfig = "WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA",
    [string]$CertTemplate = "SmartcardLogon"
)

#Requires -RunAsAdministrator

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Certificate Issuer Service Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Generate API token if not provided
if (-not $ApiToken) {
    $ApiToken = [System.Guid]::NewGuid().ToString("N")
    Write-Host "Generated API Token: $ApiToken" -ForegroundColor Yellow
    Write-Host "SAVE THIS TOKEN - you'll need it for Authentik configuration!" -ForegroundColor Red
    Write-Host ""
}

# Create install directory
if (-not (Test-Path $InstallPath)) {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    Write-Host "Created directory: $InstallPath" -ForegroundColor Green
}

# Copy the service script
$scriptSource = Join-Path $PSScriptRoot "CertIssuerService.ps1"
$scriptDest = Join-Path $InstallPath "CertIssuerService.ps1"

if (Test-Path $scriptSource) {
    Copy-Item -Path $scriptSource -Destination $scriptDest -Force
    Write-Host "Copied service script to: $scriptDest" -ForegroundColor Green
} else {
    Write-Host "ERROR: CertIssuerService.ps1 not found in $PSScriptRoot" -ForegroundColor Red
    exit 1
}

# Create configuration file
$configPath = Join-Path $InstallPath "config.json"
$config = @{
    Port = $Port
    ApiToken = $ApiToken
    CAConfig = $CAConfig
    CertTemplate = $CertTemplate
    CertValidityMinutes = 60
} | ConvertTo-Json

$config | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "Created config file: $configPath" -ForegroundColor Green

# Create a wrapper script for the service
$wrapperScript = @"
# Service wrapper - reads config and starts the service
`$configPath = Join-Path `$PSScriptRoot "config.json"
`$config = Get-Content `$configPath | ConvertFrom-Json

& "`$PSScriptRoot\CertIssuerService.ps1" ``
    -Port `$config.Port ``
    -ApiToken `$config.ApiToken ``
    -CAConfig `$config.CAConfig ``
    -CertTemplate `$config.CertTemplate ``
    -CertValidityMinutes `$config.CertValidityMinutes
"@

$wrapperPath = Join-Path $InstallPath "Start-Service.ps1"
$wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8
Write-Host "Created wrapper script: $wrapperPath" -ForegroundColor Green

# Create a batch file to run the service
$batchContent = @"
@echo off
cd /d "$InstallPath"
powershell.exe -ExecutionPolicy Bypass -File "Start-Service.ps1"
"@

$batchPath = Join-Path $InstallPath "RunService.bat"
$batchContent | Out-File -FilePath $batchPath -Encoding ASCII
Write-Host "Created batch file: $batchPath" -ForegroundColor Green

# Open firewall port
Write-Host ""
Write-Host "Opening firewall port $Port..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "Authentik Cert Issuer" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "To start the service manually:"
Write-Host "  cd $InstallPath"
Write-Host "  .\RunService.bat"
Write-Host ""
Write-Host "Or run in PowerShell:"
Write-Host "  & '$wrapperPath'"
Write-Host ""
Write-Host "Service URL: http://localhost:$Port"
Write-Host "Health check: http://localhost:$Port/health"
Write-Host ""
Write-Host "API Token (for Authentik): $ApiToken" -ForegroundColor Yellow
Write-Host ""
Write-Host "Test with:"
Write-Host @"
  Invoke-RestMethod -Uri "http://localhost:$Port/health"
"@
Write-Host ""
