# Install-CertIssuerService.ps1
# Installs the Authentik Certificate Issuer as a Windows Service
# Run as Administrator on the Domain Controller

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Status")]
    [string]$Action = "Install"
)

$ServiceName = "AuthentikCertIssuer"
$InstallPath = "C:\ProgramData\Authentik\CertIssuer"
$ScriptPath = "$InstallPath\FullCertService.ps1"
$NssmPath = "$InstallPath\nssm.exe"

function Install-Service {
    Write-Host "Installing Authentik Certificate Issuer Service..." -ForegroundColor Cyan
    
    # Create directories
    @("$InstallPath", "$InstallPath\Logs", "$InstallPath\Temp") | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "Created: $_" -ForegroundColor Gray
        }
    }
    
    # Check for NSSM
    if (-not (Test-Path $NssmPath)) {
        Write-Host "ERROR: nssm.exe not found at $NssmPath" -ForegroundColor Red
        Write-Host "Download from https://nssm.cc/download and extract nssm.exe to $InstallPath" -ForegroundColor Yellow
        return
    }
    
    # Check for service script
    if (-not (Test-Path $ScriptPath)) {
        Write-Host "ERROR: FullCertService.ps1 not found at $ScriptPath" -ForegroundColor Red
        return
    }
    
    # Check for config
    $configPath = "$InstallPath\config.json"
    if (-not (Test-Path $configPath)) {
        Write-Host "ERROR: config.json not found at $configPath" -ForegroundColor Red
        Write-Host "Create config.json with Port, ApiToken, CAConfig, and CertTemplate" -ForegroundColor Yellow
        return
    }
    
    # Install service
    & $NssmPath install $ServiceName "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-ExecutionPolicy Bypass -File `"$ScriptPath`""
    
    # Configure service
    & $NssmPath set $ServiceName DisplayName "Authentik Certificate Issuer"
    & $NssmPath set $ServiceName Description "Issues smart card certificates for Authentik passwordless authentication"
    & $NssmPath set $ServiceName Start SERVICE_AUTO_START
    & $NssmPath set $ServiceName AppDirectory $InstallPath
    & $NssmPath set $ServiceName AppStdout "$InstallPath\Logs\service_stdout.log"
    & $NssmPath set $ServiceName AppStderr "$InstallPath\Logs\service_stderr.log"
    
    Write-Host "Service installed successfully!" -ForegroundColor Green
    Write-Host "Run: .\Install-CertIssuerService.ps1 -Action Start" -ForegroundColor Cyan
}

function Uninstall-Service {
    Write-Host "Uninstalling service..." -ForegroundColor Cyan
    & $NssmPath stop $ServiceName 2>$null
    & $NssmPath remove $ServiceName confirm
    Write-Host "Service uninstalled." -ForegroundColor Green
}

function Start-ServiceCmd {
    Write-Host "Starting service..." -ForegroundColor Cyan
    & $NssmPath start $ServiceName
}

function Stop-ServiceCmd {
    Write-Host "Stopping service..." -ForegroundColor Cyan
    & $NssmPath stop $ServiceName
}

function Get-ServiceStatus {
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "Service: $($svc.DisplayName)" -ForegroundColor Cyan
        Write-Host "Status:  $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq "Running") { "Green" } else { "Yellow" })
        
        # Test health endpoint
        try {
            $config = Get-Content "$InstallPath\config.json" | ConvertFrom-Json
            $health = Invoke-RestMethod "http://localhost:$($config.Port)/health" -ErrorAction Stop
            Write-Host "Health:  $($health.status)" -ForegroundColor Green
            Write-Host "CA:      $($health.ca)" -ForegroundColor Gray
        } catch {
            Write-Host "Health:  Unable to reach API" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Service not installed." -ForegroundColor Yellow
    }
}

# Main
switch ($Action) {
    "Install"   { Install-Service }
    "Uninstall" { Uninstall-Service }
    "Start"     { Start-ServiceCmd }
    "Stop"      { Stop-ServiceCmd }
    "Status"    { Get-ServiceStatus }
}
