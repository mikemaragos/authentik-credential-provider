# AuthentikCertService.ps1
# Windows Service implementation for Authentik Certificate Issuer
# Installs as a proper Windows Service with auto-start capability

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Status", "Run")]
    [string]$Action = "Run",
    
    [string]$ServiceName = "AuthentikCertIssuer",
    [string]$DisplayName = "Authentik Certificate Issuer Service",
    [string]$Description = "Issues smart card certificates for Authentik passwordless authentication"
)

# Service configuration file path
$ConfigPath = "$env:ProgramData\Authentik\CertIssuer\config.json"
$LogPath = "$env:ProgramData\Authentik\CertIssuer\Logs"
$ServiceScript = "$env:ProgramData\Authentik\CertIssuer\CertIssuerWorker.ps1"

# Default configuration
$DefaultConfig = @{
    Port = 8443
    UseHttps = $false
    ApiToken = "CHANGE-THIS-TOKEN-$(Get-Random -Maximum 99999)"
    CAConfig = ""
    CertTemplate = "AuthentikSmartcard"
    AllowedIPs = @("127.0.0.1", "::1")
    MaxConcurrentRequests = 10
    CertRetentionHours = 24
    LogLevel = "Info"
    EventLogSource = "AuthentikCertIssuer"
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor Gray }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # File logging
    $logFile = Join-Path $LogPath "CertIssuer_$(Get-Date -Format 'yyyyMMdd').log"
    if (Test-Path (Split-Path $logFile -Parent)) {
        Add-Content -Path $logFile -Value $logMessage
    }
    
    # Event Log
    try {
        $eventType = switch ($Level) {
            "Info" { "Information" }
            "Warning" { "Warning" }
            "Error" { "Error" }
        }
        Write-EventLog -LogName "Application" -Source $DefaultConfig.EventLogSource -EventId 1000 -EntryType $eventType -Message $Message -ErrorAction SilentlyContinue
    } catch {}
}

function Initialize-ServiceEnvironment {
    Write-Log "Initializing service environment..."
    
    # Create directories
    $dirs = @(
        "$env:ProgramData\Authentik\CertIssuer",
        "$env:ProgramData\Authentik\CertIssuer\Logs",
        "$env:ProgramData\Authentik\CertIssuer\Temp"
    )
    
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir"
        }
    }
    
    # Create Event Log source
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($DefaultConfig.EventLogSource)) {
            New-EventLog -LogName "Application" -Source $DefaultConfig.EventLogSource -ErrorAction Stop
            Write-Log "Created Event Log source: $($DefaultConfig.EventLogSource)"
        }
    } catch {
        Write-Log "Could not create Event Log source: $_" -Level Warning
    }
    
    # Create default config if not exists
    if (-not (Test-Path $ConfigPath)) {
        $DefaultConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $ConfigPath -Encoding UTF8
        Write-Log "Created default configuration at: $ConfigPath"
        Write-Log "IMPORTANT: Edit $ConfigPath and set CAConfig and ApiToken!" -Level Warning
    }
}

function Get-ServiceConfig {
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            return $config
        } catch {
            Write-Log "Error reading config: $_" -Level Error
            return $DefaultConfig
        }
    }
    return $DefaultConfig
}

function Install-CertIssuerService {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Installing Authentik Certificate Issuer Service" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Initialize environment
    Initialize-ServiceEnvironment
    
    # Create the worker script that runs as the service
    $workerScript = @'
# CertIssuerWorker.ps1 - Service Worker Script
# This script is executed by NSSM as a Windows Service

param(
    [string]$ConfigPath = "$env:ProgramData\Authentik\CertIssuer\config.json"
)

# Load configuration
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

$Port = $config.Port
$ApiToken = $config.ApiToken
$CAConfig = $config.CAConfig
$CertTemplate = $config.CertTemplate
$UseHttps = $config.UseHttps
$LogPath = "$env:ProgramData\Authentik\CertIssuer\Logs"
$TempPath = "$env:ProgramData\Authentik\CertIssuer\Temp"

# Logging function
function Write-ServiceLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $logFile = Join-Path $LogPath "CertIssuer_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage
    
    try {
        $eventType = switch ($Level) { "Info" { "Information" } "Warning" { "Warning" } "Error" { "Error" } default { "Information" } }
        Write-EventLog -LogName "Application" -Source "AuthentikCertIssuer" -EventId 1000 -EntryType $eventType -Message $Message -ErrorAction SilentlyContinue
    } catch {}
}

# Certificate issuance function
function Issue-Certificate {
    param([string]$Username, [string]$UPN)
    
    Write-ServiceLog "Issuing certificate for $Username ($UPN)"
    
    if ([string]::IsNullOrEmpty($CAConfig)) {
        return @{ success = $false; error = "CA not configured" }
    }
    
    # Get UPN from AD if not provided
    if ([string]::IsNullOrEmpty($UPN)) {
        try {
            $adUser = Get-ADUser -Identity $Username -Properties userPrincipalName -ErrorAction Stop
            $UPN = $adUser.userPrincipalName
        } catch {
            return @{ success = $false; error = "User not found in AD: $_" }
        }
    }
    
    if ([string]::IsNullOrEmpty($UPN)) {
        return @{ success = $false; error = "User has no UPN configured in AD" }
    }
    
    $requestId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $infFile = Join-Path $TempPath "req_$requestId.inf"
    $reqFile = Join-Path $TempPath "req_$requestId.req"
    $cerFile = Join-Path $TempPath "req_$requestId.cer"
    $pfxFile = Join-Path $TempPath "req_$requestId.pfx"
    
    try {
        # Create INF
        @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$Username"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = $CertTemplate
"@ | Out-File -FilePath $infFile -Encoding ASCII
        
        # Generate request
        $null = & certreq -new -q $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -new failed" }
        
        # Submit to CA
        $null = & certreq -submit -q -config $CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -submit failed" }
        
        # Accept certificate
        $null = & certreq -accept -q $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -accept failed" }
        
        Start-Sleep -Milliseconds 500
        
        # Find certificate
        $tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFile)
        $thumbprint = $tempCert.Thumbprint
        
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $cert) { throw "Certificate not found after accept" }
        if (-not $cert.HasPrivateKey) { throw "Certificate has no private key" }
        
        # Export PFX
        $pfxPassword = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $securePassword | Out-Null
        
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Cleanup from local store
        $cert | Remove-Item -Force -ErrorAction SilentlyContinue
        
        Write-ServiceLog "Certificate issued successfully: $thumbprint"
        
        return @{
            success = $true
            thumbprint = $thumbprint
            pfx_base64 = $pfxBase64
            pfx_password = $pfxPassword
            subject = $cert.Subject
            upn = $UPN
            not_before = $cert.NotBefore.ToString("o")
            not_after = $cert.NotAfter.ToString("o")
        }
    }
    catch {
        Write-ServiceLog "Certificate issuance failed: $_" -Level Error
        return @{ success = $false; error = $_.ToString() }
    }
    finally {
        @($infFile, $reqFile, $cerFile, $pfxFile) | ForEach-Object {
            if ($_ -and (Test-Path $_)) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
        }
    }
}

# JSON response function
function Send-Response {
    param($Response, [hashtable]$Data, [int]$StatusCode = 200)
    $json = $Data | ConvertTo-Json -Depth 10
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json"
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

# Main service loop
Write-ServiceLog "Service starting on port $Port"

$prefix = if ($UseHttps) { "https://+:$Port/" } else { "http://+:$Port/" }
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-ServiceLog "Service started successfully"
    
    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $response.Headers.Add("Access-Control-Allow-Origin", "*")
            $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
            
            $path = $request.Url.LocalPath
            $method = $request.HttpMethod
            
            Write-ServiceLog "$method $path"
            
            if ($method -eq "OPTIONS") {
                $response.StatusCode = 200
                $response.Close()
                continue
            }
            
            if ($path -eq "/health") {
                Send-Response -Response $response -Data @{
                    status = "healthy"
                    service = "AuthentikCertIssuer"
                    version = "2.0"
                    uptime = [int]((Get-Date) - $script:startTime).TotalSeconds
                }
                continue
            }
            
            if ($path -eq "/api/v1/issue-certificate" -and $method -eq "POST") {
                $authHeader = $request.Headers["Authorization"]
                if ($authHeader -ne "Bearer $ApiToken") {
                    Write-ServiceLog "Unauthorized request" -Level Warning
                    Send-Response -Response $response -Data @{ success = $false; error = "Unauthorized" } -StatusCode 401
                    continue
                }
                
                $reader = New-Object System.IO.StreamReader($request.InputStream)
                $body = $reader.ReadToEnd()
                $reader.Close()
                
                try {
                    $requestData = $body | ConvertFrom-Json
                } catch {
                    Send-Response -Response $response -Data @{ success = $false; error = "Invalid JSON" } -StatusCode 400
                    continue
                }
                
                if (-not $requestData.username) {
                    Send-Response -Response $response -Data @{ success = $false; error = "Missing username" } -StatusCode 400
                    continue
                }
                
                $result = Issue-Certificate -Username $requestData.username -UPN $requestData.upn
                $statusCode = if ($result.success) { 200 } else { 500 }
                Send-Response -Response $response -Data $result -StatusCode $statusCode
                continue
            }
            
            Send-Response -Response $response -Data @{ error = "Not Found" } -StatusCode 404
        }
        catch {
            Write-ServiceLog "Request error: $_" -Level Error
        }
    }
}
catch {
    Write-ServiceLog "Service error: $_" -Level Error
}
finally {
    if ($listener) { $listener.Stop() }
    Write-ServiceLog "Service stopped"
}

$script:startTime = Get-Date
'@
    
    $workerScript | Out-File -FilePath $ServiceScript -Encoding UTF8 -Force
    Write-Log "Created worker script: $ServiceScript"
    
    # Check for NSSM
    $nssmPath = "$env:ProgramData\Authentik\CertIssuer\nssm.exe"
    if (-not (Test-Path $nssmPath)) {
        Write-Host ""
        Write-Host "NSSM (Non-Sucking Service Manager) is required to install as a service." -ForegroundColor Yellow
        Write-Host "Download from: https://nssm.cc/download" -ForegroundColor Yellow
        Write-Host "Place nssm.exe in: $env:ProgramData\Authentik\CertIssuer\" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Alternatively, you can run the service manually:" -ForegroundColor Cyan
        Write-Host "  powershell -ExecutionPolicy Bypass -File `"$ServiceScript`"" -ForegroundColor White
        return
    }
    
    # Install service using NSSM
    Write-Log "Installing service using NSSM..."
    
    & $nssmPath install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -File `"$ServiceScript`""
    & $nssmPath set $ServiceName DisplayName $DisplayName
    & $nssmPath set $ServiceName Description $Description
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START
    & $nssmPath set $ServiceName AppDirectory "$env:ProgramData\Authentik\CertIssuer"
    & $nssmPath set $ServiceName AppStdout "$LogPath\service_stdout.log"
    & $nssmPath set $ServiceName AppStderr "$LogPath\service_stderr.log"
    & $nssmPath set $ServiceName AppRotateFiles 1
    & $nssmPath set $ServiceName AppRotateBytes 10485760
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Service Installed Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration file: $ConfigPath" -ForegroundColor Yellow
    Write-Host "IMPORTANT: Edit the config file and set:" -ForegroundColor Red
    Write-Host "  - CAConfig (e.g., 'DC.domain.local\CA-Name')" -ForegroundColor White
    Write-Host "  - ApiToken (secure token for authentication)" -ForegroundColor White
    Write-Host ""
    Write-Host "To start the service:" -ForegroundColor Cyan
    Write-Host "  Start-Service $ServiceName" -ForegroundColor White
    Write-Host ""
}

function Uninstall-CertIssuerService {
    Write-Host "Uninstalling service..." -ForegroundColor Yellow
    
    # Stop service if running
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Write-Log "Service stopped"
    }
    
    # Remove using NSSM if available
    $nssmPath = "$env:ProgramData\Authentik\CertIssuer\nssm.exe"
    if (Test-Path $nssmPath) {
        & $nssmPath remove $ServiceName confirm
    } else {
        # Try sc.exe
        sc.exe delete $ServiceName
    }
    
    Write-Host "Service uninstalled" -ForegroundColor Green
    Write-Host "Configuration and logs preserved in: $env:ProgramData\Authentik\CertIssuer" -ForegroundColor Yellow
}

function Get-ServiceStatus {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Authentik Certificate Issuer Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($service) {
        Write-Host "Service Name: $ServiceName" -ForegroundColor White
        Write-Host "Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq "Running") { "Green" } else { "Yellow" })
        Write-Host "Start Type: $($service.StartType)" -ForegroundColor White
    } else {
        Write-Host "Service not installed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Configuration: $ConfigPath" -ForegroundColor White
    if (Test-Path $ConfigPath) {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Host "  Port: $($config.Port)" -ForegroundColor Gray
        Write-Host "  CA: $($config.CAConfig)" -ForegroundColor Gray
        Write-Host "  Template: $($config.CertTemplate)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Logs: $LogPath" -ForegroundColor White
    if (Test-Path $LogPath) {
        $latestLog = Get-ChildItem $LogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestLog) {
            Write-Host "  Latest: $($latestLog.Name)" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

# Main execution
switch ($Action) {
    "Install" { Install-CertIssuerService }
    "Uninstall" { Uninstall-CertIssuerService }
    "Start" { Start-Service -Name $ServiceName; Write-Host "Service started" -ForegroundColor Green }
    "Stop" { Stop-Service -Name $ServiceName; Write-Host "Service stopped" -ForegroundColor Yellow }
    "Status" { Get-ServiceStatus }
    "Run" {
        # Run interactively (for testing)
        Initialize-ServiceEnvironment
        $config = Get-ServiceConfig
        
        if ([string]::IsNullOrEmpty($config.CAConfig)) {
            Write-Host "ERROR: CAConfig not set in $ConfigPath" -ForegroundColor Red
            Write-Host "Please configure the CA before running the service." -ForegroundColor Yellow
            exit 1
        }
        
        Write-Host "Starting in interactive mode..." -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
        Write-Host ""
        
        & powershell -ExecutionPolicy Bypass -File $ServiceScript
    }
}
