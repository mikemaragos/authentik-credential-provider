<#
.SYNOPSIS
    Install CertIssuer as a Windows Service
    
.DESCRIPTION
    This script:
    1. Stops and removes any existing CertIssuer service
    2. Downloads NSSM (Non-Sucking Service Manager) if needed
    3. Installs CertIssuer as a Windows service
    4. Configures service for automatic startup
    
.EXAMPLE
    .\Install-CertIssuerService.ps1 -ApiToken "your-secret-token"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiToken,
    
    [string]$InstallPath = "C:\CertIssuer",
    [string]$ServiceName = "CertIssuer",
    [int]$Port = 8443,
    [string]$CAServer = "WIN-6DP39D0OLI8.test.local",
    [string]$CAName = "test-WIN-6DP39D0OLI8-CA",
    [string]$Template = "AuthentikSmartcard"
)

$ErrorActionPreference = "Stop"

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "CertIssuer Service Installer" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Must run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# ============================================
# Step 1: Stop and Remove Old Service
# ============================================
Write-Host "`n[1/5] Checking for existing service..." -ForegroundColor Yellow

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "  Found existing service: $ServiceName (Status: $($existingService.Status))" -ForegroundColor White
    
    if ($existingService.Status -eq 'Running') {
        Write-Host "  Stopping service..." -ForegroundColor White
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    Write-Host "  Removing service..." -ForegroundColor White
    
    # Try NSSM first
    $nssm = "$InstallPath\nssm.exe"
    if (Test-Path $nssm) {
        & $nssm remove $ServiceName confirm 2>$null
    }
    
    # Also try sc.exe
    & sc.exe delete $ServiceName 2>$null
    Start-Sleep -Seconds 2
    
    Write-Host "  Old service removed" -ForegroundColor Green
} else {
    Write-Host "  No existing service found" -ForegroundColor Green
}

# Also check for any other CertIssuer variants
$variants = @("CertIssuerService", "Authentik-CertIssuer", "certissuer")
foreach ($variant in $variants) {
    $svc = Get-Service -Name $variant -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Found variant service: $variant - removing..." -ForegroundColor Yellow
        Stop-Service -Name $variant -Force -ErrorAction SilentlyContinue
        & sc.exe delete $variant 2>$null
    }
}

# ============================================
# Step 2: Create Installation Directory
# ============================================
Write-Host "`n[2/5] Setting up installation directory..." -ForegroundColor Yellow

if (Test-Path $InstallPath) {
    Write-Host "  Cleaning existing installation..." -ForegroundColor White
    # Keep logs if they exist
    if (Test-Path "$InstallPath\logs") {
        $backupLogs = "$InstallPath\logs_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Move-Item "$InstallPath\logs" $backupLogs -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallPath\logs" -Force | Out-Null

Write-Host "  Installation directory: $InstallPath" -ForegroundColor Green

# ============================================
# Step 3: Download NSSM
# ============================================
Write-Host "`n[3/5] Setting up NSSM (service manager)..." -ForegroundColor Yellow

$nssmPath = "$InstallPath\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Write-Host "  Downloading NSSM..." -ForegroundColor White
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$env:TEMP\nssm.zip"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
        
        # Extract
        $nssmExtract = "$env:TEMP\nssm_extract"
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        
        # Copy 64-bit version
        Copy-Item "$nssmExtract\nssm-2.24\win64\nssm.exe" $nssmPath
        
        # Cleanup
        Remove-Item $nssmZip -Force
        Remove-Item $nssmExtract -Recurse -Force
        
        Write-Host "  NSSM downloaded and installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: Could not download NSSM. Will try alternative method." -ForegroundColor Yellow
        Write-Host "  You can manually download from https://nssm.cc/download" -ForegroundColor Yellow
    }
} else {
    Write-Host "  NSSM already present" -ForegroundColor Green
}

# ============================================
# Step 4: Create Service Script
# ============================================
Write-Host "`n[4/5] Creating service script..." -ForegroundColor Yellow

$serviceScript = @'
<#
.SYNOPSIS
    CertIssuer Service - Issues certificates via AD CS
    
.DESCRIPTION
    REST API service for certificate issuance with AD mapping updates.
    Designed to run as a Windows service via NSSM.
#>

param(
    [int]$Port = {{PORT}},
    [string]$CAServer = "{{CA_SERVER}}",
    [string]$CAName = "{{CA_NAME}}",
    [string]$Template = "{{TEMPLATE}}",
    [string]$ApiToken = "{{API_TOKEN}}",
    [string]$LogPath = "{{INSTALL_PATH}}\logs"
)

$ErrorActionPreference = "Stop"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "INFO" { "White" }
        "DEBUG" { "Gray" }
        default { "White" }
    }
    Write-Host $logMessage -ForegroundColor $color
    
    # File output
    $logFile = Join-Path $LogPath "certissuer_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

# Configuration
$Script:Config = @{
    Port = $Port
    CAServer = $CAServer
    CAName = $CAName
    Template = $Template
    ApiToken = $ApiToken
    CAConfig = "$CAServer\$CAName"
    LogPath = $LogPath
}

Write-Log "=" * 60
Write-Log "CertIssuer Service Starting"
Write-Log "=" * 60
Write-Log "CA Server: $($Script:Config.CAServer)"
Write-Log "CA Name: $($Script:Config.CAName)"
Write-Log "Template: $($Script:Config.Template)"
Write-Log "Port: $($Script:Config.Port)"
Write-Log "Log Path: $($Script:Config.LogPath)"
Write-Log "=" * 60

function Test-ApiToken {
    param([System.Net.HttpListenerRequest]$Request)
    $authHeader = $Request.Headers["Authorization"]
    if (-not $authHeader) { return $false }
    if ($authHeader.StartsWith("Bearer ")) {
        $token = $authHeader.Substring(7)
        return $token -eq $Script:Config.ApiToken
    }
    return $false
}

function Send-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [hashtable]$Data,
        [int]$StatusCode = 200
    )
    $json = $Data | ConvertTo-Json -Depth 10
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json"
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

function Get-SubjectKeyIdentifier {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq "2.5.29.14") {
            $ski = $ext.Format($false)
            return ($ski -replace '\s', '').ToUpper()
        }
    }
    return $null
}

function New-CertificateRequest {
    param(
        [string]$Username,
        [string]$Domain,
        [string]$Template
    )
    
    $upn = "$Username@$Domain"
    $tempDir = [System.IO.Path]::GetTempPath()
    $reqFile = Join-Path $tempDir "$Username-$(Get-Random).req"
    $cerFile = $reqFile -replace '\.req$', '.cer'
    $infFile = $reqFile -replace '\.req$', '.inf'
    
    try {
        # Create INF file for certificate request
        $inf = @"
[Version]
Signature = "`$Windows NT$"

[NewRequest]
Subject = "CN=$Username"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.4.1.311.20.2.2
OID = 1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=$upn"

[RequestAttributes]
CertificateTemplate = $Template
"@
        
        $inf | Out-File -FilePath $infFile -Encoding ASCII
        Write-Log "Created INF file: $infFile" -Level DEBUG
        
        # Generate request
        Write-Log "Generating certificate request for $Username..."
        $result = & certreq -new $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $result"
        }
        
        # Submit to CA
        Write-Log "Submitting to CA: $($Script:Config.CAConfig)"
        $result = & certreq -submit -config $Script:Config.CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $result"
        }
        
        # Accept certificate
        Write-Log "Accepting certificate..."
        $result = & certreq -accept $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "certreq -accept warning: $result" -Level WARN
        }
        
        # Find certificate in store
        Start-Sleep -Milliseconds 500
        $cert = Get-ChildItem Cert:\CurrentUser\My | 
                Where-Object { $_.Subject -eq "CN=$Username" } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1
        
        if (-not $cert) {
            throw "Certificate not found in store after import"
        }
        
        Write-Log "Certificate thumbprint: $($cert.Thumbprint)"
        
        # Get SKI
        $ski = Get-SubjectKeyIdentifier -Cert $cert
        Write-Log "SKI: $ski"
        
        # Export certificate (DER)
        $certDer = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        
        # Export with private key (PFX)
        $tempPwd = [System.Guid]::NewGuid().ToString()
        $secPwd = ConvertTo-SecureString -String $tempPwd -Force -AsPlainText
        $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $secPwd)
        
        # Remove from local store
        $cert | Remove-Item -Force
        
        return @{
            Success = $true
            CertificateDer = [Convert]::ToBase64String($certDer)
            PfxBase64 = [Convert]::ToBase64String($pfxBytes)
            PfxPassword = $tempPwd
            SKI = $ski
            Thumbprint = $cert.Thumbprint
            Expires = $cert.NotAfter.ToString("o")
            UPN = $upn
        }
    }
    finally {
        @($reqFile, $cerFile, $infFile) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Set-ADUserCertMapping {
    param(
        [string]$Username,
        [string]$SKI
    )
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $mapping = "X509:<SKI>$SKI"
        Write-Log "Setting altSecurityIdentities for $Username : $mapping"
        
        Set-ADUser -Identity $Username -Replace @{altSecurityIdentities = $mapping}
        
        # Verify
        $user = Get-ADUser -Identity $Username -Properties altSecurityIdentities
        Write-Log "Verified mapping: $($user.altSecurityIdentities)"
        
        return $true
    }
    catch {
        Write-Log "Failed to set AD mapping: $_" -Level ERROR
        return $false
    }
}

function Handle-IssueCertificate {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    
    try {
        $reader = New-Object System.IO.StreamReader($Request.InputStream)
        $body = $reader.ReadToEnd()
        $reader.Close()
        
        $data = $body | ConvertFrom-Json
        
        $username = $data.username
        $domain = if ($data.domain) { $data.domain } else { "test.local" }
        $template = if ($data.template) { $data.template } else { $Script:Config.Template }
        
        if (-not $username) {
            Send-JsonResponse -Response $Response -Data @{
                success = $false
                error = "Username is required"
            } -StatusCode 400
            return
        }
        
        Write-Log "Certificate request for: $username@$domain (template: $template)"
        
        # Issue certificate
        $certResult = New-CertificateRequest -Username $username -Domain $domain -Template $template
        
        if (-not $certResult.Success) {
            Send-JsonResponse -Response $Response -Data @{
                success = $false
                error = "Failed to issue certificate"
            } -StatusCode 500
            return
        }
        
        # Update AD mapping
        $adResult = Set-ADUserCertMapping -Username $username -SKI $certResult.SKI
        
        Send-JsonResponse -Response $Response -Data @{
            success = $true
            certificate = $certResult.CertificateDer
            pfx = $certResult.PfxBase64
            pfx_password = $certResult.PfxPassword
            ski = $certResult.SKI
            thumbprint = $certResult.Thumbprint
            expires = $certResult.Expires
            upn = $certResult.UPN
            ad_mapping_updated = $adResult
        }
        
        Write-Log "Certificate issued successfully for $username"
    }
    catch {
        Write-Log "Error issuing certificate: $_" -Level ERROR
        Send-JsonResponse -Response $Response -Data @{
            success = $false
            error = $_.ToString()
        } -StatusCode 500
    }
}

function Handle-Health {
    param([System.Net.HttpListenerResponse]$Response)
    
    Send-JsonResponse -Response $Response -Data @{
        status = "healthy"
        timestamp = (Get-Date).ToString("o")
        ca_server = $Script:Config.CAServer
        ca_name = $Script:Config.CAName
        template = $Script:Config.Template
    }
}

function Handle-GetMapping {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    
    $username = $Request.QueryString["username"]
    if (-not $username) {
        Send-JsonResponse -Response $Response -Data @{
            success = $false
            error = "username parameter required"
        } -StatusCode 400
        return
    }
    
    try {
        Import-Module ActiveDirectory
        $user = Get-ADUser -Identity $username -Properties altSecurityIdentities
        
        Send-JsonResponse -Response $Response -Data @{
            success = $true
            username = $username
            altSecurityIdentities = @($user.altSecurityIdentities)
        }
    }
    catch {
        Send-JsonResponse -Response $Response -Data @{
            success = $false
            error = $_.ToString()
        } -StatusCode 500
    }
}

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$prefix = "http://+:$Port/"
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-Log "Listening on $prefix"
}
catch {
    Write-Log "Failed to start listener: $_" -Level ERROR
    Write-Log "Try running: netsh http add urlacl url=$prefix user=Everyone" -Level WARN
    exit 1
}

# Main request loop
Write-Log "Ready to accept requests"

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $method = $request.HttpMethod
        $path = $request.Url.AbsolutePath
        
        Write-Log "$method $path from $($request.RemoteEndPoint)"
        
        switch -Regex ("$method $path") {
            "GET /api/v1/health" {
                Handle-Health -Response $response
            }
            "POST /api/v1/certificate/issue" {
                if (-not (Test-ApiToken -Request $request)) {
                    Send-JsonResponse -Response $response -Data @{
                        success = $false
                        error = "Invalid API token"
                    } -StatusCode 401
                }
                else {
                    Handle-IssueCertificate -Request $request -Response $response
                }
            }
            "GET /api/v1/user/mapping" {
                if (-not (Test-ApiToken -Request $request)) {
                    Send-JsonResponse -Response $response -Data @{
                        success = $false
                        error = "Invalid API token"
                    } -StatusCode 401
                }
                else {
                    Handle-GetMapping -Request $request -Response $response
                }
            }
            default {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Not found"
                } -StatusCode 404
            }
        }
    }
}
catch {
    Write-Log "Service error: $_" -Level ERROR
}
finally {
    $listener.Stop()
    Write-Log "Service stopped"
}
'@

# Replace placeholders
$serviceScript = $serviceScript -replace '{{PORT}}', $Port
$serviceScript = $serviceScript -replace '{{CA_SERVER}}', $CAServer
$serviceScript = $serviceScript -replace '{{CA_NAME}}', $CAName
$serviceScript = $serviceScript -replace '{{TEMPLATE}}', $Template
$serviceScript = $serviceScript -replace '{{API_TOKEN}}', $ApiToken
$serviceScript = $serviceScript -replace '{{INSTALL_PATH}}', $InstallPath

# Save script
$scriptPath = "$InstallPath\CertIssuer-Service.ps1"
$serviceScript | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Host "  Service script created: $scriptPath" -ForegroundColor Green

# ============================================
# Step 5: Install Service
# ============================================
Write-Host "`n[5/5] Installing service..." -ForegroundColor Yellow

# Configure URL ACL
Write-Host "  Configuring URL ACL..." -ForegroundColor White
$urlAcl = "http://+:$Port/"
& netsh http delete urlacl url=$urlAcl 2>$null
& netsh http add urlacl url=$urlAcl user=Everyone | Out-Null

if (Test-Path $nssmPath) {
    # Install using NSSM
    Write-Host "  Installing service with NSSM..." -ForegroundColor White
    
    & $nssmPath install $ServiceName powershell.exe
    & $nssmPath set $ServiceName AppParameters "-ExecutionPolicy Bypass -File `"$scriptPath`""
    & $nssmPath set $ServiceName AppDirectory $InstallPath
    & $nssmPath set $ServiceName DisplayName "CertIssuer - Certificate Issuance Service"
    & $nssmPath set $ServiceName Description "Issues certificates via AD CS and updates AD mappings for PKINIT authentication"
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START
    & $nssmPath set $ServiceName AppStdout "$InstallPath\logs\service_stdout.log"
    & $nssmPath set $ServiceName AppStderr "$InstallPath\logs\service_stderr.log"
    & $nssmPath set $ServiceName AppRotateFiles 1
    & $nssmPath set $ServiceName AppRotateBytes 1048576
    
    Write-Host "  Service installed successfully" -ForegroundColor Green
    
    # Start service
    Write-Host "  Starting service..." -ForegroundColor White
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq 'Running') {
        Write-Host "  Service is running!" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Service status is $($svc.Status)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  NSSM not available. Creating scheduled task instead..." -ForegroundColor Yellow
    
    # Create scheduled task as alternative
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force
    
    # Start task now
    Start-ScheduledTask -TaskName $ServiceName
    
    Write-Host "  Scheduled task created and started" -ForegroundColor Green
}

# ============================================
# Summary
# ============================================
Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""
Write-Host "Service Name:    $ServiceName"
Write-Host "Install Path:    $InstallPath"
Write-Host "API Port:        $Port"
Write-Host "CA Server:       $CAServer"
Write-Host "CA Name:         $CAName"
Write-Host "Template:        $Template"
Write-Host "Log Path:        $InstallPath\logs"
Write-Host ""
Write-Host "API Endpoints:" -ForegroundColor Yellow
Write-Host "  Health:        http://localhost:$Port/api/v1/health"
Write-Host "  Issue Cert:    POST http://localhost:$Port/api/v1/certificate/issue"
Write-Host "  Get Mapping:   GET http://localhost:$Port/api/v1/user/mapping?username=xxx"
Write-Host ""
Write-Host "Test command:" -ForegroundColor Yellow
Write-Host "  Invoke-RestMethod http://localhost:$Port/api/v1/health"
Write-Host ""
Write-Host "Management commands:" -ForegroundColor Yellow
Write-Host "  Get-Service $ServiceName"
Write-Host "  Stop-Service $ServiceName"
Write-Host "  Start-Service $ServiceName"
Write-Host "  Restart-Service $ServiceName"
Write-Host ""
