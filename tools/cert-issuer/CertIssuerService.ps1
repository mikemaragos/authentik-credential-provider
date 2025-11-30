# CertIssuerService.ps1
# REST API service that issues smartcard certificates from AD CS
# Updated to use AuthentikSmartcard template with UPN in SAN
# Run as Administrator on a machine with AD CS tools (typically the DC or CA server)

param(
    [int]$Port = 8443,
    [string]$ApiToken = "CHANGE-THIS-SECRET-TOKEN",
    [string]$CAConfig = "WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA",
    [string]$CertTemplate = "AuthentikSmartcard",  # Use our working template with UPN in SAN
    [switch]$AllowHttp,                             # Use HTTP instead of HTTPS
    [string]$CertFile = "",                         # PFX for HTTPS listener
    [string]$CertPassword = ""
)

# Requires running as Administrator
#Requires -RunAsAdministrator

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Authentik Certificate Issuer Service" -ForegroundColor Cyan
Write-Host "  (PKINIT Smart Card Version)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Port: $Port"
Write-Host "  CA: $CAConfig"
Write-Host "  Template: $CertTemplate"
Write-Host "  Protocol: $(if ($AllowHttp) { 'HTTP' } else { 'HTTPS' })"
Write-Host ""

# Verify template exists and has correct flags
Write-Host "Verifying certificate template..." -ForegroundColor Yellow
$templateCheck = certutil -dstemplate $CertTemplate msPKI-Certificate-Name-Flag 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Template '$CertTemplate' not found or not accessible" -ForegroundColor Red
    Write-Host "Please run Configure-SmartCardTemplate.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Check for UPN flag
if ($templateCheck -notmatch "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN") {
    Write-Host "WARNING: Template may not have UPN in SAN flag set" -ForegroundColor Yellow
    Write-Host "Run Configure-SmartCardTemplate.ps1 to fix this" -ForegroundColor Yellow
}
Write-Host "Template verified: $CertTemplate" -ForegroundColor Green
Write-Host ""

# Create HTTP listener
$prefix = if ($AllowHttp) { "http://+:$Port/" } else { "https://+:$Port/" }
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-Host "Service started on $prefix" -ForegroundColor Green
    Write-Host "Waiting for requests..." -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host "ERROR: Failed to start listener: $_" -ForegroundColor Red
    Write-Host "Make sure to run as Administrator and port $Port is not in use" -ForegroundColor Yellow
    if (-not $AllowHttp) {
        Write-Host "For HTTPS, you need a valid certificate bound to the port" -ForegroundColor Yellow
        Write-Host "Or use -AllowHttp for testing" -ForegroundColor Yellow
    }
    exit 1
}

# Function to get AD user info
function Get-ADUserInfo {
    param([string]$Username)
    
    try {
        $user = Get-ADUser -Identity $Username -Properties userPrincipalName, mail, distinguishedName -ErrorAction Stop
        return @{
            Found = $true
            UPN = $user.userPrincipalName
            Email = $user.mail
            DN = $user.distinguishedName
        }
    }
    catch {
        return @{
            Found = $false
            Error = $_.Exception.Message
        }
    }
}

# Function to issue certificate
function Issue-SmartcardCertificate {
    param(
        [string]$Username,
        [string]$UPN,
        [string]$Domain
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - Issuing cert for $Username ($UPN)" -ForegroundColor Yellow
    
    # Verify user exists in AD
    $adUser = Get-ADUserInfo -Username $Username
    if (-not $adUser.Found) {
        return @{
            success = $false
            error = "User '$Username' not found in Active Directory: $($adUser.Error)"
        }
    }
    
    # Use AD UPN if not provided
    if ([string]::IsNullOrEmpty($UPN)) {
        $UPN = $adUser.UPN
        if ([string]::IsNullOrEmpty($UPN)) {
            return @{
                success = $false
                error = "User '$Username' does not have a userPrincipalName configured in AD"
            }
        }
    }
    
    Write-Host "  Using UPN: $UPN" -ForegroundColor Gray
    
    $tempDir = "C:\temp\certissuer"
    if (-not (Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }
    
    $requestId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $infFile = Join-Path $tempDir "certreq_$requestId.inf"
    $reqFile = Join-Path $tempDir "certreq_$requestId.req"
    $cerFile = Join-Path $tempDir "certreq_$requestId.cer"
    $pfxFile = Join-Path $tempDir "certreq_$requestId.pfx"
    
    try {
        # Create INF file for certificate request
        # Use Microsoft RSA SChannel provider for exportable key
        # The template will add UPN to SAN automatically
        $infContent = @"
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
SMIME = FALSE
UseExistingKeySet = FALSE

[RequestAttributes]
CertificateTemplate = $CertTemplate
"@
        
        $infContent | Out-File -FilePath $infFile -Encoding ASCII
        Write-Host "  Created INF file" -ForegroundColor Gray
        
        # Generate certificate request
        $output = & certreq -new -q $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $output"
        }
        Write-Host "  Created request file" -ForegroundColor Gray
        
        # Submit to CA
        $output = & certreq -submit -q -config $CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $output"
        }
        Write-Host "  Certificate issued" -ForegroundColor Gray
        
        # Accept the certificate (links with private key)
        $output = & certreq -accept -q $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -accept failed: $output"
        }
        Write-Host "  Certificate accepted" -ForegroundColor Gray
        
        # Wait for cert store update
        Start-Sleep -Milliseconds 500
        
        # Find the certificate by parsing the .cer file for thumbprint
        $tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFile)
        $expectedThumbprint = $tempCert.Thumbprint
        Write-Host "  Looking for thumbprint: $expectedThumbprint" -ForegroundColor Gray
        
        # Find in CurrentUser\My store
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
                Where-Object { $_.Thumbprint -eq $expectedThumbprint }
        
        if (-not $cert) {
            # Try LocalMachine
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Thumbprint -eq $expectedThumbprint }
        }
        
        if (-not $cert) {
            # List what we have for debugging
            Write-Host "  Available certificates:" -ForegroundColor Yellow
            Get-ChildItem -Path Cert:\CurrentUser\My | ForEach-Object {
                Write-Host "    - $($_.Subject) [$($_.Thumbprint.Substring(0,8))...]" -ForegroundColor Gray
            }
            throw "Certificate not found in store after accept"
        }
        
        Write-Host "  Found certificate" -ForegroundColor Gray
        
        if (-not $cert.HasPrivateKey) {
            throw "Certificate found but has no private key"
        }
        
        # Verify UPN is in SAN
        $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        if ($san) {
            $sanText = $san.Format($true)
            if ($sanText -match "Principal Name") {
                Write-Host "  UPN in SAN: Verified" -ForegroundColor Green
            } else {
                Write-Host "  WARNING: UPN not found in SAN!" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  WARNING: No SAN extension found!" -ForegroundColor Yellow
        }
        
        # Export to PFX with a random password
        $pfxPassword = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $securePassword | Out-Null
        Write-Host "  Exported PFX" -ForegroundColor Gray
        
        # Read PFX as base64
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Read certificate as PEM
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $certBase64 = [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $certPem = "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----"
        
        # Store details
        $thumbprint = $cert.Thumbprint
        $notBefore = $cert.NotBefore.ToString("o")
        $notAfter = $cert.NotAfter.ToString("o")
        $subject = $cert.Subject
        
        # Remove certificate from this machine's store
        # (We're just issuing for the client, don't need it here)
        try {
            $cert | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host "  Removed certificate from local store" -ForegroundColor Gray
        }
        catch {
            Write-Host "  Warning: Could not remove certificate: $_" -ForegroundColor Yellow
        }
        
        Write-Host "$timestamp - Certificate issued successfully" -ForegroundColor Green
        
        return @{
            success = $true
            certificate_pem = $certPem
            pfx_base64 = $pfxBase64
            pfx_password = $pfxPassword
            thumbprint = $thumbprint
            not_before = $notBefore
            not_after = $notAfter
            subject = $subject
            upn = $UPN
        }
    }
    catch {
        Write-Host "$timestamp - ERROR: $_" -ForegroundColor Red
        return @{
            success = $false
            error = $_.ToString()
        }
    }
    finally {
        # Cleanup temp files
        @($infFile, $reqFile, $cerFile, $pfxFile) | ForEach-Object {
            if ($_ -and (Test-Path $_)) { 
                Remove-Item $_ -Force -ErrorAction SilentlyContinue 
            }
        }
    }
}

# Function to send JSON response
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

# Main request handling loop
Write-Host "Press Ctrl+C to stop the service" -ForegroundColor Gray
Write-Host ""

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        # Add CORS headers
        $response.Headers.Add("Access-Control-Allow-Origin", "*")
        $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        $path = $request.Url.LocalPath
        $method = $request.HttpMethod
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "$timestamp - $method $path" -ForegroundColor Gray
        
        # Handle OPTIONS (CORS preflight)
        if ($method -eq "OPTIONS") {
            $response.StatusCode = 200
            $response.Close()
            continue
        }
        
        # Health check endpoint
        if ($path -eq "/health" -and $method -eq "GET") {
            Send-JsonResponse -Response $response -Data @{
                status = "healthy"
                service = "Authentik Certificate Issuer"
                version = "2.0"
                ca = $CAConfig
                template = $CertTemplate
            }
            continue
        }
        
        # Issue certificate endpoint
        if ($path -eq "/api/v1/issue-certificate" -and $method -eq "POST") {
            # Check authorization
            $authHeader = $request.Headers["Authorization"]
            if ($authHeader -ne "Bearer $ApiToken") {
                Write-Host "$timestamp - Unauthorized request" -ForegroundColor Red
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Unauthorized"
                } -StatusCode 401
                continue
            }
            
            # Read request body
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            try {
                $requestData = $body | ConvertFrom-Json
            }
            catch {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Invalid JSON"
                } -StatusCode 400
                continue
            }
            
            # Validate required fields
            if (-not $requestData.username) {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Missing required field: username"
                } -StatusCode 400
                continue
            }
            
            # Issue the certificate
            $result = Issue-SmartcardCertificate `
                -Username $requestData.username `
                -UPN $requestData.upn `
                -Domain $requestData.domain
            
            $statusCode = if ($result.success) { 200 } else { 500 }
            Send-JsonResponse -Response $response -Data $result -StatusCode $statusCode
            continue
        }
        
        # 404 for unknown endpoints
        Send-JsonResponse -Response $response -Data @{
            error = "Not Found"
            path = $path
            endpoints = @(
                "GET /health - Health check"
                "POST /api/v1/issue-certificate - Issue certificate"
            )
        } -StatusCode 404
    }
    catch {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "$timestamp - Request error: $_" -ForegroundColor Red
    }
}

$listener.Stop()
