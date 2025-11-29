# CertIssuerService.ps1
# REST API service that issues smartcard certificates from AD CS
# Run as Administrator on a machine with AD CS tools

param(
    [int]$Port = 8443,
    [string]$ApiToken = "CHANGE-THIS-SECRET-TOKEN",
    [string]$CAConfig = "WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA",
    [string]$CertTemplate = "SmartcardLogon",
    [int]$CertValidityMinutes = 60
)

# Requires running as Administrator
#Requires -RunAsAdministrator

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Authentik Certificate Issuer Service" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:"
Write-Host "  Port: $Port"
Write-Host "  CA: $CAConfig"
Write-Host "  Template: $CertTemplate"
Write-Host "  Validity: $CertValidityMinutes minutes"
Write-Host ""

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")

try {
    $listener.Start()
    Write-Host "Service started on port $Port" -ForegroundColor Green
    Write-Host "Waiting for requests..." -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host "ERROR: Failed to start listener: $_" -ForegroundColor Red
    Write-Host "Make sure to run as Administrator and port $Port is not in use" -ForegroundColor Yellow
    exit 1
}

# Function to issue certificate
function Issue-SmartcardCertificate {
    param(
        [string]$Username,
        [string]$UPN,
        [string]$Domain
    )
    
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Issuing cert for $Username ($UPN)" -ForegroundColor Yellow
    
    $tempDir = "C:\temp"
    if (-not (Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }
    
    $requestId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $infFile = Join-Path $tempDir "certreq_$requestId.inf"
    $reqFile = Join-Path $tempDir "certreq_$requestId.req"
    $cerFile = Join-Path $tempDir "certreq_$requestId.cer"
    $rspFile = Join-Path $tempDir "certreq_$requestId.rsp"
    $pfxFile = Join-Path $tempDir "certreq_$requestId.pfx"
    
    try {
        # Create INF file for certificate request
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

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=$UPN"

[RequestAttributes]
CertificateTemplate = $CertTemplate
"@
        
        $infContent | Out-File -FilePath $infFile -Encoding ASCII
        Write-Host "  Created INF file: $infFile" -ForegroundColor Gray
        
        # Generate certificate request
        $output = & certreq -new -q $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $output"
        }
        Write-Host "  Created request file: $reqFile" -ForegroundColor Gray
        
        # Submit to CA
        $output = & certreq -submit -q -config $CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $output"
        }
        Write-Host "  Certificate issued: $cerFile" -ForegroundColor Gray
        
        # Accept the certificate (links with private key)
        $output = & certreq -accept -q $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -accept failed: $output"
        }
        Write-Host "  Certificate accepted" -ForegroundColor Gray
        
        # Wait a moment for the cert store to update
        Start-Sleep -Seconds 1
        
        # Find the certificate we just installed - search by subject
        $searchName = "CN=$Username"
        Write-Host "  Searching for certificate with subject: $searchName" -ForegroundColor Gray
        
        # Try CurrentUser store first
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
                Where-Object { $_.Subject -eq $searchName } |
                Sort-Object NotBefore -Descending |
                Select-Object -First 1
        
        # If not found, try LocalMachine store
        if (-not $cert) {
            Write-Host "  Not found in CurrentUser, trying LocalMachine..." -ForegroundColor Gray
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Subject -eq $searchName } |
                    Sort-Object NotBefore -Descending |
                    Select-Object -First 1
        }
        
        # If still not found, try matching by thumbprint from the cer file
        if (-not $cert) {
            Write-Host "  Trying to find by parsing certificate file..." -ForegroundColor Gray
            $cerContent = Get-Content $cerFile -Raw
            $tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFile)
            $expectedThumbprint = $tempCert.Thumbprint
            Write-Host "  Looking for thumbprint: $expectedThumbprint" -ForegroundColor Gray
            
            $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Thumbprint -eq $expectedThumbprint }
            
            if (-not $cert) {
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Thumbprint -eq $expectedThumbprint }
            }
        }
        
        if (-not $cert) {
            # List all certs for debugging
            Write-Host "  Listing all CurrentUser\My certificates:" -ForegroundColor Yellow
            Get-ChildItem -Path Cert:\CurrentUser\My | ForEach-Object {
                Write-Host "    - $($_.Subject) [$($_.Thumbprint.Substring(0,8))...] HasKey:$($_.HasPrivateKey)" -ForegroundColor Gray
            }
            throw "Certificate not found in store after accept"
        }
        
        Write-Host "  Found certificate: $($cert.Thumbprint)" -ForegroundColor Gray
        
        if (-not $cert.HasPrivateKey) {
            throw "Certificate found but has no private key"
        }
        
        # Export to PFX with a random password
        $pfxPassword = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $securePassword | Out-Null
        Write-Host "  Exported PFX: $pfxFile" -ForegroundColor Gray
        
        # Read PFX as base64
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Read certificate as PEM
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $certBase64 = [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $certPem = "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----"
        
        # Store the thumbprint before removing
        $thumbprint = $cert.Thumbprint
        $notBefore = $cert.NotBefore.ToString("o")
        $notAfter = $cert.NotAfter.ToString("o")
        $subject = $cert.Subject
        
        # Remove certificate from store (we don't need it here, the client will import the PFX)
        try {
            $cert | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host "  Removed certificate from store" -ForegroundColor Gray
        }
        catch {
            Write-Host "  Warning: Could not remove certificate from store: $_" -ForegroundColor Yellow
        }
        
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Certificate issued successfully" -ForegroundColor Green
        
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
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $_" -ForegroundColor Red
        return @{
            success = $false
            error = $_.ToString()
        }
    }
    finally {
        # Cleanup temp files
        @($infFile, $reqFile, $cerFile, $rspFile, $pfxFile) | ForEach-Object {
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
        
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $method $path" -ForegroundColor Gray
        
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
                Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Unauthorized request" -ForegroundColor Red
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
            if (-not $requestData.username -or -not $requestData.upn) {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Missing required fields: username, upn"
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
        } -StatusCode 404
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Request error: $_" -ForegroundColor Red
    }
}

$listener.Stop()
