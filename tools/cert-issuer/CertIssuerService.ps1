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

# For HTTPS, you'd need to bind a certificate:
# netsh http add sslcert ipport=0.0.0.0:8443 certhash=<thumbprint> appid={...}
# $listener.Prefixes.Add("https://+:$Port/")

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
    
    $tempDir = [System.IO.Path]::GetTempPath()
    $requestId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $infFile = Join-Path $tempDir "certreq_$requestId.inf"
    $reqFile = Join-Path $tempDir "certreq_$requestId.req"
    $cerFile = Join-Path $tempDir "certreq_$requestId.cer"
    $pfxFile = Join-Path $tempDir "certreq_$requestId.pfx"
    
    try {
        # Create INF file for certificate request
        $infContent = @"
[Version]
Signature="`$Windows NT$"

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
        
        # Generate certificate request
        $result = & certreq -new -q $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $result"
        }
        
        # Submit to CA
        $result = & certreq -submit -q -config $CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $result"
        }
        
        # Accept the certificate (links with private key)
        $result = & certreq -accept -q $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -accept failed: $result"
        }
        
        # Find the certificate we just installed
        Start-Sleep -Milliseconds 500
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My | 
                Where-Object { $_.Subject -eq "CN=$Username" } |
                Sort-Object NotBefore -Descending |
                Select-Object -First 1
        
        if (-not $cert) {
            throw "Certificate not found in store after accept"
        }
        
        # Export to PFX with a random password
        $pfxPassword = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $securePassword | Out-Null
        
        # Read PFX as base64
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Read certificate as PEM
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $certBase64 = [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $certPem = "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----"
        
        # Remove certificate from store (we don't need it here)
        $cert | Remove-Item -Force
        
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Certificate issued successfully" -ForegroundColor Green
        
        return @{
            success = $true
            certificate_pem = $certPem
            pfx_base64 = $pfxBase64
            pfx_password = $pfxPassword
            thumbprint = $cert.Thumbprint
            not_before = $cert.NotBefore.ToString("o")
            not_after = $cert.NotAfter.ToString("o")
            subject = $cert.Subject
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
        @($infFile, $reqFile, $cerFile, $pfxFile) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
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
