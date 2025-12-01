# FullCertService.ps1
# Complete Certificate Issuer Service with actual AD CS integration
# Run as Administrator on DC
#
# Updated: 2025-12-01 - Added SID extension (1.3.6.1.4.1.311.25.2) for KB5014754 compliance

$ConfigPath = "C:\ProgramData\Authentik\CertIssuer\config.json"
$LogPath = "C:\ProgramData\Authentik\CertIssuer\Logs"
$TempPath = "C:\ProgramData\Authentik\CertIssuer\Temp"

# Load config
$config = Get-Content $ConfigPath | ConvertFrom-Json
$Port = $config.Port
$ApiToken = $config.ApiToken
$CAConfig = $config.CAConfig
$CertTemplate = $config.CertTemplate

# Ensure directories exist
@($LogPath, $TempPath) | ForEach-Object { 
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = "$LogPath\service_$(Get-Date -Format 'yyyyMMdd').log"
    "[$ts] [$Level] $Message" | Add-Content $logFile
    $color = switch ($Level) { "Error" { "Red" } "Warning" { "Yellow" } default { "Gray" } }
    Write-Host "[$ts] $Message" -ForegroundColor $color
}

function Convert-SidToHex {
    # Convert SID string to hex bytes for certificate extension
    param([string]$SidString)
    
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $sidBytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sidBytes, 0)
        
        # Return as hex string with spaces
        return ($sidBytes | ForEach-Object { $_.ToString("X2") }) -join " "
    } catch {
        Write-Log "Failed to convert SID to hex: $_" "Error"
        return $null
    }
}

function Issue-Certificate {
    param([string]$Username, [string]$UPN)
    
    Write-Log "Issuing certificate for $Username ($UPN)"
    
    if ([string]::IsNullOrEmpty($CAConfig)) {
        return @{ success = $false; error = "CA not configured" }
    }
    
    # Get UPN, Email, and SID from AD
    $Email = $null
    $UserSID = $null
    try {
        $adUser = Get-ADUser -Identity $Username -Properties userPrincipalName, mail, EmailAddress, ObjectSID -ErrorAction Stop
        
        # Get UPN from AD if not provided
        if ([string]::IsNullOrEmpty($UPN)) {
            $UPN = $adUser.userPrincipalName
            Write-Log "Retrieved UPN from AD: $UPN"
        }
        
        # Get Email from AD
        $Email = $adUser.mail
        if ([string]::IsNullOrEmpty($Email)) {
            $Email = $adUser.EmailAddress
        }
        
        # If still no email, use UPN as email (common pattern for AD)
        if ([string]::IsNullOrEmpty($Email)) {
            $Email = $UPN
            Write-Log "No email in AD, using UPN as email: $Email"
        } else {
            Write-Log "Retrieved Email from AD: $Email"
        }
        
        # Get SID from AD
        $UserSID = $adUser.SID.Value
        Write-Log "Retrieved SID from AD: $UserSID"
        
    } catch {
        Write-Log "User not found in AD: $_" "Error"
        return @{ success = $false; error = "User '$Username' not found in AD: $_" }
    }
    
    if ([string]::IsNullOrEmpty($UPN)) {
        return @{ success = $false; error = "User has no UPN configured in AD" }
    }
    
    if ([string]::IsNullOrEmpty($UserSID)) {
        return @{ success = $false; error = "Could not retrieve user SID from AD" }
    }
    
    $id = [guid]::NewGuid().ToString("N").Substring(0, 8)
    $infFile = "$TempPath\req_$id.inf"
    $reqFile = "$TempPath\req_$id.req"
    $cerFile = "$TempPath\req_$id.cer"
    $pfxFile = "$TempPath\req_$id.pfx"
    
    try {
        # Convert SID to hex for the extension
        $sidHex = Convert-SidToHex -SidString $UserSID
        if (-not $sidHex) {
            throw "Failed to convert SID to hex format"
        }
        Write-Log "SID hex bytes: $sidHex"
        
        # Build the SID extension value
        # Format: SEQUENCE { OID 1.3.6.1.4.1.311.25.2.1, OCTET STRING containing SID }
        # The certreq format for this is complex - we use hex encoding
        
        # Create certificate request INF with UPN, Email in SAN, and SID extension
        $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$Username"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft Strong Cryptographic Provider"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0xa0

[Extensions]
; Subject Alternative Name with UPN and Email
2.5.29.17 = "{text}"
_continue_ = "upn=$UPN&"
_continue_ = "email=$Email"

; SID extension for KB5014754 Strong Certificate Mapping
; OID 1.3.6.1.4.1.311.25.2 = szOID_NTDS_CA_SECURITY_EXT
1.3.6.1.4.1.311.25.2 = "{text}"
_continue_ = "tag=04"
_continue_ = "oid=1.3.6.1.4.1.311.25.2.1&"
_continue_ = "tag=04&hex=$($sidHex -replace ' ','')"

[RequestAttributes]
CertificateTemplate = $CertTemplate
"@
        $inf | Out-File $infFile -Encoding ASCII
        Write-Log "Created INF file with UPN=$UPN, Email=$Email, SID=$UserSID"
        
        # Generate certificate request
        $output = & certreq -new -q $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) { 
            Write-Log "certreq -new failed: $output" "Error"
            throw "certreq -new failed: $output" 
        }
        Write-Log "Generated certificate request"
        
        # Submit to CA
        $output = & certreq -submit -q -config $CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) { 
            Write-Log "certreq -submit failed: $output" "Error"
            throw "certreq -submit failed: $output" 
        }
        Write-Log "Submitted to CA and received certificate"
        
        # Accept certificate (links with private key)
        $output = & certreq -accept -q $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) { 
            Write-Log "certreq -accept failed: $output" "Error"
            throw "certreq -accept failed: $output" 
        }
        Write-Log "Accepted certificate"
        
        # Wait for store to update
        Start-Sleep -Milliseconds 500
        
        # Find the certificate by thumbprint
        $tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFile)
        $thumbprint = $tempCert.Thumbprint
        Write-Log "Looking for certificate with thumbprint: $thumbprint"
        
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
                Where-Object { $_.Thumbprint -eq $thumbprint }
        
        if (-not $cert) {
            # Try LocalMachine store
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Thumbprint -eq $thumbprint }
        }
        
        if (-not $cert) {
            throw "Certificate not found in store after accept"
        }
        
        if (-not $cert.HasPrivateKey) {
            throw "Certificate has no private key attached"
        }
        
        Write-Log "Found certificate with private key"
        
        # Verify UPN and Email in SAN
        $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        if ($san) {
            $sanText = $san.Format($true)
            Write-Log "SAN contents: $sanText"
            if ($sanText -match "Principal Name") {
                Write-Log "UPN verified in SAN"
            } else {
                Write-Log "WARNING: UPN not found in SAN!" "Warning"
            }
            if ($sanText -match "RFC822" -or $sanText -match "email") {
                Write-Log "Email verified in SAN"
            } else {
                Write-Log "WARNING: Email not found in SAN!" "Warning"
            }
        }
        
        # Verify SID extension
        $sidExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.25.2" }
        if ($sidExt) {
            Write-Log "SID extension (1.3.6.1.4.1.311.25.2) present in certificate"
        } else {
            Write-Log "WARNING: SID extension not found in certificate!" "Warning"
        }
        
        # Export to PFX with random password
        $pfxPassword = [guid]::NewGuid().ToString("N").Substring(0, 16)
        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $securePassword | Out-Null
        Write-Log "Exported PFX"
        
        # Read PFX as base64
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Store certificate details
        $subject = $cert.Subject
        $notBefore = $cert.NotBefore.ToString("o")
        $notAfter = $cert.NotAfter.ToString("o")
        
        # Remove certificate from local store (we're just issuing for the client)
        try {
            $cert | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Log "Removed certificate from local store"
        } catch {
            Write-Log "Could not remove cert from local store: $_" "Warning"
        }
        
        Write-Log "Certificate issued successfully: $thumbprint"
        
        return @{
            success = $true
            thumbprint = $thumbprint
            pfx_base64 = $pfxBase64
            pfx_password = $pfxPassword
            subject = $subject
            upn = $UPN
            email = $Email
            sid = $UserSID
            not_before = $notBefore
            not_after = $notAfter
        }
    }
    catch {
        Write-Log "Certificate issuance failed: $_" "Error"
        return @{ success = $false; error = $_.ToString() }
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

function Send-JsonResponse {
    param($Response, [hashtable]$Data, [int]$StatusCode = 200)
    
    $json = $Data | ConvertTo-Json -Depth 10
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json"
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

# Main
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Authentik Certificate Issuer Service" -ForegroundColor Cyan
Write-Host "  (KB5014754 Compliant - SID Extension)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Port:     $Port" -ForegroundColor White
Write-Host "CA:       $CAConfig" -ForegroundColor White
Write-Host "Template: $CertTemplate" -ForegroundColor White
Write-Host "Token:    $($ApiToken.Substring(0,8))..." -ForegroundColor White
Write-Host ""

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")

try {
    $listener.Start()
    Write-Host "Service STARTED - Listening on port $Port" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
    Write-Host ""
    Write-Log "Service started on port $Port"
    
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        # CORS headers
        $response.Headers.Add("Access-Control-Allow-Origin", "*")
        $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        $path = $request.Url.LocalPath
        $method = $request.HttpMethod
        
        Write-Host "$(Get-Date -Format 'HH:mm:ss') $method $path" -ForegroundColor Gray
        
        # Handle OPTIONS (CORS preflight)
        if ($method -eq "OPTIONS") {
            $response.StatusCode = 200
            $response.Close()
            continue
        }
        
        # Health endpoint
        if ($path -eq "/health") {
            Send-JsonResponse -Response $response -Data @{
                status = "healthy"
                port = $Port
                ca = $CAConfig
                template = $CertTemplate
                features = @("SAN", "SID_EXTENSION")
            }
            continue
        }
        
        # Issue certificate endpoint
        if ($path -eq "/api/v1/issue-certificate" -and $method -eq "POST") {
            # Check authorization
            $authHeader = $request.Headers["Authorization"]
            if ($authHeader -ne "Bearer $ApiToken") {
                Write-Log "Unauthorized request" "Warning"
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
            } catch {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Invalid JSON"
                } -StatusCode 400
                continue
            }
            
            if (-not $requestData.username) {
                Send-JsonResponse -Response $response -Data @{
                    success = $false
                    error = "Missing required field: username"
                } -StatusCode 400
                continue
            }
            
            # Issue the certificate
            $result = Issue-Certificate -Username $requestData.username -UPN $requestData.upn
            
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
}
catch {
    Write-Log "Service error: $_" "Error"
}
finally {
    if ($listener) { 
        $listener.Stop() 
        Write-Log "Service stopped"
    }
}
