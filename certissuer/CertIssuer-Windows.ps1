<#
.SYNOPSIS
    CertIssuer Windows Service - Issues certificates via AD CS
    
.DESCRIPTION
    This script provides a REST API for issuing certificates from AD CS
    and updating altSecurityIdentities in Active Directory.
    
    Run on a Windows server with:
    - Access to AD CS (certreq.exe)
    - LDAP access to Active Directory
    - Network access from Authentik server
    
.EXAMPLE
    .\CertIssuer-Windows.ps1 -Port 8443 -CAServer "WIN-6DP39D0OLI8.test.local" -CAName "test-WIN-6DP39D0OLI8-CA"
#>

param(
    [int]$Port = 8443,
    [string]$CAServer = "WIN-6DP39D0OLI8.test.local",
    [string]$CAName = "test-WIN-6DP39D0OLI8-CA",
    [string]$Template = "AuthentikSmartcard",
    [string]$ApiToken = "your-secret-token",
    [string]$BindAddress = "+"
)

# Requires running as Administrator for HTTP listener
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Configuration
$Script:Config = @{
    Port = $Port
    CAServer = $CAServer
    CAName = $CAName
    Template = $Template
    ApiToken = $ApiToken
    CAConfig = "$CAServer\$CAName"
}

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "CertIssuer Windows Service" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "CA Server: $($Script:Config.CAServer)"
Write-Host "CA Name: $($Script:Config.CAName)"
Write-Host "Template: $($Script:Config.Template)"
Write-Host "Port: $($Script:Config.Port)"
Write-Host "=" * 60 -ForegroundColor Cyan

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$prefix = "https://$($BindAddress):$Port/"
$listener.Prefixes.Add($prefix)

# For HTTP (testing only):
# $prefix = "http://$($BindAddress):$Port/"

try {
    $listener.Start()
    Write-Host "Listening on $prefix" -ForegroundColor Green
}
catch {
    Write-Host "Failed to start listener: $_" -ForegroundColor Red
    Write-Host "Try running: netsh http add urlacl url=$prefix user=Everyone" -ForegroundColor Yellow
    exit 1
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "INFO" { "White" }
        "DEBUG" { "Gray" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

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
            # Subject Key Identifier
            $ski = $ext.Format($false)
            # Remove spaces and convert to uppercase
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
    $pfxFile = $reqFile -replace '\.req$', '.pfx'
    
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
        
        # Generate request using certreq
        Write-Log "Generating certificate request..."
        $result = & certreq -new $infFile $reqFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $result"
        }
        Write-Log "Request file created: $reqFile" -Level DEBUG
        
        # Submit to CA
        Write-Log "Submitting to CA: $($Script:Config.CAConfig)"
        $result = & certreq -submit -config $Script:Config.CAConfig $reqFile $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $result"
        }
        Write-Log "Certificate issued: $cerFile" -Level DEBUG
        
        # Accept the certificate to install it
        Write-Log "Accepting certificate..."
        $result = & certreq -accept $cerFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "certreq -accept warning: $result" -Level WARN
        }
        
        # Find the certificate in the store
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
        
        # Remove from local store (we don't need it here)
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
        # Cleanup temp files
        @($reqFile, $cerFile, $infFile, $pfxFile) | ForEach-Object {
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
        # Read request body
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
        
        Write-Log "Certificate issued successfully for $username" -Level INFO
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

# Main request loop
Write-Host ""
Write-Host "Ready to accept requests. Press Ctrl+C to stop." -ForegroundColor Green
Write-Host ""

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $method = $request.HttpMethod
        $path = $request.Url.AbsolutePath
        
        Write-Log "$method $path from $($request.RemoteEndPoint)"
        
        # Route requests
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
finally {
    $listener.Stop()
    Write-Host "Listener stopped." -ForegroundColor Yellow
}
