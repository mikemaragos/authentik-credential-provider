# Test-AuthentikAPI.ps1
# PowerShell script to test Authentik API endpoints used by the credential provider

param(
    [string]$ServerUrl = "authentik.test.local",
    [int]$Port = 443,
    [string]$FlowSlug = "windows-otp-auth",
    [string]$Username = "",
    [string]$Password = "",
    [string]$OTP = "",
    [switch]$UseHttp,
    [switch]$IgnoreSslErrors
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Authentik API Test Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Read from registry if parameters not provided
if ([string]::IsNullOrEmpty($ServerUrl) -or $ServerUrl -eq "authentik.test.local") {
    try {
        $config = Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider" -ErrorAction SilentlyContinue
        if ($config) {
            $ServerUrl = $config.ServerUrl
            $Port = $config.ServerPort
            $FlowSlug = $config.FlowSlug
            $UseHttp = ($config.UseHttps -eq 0)
            $IgnoreSslErrors = ($config.IgnoreSslErrors -eq 1)
            Write-Host "📋 Configuration loaded from registry" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️  Could not read registry, using parameters" -ForegroundColor Yellow
    }
}

# Build base URL
$protocol = if ($UseHttp) { "http" } else { "https" }
$baseUrl = "${protocol}://${ServerUrl}:${Port}"
$flowUrl = "$baseUrl/api/v3/flows/executor/$FlowSlug/"

Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Server:   $ServerUrl"
Write-Host "  Port:     $Port"
Write-Host "  Protocol: $protocol"
Write-Host "  Flow:     $FlowSlug"
Write-Host "  Flow URL: $flowUrl"
Write-Host ""

# Ignore SSL errors if requested
if ($IgnoreSslErrors -and !$UseHttp) {
    Write-Host "⚠️  SSL certificate validation DISABLED" -ForegroundColor Yellow
    
    # Disable SSL validation for PowerShell
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
}

# Test 1: Basic Connectivity
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 1: Network Connectivity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "Testing TCP connection to ${ServerUrl}:${Port}..."
$tcpTest = Test-NetConnection -ComputerName $ServerUrl -Port $Port -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "✅ TCP connection successful" -ForegroundColor Green
} else {
    Write-Host "❌ TCP connection FAILED" -ForegroundColor Red
    Write-Host "   Cannot reach $ServerUrl on port $Port" -ForegroundColor Red
    Write-Host "   Check firewall, DNS, and network connectivity" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Test 2: HTTPS/HTTP Connection
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 2: HTTP(S) Connection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "Testing $protocol connection to base URL..."
try {
    $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-Host "✅ HTTP(S) connection successful" -ForegroundColor Green
    Write-Host "   Status: $($response.StatusCode) $($response.StatusDescription)" -ForegroundColor Green
} catch {
    Write-Host "❌ HTTP(S) connection FAILED" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Message -like "*SSL*" -or $_.Exception.Message -like "*certificate*") {
        Write-Host ""
        Write-Host "💡 SSL Certificate Issue Detected!" -ForegroundColor Yellow
        Write-Host "   Solutions:" -ForegroundColor Yellow
        Write-Host "   1. Set IgnoreSslErrors=1 in registry (testing only)" -ForegroundColor Yellow
        Write-Host "   2. Import certificate to Trusted Root" -ForegroundColor Yellow
        Write-Host "   3. Use valid SSL certificate on Authentik" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 3: Flow Endpoint (GET)
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 3: Flow Endpoint (GET)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "Testing flow endpoint: $flowUrl"
try {
    $response = Invoke-WebRequest -Uri $flowUrl -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-Host "✅ Flow endpoint accessible" -ForegroundColor Green
    Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "   Content-Type: $($response.Headers['Content-Type'])" -ForegroundColor Green
    Write-Host "   Content Length: $($response.Content.Length) bytes" -ForegroundColor Green
    
    # Try to parse JSON
    try {
        $json = $response.Content | ConvertFrom-Json
        Write-Host "   Flow Type: $($json.type)" -ForegroundColor Green
        Write-Host ""
        Write-Host "📄 Flow Response:" -ForegroundColor Cyan
        Write-Host ($response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 5)
    } catch {
        Write-Host "   Response is not JSON" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Flow endpoint FAILED" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "💡 Possible Issues:" -ForegroundColor Yellow
    Write-Host "   - Flow slug '$FlowSlug' does not exist in Authentik" -ForegroundColor Yellow
    Write-Host "   - Flow is not published/active" -ForegroundColor Yellow
    Write-Host "   - Authentik API is not accessible" -ForegroundColor Yellow
}
Write-Host ""

# Test 4: Authentication with Username/Password
if (![string]::IsNullOrEmpty($Username)) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Test 4: Authentication (Username/Password)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "Testing authentication for user: $Username"
    
    # Build JSON payload
    $body = @{
        uid_field = $Username
    }
    
    if (![string]::IsNullOrEmpty($Password)) {
        $body.password = $Password
    }
    
    $jsonBody = $body | ConvertTo-Json
    
    Write-Host "Sending POST to: $flowUrl"
    Write-Host "Payload: $jsonBody" -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri $flowUrl `
                                       -Method POST `
                                       -Body $jsonBody `
                                       -ContentType "application/json" `
                                       -UseBasicParsing `
                                       -TimeoutSec 10 `
                                       -ErrorAction Stop
        
        Write-Host "✅ Authentication request successful" -ForegroundColor Green
        Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Green
        
        # Parse response
        $authResponse = $response.Content | ConvertFrom-Json
        
        Write-Host ""
        Write-Host "📄 Authentication Response:" -ForegroundColor Cyan
        Write-Host ($authResponse | ConvertTo-Json -Depth 5)
        Write-Host ""
        
        # Check response type
        if ($authResponse.type -eq "redirect") {
            Write-Host "✅ Authentication SUCCESSFUL (redirect)" -ForegroundColor Green
            Write-Host "   User authenticated successfully!" -ForegroundColor Green
        } elseif ($authResponse.component -like "*authenticator*" -or $authResponse.type -eq "native") {
            Write-Host "⏭️  OTP Challenge Required" -ForegroundColor Yellow
            Write-Host "   Authentik is requesting OTP verification" -ForegroundColor Yellow
            
            # Check for flow_info
            if ($authResponse.flow_info) {
                Write-Host "   Flow Info:" -ForegroundColor Cyan
                Write-Host "     Title: $($authResponse.flow_info.title)" -ForegroundColor Cyan
                Write-Host "     Background: $($authResponse.flow_info.background)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "⚠️  Unexpected Response Type: $($authResponse.type)" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "❌ Authentication request FAILED" -ForegroundColor Red
        Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            Write-Host "   Response Body: $errorBody" -ForegroundColor Red
        }
    }
    Write-Host ""
}

# Test 5: OTP Validation
if (![string]::IsNullOrEmpty($Username) -and ![string]::IsNullOrEmpty($OTP)) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Test 5: OTP Validation" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "Testing OTP validation for user: $Username"
    
    # Build JSON payload
    $body = @{
        code = $OTP
    }
    
    $jsonBody = $body | ConvertTo-Json
    
    Write-Host "Sending POST to: $flowUrl"
    Write-Host "Payload: $jsonBody" -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri $flowUrl `
                                       -Method POST `
                                       -Body $jsonBody `
                                       -ContentType "application/json" `
                                       -UseBasicParsing `
                                       -TimeoutSec 10 `
                                       -ErrorAction Stop
        
        Write-Host "✅ OTP validation request successful" -ForegroundColor Green
        Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Green
        
        # Parse response
        $otpResponse = $response.Content | ConvertFrom-Json
        
        Write-Host ""
        Write-Host "📄 OTP Validation Response:" -ForegroundColor Cyan
        Write-Host ($otpResponse | ConvertTo-Json -Depth 5)
        Write-Host ""
        
        # Check response type
        if ($otpResponse.type -eq "redirect") {
            Write-Host "✅ OTP Validation SUCCESSFUL" -ForegroundColor Green
            Write-Host "   User fully authenticated!" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Unexpected Response Type: $($otpResponse.type)" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "❌ OTP validation FAILED" -ForegroundColor Red
        Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            Write-Host "   Response Body: $errorBody" -ForegroundColor Red
        }
    }
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration Used:" -ForegroundColor Cyan
Write-Host "  ServerUrl:        $ServerUrl"
Write-Host "  ServerPort:       $Port"
Write-Host "  FlowSlug:         $FlowSlug"
Write-Host "  UseHttps:         $(!$UseHttp)"
Write-Host "  IgnoreSslErrors:  $IgnoreSslErrors"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
if ([string]::IsNullOrEmpty($Username)) {
    Write-Host "  1. Run with username/password to test authentication:" -ForegroundColor Yellow
    Write-Host "     .\Test-AuthentikAPI.ps1 -Username 'testuser' -Password 'testpass'" -ForegroundColor Gray
}
if (![string]::IsNullOrEmpty($Username) -and [string]::IsNullOrEmpty($OTP)) {
    Write-Host "  2. If OTP is required, run with OTP code:" -ForegroundColor Yellow
    Write-Host "     .\Test-AuthentikAPI.ps1 -Username 'testuser' -OTP '123456'" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  3. Check DebugView for credential provider logs" -ForegroundColor Yellow
Write-Host "  4. Lock screen (Win+L) and test the tile" -ForegroundColor Yellow
Write-Host ""
