# Quick-Test-Auth.ps1
# Quick test script that mimics the exact API calls the DLL makes

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Quick Authentik Authentication Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Read configuration from registry
try {
    $config = Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider" -ErrorAction Stop
    Write-Host "✅ Configuration loaded from registry:" -ForegroundColor Green
    Write-Host "   ServerUrl:        $($config.ServerUrl)"
    Write-Host "   ServerPort:       $($config.ServerPort)"
    Write-Host "   FlowSlug:         $($config.FlowSlug)"
    Write-Host "   UseHttps:         $($config.UseHttps)"
    Write-Host "   IgnoreSslErrors:  $($config.IgnoreSslErrors)"
    Write-Host ""
} catch {
    Write-Host "❌ ERROR: Could not read registry configuration!" -ForegroundColor Red
    Write-Host "   Path: HKLM:\SOFTWARE\AuthentikCredentialProvider" -ForegroundColor Red
    exit 1
}

# Build URL
$protocol = if ($config.UseHttps -eq 1) { "https" } else { "http" }
$url = "${protocol}://$($config.ServerUrl):$($config.ServerPort)/api/v3/flows/executor/$($config.FlowSlug)/"

Write-Host "API Endpoint: $url" -ForegroundColor Cyan
Write-Host ""

# Handle SSL if needed
if ($config.IgnoreSslErrors -eq 1 -and $config.UseHttps -eq 1) {
    Write-Host "⚠️  Disabling SSL certificate validation..." -ForegroundColor Yellow
    
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
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Write-Host ""
}

# Get credentials
$username = Read-Host "Enter username"
$password = Read-Host "Enter password" -AsSecureString
$passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Test 1: Initial authentication
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 1: Initial Authentication" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$body = @{
    uid_field = $username
    password = $passwordPlain
} | ConvertTo-Json

Write-Host "Sending POST request..." -ForegroundColor Gray
Write-Host "URL: $url" -ForegroundColor Gray

try {
    $response = Invoke-RestMethod -Uri $url `
                                   -Method POST `
                                   -Body $body `
                                   -ContentType "application/json" `
                                   -TimeoutSec 30
    
    Write-Host "✅ Response received!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Response Type: $($response.type)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Full Response:" -ForegroundColor Cyan
    Write-Host ($response | ConvertTo-Json -Depth 10)
    Write-Host ""
    
    # Check if OTP is required
    if ($response.component -like "*authenticator*" -or $response.type -eq "native") {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Step 2: OTP Required" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Authentik is requesting OTP verification" -ForegroundColor Yellow
        Write-Host ""
        
        $otp = Read-Host "Enter OTP code"
        
        $otpBody = @{
            code = $otp
        } | ConvertTo-Json
        
        Write-Host "Sending OTP validation..." -ForegroundColor Gray
        
        try {
            $otpResponse = Invoke-RestMethod -Uri $url `
                                              -Method POST `
                                              -Body $otpBody `
                                              -ContentType "application/json" `
                                              -TimeoutSec 30
            
            Write-Host "✅ OTP Response received!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Response Type: $($otpResponse.type)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Full Response:" -ForegroundColor Cyan
            Write-Host ($otpResponse | ConvertTo-Json -Depth 10)
            Write-Host ""
            
            if ($otpResponse.type -eq "redirect") {
                Write-Host "========================================" -ForegroundColor Green
                Write-Host "✅ AUTHENTICATION SUCCESSFUL!" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Authentication not complete. Type: $($otpResponse.type)" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "❌ OTP Validation FAILED!" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.ErrorDetails) {
                Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
            }
        }
        
    } elseif ($response.type -eq "redirect") {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "✅ AUTHENTICATION SUCCESSFUL!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "(No OTP required)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Unexpected response type: $($response.type)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "❌ Authentication FAILED!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails) {
        Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    
    # Additional diagnostics
    Write-Host ""
    Write-Host "Diagnostics:" -ForegroundColor Yellow
    Write-Host "  - Check if Authentik server is running" -ForegroundColor Yellow
    Write-Host "  - Verify flow slug '$($config.FlowSlug)' exists in Authentik" -ForegroundColor Yellow
    Write-Host "  - Check Authentik logs for errors" -ForegroundColor Yellow
    Write-Host "  - Verify username/password are correct" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test complete!" -ForegroundColor Cyan
