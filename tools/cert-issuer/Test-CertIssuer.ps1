# Test-CertIssuer.ps1
# Test the certificate issuer service

param(
    [string]$ServiceUrl = "http://localhost:8443",
    [string]$ApiToken = "YOUR-API-TOKEN-HERE",
    [string]$Username = "testuser",
    [string]$UPN = "testuser@test.local",
    [string]$Domain = "TEST"
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Certificate Issuer Test" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Health check
Write-Host "Test 1: Health Check" -ForegroundColor Yellow
Write-Host "  GET $ServiceUrl/health"
try {
    $health = Invoke-RestMethod -Uri "$ServiceUrl/health" -Method GET
    Write-Host "  Status: $($health.status)" -ForegroundColor Green
    Write-Host "  CA: $($health.ca)"
    Write-Host "  Template: $($health.template)"
}
catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    Write-Host "  Make sure the service is running!" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Test 2: Issue certificate (without auth - should fail)
Write-Host "Test 2: Unauthorized Request (should fail)" -ForegroundColor Yellow
Write-Host "  POST $ServiceUrl/api/v1/issue-certificate (no auth)"
try {
    $result = Invoke-RestMethod -Uri "$ServiceUrl/api/v1/issue-certificate" -Method POST -ContentType "application/json" -Body "{}"
    Write-Host "  ERROR: Should have been rejected!" -ForegroundColor Red
}
catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  Correctly rejected with 401 Unauthorized" -ForegroundColor Green
    } else {
        Write-Host "  Unexpected error: $_" -ForegroundColor Red
    }
}

Write-Host ""

# Test 3: Issue certificate (with auth)
Write-Host "Test 3: Issue Certificate" -ForegroundColor Yellow
Write-Host "  POST $ServiceUrl/api/v1/issue-certificate"
Write-Host "  Username: $Username"
Write-Host "  UPN: $UPN"

$body = @{
    username = $Username
    upn = $UPN
    domain = $Domain
} | ConvertTo-Json

$headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type" = "application/json"
}

try {
    $startTime = Get-Date
    $result = Invoke-RestMethod -Uri "$ServiceUrl/api/v1/issue-certificate" -Method POST -Headers $headers -Body $body
    $elapsed = (Get-Date) - $startTime
    
    if ($result.success) {
        Write-Host "  SUCCESS!" -ForegroundColor Green
        Write-Host "  Thumbprint: $($result.thumbprint)"
        Write-Host "  Subject: $($result.subject)"
        Write-Host "  Valid: $($result.not_before) to $($result.not_after)"
        Write-Host "  PFX Password: $($result.pfx_password)"
        Write-Host "  Time: $($elapsed.TotalSeconds.ToString('F2')) seconds"
        Write-Host ""
        Write-Host "  Certificate PEM (first 100 chars):" -ForegroundColor Gray
        Write-Host "  $($result.certificate_pem.Substring(0, [Math]::Min(100, $result.certificate_pem.Length)))..."
        
        # Save the PFX for testing
        $pfxPath = "C:\temp\test_$Username.pfx"
        $pfxBytes = [System.Convert]::FromBase64String($result.pfx_base64)
        [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
        Write-Host ""
        Write-Host "  PFX saved to: $pfxPath" -ForegroundColor Yellow
        Write-Host "  PFX password: $($result.pfx_password)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  FAILED: $($result.error)" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
