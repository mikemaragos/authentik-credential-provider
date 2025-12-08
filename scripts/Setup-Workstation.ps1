# Setup-Workstation.ps1
# Phase 1: Smart Card Workstation Setup
# Run as Administrator on domain-joined workstation

param(
    [string]$Username = "shop",
    [string]$CertTemplate = "AuthentikSmartcard",
    [string]$VSCPin = "12345678"
)

Write-Host "=== Phase 1: Smart Card Workstation Setup ===" -ForegroundColor Cyan
Write-Host "Username: $Username" -ForegroundColor White
Write-Host "Template: $CertTemplate" -ForegroundColor White
Write-Host ""

# Step 1: Cleanup previous certs
Write-Host "[1/6] Cleaning up previous certificates..." -ForegroundColor Yellow
$oldCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*$Username*"}
if ($oldCerts) {
    $oldCerts | Remove-Item -Force
    Write-Host "  Removed $($oldCerts.Count) certificate(s)" -ForegroundColor Green
} else {
    Write-Host "  No existing certificates found" -ForegroundColor Green
}

# Step 2: Destroy any existing VSC
Write-Host "[2/6] Destroying existing VSC..." -ForegroundColor Yellow
$destroyResult = tpmvscmgr.exe destroy /instance ROOT\SMARTCARDREADER\0000 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  VSC destroyed" -ForegroundColor Green
} else {
    Write-Host "  No existing VSC to destroy" -ForegroundColor Green
}

# Step 3: Create VSC
Write-Host "[3/6] Creating Virtual Smart Card..." -ForegroundColor Yellow
Write-Host "  Enter PIN when prompted: $VSCPin" -ForegroundColor Magenta

# Note: /pin PROMPT requires user interaction
$createResult = tpmvscmgr.exe create /name "AuthentikVSC" /pin PROMPT /adminkey random /generate
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to create VSC" -ForegroundColor Red
    exit 1
}
Write-Host "  VSC created successfully" -ForegroundColor Green

# Wait for smart card service
Start-Sleep -Seconds 2

# Step 4: Enroll certificate
Write-Host "[4/6] Enrolling certificate..." -ForegroundColor Yellow
Write-Host "  Select Virtual Smart Card when prompted" -ForegroundColor Magenta
Write-Host "  Subject: CN=$Username" -ForegroundColor Magenta
Write-Host "  SAN UPN: $Username@$($env:USERDNSDOMAIN.ToLower())" -ForegroundColor Magenta

certreq -enroll -user $CertTemplate
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Certificate enrollment failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Certificate enrolled successfully" -ForegroundColor Green

# Step 5: Verify and get SKI
Write-Host "[5/6] Verifying certificate and extracting SKI..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=$Username"} | Select-Object -First 1
if (!$cert) {
    Write-Host "  ERROR: Certificate not found in store" -ForegroundColor Red
    exit 1
}

$ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
if (!$ski) {
    Write-Host "  ERROR: SKI extension not found" -ForegroundColor Red
    exit 1
}

$skiHash = $ski.Format(0)
Write-Host "  Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
Write-Host "  SKI Hash: $skiHash" -ForegroundColor Green

# Step 6: Enable Smart Card Credential Provider
Write-Host "[6/6] Enabling Smart Card Credential Provider..." -ForegroundColor Yellow
$cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
if (!(Test-Path $cpPath)) { 
    New-Item -Path $cpPath -Force | Out-Null
}
Set-ItemProperty -Path $cpPath -Name "Disabled" -Value 0 -Type DWord
Write-Host "  Smart Card CP enabled" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=== SETUP COMPLETE ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "NEXT STEP - Run this on Domain Controller:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Set-ADUser $Username -Clear altSecurityIdentities" -ForegroundColor White
Write-Host "Set-ADUser $Username -Add @{altSecurityIdentities=`"X509:<SKI>$skiHash`"}" -ForegroundColor White
Write-Host ""
Write-Host "THEN TEST:" -ForegroundColor Yellow
Write-Host "runas /smartcard /user:$Username@$($env:USERDNSDOMAIN.ToLower()) cmd.exe" -ForegroundColor White
Write-Host "PIN: $VSCPin" -ForegroundColor White
Write-Host ""
Write-Host "Lock screen (Win+L) and select smart card tile" -ForegroundColor White
