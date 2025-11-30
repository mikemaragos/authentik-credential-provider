# Enroll-SmartCardCertificate.ps1
# Enrolls a certificate on a TPM Virtual Smart Card for PKINIT authentication
# Run on workstation as the user who will use the smart card

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$CAConfig,  # e.g., "WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA"
    
    [string]$TemplateName = "AuthentikSmartcard",
    [string]$VSCName = "Authentik VSC",
    [string]$TempPath = "C:\temp",
    [switch]$RecreateVSC
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Smart Card Certificate Enrollment Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Ensure temp directory exists
if (-not (Test-Path $TempPath)) {
    New-Item -ItemType Directory -Path $TempPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$infFile = Join-Path $TempPath "smartcard_$timestamp.inf"
$csrFile = Join-Path $TempPath "smartcard_$timestamp.csr"
$cerFile = Join-Path $TempPath "smartcard_$timestamp.cer"

# Check for existing certificates
Write-Host "`nChecking for existing certificates..." -ForegroundColor Yellow
$existingCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$Username*" }
if ($existingCerts) {
    Write-Host "Found $($existingCerts.Count) existing certificate(s) for $Username" -ForegroundColor Yellow
    $existingCerts | ForEach-Object {
        Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Gray
        Write-Host "  Subject: $($_.Subject)" -ForegroundColor Gray
        Write-Host "  NotBefore: $($_.NotBefore)" -ForegroundColor Gray
        Write-Host "  HasPrivateKey: $($_.HasPrivateKey)" -ForegroundColor Gray
        Write-Host ""
    }
    
    if ($existingCerts.Count -gt 0) {
        Write-Host "WARNING: Multiple certificates can cause authentication issues!" -ForegroundColor Red
        Write-Host "Consider using -RecreateVSC to start fresh" -ForegroundColor Yellow
    }
}

# Recreate VSC if requested
if ($RecreateVSC) {
    Write-Host "`nRecreating Virtual Smart Card..." -ForegroundColor Cyan
    Write-Host "NOTE: This must be run from physical/Proxmox console, NOT RDP!" -ForegroundColor Yellow
    
    # Check if running in RDP session
    $rdpSession = Get-Process -Name "mstsc" -ErrorAction SilentlyContinue
    if ($env:SESSIONNAME -and $env:SESSIONNAME -ne "Console") {
        Write-Error "This operation must be run from physical console or Proxmox, not RDP session"
        Write-Host "Current session: $env:SESSIONNAME" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Destroying existing VSC..." -ForegroundColor Yellow
    tpmvscmgr destroy /instance ROOT\SMARTCARDREADER\0000 2>$null
    
    Write-Host "Creating new VSC..." -ForegroundColor Yellow
    Write-Host "You will be prompted to enter and confirm a PIN" -ForegroundColor Cyan
    tpmvscmgr create /name $VSCName /pin PROMPT /adminkey random /generate
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create VSC"
        exit 1
    }
    
    Write-Host "VSC created successfully!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Check VSC status
Write-Host "`nChecking VSC status..." -ForegroundColor Yellow
$vscInfo = certutil -scinfo -silent 2>&1
if ($vscInfo -match "Microsoft Virtual Smart Card") {
    Write-Host "VSC detected" -ForegroundColor Green
} else {
    Write-Host "VSC not detected. Please create one first:" -ForegroundColor Red
    Write-Host "  tpmvscmgr create /name `"$VSCName`" /pin PROMPT /adminkey random /generate" -ForegroundColor Yellow
    exit 1
}

# Create certificate request INF file
Write-Host "`nCreating certificate request..." -ForegroundColor Cyan

$infContent = @"
[NewRequest]
Subject = "CN=$Username"
ProviderName = "Microsoft Base Smart Card Crypto Provider"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = FALSE
UseExistingKeySet = FALSE
RequestType = PKCS10

[RequestAttributes]
CertificateTemplate = $TemplateName
"@

$infContent | Out-File -FilePath $infFile -Encoding ASCII
Write-Host "INF file created: $infFile" -ForegroundColor Green

# Generate CSR
Write-Host "`nGenerating certificate signing request..." -ForegroundColor Cyan
Write-Host "You will be prompted for your smart card PIN" -ForegroundColor Yellow

$result = certreq -new $infFile $csrFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create CSR: $result"
    exit 1
}
Write-Host "CSR created: $csrFile" -ForegroundColor Green

# Submit to CA
Write-Host "`nSubmitting request to CA..." -ForegroundColor Cyan
Write-Host "CA Config: $CAConfig" -ForegroundColor Yellow

$result = certreq -submit -config $CAConfig $csrFile $cerFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to submit CSR: $result"
    exit 1
}
Write-Host "Certificate issued: $cerFile" -ForegroundColor Green

# Accept certificate
Write-Host "`nAccepting certificate..." -ForegroundColor Cyan

$result = certreq -accept $cerFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to accept certificate: $result"
    exit 1
}
Write-Host "Certificate accepted and installed!" -ForegroundColor Green

# Verify installation
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$newCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$Username*" } | Sort-Object NotBefore -Descending | Select-Object -First 1

if ($newCert) {
    Write-Host "`nNew Certificate Details:" -ForegroundColor Green
    Write-Host "  Thumbprint: $($newCert.Thumbprint)" -ForegroundColor White
    Write-Host "  Subject: $($newCert.Subject)" -ForegroundColor White
    Write-Host "  NotBefore: $($newCert.NotBefore)" -ForegroundColor White
    Write-Host "  NotAfter: $($newCert.NotAfter)" -ForegroundColor White
    Write-Host "  HasPrivateKey: $($newCert.HasPrivateKey)" -ForegroundColor White
    
    # Check for UPN in SAN
    $san = $newCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($san) {
        Write-Host "`nSubject Alternative Name:" -ForegroundColor Green
        Write-Host "  $($san.Format($true))" -ForegroundColor White
    } else {
        Write-Host "`nWARNING: No Subject Alternative Name extension found!" -ForegroundColor Red
        Write-Host "Smart card login may fail without UPN in SAN" -ForegroundColor Yellow
    }
    
    # Count total certificates
    $totalCerts = (Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$Username*" }).Count
    if ($totalCerts -gt 1) {
        Write-Host "`nWARNING: Multiple certificates ($totalCerts) found for $Username!" -ForegroundColor Red
        Write-Host "This may cause authentication issues. Consider recreating VSC." -ForegroundColor Yellow
    }
} else {
    Write-Error "Certificate not found after installation!"
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Enrollment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host @"

Next Steps:
1. Lock the workstation (Win+L)
2. Select smart card sign-in option
3. Enter your PIN: (the PIN you set for the VSC)
4. You should be logged in!

If login fails, check:
- DC System log for Event ID 39
- Workstation System log for Kerberos errors
- Ensure only one certificate exists for the user

"@ -ForegroundColor Cyan
