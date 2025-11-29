# Test-PKINITAuth.ps1
# Diagnostic script to test PKINIT certificate authentication
# Run on the WORKSTATION as Administrator

param(
    [string]$Username = "shop",
    [string]$Domain = "TEST",
    [string]$CertThumbprint = ""
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " PKINIT Authentication Diagnostic Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Find certificates
Write-Host "[1] Searching for certificates..." -ForegroundColor Yellow

$certs = @()
$certs += Get-ChildItem Cert:\CurrentUser\My | Where-Object { 
    $_.Subject -like "*$Username*" -and 
    $_.HasPrivateKey -eq $true 
}
$certs += Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
    $_.Subject -like "*$Username*" -and 
    $_.HasPrivateKey -eq $true 
}

if ($certs.Count -eq 0) {
    Write-Host "    ERROR: No certificates found for user '$Username'" -ForegroundColor Red
    exit 1
}

Write-Host "    Found $($certs.Count) certificate(s):" -ForegroundColor Green
foreach ($cert in $certs) {
    Write-Host "    - Subject: $($cert.Subject)" -ForegroundColor Gray
    Write-Host "      Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "      Store: $($cert.PSParentPath)" -ForegroundColor Gray
    Write-Host "      HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Gray
    Write-Host "      NotAfter: $($cert.NotAfter)" -ForegroundColor Gray
    
    # Check EKUs
    $ekus = $cert.EnhancedKeyUsageList
    if ($ekus) {
        Write-Host "      EKUs:" -ForegroundColor Gray
        foreach ($eku in $ekus) {
            $color = if ($eku.ObjectId -eq "1.3.6.1.4.1.311.20.2.2") { "Green" } else { "Gray" }
            Write-Host "        - $($eku.FriendlyName) ($($eku.ObjectId))" -ForegroundColor $color
        }
    }
    Write-Host ""
}

# Select certificate
if ($CertThumbprint) {
    $selectedCert = $certs | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
} else {
    $selectedCert = $certs | Where-Object { 
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.4.1.311.20.2.2" 
    } | Select-Object -First 1
}

if (-not $selectedCert) {
    $selectedCert = $certs[0]
}

Write-Host "[2] Using certificate: $($selectedCert.Thumbprint)" -ForegroundColor Yellow
Write-Host ""

# Step 2: Check certificate chain
Write-Host "[3] Validating certificate chain..." -ForegroundColor Yellow

$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority

$chainValid = $chain.Build($selectedCert)
if ($chainValid) {
    Write-Host "    Certificate chain is valid" -ForegroundColor Green
} else {
    Write-Host "    Certificate chain validation failed:" -ForegroundColor Red
    foreach ($status in $chain.ChainStatus) {
        Write-Host "    - $($status.StatusInformation)" -ForegroundColor Red
    }
}

Write-Host "    Chain elements:" -ForegroundColor Gray
foreach ($element in $chain.ChainElements) {
    Write-Host "    - $($element.Certificate.Subject)" -ForegroundColor Gray
}
Write-Host ""

# Step 3: Check if certificate issuer is trusted by DC
Write-Host "[4] Checking CA trust..." -ForegroundColor Yellow

$issuer = $selectedCert.Issuer
Write-Host "    Certificate Issuer: $issuer" -ForegroundColor Gray

# Check if issuer is in Trusted Root or Enterprise trust
$trustedRoots = Get-ChildItem Cert:\LocalMachine\Root
$ntAuthStore = Get-ChildItem Cert:\LocalMachine\NTAuth -ErrorAction SilentlyContinue

$issuerCert = $trustedRoots | Where-Object { $_.Subject -eq $issuer } | Select-Object -First 1
if ($issuerCert) {
    Write-Host "    CA is in Trusted Root Certification Authorities" -ForegroundColor Green
} else {
    Write-Host "    WARNING: CA not found in Trusted Root store" -ForegroundColor Yellow
}

if ($ntAuthStore) {
    $ntAuthCert = $ntAuthStore | Where-Object { $_.Subject -eq $issuer } | Select-Object -First 1
    if ($ntAuthCert) {
        Write-Host "    CA is in NTAuth store (Enterprise CA)" -ForegroundColor Green
    } else {
        Write-Host "    WARNING: CA not found in NTAuth store - PKINIT may fail!" -ForegroundColor Red
        Write-Host "    The CA must be in NTAuth for smart card logon to work." -ForegroundColor Red
    }
} else {
    Write-Host "    NTAuth store not accessible" -ForegroundColor Yellow
}
Write-Host ""

# Step 4: Check UPN in certificate
Write-Host "[5] Checking User Principal Name (UPN)..." -ForegroundColor Yellow

$sanExtension = $selectedCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
if ($sanExtension) {
    $sanData = $sanExtension.Format($true)
    Write-Host "    Subject Alternative Names:" -ForegroundColor Gray
    Write-Host $sanData -ForegroundColor Gray
    
    if ($sanData -match "Principal Name=(.+)") {
        $certUPN = $Matches[1].Trim()
        Write-Host "    Certificate UPN: $certUPN" -ForegroundColor Green
    } else {
        Write-Host "    WARNING: No UPN found in certificate SAN" -ForegroundColor Yellow
    }
} else {
    Write-Host "    WARNING: No Subject Alternative Name extension found" -ForegroundColor Yellow
}
Write-Host ""

# Step 5: Test private key access
Write-Host "[6] Testing private key access..." -ForegroundColor Yellow

try {
    $privateKey = $selectedCert.PrivateKey
    if ($privateKey) {
        Write-Host "    Private key accessible (legacy CSP)" -ForegroundColor Green
        Write-Host "    Key type: $($privateKey.GetType().Name)" -ForegroundColor Gray
    }
} catch {
    Write-Host "    Legacy CSP private key not directly accessible" -ForegroundColor Gray
}

# Try CNG key
try {
    $cngKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($selectedCert)
    if ($cngKey) {
        Write-Host "    CNG RSA private key accessible" -ForegroundColor Green
        Write-Host "    Key size: $($cngKey.KeySize) bits" -ForegroundColor Gray
    }
} catch {
    Write-Host "    CNG RSA key: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# Step 6: Check domain controller accessibility
Write-Host "[7] Checking domain controller..." -ForegroundColor Yellow

try {
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
    Write-Host "    Domain Controller: $($dc.Name)" -ForegroundColor Green
    Write-Host "    IP Address: $($dc.IPAddress)" -ForegroundColor Gray
} catch {
    Write-Host "    ERROR: Cannot find domain controller: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Step 7: Check Kerberos configuration
Write-Host "[8] Checking Kerberos configuration..." -ForegroundColor Yellow

$kerbTickets = klist 2>&1
if ($kerbTickets -match "Cached Tickets") {
    Write-Host "    Kerberos tickets found" -ForegroundColor Green
} else {
    Write-Host "    No Kerberos tickets cached" -ForegroundColor Yellow
}
Write-Host ""

# Step 8: Summary and recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$issues = @()

if (-not $chainValid) {
    $issues += "Certificate chain validation failed"
}

if (-not $issuerCert) {
    $issues += "CA not in Trusted Root store"
}

if (-not $ntAuthCert) {
    $issues += "CA not in NTAuth store (required for PKINIT)"
}

if (-not ($sanData -match "Principal Name")) {
    $issues += "No UPN in certificate SAN"
}

if ($issues.Count -eq 0) {
    Write-Host "All checks passed! Certificate should work for PKINIT." -ForegroundColor Green
} else {
    Write-Host "Issues found:" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Next Steps" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($issues -contains "CA not in NTAuth store (required for PKINIT)") {
    Write-Host @"
    
The CA certificate must be in the NTAuth store for PKINIT to work.
Run this on the DC to add the CA to NTAuth:

    certutil -dspublish -f <CA-cert-file.cer> NTAuthCA

Or via Group Policy, the CA should be added automatically if it's
an Enterprise CA. For a standalone CA, you need to add it manually.

"@ -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Script completed." -ForegroundColor Cyan
