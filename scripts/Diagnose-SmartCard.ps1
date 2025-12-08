# Diagnose-SmartCard.ps1
# Phase 1: Smart Card Authentication Diagnostics
# Run on workstation to troubleshoot authentication issues

param(
    [string]$Username = "shop"
)

Write-Host "=== Smart Card Authentication Diagnostics ===" -ForegroundColor Cyan
Write-Host "Target User: $Username" -ForegroundColor White
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor White
Write-Host ""

$issues = @()

# 1. Check Smart Card Service
Write-Host "[1/8] Smart Card Service..." -ForegroundColor Yellow
$scService = Get-Service SCardSvr -ErrorAction SilentlyContinue
if ($scService.Status -eq "Running") {
    Write-Host "  ✓ Running" -ForegroundColor Green
} else {
    Write-Host "  ✗ NOT Running" -ForegroundColor Red
    $issues += "Smart Card Service not running"
}

# 2. Check VSC
Write-Host "[2/8] Virtual Smart Card..." -ForegroundColor Yellow
$scInfo = certutil -scinfo 2>&1
if ($scInfo -match "Microsoft Virtual Smart Card") {
    Write-Host "  ✓ VSC Present" -ForegroundColor Green
} else {
    Write-Host "  ✗ VSC NOT Found" -ForegroundColor Red
    $issues += "No Virtual Smart Card found"
}

# 3. Check Certificate on VSC
Write-Host "[3/8] Certificate on VSC..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=$Username"} | Select-Object -First 1
if ($cert) {
    Write-Host "  ✓ Certificate found: $($cert.Thumbprint)" -ForegroundColor Green
    Write-Host "    Subject: $($cert.Subject)" -ForegroundColor White
    Write-Host "    Expires: $($cert.NotAfter)" -ForegroundColor White
    
    # Check EKU
    $eku = $cert.EnhancedKeyUsageList | Where-Object {$_.ObjectId -eq "1.3.6.1.4.1.311.20.2.2"}
    if ($eku) {
        Write-Host "  ✓ Smart Card Logon EKU present" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Smart Card Logon EKU MISSING" -ForegroundColor Red
        $issues += "Certificate missing Smart Card Logon EKU"
    }
    
    # Check SAN/UPN
    $san = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}
    if ($san) {
        $sanText = $san.Format(1)
        if ($sanText -match "$Username@") {
            Write-Host "  ✓ UPN in SAN: $($sanText -replace "`n", " ")" -ForegroundColor Green
        } else {
            Write-Host "  ✗ UPN not found in SAN" -ForegroundColor Red
            $issues += "Certificate missing UPN in SAN"
        }
    }
    
    # Get SKI
    $ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
    if ($ski) {
        $skiHash = $ski.Format(0)
        Write-Host "  ✓ SKI Hash: $skiHash" -ForegroundColor Green
    }
} else {
    Write-Host "  ✗ NO Certificate for $Username" -ForegroundColor Red
    $issues += "No certificate found for user"
}

# 4. Check NTAuth Store
Write-Host "[4/8] NTAuth Store (CA Trust)..." -ForegroundColor Yellow
$ntauth = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates" -ErrorAction SilentlyContinue
if ($ntauth) {
    Write-Host "  ✓ CA(s) in NTAuth: $($ntauth.Count)" -ForegroundColor Green
    foreach ($ca in $ntauth) {
        Write-Host "    - $($ca.PSChildName.Substring(0,20))..." -ForegroundColor White
    }
} else {
    Write-Host "  ✗ NTAuth Store EMPTY" -ForegroundColor Red
    $issues += "NTAuth store empty - run gpupdate /force"
}

# 5. Check Smart Card Credential Provider
Write-Host "[5/8] Smart Card Credential Provider..." -ForegroundColor Yellow
$cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
$cpDisabled = Get-ItemProperty $cpPath -Name "Disabled" -ErrorAction SilentlyContinue
if ($cpDisabled.Disabled -eq 0 -or $cpDisabled -eq $null) {
    Write-Host "  ✓ Enabled" -ForegroundColor Green
} else {
    Write-Host "  ✗ DISABLED" -ForegroundColor Red
    $issues += "Smart Card Credential Provider disabled"
}

# 6. Certificate Chain Validation
Write-Host "[6/8] Certificate Chain Validation..." -ForegroundColor Yellow
if ($cert) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $valid = $chain.Build($cert)
    if ($valid) {
        Write-Host "  ✓ Chain validates" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Chain validation FAILED" -ForegroundColor Red
        foreach ($status in $chain.ChainStatus) {
            Write-Host "    - $($status.StatusInformation)" -ForegroundColor Red
        }
        $issues += "Certificate chain validation failed"
    }
}

# 7. Domain Connectivity
Write-Host "[7/8] Domain Controller Connectivity..." -ForegroundColor Yellow
$dc = (Get-WmiObject -Class Win32_ComputerSystem).Domain
$dcName = (nltest /dsgetdc:$dc 2>&1) -match "DC: " | ForEach-Object { $_ -replace ".*DC: \\\\" }
if ($dcName) {
    $ping = Test-Connection $dcName -Count 1 -Quiet
    if ($ping) {
        Write-Host "  ✓ DC reachable: $dcName" -ForegroundColor Green
    } else {
        Write-Host "  ✗ DC NOT reachable: $dcName" -ForegroundColor Red
        $issues += "Cannot reach Domain Controller"
    }
} else {
    Write-Host "  ✗ Cannot determine DC" -ForegroundColor Red
    $issues += "Cannot determine Domain Controller"
}

# 8. Kerberos Tickets
Write-Host "[8/8] Current Kerberos Tickets..." -ForegroundColor Yellow
$klist = klist 2>&1
$tgtCount = ($klist | Select-String "krbtgt").Count
Write-Host "  TGT tickets: $tgtCount" -ForegroundColor White

# Summary
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
if ($issues.Count -eq 0) {
    Write-Host "✓ No issues detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "If authentication still fails, check on DC:" -ForegroundColor Yellow
    Write-Host "  1. Get-ADUser $Username -Properties altSecurityIdentities" -ForegroundColor White
    Write-Host "  2. Verify SKI mapping matches: X509:<SKI>$skiHash" -ForegroundColor White
    Write-Host "  3. Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement" -ForegroundColor White
} else {
    Write-Host "✗ Issues found: $($issues.Count)" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Quick Test Command:" -ForegroundColor Yellow
Write-Host "runas /smartcard /user:$Username@$($env:USERDNSDOMAIN.ToLower()) cmd.exe" -ForegroundColor White
