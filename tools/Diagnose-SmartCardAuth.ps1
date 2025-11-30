# Diagnose-SmartCardAuth.ps1
# Diagnostic script for troubleshooting smart card PKINIT authentication
# Can be run on workstation or domain controller

param(
    [ValidateSet("Workstation", "DC", "Both")]
    [string]$Target = "Workstation",
    
    [string]$Username = "shop"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Smart Card Authentication Diagnostics" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow

function Test-Workstation {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "WORKSTATION DIAGNOSTICS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Check VSC
    Write-Host "`n[1] Virtual Smart Card Status" -ForegroundColor Yellow
    Write-Host "-" * 40
    $vscInfo = certutil -scinfo -silent 2>&1
    if ($vscInfo -match "Microsoft Virtual Smart Card") {
        Write-Host "✓ VSC detected" -ForegroundColor Green
        certutil -scinfo -silent | Select-String -Pattern "Card|Reader|Provider"
    } else {
        Write-Host "✗ VSC NOT detected" -ForegroundColor Red
    }
    
    # Check certificates
    Write-Host "`n[2] User Certificates" -ForegroundColor Yellow
    Write-Host "-" * 40
    $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$Username*" }
    if ($certs) {
        Write-Host "Found $($certs.Count) certificate(s):" -ForegroundColor Green
        $certs | ForEach-Object {
            Write-Host "`n  Thumbprint: $($_.Thumbprint)" -ForegroundColor White
            Write-Host "  Subject: $($_.Subject)" -ForegroundColor White
            Write-Host "  NotBefore: $($_.NotBefore)" -ForegroundColor White
            Write-Host "  HasPrivateKey: $($_.HasPrivateKey)" -ForegroundColor $(if ($_.HasPrivateKey) { "Green" } else { "Red" })
            
            # Check for UPN in SAN
            $san = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($san) {
                $sanText = $san.Format($true)
                if ($sanText -match "Principal Name") {
                    Write-Host "  UPN in SAN: ✓" -ForegroundColor Green
                    Write-Host "    $sanText" -ForegroundColor Gray
                } else {
                    Write-Host "  UPN in SAN: ✗ (CRITICAL!)" -ForegroundColor Red
                }
            } else {
                Write-Host "  SAN Extension: ✗ MISSING (CRITICAL!)" -ForegroundColor Red
            }
            
            # Check EKU
            $eku = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
            if ($eku) {
                $ekuText = $eku.Format($true)
                $hasSmartCard = $ekuText -match "Smart Card Logon"
                $hasClientAuth = $ekuText -match "Client Authentication"
                Write-Host "  Smart Card Logon EKU: $(if ($hasSmartCard) { '✓' } else { '✗' })" -ForegroundColor $(if ($hasSmartCard) { "Green" } else { "Red" })
                Write-Host "  Client Auth EKU: $(if ($hasClientAuth) { '✓' } else { '✗' })" -ForegroundColor $(if ($hasClientAuth) { "Green" } else { "Red" })
            }
        }
        
        if ($certs.Count -gt 1) {
            Write-Host "`n⚠ WARNING: Multiple certificates detected!" -ForegroundColor Red
            Write-Host "  This can cause Windows to select the wrong certificate" -ForegroundColor Yellow
            Write-Host "  Recommendation: Recreate VSC with single certificate" -ForegroundColor Yellow
        }
    } else {
        Write-Host "✗ No certificates found for $Username" -ForegroundColor Red
    }
    
    # Check recent Kerberos errors
    Write-Host "`n[3] Recent Kerberos Errors (last 10)" -ForegroundColor Yellow
    Write-Host "-" * 40
    $kerbErrors = Get-WinEvent -LogName "System" -MaxEvents 100 -ErrorAction SilentlyContinue | 
        Where-Object { $_.ProviderName -like "*Kerb*" -and $_.LevelDisplayName -eq "Error" } | 
        Select-Object -First 10
    
    if ($kerbErrors) {
        $kerbErrors | ForEach-Object {
            Write-Host "`n  Time: $($_.TimeCreated)" -ForegroundColor Gray
            Write-Host "  Event ID: $($_.Id)" -ForegroundColor Gray
            $msg = $_.Message -split "`n" | Select-Object -First 5
            $msg | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        }
    } else {
        Write-Host "✓ No recent Kerberos errors" -ForegroundColor Green
    }
    
    # Check CAPI2 logging
    Write-Host "`n[4] CAPI2 Logging Status" -ForegroundColor Yellow
    Write-Host "-" * 40
    try {
        $capi2 = Get-WinEvent -ListLog "Microsoft-Windows-CAPI2/Operational" -ErrorAction Stop
        Write-Host "CAPI2 Logging: $(if ($capi2.IsEnabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($capi2.IsEnabled) { "Green" } else { "Yellow" })
        if (-not $capi2.IsEnabled) {
            Write-Host "  Enable with: wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Could not check CAPI2 status" -ForegroundColor Yellow
    }
}

function Test-DomainController {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "DOMAIN CONTROLLER DIAGNOSTICS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Check if running on DC
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    if (-not $isDC) {
        Write-Host "⚠ This does not appear to be a Domain Controller" -ForegroundColor Yellow
    }
    
    # Check KDC service
    Write-Host "`n[1] KDC Service Status" -ForegroundColor Yellow
    Write-Host "-" * 40
    $kdc = Get-Service -Name "kdc" -ErrorAction SilentlyContinue
    if ($kdc) {
        Write-Host "KDC Service: $($kdc.Status)" -ForegroundColor $(if ($kdc.Status -eq "Running") { "Green" } else { "Red" })
    } else {
        Write-Host "KDC Service: Not found (not a DC?)" -ForegroundColor Yellow
    }
    
    # Check KDC registry settings
    Write-Host "`n[2] KDC Registry Settings" -ForegroundColor Yellow
    Write-Host "-" * 40
    $kdcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
    
    $strongBinding = Get-ItemProperty -Path $kdcPath -Name "StrongCertificateBindingEnforcement" -ErrorAction SilentlyContinue
    if ($strongBinding) {
        $val = $strongBinding.StrongCertificateBindingEnforcement
        $status = switch ($val) {
            0 { "Disabled (testing mode)" }
            1 { "Compatibility mode" }
            2 { "Full enforcement" }
            default { "Unknown ($val)" }
        }
        Write-Host "StrongCertificateBindingEnforcement: $val - $status" -ForegroundColor $(if ($val -eq 0) { "Yellow" } else { "White" })
    } else {
        Write-Host "StrongCertificateBindingEnforcement: Not set (default behavior)" -ForegroundColor Gray
    }
    
    $useSAN = Get-ItemProperty -Path $kdcPath -Name "UseSubjectAltName" -ErrorAction SilentlyContinue
    if ($useSAN) {
        Write-Host "UseSubjectAltName: $($useSAN.UseSubjectAltName)" -ForegroundColor $(if ($useSAN.UseSubjectAltName -eq 1) { "Green" } else { "Yellow" })
    } else {
        Write-Host "UseSubjectAltName: Not set" -ForegroundColor Gray
    }
    
    # Check Event 39 errors
    Write-Host "`n[3] Recent Certificate Mapping Errors (Event 39)" -ForegroundColor Yellow
    Write-Host "-" * 40
    $event39 = Get-WinEvent -LogName "System" -MaxEvents 100 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Id -eq 39 } | 
        Select-Object -First 5
    
    if ($event39) {
        Write-Host "✗ Found $($event39.Count) certificate mapping errors" -ForegroundColor Red
        $event39 | ForEach-Object {
            Write-Host "`n  Time: $($_.TimeCreated)" -ForegroundColor Gray
            $_.Message -split "`n" | Select-Object -First 8 | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        }
    } else {
        Write-Host "✓ No recent certificate mapping errors" -ForegroundColor Green
    }
    
    # Check user's altSecurityIdentities
    Write-Host "`n[4] User altSecurityIdentities" -ForegroundColor Yellow
    Write-Host "-" * 40
    try {
        $adUser = Get-ADUser -Identity $Username -Properties altSecurityIdentities -ErrorAction Stop
        $altSec = $adUser.altSecurityIdentities
        if ($altSec) {
            Write-Host "Found $($altSec.Count) mapping(s):" -ForegroundColor Green
            $altSec | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        } else {
            Write-Host "No altSecurityIdentities configured" -ForegroundColor Gray
            Write-Host "  (Not required if UPN is in certificate SAN)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Could not query AD user: $_" -ForegroundColor Yellow
    }
    
    # Check NTAuth store
    Write-Host "`n[5] NTAuth Store" -ForegroundColor Yellow
    Write-Host "-" * 40
    $ntauth = certutil -viewstore -enterprise NTAuth 2>&1
    $caCount = ($ntauth | Select-String -Pattern "================ Certificate").Count
    Write-Host "CA certificates in NTAuth: $caCount" -ForegroundColor $(if ($caCount -gt 0) { "Green" } else { "Red" })
    
    # Check certificate template
    Write-Host "`n[6] Certificate Template Configuration" -ForegroundColor Yellow
    Write-Host "-" * 40
    $template = certutil -dstemplate AuthentikSmartcard msPKI-Certificate-Name-Flag 2>&1
    if ($template -match "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN") {
        Write-Host "✓ Template has CT_FLAG_SUBJECT_ALT_REQUIRE_UPN" -ForegroundColor Green
    } else {
        Write-Host "✗ Template missing CT_FLAG_SUBJECT_ALT_REQUIRE_UPN" -ForegroundColor Red
    }
    $template | Select-String -Pattern "msPKI-Certificate-Name-Flag|CT_FLAG" | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    
    # Check recent 4768 events (TGT requests)
    Write-Host "`n[7] Recent TGT Requests (Event 4768)" -ForegroundColor Yellow
    Write-Host "-" * 40
    $tgtEvents = Get-WinEvent -LogName "Security" -MaxEvents 100 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Id -eq 4768 } | 
        Select-Object -First 5
    
    if ($tgtEvents) {
        Write-Host "Found $($tgtEvents.Count) recent TGT request(s)" -ForegroundColor Green
        $tgtEvents | ForEach-Object {
            $msg = $_.Message
            $accountMatch = [regex]::Match($msg, "Account Name:\s+(\S+)")
            $resultMatch = [regex]::Match($msg, "Result Code:\s+(\S+)")
            $preAuthMatch = [regex]::Match($msg, "Pre-Authentication Type:\s+(\S+)")
            
            Write-Host "`n  Time: $($_.TimeCreated)" -ForegroundColor Gray
            if ($accountMatch.Success) { Write-Host "  Account: $($accountMatch.Groups[1].Value)" -ForegroundColor White }
            if ($resultMatch.Success) { Write-Host "  Result: $($resultMatch.Groups[1].Value)" -ForegroundColor $(if ($resultMatch.Groups[1].Value -eq "0x0") { "Green" } else { "Red" }) }
            if ($preAuthMatch.Success) { 
                $preAuth = $preAuthMatch.Groups[1].Value
                Write-Host "  PreAuth Type: $preAuth $(if ($preAuth -eq '2') { '(Password)' } elseif ($preAuth -eq '16') { '(PKINIT)' } else { '' })" -ForegroundColor White 
            }
        }
    } else {
        Write-Host "No recent TGT requests found" -ForegroundColor Yellow
    }
}

# Run diagnostics based on target
if ($Target -eq "Workstation" -or $Target -eq "Both") {
    Test-Workstation
}

if ($Target -eq "DC" -or $Target -eq "Both") {
    Test-DomainController
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Diagnostics Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host @"

Common Issues and Solutions:

1. "No UPN in SAN" - Reconfigure template with CT_FLAG_SUBJECT_ALT_REQUIRE_UPN
2. "Multiple certificates" - Destroy VSC and recreate with single certificate
3. "Event 39 errors" - Check certificate mapping, ensure UPN matches AD
4. "Kerberos 0x19 with empty client" - Certificate not on smart card provider
5. "StrongCertificateBindingEnforcement=2" - May need explicit altSecurityIdentities

"@ -ForegroundColor Yellow
