# Setup-DC.ps1
# Phase 1: Domain Controller Configuration for Smart Card Authentication
# Run as Administrator on Domain Controller

param(
    [string]$Username,
    [string]$SKIHash,
    [switch]$InitialSetup
)

Write-Host "=== Phase 1: Domain Controller Setup ===" -ForegroundColor Cyan

# Initial one-time setup
if ($InitialSetup) {
    Write-Host ""
    Write-Host "[1/2] Configuring StrongCertificateBindingEnforcement..." -ForegroundColor Yellow
    
    $currentValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -ErrorAction SilentlyContinue
    
    if ($currentValue.StrongCertificateBindingEnforcement -eq 0) {
        Write-Host "  Already set to 0" -ForegroundColor Green
    } else {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord
        Write-Host "  Set to 0" -ForegroundColor Green
        
        Write-Host "[2/2] Restarting KDC service..." -ForegroundColor Yellow
        Restart-Service kdc
        Write-Host "  KDC restarted" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "=== INITIAL SETUP COMPLETE ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DC is now configured for smart card authentication." -ForegroundColor White
    Write-Host "Run this script again with -Username and -SKIHash to set user mappings." -ForegroundColor White
    exit 0
}

# User mapping setup
if (!$Username -or !$SKIHash) {
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  Initial DC setup:    .\Setup-DC.ps1 -InitialSetup" -ForegroundColor White
    Write-Host "  Set user mapping:    .\Setup-DC.ps1 -Username shop -SKIHash abc123..." -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Setting up user: $Username" -ForegroundColor White
Write-Host "SKI Hash: $SKIHash" -ForegroundColor White
Write-Host ""

# Verify user exists
$user = Get-ADUser $Username -Properties altSecurityIdentities -ErrorAction SilentlyContinue
if (!$user) {
    Write-Host "ERROR: User '$Username' not found in AD" -ForegroundColor Red
    exit 1
}

# Clear existing mappings
Write-Host "[1/3] Clearing existing mappings..." -ForegroundColor Yellow
Set-ADUser $Username -Clear altSecurityIdentities
Write-Host "  Cleared" -ForegroundColor Green

# Add new SKI mapping
Write-Host "[2/3] Adding SKI mapping..." -ForegroundColor Yellow
$mapping = "X509:<SKI>$SKIHash"
Set-ADUser $Username -Add @{altSecurityIdentities=$mapping}
Write-Host "  Added: $mapping" -ForegroundColor Green

# Verify
Write-Host "[3/3] Verifying..." -ForegroundColor Yellow
$user = Get-ADUser $Username -Properties altSecurityIdentities
Write-Host "  altSecurityIdentities: $($user.altSecurityIdentities)" -ForegroundColor Green

Write-Host ""
Write-Host "=== USER MAPPING COMPLETE ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test on workstation:" -ForegroundColor Yellow
Write-Host "runas /smartcard /user:$Username@$((Get-ADDomain).DNSRoot) cmd.exe" -ForegroundColor White
