# Configure-SmartCardTemplate.ps1
# Configures certificate template for PKINIT smart card authentication
# Run on Domain Controller with AD CS installed

param(
    [string]$TemplateName = "AuthentikSmartcard",
    [switch]$CreateNew,
    [switch]$Force
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Smart Card Template Configuration Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Check if AD module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell module not found"
    exit 1
}

Import-Module ActiveDirectory

# Get configuration naming context
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

Write-Host "`nTemplate DN: $templateDN" -ForegroundColor Yellow

# Check if template exists
$templateExists = $null
try {
    $templateExists = Get-ADObject -Identity $templateDN -ErrorAction Stop
    Write-Host "Template '$TemplateName' found" -ForegroundColor Green
} catch {
    Write-Host "Template '$TemplateName' not found" -ForegroundColor Red
    if (-not $CreateNew) {
        Write-Host "Use -CreateNew to create a new template (requires duplicating from SmartcardLogon)"
        exit 1
    }
}

# Define the required flags
# CT_FLAG_SUBJECT_ALT_REQUIRE_UPN    = 0x02000000 (33554432)
# CT_FLAG_SUBJECT_REQUIRE_EMAIL      = 0x20000000 (536870912)
# CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000 (1073741824)
# Combined = 0x62000000 (1644167168)

$requiredFlags = 0x62000000

Write-Host "`nConfiguring template flags..." -ForegroundColor Cyan
Write-Host "Required msPKI-Certificate-Name-Flag: 0x$($requiredFlags.ToString('X8')) ($requiredFlags)" -ForegroundColor Yellow
Write-Host "  CT_FLAG_SUBJECT_ALT_REQUIRE_UPN    = 0x02000000 (33554432)" -ForegroundColor Gray
Write-Host "  CT_FLAG_SUBJECT_REQUIRE_EMAIL      = 0x20000000 (536870912)" -ForegroundColor Gray
Write-Host "  CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000 (1073741824)" -ForegroundColor Gray

if ($templateExists) {
    # Get current flags
    $currentFlags = (Get-ADObject -Identity $templateDN -Properties 'msPKI-Certificate-Name-Flag').'msPKI-Certificate-Name-Flag'
    Write-Host "`nCurrent flags: 0x$($currentFlags.ToString('X8')) ($currentFlags)" -ForegroundColor Yellow
    
    if ($currentFlags -eq $requiredFlags) {
        Write-Host "Template already has correct flags configured!" -ForegroundColor Green
    } else {
        if ($Force -or (Read-Host "Update template flags? (y/n)") -eq 'y') {
            Write-Host "Updating template flags..." -ForegroundColor Cyan
            Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag'=$requiredFlags}
            Write-Host "Template flags updated successfully!" -ForegroundColor Green
        }
    }
}

# Grant Authenticated Users enroll permission
Write-Host "`nConfiguring enrollment permissions..." -ForegroundColor Cyan
try {
    $result = dsacls $templateDN /G "Authenticated Users:CA;Enroll" 2>&1
    Write-Host "Enrollment permissions configured" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not set permissions: $_" -ForegroundColor Yellow
}

# Restart Certificate Services
Write-Host "`nRestarting Certificate Services..." -ForegroundColor Cyan
try {
    Restart-Service certsvc -Force
    Write-Host "Certificate Services restarted" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not restart certsvc: $_" -ForegroundColor Yellow
    Write-Host "Please restart Certificate Services manually" -ForegroundColor Yellow
}

# Verify configuration
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nTemplate configuration:" -ForegroundColor Yellow
certutil -dstemplate $TemplateName msPKI-Certificate-Name-Flag

Write-Host "`nCA templates available:" -ForegroundColor Yellow
certutil -catemplates | Select-String -Pattern $TemplateName

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host @"

Next Steps:
1. On workstation, create Virtual Smart Card:
   tpmvscmgr create /name "VSC" /pin PROMPT /adminkey random /generate

2. Create certificate request and enroll:
   certreq -new request.inf request.csr
   certreq -submit -config "DC\CA" request.csr cert.cer
   certreq -accept cert.cer

3. Test smart card login with Win+L

"@ -ForegroundColor Cyan
