# Install-CertIssuerNative.ps1
# Installs Certificate Issuer as a native Windows Service using sc.exe
# No NSSM required - uses PowerShell scheduled task as service wrapper

#Requires -RunAsAdministrator

param(
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Status")]
    [string]$Action = "Install",
    
    [string]$ServiceName = "AuthentikCertIssuer",
    [int]$Port = 8443,
    [string]$CAConfig = "",
    [string]$ApiToken = ""
)

$ConfigDir = "$env:ProgramData\Authentik\CertIssuer"
$ConfigPath = "$ConfigDir\config.json"
$LogPath = "$ConfigDir\Logs"
$TaskName = "AuthentikCertIssuerService"

function Initialize-Environment {
    # Create directories
    @($ConfigDir, $LogPath, "$ConfigDir\Temp") | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "Created: $_" -ForegroundColor Gray
        }
    }
    
    # Create Event Log source
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("AuthentikCertIssuer")) {
            New-EventLog -LogName "Application" -Source "AuthentikCertIssuer" -ErrorAction Stop
        }
    } catch {}
    
    # Create config if not exists
    if (-not (Test-Path $ConfigPath)) {
        $config = @{
            Port = $Port
            ApiToken = if ($ApiToken) { $ApiToken } else { "TOKEN-$(Get-Random -Maximum 999999)" }
            CAConfig = $CAConfig
            CertTemplate = "AuthentikSmartcard"
            UseHttps = $false
        }
        $config | ConvertTo-Json | Out-File $ConfigPath -Encoding UTF8
        Write-Host "Created config: $ConfigPath" -ForegroundColor Yellow
        Write-Host "IMPORTANT: Edit config.json and set CAConfig!" -ForegroundColor Red
    }
}

function Get-Config {
    if (Test-Path $ConfigPath) {
        return Get-Content $ConfigPath -Raw | ConvertFrom-Json
    }
    return $null
}

# Create the actual service script
$ServiceScript = @'
# CertIssuer Service Script
param([string]$ConfigPath)

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$Port = $config.Port
$ApiToken = $config.ApiToken
$CAConfig = $config.CAConfig
$CertTemplate = $config.CertTemplate
$LogDir = Split-Path $ConfigPath -Parent
$LogPath = "$LogDir\Logs"
$TempPath = "$LogDir\Temp"

function Log($msg, $level = "Info") {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = "$LogPath\service_$(Get-Date -Format 'yyyyMMdd').log"
    "[$ts] [$level] $msg" | Add-Content $logFile
    try { Write-EventLog -LogName Application -Source AuthentikCertIssuer -EventId 1000 -EntryType $level -Message $msg -EA SilentlyContinue } catch {}
}

function Issue-Cert($user, $upn) {
    Log "Issuing cert for $user"
    if (-not $CAConfig) { return @{success=$false; error="CA not configured"} }
    
    if (-not $upn) {
        try { $upn = (Get-ADUser $user -Properties userPrincipalName).userPrincipalName }
        catch { return @{success=$false; error="User not found: $_"} }
    }
    if (-not $upn) { return @{success=$false; error="No UPN for user"} }
    
    $id = (Get-Random -Max 99999999).ToString("X8")
    $inf = "$TempPath\$id.inf"; $req = "$TempPath\$id.req"; $cer = "$TempPath\$id.cer"; $pfx = "$TempPath\$id.pfx"
    
    try {
        @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$user"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
[RequestAttributes]
CertificateTemplate = $CertTemplate
"@ | Out-File $inf -Encoding ASCII
        
        $null = certreq -new -q $inf $req 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -new failed" }
        
        $null = certreq -submit -q -config $CAConfig $req $cer 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -submit failed" }
        
        $null = certreq -accept -q $cer 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -accept failed" }
        
        Start-Sleep -Milliseconds 500
        
        $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)).Thumbprint
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $thumb }
        if (-not $cert -or -not $cert.HasPrivateKey) { throw "Cert not found or no key" }
        
        $pw = (Get-Random -Max 9999999999999999).ToString("X16")
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString $pw -Force -AsPlainText) | Out-Null
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx))
        
        $cert | Remove-Item -Force -EA SilentlyContinue
        Log "Cert issued: $thumb"
        
        return @{success=$true; thumbprint=$thumb; pfx_base64=$b64; pfx_password=$pw; upn=$upn; subject=$cert.Subject}
    }
    catch {
        Log "Failed: $_" "Error"
        return @{success=$false; error=$_.ToString()}
    }
    finally {
        @($inf,$req,$cer,$pfx) | Where-Object {$_ -and (Test-Path $_)} | Remove-Item -Force -EA SilentlyContinue
    }
}

function Send-Json($resp, $data, $code = 200) {
    $json = $data | ConvertTo-Json -Depth 10
    $buf = [Text.Encoding]::UTF8.GetBytes($json)
    $resp.StatusCode = $code
    $resp.ContentType = "application/json"
    $resp.ContentLength64 = $buf.Length
    $resp.OutputStream.Write($buf, 0, $buf.Length)
    $resp.OutputStream.Close()
}

Log "Starting on port $Port"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")

try {
    $listener.Start()
    Log "Service started"
    
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request; $resp = $ctx.Response
        $resp.Headers.Add("Access-Control-Allow-Origin", "*")
        $resp.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $resp.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        $path = $req.Url.LocalPath
        
        if ($req.HttpMethod -eq "OPTIONS") { $resp.StatusCode = 200; $resp.Close(); continue }
        
        if ($path -eq "/health") {
            Send-Json $resp @{status="healthy"; port=$Port; ca=$CAConfig}
            continue
        }
        
        if ($path -eq "/api/v1/issue-certificate" -and $req.HttpMethod -eq "POST") {
            if ($req.Headers["Authorization"] -ne "Bearer $ApiToken") {
                Send-Json $resp @{success=$false; error="Unauthorized"} 401
                continue
            }
            $body = (New-Object IO.StreamReader($req.InputStream)).ReadToEnd()
            try { $data = $body | ConvertFrom-Json } catch { Send-Json $resp @{success=$false; error="Invalid JSON"} 400; continue }
            if (-not $data.username) { Send-Json $resp @{success=$false; error="Missing username"} 400; continue }
            
            $result = Issue-Cert $data.username $data.upn
            Send-Json $resp $result $(if ($result.success) {200} else {500})
            continue
        }
        
        Send-Json $resp @{error="Not Found"} 404
    }
} catch {
    Log "Service error: $_" "Error"
} finally {
    if ($listener) { $listener.Stop() }
    Log "Service stopped"
}
'@

$ServiceScriptPath = "$ConfigDir\CertIssuerService.ps1"

function Install-Service {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Installing Authentik Certificate Issuer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Initialize-Environment
    
    # Save the service script
    $ServiceScript | Out-File $ServiceScriptPath -Encoding UTF8 -Force
    Write-Host "Created service script: $ServiceScriptPath" -ForegroundColor Green
    
    # Create scheduled task that runs at startup as SYSTEM
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ServiceScriptPath`" -ConfigPath `"$ConfigPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    # Remove existing task if present
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    
    # Register new task
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Authentik Certificate Issuer Service" | Out-Null
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Installation Complete!" -ForegroundColor Green  
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration: $ConfigPath" -ForegroundColor Yellow
    
    $config = Get-Config
    if (-not $config.CAConfig) {
        Write-Host ""
        Write-Host "IMPORTANT: Edit config.json and set CAConfig!" -ForegroundColor Red
        Write-Host "Example: WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "To start now: .\Install-CertIssuerNative.ps1 -Action Start" -ForegroundColor Cyan
    Write-Host "Service will auto-start on boot" -ForegroundColor Cyan
}

function Uninstall-Service {
    Write-Host "Uninstalling..." -ForegroundColor Yellow
    
    # Stop task if running
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    
    # Remove task
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "Service uninstalled" -ForegroundColor Green
    Write-Host "Config preserved in: $ConfigDir" -ForegroundColor Gray
}

function Start-ServiceTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host "Service not installed. Run with -Action Install first." -ForegroundColor Red
        return
    }
    
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    
    $config = Get-Config
    Write-Host "Service starting on port $($config.Port)..." -ForegroundColor Green
    Write-Host "Test: Invoke-RestMethod http://localhost:$($config.Port)/health" -ForegroundColor Cyan
}

function Stop-ServiceTask {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    
    # Also kill any running PowerShell hosting the service
    Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*CertIssuerService.ps1*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Write-Host "Service stopped" -ForegroundColor Yellow
}

function Get-ServiceStatus {
    Write-Host ""
    Write-Host "=== Authentik Certificate Issuer Status ===" -ForegroundColor Cyan
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "Task Status: $($task.State)" -ForegroundColor $(if ($task.State -eq "Running") {"Green"} else {"Yellow"})
        Write-Host "Last Run: $($info.LastRunTime)" -ForegroundColor Gray
        Write-Host "Next Run: $($info.NextRunTime)" -ForegroundColor Gray
    } else {
        Write-Host "Service not installed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Config: $ConfigPath" -ForegroundColor White
    if (Test-Path $ConfigPath) {
        $config = Get-Config
        Write-Host "  Port: $($config.Port)" -ForegroundColor Gray
        Write-Host "  CA: $($config.CAConfig)" -ForegroundColor Gray
        Write-Host "  Template: $($config.CertTemplate)" -ForegroundColor Gray
        
        # Test if service is responding
        try {
            $health = Invoke-RestMethod "http://localhost:$($config.Port)/health" -TimeoutSec 2 -ErrorAction Stop
            Write-Host ""
            Write-Host "Health Check: OK" -ForegroundColor Green
        } catch {
            Write-Host ""
            Write-Host "Health Check: Not responding" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Main
switch ($Action) {
    "Install" { Install-Service }
    "Uninstall" { Uninstall-Service }
    "Start" { Start-ServiceTask }
    "Stop" { Stop-ServiceTask }
    "Status" { Get-ServiceStatus }
}
