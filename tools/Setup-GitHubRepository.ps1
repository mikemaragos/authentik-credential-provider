# Setup-GitHubRepository.ps1
# Automated setup script for Authentik Credential Provider GitHub repository
# Version: 1.0
# Date: November 22, 2025

<#
.SYNOPSIS
    Sets up the GitHub repository structure for the Authentik Credential Provider project.

.DESCRIPTION
    This script automates the initial setup of the GitHub repository including:
    - Creating folder structure
    - Copying existing project files
    - Creating essential configuration files
    - Initializing Git repository
    - Creating initial commit

.PARAMETER RepositoryPath
    Local path where the repository will be created/located.
    Default: C:\Projects\authentik-credential-provider

.PARAMETER SourcePath
    Path to your existing project files.
    Required if you want to copy existing files.

.PARAMETER ImprovementsPath
    Path to the improved files from the analysis.
    Default: Current directory

.PARAMETER GitHubUsername
    Your GitHub username (for remote URL setup).

.PARAMETER SkipGitInit
    Skip Git initialization (if already cloned from GitHub).

.EXAMPLE
    .\Setup-GitHubRepository.ps1 -GitHubUsername "myusername"
    
.EXAMPLE
    .\Setup-GitHubRepository.ps1 -RepositoryPath "D:\Dev\authentik-cp" -GitHubUsername "myusername" -SourcePath "C:\OldProject"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RepositoryPath = "C:\Projects\authentik-credential-provider",
    
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$ImprovementsPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$true)]
    [string]$GitHubUsername,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipGitInit
)

# Script configuration
$ErrorActionPreference = "Stop"
$RepositoryName = "authentik-credential-provider"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Authentik Credential Provider" -ForegroundColor Cyan
Write-Host "GitHub Repository Setup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Git is installed
Write-Host "[1/8] Checking prerequisites..." -ForegroundColor Yellow
try {
    $gitVersion = git --version
    Write-Host "  ✓ Git found: $gitVersion" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ Git not found! Please install Git first." -ForegroundColor Red
    Write-Host "    Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Create repository directory if it doesn't exist
Write-Host ""
Write-Host "[2/8] Creating repository structure..." -ForegroundColor Yellow

if (-not (Test-Path $RepositoryPath)) {
    New-Item -ItemType Directory -Path $RepositoryPath -Force | Out-Null
    Write-Host "  ✓ Created repository directory: $RepositoryPath" -ForegroundColor Green
}
else {
    Write-Host "  ℹ Repository directory already exists: $RepositoryPath" -ForegroundColor Cyan
}

Set-Location $RepositoryPath

# Create folder structure
$folders = @(
    ".github\workflows",
    "docs\architecture",
    "docs\deployment",
    "docs\development",
    "docs\user-guide",
    "src\AuthentikCredentialProvider",
    "tests\AuthentikCredentialProvider.Tests",
    "tools\Diagnostics",
    "assets"
)

foreach ($folder in $folders) {
    $fullPath = Join-Path $RepositoryPath $folder
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Host "  ✓ Created: $folder" -ForegroundColor Green
    }
}

# Copy existing project files if source path provided
Write-Host ""
Write-Host "[3/8] Copying project files..." -ForegroundColor Yellow

if ($SourcePath -and (Test-Path $SourcePath)) {
    Write-Host "  Copying from: $SourcePath" -ForegroundColor Cyan
    
    # Copy source files
    $srcDest = Join-Path $RepositoryPath "src\AuthentikCredentialProvider"
    
    Get-ChildItem -Path $SourcePath -Filter "*.cpp" | ForEach-Object {
        Copy-Item $_.FullName -Destination $srcDest -Force
        Write-Host "  ✓ Copied: $($_.Name)" -ForegroundColor Green
    }
    
    Get-ChildItem -Path $SourcePath -Filter "*.h" | ForEach-Object {
        Copy-Item $_.FullName -Destination $srcDest -Force
        Write-Host "  ✓ Copied: $($_.Name)" -ForegroundColor Green
    }
    
    Get-ChildItem -Path $SourcePath -Filter "*.vcxproj*" | ForEach-Object {
        Copy-Item $_.FullName -Destination $srcDest -Force
        Write-Host "  ✓ Copied: $($_.Name)" -ForegroundColor Green
    }
    
    Get-ChildItem -Path $SourcePath -Filter "*.sln" | ForEach-Object {
        Copy-Item $_.FullName -Destination (Join-Path $RepositoryPath "src") -Force
        Write-Host "  ✓ Copied: $($_.Name)" -ForegroundColor Green
    }
}
else {
    Write-Host "  ℹ No source path provided - skipping existing files" -ForegroundColor Cyan
}

# Copy improved files from analysis
Write-Host ""
Write-Host "[4/8] Copying improved files from analysis..." -ForegroundColor Yellow

$improvementFiles = @{
    "AuthentikAPI_IMPROVED.cpp" = "src\AuthentikCredentialProvider\AuthentikAPI.cpp"
    "SecureString.h" = "src\AuthentikCredentialProvider\SecureString.h"
    "RateLimiter.h" = "src\AuthentikCredentialProvider\RateLimiter.h"
    "ConfigurationManager.h" = "src\AuthentikCredentialProvider\ConfigurationManager.h"
    "PROJECT_ANALYSIS_AND_IMPROVEMENTS.md" = "docs\development\PROJECT_ANALYSIS.md"
    "IMPLEMENTATION_GUIDE.md" = "docs\development\IMPLEMENTATION_GUIDE.md"
    "EXECUTIVE_SUMMARY.md" = "docs\EXECUTIVE_SUMMARY.md"
    "KNOWLEDGE_BASE.md" = "KNOWLEDGE_BASE.md"
}

foreach ($file in $improvementFiles.Keys) {
    $source = Join-Path $ImprovementsPath $file
    $dest = Join-Path $RepositoryPath $improvementFiles[$file]
    
    if (Test-Path $source) {
        # Create destination directory if needed
        $destDir = Split-Path $dest -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        
        Copy-Item $source -Destination $dest -Force
        Write-Host "  ✓ Copied: $file" -ForegroundColor Green
    }
    else {
        Write-Host "  ⚠ Not found: $file (skipping)" -ForegroundColor Yellow
    }
}

# Create README.md
Write-Host ""
Write-Host "[5/8] Creating README.md..." -ForegroundColor Yellow

$readmeContent = @"
# Authentik Credential Provider for Windows

Windows Credential Provider that integrates with Authentik for OTP-based domain authentication.

## 🚀 Features

- Two-step OTP authentication (Username/Password → OTP)
- Integration with Authentik authentication server
- Support for TOTP, SMS, Email, and other OTP methods
- Windows domain authentication
- Rate limiting and brute force protection
- Secure password handling
- Production-ready security

## 📋 Status

- **Current Version:** 2.0 (Production-Ready)
- **Status:** Active Development
- **License:** MIT

## 🔐 Security

This credential provider implements:
- ✅ SSL/TLS certificate validation
- ✅ Input validation and sanitization
- ✅ Rate limiting and brute force protection
- ✅ Secure password handling (automatic memory zeroing)
- ✅ DPAPI encryption for sensitive configuration

## 📚 Documentation

- [Executive Summary](docs/EXECUTIVE_SUMMARY.md)
- [Implementation Guide](docs/development/IMPLEMENTATION_GUIDE.md)
- [Architecture Documentation](docs/architecture/)
- [Deployment Guide](docs/deployment/)
- [Knowledge Base](KNOWLEDGE_BASE.md)

## 🛠️ Development

### Prerequisites

- Visual Studio 2019 or 2022
- Windows SDK 10.0.19041.0 or later
- Git

### Building

1. Clone the repository
2. Open ``src/AuthentikCredentialProvider.sln`` in Visual Studio
3. Select Release configuration, x64 platform
4. Build → Build Solution

See [Development Guide](docs/development/BUILDING.md) for details.

## 📦 Installation

See [Deployment Guide](docs/deployment/DEPLOYMENT.md) for installation instructions.

Quick install:
``````powershell
.\tools\Install-AuthentikCP.ps1 -ServerUrl "authentik.example.com" -FlowSlug "windows-otp-auth"
``````

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 🗺️ Roadmap

- [x] Phase 1: Security Hardening
- [ ] Phase 2: Quality Improvements
- [ ] Phase 3: Enterprise Features
- [ ] Phase 4: Advanced Features

See [Implementation Guide](docs/development/IMPLEMENTATION_GUIDE.md) for detailed roadmap.
"@

$readmePath = Join-Path $RepositoryPath "README.md"
$readmeContent | Out-File -FilePath $readmePath -Encoding UTF8
Write-Host "  ✓ Created README.md" -ForegroundColor Green

# Create CHANGELOG.md
$changelogContent = @"
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive project analysis and improvement plan
- SecureString class for secure password handling
- RateLimiter class for brute force protection
- ConfigurationManager for centralized configuration
- Enhanced logging system
- Complete documentation suite

### Changed
- Replaced string-based JSON parsing with RapidJSON
- Improved SSL certificate validation (removed bypass)
- Enhanced error handling and validation

### Security
- Enabled SSL certificate validation
- Added input validation and sanitization
- Implemented rate limiting
- Secure memory handling for passwords

## [1.0.0] - 2025-11-01

### Added
- Initial working prototype
- Two-step OTP authentication
- Authentik API integration
- Windows domain authentication support

### Known Issues
- SSL certificate validation disabled (FIXED in v2.0)
- No rate limiting (FIXED in v2.0)
- Basic JSON parsing (FIXED in v2.0)
"@

$changelogPath = Join-Path $RepositoryPath "CHANGELOG.md"
$changelogContent | Out-File -FilePath $changelogPath -Encoding UTF8
Write-Host "  ✓ Created CHANGELOG.md" -ForegroundColor Green

# Create .gitignore if it doesn't exist
$gitignorePath = Join-Path $RepositoryPath ".gitignore"
if (-not (Test-Path $gitignorePath)) {
    $gitignoreContent = @"
# Visual Studio
.vs/
*.user
*.suo
*.userosscache
*.sln.docstates

# Build results
[Dd]ebug/
[Dd]ebugPublic/
[Rr]elease/
[Rr]eleases/
x64/
x86/
[Ww]in32/
[Aa]rm/
[Aa]rm64/
bld/
[Bb]in/
[Oo]bj/
[Ll]og/
[Ll]ogs/

# Compiled DLLs
*.dll
*.exe
*.pdb
*.ilk
*.obj
*.lib

# Sensitive data
*.pfx
*.snk
secrets.json
appsettings.local.json

# IDE
.vscode/
.idea/

# OS
Thumbs.db
.DS_Store

# Test results
TestResults/
*.trx
*.coverage
"@
    
    $gitignoreContent | Out-File -FilePath $gitignorePath -Encoding UTF8
    Write-Host "  ✓ Created .gitignore" -ForegroundColor Green
}

# Initialize Git repository if not skipped
Write-Host ""
Write-Host "[6/8] Initializing Git repository..." -ForegroundColor Yellow

if (-not $SkipGitInit) {
    if (-not (Test-Path (Join-Path $RepositoryPath ".git"))) {
        git init
        Write-Host "  ✓ Git repository initialized" -ForegroundColor Green
        
        # Set remote
        $remoteUrl = "https://github.com/$GitHubUsername/$RepositoryName.git"
        git remote add origin $remoteUrl
        Write-Host "  ✓ Added remote: $remoteUrl" -ForegroundColor Green
    }
    else {
        Write-Host "  ℹ Git repository already initialized" -ForegroundColor Cyan
    }
}
else {
    Write-Host "  ℹ Skipped Git initialization" -ForegroundColor Cyan
}

# Stage all files
Write-Host ""
Write-Host "[7/8] Staging files..." -ForegroundColor Yellow

git add .
$stagedFiles = git diff --cached --name-only | Measure-Object -Line
Write-Host "  ✓ Staged $($stagedFiles.Lines) files" -ForegroundColor Green

# Create initial commit
Write-Host ""
Write-Host "[8/8] Creating initial commit..." -ForegroundColor Yellow

$commitMessage = @"
Initial commit: Windows Credential Provider with Authentik integration

- Added complete source code for credential provider
- Added improved API client with security fixes
- Added SecureString, RateLimiter, ConfigurationManager
- Added comprehensive documentation
- Added project structure and configuration
- Includes KNOWLEDGE_BASE, implementation guide, and analysis

Project ready for collaborative development with Claude AI.
"@

git commit -m $commitMessage
Write-Host "  ✓ Initial commit created" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repository Location: $RepositoryPath" -ForegroundColor White
Write-Host "Remote URL: https://github.com/$GitHubUsername/$RepositoryName.git" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Create repository on GitHub.com" -ForegroundColor White
Write-Host "  2. Push to GitHub:" -ForegroundColor White
Write-Host "     cd $RepositoryPath" -ForegroundColor Cyan
Write-Host "     git push -u origin main" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. Generate Personal Access Token:" -ForegroundColor White
Write-Host "     GitHub → Settings → Developer settings → Personal access tokens" -ForegroundColor Cyan
Write-Host "     Select scopes: repo (all), workflow" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. Share with Claude:" -ForegroundColor White
Write-Host "     - Repository URL" -ForegroundColor Cyan
Write-Host "     - Personal Access Token" -ForegroundColor Cyan
Write-Host ""
Write-Host "  5. Open in Visual Studio:" -ForegroundColor White
Write-Host "     File → Open → Project/Solution" -ForegroundColor Cyan
Write-Host "     Open: $RepositoryPath\src\AuthentikCredentialProvider.sln" -ForegroundColor Cyan
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Yellow
Write-Host "  - Executive Summary: docs\EXECUTIVE_SUMMARY.md" -ForegroundColor White
Write-Host "  - Implementation Guide: docs\development\IMPLEMENTATION_GUIDE.md" -ForegroundColor White
Write-Host "  - GitHub Setup Guide: See GITHUB_SETUP_GUIDE.md" -ForegroundColor White
Write-Host ""
Write-Host "Ready to start development! 🚀" -ForegroundColor Green
Write-Host ""
