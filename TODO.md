# Authentik Credential Provider - TODO List

## Current Sprint: UI Polish & Service Robustness

### 1. ✅ Logo/Branding Update
- [ ] Create Authentik-style logo (geometric design, coral/orange #FD4B2D)
- [ ] Update credential provider tile icon
- [ ] Update Windows logon screen branding
- [ ] Create multiple sizes (16x16, 32x32, 48x48, 256x256)

### 2. ✅ Certificate Issuer Windows Service
- [ ] Convert PowerShell script to proper Windows Service
- [ ] Implement auto-start on boot
- [ ] Add Windows Event Log integration
- [ ] Create service installer (MSI)
- [ ] Add service management UI
- [ ] Implement health monitoring
- [ ] Add certificate rotation/cleanup

### 3. 🔄 In Progress
- [x] PKINIT Smart Card authentication working
- [x] Certificate template with UPN in SAN
- [x] Basic credential provider flow
- [x] PowerShell diagnostic tools

### 4. 📋 Backlog
- [ ] Authentik flow configuration guide
- [ ] Offline authentication support
- [ ] Certificate renewal automation
- [ ] Multi-domain support
- [ ] Group Policy templates
- [ ] MSI installer for credential provider
- [ ] Comprehensive logging to Event Viewer

---

## Technical Details

### Logo Requirements
- Primary color: #FD4B2D (Authentik coral/orange)
- Secondary: #1A1A2E (dark background compatible)
- Format: ICO file with multiple sizes
- Style: Geometric/modern matching Authentik brand

### Service Requirements
- Run as LocalSystem or dedicated service account
- Listen on configurable port (default 8443)
- HTTPS with certificate
- Windows Event Log for audit trail
- Automatic certificate cleanup (configurable retention)
- Health endpoint for monitoring
- Graceful shutdown handling

---

Last Updated: November 30, 2025
