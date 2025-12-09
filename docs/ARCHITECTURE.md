# System Architecture

## Overview

The Authentik Credential Provider enables passwordless Windows domain authentication by combining:
- **Authentik** for OTP validation
- **AD Certificate Services** for certificate issuance
- **Virtual Smart Card** for certificate storage
- **PKINIT** for Kerberos authentication

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WORKSTATION                                  │
│  ┌─────────────────────┐     ┌─────────────────────────────────┐   │
│  │ Credential Provider │     │ Virtual Smart Card (TPM)         │   │
│  │ (AuthentikCP.dll)   │────▶│ - Stores certificate             │   │
│  │                     │     │ - PIN protected                  │   │
│  │ 1. Collect OTP      │     │ - Crypto operations              │   │
│  │ 2. Request cert     │     └──────────────┬──────────────────┘   │
│  │ 3. Import to VSC    │                    │                       │
│  │ 4. Submit to LSA    │                    │ PKINIT AS-REQ         │
│  └──────────┬──────────┘                    │                       │
│             │                               ▼                       │
└─────────────┼───────────────────────────────┼───────────────────────┘
              │ HTTPS (8443)                  │ Kerberos (88)
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      DOMAIN CONTROLLER                               │
│  ┌─────────────────────┐     ┌─────────────────────────────────┐   │
│  │ CertIssuer Service  │     │ KDC (Kerberos)                   │   │
│  │                     │     │                                   │   │
│  │ 1. Validate OTP     │     │ 1. Validate certificate          │   │
│  │    (via Authentik)  │     │ 2. Map to AD account             │   │
│  │ 2. Generate cert    │     │ 3. Issue TGT                     │   │
│  │    (via AD CS)      │     │                                   │   │
│  │ 3. Return PFX       │     └─────────────────────────────────┘   │
│  └──────────┬──────────┘                                            │
│             │                                                        │
└─────────────┼────────────────────────────────────────────────────────┘
              │ HTTPS
              ▼
┌─────────────────────────┐
│      AUTHENTIK          │
│                         │
│ - User database         │
│ - OTP validation        │
│ - TOTP/Push/SMS         │
└─────────────────────────┘
```

## Authentication Flow

```
User                CP                CertIssuer           KDC
 │                  │                     │                 │
 │─── Username ────▶│                     │                 │
 │─── OTP Code ────▶│                     │                 │
 │                  │                     │                 │
 │                  │── Validate OTP ────▶│                 │
 │                  │   + Request Cert    │                 │
 │                  │                     │                 │
 │                  │◀── PFX Certificate ─│                 │
 │                  │                     │                 │
 │                  │── Import to VSC     │                 │
 │                  │                     │                 │
 │                  │── PKINIT AS-REQ ───────────────────▶│
 │                  │   (Certificate)     │                 │
 │                  │                     │                 │
 │                  │◀── TGT ─────────────────────────────│
 │                  │                     │                 │
 │◀── Logged In ───│                     │                 │
```

## Key Components

### Credential Provider (phase2/)
- **AuthentikCredential.cpp** - UI tile, handles user input
- **AuthentikAPI.cpp** - HTTPS client for CertIssuer
- **VSCManager.cpp** - Virtual Smart Card operations
- **CredentialPacking.cpp** - KERB_CERTIFICATE_LOGON serialization

### CertIssuer Service (certissuer/)
- Python Flask API running on DC
- Validates OTP with Authentik
- Requests certificate from AD CS
- Returns PFX to credential provider

### Virtual Smart Card
- TPM-backed certificate storage
- Created via `tpmvscmgr.exe`
- PIN: Default `12345678`
- Reader: `Microsoft Virtual Smart Card 0`

## Security Model

1. **No password transmitted** - Only OTP code sent to Authentik
2. **Short-lived certificates** - Issued per-login, expire quickly
3. **TPM protection** - Private key never leaves TPM
4. **PKINIT** - Industry-standard smart card authentication
