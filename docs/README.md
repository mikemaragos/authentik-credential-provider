# Documentation Index

**Authentik Credential Provider for Windows - Complete Documentation**

---

## 📚 Documentation Overview

This project includes comprehensive documentation for installation, configuration, testing, and troubleshooting.

---

## 🚀 Getting Started (Read These First)

### 1. [QUICK_INSTALL.md](QUICK_INSTALL.md)
**5-minute installation reference card**
- Quick copy-paste commands
- Minimal explanations
- Perfect for experienced admins

**Start here if:** You know Windows credential providers and just need the commands.

---

### 2. [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md)
**Pre-deployment checklist**
- System requirements
- Visual C++ Redistributable (CRITICAL!)
- Network requirements
- Testing procedures
- Backup and recovery

**Start here if:** You're planning a production deployment.

---

## 🔧 Installation & Configuration

### 3. [INSTALLATION.md](INSTALLATION.md)
**Complete installation guide**
- Step-by-step installation
- VC++ Redistributable installation
- Registry configuration
- Troubleshooting common issues
- Uninstallation procedure

**Use this for:** First-time installation or detailed guidance.

---

### 4. [CONFIGURATION.md](CONFIGURATION.md)
**Registry settings reference**
- Complete registry settings documentation
- ServerUrl, ServerPort, FlowSlug, UseHttps
- IgnoreSslErrors setting (for self-signed certs)
- Production vs Development examples
- PowerShell configuration templates
- Security best practices

**Use this for:** Understanding and configuring registry settings.

---

### 5. [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) ⭐ **NEW!**
**Complete Authentik server configuration**
- LDAP/Active Directory source setup
- OTP/MFA configuration
- Authentication flow creation
- Flow testing procedures
- User OTP enrollment
- API endpoint testing
- Troubleshooting Authentik issues

**Use this for:** Setting up the Authentik server side.

---

## 🧪 Testing & Debugging

### 6. [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md)
**Testing Authentik API connectivity**
- PowerShell testing tools
- Quick-Test-Auth.ps1 usage
- Test-AuthentikAPI.ps1 usage
- Understanding API responses
- Common issues and solutions
- Debugging checklist

**Use this for:** Diagnosing authentication failures and API issues.

---

### 7. Testing Tools (in `/tools` directory)

#### [Quick-Test-Auth.ps1](../tools/Quick-Test-Auth.ps1)
Interactive test script that mimics the DLL's API calls.
```powershell
.\Quick-Test-Auth.ps1
# Prompts for username, password, OTP
```

#### [Test-AuthentikAPI.ps1](../tools/Test-AuthentikAPI.ps1)
Comprehensive diagnostic tool for API testing.
```powershell
.\Test-AuthentikAPI.ps1 -Username "test" -Password "pass"
```

---

## 📖 General Information

### 8. [README.md](../README.md)
**Project overview**
- What this project does
- Architecture overview
- Building from source
- Quick start
- Known limitations

**Use this for:** Understanding what the project is about.

---

### 9. [KNOWLEDGE_BASE.md](../KNOWLEDGE_BASE.md)
**Complete project knowledge base**
- Critical success factors
- Architecture decisions
- Known issues and solutions
- Lessons learned
- Future enhancements

**Use this for:** Deep technical understanding and project history.

---

## 📋 Quick Reference Guide

### **I want to...**

| Task | Read This |
|------|-----------|
| Install the credential provider quickly | [QUICK_INSTALL.md](QUICK_INSTALL.md) |
| Plan a production deployment | [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md) |
| Do a first-time installation | [INSTALLATION.md](INSTALLATION.md) |
| Configure registry settings | [CONFIGURATION.md](CONFIGURATION.md) |
| Set up Authentik server | [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) ⭐ |
| Test if Authentik is working | [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md) |
| Troubleshoot authentication failures | [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md) + [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) |
| Fix "module could not be found" | [INSTALLATION.md](INSTALLATION.md) → VC++ Redistributable |
| Use self-signed SSL certificate | [CONFIGURATION.md](CONFIGURATION.md) → IgnoreSslErrors |
| Build from source | [README.md](../README.md) + VS2022_SETUP_GUIDE.md |
| Understand the architecture | [README.md](../README.md) + [KNOWLEDGE_BASE.md](../KNOWLEDGE_BASE.md) |

---

## 🔄 Typical Workflow

### **For First-Time Setup:**

1. **Read:** [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md)
   - Check system requirements
   - Install VC++ Redistributable

2. **Read:** [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md)
   - Configure Authentik server
   - Create authentication flow
   - Test flow in web browser

3. **Read:** [INSTALLATION.md](INSTALLATION.md)
   - Install credential provider DLL
   - Configure registry

4. **Read:** [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md)
   - Test API connectivity
   - Verify authentication works

5. **Test:** Lock screen and try logging in!

---

### **For Troubleshooting:**

**Issue: Can't register DLL (regsvr32 fails)**
→ [INSTALLATION.md](INSTALLATION.md) → Install VC++ Redistributable

**Issue: Tile doesn't appear on lock screen**
→ [INSTALLATION.md](INSTALLATION.md) → Check registration, reboot

**Issue: Authentication fails**
→ [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md) → Test API
→ [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) → Check flow configuration

**Issue: SSL/certificate errors**
→ [CONFIGURATION.md](CONFIGURATION.md) → Set IgnoreSslErrors=1 (testing only)
→ [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) → Fix SSL on Authentik

**Issue: "Page not found" for flow**
→ [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) → Verify flow exists and slug is correct

**Issue: OTP not working**
→ [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) → Check OTP enrollment and time sync

---

## 🎯 Documentation by Role

### **Windows Administrator**
You need to install and configure the credential provider on Windows machines.

**Read in this order:**
1. [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md)
2. [INSTALLATION.md](INSTALLATION.md)
3. [CONFIGURATION.md](CONFIGURATION.md)
4. [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md)

---

### **Authentik Administrator**
You need to configure the Authentik server to work with Windows clients.

**Read in this order:**
1. [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) ⭐
2. [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md)
3. [CONFIGURATION.md](CONFIGURATION.md) (to understand Windows side)

---

### **Developer**
You want to build, modify, or understand the code.

**Read in this order:**
1. [README.md](../README.md)
2. [KNOWLEDGE_BASE.md](../KNOWLEDGE_BASE.md)
3. development/VS2022_SETUP_GUIDE.md
4. Source code comments

---

### **End User**
You need to use the credential provider to log in.

**You don't need to read anything!** Just:
1. Enroll your OTP device (via Authentik web UI)
2. At Windows login, enter username + password
3. When prompted, enter your OTP code

---

## 📊 Documentation Status

| Document | Status | Last Updated |
|----------|--------|--------------|
| README.md | ✅ Complete | Nov 2025 |
| QUICK_INSTALL.md | ✅ Complete | Nov 23, 2025 |
| INSTALLATION.md | ✅ Complete | Nov 23, 2025 |
| CONFIGURATION.md | ✅ Complete | Nov 23, 2025 |
| DEPLOYMENT_PREREQUISITES.md | ✅ Complete | Nov 23, 2025 |
| AUTHENTIK_SETUP_GUIDE.md | ✅ Complete | Nov 23, 2025 |
| API_TESTING_GUIDE.md | ✅ Complete | Nov 23, 2025 |
| KNOWLEDGE_BASE.md | ✅ Complete | Nov 2025 |

---

## 🆘 Still Need Help?

### **Before Asking for Help:**

Run through this checklist:

1. **VC++ Redistributable installed?**
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
   ```

2. **Registry configured?**
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\AuthentikCredentialProvider"
   ```

3. **Authentik flow created?**
   - Check slug matches registry

4. **API test succeeds?**
   ```powershell
   .\Quick-Test-Auth.ps1
   ```

5. **DebugView running?**
   - Capture logs during login attempt

### **When Asking for Help:**

Provide:
- Windows version
- Authentik version
- PowerShell test output
- DebugView logs
- Registry configuration
- Authentik flow configuration

### **Resources:**

- **GitHub Issues:** https://github.com/mikemaragos/authentik-credential-provider/issues
- **Authentik Docs:** https://goauthentik.io/docs/
- **Authentik Discord:** https://goauthentik.io/discord

---

## 📦 File Locations

All documentation is available in:
- **GitHub:** `docs/` directory
- **Local Build:** Project root and `docs/` folder

---

## 🔄 Documentation Updates

This documentation is actively maintained. Check the GitHub repository for the latest versions:

```
https://github.com/mikemaragos/authentik-credential-provider/tree/main/docs
```

---

**Last Updated:** November 23, 2025  
**Documentation Version:** 2.0

---

## 🎉 Quick Start Paths

Choose your path:

**Path 1: "Just Make It Work" (Quick & Dirty)**
1. [QUICK_INSTALL.md](QUICK_INSTALL.md) (Windows side)
2. [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md) (Authentik side)
3. Set IgnoreSslErrors=1 if using self-signed cert
4. Test!

**Path 2: "Production Ready" (Proper Setup)**
1. [DEPLOYMENT_PREREQUISITES.md](DEPLOYMENT_PREREQUISITES.md)
2. [AUTHENTIK_SETUP_GUIDE.md](AUTHENTIK_SETUP_GUIDE.md)
3. [INSTALLATION.md](INSTALLATION.md)
4. [CONFIGURATION.md](CONFIGURATION.md)
5. [API_TESTING_GUIDE.md](API_TESTING_GUIDE.md)
6. Deploy with proper SSL, testing, monitoring

**Path 3: "I'm a Developer" (Deep Dive)**
1. [README.md](../README.md)
2. [KNOWLEDGE_BASE.md](../KNOWLEDGE_BASE.md)
3. Build from source
4. Read all the other docs
5. Modify and contribute!

---

**Happy authenticating! 🚀**
