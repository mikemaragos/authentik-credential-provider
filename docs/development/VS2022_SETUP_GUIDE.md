# Visual Studio 2022 - Complete Setup & Workflow Guide

**Project:** Authentik Credential Provider  
**Repository:** https://github.com/mikemaragos/authentik-credential-provider  
**Last Updated:** November 23, 2025

---

## 🎯 Goal

Set up Visual Studio 2022 to:
- ✅ Clone and open the project from GitHub
- ✅ Build and compile the DLL
- ✅ Debug the credential provider
- ✅ Make changes and commit back to GitHub
- ✅ Work collaboratively with Claude

---

## Part 1: Initial Setup (One-Time)

### Step 1: Install Prerequisites

**Required:**
- ✅ Visual Studio 2022 (Community, Professional, or Enterprise)
- ✅ Workload: "Desktop development with C++"
- ✅ Windows SDK 10.0.19041.0 or later
- ✅ Git for Windows

**Check Installation:**
```powershell
# Check Visual Studio
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" /?

# Check Git
git --version
```

### Step 2: Clone Repository in Visual Studio

**Method A: From Start Window (Easiest)**

1. **Launch Visual Studio 2022**
2. Click **"Clone a repository"**
3. **Repository location:**
   ```
   https://github.com/mikemaragos/authentik-credential-provider.git
   ```
4. **Local path:**
   ```
   C:\Projects\authentik-credential-provider
   ```
   *(Or choose your preferred location)*
5. Click **"Clone"**
6. Wait for cloning to complete (shows in Output window)

**Method B: From Menu**

1. **File** → **Clone Repository**
2. Enter URL and path as above
3. Click **"Clone"**

**Method C: Command Line First, Then Open**

```bash
cd C:\Projects
git clone https://github.com/mikemaragos/authentik-credential-provider.git
cd authentik-credential-provider
start src\AuthentikCredentialProvider.sln
```

### Step 3: Open the Solution

Once cloned:

1. Visual Studio should detect the solution automatically
2. Look for `src/AuthentikCredentialProvider.sln` in Solution Explorer
3. **Double-click** to open

**OR manually:**

1. **File** → **Open** → **Project/Solution**
2. Navigate to `C:\Projects\authentik-credential-provider\src\`
3. Select **AuthentikCredentialProvider.sln**
4. Click **"Open"**

### Step 4: Configure Build Settings

1. At the top toolbar, select:
   - **Configuration:** `Debug` (for development) or `Release` (for testing)
   - **Platform:** `x64` (IMPORTANT - must be x64!)

2. Verify in **Solution Explorer**:
   - Right-click solution → **Properties**
   - Configuration Properties → Configuration
   - Ensure Platform is **x64** for all configurations

---

## Part 2: Building the Project

### First Build

1. **Build** → **Build Solution** (or press `Ctrl+Shift+B`)
2. Watch the **Output** window for progress
3. Look for: `========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========`

**Expected Output Location:**
- Debug: `src\x64\Debug\AuthentikCredentialProvider.dll`
- Release: `src\x64\Release\AuthentikCredentialProvider.dll`

### Common Build Issues & Solutions

**Issue 1: "Cannot find Windows SDK"**
```
Solution:
1. Tools → Get Tools and Features
2. Select "Desktop development with C++"
3. On right side, check "Windows 10 SDK (10.0.19041.0)" or later
4. Click "Modify"
```

**Issue 2: "Platform x64 not found"**
```
Solution:
1. Build → Configuration Manager
2. Active solution platform → New → x64
3. Copy settings from: Any CPU
4. Click OK
```

**Issue 3: "Cannot open include file"**
```
Solution:
1. Right-click project → Properties
2. C/C++ → General → Additional Include Directories
3. Ensure $(ProjectDir) is included
4. Apply and rebuild
```

**Issue 4: "Unresolved external symbol"**
```
Solution:
1. Right-click project → Properties
2. Linker → Input → Additional Dependencies
3. Verify these are listed:
   Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib;Crypt32.lib;Credui.lib
4. Apply and rebuild
```

---

## Part 3: Testing the DLL

### Method 1: Manual Installation (for testing)

```powershell
# Run PowerShell as Administrator

# 1. Copy DLL to System32
Copy-Item "C:\Projects\authentik-credential-provider\src\x64\Debug\AuthentikCredentialProvider.dll" `
          "C:\Windows\System32\" -Force

# 2. Register the DLL
regsvr32 "C:\Windows\System32\AuthentikCredentialProvider.dll"

# You should see: "DllRegisterServer in AuthentikCredentialProvider.dll succeeded."

# 3. Configure registry (if not already done)
# See QUICKSTART.md for registry settings

# 4. Reboot
shutdown /r /t 0
```

### Method 2: Using DebugView (for logging)

1. **Download DebugView:**
   https://docs.microsoft.com/en-us/sysinternals/downloads/debugview

2. **Run as Administrator**

3. **Configure:**
   - Capture → Capture Win32
   - Capture → Capture Global Win32
   - Edit → Filter/Highlight → Add filter: `AuthentikCP*`

4. **Lock screen** (Win+L)

5. **Watch for logs:**
   ```
   [AuthentikCP] Constructor
   [AuthentikCP] SetUsageScenario
   [AuthentikCP] GetFieldDescriptorCount
   ...
   ```

---

## Part 4: Debugging in Visual Studio

### Setup Debugging

**IMPORTANT:** You cannot debug a credential provider in the normal way because it runs in LogonUI.exe (a protected process).

**Option A: Debug via Logs (Recommended)**

1. Build in **Debug** configuration
2. Add more `LOG()` statements where needed
3. Use **DebugView** to see logs in real-time
4. Example:
   ```cpp
   LOG("Entering InitiateAuthentication, username=%S", username.c_str());
   LOG("HTTP Status Code: %d", statusCode);
   LOG("Response body length: %zu", responseBody.length());
   ```

**Option B: Attach to Process (Advanced)**

⚠️ **Requires special setup:**

1. Disable Secure Boot (BIOS/UEFI setting)
2. Enable kernel debugging
3. Run Visual Studio as Administrator
4. **Debug** → **Attach to Process**
5. Check "Show processes from all users"
6. Find **LogonUI.exe**
7. Attach

**Option C: Test Harness (Best for development)**

Create a separate test project that loads and calls your DLL:

```cpp
// TestHarness.cpp
#include <windows.h>
#include <iostream>

int main() {
    // Load the DLL
    HMODULE hDll = LoadLibrary(L"AuthentikCredentialProvider.dll");
    
    // Test DllGetClassObject, etc.
    // Call your functions directly
    
    FreeLibrary(hDll);
    return 0;
}
```

---

## Part 5: Making Changes & Committing

### Your Workflow (Without Claude)

1. **Make changes** in Visual Studio
2. **Build** to verify (Ctrl+Shift+B)
3. **Test** the changes

4. **Commit via Visual Studio:**
   - View → **Team Explorer**
   - Click **"Changes"**
   - See your modified files
   - Enter commit message
   - Click **"Commit All"**

5. **Push to GitHub:**
   - Team Explorer → **"Sync"**
   - Click **"Push"**

### Workflow with Claude

**Scenario 1: You want Claude to make changes**

1. **Tell Claude what you need:**
   ```
   "Claude, please add input validation to the username field in AuthentikCredential.cpp"
   ```

2. **Claude updates the file on GitHub** via API

3. **Pull the changes in Visual Studio:**
   - Team Explorer → **Sync** → **Pull**
   - Or: Right-click solution → **Git** → **Pull**

4. **Build and test** the changes

5. **Provide feedback:**
   ```
   "That works great!"
   or
   "There's a bug with empty usernames, can you fix it?"
   ```

**Scenario 2: You make changes, ask Claude for review**

1. **Make your changes** in Visual Studio
2. **Commit and push** to GitHub
3. **Tell Claude:**
   ```
   "I just pushed changes to add timeout handling. Can you review?"
   ```
4. **Claude reviews** the changes on GitHub
5. **Claude provides feedback** or suggestions

**Scenario 3: Debugging together**

1. **You encounter an issue:**
   ```
   "Claude, I'm getting error 0x80070057 when packing credentials"
   ```

2. **Share relevant code or logs:**
   ```
   // Paste the error from DebugView or
   // Tell Claude which file/function is failing
   ```

3. **Claude investigates:**
   - Reviews the relevant code
   - Suggests fixes
   - Can update the code directly

4. **You test the fix:**
   - Pull changes
   - Rebuild
   - Test

5. **Iterate until fixed**

---

## Part 6: Best Practices

### Before Each Work Session

```bash
# 1. Pull latest changes
git pull origin main

# 2. Check what changed
git log -5 --oneline

# 3. Build to ensure it compiles
# Build → Build Solution
```

### During Development

- ✅ Build frequently (after small changes)
- ✅ Use descriptive commit messages
- ✅ Test each change before committing
- ✅ Use DEBUG builds for development
- ✅ Use RELEASE builds for final testing
- ✅ Keep DebugView running for logs

### After Making Changes

```bash
# 1. Build successfully
# Build → Build Solution → No errors

# 2. Test the changes
# Install DLL, test on lock screen

# 3. Commit with clear message
# Team Explorer → Changes → Commit

# 4. Push to GitHub
# Team Explorer → Sync → Push
```

---

## Part 7: Common Development Tasks

### Task: Add a new source file

1. **Right-click** `Source Files` in Solution Explorer
2. **Add** → **New Item**
3. Choose **C++ File (.cpp)** or **Header File (.h)**
4. Name it (e.g., `BiometricAuth.cpp`)
5. Click **Add**
6. **File automatically added** to project
7. **Commit** the change

### Task: Change build configuration

1. **Build** → **Configuration Manager**
2. Select configuration (Debug/Release)
3. Verify platform is **x64**
4. Click **Close**
5. Rebuild: **Build** → **Rebuild Solution**

### Task: View compiler output

1. **View** → **Output** (Ctrl+Alt+O)
2. Select "Build" from dropdown
3. See detailed build logs

### Task: Clean build (fresh compile)

1. **Build** → **Clean Solution**
2. Deletes all compiled files
3. **Build** → **Rebuild Solution**
4. Compiles everything from scratch

---

## Part 8: Git Integration in Visual Studio

### View Git History

1. **View** → **Team Explorer**
2. Click **"Branches"** or **"Sync"**
3. View **"Outgoing Commits"** / **"Incoming Commits"**

### Create a Branch

1. Team Explorer → **Branches**
2. Right-click **main** → **New Local Branch From...**
3. Name: `feature/my-feature`
4. Click **Create Branch**
5. Make changes on this branch
6. Merge back when done

### Resolve Merge Conflicts

1. When pulling, if conflicts occur:
2. Team Explorer → **Conflicts**
3. For each conflict:
   - **Compare** to see differences
   - **Take Source** (your version) or **Take Target** (GitHub version)
   - Or **Merge** manually
4. After resolving all → **Commit Merge**

---

## Part 9: Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Build Solution | `Ctrl+Shift+B` |
| Rebuild Solution | `Ctrl+Alt+F7` |
| Start Debugging | `F5` |
| Build Current Project | `Ctrl+B` |
| Go to Definition | `F12` |
| Find in Files | `Ctrl+Shift+F` |
| Comment Selection | `Ctrl+K, Ctrl+C` |
| Uncomment Selection | `Ctrl+K, Ctrl+U` |
| Format Document | `Ctrl+K, Ctrl+D` |
| Team Explorer | `Ctrl+0, Ctrl+M` |

---

## Part 10: Troubleshooting

### "Solution fails to load"

```
1. Close Visual Studio
2. Delete .vs folder in solution directory
3. Reopen Visual Studio
4. File → Open → Project/Solution
```

### "Git authentication failed"

```
1. Tools → Options → Source Control → Git Global Settings
2. Set credential helper
3. Or use Git Credential Manager
```

### "Cannot register DLL - Access Denied"

```
Run PowerShell or Command Prompt as Administrator
```

### "Changes not showing in Team Explorer"

```
1. Team Explorer → Changes → Refresh
2. Or close and reopen Team Explorer
```

---

## Part 11: Development Workflow Diagram

```
┌─────────────────────────────────────────────────┐
│ 1. PULL LATEST CODE                             │
│    Team Explorer → Sync → Pull                  │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 2. MAKE CHANGES                                 │
│    Edit files in Solution Explorer              │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 3. BUILD                                        │
│    Ctrl+Shift+B                                 │
│    Fix any errors                               │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 4. TEST                                         │
│    Copy DLL, register, test on lock screen      │
│    Check DebugView for logs                     │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 5. COMMIT                                       │
│    Team Explorer → Changes                      │
│    Enter message → Commit All                   │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 6. PUSH                                         │
│    Team Explorer → Sync → Push                  │
└──────────────┬──────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────┐
│ 7. COLLABORATE WITH CLAUDE                      │
│    Tell Claude about changes                    │
│    Claude can review/suggest improvements       │
│    Claude can update code directly              │
└─────────────────────────────────────────────────┘
```

---

## Part 12: Quick Reference Commands

### PowerShell (Run as Admin)

```powershell
# Install DLL for testing
Copy-Item "src\x64\Debug\AuthentikCredentialProvider.dll" "C:\Windows\System32\" -Force
regsvr32 "C:\Windows\System32\AuthentikCredentialProvider.dll"

# Uninstall DLL
regsvr32 /u "C:\Windows\System32\AuthentikCredentialProvider.dll"
Remove-Item "C:\Windows\System32\AuthentikCredentialProvider.dll" -Force

# Configure registry
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerUrl" -Value "authentik.test.local"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "FlowSlug" -Value "windows-otp-auth"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "UseHttps" -Value 1 -Type DWord
```

---

## 🎯 YOU'RE READY!

You now have:
- ✅ Complete Visual Studio 2022 setup
- ✅ Project cloned from GitHub
- ✅ Ability to build and test
- ✅ Git integration working
- ✅ Collaborative workflow with Claude
- ✅ Debugging strategies
- ✅ Best practices guide

---

## 📞 Need Help?

**Common Questions:**

"**VS can't find the solution**" → Make sure you cloned to the right path, solution is at `src/AuthentikCredentialProvider.sln`

"**Build fails with errors**" → Check Part 2 "Common Build Issues"

"**Can't test the DLL**" → See Part 3 for installation steps

"**Git not working**" → Check Part 8 for Git integration help

"**Want Claude to help**" → Just ask! Tell me what you need

---

**Ready to start development!** 🚀

Open Visual Studio, clone the repo, and let's build something great together!
