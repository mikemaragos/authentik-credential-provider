# Contributing to Authentik Credential Provider

Thank you for your interest in contributing to the Authentik Credential Provider project!

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/authentik-credential-provider.git
   cd authentik-credential-provider
   ```
3. **Create a feature branch**: 
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Make your changes**
5. **Test thoroughly**
6. **Commit with clear messages**
7. **Push to your fork**
8. **Create a Pull Request**

## 📋 Development Setup

### Prerequisites
- Visual Studio 2019 or 2022
- Windows SDK 10.0.19041.0 or later
- Git

### Building
```bash
# Open in Visual Studio
start src/AuthentikCredentialProvider.sln

# Or build from command line
msbuild src/AuthentikCredentialProvider.sln /p:Configuration=Release /p:Platform=x64
```

## 💻 Code Style

### C++ Guidelines
- Follow Microsoft C++ coding conventions
- Use meaningful variable names (no single letters except loop counters)
- Add comments for complex logic
- Document all public APIs with XML-style comments
- Use RAII for resource management
- Prefer const correctness
- Use smart pointers when appropriate

### Example
```cpp
/// @brief Validates user credentials with Authentik server
/// @param username User's domain username (e.g., "john.doe")
/// @param password User's password
/// @return AuthentikResponse containing validation result
/// @throws std::invalid_argument if username is empty
AuthentikResponse ValidateCredentials(
    const std::wstring& username,
    const SecureString& password);
```

### Naming Conventions
- Classes: `PascalCase` (e.g., `AuthentikAPI`)
- Functions: `PascalCase` (e.g., `InitiateAuthentication`)
- Variables: `camelCase` (e.g., `serverUrl`)
- Constants: `UPPER_CASE` (e.g., `MAX_RETRIES`)
- Private members: `_camelCase` (e.g., `_serverUrl`)

## 🧪 Testing

### Unit Tests
- Write unit tests for all new functionality
- Ensure all existing tests pass
- Test both success and failure paths
- Achieve >80% code coverage

```bash
# Run all tests
dotnet test tests/AuthentikCredentialProvider.Tests/

# Run with coverage
dotnet test /p:CollectCoverage=true
```

### Manual Testing
1. Build in Debug mode
2. Copy DLL to System32 and register
3. Run DebugView as Administrator
4. Test authentication flow
5. Verify logs in DebugView

### Test Checklist
- [ ] Compiles without warnings
- [ ] All unit tests pass
- [ ] Manual testing completed
- [ ] No memory leaks (verified with Application Verifier)
- [ ] Works on Windows 10 and 11
- [ ] Documentation updated

## 🔒 Security

### Security Guidelines
- **Never commit sensitive data** (passwords, keys, tokens, certificates)
- Follow secure coding practices (OWASP guidelines)
- Use `SecureString` for all sensitive data
- Validate all user inputs
- Use RAII for proper cleanup
- Report security vulnerabilities privately (see SECURITY.md)

### Security Checklist
- [ ] Input validation implemented
- [ ] No SQL/JSON injection vulnerabilities
- [ ] Sensitive data securely handled
- [ ] No hardcoded credentials
- [ ] SSL/TLS properly configured
- [ ] Rate limiting in place

## 📝 Commit Messages

### Format
```
<type>: <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting (no logic changes)
- `refactor`: Code restructuring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

### Examples

**Good:**
```
feat: Add biometric authentication support

- Implements Windows Hello integration
- Adds fingerprint and face recognition
- Includes fallback to OTP if biometric fails

Closes #123
```

**Bad:**
```
Updated stuff
```

## 🔄 Pull Request Process

1. **Update documentation** if you've changed APIs or added features
2. **Add/update tests** for new functionality
3. **Update CHANGELOG.md** under "Unreleased"
4. **Ensure CI/CD passes** (all tests, builds succeed)
5. **Request review** from maintainers
6. **Address feedback** promptly

### PR Template
Your PR should include:
- Clear description of changes
- Why the change is needed
- How you tested it
- Screenshots (if UI changes)
- Breaking changes noted

## 📚 Documentation

### What to Document
- Public APIs (with XML comments)
- Complex algorithms
- Configuration options
- Installation procedures
- Troubleshooting steps

### Documentation Style
- Clear and concise
- Include examples
- Use proper markdown formatting
- Keep language simple

## 🐛 Bug Reports

### Good Bug Reports Include:
- Clear title
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (Windows version, etc.)
- Logs (from DebugView)
- Screenshots (if applicable)

### Template
```markdown
**Environment:**
- Windows Version: 11 22H2
- Credential Provider Version: 2.0
- Authentik Version: 2024.x

**Steps to Reproduce:**
1. Step one
2. Step two
3. ...

**Expected:**
User should be authenticated successfully

**Actual:**
Authentication fails with error XYZ

**Logs:**
[Paste DebugView logs here]
```

## 💡 Feature Requests

### Good Feature Requests Include:
- Clear use case
- Why it's needed
- Proposed solution (optional)
- Alternatives considered

## 🎯 Development Priorities

Current focus areas:
1. **Phase 2**: Quality improvements (JSON parsing, logging, tests)
2. **Phase 3**: Enterprise features (MSI installer, Group Policy)
3. **Phase 4**: Advanced features (PKINIT, offline OTP)

See [Implementation Guide](docs/development/IMPLEMENTATION_GUIDE.md) for details.

## ❓ Questions?

- Check existing [Issues](https://github.com/mikemaragos/authentik-credential-provider/issues)
- Read the [Documentation](docs/)
- Ask in [Discussions](https://github.com/mikemaragos/authentik-credential-provider/discussions)

## 📜 Code of Conduct

### Our Standards
- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the project
- Show empathy

### Unacceptable Behavior
- Harassment or discrimination
- Trolling or insulting comments
- Public or private harassment
- Publishing others' private information

## 🙏 Recognition

Contributors will be recognized in:
- README.md acknowledgments
- Release notes
- GitHub contributors page

Thank you for contributing! 🎉
