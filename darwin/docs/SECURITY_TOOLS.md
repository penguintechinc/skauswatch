# Security Tools Integration

The AI PR Reviewer includes comprehensive open-source security scanning tools that run **by default** on every review. These tools complement AI-based security analysis with proven static analysis and vulnerability detection.

## Overview

**Security is multi-layered**: The PR Reviewer combines:
1. **Open-source security tools** (bandit, gosec, semgrep, etc.) - Run automatically
2. **AI-powered analysis** (GPT-4o, Claude Sonnet, etc.) - Contextual security review
3. **Vulnerability scanners** (trivy, grype) - Dependency and container scanning

All tools run in parallel and results are aggregated into a single review.

---

## Installed Security Tools

### Language-Specific Security Scanners

#### Python Security - Bandit
**Tool**: [Bandit](https://github.com/PyCQA/bandit) v1.8.0

**Purpose**: Python code security scanner

**Checks**:
- SQL injection vulnerabilities
- Hardcoded passwords and secrets
- Use of `eval()`, `exec()`, `pickle`
- Weak cryptographic functions (MD5, SHA1)
- Shell injection via `subprocess`
- Path traversal vulnerabilities
- XML parsing vulnerabilities (XXE)

**Configuration**:
```bash
# Runs automatically on all Python files
bandit -r /path/to/code -f json
```

**Example Findings**:
```python
# ❌ Bandit detects:
password = "hardcoded_password"  # B105: hardcoded_password_string
os.system(user_input)             # B605: shell_injection
eval(user_data)                   # B307: use_of_eval
```

---

#### Python Type Checker - Pyright
**Tool**: [Pyright](https://github.com/microsoft/pyright) v1.1.390

**Purpose**: Fast static type checker for Python (by Microsoft)

**Checks**:
- Type errors and mismatches
- Undefined variables
- Unreachable code
- Missing return statements
- Incompatible assignments
- Protocol violations

**Configuration**:
```bash
# Analyze Python code
pyright /path/to/code
```

**Example Findings**:
```python
# ❌ Pyright detects:
def greet(name: str) -> str:
    print(name)  # Missing return statement

x: int = "hello"  # Type mismatch: str vs int

if False:
    unreachable_code()  # Unreachable code
```

**Why Pyright**:
- Faster than mypy (written in TypeScript/Node.js)
- Better type inference
- VS Code Pylance uses Pyright
- Strict type checking mode

---

#### Python Linter - Ruff
**Tool**: [Ruff](https://github.com/astral-sh/ruff) v0.9.2

**Purpose**: Extremely fast Python linter and formatter (written in Rust)

**Checks**:
- All Flake8 rules (E, F, W)
- isort import sorting
- pydocstyle docstring conventions
- pyupgrade syntax modernization
- 700+ rules from 50+ linters
- Auto-fixing capabilities

**Configuration**:
```bash
# Lint and auto-fix Python code
ruff check /path/to/code --fix

# Format Python code
ruff format /path/to/code
```

**Example Findings**:
```python
# ❌ Ruff detects:
import os, sys  # E401: Multiple imports on one line
from typing import *  # F403: Wildcard import

def foo( x,y ):  # E201, E202: Whitespace errors
    pass

unused_var = 42  # F841: Local variable assigned but never used
```

**Why Ruff**:
- **10-100x faster** than traditional Python linters
- Replaces Flake8, isort, Black, pyupgrade, and more
- Written in Rust for maximum performance
- Auto-fixes most issues
- Growing ecosystem with excellent VS Code integration

---

#### Go Security - gosec
**Tool**: [gosec](https://github.com/securego/gosec) v2.latest

**Purpose**: Go code security scanner

**Checks**:
- SQL injection (database/sql usage)
- Command injection via exec.Command
- Weak random number generation
- Weak cryptographic algorithms
- Directory traversal
- File permissions (chmod 777)
- Unsafe TLS configurations
- Use of deprecated/insecure packages

**Configuration**:
```bash
# Runs automatically on all Go files
gosec -fmt=json ./...
```

**Example Findings**:
```go
// ❌ gosec detects:
db.Query("SELECT * FROM users WHERE id = " + userInput)  // G201: SQL injection
exec.Command(userInput)                                   // G204: command injection
rand.Read(key)                                           // G404: weak random
```

---

### Multi-Language Security Analysis

#### Semgrep SAST
**Tool**: [Semgrep](https://semgrep.dev/) v1.99.0

**Purpose**: Static Application Security Testing (SAST) for multiple languages

**Languages**: Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C, C++, Rust, Kotlin, Swift, Scala

**Checks**:
- OWASP Top 10 vulnerabilities
- Custom security patterns
- Framework-specific vulnerabilities (Django, Flask, React, etc.)
- API security issues
- Authentication/authorization flaws
- Data exposure risks

**Rulesets**:
- `p/owasp-top-ten` - OWASP Top 10 checks
- `p/security-audit` - General security audit
- `p/secrets` - Secrets and credentials detection
- `p/ci` - CI/CD security

**Configuration**:
```bash
# Runs with multiple rulesets
semgrep --config=p/owasp-top-ten \
        --config=p/security-audit \
        --config=p/secrets \
        --json /path/to/code
```

**Example Findings**:
```javascript
// ❌ Semgrep detects:
eval(userInput);                              // code-injection
document.innerHTML = userInput;               // xss
fetch(url, {credentials: 'include'});         // cors-misconfiguration
```

---

#### Secrets Detection - Gitleaks
**Tool**: [Gitleaks](https://github.com/gitleaks/gitleaks) v8.21.3

**Purpose**: Detect hardcoded secrets, API keys, and credentials

**Checks**:
- AWS access keys
- API keys (GitHub, GitLab, Slack, etc.)
- Private keys (RSA, SSH)
- Database credentials
- OAuth tokens
- Generic secret patterns

**Configuration**:
```bash
# Runs on entire repository
gitleaks detect --source=/path/to/code --report-path=report.json
```

**Example Findings**:
```bash
# ❌ Gitleaks detects:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE       # aws-access-key
GITHUB_TOKEN=ghp_1234567890abcdefghijklmno   # github-pat
-----BEGIN RSA PRIVATE KEY-----              # private-key
```

---

### Advanced Static Analyzers

#### Facebook Infer - Deep Static Analysis
**Tool**: [Infer](https://fbinfer.com/) v1.2.0

**Purpose**: Advanced static analyzer using separation logic and abstract interpretation

**Languages**: Java, C, C++, Objective-C

**Checks**:
- **Null pointer dereferences**
- **Memory leaks** (C/C++)
- **Resource leaks** (file handles, connections)
- **Concurrency issues** (race conditions, deadlocks)
- **Use-after-free** (C/C++)
- **Double-free** (C/C++)
- **Thread safety violations**

**Key Strength**: **Formal verification** - mathematically proves absence of bugs

**Configuration**:
```bash
# Analyze Java project
infer run -- javac *.java

# Analyze C/C++ project
infer run -- make

# Analyze specific files
infer run -- clang -c file.c
```

**Example Findings**:
```java
// ❌ Infer detects:
String getValue() {
    if (map.containsKey("key")) {
        return map.get("key").toString();  // NULL_DEREFERENCE: get() may return null
    }
}

void cleanup() {
    InputStream is = new FileInputStream("file.txt");
    is.read();
    // RESOURCE_LEAK: InputStream never closed
}
```

**Why Infer is Powerful**:
- Zero false positives on verified issues (mathematical proof)
- Finds complex bugs that pattern matchers miss
- Used in production at Facebook, Mozilla, AWS
- Interprocedural analysis (tracks values across functions)

---

#### Cppcheck - C/C++ Static Analyzer
**Tool**: [Cppcheck](http://cppcheck.sourceforge.net/) latest

**Purpose**: Static analysis for C/C++ focusing on undefined behavior

**Checks**:
- Buffer overflows
- Memory leaks
- Null pointer dereferences
- Uninitialized variables
- Division by zero
- Invalid pointer usage
- Out-of-bounds array access
- STL misuse

**Configuration**:
```bash
# Analyze C/C++ code
cppcheck --enable=all --inconclusive --xml /path/to/code
```

**Example Findings**:
```cpp
// ❌ Cppcheck detects:
char buffer[10];
strcpy(buffer, long_string);  // Buffer overflow

int* ptr;
*ptr = 5;  // Uninitialized pointer

int arr[5];
arr[10] = 0;  // Out of bounds
```

---

#### Clang Static Analyzer - Compiler-based Analysis
**Tool**: [Clang Static Analyzer](https://clang-analyzer.llvm.org/) (scan-build)

**Purpose**: Deep static analysis using compiler infrastructure

**Languages**: C, C++, Objective-C

**Checks**:
- Memory errors (leaks, use-after-free)
- API misuse
- Dead code
- Logic errors
- Security issues (buffer overflows, format strings)

**Configuration**:
```bash
# Analyze with scan-build
scan-build make

# Analyze single file
clang --analyze -Xanalyzer -analyzer-output=text file.c
```

**Example Findings**:
```c
// ❌ Clang detects:
void* malloc_wrapper() {
    void* p = malloc(100);
    return p;  // Memory leak if caller doesn't free
}

char* getString() {
    char buffer[100];
    return buffer;  // Return of stack memory
}
```

---

#### SpotBugs - Java Static Analysis
**Tool**: [SpotBugs](https://spotbugs.github.io/) v4.8.6 (successor to FindBugs)

**Purpose**: Java bytecode analyzer for bug patterns

**Checks**:
- Null pointer dereferences
- SQL injection
- Path traversal
- Insecure random
- Weak cryptography
- Exposed synchronization
- Resource leaks

**Configuration**:
```bash
# Analyze Java project
spotbugs -textui -effort:max /path/to/classes
```

**Example Findings**:
```java
// ❌ SpotBugs detects:
Random rand = new Random();  // Predictable random (use SecureRandom)

String sql = "SELECT * FROM users WHERE id = " + userId;  // SQL injection

synchronized(new Object()) {  // Synchronization on new object (useless)
    // ...
}
```

---

#### PMD - Java Source Code Analyzer
**Tool**: [PMD](https://pmd.github.io/) v7.8.0

**Purpose**: Source code analyzer for Java, JavaScript, XML, and more

**Checks**:
- Code style violations
- Complexity (cyclomatic, cognitive)
- Design issues
- Performance problems
- Security vulnerabilities
- Best practices violations

**Configuration**:
```bash
# Analyze Java code
pmd check -d /path/to/src -R rulesets/java/quickstart.xml -f text
```

**Example Findings**:
```java
// ❌ PMD detects:
if (obj.equals("string")) { }  // Literal should be on left: "string".equals(obj)

for (int i = 0; i < list.size(); i++) {
    list.get(i);  // Inefficient list iteration, use enhanced for
}

public void method() throws Exception { }  // Overly broad exception
```

---

#### SonarScanner - Multi-Language Analysis
**Tool**: [SonarScanner](https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/) v6.2.1

**Purpose**: Code quality and security analysis for 30+ languages

**Languages**: Java, C/C++, C#, JavaScript, TypeScript, Python, Go, PHP, Ruby, Kotlin, Swift, and more

**Checks**:
- **Security hotspots** (OWASP Top 10)
- **Code smells** (maintainability issues)
- **Bugs** (reliability issues)
- **Vulnerabilities** (security issues)
- **Technical debt** (complexity, duplication)

**Configuration**:
```bash
# Requires SonarQube server or SonarCloud
sonar-scanner \
  -Dsonar.projectKey=myproject \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000
```

**Example Findings**:
- Critical: Hard-coded credentials
- Major: SQL injection vulnerability
- Minor: Cognitive complexity too high (15, should be < 10)
- Info: Duplicated code block (15 lines)

---

### License and Dependency Analysis

#### ScanCode Toolkit - License & Dependency Scanner
**Tool**: [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) v32.3.0 (AboutCode)

**Purpose**: Comprehensive license, copyright, and dependency detection

**Scans**:
- **Licenses**: Detects 1,700+ open-source licenses
- **Copyrights**: Extracts copyright statements
- **Package manifests**: Identifies dependencies (npm, pip, maven, etc.)
- **Emails and URLs**: Extracts contact information
- **File types**: Identifies programming languages

**Checks**:
- License compliance violations
- Incompatible license combinations (GPL + MIT issues)
- Missing license headers
- Copyright attribution requirements
- Dependency license risks

**Configuration**:
```bash
# Scan for licenses and copyrights
scancode --license --copyright /path/to/code --json-pp output.json

# Scan for packages and dependencies
scancode --package --license /path/to/code --json-pp output.json

# Full scan (comprehensive)
scancode --license --copyright --package --info /path/to/code --json-pp output.json
```

**Example Findings**:
```
File: src/utils/helper.js
├─ License: MIT License
├─ Copyright: Copyright (c) 2024 Example Corp
└─ Package: lodash@4.17.21 (MIT)

File: lib/crypto.c
├─ License: GPL-3.0-only  ⚠️ WARNING: GPL incompatible with MIT project
├─ Copyright: Copyright (c) 2023 Developer Name
└─ Risk: License incompatibility detected

File: requirements.txt
├─ Package: requests==2.28.0 (Apache-2.0)
├─ Package: pycryptodome==3.15.0 (BSD-2-Clause, Public Domain)
└─ Total dependencies: 47 packages
```

**Why ScanCode is Critical**:
- **Legal compliance**: Avoid license violations (can cost millions)
- **Supply chain visibility**: Know what's in your dependencies
- **Open-source governance**: Ensure license compatibility
- **SBOM generation**: Software Bill of Materials for audits

**Use Cases**:
1. **Pre-release compliance**: Scan before shipping
2. **Acquisition due diligence**: Audit code before purchase
3. **Open-source policy**: Enforce license rules
4. **Security audit**: Identify risky dependencies

---

#### CycloneDX CLI - SBOM and License Scanner
**Tool**: [CycloneDX](https://github.com/CycloneDX/cyclonedx-cli) v0.27.3

**Purpose**: Generate Software Bill of Materials (SBOM) and detect dependency licenses

**Scans**:
- **SBOM Generation**: CycloneDX and SPDX formats
- **Dependency Licenses**: Extract licenses from package manifests
- **Component Analysis**: Identify all dependencies recursively
- **Vulnerability Correlation**: Link to CVE databases

**Checks**:
- License compliance across dependencies
- Dependency tree analysis
- Component provenance tracking
- Supply chain transparency

**Configuration**:
```bash
# Generate SBOM from package manager files
cyclonedx-cli analyze /path/to/project --output sbom.json

# Convert between SBOM formats
cyclonedx-cli convert --input sbom.xml --output sbom.json

# Validate SBOM
cyclonedx-cli validate --input sbom.json
```

**Python License Detection** (pip-licenses):
```bash
# Extract Python package licenses
pip-licenses --format=json --with-system

# Output example:
# [
#   {"Name": "requests", "Version": "2.28.0", "License": "Apache-2.0"},
#   {"Name": "flask", "Version": "3.1.0", "License": "BSD-3-Clause"}
# ]
```

**Example SBOM Output**:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.28.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "purl": "pkg:pypi/requests@2.28.0"
    },
    {
      "type": "library",
      "name": "flask",
      "version": "3.1.0",
      "licenses": [{"license": {"id": "BSD-3-Clause"}}]
    }
  ]
}
```

**Why CycloneDX**:
- **Industry standard**: OWASP-backed SBOM format
- **Supply chain transparency**: Know exactly what's in your software
- **License compliance**: Automated license detection
- **Integration**: Works with vulnerability databases (NVD, OSV)
- **Multi-language**: Python, JavaScript, Go, Java, Ruby, PHP support

**Use Cases**:
1. **Compliance reporting**: Generate SBOMs for customers
2. **License auditing**: Detect problematic licenses automatically
3. **Vulnerability tracking**: Link dependencies to CVEs
4. **Supply chain security**: Document all software components

---

### Dependency & Container Vulnerability Scanners

#### Trivy - Universal Scanner
**Tool**: [Trivy](https://github.com/aquasecurity/trivy) v0.58.2

**Purpose**: Comprehensive vulnerability scanner for containers, filesystems, and dependencies

**Scans**:
- Container images (Docker, OCI)
- Filesystem vulnerabilities
- Language dependencies:
  - Python (pip, pipenv, poetry)
  - JavaScript (npm, yarn, pnpm)
  - Go (go.mod)
  - Java (Maven, Gradle)
  - Ruby (Bundler)
  - PHP (Composer)
  - Rust (Cargo)
- IaC misconfigurations (Dockerfile, Kubernetes, Terraform)
- License compliance

**Configuration**:
```bash
# Scan filesystem for vulnerabilities
trivy fs --format json /path/to/code

# Scan dependencies only
trivy fs --scanners vuln /path/to/code

# Scan container image
trivy image myapp:latest
```

**Example Findings**:
```
CVE-2024-1234  CRITICAL  requests 2.28.0  Upgrade to 2.31.0+
CVE-2024-5678  HIGH      express 4.17.0   Upgrade to 4.18.2+
```

---

#### Grype - Vulnerability Scanner
**Tool**: [Grype](https://github.com/anchore/grype) latest

**Purpose**: Vulnerability scanner for container images and filesystems

**Scans**:
- Language-specific packages:
  - Python (PyPI)
  - JavaScript (npm)
  - Go (Go modules)
  - Java (Maven, JAR)
  - Ruby (Gems)
  - .NET (NuGet)
- OS packages (Debian, Alpine, RHEL, etc.)
- Binary applications

**Configuration**:
```bash
# Scan directory
grype dir:/path/to/code -o json

# Scan specific package manager
grype npm:/path/to/package.json -o json
```

**Example Findings**:
```
django  3.2.0  CVE-2024-XXXX  CRITICAL  SQL injection in QuerySet
lodash  4.17.19  CVE-2024-YYYY  HIGH    Prototype pollution
```

---

## Security Scanning Workflow

### Automatic Execution

All security tools run **automatically** on every PR review:

1. **Language Detection**: Detect languages in PR
2. **Tool Selection**: Choose relevant security scanners
3. **Parallel Execution**: Run all applicable tools simultaneously
4. **Result Aggregation**: Combine findings from all tools
5. **AI Analysis**: Send aggregated results + code to AI for contextual review
6. **Report Generation**: Create unified security report

### Example Review Flow

```
PR Opened → Security Scan Triggered
  ↓
├─ Bandit (Python files)      [1.2s] → 2 issues found
├─ gosec (Go files)           [0.8s] → 1 issue found
├─ Semgrep (All files)        [3.5s] → 5 issues found
├─ Gitleaks (Repository)      [0.5s] → 0 secrets found
├─ Trivy (Dependencies)       [2.1s] → 3 CVEs found
└─ Grype (Dependencies)       [1.9s] → 3 CVEs found
  ↓
Aggregate Results → 11 security findings
  ↓
Send to AI (GPT-4o/Claude) → Contextual analysis
  ↓
Post Review Comment → Prioritized, actionable findings
```

---

## Security Tool Configuration

### Enable/Disable Tools

```bash
# In .env or environment variables

# Enable/disable security category
REVIEW_SECURITY_ENABLED=true

# Tool-specific toggles (all enabled by default)
SECURITY_BANDIT_ENABLED=true              # Python security
SECURITY_GOSEC_ENABLED=true               # Go security
SECURITY_SEMGREP_ENABLED=true             # Multi-language SAST
SECURITY_GITLEAKS_ENABLED=true            # Secrets detection
SECURITY_TRIVY_ENABLED=true               # Dependency scanning
SECURITY_GRYPE_ENABLED=true               # Vulnerability scanning
```

### Custom Semgrep Rules

```bash
# Use custom Semgrep rulesets
SEMGREP_CONFIG=p/owasp-top-ten,p/security-audit,path/to/custom/rules.yaml
```

### Severity Filtering

```bash
# Only report high/critical findings
SECURITY_MIN_SEVERITY=high

# Severity levels: critical, high, medium, low, info
```

---

## Security Tool Output

### JSON Output Format

Each tool outputs findings in a standardized format:

```json
{
  "tool": "bandit",
  "language": "python",
  "findings": [
    {
      "file": "app/views.py",
      "line": 42,
      "severity": "high",
      "rule_id": "B608",
      "title": "Possible SQL injection",
      "description": "Use of string concatenation in SQL query",
      "recommendation": "Use parameterized queries with db.execute(query, params)"
    }
  ],
  "scan_time_ms": 1234,
  "files_scanned": 150
}
```

### AI-Enhanced Analysis

The AI models (GPT-4o, Claude) receive:
1. Raw tool findings (JSON)
2. Code context (actual code snippets)
3. Framework/library information

AI adds:
- Exploitability assessment
- Real-world attack scenarios
- Framework-specific mitigation
- Code fix suggestions
- Priority recommendations

---

## Comparison: Tools vs AI

### What Static Tools Do Well

✅ **Pattern Matching**: Known vulnerability patterns (SQL injection, XSS)
✅ **Dependency Scanning**: CVE database lookups
✅ **Secrets Detection**: Regex-based secret finding
✅ **Compliance**: Standard security rules (OWASP Top 10)
✅ **Speed**: Fast, deterministic results
✅ **No False Positives**: Rule-based, predictable

### What AI Does Well

✅ **Context Understanding**: Business logic vulnerabilities
✅ **Novel Patterns**: Detect new/unknown vulnerability types
✅ **Framework-Specific**: Deep framework knowledge
✅ **Explanation**: Explain "why" and "how to fix"
✅ **Prioritization**: Risk-based prioritization
✅ **Custom Code**: Analyze unique/custom implementations

### Combined Approach (Best)

🎯 **Layered Security**: Tools catch known issues, AI catches context-dependent issues

**Example**:
```python
# Bandit catches:
password = os.getenv("PASSWORD")  # ❌ Bandit: use of env var for password

# AI catches:
if user.role == "admin":
    # ❌ AI: Admin check without session validation
    # ❌ AI: Missing CSRF protection
    # ❌ AI: No audit logging for admin actions
    delete_all_users()
```

---

## Security Findings Dashboard

### WebUI Security View

Navigate to **Reviews > [Review ID] > Security** to see:

- **Tool Findings**: Grouped by tool (Bandit, gosec, Semgrep, etc.)
- **Severity Distribution**: Critical/High/Medium/Low counts
- **CVE Details**: Links to CVE databases for vulnerabilities
- **Fix Suggestions**: AI-generated remediation code
- **Trend Analysis**: Security findings over time

### API Access

```bash
# Get security findings for a review
curl /api/v1/reviews/{id}/security

# Filter by severity
curl /api/v1/reviews/{id}/security?severity=critical,high

# Get findings by tool
curl /api/v1/reviews/{id}/security?tool=bandit,gosec
```

---

## Best Practices

### For Developers

1. **Run Security Scans Locally**: Install tools and run before pushing
   ```bash
   # Python
   bandit -r . && semgrep --config=p/security-audit .

   # Go
   gosec ./... && semgrep --config=p/security-audit .
   ```

2. **Address High/Critical First**: Prioritize by severity and exploitability

3. **Don't Disable Tools**: All tools enabled by default for a reason

4. **Review AI Suggestions**: AI provides context, not just findings

### For Security Teams

1. **Custom Semgrep Rules**: Add organization-specific security patterns

2. **Tune False Positives**: Create exception rules for known safe patterns

3. **Track Metrics**: Monitor security findings trends over time

4. **Integrate with SIEM**: Export findings to security information systems

---

## Tool Comparison Matrix

| Tool | Languages | Finds | Speed | False Positive Rate | Best For |
|------|-----------|-------|-------|---------------------|----------|
| **Bandit** | Python | Code patterns | Fast | Low | Python security |
| **Pyright** | Python | Type errors | Very Fast | Very Low | Python type checking |
| **gosec** | Go | Code patterns | Fast | Low | Go security |
| **Infer** | Java, C, C++, Obj-C | Formal verification | Slow | **Zero*** | Memory safety, concurrency |
| **Cppcheck** | C/C++ | Undefined behavior | Fast | Low | C/C++ static analysis |
| **Clang Analyzer** | C/C++, Obj-C | Compiler-level bugs | Medium | Low | Deep C/C++ analysis |
| **SpotBugs** | Java | Bytecode patterns | Medium | Low | Java bug detection |
| **PMD** | Java, JS, XML | Code quality | Fast | Medium | Java best practices |
| **SonarScanner** | 30+ languages | Quality + Security | Slow | Medium | Enterprise code quality |
| **Semgrep** | 30+ languages | Custom patterns | Medium | Low-Medium | Multi-language SAST |
| **Gitleaks** | All (text) | Secrets | Very Fast | Very Low | Secret scanning |
| **ScanCode** | All | Licenses, SBOM | Medium | Very Low | License compliance |
| **Trivy** | All (deps) | CVEs | Medium | Very Low | Dependency scanning |
| **Grype** | All (deps) | CVEs | Medium | Very Low | Vulnerability scanning |

**Zero false positives**: Infer uses mathematical proof - verified findings are guaranteed bugs

---

## Example Security Review Output

```markdown
## Security Review Results

### Summary
- **Total Findings**: 8
- **Critical**: 1
- **High**: 3
- **Medium**: 3
- **Low**: 1

### Critical Findings

#### 1. SQL Injection in User Login
**Tool**: Semgrep + Bandit
**File**: `app/auth.py:42`
**Severity**: 🔴 Critical

Detected SQL injection vulnerability:
\`\`\`python
query = f"SELECT * FROM users WHERE username='{username}'"
db.execute(query)
\`\`\`

**AI Analysis**: This allows an attacker to bypass authentication by injecting SQL commands. For example, username `' OR '1'='1` would return all users.

**Fix**:
\`\`\`python
query = "SELECT * FROM users WHERE username = ?"
db.execute(query, (username,))
\`\`\`

---

#### 2. Hardcoded AWS Credentials
**Tool**: Gitleaks
**File**: `config/settings.py:15`
**Severity**: 🔴 Critical

Found hardcoded AWS access key:
\`\`\`python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
\`\`\`

**AI Analysis**: Hardcoded credentials in version control can be extracted by anyone with repository access, including historical commits.

**Fix**: Use environment variables or AWS IAM roles.

---

### High Findings

#### 3. Vulnerable Django Version (CVE-2024-1234)
**Tool**: Trivy + Grype
**Severity**: 🟠 High

Django 3.2.0 contains SQL injection vulnerability.

**Fix**: Upgrade to Django 3.2.25+
\`\`\`bash
pip install django>=3.2.25
\`\`\`

---

### Scan Details
- **Bandit**: 2 findings (1 high, 1 medium) in 1.2s
- **gosec**: 1 finding (1 medium) in 0.8s
- **Semgrep**: 3 findings (1 critical, 1 high, 1 low) in 3.5s
- **Gitleaks**: 1 finding (1 critical) in 0.5s
- **Trivy**: 1 finding (1 high) in 2.1s
```

---

## Further Reading

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [gosec Documentation](https://github.com/securego/gosec)
- [Semgrep Rules](https://semgrep.dev/explore)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype Documentation](https://github.com/anchore/grype)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

**Last Updated**: 2025-01-08
**Maintained by**: Darwin PR Reviewer Team
