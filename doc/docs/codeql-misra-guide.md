# CodeQL with MISRA Rules Guide for Timpani

This document explains how to use CodeQL for static analysis of Timpani's C/C++ codebase with MISRA coding standards.

## Overview

CodeQL is GitHub's powerful semantic code analysis engine that can detect security vulnerabilities, bugs, and coding standard violations. We've configured it to check MISRA C:2012 and MISRA C++:2008 compliance for the Timpani project.

## MISRA Standards

**MISRA C** (Motor Industry Software Reliability Association) provides guidelines for the C programming language designed to facilitate code safety, security, portability, and reliability in embedded systems.

- **MISRA C:2012** - Latest standard with 143 rules and 16 directives
- **MISRA C++:2008** - Standard for C++ embedded systems

## Repository Structure

```
.github/
├── workflows/
│   └── codeql-analysis.yml          # Main GitHub Actions workflow
└── codeql/
    ├── codeql-config.yml             # CodeQL configuration
    ├── queries/
    │   └── misra-suite.qls           # MISRA query suite
    └── custom-queries/
        └── misra-rules.ql            # Custom MISRA checks
```

## Workflow Configuration

### Automatic Scanning

The CodeQL workflow runs automatically on:
- **Push** to `main` or `develop` branches
- **Pull requests** targeting `main` or `develop`
- **Weekly schedule** (Mondays at 02:00 UTC)
- **Manual trigger** via GitHub Actions UI

### Components Analyzed

1. **timpani-n** - C implementation (BPF-based scheduler)
2. **timpani-o** - C++ implementation (orchestrator)
3. **libtrpc** - IPC library
4. **sample-apps** - Sample applications

## MISRA Rules Checked

### Key MISRA C:2012 Rules

| Rule | Category | Description |
|------|----------|-------------|
| 8.9 | Required | Object scope minimization |
| 8.14 | Required | Restrict qualifier usage |
| 10.x | Required | Type conversions |
| 15.x | Required | Control flow |
| 17.7 | Required | Return value checking |
| 18.4 | Advisory | Pointer arithmetic |
| 21.3 | Required | Memory allocation functions |
| 21.6 | Required | Standard I/O functions |

### Security and Quality Checks

- **Null pointer dereference**
- **Buffer overflow** (snprintf, format strings)
- **Integer overflow** and signed overflow
- **Use-after-free** and **double-free**
- **Resource leaks**
- **Dead code** and **unreachable code**
- **Uninitialized variables**
- **Undefined behavior**

## Running CodeQL Locally

### Prerequisites

```bash
# Install CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH=$PATH:$(pwd)/codeql

# Clone CodeQL standard libraries
git clone https://github.com/github/codeql.git codeql-repo
```

### Create CodeQL Database

```bash
# For timpani-n (C code)
cd timpani-n
mkdir -p build
cd build
codeql database create ../codeql-db-n \
  --language=cpp \
  --command="cmake .. && make" \
  --source-root=..

# For timpani-o (C++ code)
cd ../../timpani-o
mkdir -p build
cd build
codeql database create ../codeql-db-o \
  --language=cpp \
  --command="cmake .. && make" \
  --source-root=..
```

### Run Analysis

```bash
# Run with standard query suite
codeql database analyze codeql-db-n \
  --format=sarif-latest \
  --output=results-n.sarif \
  -- cpp-security-extended.qls

# Run with custom MISRA queries
codeql database analyze codeql-db-n \
  --format=sarif-latest \
  --output=results-misra.sarif \
  -- .github/codeql/queries/misra-suite.qls
```

### View Results

```bash
# Convert SARIF to CSV for easier viewing
codeql database interpret-results codeql-db-n \
  --format=csv \
  --output=results.csv \
  results-n.sarif

# Or view in VS Code with SARIF Viewer extension
code results-n.sarif
```

## GitHub Integration

### Viewing Results

1. Navigate to your repository on GitHub
2. Go to **Security** → **Code scanning alerts**
3. Filter by:
   - **Severity** (Critical, High, Medium, Low)
   - **Status** (Open, Closed, Fixed)
   - **Tags** (misra-c, security, correctness)

### Pull Request Integration

CodeQL automatically comments on pull requests with:
- New vulnerabilities introduced
- MISRA violations
- Suggested fixes

Example:
```
CodeQL found 2 new issues:
⚠️ Warning: MISRA C:2012 Rule 17.7 violation
   Return value not checked at line 45

🔴 Error: Potential null pointer dereference at line 102
```

## Custom MISRA Rules

You can add custom rules by editing `.github/codeql/custom-queries/misra-rules.ql`:

```ql
/**
 * @name Custom MISRA Check
 * @description Checks for specific pattern
 * @kind problem
 * @tags misra-c
 */

import cpp

from FunctionCall fc
where fc.getTarget().getName() = "dangerous_function"
select fc, "Avoid using dangerous_function per company policy"
```

## Troubleshooting

### Build Failures

If CodeQL fails to build:
```bash
# Check dependencies
sudo apt-get install -y build-essential cmake clang

# Verify CMake configuration
cd timpani-n/build
cmake .. -DCMAKE_VERBOSE_MAKEFILE=ON
```

### Missing Dependencies

```bash
# Install all timpani dependencies
cd /home/acrn/new_ak/pullpiri_akshay/timpani
./scripts/installdeps.sh
```

### Query Timeout

If queries timeout, reduce scope in `codeql-config.yml`:
```yaml
paths:
  - timpani-n/src/core.c  # Analyze specific files only
```

## References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [MISRA C:2012 Guidelines](https://misra.org.uk/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [CodeQL Query Reference for C/C++](https://codeql.github.com/codeql-query-help/cpp/)

## CI/CD Integration

The CodeQL workflow is integrated with the timpani CI/CD pipeline:

```yaml
# ci-dispatcher.yml can trigger CodeQL
jobs:
  security-scan:
    uses: ./.github/workflows/codeql-analysis.yml
```

## Contributing

When adding new code:
1. Run CodeQL locally before pushing
2. Address all High/Critical findings
3. Document any suppressed warnings in PR description
4. Ensure MISRA compliance for safety-critical code

---
