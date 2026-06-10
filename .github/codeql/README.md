# CodeQL with MISRA Rules - Quick Start

## 🚀 Quick Setup

This directory contains CodeQL configuration for analyzing Timpani C/C++ code with MISRA compliance checks.

## 📁 Files Created

1. **`.github/workflows/codeql-analysis.yml`** - GitHub Actions workflow
2. **`.github/codeql/codeql-config.yml`** - CodeQL configuration
3. **`.github/codeql/queries/misra-suite.qls`** - MISRA query suite
4. **`.github/codeql/custom-queries/misra-rules.ql`** - Custom MISRA checks
5. **`doc/docs/codeql-misra-guide.md`** - Complete documentation

## ⚡ Quick Start

### Option 1: Use GitHub Actions (Recommended)

1. **Push to GitHub:**
   ```bash
   git add .github/
   git commit -m "Add CodeQL with MISRA rules"
   git push
   ```

2. **View Results:**
   - Go to GitHub → **Security** → **Code scanning alerts**
   - Results appear after first workflow run

### Option 2: Run Locally

1. **Install CodeQL CLI:**
   ```bash
   wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
   unzip codeql-linux64.zip
   export PATH=$PATH:$(pwd)/codeql
   ```

2. **Create Database & Analyze:**
   ```bash
   cd timpani-n
   codeql database create codeql-db \
     --language=cpp \
     --command="mkdir build && cd build && cmake .. && make"
   
   codeql database analyze codeql-db \
     --format=sarif-latest \
     --output=results.sarif \
     cpp-security-extended.qls
   ```

## 🎯 MISRA Rules Checked

### Critical Rules
- **Rule 17.7** - Return value must be checked
- **Rule 21.3** - Memory allocation validation
- **Rule 21.6** - Avoid standard I/O in production

### Security Checks
- Null pointer dereference
- Buffer overflow
- Use-after-free
- Integer overflow
- Resource leaks

## 📊 Workflow Triggers

The CodeQL scan runs on:
- ✅ Push to `main` or `develop`
- ✅ Pull requests
- ✅ Weekly (Monday 2 AM UTC)
- ✅ Manual trigger

## 🔧 Customization

### Add Custom Rule

Edit `.github/codeql/custom-queries/misra-rules.ql`:

```ql
from FunctionCall fc
where fc.getTarget().getName() = "your_function"
select fc, "Your custom message"
```

### Exclude Paths

Edit `.github/codeql/codeql-config.yml`:

```yaml
paths-ignore:
  - '**/test/**'
  - 'your/path/**'
```

## 🐛 Troubleshooting

### Workflow Fails to Build?

Check dependencies in workflow or install locally:
```bash
sudo apt-get install -y build-essential cmake clang libelf-dev
```

### Too Many Warnings?

Start with high-severity issues first, then gradually address medium/low.

## 📚 Documentation

See [doc/docs/codeql-misra-guide.md](../doc/docs/codeql-misra-guide.md) for complete guide.

## 🔗 Resources

- [CodeQL Docs](https://codeql.github.com/docs/)
- [MISRA C:2012](https://misra.org.uk/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)

---

**Next Steps:**
1. Commit and push to GitHub
2. Wait for workflow to run
3. Review findings in Security tab
4. Fix high-priority issues first
