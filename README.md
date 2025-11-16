# 🐤 Canary Scanner - Production-Ready Secret Detection

<div align="center">

[![Security](https://img.shields.io/badge/security-first-green.svg)](https://github.com/your-org/canary-scanner)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://docker.com)
[![CI/CD](https://img.shields.io/badge/ci/cd-github--actions-green.svg)](https://github.com/features/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

*A powerful, efficient, and user-friendly secret detection tool that prevents credentials from leaking into your codebase.*

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

## 🚀 Features

### 🔍 **Comprehensive Detection**
- **30+ Built-in Patterns** for popular services (AWS, GitHub, Stripe, Google, etc.)
- **Multi-Confidence System** with High/Medium/Low risk levels
- **Smart Entropy Analysis** using Shannon entropy to reduce false positives
- **Custom Pattern Support** for organization-specific secrets

### ⚡ **High Performance**
- **Optimized Scanning** with intelligent file filtering and binary detection
- **Memory Efficient** line-by-line processing for large repositories
- **Fast Pattern Matching** with pre-compiled regex patterns
- **Directory Exclusions** automatically skips build artifacts and dependencies

### 🛡️ **Security First**
- **Secure by Default** with automatic secret masking in outputs
- **Non-Root Execution** in Docker containers for enhanced security
- **No Data Persistence** - secrets never stored on disk
- **Comprehensive Input Validation** prevents injection attacks

### 🔄 **CI/CD Ready**
- **GitHub Actions Integration** with automated workflows
- **Docker Containerization** for consistent execution environments
- **Proper Exit Codes** for pipeline integration
- **PR Status Checks** with automated merge blocking
- **JSON Output Format** for automation and integration

### 🎨 **Developer Friendly**
- **Beautiful Terminal Output** with color-coded results and clear priorities
- **Rich Progress Indicators** for long-running scans
- **Detailed Error Messages** with actionable remediation guidance
- **Flexible Configuration** with command-line options and environment variables

## 🏃 Quick Start

### Local Installation
```bash
# Clone and setup
git clone <repository-url>
cd canary-scanner
python -m venv venv && source venv/bin/activate

# Install and run
pip install -r requirements.txt
python canary.py .
```

### Docker Usage
```bash
# Build and run
docker build -t canary-scanner .
docker run --rm -v "$(pwd):/scan" canary-scanner /scan
```

### CI/CD Integration
Add the workflow file to `.github/workflows/secret-scan.yml` and push to GitHub. The scanner will automatically:
- ✅ Build and test on every push and PR
- 🔍 Scan for secrets with intelligent analysis
- 🛡️ Block merges if secrets are detected
- 💬 Comment on PRs with detailed findings

## 📊 Example Output

### Console Output
```
🚨 SECURITY ALERT: 2 Potential Secret(s) Detected!

🔴 CRITICAL: 1 high-confidence secrets found
🟡 MEDIUM: 1 medium-confidence secrets found

┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Priority    ┃ File                  ┃ Line ┃ Rule ID       ┃ Description                     ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 🔴 CRITICAL │ src/config.py         │ 15   │ AWS-001       │ AWS Access Key ID               │
│ 🟡 MEDIUM   │ src/database.py       │ 28   │ POSTGRES-001  │ PostgreSQL Connection String    │
└─────────────┴───────────────────────┴──────┴───────────────┴─────────────────────────────────┘

⚠️  IMMEDIATE ACTION REQUIRED:
1. 🛑 DO NOT MERGE this code until secrets are removed
2. 🔄 Rotate any exposed credentials immediately  
3. 🗑️ Remove secrets from source code
4. 🔐 Use environment variables or secure vaults
```

### JSON Output (for automation)
```json
{
  "scan_metadata": {
    "scanner_version": "2.0.0",
    "scan_timestamp": "2025-10-12 10:30:45 UTC",
    "total_findings": 2
  },
  "severity_breakdown": {
    "critical": 1,
    "medium": 1, 
    "low": 0
  },
  "ci_metadata": {
    "pipeline_should_fail": true,
    "recommended_action": "Block deployment"
  }
}
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [**Setup Guide**](SETUP.md) | Complete installation and configuration instructions |
| [**Architecture**](ARCHITECTURE.md) | Technical architecture and design decisions |
| [**API Reference**](docs/API.md) | Detailed API documentation and examples |
| [**Contributing**](docs/CONTRIBUTING.md) | Guidelines for contributing to the project |
| [**Troubleshooting**](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## 🛠️ Usage Examples

### Basic Scanning
```bash
# Scan current directory
python canary.py .

# Scan specific directory
python canary.py /path/to/project

# Scan single file
python canary.py src/config.py
```

### Advanced Options
```bash
# CI/CD mode with medium threshold
python canary.py . --ci-mode --fail-on medium

# JSON output for automation
python canary.py . --output-json > results.json

# Verbose mode (shows full secrets - use carefully!)
python canary.py . --verbose
```

### Docker Usage
```bash
# Basic scan
docker run --rm -v "$(pwd):/scan" canary-scanner /scan

# With custom options
docker run --rm -v "$(pwd):/scan" canary-scanner /scan --ci-mode --fail-on high
```

### Custom Patterns
```yaml
# Add to patterns.yml
- rule_id: MYCOMPANY-001
  description: "My Company API Key"
  regex: 'mycompany_[a-zA-Z0-9]{32}'
  confidence: "High"
```

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CANARY SCANNER ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────┤
│  🚀 CLI LAYER (canary.py)                                     │
│  ├── Argument parsing • User interface • Output formatting      │
│                                                                 │
│  🧠 CORE ENGINE (scanner/core.py)                             │ 
│  ├── File scanning • Entropy analysis • Finding aggregation    │
│                                                                 │
│  🎯 PATTERN MANAGEMENT (scanner/patterns.py)                  │
│  ├── YAML loading • Regex compilation • Validation             │
│                                                                 │
│  🗄️ CONFIGURATION (patterns.yml)                              │
│  ├── 30+ patterns • Confidence levels • Custom rules          │
│                                                                 │
│  🐳 CONTAINERIZATION (Docker)                                 │
│  ├── Multi-stage builds • Security hardening • Health checks   │
│                                                                 │
│  🔄 CI/CD INTEGRATION                                          │
│  ├── GitHub Actions • PR checks • Security gates              │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Configuration

### Command Line Options
```
usage: canary.py [-h] [--output-json] [--verbose] [--ci-mode] 
                 [--fail-on {any,high,medium}] [--patterns-file PATTERNS_FILE] 
                 [--version] path

positional arguments:
  path                  The file or directory path to scan

optional arguments:
  --output-json         Output results in JSON format for CI/CD integration
  --verbose, -v         Show full secret values (⚠️ use with extreme caution)
  --ci-mode             CI/CD optimized mode with enhanced metadata
  --fail-on {any,high,medium}
                        Set failure threshold (default: any)
  --patterns-file       Path to patterns file (default: patterns.yml)
  --version             Show program's version number and exit
```

### Environment Variables
```bash
export CANARY_PATTERNS_FILE="/path/to/custom/patterns.yml"
export CANARY_FAIL_ON="medium" 
export CANARY_VERBOSE=1
```

## 🚦 Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | No secrets found |
| 1 | Security Failure | Secrets detected (blocks CI/CD) |
| 2 | Configuration Error | Invalid configuration or runtime error |
| 130 | Interrupted | User interrupted scan (Ctrl+C) |

## 🧪 Testing

### Run Tests
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=scanner --cov-report=html
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing  
- **Security Tests**: Vulnerability and penetration testing
- **Performance Tests**: Load and stress testing

## 📈 Performance

### Benchmarks (on modern hardware)
- **Small Repository** (< 100 files): 1-3 seconds
- **Medium Repository** (100-1,000 files): 5-15 seconds
- **Large Repository** (1,000+ files): 30-60 seconds
- **Very Large Repository** (10,000+ files): 2-5 minutes

### Optimization Features
- Binary file detection and skipping
- Intelligent directory filtering
- Memory-efficient line-by-line processing
- Pre-compiled regex patterns
- Confidence-based processing order

## 🛡️ Security

### Security Features
- Non-root container execution
- Automatic secret masking in outputs
- Input validation and sanitization
- No secret persistence to disk
- Comprehensive error handling

### Supported Secret Types
- **Cloud Providers**: AWS, Google Cloud, Azure
- **Version Control**: GitHub, GitLab, Bitbucket
- **Payment**: Stripe, PayPal, Square
- **Communication**: Slack, Discord, Twilio
- **Databases**: MongoDB, PostgreSQL, MySQL
- **Generic**: API keys, tokens, passwords, JWTs

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

### Quick Contribute
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Areas for Contribution
- 🎯 New secret patterns
- 🚀 Performance optimizations
- 📚 Documentation improvements
- 🧪 Test coverage expansion
- 🎨 UI/UX enhancements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- **Security Community**: For threat intelligence and pattern contributions
- **Open Source Tools**: Rich, PyYAML, and other excellent libraries
- **GitHub Actions**: For providing an excellent CI/CD platform
- **Docker**: For containerization technology

## 📞 Support

- **Documentation**: Comprehensive guides in the `docs/` directory
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Community discussions and Q&A
- **Security**: Report security vulnerabilities via private disclosure

---

