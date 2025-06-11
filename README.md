# CipherAsh SSL/TLS Security Scanner

A comprehensive SSL/TLS security analysis tool with a modern web interface. CipherAsh provides detailed security assessments of websites' SSL/TLS configurations, vulnerability detection, certificate analysis, and professional PDF reporting. Built with Flask, sslyze, and React-style frontend components.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/DeepKariaX/CipherAsh-SSL-Scanner/pulls)
[![GitHub Issues](https://img.shields.io/github/issues/DeepKariaX/Analysis-Alpaca-Researcher)](https://github.com/DeepKariaX/CipherAsh-SSL-Scanner/issues)
[![GitHub Stars](https://img.shields.io/github/stars/DeepKariaX/Analysis-Alpaca-Researcher)](https://github.com/DeepKariaX/CipherAsh-SSL-Scanner/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/DeepKariaX/Analysis-Alpaca-Researcher)](https://github.com/DeepKariaX/CipherAsh-SSL-Scanner/network)


## 🚀 Quick Start

```bash
# 1. Clone and navigate to the project
git clone https://github.com/DeepKariaX/CipherAsh-SSL-Scanner.git
cd CipherAsh-SSL-Scanner

# 2. Install dependencies (use virtual environment recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Start the application
python app.py
# Server runs on http://localhost:5000
```

## ✨ Features

### Core Security Analysis

- **Comprehensive SSL/TLS Protocol Testing**: Support for SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3
- **Cipher Suite Analysis**: Detailed examination of supported cipher suites per protocol
- **Certificate Validation**: Complete certificate chain analysis and validation
- **Vulnerability Detection**: Tests for Heartbleed, ROBOT, CRIME, CCS Injection, and more
- **Security Headers Analysis**: HSTS, HPKP, and other security header detection
- **Performance Features**: Session resumption, TLS 1.3 early data support analysis

## 🏗 Architecture

### Components Overview

```
CipherAsh/
├── app.py
├── static/                 
├── templates/
│   └── index.html        
├── scanned_domains/       
├── requirements.txt      
└── README.md            
```

### Core Components

**Flask Application** (`app.py`)
- SSL/TLS scanning engine powered by sslyze
- RESTful API endpoints for scan operations
- JSON storage system for persistent data
- Comprehensive vulnerability assessment
- Performance and security feature analysis

**Web Interface** (`templates/index.html`)
- Two-stage UI: landing page → results dashboard
- Tabbed navigation for organized data presentation
- PDF report generation with jsPDF
- Real-time scan progress tracking
- Responsive design for all device types

**Data Storage** (`scanned_domains/`)
- JSON-based storage system
- Automatic scan history management
- Domain-based file organization
- Metadata tracking for scan analytics

## 🚀 Usage

### Web Interface

1. **Start the Application**
   ```bash
   python app.py
   ```

2. **Access the Interface**
   - Open your browser to `http://localhost:5000`
   - Enter a domain name (e.g., `google.com` or `https://example.com`)
   - Click "Start SSL/TLS Scan"

3. **View Results**
   - Navigate through tabbed sections:
     - **SSL/TLS Protocols**: Protocol support and cipher suites
     - **Certificates**: Certificate details and validation
     - **Vulnerabilities**: Security vulnerability assessment
     - **Security Features**: Security header and feature analysis
     - **Performance Features**: Performance optimization features

4. **Download Reports**
   - Click "Download Report" to generate a professional PDF
   - Reports include comprehensive analysis with CipherAsh branding


## 🔍 Security Analysis

### Vulnerability Detection

**Heartbleed (CVE-2014-0160)**
- Tests for the critical OpenSSL vulnerability
- Detects information disclosure risks

**ROBOT Attack**
- Return Of Bleichenbacher's Oracle Threat
- Tests RSA PKCS#1 v1.5 padding oracle vulnerabilities

**CRIME (CVE-2012-4929)**
- Compression Ratio Info-leak Made Easy
- Detects TLS compression vulnerabilities

**OpenSSL CCS Injection (CVE-2014-0224)**
- Tests for ChangeCipherSpec injection vulnerability
- Early TLS handshake manipulation detection

**Session Renegotiation**
- Client-initiated renegotiation vulnerability testing
- Secure renegotiation support verification

### Protocol Analysis

**SSL/TLS Protocol Support**
- SSL 2.0/3.0: Legacy protocols (should be disabled)
- TLS 1.0/1.1: Deprecated protocols
- TLS 1.2: Current standard protocol
- TLS 1.3: Latest protocol with enhanced security

**Cipher Suite Analysis**
- Strength assessment of supported cipher suites
- Identification of weak or deprecated ciphers
- Perfect Forward Secrecy (PFS) support detection

### Certificate Validation

**Certificate Chain Analysis**
- Complete certificate chain validation
- Root CA verification
- Intermediate certificate validation

**Certificate Properties**
- Subject and issuer information
- Serial number and public key details
- Validity period and expiration dates
- Signature algorithm analysis

### Common Test Cases

- **Valid domains**: google.com, github.com, cloudflare.com
- **Invalid domains**: nonexistent.domain.test
- **Protocol variations**: http://example.com, https://example.com
- **Edge cases**: domains with special characters, very long domains

## 🤝 Contributing

We welcome contributions to CipherAsh! Here's how you can help:

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper testing
4. **Follow code style**: Use Black for formatting, flake8 for linting
5. **Submit a pull request** with detailed description

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **sslyze** - Comprehensive SSL/TLS scanning library
- **Flask** - Lightweight and powerful web framework
- **jsPDF** - Client-side PDF generation
- **OpenSSL** - SSL/TLS library and cryptographic toolkit
- **Security Research Community** - Vulnerability research and disclosure