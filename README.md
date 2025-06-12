# 🔍 VulnSeer

**AI-Powered Network Vulnerability Scanner**

VulnSeer combines the power of Nmap's service detection with multiple AI providers to deliver intelligent vulnerability assessments. Unlike traditional scanners that rely on static databases, VulnSeer leverages AI to provide contextual analysis of discovered services and their potential security risks.

## ✨ Features

- 🤖 **Multi-AI Integration**: Supports OpenAI GPT, Anthropic Claude, and Groq
- 🎯 **Smart Service Detection**: Advanced parsing of Nmap output with version extraction
- 🛡️ **Conservative Mode**: Risk assessment without potentially inaccurate CVE claims
- ⚡ **Fast Scanning**: Efficient network discovery with targeted port scanning
- 📊 **Detailed Reports**: Comprehensive vulnerability analysis with actionable recommendations
- 🔄 **Multiple Targets**: Support for single hosts, CIDR ranges, and target files
- ⚠️ **Accuracy Focus**: Built-in warnings and verification prompts for CVE data

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Nmap installed and accessible in PATH
- API key for at least one supported AI provider

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnseer.git
cd vulnseer

# Install Python dependencies
pip install -r requirements.txt

# Verify nmap installation
nmap --version
```

### Basic Usage

```bash
# Conservative scan (recommended for accuracy)
python3 vulnseer.py 192.168.1.100 --anthropic-key YOUR_KEY --no-cves

# Full scan with CVE analysis (verify results independently)
python3 vulnseer.py 192.168.1.0/24 --openai-key YOUR_KEY --ports 22,80,443

# Multi-provider analysis for cross-validation
python3 vulnseer.py target.com --openai-key KEY1 --anthropic-key KEY2 --providers openai anthropic
```

## 📋 Requirements

Create a `requirements.txt` file:

```
openai>=1.0.0
anthropic>=0.7.0
requests>=2.25.0
```

## 🔧 Configuration

### API Keys

VulnSeer supports multiple AI providers. You need at least one API key:

- **OpenAI**: Get from [platform.openai.com](https://platform.openai.com)
- **Anthropic**: Get from [console.anthropic.com](https://console.anthropic.com)  
- **Groq**: Get from [console.groq.com](https://console.groq.com)

### Command Line Options

```
usage: vulnseer.py [-h] [--ports PORTS] [--openai-key OPENAI_KEY] 
                   [--anthropic-key ANTHROPIC_KEY] [--groq-key GROQ_KEY]
                   [--output OUTPUT] [--providers {openai,anthropic,groq} ...]
                   [--no-cves]
                   targets

positional arguments:
  targets               Target IP/CIDR/hostname or file containing targets

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS, -p PORTS
                        Port specification (e.g., '22,80,443' or '1-1000')
  --openai-key OPENAI_KEY
                        OpenAI API key
  --anthropic-key ANTHROPIC_KEY
                        Anthropic API key
  --groq-key GROQ_KEY   Groq API key
  --output OUTPUT, -o OUTPUT
                        Output report file
  --providers {openai,anthropic,groq} ...
                        AI providers to use (default: openai)
  --no-cves            Disable CVE reporting (conservative mode)
```

## 📖 Usage Examples

### Single Host Scan
```bash
python3 vulnseer.py 10.0.0.1 --anthropic-key sk-ant-xxx --ports 22,80,443,3389
```

### Network Range Scan
```bash
python3 vulnseer.py 192.168.1.0/24 --openai-key sk-xxx --no-cves --output network_scan.txt
```

### Target File Scan
```bash
echo -e "scanme.nmap.org\n45.33.32.156\nexample.com" > targets.txt
python3 vulnseer.py targets.txt --anthropic-key sk-ant-xxx --providers anthropic
```

### Conservative Assessment (Recommended)
```bash
# Most accurate - focuses on risk assessment without potentially false CVEs
python3 vulnseer.py target.com --anthropic-key sk-ant-xxx --no-cves
```

### Multi-Provider Validation
```bash
# Cross-validate results using multiple AI providers
python3 vulnseer.py 192.168.1.50 \
  --openai-key sk-xxx \
  --anthropic-key sk-ant-xxx \
  --providers openai anthropic \
  --ports 21,22,23,25,53,80,110,143,443,993,995
```

## 📊 Sample Output

### Conservative Mode
```
VULNERABILITY SCAN REPORT
==================================================
📊 RISK ASSESSMENT MODE:
- CVE reporting disabled for conservative analysis
- Risk assessments based on software age and maintenance status
==================================================

Host: 192.168.1.100:22
Service: openssh 7.4
Estimated Age: ~8 years (Very Old)
Risk: High
CVEs: Disabled (risk assessment mode)
Exploitable: True
Exploits Available: Unknown
Patch Status: Available

Detailed Analysis:
OpenSSH 7.4 was released in 2016, making it approximately 8 years old.
While not ancient, this version lacks numerous security improvements and
patches from recent years. Upgrade to OpenSSH 9.0+ recommended for
enhanced security posture.
```

### CVE Mode (With Warnings)
```
⚠️  IMPORTANT DISCLAIMER:
- CVE information should be independently verified
- Always consult vendor security advisories

Host: 192.168.1.100:80
Service: apache_httpd 2.4.29
Risk: Medium
CVEs: CVE-2021-44790, CVE-2021-44224 ⚠️ VERIFY INDEPENDENTLY
Exploitable: True
Exploits Available: True
Patch Status: Available
```

## ⚙️ Advanced Features

### Custom Port Ranges
```bash
# Scan common ports only (faster)
python3 vulnseer.py 10.0.0.0/24 --ports 21,22,23,25,53,80,443,993,995,3389,5900

# Scan specific range
python3 vulnseer.py target.com --ports 8000-8999

# Scan all ports (slow but comprehensive)
python3 vulnseer.py 192.168.1.1 --ports 1-65535
```

### Output Formats
```bash
# Save to file
python3 vulnseer.py targets.txt --anthropic-key xxx --output vulnerability_report.txt

# Console output with detailed analysis
python3 vulnseer.py target.com --openai-key xxx --no-cves
```

## 🛡️ Security & Accuracy

### CVE Accuracy Warning

**Important**: AI-generated CVE information should always be independently verified. VulnSeer includes multiple safeguards:

- **Conservative Mode**: Use `--no-cves` for risk assessment without specific CVE claims
- **Verification Warnings**: Real-time alerts when CVEs are mentioned
- **Cross-Validation**: Use multiple AI providers to compare results
- **Manual Verification**: Always check official sources like [NVD](https://nvd.nist.gov/)

### Best Practices

1. **Start Conservative**: Use `--no-cves` for initial assessments
2. **Cross-Validate**: Use multiple AI providers for important scans
3. **Verify Critical Findings**: Manually confirm high-risk vulnerabilities
4. **Update Regularly**: Keep Nmap and dependencies updated
5. **Scope Appropriately**: Only scan networks you own or have permission to test

### Development Setup
```bash
git clone https://github.com/yourusername/vulnseer.git
cd vulnseer
pip install -r requirements-dev.txt
python3 -m pytest tests/
```

## ⚠️ Disclaimer

VulnSeer is intended for authorized security testing only. Users are responsible for:

- Obtaining proper authorization before scanning networks
- Complying with applicable laws and regulations
- Independently verifying all vulnerability information
- Using results responsibly and ethically

The authors are not responsible for misuse of this tool or accuracy of AI-generated vulnerability assessments.

## 🔗 Resources

- [Nmap Documentation](https://nmap.org/docs.html)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic API Documentation](https://docs.anthropic.com/)

---

Made with ❤️ for the cybersecurity community
