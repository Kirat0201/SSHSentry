# SSHSentry 🛡️

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-SOC%20Ready-red.svg)]()
[![Code Style](https://img.shields.io/badge/Code%20Style-PEP%208-black.svg)](https://www.python.org/dev/peps/pep-0008/)

> **A production-grade, zero-dependency Python tool for detecting SSH brute-force attacks in real-time**

SSHSentry is a robust command-line utility designed for Security Operations Centers (SOCs) and system administrators to identify and analyze SSH brute-force attack patterns from Linux authentication logs. Built with enterprise-grade architecture, it provides actionable threat intelligence through multiple export formats.

---

## 📋 Executive Summary

SSH brute-force attacks remain one of the most prevalent threats to Linux servers. SSHSentry provides a lightweight, portable solution that:

- **Detects** malicious IP addresses attempting brute-force attacks
- **Analyzes** authentication patterns to assess threat severity
- **Reports** findings in human-readable and machine-parseable formats
- **Operates** with zero external dependencies using only Python standard library

This tool is ideal for:
- 🔐 **Security Operations Centers (SOCs)** monitoring SSH access
- 🖥️ **System Administrators** hardening server security
- 📊 **Security Auditors** analyzing authentication patterns
- 🎓 **Cybersecurity Students** learning log analysis techniques

---

## ✨ Key Features

### Core Capabilities
- ✅ **Zero Dependencies**: Uses only Python standard library (no pip install required)
- ✅ **Object-Oriented Design**: Clean, maintainable architecture with separation of concerns
- ✅ **Type Hinting**: Full type annotations for better code quality and IDE support
- ✅ **Comprehensive Error Handling**: Graceful handling of file permissions and missing files
- ✅ **Multiple Export Formats**: CSV, JSON, and console output
- ✅ **PEP 8 Compliant**: Professional code styling and documentation
- ✅ **Production Ready**: Suitable for deployment in enterprise environments

### Analysis Features
- 🎯 **Smart Pattern Recognition**: Multiple regex patterns to catch various log formats
- 📈 **Threat Severity Levels**: Automatic classification (LOW, MEDIUM, HIGH, CRITICAL)
- 👥 **Username Tracking**: Identifies targeted user accounts
- ⏰ **Temporal Analysis**: Tracks first and last seen timestamps
- 📊 **Statistical Summary**: Comprehensive overview of attack patterns

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Read access to authentication logs (typically `/var/log/auth.log` or `/var/log/secure`)

### Installation

No installation required! Simply clone or download the repository:

```bash
git clone https://github.com/Kirat0201/SSHSentry.git
cd SSHSentry
```

### Basic Usage

1. **Generate test data** (for demonstration):
```bash
python generate_test_logs.py --output auth.log --lines 1000
```

2. **Run the analysis**:
```bash
python ssh_sentry.py --file auth.log --threshold 5
```

3. **Export results**:
```bash
# Export to CSV
python ssh_sentry.py --file auth.log --threshold 10 --output csv --output-file threats.csv

# Export to JSON
python ssh_sentry.py --file auth.log --threshold 10 --output json --output-file threats.json

# Export to both formats
python ssh_sentry.py --file auth.log --threshold 10 --output both --output-file threats
```

### Real-World Usage

**Analyze your actual auth logs** (requires sudo on most systems):

```bash
# On Debian/Ubuntu systems
sudo python ssh_sentry.py --file /var/log/auth.log --threshold 5

# On RedHat/CentOS systems
sudo python ssh_sentry.py --file /var/log/secure --threshold 5

# Lower threshold for stricter detection
sudo python ssh_sentry.py --file /var/log/auth.log --threshold 3 --output csv --output-file daily_threats.csv
```

---

## 📖 Usage Examples

### Example 1: Basic Console Output
```bash
python ssh_sentry.py --file auth.log --threshold 5
```

**Output:**
```
================================================================================
              SSHSENTRY - THREAT ANALYSIS REPORT
================================================================================

Generated: 2024-11-22 16:00:00

--------------------------------------------------------------------------------
SUMMARY STATISTICS
--------------------------------------------------------------------------------
Total Failed Attempts: 715
Unique Source IPs: 7
Flagged IPs (≥5 attempts): 7

--------------------------------------------------------------------------------
DETECTED THREATS (Sorted by Severity)
--------------------------------------------------------------------------------

IP Address         Attempts   Threat     Usernames            Last Seen
--------------------------------------------------------------------------------
185.220.101.45     214        CRITICAL   root, admin, test... Nov 22 15:45:12
45.155.205.33      178        CRITICAL   root, postgres, o... Nov 22 15:44:58
103.99.0.122       143        HIGH       admin, git, ubunt... Nov 22 15:43:22
198.98.51.189      107        HIGH       root, mysql, apac... Nov 22 15:42:45
91.240.118.168     36         MEDIUM     test, user, ftpus... Nov 22 15:41:30
139.59.47.201      21         MEDIUM     root, admin          Nov 22 15:40:15
159.65.88.43       14         LOW        admin, guest         Nov 22 15:39:00

================================================================================
⚠ WARNING: 7 potential brute-force sources detected!
================================================================================
```

### Example 2: Generate Custom Test Data
```bash
# Generate 5000 lines with 80% attack traffic
python generate_test_logs.py --output large_test.log --lines 5000 --attack-ratio 0.8

# Generate logs for a specific hostname
python generate_test_logs.py --output prod_server.log --lines 2000 --hostname prod-web-01
```

### Example 3: Automated Daily Reporting
Create a bash script for daily analysis:

```bash
#!/bin/bash
# daily_ssh_analysis.sh

DATE=$(date +%Y-%m-%d)
LOG_FILE="/var/log/auth.log"
OUTPUT_DIR="/var/log/ssh_sentry"

mkdir -p "$OUTPUT_DIR"

python /path/to/ssh_sentry.py \
    --file "$LOG_FILE" \
    --threshold 5 \
    --output both \
    --output-file "$OUTPUT_DIR/threats_$DATE"

echo "Analysis complete. Reports saved to $OUTPUT_DIR"
```

---

## 🔍 Technical Deep Dive

### Architecture Overview

SSHSentry follows **Object-Oriented Programming** principles with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                     SSHSentry                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐    ┌──────────────────┐                │
│  │   LogParser    │───▶│ ThreatAnalyzer   │                │
│  └────────────────┘    └──────────────────┘                │
│         │                       │                            │
│         │                       ▼                            │
│         │              ┌──────────────────┐                 │
│         │              │ ReportGenerator  │                 │
│         │              └──────────────────┘                 │
│         │                       │                            │
│         ▼                       ▼                            │
│  [Failed Attempts]    [Console/CSV/JSON Output]            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Class Descriptions

#### 1. **LogParser**
- **Purpose**: Parses authentication logs using regex patterns
- **Key Methods**:
  - `parse_log_file()`: Main parsing logic
  - `_parse_line()`: Regex matching for individual log lines
  - `_validate_file()`: Pre-execution file validation
- **Error Handling**: FileNotFoundError, PermissionError

#### 2. **ThreatAnalyzer**
- **Purpose**: Aggregates failed attempts and identifies threats
- **Key Methods**:
  - `analyze_attempts()`: Groups attempts by IP and applies threshold
  - `_generate_threat_report()`: Creates detailed threat profiles
  - `get_statistics()`: Computes overall metrics
- **Algorithm**: Threshold-based detection with severity classification

#### 3. **ReportGenerator**
- **Purpose**: Formats and exports analysis results
- **Key Methods**:
  - `print_console_report()`: Human-readable table output
  - `export_to_csv()`: Machine-readable CSV format
  - `export_to_json()`: Structured JSON with metadata
- **Output Options**: Console, CSV, JSON, or combination

### Regex Pattern Explanation

The tool uses **four sophisticated regex patterns** to capture failed SSH authentication attempts:

#### Pattern 1: Failed Password Attempts
```regex
(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?
Failed password for (?:invalid user )?(?P<username>\S+) from 
(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)
```

**Explanation:**
- `(?P<timestamp>...)` - Captures timestamp in format "Nov 22 14:30:45"
- `Failed password for` - Literal match for failed password event
- `(?:invalid user )?` - Optional "invalid user" prefix (non-capturing group)
- `(?P<username>\S+)` - Captures the username (non-whitespace characters)
- `(?P<ip>\d+\.\d+\.\d+\.\d+)` - Captures IPv4 address (quad-dotted notation)
- `port (?P<port>\d+)` - Captures the source port number

**Example Matches:**
```
Nov 22 14:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2
Nov 22 14:31:12 server sshd[1235]: Failed password for invalid user admin from 10.0.0.50 port 60000 ssh2
```

#### Pattern 2: Authentication Failures
```regex
(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?
authentication failure.*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)
(?:.*?user=(?P<username>\S+))?
```

**Explanation:**
- `authentication failure` - PAM authentication failure indicator
- `rhost=(?P<ip>...)` - Remote host IP address
- `(?:.*?user=(?P<username>\S+))?` - Optional username capture

**Example Match:**
```
Nov 22 14:32:00 server sshd[1236]: PAM 2 more authentication failure; rhost=203.0.113.45 user=admin
```

#### Pattern 3: Invalid User Detection
```regex
(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?
Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)
```

**Explanation:**
- `Invalid user` - Indicates attempted login with non-existent account
- Captures username and source IP

**Example Match:**
```
Nov 22 14:33:15 server sshd[1237]: Invalid user hacker from 198.51.100.42 port 44444
```

#### Pattern 4: Pre-Authentication Connection Closures
```regex
(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?
Connection closed by (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+)
.*?preauth
```

**Explanation:**
- `Connection closed by` - Connection terminated before authentication
- `[preauth]` - Pre-authentication phase (common in brute-force)

**Example Match:**
```
Nov 22 14:34:20 server sshd[1238]: Connection closed by authenticating user root 172.16.0.99 port 33333 [preauth]
```

### Threat Level Classification

| Threat Level | Failed Attempts | Action Recommended |
|--------------|----------------|-------------------|
| **CRITICAL** | ≥ 100 attempts | Immediate IP blocking, incident response |
| **HIGH**     | 50-99 attempts | Add to watchlist, consider blocking |
| **MEDIUM**   | 20-49 attempts | Monitor closely, review firewall rules |
| **LOW**      | 5-19 attempts  | Log for analysis, no immediate action |

---

## 📁 File Structure

```
SSHSentry/
│
├── ssh_sentry.py               # Main analysis tool (SOC-ready)
├── generate_test_logs.py       # Test data generator
├── README.md                   # This documentation
├── LICENSE                     # Apache 2.0 License
│
└── (Generated Files)
    ├── auth.log              # Sample log data (after running generator)
    ├── threats.csv           # CSV export (after analysis)
    └── threats.json          # JSON export (after analysis)
```

---

## 🛠️ Command-Line Options

### ssh_sentry.py

| Option | Required | Description | Default |
|--------|----------|-------------|---------|
| `--file` | Yes | Path to authentication log file | - |
| `--threshold` | No | Minimum failed attempts to flag IP | 5 |
| `--output` | No | Export format: `csv`, `json`, or `both` | None (console only) |
| `--output-file` | No | Output file path (base name for `both`) | threats |
| `--version` | No | Show version information | - |

### generate_test_logs.py

| Option | Required | Description | Default |
|--------|----------|-------------|---------|
| `--output` | No | Output file path | auth.log |
| `--lines` | No | Total number of log lines | 1000 |
| `--attack-ratio` | No | Ratio of attack to legitimate traffic (0.0-1.0) | 0.7 |
| `--hostname` | No | Hostname in log entries | sentry-test |

---

## 🧪 Testing Workflow

### Step 1: Generate Test Data
```bash
python generate_test_logs.py --output test_auth.log --lines 2000
```

**Expected Output:**
```
SSHSentry - Dummy Log Generator
==================================================
Generating 2000 log entries...

✓ Generated 2000 log entries
✓ Saved to: /path/to/test_auth.log

Log Statistics:
  - Total lines: 2000
  - Attack lines: ~1400
  - Legitimate lines: ~600
  - Malicious IPs: 7

Malicious IPs in dataset:
  - 185.220.101.45
  - 103.99.0.122
  - 45.155.205.33
  - 198.98.51.189
  - 91.240.118.168
  - 139.59.47.201
  - 159.65.88.43
```

### Step 2: Run Analysis
```bash
python ssh_sentry.py --file test_auth.log --threshold 10
```

### Step 3: Export Results
```bash
python ssh_sentry.py --file test_auth.log --threshold 10 --output both --output-file results
```

### Step 4: Verify Outputs
```bash
# Check CSV export
cat results.csv

# Check JSON export
cat results.json | python -m json.tool
```

---

## 🔒 Security Considerations

### Safe Usage
- ✅ **No External Dependencies**: Eliminates supply chain attack risks
- ✅ **Read-Only Operations**: Tool never modifies log files
- ✅ **Input Validation**: All file paths and arguments validated
- ✅ **Error Handling**: Prevents information leakage through exceptions

### Best Practices
1. **Run with Least Privilege**: Use `sudo` only when necessary
2. **Secure Output Files**: Restrict permissions on CSV/JSON exports
3. **Regular Analysis**: Run daily to detect emerging threats
4. **Combine with Firewall**: Integrate findings with iptables/firewalld
5. **False Positive Review**: Always verify before blocking IPs

### Limitations
- Does not automatically block IPs (by design for safety)
- Requires read access to system logs
- Regex patterns may need adjustment for custom log formats
- Timestamp parsing assumes standard syslog format

---

## 📊 Sample Output Formats

### Console Output
Clear, executive-friendly summary with color coding and severity indicators.

### CSV Format
```csv
ip_address,failed_attempts,threat_level,usernames_targeted,first_seen,last_seen
185.220.101.45,214,CRITICAL,"root, admin, test",Nov 22 14:15:30,Nov 22 15:45:12
45.155.205.33,178,CRITICAL,"root, postgres, oracle",Nov 22 14:18:22,Nov 22 15:44:58
```

### JSON Format
```json
{
  "metadata": {
    "generated_at": "2024-11-22T16:00:00",
    "tool": "SSHSentry",
    "version": "1.0.0"
  },
  "statistics": {
    "total_failed_attempts": 715,
    "unique_ips": 7,
    "flagged_ips": 7,
    "threshold": 5
  },
  "threats": [
    {
      "ip_address": "185.220.101.45",
      "failed_attempts": 214,
      "threat_level": "CRITICAL",
      "usernames_targeted": ["root", "admin", "test"],
      "first_seen": "Nov 22 14:15:30",
      "last_seen": "Nov 22 15:45:12"
    }
  ]
}
```

---

## 🤝 Contributing

Contributions are welcome! This project maintains high standards:

- **Code Style**: PEP 8 compliant
- **Type Hints**: Required for all functions
- **Documentation**: Comprehensive docstrings
- **Testing**: Validate with dummy data generator
- **No Dependencies**: Standard library only

---

## 📜 License

This project is licensed under the APACHE 2.0 License. See [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Harkirat Kalra**

---

## 🎓 Educational Value

This project demonstrates:
- ✅ **Professional Python Architecture**: OOP, type hints, dataclasses
- ✅ **Regex Mastery**: Complex pattern matching with named groups
- ✅ **Error Handling Best Practices**: Proper exception hierarchy
- ✅ **Logging Standards**: Production-ready logging configuration
- ✅ **CLI Design**: User-friendly argparse implementation
- ✅ **Data Processing**: Aggregation, sorting, and statistical analysis
- ✅ **Multiple Output Formats**: CSV, JSON, and formatted console output
- ✅ **Security Awareness**: Authentication log analysis techniques

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Review the Technical Deep Dive section
- Check command-line help: `python ssh_sentry.py --help`

---

## 🚀 Future Enhancements

Potential additions (maintaining zero-dependency philosophy):
- [ ] Support for multiple log file formats (Windows Event Logs)
- [ ] Real-time log monitoring with file watching
- [ ] GeoIP lookup integration (optional module)
- [ ] Automatic firewall rule generation (safety-checked)
- [ ] Historical trend analysis
- [ ] Email alerting for critical threats

---

**⚡ Start protecting your SSH infrastructure today!**

```bash
python generate_test_logs.py --output auth.log
python ssh_sentry.py --file auth.log --threshold 5
```

---

*Built with 🛡️ for the cybersecurity community*
