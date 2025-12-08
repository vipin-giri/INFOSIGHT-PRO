# INFOSIGHT - Advanced Information Disclosure Scanner

**INFOSIGHT** is a powerful, open-source security scanning tool designed to detect information disclosure vulnerabilities in web applications. It performs comprehensive analysis of HTTP headers, HTML content, sensitive endpoints, and more to identify potential security risks.

## Features

### Core Scanning Capabilities
- **Header Analysis**: Detects version leaks in Server, X-Powered-By, and other HTTP headers
- **HTML Deep Scanning**: Analyzes meta tags, comments, error messages, robots.txt, and sitemap.xml
- **Sensitive Endpoint Detection**: Checks for exposed configuration files (.env, .git/config, etc.)
- **Secrets & Credentials Detection**: Identifies API keys, JWT tokens, and hardcoded secrets
- **Cloud Storage Scanning**: Detects exposed S3, GCS, and Azure Blob Storage URLs
- **Private IP Disclosure**: Finds internal IP addresses in responses

### Advanced Features
- **Automatic Web Crawling**: Discovers and scans all pages within a domain
- **Configurable Crawl Depth**: Control crawl depth and maximum pages to scan
- **Multi-threading**: Scan multiple targets simultaneously
- **Active Fingerprinting**: Test sensitive endpoints for accessibility
- **SSL Verification Control**: Option to disable SSL verification for testing

### Export Formats
- **JSON**: Detailed structured output
- **CSV**: Spreadsheet-compatible format with aggregated findings
- **Excel (XLSX)**: Color-coded report with severity indicators
- **TXT**: Plain text report for easy reading

## Installation

### Requirements
- Python 3.7+
- pip (Python package manager)

### Setup

1. **Clone or download the repository**:
   ```bash
   git clone https://github.com/vipin-giri/INFOSIGHT-PRO.git
   cd INFOSIGHT-PRO
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Optional: For Excel export support, install openpyxl:
   ```bash
   pip install openpyxl
   ```

## Usage

### Basic Scanning

Scan a single URL:
```bash
python infosight.py -u https://example.com
```

### Scan Multiple Targets

Scan targets from a file (one URL per line):
```bash
python infosight.py -f targets.txt
```

### Command-Line Options

```
-u, --url URL              Target URL (e.g., https://example.com)
-f, --file FILE            File containing list of targets (one per line)
--no-verify                Skip SSL certificate verification
--show-mitigation          Show mitigation tips for vulnerabilities
--only-vuln                Show only vulnerable targets
--no-crawl                 Disable web crawling (scan only initial page)
--deep                     Enable deep scanning (enabled by default)
--no-deep                  Disable deep scanning
--active                   Active fingerprinting (test sensitive endpoints)
--max-pages N              Maximum pages to crawl per domain
--max-depth N              Maximum crawl depth (0=root only, 1=one hop, etc.)
--threads N                Number of concurrent threads (default: 5)
-o, --output FILE          Export results to file (json/csv/xlsx/txt)
-h, --help                 Show help message
```

### Examples

**Scan with crawling and export results**:
```bash
python infosight.py -u https://example.com -o results.json
```

**Quick scan without crawling**:
```bash
python infosight.py -u https://example.com --no-crawl
```

**Active fingerprinting with crawling**:
```bash
python infosight.py -u https://example.com --active --max-pages 50
```

**Scan with SSL verification disabled**:
```bash
python infosight.py -u https://example.com --no-verify
```

**Export to Excel with mitigation tips**:
```bash
python infosight.py -f targets.txt --show-mitigation -o report.xlsx
```

## Vulnerability Types

### Header-Based Vulnerabilities
- **Server Header Version Disclosure**: Exposed application server versions
- **X-Powered-By Leaks**: Framework and version information
- **Backend Server Information**: Internal server details

### Content-Based Vulnerabilities
- **Meta Generator Tags**: CMS and version information
- **HTML Comments**: Sensitive comments left in production code
- **Error Messages**: Stack traces and detailed error information
- **Directory Listing**: Enabled directory browsing

### Endpoint Vulnerabilities
- **Sensitive File Exposure**: .env, .git/config, composer.json, etc.
- **Backup Files**: SQL backups, zip archives
- **Configuration Files**: web.config, .htaccess, php.ini
- **Git/SVN Metadata**: Version control information

### Secret Detection
- **API Keys**: AWS, Google, Slack tokens
- **JWT Tokens**: Authentication tokens in responses
- **Cloud Storage URLs**: S3, GCS, Azure Blob Storage
- **Private IPs**: Internal IP addresses
- **Email Addresses**: Exposed contact information

## Severity Levels

- **High**: Critical information disclosure (API keys, secrets, file access)
- **Medium**: Important leaks (version info, internal IPs, backup files)
- **Low**: Minor information leaks (meta tags, low-risk endpoints)

## Mitigation Recommendations

INFOSIGHT provides automated mitigation tips including:
- Header hardening and obfuscation
- Reverse proxy configuration
- Error message customization
- Sensitive file protection
- Secret management best practices

Use the `--show-mitigation` flag to display detailed recommendations.

## Output Examples

### Console Output
```
[HIGH] Header: Server
  Value: Apache/2.4.41 (Ubuntu)
  Evidence: 2.4.41

[MEDIUM] Private IP
  Details: 192.168.1.100

[HIGH] API key
  Details: AKIA1234567890ABCDEF
```

### JSON Export
```json
[
  {
    "url": "https://example.com",
    "vulnerable": true,
    "findings": [
      {
        "type": "header",
        "header": "Server",
        "value": "Apache/2.4.41 (Ubuntu)",
        "severity": "High"
      }
    ],
    "timestamp": "2025-12-08 10:30:45"
  }
]
```

## Performance Tips

1. **Use threading for multiple targets**: Default is 5 threads, increase if scanning many URLs
   ```bash
   python infosight.py -f targets.txt --threads 10
   ```

2. **Limit crawl scope**: Use `--max-pages` and `--max-depth` to speed up large sites
   ```bash
   python infosight.py -u https://example.com --max-pages 100 --max-depth 2
   ```

3. **Disable unnecessary features**: Use `--no-deep` or `--no-crawl` for faster scanning
   ```bash
   python infosight.py -u https://example.com --no-crawl --no-deep
   ```

## Legal & Ethical Use

**IMPORTANT**: INFOSIGHT is intended for authorized security testing only. Unauthorized scanning of websites or networks is illegal. Always:

- Obtain proper authorization before scanning any target
- Comply with local laws and regulations
- Use responsibly in authorized penetration tests
- Respect privacy and data protection laws

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.

## Support

For issues, feature requests, or questions, please open an issue on GitHub.

## References

Security Standards and Best Practices:
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP Information Disclosure](https://owasp.org/www-community/attacks/Information_disclosure)
- [MDN HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/)

## Disclaimer

This tool is provided "as-is" without warranties. Users are responsible for ensuring their use of INFOSIGHT complies with all applicable laws and regulations. The authors are not liable for any misuse or damage caused by this tool.

---

**Version**: 1.0.0  
**License**: MIT  
**Author**: Vipin Giri
