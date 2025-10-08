# Sensitive Data Detector

Script to scan directories for sensitive data like tokens, passwords, secrets and others.

## Usage

```bash
python sensitive-data-detector.py <directory>
```

## What it detects

- AWS Access Keys and Secret Keys
- GitHub Tokens
- JWT Tokens
- API Keys
- Bearer Tokens
- **Passwords and Usernames** (plaintext and base64 encoded)
- Private SSH/RSA Keys
- Docker Pull Secrets
- Generic secrets and tokens
- **Management Interface URLs** (iDRAC, iLO, IPMI, BMC)
- **Private IP Addresses**
- **Email Addresses**
- **Internal System URLs** (localhost, .local, .internal, .corp, .lan domains)
- Sensitive data in **images** (JPG, PNG, BMP, TIFF) using OCR
- Sensitive data in **SVG files**

## Features

- Recursive directory scanning
- **Real-time feedback** - shows progress and identifies when scanning images with OCR
- **Automatic summary report** - categorizes findings by severity (critical vs infrastructure)
- Ignores binary files and common build directories
- Shows file path, line number, and content preview
- Skips large files (>10MB)
- **OCR support for images** - detects sensitive data in screenshots and images
- **SVG text extraction** - scans vector images containing text

## Example

```bash
python sensitive-data-detector.py /path/to/your/project
```

Output:
```
Scanning: /path/to/your/project
OCR Status: Enabled (images will be scanned)

Found 45 files to scan...

[1/45] Scanning: config.py
[2/45] Scanning: setup.sh - FOUND 1 alert(s)
[3/45] Scanning: screenshot.png (OCR) - FOUND 2 alert(s)
[4/45] Scanning: logo.svg (SVG)
[5/45] Scanning: deployment.yaml - FOUND 1 alert(s)
...

WARNING: FOUND 3 POTENTIAL SENSITIVE DATA:

Type: AWS Access Key
File: /path/to/your/project/config.py
Line: 15
Content: aws_access_key = "AKIAIOSFODNN7EXAMPLE"
--------------------------------------------------------------------------------
Type: Base64 Credentials
File: /path/to/your/project/setup.sh
Line: 42
Content: username: dXNlcjEyMzQ=
--------------------------------------------------------------------------------
Type: iDRAC/BMC Address
File: /path/to/your/project/screenshot.png
Line: N/A (OCR)
Content: address: idrac-virtualmedia://10.0.0.100/redfish/v1/Systems/System.Embedded.1
--------------------------------------------------------------------------------

Statistics:
   Files scanned: 45
   Alerts found: 3

================================================================================
SUMMARY:
================================================================================
CRITICAL: This repository contains sensitive customer data, such as passwords, 
tokens, secrets. It also contains email addresses, sensitive infrastructure 
information (IPs, hostnames, internal URLs).
================================================================================
```

## Requirements

- Python 3.6+
- No external dependencies for basic text scanning

### Optional (for image scanning):
```bash
pip install pillow pytesseract
```

Also install tesseract-ocr on your system:
- **Ubuntu/Debian**: `sudo apt-get install tesseract-ocr`
- **macOS**: `brew install tesseract`
- **Windows**: Download from [GitHub](https://github.com/UB-Mannheim/tesseract/wiki)

The script will work without these dependencies but will skip image files.

## Detection Examples

The script can detect various formats of sensitive data:

**Plaintext credentials:**
```
username: john_doe
password: MyP@ssw0rd2024
```

**Base64 encoded credentials:**
```
username: dXNlcjEyMzQ=
password: cGFzc3dvcmQxMjM0NQ==
```

**Management interfaces:**
```
address: idrac-virtualmedia://10.0.0.100/redfish/v1/Systems/System.Embedded.1
```

**API tokens and keys:**
```
api_key: eHqLyjDrjtT1zdp7dc
bearer_token: Bearer eyJhbcOIzNiIsInR5cCI6IkpXVCJ9...
```

**Email addresses:**
```
user@example.com
support@test-system.local
```

**Internal system URLs:**
```
https://gitlab.internal:8080/project/repo
http://jenkins.corp/job/deploy
https://192.168.0.50:3000/admin
http://localhost:8080/api/secrets
```

**In images (with OCR enabled):** The script can detect all the above patterns even when they appear in screenshots or photos.

## Customization

You can easily add custom detection patterns by editing the `PATTERNS` dictionary in the script:

```python
PATTERNS = {
    'Your Custom Pattern': r'your_regex_pattern_here',
    # ... other patterns
}
```

## Summary Reports

At the end of each scan, the script provides a categorized summary:

**No sensitive data found:**
```
This repository does not contain obvious sensitive customer data such as 
passwords, tokens, or secrets.
```

**Infrastructure data only:**
```
This repository does not contain customer data such as passwords, tokens, 
and secrets. However, it does contain email addresses, sensitive infrastructure 
information (IPs, hostnames, internal URLs).
```

**Critical data found:**
```
CRITICAL: This repository contains sensitive customer data, such as passwords, 
tokens, secrets. It also contains email addresses, sensitive infrastructure 
information (IPs, hostnames, internal URLs).
```

## Important Notes

- The script may produce false positives - review all findings manually
- OCR accuracy depends on image quality and text clarity
- Base64 detection may match non-credential data (review context)
- Private IPs are flagged but may be legitimate internal addresses
- **Email addresses** may include legitimate contact info in documentation
- **Internal URLs** detection helps identify exposed internal infrastructure references
- Always verify findings before taking action
