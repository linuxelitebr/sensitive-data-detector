# Sensitive Data Detector

Script to scan directories for sensitive data like tokens, passwords, and pull-secrets.

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
- Sensitive data in **images** (JPG, PNG, BMP, TIFF) using OCR
- Sensitive data in **SVG files**

## Features

- Recursive directory scanning
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

WARNING: FOUND 3 POTENTIAL SENSITIVE DATA:

Type: AWS Access Key
File: /path/to/your/project/config.py
Line: 15
Content: aws_access_key = "AKEXAMPLE"
--------------------------------------------------------------------------------
Type: Base64 Credentials
File: /path/to/your/project/setup.sh
Line: 42
Content: username: cnxJFsuaYaQ==
--------------------------------------------------------------------------------
Type: iDRAC/BMC Address
File: /path/to/your/project/screenshot.png
Line: N/A (OCR)
Content: address: idrac-virtualmedia://X.X.X.X/redfish/v1/Systems/System.Embedded.1
--------------------------------------------------------------------------------
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
username: admin
password: secret
```

**Base64 encoded credentials:**
```
username: auqwejahe
password: cKjHgTyVg==
```

**Management interfaces:**
```
address: idrac-virtualmedia://x.x.x.x/redfish/v1/Systems/System.Embedded.1
```

**API tokens and keys:**
```
api_key: AK51H8x2KL78R0
bearer_token: Bearer eyJhbGIINiIgsIndRs5scsCsIs6sIsks9...
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

## Important Notes

- The script may produce false positives - review all findings manually
- OCR accuracy depends on image quality and text clarity
- Base64 detection may match non-credential data (review context)
- Private IPs are flagged but may be legitimate internal addresses
- Always verify findings before taking action
