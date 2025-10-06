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
- Passwords in code
- Private SSH/RSA Keys
- Docker Pull Secrets
- Generic secrets and tokens

## Features

- Recursive directory scanning
- Ignores binary files and common build directories
- Shows file path, line number, and content preview
- Skips large files (>10MB)

## Example

```bash
python sensitive-data-detector.py /path/to/your/project
```

Output:
```
Scanning: /path/to/your/project

WARNING: FOUND 2 POTENTIAL SENSITIVE DATA:

Type: AWS Access Key
File: /path/to/your/project/config.py
Line: 15
Content: aws_access_key = "AKIAIOSFODNN7EXAMPLE"
--------------------------------------------------------------------------------
```

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)
