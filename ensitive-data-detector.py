#!/usr/bin/env python3
# Usage: python sensitive-data-detector.py <directory>

import os
import re
import sys
from pathlib import Path

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws[_\-]?secret[_\-]?access[_\-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36,}',
    'Generic API Key': r'api[_\-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{20,}',
    'Bearer Token': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    'JWT Token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    'Password Field': r'password["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}',
    'Username Field': r'username["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}',
    'Private Key': r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE KEY-----',
    'Docker Pull Secret': r'\.dockerconfigjson.*eyJ[A-Za-z0-9+/=]+',
    'Generic Secret': r'secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    'Token Generic': r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
    'Base64 Credentials': r'(?:username|password|user|pass|passwd|pwd)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/]{8,}={0,2}',
    'iDRAC/BMC Address': r'(?:idrac|redfish|ipmi|ilo|bmc)(?:-virtualmedia)?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\s]*',
    'Private IP Address': r'(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})',
    'Email Address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Internal System URL': r'https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[\w-]+\.(?:local|internal|corp|lan))(?::\d+)?[^\s]*',
}

IGNORE_EXTENSIONS = {'.exe', '.bin', '.so', '.dll', '.pyc', '.class', '.zip', '.tar', '.gz', 
                     '.pdf', '.doc', '.docx', '.xls', '.xlsx'}

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif'}

SVG_EXTENSION = '.svg'

IGNORE_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

def should_scan_file(file_path):
    ext = file_path.suffix.lower()
    
    if ext in IGNORE_EXTENSIONS:
        return False, None
    
    if ext in IMAGE_EXTENSIONS:
        return True, 'image'
    
    if ext == SVG_EXTENSION:
        return True, 'svg'
    
    try:
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return False, None
    except:
        return False, None
    
    return True, 'text'

def extract_text_from_image(file_path):
    if not OCR_AVAILABLE:
        return None
    
    try:
        image = Image.open(file_path)
        text = pytesseract.image_to_string(image)
        return text
    except Exception as e:
        return None

def scan_content(content, file_path, file_type='text'):
    findings = []
    
    if not content:
        return findings
    
    for secret_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            if file_type == 'image':
                findings.append({
                    'type': secret_type,
                    'file': str(file_path),
                    'line': 'N/A (OCR)',
                    'content': match.group()[:100]
                })
            else:
                line_num = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                if line_num <= len(lines):
                    line_content = lines[line_num - 1].strip()
                    findings.append({
                        'type': secret_type,
                        'file': str(file_path),
                        'line': line_num,
                        'content': line_content[:100]
                    })
    
    return findings

def scan_file(file_path, file_type):
    findings = []
    
    try:
        if file_type == 'image':
            content = extract_text_from_image(file_path)
            if content:
                findings = scan_content(content, file_path, 'image')
        elif file_type in ['text', 'svg']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            findings = scan_content(content, file_path, file_type)
    except Exception as e:
        pass
    
    return findings

def scan_directory(directory):
    all_findings = []
    scanned_files = 0
    skipped_images = 0
    total_files = 0
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            file_path = Path(root) / file
            should_scan, file_type = should_scan_file(file_path)
            if should_scan:
                if file_type == 'image' and not OCR_AVAILABLE:
                    skipped_images += 1
                else:
                    total_files += 1
    
    print(f"Found {total_files} files to scan...\n")
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            file_path = Path(root) / file
            should_scan, file_type = should_scan_file(file_path)
            
            if should_scan:
                if file_type == 'image' and not OCR_AVAILABLE:
                    continue
                
                scanned_files += 1
                print(f"[{scanned_files}/{total_files}] Scanning: {file_path.name}", end='')
                
                if file_type == 'image':
                    print(" (OCR)", end='')
                elif file_type == 'svg':
                    print(" (SVG)", end='')
                
                findings = scan_file(file_path, file_type)
                
                if findings:
                    print(f" - FOUND {len(findings)} alert(s)")
                else:
                    print()
                
                all_findings.extend(findings)
    
    return all_findings, scanned_files, skipped_images

def generate_summary(findings):
    if not findings:
        return None
    
    critical_types = {
        'AWS Access Key', 'AWS Secret Key', 'GitHub Token', 'Generic API Key',
        'Bearer Token', 'JWT Token', 'Password Field', 'Private Key',
        'Docker Pull Secret', 'Generic Secret', 'Token Generic', 'Base64 Credentials'
    }
    
    infrastructure_types = {
        'Email Address', 'Private IP Address', 'iDRAC/BMC Address',
        'Internal System URL', 'Username Field'
    }
    
    critical_findings = []
    infrastructure_findings = []
    
    for finding in findings:
        finding_type = finding['type']
        if finding_type in critical_types:
            if finding_type not in critical_findings:
                critical_findings.append(finding_type)
        elif finding_type in infrastructure_types:
            if finding_type not in infrastructure_findings:
                infrastructure_findings.append(finding_type)
    
    summary_parts = []
    
    if critical_findings:
        credential_types = []
        if any(t in critical_findings for t in ['Password Field', 'Base64 Credentials']):
            credential_types.append('passwords')
        if any(t in critical_findings for t in ['AWS Access Key', 'AWS Secret Key', 'GitHub Token', 
                                                  'Generic API Key', 'Bearer Token', 'JWT Token', 'Token Generic']):
            credential_types.append('tokens')
        if any(t in critical_findings for t in ['Generic Secret', 'Docker Pull Secret', 'Private Key']):
            credential_types.append('secrets')
        
        summary_parts.append(
            f"CRITICAL: This repository contains sensitive customer data, such as {', '.join(credential_types)}."
        )
    
    if infrastructure_findings:
        infra_types = []
        if 'Email Address' in infrastructure_findings:
            infra_types.append('email addresses')
        if any(t in infrastructure_findings for t in ['Private IP Address', 'iDRAC/BMC Address', 'Internal System URL']):
            infra_types.append('sensitive infrastructure information (IPs, hostnames, internal URLs)')
        if 'Username Field' in infrastructure_findings:
            infra_types.append('usernames')
        
        if critical_findings:
            summary_parts.append(f"It also contains {', '.join(infra_types)}.")
        else:
            summary_parts.append(
                f"This repository does not contain customer data such as passwords, tokens, and secrets. "
                f"However, it does contain {', '.join(infra_types)}."
            )
    
    if not critical_findings and not infrastructure_findings:
        summary_parts.append(
            "This repository does not contain obvious sensitive customer data such as passwords, tokens, or secrets."
        )
    
    return ' '.join(summary_parts)

def main():
    if len(sys.argv) < 2:
        print("Usage: python sensitive-data-detector.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory")
        sys.exit(1)
    
    print(f"Scanning: {directory}")
    print(f"OCR Status: {'Enabled (images will be scanned)' if OCR_AVAILABLE else 'Disabled (images will be skipped)'}")
    
    if not OCR_AVAILABLE:
        print("To enable OCR: pip install pillow pytesseract")
    
    print()
    
    findings, scanned_files, skipped_images = scan_directory(directory)
    
    print()
    
    if findings:
        print(f"WARNING: FOUND {len(findings)} POTENTIAL SENSITIVE DATA:\n")
        
        for finding in findings:
            print(f"Type: {finding['type']}")
            print(f"File: {finding['file']}")
            print(f"Line: {finding['line']}")
            print(f"Content: {finding['content']}")
            print("-" * 80)
    else:
        print("No sensitive data detected!")
    
    print(f"\nStatistics:")
    print(f"   Files scanned: {scanned_files}")
    if skipped_images > 0:
        print(f"   Images skipped (OCR not available): {skipped_images}")
    print(f"   Alerts found: {len(findings)}")
    
    summary = generate_summary(findings)
    if summary:
        print(f"\n{'=' * 80}")
        print("SUMMARY:")
        print('=' * 80)
        print(summary)
        print('=' * 80)

if __name__ == '__main__':
    main()
