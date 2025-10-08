#!/usr/bin/env python3
# Usage: python sensitive-data-detector.py <directory>
# Image OCR requisites: pillow pytesseract
"""
Script to detect sensitive data in files and images (using OCR)
"""
import os
import re
import sys
from pathlib import Path

# Try to import OCR libraries
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# Sensitive data patterns
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
}

# Extensions to ignore for text scanning
IGNORE_EXTENSIONS = {'.exe', '.bin', '.so', '.dll', '.pyc', '.class', '.zip', '.tar', '.gz', 
                     '.pdf', '.doc', '.docx', '.xls', '.xlsx'}

# Image extensions to scan with OCR
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif'}

# SVG is text-based, so we can read it directly
SVG_EXTENSION = '.svg'

# Directories to ignore
IGNORE_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

def should_scan_file(file_path):
    """Check if file should be scanned"""
    ext = file_path.suffix.lower()
    
    if ext in IGNORE_EXTENSIONS:
        return False, None
    
    if ext in IMAGE_EXTENSIONS:
        return True, 'image'
    
    if ext == SVG_EXTENSION:
        return True, 'svg'
    
    # Ignore very large files (>10MB) for text files
    try:
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return False, None
    except:
        return False, None
    
    return True, 'text'

def extract_text_from_image(file_path):
    """Extract text from image using OCR"""
    if not OCR_AVAILABLE:
        return None
    
    try:
        image = Image.open(file_path)
        text = pytesseract.image_to_string(image)
        return text
    except Exception as e:
        return None

def scan_content(content, file_path, file_type='text'):
    """Scan content for sensitive data"""
    findings = []
    
    if not content:
        return findings
    
    for secret_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            if file_type == 'image':
                # For images, we don't have line numbers
                findings.append({
                    'type': secret_type,
                    'file': str(file_path),
                    'line': 'N/A (OCR)',
                    'content': match.group()[:100]
                })
            else:
                # Find line number for text files
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract complete line
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
    """Scan a file for sensitive data"""
    findings = []
    
    try:
        if file_type == 'image':
            # Extract text from image using OCR
            content = extract_text_from_image(file_path)
            if content:
                findings = scan_content(content, file_path, 'image')
        
        elif file_type in ['text', 'svg']:
            # Read text files and SVG directly
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            findings = scan_content(content, file_path, file_type)
    
    except Exception as e:
        pass  # Ignore read errors
    
    return findings

def scan_directory(directory):
    """Scan directory recursively"""
    all_findings = []
    scanned_files = 0
    skipped_images = 0
    
    for root, dirs, files in os.walk(directory):
        # Remove ignored directories from search
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            file_path = Path(root) / file
            
            should_scan, file_type = should_scan_file(file_path)
            
            if should_scan:
                if file_type == 'image' and not OCR_AVAILABLE:
                    skipped_images += 1
                    continue
                
                scanned_files += 1
                findings = scan_file(file_path, file_type)
                all_findings.extend(findings)
    
    return all_findings, scanned_files, skipped_images

def main():
    if len(sys.argv) < 2:
        print("Usage: python sensitive-data-detector.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory")
        sys.exit(1)
    
    if not OCR_AVAILABLE:
        print("WARNING: OCR libraries not installed. Image scanning disabled.")
        print("To enable image scanning, install: pip install pillow pytesseract")
        print("Also install tesseract-ocr on your system.\n")
    
    print(f"Scanning: {directory}\n")
    
    findings, scanned_files, skipped_images = scan_directory(directory)
    
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

if __name__ == '__main__':
    main()
