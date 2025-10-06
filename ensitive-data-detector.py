#!/usr/bin/env python3
# Usage: python sensitive-data-detector.py <directory>
"""
Script to detect sensitive data in files
"""
import os
import re
import sys
from pathlib import Path

# Sensitive data patterns
PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws[_\-]?secret[_\-]?access[_\-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36,}',
    'Generic API Key': r'api[_\-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{20,}',
    'Bearer Token': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    'JWT Token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    'Password Field': r'password["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
    'Private Key': r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE KEY-----',
    'Docker Pull Secret': r'\.dockerconfigjson.*eyJ[A-Za-z0-9+/=]+',
    'Generic Secret': r'secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    'Token Generic': r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
}

# Extensions to ignore
IGNORE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz', 
                     '.exe', '.bin', '.so', '.dll', '.pyc', '.class'}

# Directories to ignore
IGNORE_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

def should_scan_file(file_path):
    """Check if file should be scanned"""
    if file_path.suffix.lower() in IGNORE_EXTENSIONS:
        return False
    
    # Ignore very large files (>10MB)
    try:
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return False
    except:
        return False
    
    return True

def scan_file(file_path):
    """Scan a file for sensitive data"""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        for secret_type, pattern in PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract complete line
                lines = content.split('\n')
                if line_num <= len(lines):
                    line_content = lines[line_num - 1].strip()
                    
                    findings.append({
                        'type': secret_type,
                        'file': str(file_path),
                        'line': line_num,
                        'content': line_content[:100]  # Limit to 100 chars
                    })
    except Exception as e:
        pass  # Ignore read errors
    
    return findings

def scan_directory(directory):
    """Scan directory recursively"""
    all_findings = []
    scanned_files = 0
    
    for root, dirs, files in os.walk(directory):
        # Remove ignored directories from search
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            file_path = Path(root) / file
            
            if should_scan_file(file_path):
                scanned_files += 1
                findings = scan_file(file_path)
                all_findings.extend(findings)
    
    return all_findings, scanned_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python sensitive-data-detector.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory")
        sys.exit(1)
    
    print(f"Scanning: {directory}\n")
    
    findings, scanned_files = scan_directory(directory)
    
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
    print(f"   Alerts found: {len(findings)}")

if __name__ == '__main__':
    main()
