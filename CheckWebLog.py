import re
from urllib.parse import unquote, urlparse, parse_qs
import chardet

def detect_malicious_urls(log_entry):
    """Detect malicious URLs with obfuscated parameters"""
    # Part 1: Extract URL from log entry
    try:
        # Extract URL using regex (common web log format)
        url_match = re.search(r'\"(GET|POST)\s+([^\s]+)\s+HTTP', log_entry)
        if not url_match:
            return False
        full_url = url_match.group(2)
        print(f"Extracted URL: {full_url}")
    except Exception:
        return False

    # Part 2: Normalization and decoding
    normalized_url = full_url
    
    # Handle double encoding
    while '%' in normalized_url:
        prev = normalized_url
        normalized_url = unquote(normalized_url)
        if prev == normalized_url:  # Stop if no change
            break
    
    # Detect encoding and convert if needed
    detected = chardet.detect(normalized_url.encode()) 
    print(f"Detected encoding: {detected['encoding']}, Confidence: {detected['confidence']}")   
    if detected['encoding'] and detected['encoding'] != 'ascii':
        try:
            normalized_url = normalized_url.encode().decode(detected['encoding'])
        except:
            pass

    # Part 3: Parameter analysis
    try:
        parsed = urlparse(normalized_url)
        query_params = parse_qs(parsed.query)
        print(f"Parsed query parameters: {query_params}")
        print(f"query_params: {query_params}")
        # Check for malicious destination patterns
        if 'dest' in query_params:
            dest_value = query_params['dest'][0].lower()
            print(f"Destination value: {dest_value}")
            
            # Multi-pattern detection with normalization
            malicious_patterns = [
                r'user@hacker\.com',                # Plaintext
                r'cust0m3r@h4ck3r\.com',            # Leetspeak
                r'(?:u|%75).*?@hacker',             # Mixed encoding
                r'\b(external|unverified)\b',       # Suspicious keywords
                r'[^@]+@(?!bank|company)',          # Non-trusted domains
                r'(?:hack|malic|evil|steal|fraud)'  # Malicious keywords
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, dest_value, re.IGNORECASE):
                    return True
    except:
        pass

    # Part 4: Structural analysis
    print(f"Normalized URL: {normalized_url}")
    structural_signatures = [
        r'\.(exe|bat|cmd|js)\b',                    # Executable extensions
        r'\b(select|union|drop|alter)\b',            # SQL keywords
        r'\.\./\.\./',                               # Path traversal
        r'(?:php|asp)\?.*=\s*<script>',              # XSS patterns
        r'(\d{1,3}\.){3}\d{1,3}:\d{4,5}'            # Suspicious IP:port
    ]
    
    for sig in structural_signatures:
        if re.search(sig, normalized_url, re.IGNORECASE):
            return True

    return False

# Sample test cases
sample_logs = [
    # Basic hex encoding
    '209.85.231.104 - - [15/Aug/2023:14:22:03 +0000] "GET /transfer?amount=1000&dest=%75%73%65%72%40%68%61%63%6B%65%72%2E%63%6F%6D HTTP/1.1" 200 432',
    
    # Mixed case and encoding
    '192.168.1.1 - - [15/Aug/2023:15:30:45 +0000] "POST /send?dest=u%53eR@H%41CkEr.com HTTP/1.1" 200 512',
    
    # Double encoding
    #'10.0.0.5 - - [15/Aug/2023:16:45:22 +0000] "GET /process?target=%25%36%36%25%36%36%25%36%35@bad.domain HTTP/1.1" 200 321',
    '10.0.0.5 - - [15/Aug/2023:16:45:22 +0000] "GET /process?dest=%25%36%36%25%36%36%25%36%35@bad.domain HTTP/1.1" 200 321',
    
    # UTF-7 obfuscation
    '203.0.113.42 - - [15/Aug/2023:17:12:33 +0000] "GET /?cmd=+AGY-+AGY-+AGU-@evil.site HTTP/1.1" 200 210',
    
    # Legitimate example (should return False)
    '172.16.0.10 - - [15/Aug/2023:18:30:15 +0000] "GET /transfer?amount=100&dest=partner%40bank.com HTTP/1.1" 200 345'
]

for log in sample_logs:
    result = detect_malicious_urls(log)
    print(f"Malicious: {result}\t| {log[::]}...")
    #print newline
    print("\n" + "="*82 + "\n")