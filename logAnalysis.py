import re

def analyze_logs(log_file):
    suspicious_patterns = [
        r'(?i)password\s*=\s*[\'"].*?[\'"]',  # Detecting password leakage
        r'(?i)user\s*=\s*[\'"].*?[\'"]',      # Detecting username leakage
        r'(?i)access\s*denied',               # Detecting failed login attempts
        r'(?i)failed\s*password\s*for',      # Detecting failed login attempts
        r'(?i)(sql|code)\s*injection',       # Detecting SQL or code injection attempts
    ]

    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            for pattern in suspicious_patterns:
                if re.search(pattern, line):
                    print(f"Suspicious activity detected in line {line_num}:")
                    print(line.strip())
                    print("-" * 50)

# Example usage:
if __name__ == "__main__":
    log_file = "path/to/your/log/file.log"
    analyze_logs(log_file)