import json
from collections import defaultdict
import datetime

def parse_aws_waf_logs(file_path):
    """Parse AWS WAF log file"""
    logs = []
    blocked_ips = defaultdict(int)
    attack_types = defaultdict(int)
    malicious_agents = defaultdict(int)
    
    with open(file_path, 'r') as f:
        for line in f:
            #try:
                log_entry = json.loads(line.strip())
                
                # Extract basic information
                ts = log_entry.get('timestamp')
                timestamp = datetime.datetime.fromtimestamp(ts/1000).strftime('%Y-%m-%d %H:%M:%S')
                action = log_entry.get('action')
                rule_id = log_entry.get('terminatingRuleId', 'N/A')
                
                # Extract HTTP request details
                http_request = log_entry.get('httpRequest', {})
                client_ip = http_request.get('clientIp')
                country = http_request.get('country', 'Unknown')
                uri = http_request.get('uri')
                args = http_request.get('args', '')
                
                # Extract User-Agent
                user_agent = "Unknown"
                for header in http_request.get('headers', []):
                    if header.get('name') == 'User-Agent':
                        user_agent = header.get('value')
                        break
                
                # Identify attack type
                attack_type = "Normal"
                if " OR 1=1" in args or "UNION SELECT" in args:
                    attack_type = "SQL Injection"
                elif "/etc/passwd" in args or "/../" in uri:
                    attack_type = "Path Traversal"
                elif "sqlmap" in user_agent:
                    attack_type = "Automated Tool (sqlmap)"
                elif "MJ12bot" in user_agent or "scrapy" in user_agent:
                    attack_type = "Web Scraping"
                elif rule_id == "rate-based-block":
                    attack_type = "Brute Force Attempt"
                
                # Record security events
                if action == "BLOCK" or attack_type != "Normal":
                    blocked_ips[client_ip] += 1
                    attack_types[attack_type] += 1
                
                # Record malicious user agents
                if attack_type != "Normal":
                    malicious_agents[user_agent] += 1
                
                # Create structured log object
                logs.append({
                    'timestamp': timestamp,
                    'action': action,
                    'client_ip': client_ip,
                    'country': country,
                    'uri': uri,
                    'args': args,
                    'rule_id': rule_id,
                    'user_agent': user_agent,
                    'attack_type': attack_type
                })
                
            #except Exception as e:
                #print(f"Parsing error: {e}\nLine content: {line}")
    
    return logs, blocked_ips, attack_types, malicious_agents

# Generate security report
def generate_security_report(logs, blocked_ips, attack_types, malicious_agents):
    """Generate security analysis report"""
    print("\n=== AWS WAF Log Security Analysis Report ===")
    
    # 1. Overall statistics
    total_requests = len(logs)
    blocked_requests = len([log for log in logs if log['action'] == 'BLOCK'])
    suspicious_requests = len([log for log in logs if log['attack_type'] != 'Normal'])
    
    print(f"\n📊 Overall Statistics:")
    print(f"- Total Requests: {total_requests}")
    print(f"- Blocked Requests: {blocked_requests} ({blocked_requests/total_requests:.0%})")
    print(f"- Suspicious Requests: {suspicious_requests} ({suspicious_requests/total_requests:.0%})")
    
    # 2. Attack type analysis
    print("\n🔥 Attack Type Distribution:")
    for attack, count in attack_types.items():
        if attack != "Normal":
            print(f"- {attack}: {count} times")
    
    # 3. Malicious IP analysis
    print("\n🕵️ Malicious IP Ranking:")
    for ip, count in sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True):
        logs_for_ip = [log for log in logs if log['client_ip'] == ip]
        countries = set(log['country'] for log in logs_for_ip if log.get('country'))
        country_str = f" ({', '.join(countries)})" if countries else ""
        print(f"- {ip}{country_str}: {count} malicious requests")
    
    # 4. Malicious tool detection
    print("\n🛠️ Malicious Tools/Bots:")
    for agent, count in malicious_agents.items():
        print(f"- {agent[:70]}{'...' if len(agent) > 70 else ''}: {count} times")
    
    # 5. Key security events
    print("\n🚨 Key Security Event Timeline:")
    for log in sorted(logs, key=lambda x: x['timestamp']):
        if log['attack_type'] != "Normal":
            print(f"- [{log['timestamp']}] {log['client_ip']} -> {log['attack_type']} ({log['rule_id']})")
            print(f"  Target: {log['uri']}")
            if log['args']:
                print(f"  Parameters: {log['args'][:100]}{'...' if len(log['args']) > 100 else ''}")

# Main program
if __name__ == "__main__":
    print("Starting to parse AWS WAF logs...")
    logs, blocked_ips, attack_types, malicious_agents = parse_aws_waf_logs('aws_waf.log')
    generate_security_report(logs, blocked_ips, attack_types, malicious_agents)
    
    # View all log details (optional)
    print("\n🔍 Full Log Details:")
    for i, log in enumerate(logs, 1):
        print(f"\nEntry {i}:")
        print(f"• Timestamp: {log['timestamp']}")
        print(f"• Action: {log['action']}")
        print(f"• IP: {log['client_ip']} ({log['country']})")
        print(f"• Target: {log['uri']}")
        print(f"• Parameters: {log['args'][:100]}{'...' if len(log['args']) > 100 else ''}")
        print(f"• Rule: {log['rule_id']}")
        print(f"• User-Agent: {log['user_agent'][:100]}{'...' if len(log['user_agent']) > 100 else ''}")
        print(f"• Attack Type: {log['attack_type']}")