import json
import datetime

def detect_web_scraping(file_path):
    """Filter and detect Web Scraping attacks from AWS WAF logs."""
    web_scraping_attacks = []

    with open(file_path, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line.strip())
                
                # Extract necessary fields
                http_request = log_entry.get('httpRequest', {})
                args = http_request.get('args', '')
                uri = http_request.get('uri', '')
                user_agent = "Unknown"
                for header in http_request.get('headers', []):
                    if header.get('name') == 'User-Agent':
                        user_agent = header.get('value')
                        break

                # Detect Web Scraping attack
                attack_type = None
                if "MJ12bot" in user_agent or "scrapy" in user_agent:
                    attack_type = "Web Scraping"

                # Record only Web Scraping attacks
                if attack_type == "Web Scraping":
                    web_scraping_attacks.append({
                        'timestamp': datetime.datetime.fromtimestamp(log_entry.get('timestamp') / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                        'client_ip': http_request.get('clientIp'),
                        'uri': uri,
                        'args': args,
                        'user_agent': user_agent,
                        'attack_type': attack_type
                    })

            except Exception as e:
                print(f"Error parsing log: {e}\nLine: {line}")

    return web_scraping_attacks

# Main program
if __name__ == "__main__":
    print("Detecting Web Scraping attacks in AWS WAF logs...")
    web_scraping_attacks = detect_web_scraping('aws_waf.log')

    # Print detected Web Scraping attacks
    print("\n=== Detected Web Scraping Attacks ===")
    for attack in web_scraping_attacks:
        print(f"- [{attack['timestamp']}] {attack['client_ip']} -> {attack['attack_type']}")
        print(f"  URI: {attack['uri']}")
        if attack['args']:
            print(f"  Args: {attack['args'][:100]}{'...' if len(attack['args']) > 100 else ''}")
        print(f"  User-Agent: {attack['user_agent']}")