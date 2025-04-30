#!/usr/bin/env python3

import requests
import json
import sys
import argparse
from termcolor import colored

def setup_args():
    parser = argparse.ArgumentParser(description='Debug WAF configuration via Caddy Admin API')
    parser.add_argument('--admin-api', default='http://localhost:2019', help='Caddy Admin API URL (default: http://localhost:2019)')
    parser.add_argument('--config-path', default='/config/', help='Config path in the API (default: /config/)')
    parser.add_argument('--output', default='waf_config.json', help='Output file for configuration (default: waf_config.json)')
    parser.add_argument('--pretty', action='store_true', help='Pretty-print JSON output')
    parser.add_argument('--test-rules', action='store_true', help='Test WAF rules with sample requests')
    parser.add_argument('--target-url', default='http://localhost:8080', help='Target URL for rule testing (default: http://localhost:8080)')
    return parser.parse_args()

def get_caddy_config(admin_url, config_path):
    """Get the current Caddy configuration from the Admin API."""
    try:
        response = requests.get(f"{admin_url}{config_path}", timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(colored(f"Error fetching config: Status {response.status_code}", "red"))
            return None
    except requests.exceptions.RequestException as e:
        print(colored(f"Error connecting to Caddy Admin API: {str(e)}", "red"))
        return None

def extract_waf_config(config):
    """Extract WAF-related configuration from the Caddy config."""
    if not config:
        return None
    
    waf_config = {"routes": [], "handlers": [], "thresholds": []}
    
    # Try to find WAF configuration in apps.http.servers
    if 'apps' in config and 'http' in config['apps'] and 'servers' in config['apps']['http']:
        for server_name, server in config['apps']['http']['servers'].items():
            print(colored(f"Examining server: {server_name}", "cyan"))
            
            if 'routes' in server:
                for route in server['routes']:
                    # Check for WAF in route handlers
                    if 'handle' in route:
                        for handler in route['handle']:
                            if handler.get('handler') == 'waf':
                                print(colored("Found WAF handler in route", "green"))
                                waf_config['routes'].append(route)
                                waf_config['handlers'].append(handler)
                                
                                # Check for threshold
                                if 'anomaly_threshold' in handler:
                                    print(colored(f"Found anomaly threshold: {handler['anomaly_threshold']}", "green"))
                                    waf_config['thresholds'].append(handler['anomaly_threshold'])
    
    if not waf_config['handlers']:
        print(colored("No WAF handlers found in the configuration", "yellow"))
    
    return waf_config

def save_config(config, file_path, pretty=False):
    """Save the configuration to a file."""
    try:
        with open(file_path, 'w') as f:
            if pretty:
                json.dump(config, f, indent=2)
            else:
                json.dump(config, f)
        print(colored(f"Configuration saved to {file_path}", "green"))
    except Exception as e:
        print(colored(f"Error saving configuration: {str(e)}", "red"))

def test_waf_rules(target_url, waf_config):
    """Test WAF rules with sample requests to verify behavior."""
    print(colored("\nTesting WAF rules with sample requests...", "cyan"))
    
    # Check if we have any anomaly thresholds
    thresholds = waf_config.get('thresholds', [])
    threshold = thresholds[0] if thresholds else 5
    print(colored(f"Using anomaly threshold: {threshold}", "yellow"))
    
    # Test cases
    test_cases = [
        {"name": "Low Score Test", "payload": {"test": "low_score_test"}, "expected_status": 200},
        {"name": "Below Threshold Test", "payload": {"param1": "score2", "param2": "score2"}, "expected_status": 200},
        {"name": "Exceed Threshold Test", "payload": {"param1": "score3", "param2": "score3"}, "expected_status": 403},
        {"name": "Block Action Test", "payload": {"block": "true"}, "expected_status": 403},
    ]
    
    results = []
    
    for test_case in test_cases:
        print(colored(f"\nRunning test: {test_case['name']}", "cyan"))
        print(colored(f"Payload: {test_case['payload']}", "yellow"))
        print(colored(f"Expected status: {test_case['expected_status']}", "yellow"))
        
        try:
            response = requests.get(
                target_url, 
                params=test_case['payload'],
                headers={'User-Agent': 'WAF-Debug-Tool/1.0'},
                timeout=5
            )
            
            status = response.status_code
            matched = status == test_case['expected_status']
            color = "green" if matched else "red"
            
            print(colored(f"Actual status: {status} - {'✓ MATCH' if matched else '✗ MISMATCH'}", color))
            print(colored(f"Response: {response.text[:100]}...", "yellow") if len(response.text) > 100 else colored(f"Response: {response.text}", "yellow"))
            
            # Store result
            results.append({
                "name": test_case['name'],
                "expected": test_case['expected_status'],
                "actual": status,
                "matched": matched
            })
            
        except requests.exceptions.RequestException as e:
            print(colored(f"Error sending request: {str(e)}", "red"))
            results.append({
                "name": test_case['name'],
                "error": str(e),
                "matched": False
            })
    
    # Summary
    print(colored("\nTest Results Summary:", "cyan"))
    passes = sum(1 for r in results if r.get('matched', False))
    failures = len(results) - passes
    
    print(colored(f"Total Tests: {len(results)}", "yellow"))
    print(colored(f"Passes: {passes}", "green"))
    print(colored(f"Failures: {failures}", "red" if failures > 0 else "green"))
    
    # Detailed results
    print(colored("\nDetailed Results:", "cyan"))
    for result in results:
        status = "PASS" if result.get('matched', False) else "FAIL"
        color = "green" if result.get('matched', False) else "red"
        if 'error' in result:
            print(colored(f"{result['name']}: {status} - Error: {result['error']}", color))
        else:
            print(colored(f"{result['name']}: {status} - Expected: {result['expected']}, Actual: {result['actual']}", color))
    
    return results

def main():
    args = setup_args()
    admin_url = args.admin_api
    config_path = args.config_path
    output_file = args.output
    pretty = args.pretty
    test_rules = args.test_rules
    target_url = args.target_url
    
    print(colored("WAF Debug Tool", "cyan"))
    print(colored(f"Caddy Admin API: {admin_url}", "yellow"))
    
    # Get the current configuration
    print(colored("\nFetching Caddy configuration...", "cyan"))
    config = get_caddy_config(admin_url, config_path)
    
    if config:
        print(colored("Configuration retrieved successfully", "green"))
        
        # Extract WAF configuration
        print(colored("\nExtracting WAF configuration...", "cyan"))
        waf_config = extract_waf_config(config)
        
        if waf_config and waf_config['handlers']:
            # Summary of WAF configuration
            print(colored("\nWAF Configuration Summary:", "cyan"))
            print(colored(f"WAF Handlers: {len(waf_config['handlers'])}", "yellow"))
            
            for i, handler in enumerate(waf_config['handlers']):
                print(colored(f"\nHandler {i+1}:", "yellow"))
                if 'anomaly_threshold' in handler:
                    print(colored(f"  Anomaly Threshold: {handler['anomaly_threshold']}", "green"))
                else:
                    print(colored("  No anomaly threshold specified", "red"))
                
                if 'rules' in handler:
                    print(colored(f"  Rules: {len(handler['rules']) if isinstance(handler['rules'], list) else 'From file'}", "green"))
                else:
                    print(colored("  No rules specified", "red"))
                
                if 'rules_file' in handler:
                    print(colored(f"  Rules File: {handler['rules_file']}", "green"))
            
            # Test rules if requested
            if test_rules:
                test_waf_rules(target_url, waf_config)
            
            # Save the WAF configuration
            print(colored(f"\nSaving WAF configuration to {output_file}...", "cyan"))
            save_config(waf_config, output_file, pretty)
        else:
            print(colored("No WAF configuration found", "red"))
    
    print(colored("\nDebug complete.", "cyan"))

if __name__ == "__main__":
    main()
