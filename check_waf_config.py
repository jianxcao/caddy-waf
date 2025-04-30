#!/usr/bin/env python3

import requests
import json
import sys
import re
import argparse
from termcolor import colored

def setup_args():
    parser = argparse.ArgumentParser(description='Check WAF configuration for testing')
    parser.add_argument('--url', default='http://localhost:8080', help='URL to test (default: http://localhost:8080)')
    parser.add_argument('--config-endpoint', default='', help='Endpoint for accessing WAF configuration (if available)')
    parser.add_argument('--rules-file', default='sample_rules.json', help='Path to rules file (default: sample_rules.json)')
    return parser.parse_args()

def load_rules_from_file(file_path):
    """Load rules from a JSON file, handling comments if present."""
    try:
        # Read the file content
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Remove JavaScript-style comments if present
        content = re.sub(r'//.*?\n', '\n', content)  # Remove single-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)  # Remove multi-line comments
        
        # Parse JSON
        rules = json.loads(content)
        print(colored(f"Loaded {len(rules)} rules from {file_path}", "green"))
        return rules
    except json.JSONDecodeError as e:
        print(colored(f"Error parsing JSON from {file_path}: {str(e)}", "red"))
        print(colored("Make sure the file is valid JSON. JavaScript-style comments are stripped automatically.", "yellow"))
        return []
    except Exception as e:
        print(colored(f"Error loading rules from {file_path}: {str(e)}", "red"))
        return []

def check_rule_coverage(rules, threshold=5):
    """Check if rules cover all test cases needed for anomaly threshold test."""
    required_tests = {
        "low_score_test": False,
        "param1_score2": False,
        "param2_score2": False,
        "param1_score3": False,
        "param2_score3": False,
        "block_true": False,
        "increment_score1": False,
        "increment_score2": False,
        "increment_score3": False
    }
    
    # Store rule scores for tests
    rule_scores = {
        "low_score_test": 0,
        "param1_score2": 0,
        "param2_score2": 0,
        "param1_score3": 0,
        "param2_score3": 0,
        "increment_score1": 0,
        "increment_score2": 0,
        "increment_score3": 0
    }
    
    block_rule_mode = None
    
    for rule in rules:
        # Check for low score test rule
        if 'targets' in rule and 'URL_PARAM:test' in rule['targets'] and 'pattern' in rule and 'low_score_test' in rule['pattern']:
            required_tests["low_score_test"] = True
            print(colored(f"✓ Found rule for test=low_score_test (ID: {rule.get('id', 'unknown')})", "green"))
            if 'score' in rule:
                rule_scores["low_score_test"] = rule.get('score', 0)
                print(colored(f"  Score: {rule['score']}", "yellow"))
        
        # Check for param1 score2
        if 'targets' in rule and 'URL_PARAM:param1' in rule['targets'] and 'pattern' in rule and 'score2' in rule['pattern']:
            required_tests["param1_score2"] = True
            print(colored(f"✓ Found rule for param1=score2 (ID: {rule.get('id', 'unknown')})", "green"))
            if 'score' in rule:
                rule_scores["param1_score2"] = rule.get('score', 0)
                print(colored(f"  Score: {rule['score']}", "yellow"))
        
        # Check for param2 score2
        if 'targets' in rule and 'URL_PARAM:param2' in rule['targets'] and 'pattern' in rule and 'score2' in rule['pattern']:
            required_tests["param2_score2"] = True
            print(colored(f"✓ Found rule for param2=score2 (ID: {rule.get('id', 'unknown')})", "green"))
            if 'score' in rule:
                rule_scores["param2_score2"] = rule.get('score', 0)
                print(colored(f"  Score: {rule['score']}", "yellow"))
        
        # Check for param1 score3
        if 'targets' in rule and 'URL_PARAM:param1' in rule['targets'] and 'pattern' in rule and 'score3' in rule['pattern']:
            required_tests["param1_score3"] = True
            print(colored(f"✓ Found rule for param1=score3 (ID: {rule.get('id', 'unknown')})", "green"))
            if 'score' in rule:
                rule_scores["param1_score3"] = rule.get('score', 0)
                print(colored(f"  Score: {rule['score']}", "yellow"))
        
        # Check for param2 score3
        if 'targets' in rule and 'URL_PARAM:param2' in rule['targets'] and 'pattern' in rule and 'score3' in rule['pattern']:
            required_tests["param2_score3"] = True
            print(colored(f"✓ Found rule for param2=score3 (ID: {rule.get('id', 'unknown')})", "green"))
            if 'score' in rule:
                rule_scores["param2_score3"] = rule.get('score', 0)
                print(colored(f"  Score: {rule['score']}", "yellow"))
        
        # Check for block action
        if 'targets' in rule and 'URL_PARAM:block' in rule['targets'] and 'pattern' in rule and 'true' in rule['pattern']:
            required_tests["block_true"] = True
            block_rule_mode = rule.get('mode', 'unknown')
            print(colored(f"✓ Found rule for block=true (ID: {rule.get('id', 'unknown')})", "green"))
            print(colored(f"  Action: {block_rule_mode}", "yellow"))
            if block_rule_mode != 'block':
                print(colored("  WARNING: This rule should have mode='block'", "red"))
        
        # Check for increment score rules
        if 'targets' in rule and 'URL_PARAM:increment' in rule['targets']:
            if 'pattern' in rule and 'score1' in rule['pattern']:
                required_tests["increment_score1"] = True
                rule_scores["increment_score1"] = rule.get('score', 0)
                print(colored(f"✓ Found rule for increment=score1 (ID: {rule.get('id', 'unknown')})", "green"))
                if 'score' in rule:
                    print(colored(f"  Score: {rule['score']}", "yellow"))
            
            if 'pattern' in rule and 'score2' in rule['pattern']:
                required_tests["increment_score2"] = True
                rule_scores["increment_score2"] = rule.get('score', 0)
                print(colored(f"✓ Found rule for increment=score2 (ID: {rule.get('id', 'unknown')})", "green"))
                if 'score' in rule:
                    print(colored(f"  Score: {rule['score']}", "yellow"))
            
            if 'pattern' in rule and 'score3' in rule['pattern']:
                required_tests["increment_score3"] = True
                rule_scores["increment_score3"] = rule.get('score', 0)
                print(colored(f"✓ Found rule for increment=score3 (ID: {rule.get('id', 'unknown')})", "green"))
                if 'score' in rule:
                    print(colored(f"  Score: {rule['score']}", "yellow"))
    
    # Check test coverage
    missing_tests = [test.replace('_', '=') for test, found in required_tests.items() if not found]
    if missing_tests:
        print(colored(f"\n⚠ Missing rules for: {', '.join(missing_tests)}", "red"))
    else:
        print(colored("\n✓ All required test rules are present!", "green"))
    
    # Validate expected scores for key test combinations
    print(colored("\nCalculated Scores for Key Test Combinations:", "cyan"))
    
    # Test 2: Below threshold
    test2_score = rule_scores["param1_score2"] + rule_scores["param2_score2"]
    test2_should_block = test2_score >= threshold
    
    if required_tests["param1_score2"] and required_tests["param2_score2"]:
        print(colored(f"Test 2 - param1=score2&param2=score2: Score = {test2_score}", "yellow"))
        print(colored(f"  Threshold: {threshold}, Should Block: {'Yes' if test2_should_block else 'No'}", 
                     "red" if test2_should_block else "green"))
        if test2_should_block:
            print(colored("  WARNING: This test should pass (not block) but the score may trigger blocking", "red"))
    else:
        print(colored("Test 2 - param1=score2&param2=score2: Cannot calculate - missing rules", "red"))
    
    # Test 3: Exceeds threshold
    test3_score = rule_scores["param1_score3"] + rule_scores["param2_score3"]
    test3_should_block = test3_score >= threshold
    
    if required_tests["param1_score3"] and required_tests["param2_score3"]:
        print(colored(f"Test 3 - param1=score3&param2=score3: Score = {test3_score}", "yellow"))
        print(colored(f"  Threshold: {threshold}, Should Block: {'Yes' if test3_should_block else 'No'}", 
                     "green" if test3_should_block else "red"))
        if not test3_should_block:
            print(colored("  WARNING: This test should be blocked but the score is below threshold", "red"))
    else:
        print(colored("Test 3 - param1=score3&param2=score3: Cannot calculate - missing rules", "red"))
    
    # Test 4: Block action
    if required_tests["block_true"]:
        block_should_work = block_rule_mode == 'block'
        print(colored(f"Test 4 - block=true: Mode = {block_rule_mode}", "yellow"))
        print(colored(f"  Should Block: {'Yes' if block_should_work else 'No'}", 
                     "green" if block_should_work else "red"))
        if not block_should_work:
            print(colored("  WARNING: This rule should have mode='block' to properly test blocking", "red"))
    else:
        print(colored("Test 4 - block=true: Cannot evaluate - missing rule", "red"))
    
    return required_tests, missing_tests, {
        "test2_score": test2_score if required_tests["param1_score2"] and required_tests["param2_score2"] else None,
        "test3_score": test3_score if required_tests["param1_score3"] and required_tests["param2_score3"] else None,
        "test2_should_block": test2_should_block if required_tests["param1_score2"] and required_tests["param2_score2"] else None,
        "test3_should_block": test3_should_block if required_tests["param1_score3"] and required_tests["param2_score3"] else None,
        "block_should_work": block_rule_mode == 'block' if required_tests["block_true"] else None
    }

def check_waf_active(url):
    """Check if the WAF is active by attempting to trigger a basic rule."""
    block_payload = {'block': 'true'}
    
    try:
        print(colored(f"\nSending test request to {url} with block=true", "blue"))
        response = requests.get(url, params=block_payload, timeout=5)
        
        if response.status_code == 403:
            print(colored("✓ WAF appears to be active (blocked request as expected)", "green"))
            return True
        else:
            print(colored(f"⚠ WAF might not be active - received status {response.status_code} instead of 403", "red"))
            print(colored("Check your WAF configuration and make sure blocking is enabled", "yellow"))
            return False
    except requests.exceptions.RequestException as e:
        print(colored(f"Error checking WAF: {str(e)}", "red"))
        return False

def main():
    args = setup_args()
    base_url = args.url
    rules_file = args.rules_file
    
    print(colored("WAF Configuration Checker", "cyan"))
    print(colored(f"Target URL: {base_url}", "yellow"))
    print(colored(f"Rules file: {rules_file}", "yellow"))
    
    # Check server connectivity
    try:
        response = requests.get(base_url, timeout=2)
        print(colored(f"✓ Server is reachable at {base_url}", "green"))
    except requests.exceptions.RequestException:
        print(colored(f"⚠ Cannot reach server at {base_url}", "red"))
        print(colored("Make sure Caddy is running with your WAF configuration.", "yellow"))
        sys.exit(1)
    
    # Load and check rules
    rules = load_rules_from_file(rules_file)
    if rules:
        required_tests, missing_tests, test_scores = check_rule_coverage(rules)
        
        print(colored("\nExpected Test Results Based on Rules:", "cyan"))
        if test_scores["test2_should_block"] is not None:
            status = "FAIL (should block)" if test_scores["test2_should_block"] else "PASS (should allow)"
            color = "red" if test_scores["test2_should_block"] else "green"
            print(colored(f"Test 2 (Below threshold): {status}", color))
        
        if test_scores["test3_should_block"] is not None:
            status = "PASS (should block)" if test_scores["test3_should_block"] else "FAIL (should allow)"
            color = "green" if test_scores["test3_should_block"] else "red"
            print(colored(f"Test 3 (Exceed threshold): {status}", color))
        
        if test_scores["block_should_work"] is not None:
            status = "PASS (should block)" if test_scores["block_should_work"] else "FAIL (won't block)"
            color = "green" if test_scores["block_should_work"] else "red"
            print(colored(f"Test 4 (Block action): {status}", color))
        
        # Only check WAF if we have the necessary rules
        if required_tests["block_true"]:
            print(colored("\nVerifying WAF is active...", "cyan"))
            check_waf_active(base_url)
        
        # Provide recommendations
        if missing_tests:
            print(colored("\nRecommendations:", "cyan"))
            print(colored("Add the missing rules to your configuration to run all tests successfully.", "yellow"))
        
        print(colored("\nConfiguration check complete.", "cyan"))
    else:
        print(colored("\nCould not load rules for verification.", "red"))

if __name__ == "__main__":
    main()
