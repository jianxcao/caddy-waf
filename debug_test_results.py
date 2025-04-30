#!/usr/bin/env python3

import requests
import json
import sys
import argparse
from termcolor import colored

def setup_args():
    parser = argparse.ArgumentParser(description='Debug WAF test result evaluation')
    parser.add_argument('--url', default='http://localhost:8080', help='URL to test (default: http://localhost:8080)')
    parser.add_argument('--detailed', action='store_true', help='Show detailed request/response information')
    return parser.parse_args()

def debug_response_evaluation(url, test_name, payload, expected_status):
    """Send a request and debug the response evaluation logic."""
    print(colored(f"\n=== Debugging {test_name} ===", "cyan"))
    print(colored(f"URL: {url}", "yellow"))
    print(colored(f"Payload: {payload}", "yellow"))
    print(colored(f"Expected status: {expected_status}", "yellow"))
    
    try:
        # Send the request
        print(colored("\nSending request...", "blue"))
        response = requests.get(
            url, 
            params=payload,
            headers={'User-Agent': 'WAF-Threshold-Test-Debug/1.0'}, 
            timeout=5
        )
        
        # Get the status code
        status = response.status_code
        print(colored(f"Received status code: {status}", "green"))
        
        # Check if it matches expected
        match = status == expected_status
        match_str = "✓ MATCH" if match else "✗ MISMATCH"
        match_color = "green" if match else "red"
        print(colored(f"Status evaluation: {match_str}", match_color))
        
        # Show response details
        print(colored("\nResponse details:", "cyan"))
        print(colored(f"Status code: {status}", "yellow"))
        print(colored(f"Response body: {response.text[:100]}...", "yellow") if len(response.text) > 100 else colored(f"Response body: {response.text}", "yellow"))
        
        # Show evaluation details
        print(colored("\nEvaluation details:", "cyan"))
        print(colored(f"Python expression: response.status_code == {expected_status}", "yellow"))
        print(colored(f"Evaluation result: {response.status_code} == {expected_status} = {response.status_code == expected_status}", "yellow"))
        
        # Boolean check
        bool_result = bool(response and response.status_code == expected_status)
        print(colored(f"Boolean check: bool(response and response.status_code == {expected_status}) = {bool_result}", "yellow"))
        
        # Return result for summary
        return {
            "test_name": test_name,
            "expected": expected_status,
            "actual": status,
            "match": match,
            "bool_check": bool_result
        }
        
    except requests.exceptions.RequestException as e:
        print(colored(f"Error sending request: {str(e)}", "red"))
        return {
            "test_name": test_name,
            "error": str(e),
            "match": False,
            "bool_check": False
        }

def run_all_tests(url):
    """Run all the tests from the anomaly threshold test script and debug the results."""
    print(colored("Running all tests and debugging evaluation logic...", "cyan"))
    
    # Define all test cases
    test_cases = [
        {"name": "Test 1 (Low score)", "payload": {"test": "low_score_test"}, "expected": 200},
        {"name": "Test 2 (Below threshold)", "payload": {"param1": "score2", "param2": "score2"}, "expected": 200},
        {"name": "Test 3 (Exceed threshold)", "payload": {"param1": "score3", "param2": "score3"}, "expected": 403},
        {"name": "Test 4 (Block action)", "payload": {"block": "true"}, "expected": 403},
        {"name": "Test 5a (Increment 1)", "payload": {"increment": "score1"}, "expected": 200},
        {"name": "Test 5b (Increment 2)", "payload": {"increment": "score2"}, "expected": 200},
        {"name": "Test 5c (Increment 3)", "payload": {"increment": "score3"}, "expected": 200},
    ]
    
    # Run each test
    results = []
    for test in test_cases:
        result = debug_response_evaluation(url, test["name"], test["payload"], test["expected"])
        results.append(result)
    
    # Show summary
    print(colored("\n=== Test Evaluation Summary ===", "cyan"))
    for result in results:
        if "error" in result:
            print(colored(f"{result['test_name']}: Error - {result['error']}", "red"))
        else:
            status = "PASS" if result["match"] else "FAIL"
            color = "green" if result["match"] else "red"
            print(colored(f"{result['test_name']}: {status} (Expected: {result['expected']}, Actual: {result['actual']})", color))
            print(colored(f"  Boolean evaluation: {result['bool_check']}", "yellow"))
    
    # Check for any issues with Tests 3 and 4
    test3 = next((r for r in results if r["test_name"] == "Test 3 (Exceed threshold)"), None)
    test4 = next((r for r in results if r["test_name"] == "Test 4 (Block action)"), None)
    
    if test3 and test4:
        if test3["match"] and not test3["bool_check"]:
            print(colored("\nISSUE DETECTED: Test 3 status matches but boolean evaluation fails!", "red"))
            print(colored("This explains why the test incorrectly shows as failed.", "red"))
        
        if test4["match"] and not test4["bool_check"]:
            print(colored("\nISSUE DETECTED: Test 4 status matches but boolean evaluation fails!", "red"))
            print(colored("This explains why the test incorrectly shows as failed.", "red"))

def main():
    args = setup_args()
    url = args.url
    detailed = args.detailed
    
    print(colored("WAF Test Result Debugging Tool", "cyan"))
    print(colored(f"Target: {url}", "yellow"))
    
    # Check server connectivity
    try:
        response = requests.get(url, timeout=2)
        print(colored(f"Server is reachable at {url}", "green"))
        
        # Run all tests
        run_all_tests(url)
        
    except requests.exceptions.RequestException:
        print(colored(f"ERROR: Cannot reach server at {url}", "red"))
        print(colored("Make sure Caddy is running with your WAF configuration.", "yellow"))
        sys.exit(1)
    
    print(colored("\nDebugging complete.", "cyan"))

if __name__ == "__main__":
    main()
