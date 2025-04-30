#!/usr/bin/env python3

import requests
import json
import time
import sys
import argparse
from termcolor import colored

# --- setup_args function remains the same ---
def setup_args():
    parser = argparse.ArgumentParser(description='Test WAF anomaly threshold behavior')
    parser.add_argument('--url', default='http://localhost:8080', help='URL to test (default: http://localhost:8080)')
    parser.add_argument('--threshold', type=int, default=5, help='Configured anomaly threshold (default: 5)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output for response headers')
    parser.add_argument('--verbose', action='store_true', help='Show verbose test details')
    return parser.parse_args()

# --- send_request function remains the same ---
def send_request(url, payload, headers=None, expected_status=None, debug=False):
    """
    Send a request with the given payload and validate the response.

    Returns:
        tuple: (response object or None, dict of found WAF headers, bool or None for passed status)
               'passed' is True if status matches expected_status, False if it doesn't or error occurs,
               None if expected_status was not provided.
    """
    if headers is None:
        headers = {'User-Agent': 'WAF-Threshold-Test/1.0'}

    print(colored(f"\n>>> Sending request to {url}", "blue"))
    print(colored(f">>> Payload: {payload}", "blue"))

    passed = None # Default if no expectation set

    try:
        response = requests.get(
            url,
            params=payload,
            headers=headers,
            timeout=10 # Increased timeout slightly
        )

        status = response.status_code

        # Determine pass/fail based on expected status
        if expected_status is not None:
            passed = (status == expected_status)
            color = "green" if passed else "red"
            result_text = "✓ PASS" if passed else "✗ FAIL"
            print(colored(f"<<< Status: {status} (Expected: {expected_status}) - {result_text}", color))
        else:
            # No expected status, just report what we got
            print(colored(f"<<< Status: {status}", "yellow"))

        response_text = response.text
        print(colored(f"<<< Response: {response_text[:100]}...", "yellow") if len(response_text) > 100 else colored(f"<<< Response: {response_text}", "yellow"))

        # Check for WAF-specific headers
        waf_headers = {}
        if debug:
            print(colored("\n--- Response Headers ---", "cyan"))
            for header, value in response.headers.items():
                print(colored(f"  {header}: {value}", "yellow"))
                # Check for common WAF score headers - these may vary based on your WAF implementation
                lower_header = header.lower()
                if lower_header in ('x-waf-score', 'x-waf-anomaly-score', 'x-waf-status', 'x-waf-rules', 'x-waf-action'):
                    waf_headers[lower_header] = value
                    print(colored(f"  Found WAF header: {header}={value}", "green"))
            print(colored("--- End Headers ---", "cyan"))

        return response, waf_headers, passed

    except requests.exceptions.Timeout:
        print(colored(f"Error: Request timed out after 10 seconds.", "red"))
        passed = False # Timeout is a failure if status was expected
        if expected_status is not None:
            print(colored(f"<<< Status: TIMEOUT (Expected: {expected_status}) - ✗ FAIL", "red"))
        else:
            print(colored(f"<<< Status: TIMEOUT", "red"))
        return None, {}, passed
    except requests.exceptions.RequestException as e:
        print(colored(f"Error sending request: {str(e)}", "red"))
        passed = False # Request error is a failure if status was expected
        if expected_status is not None:
            print(colored(f"<<< Status: ERROR (Expected: {expected_status}) - ✗ FAIL", "red"))
        else:
            print(colored(f"<<< Status: ERROR", "red"))
        return None, {}, passed

# --- test_anomaly_threshold function is UPDATED ---
def test_anomaly_threshold(base_url, threshold, debug=False, verbose=False):
    """Test that anomaly threshold is properly enforced."""
    print(colored(f"\n=== Testing Anomaly Threshold (threshold={threshold}) ===", "cyan"))

    results_data = {} # Store results keyed by test name

    # --- Original Tests ---
    # Test 1: Low score (should pass, 200 OK)
    print(colored("\nTest 1: Low-score rule (should pass with 200 OK)", "magenta"))
    low_score_payload = {'test': 'low_score_test'} # RULE-1 (Score 1)
    expected_score = 1
    low_response, low_headers, test1_passed = send_request(base_url, low_score_payload, expected_status=200, debug=debug)
    results_data["Test 1 (Low score)"] = (test1_passed, low_response.status_code if low_response else "ERROR", f"Expected 200 OK for low score ({expected_score}) < threshold ({threshold})")
    print(colored(f"-> Expected anomaly score contribution: {expected_score}", "yellow"))

    # Test 2: Score below threshold (should pass, 200 OK)
    print(colored(f"\nTest 2: Score below threshold (should pass with 200 OK)", "magenta"))
    below_threshold_payload = {'param1': 'score2', 'param2': 'score2'} # RULE-PARAM1 (2) + RULE-PARAM2 (2) = 4
    expected_total_score = 4
    below_response, below_headers, test2_passed = send_request(base_url, below_threshold_payload, expected_status=200, debug=debug)
    results_data["Test 2 (Below threshold)"] = (test2_passed, below_response.status_code if below_response else "ERROR", f"Expected 200 OK for score ({expected_total_score}) < threshold ({threshold})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score} (Threshold: {threshold})", "yellow"))

    # Test 3: Score exceeding threshold (should block, 403 Forbidden)
    print(colored(f"\nTest 3: Score exceeding threshold (should block with 403 Forbidden)", "magenta"))
    exceed_threshold_payload = {'param1': 'score3', 'param2': 'score3'} # RULE-PARAM1-HIGH (3) + RULE-PARAM2-HIGH (3) = 6
    expected_total_score = 6
    exceed_response, exceed_headers, test3_passed = send_request(base_url, exceed_threshold_payload, expected_status=403, debug=debug)
    results_data["Test 3 (Exceed threshold)"] = (test3_passed, exceed_response.status_code if exceed_response else "ERROR", f"Expected 403 Forbidden for score ({expected_total_score}) >= threshold ({threshold})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score} (Threshold: {threshold})", "yellow"))

    # Test 4: Explicit 'block' action rule (should block, 403 Forbidden)
    print(colored("\nTest 4: Explicit 'block' action rule (should block with 403 Forbidden)", "magenta"))
    block_action_payload = {'block': 'true'} # RULE-BLOCK (Block Action)
    block_response, block_headers, test4_passed = send_request(base_url, block_action_payload, expected_status=403, debug=debug)
    results_data["Test 4 (Block action)"] = (test4_passed, block_response.status_code if block_response else "ERROR", "Expected 403 Forbidden for explicit block action")
    print(colored("-> Score doesn't matter for this test - blocking action should take precedence", "yellow"))

    # Test 5: Incremental scoring in separate requests (should pass, 200 OK)
    print(colored("\nTest 5: Incremental scoring in separate requests (should be isolated per request, pass with 200 OK)", "magenta"))
    incremental_results_passed = []
    incremental_status_codes = []
    for i in range(1, 4): # Tests INCR-1 (1), INCR-2 (2), INCR-3 (3)
        print(colored(f"--- Request {i} of incremental test ---", "cyan"))
        incremental_payload = {'increment': f'score{i}'}
        expected_score = i
        incremental_response, inc_headers, single_inc_passed = send_request(base_url, incremental_payload, expected_status=200, debug=debug)
        incremental_results_passed.append(single_inc_passed if single_inc_passed is not None else False)
        incremental_status_codes.append(incremental_response.status_code if incremental_response else "ERROR")
        print(colored(f"-> Expected anomaly score contribution for this request: {expected_score}", "yellow"))
        if i < 3: time.sleep(0.2) # Shorter delay
    test5_passed = all(incremental_results_passed)
    status_summary = ', '.join(map(str, incremental_status_codes))
    results_data["Test 5 (Incremental)"] = (test5_passed, status_summary, f"Expected 200 OK for all incremental tests (scores {', '.join(map(str,range(1,4)))}) < threshold ({threshold})")

    # --- NEW TESTS ---

    # Test 6: Score hitting exact threshold (should block, 403 Forbidden)
    print(colored(f"\nTest 6: Score hitting exact threshold (should block with 403 Forbidden)", "magenta"))
    exact_threshold_payload = {'param1': 'score2', 'param2': 'score3'} # RULE-PARAM1 (2) + RULE-PARAM2-HIGH (3) = 5
    expected_total_score = 5
    exact_response, exact_headers, test6_passed = send_request(base_url, exact_threshold_payload, expected_status=403, debug=debug)
    results_data["Test 6 (Exact threshold)"] = (test6_passed, exact_response.status_code if exact_response else "ERROR", f"Expected 403 Forbidden for score ({expected_total_score}) == threshold ({threshold})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score} (Threshold: {threshold})", "yellow"))

    # Test 7: Mix High/Low score below threshold (should pass, 200 OK)
    print(colored(f"\nTest 7: Mix High/Low score below threshold (should pass with 200 OK)", "magenta"))
    mix_below_payload = {'test': 'low_score_test', 'param1': 'score3'} # RULE-1 (1) + RULE-PARAM1-HIGH (3) = 4
    expected_total_score = 4
    mix_below_response, mix_below_headers, test7_passed = send_request(base_url, mix_below_payload, expected_status=200, debug=debug)
    results_data["Test 7 (Mix Below Threshold)"] = (test7_passed, mix_below_response.status_code if mix_below_response else "ERROR", f"Expected 200 OK for mixed score ({expected_total_score}) < threshold ({threshold})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score} (Threshold: {threshold})", "yellow"))

    # Test 8: Score greatly exceeding threshold (with Param3) (should block, 403 Forbidden)
    print(colored(f"\nTest 8: Score greatly exceeding threshold (should block with 403 Forbidden)", "magenta"))
    exceed_greatly_payload = {'param1': 'score3', 'param2': 'score3', 'param3': 'score3'} # RULE-PARAM1-HIGH (3) + RULE-PARAM2-HIGH (3) + RULE-PARAM3-HIGH (3) = 9
    expected_total_score = 9
    exceed_greatly_response, exceed_greatly_headers, test8_passed = send_request(base_url, exceed_greatly_payload, expected_status=403, debug=debug)
    results_data["Test 8 (Exceed Greatly)"] = (test8_passed, exceed_greatly_response.status_code if exceed_greatly_response else "ERROR", f"Expected 403 Forbidden for score ({expected_total_score}) >= threshold ({threshold})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score} (Threshold: {threshold})", "yellow"))

    # Test 9: Block action triggered with other scoring rules (should block, 403 Forbidden)
    print(colored(f"\nTest 9: Block action priority (should block with 403 Forbidden)", "magenta"))
    block_priority_payload = {'block': 'true', 'param1': 'score2'} # RULE-BLOCK (block) + RULE-PARAM1 (2)
    expected_total_score = 2 # Score is calculated but block action takes precedence
    block_priority_response, block_priority_headers, test9_passed = send_request(base_url, block_priority_payload, expected_status=403, debug=debug)
    results_data["Test 9 (Block Priority)"] = (test9_passed, block_priority_response.status_code if block_priority_response else "ERROR", "Expected 403 Forbidden due to explicit block action, regardless of score")
    print(colored(f"-> Calculated anomaly score: {expected_total_score}. Block action should override.", "yellow"))

    # Test 10: No matching rules (should pass, 200 OK)
    print(colored(f"\nTest 10: No matching rules (should pass with 200 OK)", "magenta"))
    no_match_payload = {'vanilla': 'test', 'unknown': 'data'}
    expected_total_score = 0
    no_match_response, no_match_headers, test10_passed = send_request(base_url, no_match_payload, expected_status=200, debug=debug)
    results_data["Test 10 (No Match)"] = (test10_passed, no_match_response.status_code if no_match_response else "ERROR", f"Expected 200 OK when no rules match (score {expected_total_score})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score}", "yellow"))

    # Test 11: Parameter name match, value mismatch (should pass, 200 OK)
    print(colored(f"\nTest 11: Parameter name match, value mismatch (should pass with 200 OK)", "magenta"))
    value_mismatch_payload = {'param1': 'non_matching_value', 'test': 'another_value'} # Neither value matches RULE-PARAM1 or RULE-1 patterns
    expected_total_score = 0
    value_mismatch_response, value_mismatch_headers, test11_passed = send_request(base_url, value_mismatch_payload, expected_status=200, debug=debug)
    results_data["Test 11 (Value Mismatch)"] = (test11_passed, value_mismatch_response.status_code if value_mismatch_response else "ERROR", f"Expected 200 OK when parameter values don't match rule patterns (score {expected_total_score})")
    print(colored(f"-> Expected total anomaly score: {expected_total_score}", "yellow"))


    # Summarize results
    print(colored("\n=== Anomaly Threshold Test Summary ===", "cyan"))
    print(colored(f"Target URL: {base_url}", "yellow"))
    print(colored(f"Configured threshold: {threshold}", "yellow"))

    all_passed_flag = True
    # Define the order tests should appear in the summary
    test_order = [
        "Test 1 (Low score)",
        "Test 2 (Below threshold)",
        "Test 7 (Mix Below Threshold)", # New test inserted logically
        "Test 5 (Incremental)", # Incremental scores are below threshold
        "Test 10 (No Match)",
        "Test 11 (Value Mismatch)",
        "Test 6 (Exact threshold)", # Blocking test
        "Test 3 (Exceed threshold)", # Blocking test
        "Test 8 (Exceed Greatly)", # Blocking test
        "Test 4 (Block action)", # Blocking test
        "Test 9 (Block Priority)" # Blocking test
    ]

    print(colored("\n--- Test Results ---", "cyan"))
    for test_name in test_order:
        if test_name not in results_data:
            print(colored(f"{test_name}: SKIPPED (Data not found)", "yellow"))
            all_passed_flag = False # Consider missing data a failure
            continue

        passed, status_code, description = results_data[test_name]
        # Treat None passed status as False for summary
        passed = passed if passed is not None else False
        result_text = "PASS" if passed else "FAIL"
        color = "green" if passed else "red"
        print(colored(f"{test_name}: {result_text} (Status: {status_code})", color))

        if not passed:
            all_passed_flag = False
            print(colored(f"  Reason: {description}", "yellow"))
        elif verbose:
            print(colored(f"  Details: {description} (Status: {status_code})", "yellow"))


    # Final Pass/Fail Summary
    print(colored("\n--- Overall Result ---", "cyan"))
    if all_passed_flag:
        print(colored("✓ All tests passed! Anomaly threshold and blocking logic appear to be working correctly based on expected status codes.", "green"))
    else:
        print(colored("✗ Some tests failed. Review the output above.", "red"))
        failed_tests = [name for name in test_order if name in results_data and not results_data[name][0]]
        print(colored(f"Failed tests: {', '.join(failed_tests)}", "red"))

        # Provide troubleshooting tips based on failure patterns
        test3_failed = "Test 3 (Exceed threshold)" in failed_tests
        test4_failed = "Test 4 (Block action)" in failed_tests
        test6_failed = "Test 6 (Exact threshold)" in failed_tests
        test8_failed = "Test 8 (Exceed Greatly)" in failed_tests
        test9_failed = "Test 9 (Block Priority)" in failed_tests
        blocking_tests_failed = test3_failed or test4_failed or test6_failed or test8_failed or test9_failed

        if blocking_tests_failed:
             print(colored("\nSuggestion: One or more blocking tests failed (expected 403).", "yellow"))
             if test6_failed : print(colored("  - Check if the WAF blocks exactly *at* the threshold score.", "yellow"))
             if test3_failed or test8_failed: print(colored(f"  - Verify rules correctly contribute scores and the threshold ({threshold}) is enforced.", "yellow"))
             if test4_failed or test9_failed: print(colored("  - Ensure rules with 'block' action are correctly configured and take priority.", "yellow"))

        if "Test 5 (Incremental)" in failed_tests:
             print(colored("\nSuggestion: One or more incremental tests failed (expected 200). This might indicate score accumulation across requests (incorrect) or unrelated blocking rules triggered.", "yellow"))
        if "Test 10 (No Match)" in failed_tests or "Test 11 (Value Mismatch)" in failed_tests :
             print(colored("\nSuggestion: Tests expecting no match failed (expected 200). Check for overly broad rules or default blocking actions.", "yellow"))


# --- check_server function remains the same ---
def check_server(url):
    """Check if the server is reachable."""
    print(f"\nChecking server reachability at {url}...")
    try:
        # Use HEAD request for efficiency, or GET if HEAD is disallowed/problematic
        response = requests.head(url, timeout=3)
        # Allow any success or redirect status code as "reachable"
        if 200 <= response.status_code < 400:
            print(colored(f"Server is reachable (Status: {response.status_code}).", "green"))
            return True
        else:
            # Handle client/server errors differently
            if 400 <= response.status_code < 500:
                 print(colored(f"Server responded with client error: {response.status_code}. Check URL path/config.", "yellow"))
            elif 500 <= response.status_code < 600:
                 print(colored(f"Server responded with server error: {response.status_code}. Check server/WAF logs.", "red"))
            else:
                 print(colored(f"Server responded with unexpected status: {response.status_code}.", "yellow"))
            return False # Treat non-success/redirect as potentially problematic
    except requests.exceptions.Timeout:
         print(colored(f"ERROR: Connection to {url} timed out.", "red"))
         print(colored("Check if the server/proxy is running and accessible.", "yellow"))
         return False
    except requests.exceptions.ConnectionError:
        print(colored(f"ERROR: Cannot connect to server at {url}", "red"))
        print(colored("Make sure the server/proxy (e.g., Caddy) is running and the URL is correct.", "yellow"))
        return False
    except requests.exceptions.RequestException as e:
        print(colored(f"ERROR: An unexpected network error occurred: {str(e)}", "red"))
        return False

# --- main function is UPDATED (info section) ---
def main():
    args = setup_args()
    base_url = args.url.rstrip('/') # Remove trailing slash if present
    threshold = args.threshold
    debug = args.debug
    verbose = args.verbose

    print(colored(f"WAF Anomaly Threshold Test Tool", "cyan", attrs=["bold"]))
    print(colored("-" * 30, "cyan"))
    print(f"Target URL:         {base_url}")
    print(f"Expected Threshold: {threshold}")
    print(f"Debug Mode:         {'ON' if debug else 'OFF'}")
    print(f"Verbose Mode:       {'ON' if verbose else 'OFF'}")
    print(colored("-" * 30, "cyan"))

    # UPDATED Test rule setup recommendations
    print(colored("\nINFO: This script assumes specific WAF rules are configured:", "yellow"))
    print(colored("  - Rule(s) matching 'test=low_score_test' contribute score=1.", "yellow"))
    print(colored("  - Rule(s) matching 'param1=score2' contribute score=2.", "yellow"))
    print(colored("  - Rule(s) matching 'param2=score2' contribute score=2.", "yellow"))
    print(colored("  - Rule(s) matching 'param1=score3' contribute score=3.", "yellow"))
    print(colored("  - Rule(s) matching 'param2=score3' contribute score=3.", "yellow"))
    print(colored("  - Rule(s) matching 'param3=score3' contribute score=3. (Used in Test 8)", "yellow")) # Added param3 rule info
    print(colored("  - Rule matching 'block=true' has an explicit 'block' action.", "yellow"))
    print(colored("  - Rule(s) matching 'increment=scoreX' contribute score=X (e.g., 'increment=score1' adds 1).", "yellow"))

    if not check_server(base_url):
        sys.exit(1)

    test_anomaly_threshold(base_url, threshold, debug, verbose)

if __name__ == "__main__":
    main()