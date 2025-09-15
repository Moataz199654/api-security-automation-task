import pytest
import requests
import time
import os
from utils.auth import get_forget_password_headers
from utils.payloads import get_sql_injection_payloads, get_critical_special_char_payloads

BASE_URL = os.getenv("API_BASE_URL")

@pytest.mark.emaill_security
def test_forget_password_email_enumeration():
    """
    Security test: Check if the forget password API leaks information about valid vs invalid email addresses
    
    Objective: Verify that the API does not disclose whether an email exists in the system
              through response codes, timing differences, or response content.
    
    Steps:
    1. Send request with known valid email
    2. Send request with known invalid email
    3. Compare responses to ensure they don't leak user existence information
    
    Expected: Both requests should return identical responses to prevent email enumeration
    """
    url = f"{BASE_URL}/users/forget-password"
    headers = get_forget_password_headers()
    
    # Test data
    valid_email = "amira.mosa+991^@bosta.co"  # Known valid email
    invalid_email = "nonexistent.user@bosta.co"  # Known invalid email
    
    # Function to make request and measure time
    def make_request(email):
        start_time = time.time()
        response = requests.post(url, headers=headers, json={"email": email})
        response_time = time.time() - start_time
        return response, response_time
    
    # Test with valid email
    valid_response, valid_time = make_request(valid_email)
    
    # Test with invalid email
    invalid_response, invalid_time = make_request(invalid_email)
    
    # Print debug info
    print("\nTest Results:")
    print(f"Valid Email Response - Status: {valid_response.status_code}, Time: {valid_time:.3f}s")
    print(f"Response Body: {valid_response.json()}")
    print(f"\nInvalid Email Response - Status: {invalid_response.status_code}, Time: {invalid_time:.3f}s")
    print(f"Response Body: {invalid_response.json()}")
    
    # Verify consistent behavior
    assert valid_response.status_code == invalid_response.status_code, \
        "Status codes should be identical for valid and invalid emails"
    
    # Check response bodies have same structure
    assert valid_response.json().keys() == invalid_response.json().keys(), \
        "Response structure should be identical for valid and invalid emails"
    
    # Check for suspicious timing differences (allowing for some network variance)
    time_diff = abs(valid_time - invalid_time)
    assert time_diff < 1.0, \
        f"Response time difference ({time_diff:.3f}s) suggests potential email enumeration vulnerability"
    
    print("✅ Security check passed: No email enumeration detected")


@pytest.mark.rate_limit
def test_forget_password_rate_limit():
    """
    Security test: Verify rate limiting on forget password API
    
    Objective: Ensure the API implements rate limiting to prevent:
               - Brute force attacks
               - Email enumeration through mass requests
               - DoS attacks
    
    Steps:
    1. Send multiple forget password requests in rapid succession
    2. Monitor for rate limit response (429 Too Many Requests)
    3. Track time between rate limit activation and reset
    
    Expected: 
    - API should return 429 after X number of requests
    - Rate limit should be enforced consistently
    """
    url = f"{BASE_URL}/users/forget-password"
    headers = get_forget_password_headers()
    test_email = "test.user@bosta.co"
    
    # Track request outcomes
    requests_sent = 0
    hit_429 = False
    rate_limit_threshold = 0
    start_time = time.time()
    
    print("\nTesting rate limiting...")
    
    try:
        # Send requests rapidly until we hit rate limit
        for i in range(100):  # Cap at 100 requests for safety
            response = requests.post(
                url, 
                headers=headers,
                json={"email": test_email},
                timeout=5
            )
            requests_sent += 1
            
            print(f"Request {i+1}: Status {response.status_code}")
            
            if response.status_code == 429:
                hit_429 = True
                rate_limit_threshold = requests_sent
                print(f"\nRate limit hit after {requests_sent} requests")
                print(f"Time elapsed: {time.time() - start_time:.2f} seconds")
                
                # Try to extract rate limit reset info from headers
                reset_after = response.headers.get('X-RateLimit-Reset') or \
                            response.headers.get('Retry-After')
                if reset_after:
                    print(f"Rate limit reset after: {reset_after}")
                
                break
                
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
            
    except requests.exceptions.RequestException as e:
        print(f"Error during rate limit testing: {str(e)}")
        raise
        
    # Verify rate limiting is working
    assert hit_429, "No rate limiting detected after sending multiple rapid requests"
    print(f"✅ Security check passed: Rate limiting active (threshold ~{rate_limit_threshold} requests)")


@pytest.mark.sql_injection
def test_forget_password_sql_injection():
    """
    Security test: Test SQL injection protection in forget password API
    
    Objective: Verify that the API properly sanitizes and validates email input
              to prevent SQL injection attacks.
    
    Steps:
    1. Test various SQL injection payloads in email field
    2. Verify proper error handling
    3. Check for SQL error leakage
    4. Test different injection patterns
    
    Expected: 
    - API should reject malformed emails
    - No SQL errors should be exposed
    - Consistent error responses regardless of payload
    """
    url = f"{BASE_URL}/users/forget-password"
    headers = get_forget_password_headers()
    
    # Get SQL injection test payloads
    sql_payloads = get_sql_injection_payloads()
    
    print("\nTesting SQL injection payloads...")
    
    # Store response patterns to check consistency
    response_patterns = set()
    
    for i, payload in enumerate(sql_payloads, 1):
        # Create email with SQL injection
        malicious_email = payload
        
        try:
            response = requests.post(
                url,
                headers=headers,
                json={"email": malicious_email},
                timeout=5
            )
            
            print(f"\nPayload {i}: {payload}")
            print(f"Status Code: {response.status_code}")
            
                # Check response body
            try:
                body = response.json()
                # Store response pattern (status code + error type)
                pattern = (response.status_code, body.get('errorCode', ''))
                response_patterns.add(pattern)
            except ValueError:
                print("Response was not JSON")
                
            # Verify consistent error handling
            assert response.status_code in [400, 401, 403, 422], \
                "Unexpected status code for malformed email"
                
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
            continue
            
    # Verify consistent error responses
    assert len(response_patterns) == 1, \
        f"Inconsistent error responses detected: {len(response_patterns)} different patterns"
        
    print("\n✅ Security check passed: SQL injection attempts properly handled")
    print(f"✓ All payloads received consistent responses")
    print(f"✓ Input validation working as expected")


@pytest.mark.input_validation
def test_forget_password_special_chars_validation():
    """
    Security test: Test input validation for special characters and malformed emails
    
    Objective: Verify that the API properly validates and sanitizes email inputs
              containing special characters, Unicode, null bytes, and malformed formats.
    
    Expected: 
    - API should reject malformed emails
    - Consistent error responses
    - No internal server errors
    """
    url = f"{BASE_URL}/users/forget-password"
    headers = get_forget_password_headers()
    
    # Get critical special character test payloads
    payloads = get_critical_special_char_payloads()
    
    # Track response patterns for consistency checking
    response_patterns = set()
    
    print("\nTesting input validation...")
    
    for category, category_payloads in payloads.items():
        print(f"\nTesting {category}:")
        
        for payload in category_payloads:
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json={"email": payload},
                    timeout=5
                )
                
                print(f"Payload: {repr(payload)}")
                print(f"Status Code: {response.status_code}")
                
                try:
                    body = response.json()
                    # Store response pattern (status code + error type)
                    pattern = (response.status_code, body.get('errorCode', ''))
                    response_patterns.add(pattern)
                except ValueError:
                    print("Response was not JSON")
                
                # Verify proper error handling
                assert response.status_code in [400, 401, 403, 422], \
                    f"Unexpected status code {response.status_code} for malformed email"
                    
                # Verify no 500 errors
                assert response.status_code < 500, \
                    f"Server error {response.status_code} for payload: {repr(payload)}"
                
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {str(e)}")
                continue
    
    # Verify consistent error responses
    assert len(response_patterns) == 1, \
        f"Inconsistent error responses detected: {len(response_patterns)} different patterns"
    
    print("\n✅ Security check passed: Special character and input validation")
    print(f"✓ All malformed emails properly rejected")
    print(f"✓ No server errors encountered")
    print(f"✓ Consistent error responses across all categories")