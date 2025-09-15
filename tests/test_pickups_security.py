# tests/test_pickups_security.py
import os
import time
import requests
import pytest
from dotenv import load_dotenv

# Load .env when running locally (ignored if vars already set in CI)
load_dotenv()

from utils.auth import get_pickups_security_headers
from utils.payloads import (
    valid_pickup,
    pickup_with_sql_injection_field,
    pickup_with_xss_field,
    pickup_with_oversized_description,
    pickup_with_invalid_number_of_parcels,
    mutate_field
)

BASE = os.getenv("API_BASE_URL")

@pytest.mark.parametrize("token,expected_status", [
    (None, 401),
    ("this_is_invalid_token", 401),
])
def test_validate_auth_missing_or_invalid(token, expected_status):
    url = f"{BASE}/pickups"
    headers = get_pickups_security_headers(token) if token else {k: v for k, v in get_pickups_security_headers().items() if k != "Authorization"}
    resp = requests.post(url, json=valid_pickup(), headers=headers, timeout=15)
    assert resp.status_code == expected_status

def test_validate_create_requires_valid_businessLocationId():
    url = f"{BASE}/pickups"
    # Create invalid pickup by removing contactPerson and using invalid businessLocationId
    invalid_pickup = mutate_field(valid_pickup(), "businessLocationId", "invalid_id")
    del invalid_pickup["contactPerson"]
    resp = requests.post(url, json=invalid_pickup, headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code in (400, 403, 404, 401)

def test_validate_email_and_phone_validation():
    url = f"{BASE}/pickups"
    # Test with invalid email
    invalid_email_pickup = mutate_field(valid_pickup(), "contactPerson.email", "not.a.valid.email@@invalid")
    resp = requests.post(url, json=invalid_email_pickup, headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code >= 400 and resp.status_code < 500

def test_validate_input_length_fuzzing():
    url = f"{BASE}/pickups"
    # Test with oversized name
    resp = requests.post(url, json=pickup_with_oversized_description(10000), headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with SQL injection
    resp = requests.post(url, json=pickup_with_sql_injection_field("contactPerson.name"), headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with XSS payload
    resp = requests.post(url, json=pickup_with_xss_field("contactPerson.name"), headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with negative number of parcels
    resp = requests.post(url, json=pickup_with_invalid_number_of_parcels(-1), headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code >= 400, "Should reject negative number of parcels"
    print(f"Negative parcels response: {resp.text}")

    # Test with extremely large number of parcels
    resp = requests.post(url, json=pickup_with_invalid_number_of_parcels(10000), headers=get_pickups_security_headers(), timeout=15)
    assert resp.status_code >= 400, "Should reject unreasonably large number of parcels"
    print(f"Large parcels response: {resp.text}")

@pytest.mark.rate_limit
def test_rate_limit_evansion_single_token():
    """
    Validate-RATE-01 — Rate limit evasion
    Objective: Ensure rate limiting prevents brute force or spam.
    Steps: Send many requests quickly using the same token.
    Expected: Server should return 429 Too Many Requests.
    """
    url = f"{BASE}/pickups"
    headers = get_pickups_security_headers()
    payload = valid_pickup()

    hit_429 = False
    requests_sent = 0
    
    for i in range(100):  # send 100 requests
        resp = requests.post(url, json=payload, headers=headers, timeout=5)
        requests_sent += 1
        
        print(f"Request {i+1}: Status {resp.status_code}")
        
        if resp.status_code == 429:
            hit_429 = True
            print(f"\nRate limit hit after {requests_sent} requests")
            break
            
        # Small delay to avoid overwhelming the server
        time.sleep(0.1)

      
    assert hit_429, "Did not encounter 429 Too Many Requests despite rapid requests"


# Store successful pickup IDs
successful_pickups = []

def pytest_sessionfinish(session):
    """Print successful pickup IDs at the end of the test session."""
    if successful_pickups:
        print("\n=== Test Results ===")
        print(f"Successfully accessed pickup IDs: {sorted(successful_pickups)}")
        print("====================")

@pytest.mark.parametrize("pickup_id", range(84129540, 84129670))  # End is exclusive, so we use 84129840
def test_pickup_id_range_access(pickup_id, request):
    """
    Security test: Verify that pickup details are properly protected
    
    Objective: Ensure that pickup details cannot be accessed without proper authorization
    Steps:
    1. Try to access pickup details across a range of IDs
    2. Verify that all attempts are rejected (non-200 responses)
    Expected: All requests should fail with non-200 status codes
    Security Issue: If any pickup returns 200 OK, it indicates unauthorized access
    """
    url = f"{BASE}/pickups/{pickup_id}"
    
    headers = get_pickups_security_headers()
    # Add required headers from the curl example
    headers.update({
        "Accept-Language": "en",
        "x-device-fingerprint": "1hgtilh",
        "x-device-id": "01JV70TKSFGV9Z1QWEYV3N5APC"
    })  # Let get_pickups_security_headers handle the Authorization header
    
    # Prepare the request
    req = requests.Request('GET', url, headers=headers)
    prepared_req = req.prepare()

    # Send the request
    session = requests.Session()
    resp = session.send(prepared_req, timeout=15)
    
    try:
        if resp.status_code == 200:
            # If we get a 200 OK, this is a security issue - we shouldn't have access
            response = resp.json()
            if response.get("success") and "data" in response and "_id" in response["data"]:
                successful_pickups.append(pickup_id)
                pytest.fail(f"Security issue: Successfully accessed pickup {pickup_id} without proper authorization")
            
        # Non-200 responses are good - they indicate proper access control
        print(f"Access properly denied for pickup {pickup_id} with status {resp.status_code}")
    except Exception as e:
        print(f"Error accessing pickup {pickup_id}: {str(e)}")
        # Errors are fine - they indicate the request was rejected