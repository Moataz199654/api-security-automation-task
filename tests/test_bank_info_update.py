import pytest
import requests
from utils.auth import get_token, get_bank_info_headers, create_tampered_token

from utils.payloads import valid_bank_info
from utils.json_utils import mutate_field

BASE_URL = "https://stg-app.bosta.co/api/v2"

def test_bank_info_update_token_tampering():
    """
    Security test: Verify that tampered JWT tokens are rejected
    
    Steps:
    1. Get a valid token
    2. Create a tampered version by modifying businessId
    3. Try to update bank info with tampered token
    4. Verify request is rejected with appropriate error
    """
    # Get original token
    original_token = get_token()
    
    # Create tampered token
    tampered_token = create_tampered_token(original_token)
    
    # Prepare request with tampered token
    url = f"{BASE_URL}/businesses/add-bank-info"
    headers = get_bank_info_headers(tampered_token)
    
    # Send request
    response = requests.post(url, headers=headers, json=valid_bank_info())
    
    # Print debug info
    print("\nTest Results:")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.json()}")
    
    # Verify response
    assert response.status_code == 401, "Expected 401 Unauthorized for tampered token"
    assert response.json().get("errorCode") == 1028, "Expected error code 1028 for invalid token"
    
    print("✅ Security check passed: Invalid token was rejected")

@pytest.mark.access_control
def test_bank_info_otp_direct_update():
    """
    Security test: Verify that direct OTP updates are forbidden
    
    Objective: Test for Broken Access Control by attempting to directly
              update the OTP field, which should be protected.
    
    Steps:
    1. Get a valid token
    2. Try to directly update OTP field
    3. Verify request is rejected with 403 Forbidden
    """
    # Get valid token
    token = get_token()
    
    # Prepare request with direct OTP update attempt
    url = f"{BASE_URL}/businesses/add-bank-info"  # Endpoint for OTP update
    headers = get_bank_info_headers(token)
    
    # Create payload with direct OTP modification attempt
    payload = mutate_field(valid_bank_info(), "bankInfo.paymentInfoOtp", "999999")
    
    # Send request
    response = requests.post(url, headers=headers, json=payload)
    
    # Print debug info
    print("\nTest Results:")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response Body: {response.json()}")
    except:
        print(f"Response Text: {response.text}")
    
    # Verify response - must be 403 Forbidden to indicate proper access control
    assert response.status_code == 403, "Expected 403 Forbidden for direct OTP update attempt"
    print("✅ Security check passed: Direct OTP update was forbidden")