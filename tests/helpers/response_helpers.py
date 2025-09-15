"""
Test helper functions for comparing API responses and validating behavior consistency
"""
import requests
from typing import Tuple, Dict, Any
from utils.auth import get_forget_password_headers
import os

def compare_api_responses_with_auth(
    url: str,
    payload: Dict[str, Any],
    auth_token: str = None,
    get_headers_func=get_forget_password_headers
) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
    """
    Compare API responses with and without authentication token to ensure consistent behavior.
    
    Args:
        url (str): The API endpoint URL to test
        payload (Dict[str, Any]): The request payload to send
        auth_token (str, optional): Authentication token to use. Defaults to TEST_USER_TOKEN from env.
        get_headers_func (callable, optional): Function to generate headers. Defaults to get_forget_password_headers.
    
    Returns:
        Tuple[int, Dict[str, Any], Dict[str, Any]]: Tuple containing:
            - Response status code (should be same for both requests)
            - Authenticated response JSON
            - Non-authenticated response JSON
            
    Raises:
        AssertionError: If responses differ between authenticated and non-authenticated requests
    """
    # Use provided token or get from environment
    token = auth_token or os.getenv("TEST_USER_TOKEN")
    
    # Get responses with and without token
    auth_headers = get_headers_func(token=token)
    no_auth_headers = get_headers_func()
    
    auth_response = requests.post(url, headers=auth_headers, json=payload)
    no_auth_response = requests.post(url, headers=no_auth_headers, json=payload)
    
    print(f"\nTesting with payload: {payload}")
    print(f"Auth Response - Status: {auth_response.status_code}")
    print(f"No Auth Response - Status: {no_auth_response.status_code}")
    
    # Compare status codes
    assert auth_response.status_code == no_auth_response.status_code, \
        f"Status codes differ: {auth_response.status_code} vs {no_auth_response.status_code}"
    
    # Compare response structure and content
    auth_json = auth_response.json()
    no_auth_json = no_auth_response.json()
    
    assert auth_json.keys() == no_auth_json.keys(), \
        "Response structure differs between authenticated and non-authenticated requests"
        
    assert auth_json == no_auth_json, \
        "Response content differs between authenticated and non-authenticated requests"
        
    return auth_response.status_code, auth_json, no_auth_json
