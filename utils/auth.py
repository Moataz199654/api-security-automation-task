import os
import jwt
import requests
from dotenv import load_dotenv

load_dotenv()

def get_token():
    """
    Calls the Bosta staging API to generate a fresh token for testing.
    Returns the raw JWT string (without 'Bearer ' prefix).
    """
    url = "https://stg-app.bosta.co/api/v2/users/generate-token-for-interview-task"
    response = requests.post(url)
    response.raise_for_status()

    data = response.json()
    bearer_token = data.get("token")
    if not bearer_token:
        raise ValueError("No token returned from API")

    return bearer_token.replace("Bearer ", "")

def _get_common_headers():
    """Get common headers used across all API requests"""
    return {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "Accept-Language": "en",
        "origin": "https://stg-business.bosta.co",
        "Referer": "https://stg-business.bosta.co/"
    }

def get_pickups_security_headers(token=None):
    """Get headers for pickup security API tests"""
    token = token or os.getenv("TEST_USER_TOKEN", "")
    headers = _get_common_headers()
    headers.update({
        "user-agent": "pytest-security-suite",
        "x-device-fingerprint": "1hgtilh",
        "x-device-id": "01JV70TKSFGV9Z1QWEYV3N5APC"
    })
    if token:
        headers["Authorization"] = token  
    return headers

def get_bank_info_headers(token=None):
    """Get headers for bank info API tests"""
    token = token or get_token()
    headers = _get_common_headers()
    headers.update({
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
        "X-DEVICE-FINGERPRINT": "1iwjpzb",
        "sec-ch-ua-mobile": "?0",
        "x-device-id": "01K0ZH74759AR8ER1NZSS478R6",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    })
    if token:
        headers["Authorization"] = f"Bearer {token}"  # Bearer prefix for bank info API
    return headers

def create_tampered_token(original_token, business_id="FAKE_BUSINESS_ID"):
    """Create a tampered token by modifying the businessId"""
    # Decode without verifying signature
    payload = jwt.decode(original_token, options={"verify_signature": False})
    
    # Tamper with businessId
    payload["businessAdminInfo"]["businessId"] = business_id
    
    # Re-encode with dummy secret
    return jwt.encode(payload, "dummy-secret", algorithm="HS256")


def get_forget_password_headers():
    """Get headers specific to forget password API"""
    headers = _get_common_headers()
    headers.update({
        "priority": "u=1, i",
        "sec-ch-ua": "\"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "x-device-id": "01JV70TKSFGV9Z1QWEYV3N5APC"
    })
    return headers