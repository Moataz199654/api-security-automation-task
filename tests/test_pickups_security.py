# tests/test_pickups_security.py
import os
import requests
import pytest
from dotenv import load_dotenv

# Load .env when running locally (ignored if vars already set in CI)
load_dotenv()

from utils.auth import get_auth_headers
from utils.payloads import (
    valid_pickup,
    pickup_with_sql_injection_field,
    pickup_with_xss_field,
    pickup_with_oversized_description,
    pickup_with_invalid_number_of_parcels,
    mutate_field
)

BASE = os.getenv("API_BASE_URL", "https://stg-app.bosta.co/api/v2")

@pytest.mark.parametrize("token,expected_status", [
    (None, 401),
    ("this_is_invalid_token", 401),
])
def test_validate_auth_missing_or_invalid(token, expected_status):
    url = f"{BASE}/pickups"
    headers = get_auth_headers(token) if token else {k: v for k, v in get_auth_headers().items() if k != "Authorization"}
    resp = requests.post(url, json=valid_pickup(), headers=headers, timeout=15)
    assert resp.status_code == expected_status

def test_validate_create_requires_valid_businessLocationId():
    url = f"{BASE}/pickups"
    # Create invalid pickup by removing contactPerson and using invalid businessLocationId
    invalid_pickup = mutate_field(valid_pickup(), "businessLocationId", "invalid_id")
    del invalid_pickup["contactPerson"]
    resp = requests.post(url, json=invalid_pickup, headers=get_auth_headers(), timeout=15)
    assert resp.status_code in (400, 403, 404, 401)

def test_validate_email_and_phone_validation():
    url = f"{BASE}/pickups"
    # Test with invalid email
    invalid_email_pickup = mutate_field(valid_pickup(), "contactPerson.email", "not.a.valid.email@@invalid")
    resp = requests.post(url, json=invalid_email_pickup, headers=get_auth_headers(), timeout=15)
    assert resp.status_code >= 400 and resp.status_code < 500

def test_validate_input_length_fuzzing():
    url = f"{BASE}/pickups"
    # Test with oversized name
    resp = requests.post(url, json=pickup_with_oversized_description(10000), headers=get_auth_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with SQL injection
    resp = requests.post(url, json=pickup_with_sql_injection_field("contactPerson.name"), headers=get_auth_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with XSS payload
    resp = requests.post(url, json=pickup_with_xss_field("contactPerson.name"), headers=get_auth_headers(), timeout=15)
    assert resp.status_code != 500  # server should not 500

    # Test with invalid number of parcels
    resp = requests.post(url, json=pickup_with_invalid_number_of_parcels(-1), headers=get_auth_headers(), timeout=15)
    assert resp.status_code >= 400  # should reject negative numbers

# Wallet deduction test (non-destructive / requires sandbox)
@pytest.mark.skipif(os.getenv("SKIP_WALLET_TEST", "true").lower() == "true", reason="Wallet tests skipped by default")
def test_validate_wallet_deduction_behavior():
    wallet_url = os.getenv("API_WALLET_URL")
    if not wallet_url:
        pytest.skip("No wallet API configured in env")

    # read balance (example path; adapt to real API)
    r_before = requests.get(f"{wallet_url}/balance", headers=get_auth_headers(), timeout=10)
    assert r_before.status_code == 200
    bal_before = r_before.json().get("balance")

    # create pickup
    create = requests.post(f"{BASE}/pickups", json=valid_pickup(), headers=get_auth_headers(), timeout=15)
    assert create.status_code in (200, 201)

    # read balance after
    r_after = requests.get(f"{wallet_url}/balance", headers=get_auth_headers(), timeout=10)
    assert r_after.status_code == 200
    bal_after = r_after.json().get("balance")

    assert bal_after <= bal_before  # ensure deduction happened or equal if free