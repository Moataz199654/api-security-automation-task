import json
import os
import random
import string
from copy import deepcopy as _deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any
from .json_utils import mutate_field

# Load test data from valid_payloads.json
_PAYLOADS_DATA_PATH = Path(__file__).parent.parent / "config" / "testdata" / "valid_payloads.json"
with open(_PAYLOADS_DATA_PATH) as f:
    _PAYLOADS_DATA = json.load(f)

# ----- Helpers -----
def _random_string(length: int) -> str:
    """Generate a random string of fixed length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
def valid_pickup() -> Dict[str, Any]:
    """Return a fresh copy of the valid pickup from valid_payloads.json"""
    return _deepcopy(_PAYLOADS_DATA.get("valid_pickup", {}))

def valid_bank_info() -> Dict[str, Any]:
    """Return a fresh copy of the valid bank info from valid_payloads.json"""
    return _deepcopy(_PAYLOADS_DATA.get("valid_bank_info", {}))

# ----- Dynamic / derived payloads -----
def pickup_with_future_date(days: int = 2) -> Dict[str, Any]:
    """Valid pickup but with scheduledDate shifted X days into the future."""
    p = valid_pickup()
    p["scheduledDate"] = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
    return p

def pickup_with_past_date(days: int = 1) -> Dict[str, Any]:
    """Invalid pickup scheduled in the past (X days ago)."""
    p = valid_pickup()
    p["scheduledDate"] = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    return p

def pickup_with_random_contact() -> Dict[str, Any]:
    """Valid pickup but with randomized contact name and phone."""
    p = valid_pickup()
    p["contactPerson"]["name"] = _random_string(10)
    p["contactPerson"]["phone"] = "+20" + "".join(random.choices(string.digits, k=9))
    return p

# ----- Security / fuzzing payloads -----
def pickup_with_sql_injection_field(field_path: str = "contactPerson.name") -> Dict[str, Any]:
    """
    Inject a SQLi string into a nested field.
    field_path uses dot notation, e.g. "contactPerson.name" or "businessLocationId".
    """
    return mutate_field(valid_pickup(), field_path, "'; DROP TABLE users; --")

def pickup_with_xss_field(field_path: str = "contactPerson.name") -> Dict[str, Any]:
    """Inject an XSS payload into a nested field (dot notation)."""
    return mutate_field(valid_pickup(), field_path, "<script>alert('xss')</script>")

def pickup_with_oversized_description(size: int = 10000) -> Dict[str, Any]:
    """
    Put a very large string into a package/description-like field.
    If the path doesn't exist in the base payload, this will create it under packageDetails.description.
    """
    return mutate_field(valid_pickup(), "packageDetails.description", "A" * size)

def pickup_with_invalid_number_of_parcels(value: Any) -> Dict[str, Any]:
    """Set numberOfParcels to an invalid value (string, negative, huge, etc.)."""
    return mutate_field(valid_pickup(), "numberOfParcels", value)

# ----- Bank Info Security Payloads -----
def bank_info_with_sql_injection(field: str = "beneficiaryName") -> Dict[str, Any]:
    """Create a bank info payload with SQL injection in specified field"""
    return mutate_field(valid_bank_info(), f"bankInfo.{field}", "'; DROP TABLE bank_accounts; --")

def bank_info_with_xss(field: str = "beneficiaryName") -> Dict[str, Any]:
    """Create a bank info payload with XSS in specified field"""
    return mutate_field(valid_bank_info(), f"bankInfo.{field}", "<script>alert('xss')</script>")

def bank_info_with_invalid_otp() -> Dict[str, Any]:
    """Create a bank info payload with invalid OTP format"""
    return mutate_field(valid_bank_info(), "bankInfo.paymentInfoOtp", "invalid_otp_format")