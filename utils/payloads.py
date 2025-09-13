import json
import os
import random
import string
from copy import deepcopy as _deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

# Load test data from pickups.json
_PICKUPS_DATA_PATH = Path(__file__).parent.parent / "config" / "testdata" / "pickups.json"
with open(_PICKUPS_DATA_PATH) as f:
    _PICKUPS_DATA = json.load(f)

# ----- Helpers -----
def _random_string(length: int) -> str:
    """Generate a random string of fixed length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
def valid_pickup() -> Dict[str, Any]:
    """Return a fresh copy of the valid pickup from pickups.json"""
    return _deepcopy(_PICKUPS_DATA.get("valid_pickup", {}))

def invalid_pickup_missing_contact() -> Dict[str, Any]:
    """Return the invalid payload missing contactPerson (from pickups.json)"""
    return _deepcopy(_PICKUPS_DATA.get("invalid_pickup_missing_contact", {}))

def invalid_pickup_bad_email() -> Dict[str, Any]:
    """Return the invalid payload with bad email (from pickups.json)"""
    return _deepcopy(_PICKUPS_DATA.get("invalid_pickup_bad_email", {}))

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
    p = valid_pickup()
    parts = field_path.split(".")
    cur = p
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = "'; DROP TABLE users; --"
    return p

def pickup_with_xss_field(field_path: str = "contactPerson.name") -> Dict[str, Any]:
    """Inject an XSS payload into a nested field (dot notation)."""
    p = valid_pickup()
    parts = field_path.split(".")
    cur = p
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = "<script>alert('xss')</script>"
    return p

def pickup_with_oversized_description(size: int = 10000) -> Dict[str, Any]:
    """
    Put a very large string into a package/description-like field.
    If the path doesn't exist in the base payload, this will create it under packageDetails.description.
    """
    p = valid_pickup()
    # attempt common locations for description
    if "packageDetails" not in p:
        p.setdefault("packageDetails", {})
    p["packageDetails"]["description"] = "A" * size
    return p

def pickup_with_invalid_number_of_parcels(value: Any) -> Dict[str, Any]:
    """Set numberOfParcels to an invalid value (string, negative, huge, etc.)."""
    p = valid_pickup()
    p["numberOfParcels"] = value
    return p

# ----- Utility to mutate arbitrary dotted path with a given value -----
def mutate_field(base: Dict[str, Any], field_path: str, value: Any) -> Dict[str, Any]:
    """
    Return a mutated copy of `base` where `field_path` (dot notation) is set to `value`.
    Example: mutate_field(valid_pickup(), "contactPerson.email", "bad@@")
    """
    p = _deepcopy(base)
    parts = field_path.split(".")
    cur = p
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value
    return p