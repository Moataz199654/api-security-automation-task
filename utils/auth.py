import os
from dotenv import load_dotenv

load_dotenv()


def get_auth_headers(token=None):
    token = token or os.getenv("TEST_USER_TOKEN", "")
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "origin": "https://stg-business.bosta.co",
        "user-agent": "pytest-security-suite",
    }
    if token:
        headers["Authorization"] = token
    return headers
