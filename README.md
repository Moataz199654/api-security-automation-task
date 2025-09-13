# API Security Assessment

This project contains automated security tests for assessing API endpoints.

## Project Structure
```
api-security-assessment/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── .github/
│   └── workflows/
│       └── security-tests.yml
│
├── config/
│   ├── env.example
│   └── testdata/
│       └── pickups.json
│
├── tests/
│   ├── __init__.py
│   ├── test_pickups_security.py
│   ├── test_api2_security.py
│   └── test_api3_security.py
│
├── utils/
│   ├── __init__.py
│   ├── auth.py
│   ├── payloads.py
│   └── reporting.py
│
└── reports/
    └── .gitkeep
```

## Setup
1. Create a virtual environment and activate it
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `config/env.example` to `.env` and configure your environment variables
4. Run tests: `python -m pytest tests/`

## Reports
Test reports will be generated in the `reports/` directory.
