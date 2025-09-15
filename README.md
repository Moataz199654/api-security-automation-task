# API Security Assessment

This project contains automated security tests for assessing API endpoints, focusing on common security vulnerabilities and best practices.

## Security Test Categories

### Forget Password API Tests
1. **Email Enumeration Protection** (`@pytest.mark.emaill_security`)
   - Validates that the API doesn't leak user existence information
   - Checks response codes, timing differences, and content consistency
   - Prevents user enumeration attacks

2. **Rate Limiting** (`@pytest.mark.rate_limit`)
   - Tests protection against brute force attacks
   - Verifies rate limit thresholds
   - Monitors rate limit reset behavior

3. **SQL Injection Prevention** (`@pytest.mark.sql_injection`)
   - Tests common SQL injection patterns
   - Validates input sanitization
   - Ensures consistent error handling

4. **Input Validation** (`@pytest.mark.input_validation`)
   - Tests critical special characters handling:
     - Null byte injection
     - Unicode control characters
     - Directional override characters
   - Validates proper input sanitization

### Bank Info API Tests
- Token tampering detection
- Access control validation
- OTP security checks

### Pickups API Tests
- Authentication validation
- Input fuzzing
- Rate limit evasion checks

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
    │       └── valid_payloads.json
    │
    ├── tests/
    │   ├── __init__.py
    │   ├── test_security_forget_password_api.py
    │   ├── test_pickups_security.py
    │   └── test_bank_info_update.py
    │
    ├── utils/
    │   ├── __init__.py
    │   ├── auth.py         # Authentication and header utilities
    │   ├── payloads.py     # Test payloads and data generators
    │   ├── json_utils.py   # JSON manipulation utilities
    │   └── reporting.py    # Test reporting utilities
    │
    └── reports/
        └── .gitkeep
```

## Setup
1. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment:
   ```bash
   cp config/env.example .env
   # Edit .env with your settings
   ```

4. Run tests:
   - All tests:
     ```bash
     python -m pytest tests/
     ```
   - Specific test category:
     ```bash
     python -m pytest -m sql_injection tests/  # Run SQL injection tests only
     python -m pytest -m rate_limit tests/     # Run rate limit tests only
     ```

## Test Payloads
Security test payloads are centralized in `utils/payloads.py` and organized by:
- SQL Injection patterns
- Special character injections
- Input validation test cases
- API-specific test data

## Reports
- Test reports are generated in the `reports/` directory
- Each test run creates a timestamped report
- Reports include:
  - Test results and status
  - Security findings
  - Response patterns
  - Performance metrics

## Security Categories
Tests are marked with pytest markers for easy filtering:
- `emaill_security`: Email enumeration tests
- `rate_limit`: Rate limiting and DoS protection
- `sql_injection`: SQL injection prevention
- `input_validation`: Input validation and sanitization

## Contributing
1. Follow the existing test patterns
2. Add appropriate pytest markers
3. Update test payloads in `utils/payloads.py`
4. Document new test cases in this README