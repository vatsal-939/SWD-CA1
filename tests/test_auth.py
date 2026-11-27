import pytest
from app.database import query_db

def test_security_headers_present(client):
    """Ensure essential security headers are sent in every response."""
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert 'Content-Security-Policy' in response.headers
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'


def test_successful_login(client):
    """Test valid credential authentication and session establishment."""
    response = client.post('/auth/login', data={
        'username': 'dr_smith',
        'password': 'DoctorPass123!@#'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Welcome back, Dr. Alice Smith, MD" in response.data
    
    # Check session cookie attributes
    cookies = response.headers.getlist('Set-Cookie')
    assert any('HttpOnly' in c for c in cookies)
    assert any('SameSite=Strict' in c for c in cookies)


def test_invalid_password_generic_error(client):
    """Verify system does not disclose account existence and returns generic error."""
    response = client.post('/auth/login', data={
        'username': 'dr_smith',
        'password': 'WrongPassword123!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_account_lockout_after_consecutive_failures(client, app):
    """Verify account locks out after 5 consecutive failed attempts."""
    username = 'john_doe'

    # 4 failed attempts: account should not be locked yet
    for i in range(4):
        res = client.post('/auth/login', data={
            'username': username,
            'password': f'WrongPass_{i}'
        }, follow_redirects=True)
        assert b"Invalid username or password" in res.data
        assert b"attempt(s) remaining" in res.data

    # 5th failed attempt: triggers lockout
    res_locked = client.post('/auth/login', data={
        'username': username,
        'password': 'WrongPass_5'
    }, follow_redirects=True)
    assert b"Your account has been locked for 15 minutes" in res_locked.data

    # 6th attempt with correct password during lockout: must still be blocked!
    res_blocked = client.post('/auth/login', data={
        'username': username,
        'password': 'PatientPass123!@#'
    }, follow_redirects=True)
    assert b"Account is temporarily locked" in res_blocked.data


def test_password_complexity_on_registration(client):
    """Verify registration rejects passwords failing complexity requirements."""
    # 1. Too short
    res_short = client.post('/auth/register', data={
        'full_name': 'Test User',
        'username': 'testuser1',
        'email': 'test1@example.com',
        'password': 'Short1!',
        'confirm_password': 'Short1!'
    }, follow_redirects=True)
    assert b"at least 12 characters" in res_short.data

    # 2. Missing uppercase
    res_no_upper = client.post('/auth/register', data={
        'full_name': 'Test User',
        'username': 'testuser2',
        'email': 'test2@example.com',
        'password': 'lowercase1234!@#',
        'confirm_password': 'lowercase1234!@#'
    }, follow_redirects=True)
    assert b"uppercase letter" in res_no_upper.data

    # 3. Missing digit
    res_no_digit = client.post('/auth/register', data={
        'full_name': 'Test User',
        'username': 'testuser3',
        'email': 'test3@example.com',
        'password': 'NoDigitPassword!@#',
        'confirm_password': 'NoDigitPassword!@#'
    }, follow_redirects=True)
    assert b"at least one digit" in res_no_digit.data

    # 4. Missing special character
    res_no_special = client.post('/auth/register', data={
        'full_name': 'Test User',
        'username': 'testuser4',
        'email': 'test4@example.com',
        'password': 'NoSpecialChar1234',
        'confirm_password': 'NoSpecialChar1234'
    }, follow_redirects=True)
    assert b"special character" in res_no_special.data

    # 5. Compliant password succeeds
    res_success = client.post('/auth/register', data={
        'full_name': 'Test User',
        'username': 'testuser_ok',
        'email': 'testok@example.com',
        'password': 'ValidPassword123!@#',
        'confirm_password': 'ValidPassword123!@#'
    }, follow_redirects=True)
    assert b"Account registered successfully" in res_success.data
