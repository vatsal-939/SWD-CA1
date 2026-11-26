import os
from datetime import timedelta

class Config:
    """Base application configuration with secure defaults."""
    
    # Secret key for session signing and CSRF tokens
    # In production, this must be set via an environment variable with high entropy
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-secret-key-change-in-production-1234567890')
    
    # Database path
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'medvault.db'))
    
    # Session Security Configuration (Defends against session hijacking & fixation)
    SESSION_COOKIE_NAME = '__Host-medvault_session' if os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true' else 'medvault_session'
    SESSION_COOKIE_HTTPONLY = True          # Prevents JavaScript access (Anti-XSS cookie theft)
    SESSION_COOKIE_SAMESITE = 'Strict'      # Mitigates Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'  # True for HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('PERMANENT_SESSION_LIFETIME_MINUTES', 30)))
    
    # Brute-force & Account Lockout Policy
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get('LOCKOUT_DURATION_MINUTES', 15))
    
    # Rate Limiting configuration (Flask-Limiter)
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"
    
    # Password Complexity Requirements
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True


class DevelopmentConfig(Config):
    DEBUG = False  # Keep False even in dev to avoid debug pin / code execution risks
    TESTING = False


class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ':memory:'  # Use in-memory DB for unit and security tests
    WTF_CSRF_ENABLED = False     # Disable CSRF only during specific test cases if needed
