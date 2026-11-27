import re
from functools import wraps
from flask import session, redirect, url_for, flash, abort, request
import bleach

def validate_password_complexity(password: str) -> tuple[bool, str]:
    """
    Validates password against secure policy:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."
    return True, ""


def sanitize_input(text: str) -> str:
    """
    Strip HTML tags and dangerous characters to prevent XSS.
    """
    if not text:
        return ""
    # bleach.clean removes tags and attributes
    cleaned = bleach.clean(str(text), tags=[], attributes={}, strip=True)
    return cleaned.strip()


def login_required(f):
    """Decorator to require authenticated user session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('auth.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    """
    Decorator to enforce Role-Based Access Control (RBAC).
    Returns 403 Forbidden if user lacks required role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('auth.login', next=request.path))
            
            user_role = session.get('role')
            if user_role not in allowed_roles:
                from app.logger import log_security_event
                log_security_event(
                    action="UNAUTHORIZED_ACCESS_ATTEMPT",
                    details=f"User {session.get('username')} (role: {user_role}) attempted to access {request.path} which requires {allowed_roles}",
                    status="BLOCKED",
                    user_id=session.get('user_id')
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
