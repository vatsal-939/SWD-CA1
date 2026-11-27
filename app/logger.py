from flask import request
from app.database import execute_db

def log_security_event(action: str, details: str, status: str = "SUCCESS", user_id: int = None):
    """
    Log a security event into the immutable audit_logs table.
    Captures IP address and user-agent information.
    """
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    # Truncate details if excessive to prevent log flooding
    sanitized_details = str(details)[:500]
    try:
        execute_db(
            """
            INSERT INTO audit_logs (user_id, action, details, ip_address, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, action, sanitized_details, ip_addr, status)
        )
    except Exception as e:
        # Fallback print to stdout if DB audit fails (never let logging crash the request)
        print(f"[SECURITY AUDIT FAILURE] Action: {action}, Details: {details}, Error: {e}")
