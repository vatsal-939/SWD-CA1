from datetime import datetime, timedelta, timezone
import re
import bcrypt
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app
)
from app.database import query_db, execute_db
from app.logger import log_security_event
from app.security_utils import (
    validate_password_complexity, sanitize_input, login_required
)
from app import limiter

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    """Secure user registration endpoint (defaults to patient role)."""
    if 'user_id' in session:
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '')).lower()
        email = sanitize_input(request.form.get('email', '')).lower()
        full_name = sanitize_input(request.form.get('full_name', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # 1. Input Validation
        if not username or not email or not full_name or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')

        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            flash("Username must be between 3 and 30 characters and contain only letters, numbers, and underscores.", "danger")
            return render_template('register.html')

        # Simple RFC-compliant email regex
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash("Please enter a valid email address.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        # 2. Password Complexity Validation
        is_valid, msg = validate_password_complexity(password)
        if not is_valid:
            flash(msg, "danger")
            return render_template('register.html')

        # 3. Check for existing username or email using parameterized query
        existing = query_db(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
            one=True
        )
        if existing:
            flash("An account with that username or email already exists.", "warning")
            return render_template('register.html')

        # 4. Hash password with bcrypt
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        # 5. Insert new user with default 'patient' role (strict privilege separation)
        try:
            execute_db(
                """
                INSERT INTO users (username, email, password_hash, role, full_name)
                VALUES (?, ?, ?, 'patient', ?)
                """,
                (username, email, password_hash, full_name)
            )
            log_security_event(
                action="USER_REGISTRATION",
                details=f"New patient account registered: {username} ({email})",
                status="SUCCESS"
            )
            flash("Account registered successfully! You can now log in.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash("An error occurred during registration. Please try again.", "danger")
            return render_template('register.html')

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    """
    Secure login endpoint with rate limiting, bcrypt verification,
    account lockout, and session fixation prevention.
    """
    if 'user_id' in session:
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '')).lower()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Both username and password are required.", "danger")
            return render_template('login.html')

        # Fetch user securely using parameterized query
        user = query_db(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            one=True
        )

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Check account lockout if user exists
        if user and user['lockout_until']:
            try:
                lockout_time = datetime.strptime(user['lockout_until'], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                lockout_time = None

            if lockout_time and now < lockout_time:
                remaining_mins = int((lockout_time - now).total_seconds() // 60) + 1
                log_security_event(
                    action="LOGIN_BLOCKED_LOCKOUT",
                    details=f"Login attempt on locked account '{username}'",
                    status="BLOCKED",
                    user_id=user['id']
                )
                flash(f"Account is temporarily locked due to multiple failed login attempts. Please try again in {remaining_mins} minute(s).", "danger")
                return render_template('login.html')
            elif lockout_time and now >= lockout_time:
                # Lockout period expired: reset counter
                execute_db(
                    "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?",
                    (user['id'],)
                )

        # Constant-time password check via bcrypt
        is_authenticated = False
        if user:
            try:
                is_authenticated = bcrypt.checkpw(
                    password.encode('utf-8'),
                    user['password_hash'].encode('utf-8')
                )
            except Exception:
                is_authenticated = False

        if not user or not is_authenticated:
            # Handle failed login
            if user:
                new_attempts = user['failed_login_attempts'] + 1
                max_attempts = current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS', 5)
                lockout_mins = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)

                if new_attempts >= max_attempts:
                    lockout_until_str = (now + timedelta(minutes=lockout_mins)).strftime("%Y-%m-%d %H:%M:%S")
                    execute_db(
                        "UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?",
                        (new_attempts, lockout_until_str, user['id'])
                    )
                    log_security_event(
                        action="ACCOUNT_LOCKOUT",
                        details=f"Account '{username}' locked for {lockout_mins} mins after {new_attempts} failed attempts",
                        status="WARNING",
                        user_id=user['id']
                    )
                    flash(f"Too many failed login attempts. Your account has been locked for {lockout_mins} minutes.", "danger")
                else:
                    execute_db(
                        "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
                        (new_attempts, user['id'])
                    )
                    log_security_event(
                        action="LOGIN_FAILURE",
                        details=f"Failed login attempt for '{username}' (attempt {new_attempts}/{max_attempts})",
                        status="FAILURE",
                        user_id=user['id']
                    )
                    attempts_left = max_attempts - new_attempts
                    flash(f"Invalid username or password. {attempts_left} attempt(s) remaining before account lockout.", "danger")
            else:
                # Generic message to prevent username enumeration
                log_security_event(
                    action="LOGIN_FAILURE_UNKNOWN_USER",
                    details=f"Failed login attempt for non-existent username: '{username}'",
                    status="FAILURE"
                )
                flash("Invalid username or password.", "danger")

            return render_template('login.html')

        # Authentication Successful: Reset lockout & attempts
        execute_db(
            "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?",
            (user['id'],)
        )

        # Defend against Session Fixation: clear previous session entirely
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        session.permanent = True

        log_security_event(
            action="LOGIN_SUCCESS",
            details=f"User '{username}' logged in successfully as role: {user['role']}",
            status="SUCCESS",
            user_id=user['id']
        )

        flash(f"Welcome back, {user['full_name']}!", "success")
        return redirect(url_for('auth.dashboard'))

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    """Secure logout: invalidates session on server side."""
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        log_security_event(
            action="LOGOUT",
            details=f"User '{username}' logged out",
            status="SUCCESS",
            user_id=user_id
        )

    session.clear()
    flash("You have been safely logged out.", "info")
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard tailored to the current user's role."""
    user_role = session.get('role')
    user_id = session.get('user_id')

    # Fetch summary stats based on role
    stats = {}
    if user_role == 'admin':
        stats['total_users'] = query_db("SELECT COUNT(*) FROM users", one=True)[0]
        stats['total_records'] = query_db("SELECT COUNT(*) FROM medical_records WHERE is_deleted = 0", one=True)[0]
        stats['recent_logs'] = query_db("SELECT COUNT(*) FROM audit_logs", one=True)[0]
    elif user_role == 'doctor':
        stats['total_patients'] = query_db("SELECT COUNT(DISTINCT patient_id) FROM medical_records WHERE doctor_id = ? AND is_deleted = 0", (user_id,), one=True)[0]
        stats['my_records'] = query_db("SELECT COUNT(*) FROM medical_records WHERE doctor_id = ? AND is_deleted = 0", (user_id,), one=True)[0]
    else:  # patient
        stats['my_records'] = query_db("SELECT COUNT(*) FROM medical_records WHERE patient_id = ? AND is_deleted = 0", (user_id,), one=True)[0]

    return render_template('dashboard.html', stats=stats)
