import os
from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from app.database import close_db

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

def create_app(config_class=Config):
    """Application factory for MedVault."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Security Extensions
    csrf.init_app(app)
    limiter.init_app(app)

    # Register database teardown
    app.teardown_appcontext(close_db)

    # Register Blueprints
    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Security Headers Middleware (Defends against Clickjacking, MIME-sniffing, XSS)
    @app.after_request
    def set_security_headers(response):
        # Defend against clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Control Referrer Information
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Enforce Permissions-Policy
        response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        # Content Security Policy (CSP)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        return response

    # Custom Error Handlers (Prevents stack trace / information leakage)
    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return render_template('errors/429.html', error=e.description), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500

    # Default index route
    @app.route('/')
    def index():
        from flask import redirect, url_for, session
        if 'user_id' in session:
            return redirect(url_for('auth.dashboard'))
        return redirect(url_for('auth.login'))

    return app
