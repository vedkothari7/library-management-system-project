"""
security.py - Authentication, Password Hashing, Route Guards & Brute-Force Rate Limiting
Phase 3: Production Security Architecture
"""

from functools import wraps
from datetime import datetime
from flask import session, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection
from validators import validate_password_strength


# ==============================================================================
# BRUTE-FORCE LOGIN RATE LIMITER
# ==============================================================================

def check_login_rate_limit(ip_address: str, username: str, max_attempts: int = 5, window_minutes: int = 15) -> tuple[bool, int]:
    """
    Checks if an IP address or username is temporarily locked out due to excessive failed attempts.
    Returns (is_blocked: bool, retry_after_seconds: int).
    """
    conn = get_db_connection()
    # Query failed attempts within the sliding time window
    query = """
    SELECT COUNT(*) as failed_count,
           MAX(attempt_time) as last_attempt
    FROM login_attempts
    WHERE (username = ? OR ip_address = ?)
      AND success = 0
      AND attempt_time >= datetime('now', ? || ' minutes');
    """
    row = conn.execute(query, (username.strip().lower(), ip_address, f"-{window_minutes}")).fetchone()
    conn.close()

    if row and row["failed_count"] >= max_attempts:
        return True, window_minutes * 60
    return False, 0


def record_login_attempt(ip_address: str, username: str, success: bool):
    """Logs a login attempt for security auditing and rate limiting."""
    conn = get_db_connection()
    conn.execute("""
    INSERT INTO login_attempts (ip_address, username, success)
    VALUES (?, ?, ?);
    """, (ip_address, username.strip().lower(), 1 if success else 0))
    conn.commit()
    conn.close()


def clear_failed_login_attempts(username: str, ip_address: str):
    """Clears failed attempts upon successful authentication."""
    conn = get_db_connection()
    conn.execute("""
    DELETE FROM login_attempts
    WHERE (username = ? OR ip_address = ?) AND success = 0;
    """, (username.strip().lower(), ip_address))
    conn.commit()
    conn.close()


# ==============================================================================
# ADMIN AUTHENTICATION & PASSWORD ROTATION
# ==============================================================================

def authenticate_admin(username: str, password: str, ip_address: str) -> tuple[bool, str, dict]:
    """
    Authenticates administrator with rate limiting and timing-safe password hash check.
    Returns (success: bool, message: str, admin_data: dict | None).
    """
    username_clean = username.strip().lower()

    # 1. Check rate limit
    is_blocked, wait_secs = check_login_rate_limit(ip_address, username_clean)
    if is_blocked:
        return False, "Too many failed login attempts. Account temporarily locked for 15 minutes.", None

    conn = get_db_connection()
    admin = conn.execute("""
    SELECT * FROM admins WHERE LOWER(username) = ?;
    """, (username_clean,)).fetchone()

    # Generic failure message to prevent username enumeration
    generic_error = "Invalid username or password."

    if not admin or not check_password_hash(admin["password_hash"], password):
        conn.close()
        record_login_attempt(ip_address, username_clean, success=False)
        return False, generic_error, None

    # Record success and reset failed attempts
    record_login_attempt(ip_address, username_clean, success=True)
    clear_failed_login_attempts(username_clean, ip_address)

    # Update last login
    conn.execute("""
    UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?;
    """, (admin["id"],))
    conn.commit()
    conn.close()

    return True, "Authentication successful.", dict(admin)


def change_admin_password(admin_id: int, current_password: str, new_password: str, confirm_password: str):
    """
    Forces secure password update. Validates current password, checks complexity,
    and clears the must_change_password flag.
    """
    if new_password != confirm_password:
        raise ValueError("New password and confirmation password do not match.")

    # Validate complexity
    validate_password_strength(new_password)

    conn = get_db_connection()
    admin = conn.execute("SELECT * FROM admins WHERE id = ?;", (admin_id,)).fetchone()
    if not admin:
        conn.close()
        raise ValueError("Admin account not found.")

    if not check_password_hash(admin["password_hash"], current_password):
        conn.close()
        raise ValueError("Current temporary password is incorrect.")

    if check_password_hash(admin["password_hash"], new_password):
        conn.close()
        raise ValueError("New password must be different from your current password.")

    new_hash = generate_password_hash(new_password)
    conn.execute("""
    UPDATE admins
    SET password_hash = ?, must_change_password = 0
    WHERE id = ?;
    """, (new_hash, admin_id))
    conn.commit()
    conn.close()


# ==============================================================================
# ROUTE PROTECTION DECORATOR
# ==============================================================================

def login_required(f):
    """
    Protects views from unauthenticated access.
    Redirects web requests to /login and returns 401 JSON for API requests.
    Enforces password rotation if must_change_password is true.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            # Check if this is an API request
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"error": "Unauthorized", "message": "Authentication required.", "status": 401}), 401

            flash("Please sign in to access the Library Management System.", "warning")
            return redirect(url_for("login", next=request.url))

        # Check if forced password rotation is active
        if session.get("must_change_password") and request.endpoint not in ["change_password", "logout", "static"]:
            flash("You are using a temporary password. You must change your password to continue.", "warning")
            return redirect(url_for("change_password"))

        return f(*args, **kwargs)
    return decorated_function
