"""
app.py - Athena Library Management System
Phase 4: Production Deployment, Security Hardening, Sanitized CSV Export & UX Enhancements
"""

import os
import io
import csv
import logging
import secrets
from datetime import date, timedelta
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from database import init_db, get_late_fee_per_day, set_late_fee_per_day, calculate_fine
import db_operations
import security
import validators

app = Flask(__name__)

# ==============================================================================
# ENVIRONMENT & SECURITY CONFIGURATION
# ==============================================================================

# Explicit APP_ENV check
APP_ENV = os.environ.get("APP_ENV", "development").lower()
IS_PRODUCTION = (APP_ENV == "production")

# Secure logging configuration
logging.basicConfig(
    level=logging.INFO if IS_PRODUCTION else logging.DEBUG,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)

# Secure SECRET_KEY loading
flask_secret = os.environ.get("FLASK_SECRET_KEY")
if not flask_secret:
    if IS_PRODUCTION:
        raise RuntimeError("CRITICAL ERROR: FLASK_SECRET_KEY environment variable is mandatory in production mode.")
    # Safe ephemeral key for local development and non-production testing
    flask_secret = "athena-lms-development-secret-token-" + secrets.token_hex(16)

app.secret_key = flask_secret

# Production Cookie Security Settings
COOKIE_SECURE = IS_PRODUCTION or (os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true")
app.config.update(
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    WTF_CSRF_TIME_LIMIT=7200  # 2 hours
)

# Established CSRF Protection via Flask-WTF
csrf = CSRFProtect(app)

# Reverse Proxy Support: Only wrap ProxyFix if PROXIES_COUNT > 0
# Never blindly trust forwarded headers without an explicit proxy topology count.
PROXIES_COUNT = int(os.environ.get("PROXIES_COUNT", 0))
if PROXIES_COUNT > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXIES_COUNT,
        x_proto=PROXIES_COUNT,
        x_host=PROXIES_COUNT,
        x_prefix=PROXIES_COUNT
    )
    app.logger.info(f"ProxyFix middleware enabled with {PROXIES_COUNT} trusted upstream proxies.")

# Initialize database schema and pre-migration backup if needed
init_db()


# ==============================================================================
# HTTP SECURITY HEADERS & CONTENT SECURITY POLICY (CSP)
# ==============================================================================

@app.after_request
def apply_security_headers(response):
    """
    Applies defense-in-depth HTTP security headers to all responses.
    - Strict Content Security Policy (CSP): restricts script, style, image, font execution to trusted sources.
    - X-Content-Type-Options: prevents MIME-sniffing.
    - X-Frame-Options: protects against clickjacking.
    - Referrer-Policy: avoids leaking internal paths.
    - Obsolete X-XSS-Protection header is deliberately omitted per modern W3C/OWASP standards.
    """
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ==============================================================================
# ERROR HANDLERS
# ==============================================================================

@app.errorhandler(400)
def bad_request_error(e):
    return render_template(
        "error.html",
        error_code=400,
        error_title="Bad Request",
        error_message="The server could not understand the request due to invalid syntax or parameters."
    ), 400


@app.errorhandler(401)
def unauthorized_error(e):
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401
    return render_template(
        "error.html",
        error_code=401,
        error_title="Unauthorized",
        error_message="You must be authenticated to access this protected library resource."
    ), 401


@app.errorhandler(403)
def forbidden_error(e):
    return render_template(
        "error.html",
        error_code=403,
        error_title="Access Forbidden",
        error_message="You do not have permission to access the requested resource."
    ), 403


@app.errorhandler(CSRFError)
def csrf_token_error(e):
    """Handles expired, missing or invalid CSRF tokens safely."""
    app.logger.warning(f"CSRF validation failed for path '{request.path}' from IP {request.remote_addr}: {e.description}")
    flash("Your security session token has expired or is invalid. Please refresh the page and try again.", "error")
    return render_template(
        "error.html",
        error_code=403,
        error_title="Security Token Error (CSRF)",
        error_message=f"Cross-Site Request Forgery validation failed: {e.description}. Please submit the form again."
    ), 403


@app.errorhandler(404)
def not_found_error(e):
    return render_template(
        "error.html",
        error_code=404,
        error_title="Page Not Found",
        error_message="The requested library record or page could not be located."
    ), 404


@app.errorhandler(500)
def internal_server_error(e):
    # Log exception safely without exposing raw database internals to users
    app.logger.error(f"Internal server error: {e}")
    return render_template(
        "error.html",
        error_code=500,
        error_title="Internal Server Error",
        error_message="A server-side error occurred. The administrative team has been notified."
    ), 500


# ==============================================================================
# AUTHENTICATION ROUTES (LOGIN, LOGOUT & PASSWORD ROTATION)
# ==============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Administrative authentication portal with rate-limiting protection."""
    if "admin_id" in session:
        if session.get("must_change_password"):
            return redirect(url_for("change_password"))
        return redirect(url_for("dashboard"))

    next_url = request.args.get("next", "")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        success, message, admin_data = security.authenticate_admin(username, password, client_ip)

        if success and admin_data:
            session.clear()
            session.permanent = True
            session["admin_id"] = admin_data["id"]
            session["admin_username"] = admin_data["username"]
            session["admin_name"] = admin_data["full_name"]
            session["admin_role"] = admin_data["role"]
            session["must_change_password"] = bool(admin_data["must_change_password"])

            app.logger.info(f"Successful login for user '{username}' from IP {client_ip}")

            if session["must_change_password"]:
                flash("Initial sign-in: You must set a new secure password before proceeding.", "warning")
                return redirect(url_for("change_password"))

            flash(f"Welcome back, {admin_data['full_name']}!", "success")
            # Safe redirect: only redirect to relative URLs
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        else:
            app.logger.warning(f"Failed login attempt for user '{username}' from IP {client_ip}: {message}")
            flash(message, "error")

    return render_template("login.html", next_url=next_url)


@app.route("/logout")
def logout():
    """Terminates administrative session."""
    user = session.get("admin_username", "anonymous")
    session.clear()
    app.logger.info(f"User '{user}' logged out.")
    flash("You have been signed out safely.", "info")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@security.login_required
def change_password():
    """Enforces mandatory or voluntary password rotation."""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        try:
            security.change_admin_password(
                admin_id=session["admin_id"],
                current_password=current_password,
                new_password=new_password,
                confirm_password=confirm_password
            )
            session["must_change_password"] = False
            app.logger.info(f"Admin password changed for ID {session['admin_id']}.")
            flash("Administrator password successfully updated. System unlocked.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            flash(f"Unexpected error updating password: {e}", "error")

    return render_template("change_password.html", active_page="change-password")


# ==============================================================================
# DASHBOARD OVERVIEW
# ==============================================================================

@app.route("/")
@security.login_required
def dashboard():
    """Main Library Management System Dashboard connected to live SQLite aggregates."""
    stats, recent_issues, categories = db_operations.get_dashboard_data()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        recent_issues=recent_issues,
        categories=categories
    )


@app.route("/api/index", methods=["GET", "POST"])
def vercel_entrypoint_fallback():
    """Diagnostic route to inspect exact Vercel request environ."""
    return jsonify({
        "PATH_INFO": request.environ.get("PATH_INFO"),
        "RAW_URI": request.environ.get("RAW_URI"),
        "REQUEST_URI": request.environ.get("REQUEST_URI"),
        "QUERY_STRING": request.environ.get("QUERY_STRING"),
        "HTTP_X_MATCHED_PATH": request.environ.get("HTTP_X_MATCHED_PATH"),
        "HEADERS": {k: v for k, v in request.environ.items() if k.startswith("HTTP_")}
    })


# ==============================================================================
# BOOK MANAGEMENT & SANITIZED CSV EXPORT ROUTES
# ==============================================================================

@app.route("/books")
@security.login_required
def books():
    """Books catalog interface with search, category filtering, and inventory status."""
    search_query = request.args.get("q", "").strip()
    category_filter = request.args.get("category", "All").strip()

    books_list = db_operations.get_all_books(
        search_query=search_query if search_query else None,
        category_filter=category_filter if category_filter != "All" else None
    )
    categories = db_operations.get_distinct_categories()

    return render_template(
        "books.html",
        active_page="books",
        books=books_list,
        categories=categories,
        current_query=search_query,
        current_category=category_filter
    )


@app.route("/books/export")
@security.login_required
def export_books():
    """
    Exports the books catalog to a sanitized CSV file.
    Applies formula-injection defense against Excel/Calc macro triggers.
    """
    books_list = db_operations.get_all_books()
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Book Code", "Title", "Author", "Category", "ISBN", "Total Copies", "Available Copies", "Status"
    ])

    for b in books_list:
        writer.writerow([
            validators.sanitize_csv_value(b.get("book_code")),
            validators.sanitize_csv_value(b.get("title")),
            validators.sanitize_csv_value(b.get("author")),
            validators.sanitize_csv_value(b.get("category")),
            validators.sanitize_csv_value(b.get("isbn")),
            validators.sanitize_csv_value(b.get("total_copies")),
            validators.sanitize_csv_value(b.get("available_copies")),
            validators.sanitize_csv_value(b.get("status"))
        ])

    today_str = date.today().strftime("%Y%m%d")
    filename = f"athena_books_{today_str}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/books/add", methods=["POST"])
@security.login_required
def add_book_route():
    """Processes new book addition with server-side validation."""
    title = request.form.get("title", "")
    author = request.form.get("author", "")
    category = request.form.get("category", "")
    isbn = request.form.get("isbn", "")
    total_copies = request.form.get("total_copies", 1)

    try:
        book_code = db_operations.add_book(title, author, category, isbn, total_copies)
        flash(f"Successfully added '{title}' (Code: {book_code}) to the catalog with {total_copies} copies.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected database error adding book: {str(e)}", "error")

    return redirect(url_for("books"))


@app.route("/books/<int:book_id>/edit", methods=["POST"])
@security.login_required
def edit_book_route(book_id):
    """Processes updates to book metadata and total copies."""
    title = request.form.get("title", "")
    author = request.form.get("author", "")
    category = request.form.get("category", "")
    isbn = request.form.get("isbn", "")
    total_copies = request.form.get("total_copies", 1)

    try:
        db_operations.update_book(book_id, title, author, category, isbn, total_copies)
        flash(f"Book '{title}' updated successfully.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error updating book: {str(e)}", "error")

    return redirect(url_for("books"))


@app.route("/books/<int:book_id>/delete", methods=["POST"])
@security.login_required
def delete_book_route(book_id):
    """Safely deletes a book volume if no active loans exist."""
    try:
        db_operations.delete_book(book_id)
        flash("Book successfully removed from the library catalog.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error deleting book: {str(e)}", "error")

    return redirect(url_for("books"))


# ==============================================================================
# MEMBER MANAGEMENT & SANITIZED CSV EXPORT ROUTES
# ==============================================================================

@app.route("/members")
@security.login_required
def members():
    """Patron directory interface with membership filtering and loan counters."""
    search_query = request.args.get("q", "").strip()
    type_filter = request.args.get("type", "All").strip()

    members_list = db_operations.get_all_members(
        search_query=search_query if search_query else None,
        type_filter=type_filter if type_filter != "All" else None
    )

    return render_template(
        "members.html",
        active_page="members",
        members=members_list,
        current_query=search_query,
        current_type=type_filter
    )


@app.route("/members/export")
@security.login_required
def export_members():
    """
    Exports all registered members to a sanitized CSV file.
    Applies formula-injection defense against Excel/Calc macro triggers.
    """
    members_list = db_operations.get_all_members()
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Member Code", "Full Name", "Email", "Phone", "Membership Type", "Status", "Registered Date"
    ])

    for m in members_list:
        writer.writerow([
            validators.sanitize_csv_value(m.get("member_code")),
            validators.sanitize_csv_value(m.get("name")),
            validators.sanitize_csv_value(m.get("email")),
            validators.sanitize_csv_value(m.get("phone")),
            validators.sanitize_csv_value(m.get("membership_type")),
            validators.sanitize_csv_value(m.get("status")),
            validators.sanitize_csv_value(m.get("created_at"))
        ])

    today_str = date.today().strftime("%Y%m%d")
    filename = f"athena_members_{today_str}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/members/add", methods=["POST"])
@security.login_required
def add_member_route():
    """Processes registration of a new patron."""
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    membership_type = request.form.get("membership_type", "Student")

    try:
        member_code = db_operations.add_member(name, email, phone, membership_type)
        flash(f"Member '{name}' successfully registered with ID {member_code}.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error registering member: {str(e)}", "error")

    return redirect(url_for("members"))


@app.route("/members/<int:member_id>/edit", methods=["POST"])
@security.login_required
def edit_member_route(member_id):
    """Processes updates to member details and account status."""
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    membership_type = request.form.get("membership_type", "Student")
    status = request.form.get("status", "Active")

    try:
        db_operations.update_member(member_id, name, email, phone, membership_type, status)
        flash(f"Profile for '{name}' successfully updated.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error updating member: {str(e)}", "error")

    return redirect(url_for("members"))


# ==============================================================================
# CIRCULATION: ISSUE BOOKS
# ==============================================================================

@app.route("/issue-books", methods=["GET", "POST"])
@security.login_required
def issue_books():
    """Handles book checkout: GET displays form & active loans; POST issues book."""
    if request.method == "POST":
        try:
            book_id = int(request.form.get("book_id", 0))
            member_id = int(request.form.get("member_id", 0))
            issue_date = request.form.get("issue_date", "")
            due_date = request.form.get("due_date", "")
            remarks = request.form.get("remarks", "")

            result = db_operations.issue_book(book_id, member_id, issue_date, due_date, remarks)
            flash(
                f"Successfully checked out '{result['book_title']}' to {result['member_name']}. "
                f"Loan ID: {result['transaction_code']}, Due Date: {result['due_date']}.",
                "success"
            )
            return redirect(url_for("issue_books"))
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            flash(f"Failed to issue book: {str(e)}", "error")

    # For GET or on validation error
    selected_book_id = request.args.get("book_id", type=int)
    selected_member_id = request.args.get("member_id", type=int)

    available_books = db_operations.get_available_books()
    active_members = db_operations.get_active_members()
    active_loans = db_operations.get_active_transactions()

    today_str = date.today().strftime("%Y-%m-%d")
    default_due_str = (date.today() + timedelta(days=14)).strftime("%Y-%m-%d")

    return render_template(
        "issue_books.html",
        active_page="issue-books",
        books=available_books,
        members=active_members,
        active_loans=active_loans,
        today_str=today_str,
        default_due_str=default_due_str,
        late_fee_per_day=get_late_fee_per_day(),
        selected_book_id=selected_book_id,
        selected_member_id=selected_member_id
    )


# ==============================================================================
# CIRCULATION: RETURN BOOKS & LATE FEES
# ==============================================================================

@app.route("/return-books", methods=["GET", "POST"])
@security.login_required
def return_books():
    """Handles book returns, restocking, overdue calculation, and Decimal late fee assessment."""
    if request.method == "POST":
        try:
            transaction_id = int(request.form.get("transaction_id", 0))
            return_date = request.form.get("return_date", "")
            condition = request.form.get("condition", "Good")
            remarks = request.form.get("remarks", "")
            combined_remarks = f"Condition: {condition}. {remarks}".strip()

            result = db_operations.return_book(transaction_id, return_date, combined_remarks)

            if result["fine_amount"] > Decimal("0.00"):
                flash(
                    f"Book '{result['book_title']}' returned from {result['member_name']}. "
                    f"Overdue by {result['overdue_days']} day(s). "
                    f"Assessed Late Fee: ${result['fine_amount']:.2f}. "
                    f"Copy restocked to inventory.",
                    "warning"
                )
            else:
                flash(
                    f"Book '{result['book_title']}' successfully returned on time from {result['member_name']}. "
                    f"Copy restocked to inventory.",
                    "success"
                )
            return redirect(url_for("return_books"))
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            flash(f"Failed to process return: {str(e)}", "error")

    selected_tx_id = request.args.get("transaction_id", type=int)
    active_loans = db_operations.get_active_transactions()
    today_str = date.today().strftime("%Y-%m-%d")

    return render_template(
        "return_books.html",
        active_page="return-books",
        active_loans=active_loans,
        today_str=today_str,
        late_fee_per_day=get_late_fee_per_day(),
        selected_transaction_id=selected_tx_id
    )


@app.route("/settings/late-fee", methods=["POST"])
@security.login_required
def update_late_fee():
    """Configures the library daily late fee penalty rate with Decimal precision."""
    try:
        rate = request.form.get("rate", "0.50")
        dec_rate = set_late_fee_per_day(rate)
        flash(f"Daily late fee rate updated to ${dec_rate:.2f} per day.", "success")
    except ValueError as e:
        flash(f"Invalid rate value: {str(e)}", "error")
    except Exception as e:
        flash(f"Error updating late fee rate: {str(e)}", "error")

    return redirect(url_for("return_books"))


# ==============================================================================
# PROTECTED API ENDPOINT
# ==============================================================================

@app.route("/api/calculate-fine")
@security.login_required
def api_calculate_fine():
    """Calculates overdue days and accrued fine with Decimal precision for live previews."""
    due_date = request.args.get("due_date", "")
    return_date = request.args.get("return_date", "")

    overdue_days, fine = calculate_fine(due_date, return_date)
    return jsonify({
        "due_date": due_date,
        "return_date": return_date,
        "overdue_days": overdue_days,
        "fine": str(fine),
        "rate": str(get_late_fee_per_day())
    })


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = (APP_ENV != "production")
    app.run(host=host, port=port, debug=debug)
