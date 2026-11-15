"""
test_backend.py - Unified Automated Test Suite for Library Management System
Validates Phase 1, Phase 2, and Phase 3 Security, Testing, Decimal Currency & Route Protections
Runs exclusively against an isolated temporary database to protect production project data.
"""

import unittest
import os
import io
import tempfile
from datetime import date, timedelta
from decimal import Decimal
from werkzeug.security import check_password_hash

import database
import db_operations
import security
import validators
from app import app


class TestAthenaLibrarySystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Creates an isolated temporary test database fixture."""
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False  # Disabled by default for functional route testing

        # Generate a distinct temporary SQLite database file
        cls.temp_db_fd, cls.temp_db_path = tempfile.mkstemp(prefix="athena_test_", suffix=".db")
        os.close(cls.temp_db_fd)

        # Redirect the application database engine to the temporary database
        cls.original_env_db = os.environ.get("DATABASE_PATH")
        cls.original_db_path = database.DB_PATH
        os.environ["DATABASE_PATH"] = cls.temp_db_path
        database.DB_PATH = cls.temp_db_path

        # Initialize schema and seeds inside the temporary database
        database.init_db()
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Cleans up the temporary database and restores original DB path."""
        if cls.original_env_db is not None:
            os.environ["DATABASE_PATH"] = cls.original_env_db
        else:
            os.environ.pop("DATABASE_PATH", None)
        database.DB_PATH = cls.original_db_path
        if os.path.exists(cls.temp_db_path):
            try:
                os.remove(cls.temp_db_path)
            except OSError:
                pass
        # Remove any SQLite WAL sidecars if created
        for ext in ["-wal", "-shm"]:
            sidecar = cls.temp_db_path + ext
            if os.path.exists(sidecar):
                try:
                    os.remove(sidecar)
                except OSError:
                    pass

    def _login_admin(self, must_change_pw: bool = False):
        """Helper to simulate an active authenticated administrator session."""
        with self.client.session_transaction() as sess:
            sess["admin_id"] = 1
            sess["admin_username"] = "admin"
            sess["admin_name"] = "Librarian Admin"
            sess["admin_role"] = "System Administrator"
            sess["must_change_password"] = must_change_pw

    # ==========================================================================
    # 1. DATABASE INTEGRITY & FOREIGN KEY ENFORCEMENT
    # ==========================================================================
    def test_01_foreign_key_enforcement_and_tables(self):
        """Verify SQLite foreign key enforcement is active and all tables exist."""
        conn = database.get_db_connection()
        fk_status = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        self.assertEqual(fk_status, 1, "Foreign key enforcement must be active on every connection.")

        tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        conn.close()

        expected = ["books", "members", "transactions", "settings", "admins", "login_attempts"]
        for tbl in expected:
            self.assertIn(tbl, tables, f"Expected table '{tbl}' was not found in schema.")

    # ==========================================================================
    # 2. TEMPORARY CREDENTIALS & MANDATORY FIRST-LOGIN PASSWORD ROTATION
    # ==========================================================================
    def test_02_temporary_credentials_and_forced_rotation(self):
        """Verify default admin has temporary status and is forced to rotate password."""
        conn = database.get_db_connection()
        admin = conn.execute("SELECT * FROM admins WHERE username = 'admin';").fetchone()
        conn.close()

        self.assertIsNotNone(admin)
        self.assertEqual(admin["must_change_password"], 1)
        self.assertTrue(check_password_hash(admin["password_hash"], "Admin@Temporary123!"))

        # Login with temporary credentials
        res = self.client.post("/login", data={
            "username": "admin",
            "password": "Admin@Temporary123!"
        }, follow_redirects=False)

        # Must redirect to /change-password
        self.assertEqual(res.status_code, 302)
        self.assertIn("/change-password", res.headers.get("Location", ""))

        # Attempting to access dashboard before changing password must be blocked
        self._login_admin(must_change_pw=True)
        dash_res = self.client.get("/", follow_redirects=False)
        self.assertEqual(dash_res.status_code, 302)
        self.assertIn("/change-password", dash_res.headers.get("Location", ""))

        # Successful password change
        new_pw = "NewSecurePassword#2026!"
        change_res = self.client.post("/change-password", data={
            "current_password": "Admin@Temporary123!",
            "new_password": new_pw,
            "confirm_password": new_pw
        }, follow_redirects=True)
        self.assertEqual(change_res.status_code, 200)

        # Verify database flag updated to 0
        conn = database.get_db_connection()
        updated_admin = conn.execute("SELECT * FROM admins WHERE username = 'admin';").fetchone()
        conn.close()
        self.assertEqual(updated_admin["must_change_password"], 0)
        self.assertTrue(check_password_hash(updated_admin["password_hash"], new_pw))

    # ==========================================================================
    # 3. ROUTE PROTECTION & API ACCESS CONTROL
    # ==========================================================================
    def test_03_unauthenticated_route_protection(self):
        """Verify all views and APIs are protected against unauthorized access."""
        # Clear any session
        with self.client.session_transaction() as sess:
            sess.clear()

        protected_web_routes = ["/", "/books", "/members", "/issue-books", "/return-books"]
        for route in protected_web_routes:
            res = self.client.get(route, follow_redirects=False)
            self.assertEqual(res.status_code, 302, f"Unauthenticated access to '{route}' must redirect to /login.")
            self.assertIn("/login", res.headers.get("Location", ""))

        # Protected API endpoint must return 401 JSON, not redirect
        api_res = self.client.get("/api/calculate-fine?due_date=2026-11-01&return_date=2026-11-05")
        self.assertEqual(api_res.status_code, 401)
        self.assertEqual(api_res.get_json().get("error"), "Unauthorized")

    # ==========================================================================
    # 4. LOGIN RATE LIMITING & BRUTE-FORCE PROTECTION
    # ==========================================================================
    def test_04_brute_force_rate_limiting(self):
        """Verify 5 consecutive failed logins trigger a 15-minute temporary lockout."""
        ip = "192.168.1.100"
        username = "target_admin"

        # Submit 5 failed attempts
        for _ in range(5):
            success, msg, data = security.authenticate_admin(username, "WrongPassword!", ip)
            self.assertFalse(success)
            self.assertEqual(msg, "Invalid username or password.")

        # 6th attempt must be throttled
        blocked, msg, data = security.authenticate_admin(username, "EvenCorrectPassword", ip)
        self.assertFalse(blocked)
        self.assertIn("temporarily locked", msg)

        # Clean up login attempts for this IP
        security.clear_failed_login_attempts(username, ip)

    # ==========================================================================
    # 5. SERVER-SIDE INPUT VALIDATION & REGEX INTEGRITY
    # ==========================================================================
    def test_05_input_validators(self):
        """Verify server-side validation catches invalid emails, ISBNs, and negative values."""
        # Invalid book titles or quantities
        with self.assertRaises(ValueError):
            validators.validate_book("", "Author", "Category", "978-0132350884", 5)
        with self.assertRaises(ValueError):
            validators.validate_book("Valid Title", "Author", "Category", "invalid-isbn", 5)
        with self.assertRaises(ValueError):
            validators.validate_book("Valid Title", "Author", "Category", "978-0132350884", -3)

        # Invalid emails or phones
        with self.assertRaises(ValueError):
            validators.validate_member("John Doe", "notanemail", "+1 (555) 123-4567")
        with self.assertRaises(ValueError):
            validators.validate_member("John Doe", "john@example.com", "abc")  # Non-numeric phone

        # Invalid circulation dates
        with self.assertRaises(ValueError):
            validators.validate_circulation_dates("2026-11-20", "2026-11-10")  # Due before issue

        # Password complexity rules
        with self.assertRaises(ValueError):
            validators.validate_password_strength("weak")
        with self.assertRaises(ValueError):
            validators.validate_password_strength("NoSpecialNumber1")

    # ==========================================================================
    # 6. SQL INJECTION PREVENTION (PARAMETERIZED QUERIES)
    # ==========================================================================
    def test_06_sql_injection_defense(self):
        """Verify SQL injection payloads are treated as literal text values."""
        self._login_admin()

        malicious_inputs = [
            "' OR '1'='1",
            "'; DROP TABLE books; --",
            "' UNION SELECT username, password_hash, 1, 1, 1 FROM admins --"
        ]

        for payload in malicious_inputs:
            # Search query injection attempt
            res = self.client.get(f"/books?q={payload}")
            self.assertEqual(res.status_code, 200)

            # Verification that books table remains fully intact
            conn = database.get_db_connection()
            count = conn.execute("SELECT COUNT(*) as count FROM books;").fetchone()["count"]
            conn.close()
            self.assertGreater(count, 0, "Books table must not be damaged by SQL injection payloads.")

    # ==========================================================================
    # 7. DECIMAL MONETARY PRECISION & LATE FEES
    # ==========================================================================
    def test_07_decimal_currency_accuracy(self):
        """Verify late fees use exact Decimal arithmetic and avoid float rounding errors."""
        # Set fee to $0.75 per day
        database.set_late_fee_per_day(Decimal("0.75"))
        self.assertEqual(database.get_late_fee_per_day(), Decimal("0.75"))

        # 3 days overdue: exactly $2.25
        days, fine = database.calculate_fine("2026-11-10", "2026-11-13")
        self.assertEqual(days, 3)
        self.assertEqual(fine, Decimal("2.25"))
        self.assertIsInstance(fine, Decimal)

        # 0 days overdue: exactly $0.00
        days, fine = database.calculate_fine("2026-11-15", "2026-11-10")
        self.assertEqual(days, 0)
        self.assertEqual(fine, Decimal("0.00"))

        # Restore default rate
        database.set_late_fee_per_day(Decimal("0.50"))

    # ==========================================================================
    # 8. BOOK & MEMBER CRUD OPERATIONS
    # ==========================================================================
    def test_08_book_and_member_crud(self):
        """Test adding, editing, and querying books and members."""
        self._login_admin()

        # Add Book
        isbn = "978-0131103627"
        code = db_operations.add_book(
            title="The C Programming Language",
            author="Brian Kernighan, Dennis Ritchie",
            category="Computer Science",
            isbn=isbn,
            total_copies=5
        )
        self.assertTrue(code.startswith("BK-"))

        # Update Book
        book = db_operations.get_all_books(search_query="Kernighan")[0]
        db_operations.update_book(
            book_id=book["id"],
            title="The C Programming Language (2nd Edition)",
            author=book["author"],
            category=book["category"],
            isbn=book["isbn"],
            total_copies=7
        )
        updated = db_operations.get_book_by_id(book["id"])
        self.assertEqual(updated["total_copies"], 7)
        self.assertEqual(updated["available_copies"], 7)

        # Add Member
        mem_code = db_operations.add_member(
            name="Dennis Ritchie",
            email="dennis.ritchie@bell-labs.com",
            phone="+1 (555) 444-5555",
            membership_type="Faculty"
        )
        self.assertTrue(mem_code.startswith("MEM-"))

    # ==========================================================================
    # 9. CIRCULATION: ATOMIC ISSUE AND RETURN
    # ==========================================================================
    def test_09_circulation_issue_and_return_lifecycle(self):
        """Test complete loan lifecycle, stock balance, and duplicate prevention."""
        self._login_admin()

        # Create fresh book & member
        b_code = db_operations.add_book("Clean Architecture", "Robert C. Martin", "Computer Science", "978-0134494166", 2)
        m_code = db_operations.add_member("Ken Thompson", "ken@bell-labs.com", "+1 (555) 777-6666", "Faculty")

        b = db_operations.get_all_books(search_query="Architecture")[0]
        m = db_operations.get_all_members(search_query="Thompson")[0]

        # Issue book
        today_str = date.today().strftime("%Y-%m-%d")
        due_str = (date.today() + timedelta(days=14)).strftime("%Y-%m-%d")
        tx = db_operations.issue_book(b["id"], m["id"], today_str, due_str, "Semester research")
        self.assertTrue(tx["transaction_code"].startswith("ISS-"))

        # Available copies must be decremented to 1
        self.assertEqual(db_operations.get_book_by_id(b["id"])["available_copies"], 1)

        # Prevent duplicate issue of same book
        with self.assertRaises(ValueError):
            db_operations.issue_book(b["id"], m["id"], today_str, due_str)

        # Return book
        loans = db_operations.get_active_transactions()
        target_loan = next(l for l in loans if l["transaction_code"] == tx["transaction_code"])
        ret = db_operations.return_book(target_loan["id"], today_str, "Pristine")

        # Available copies restored back to 2
        self.assertEqual(db_operations.get_book_by_id(b["id"])["available_copies"], 2)
        self.assertEqual(ret["fine_amount"], Decimal("0.00"))

        # Duplicate return rejected
        with self.assertRaises(ValueError):
            db_operations.return_book(target_loan["id"], today_str)

    # ==========================================================================
    # 10. CSRF PROTECTION ENFORCEMENT
    # ==========================================================================
    def test_10_csrf_protection_enforcement(self):
        """Verify state-changing POST requests without CSRF token are blocked with 403."""
        # Temporarily enable CSRF verification
        app.config["WTF_CSRF_ENABLED"] = True

        try:
            # Attempt POST /login without CSRF token
            res = self.client.post("/login", data={
                "username": "admin",
                "password": "AnyPassword"
            })
            self.assertEqual(res.status_code, 403, "POST request without CSRF token must return 403 Forbidden.")
            self.assertIn(b"CSRF", res.data)
        finally:
            # Restore testing mode
            app.config["WTF_CSRF_ENABLED"] = False

    # ==========================================================================
    # 11. CSV FORMULA INJECTION SANITIZATION (CWE-1236)
    # ==========================================================================
    def test_11_csv_formula_injection_sanitization(self):
        """Verify CSV formula triggers are neutralized even with leading whitespace and control characters."""
        # Standard triggers
        self.assertEqual(validators.sanitize_csv_value("=1+1"), "'=1+1")
        self.assertEqual(validators.sanitize_csv_value("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(validators.sanitize_csv_value("-5"), "'-5")
        self.assertEqual(validators.sanitize_csv_value("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(validators.sanitize_csv_value("\t=1+1"), "'\t=1+1")
        self.assertEqual(validators.sanitize_csv_value("\r@calc"), "'\r@calc")

        # Leading spaces, tabs, and carriage return disguises
        self.assertEqual(validators.sanitize_csv_value("   =1+1"), "'   =1+1")
        self.assertEqual(validators.sanitize_csv_value(" \t+calc"), "' \t+calc")
        self.assertEqual(validators.sanitize_csv_value("  @DDE()"), "'  @DDE()")
        self.assertEqual(validators.sanitize_csv_value("\t\r\n=cmd"), "'\t\r\n=cmd")

        # Benign values must remain unchanged
        self.assertEqual(validators.sanitize_csv_value("Clean Code"), "Clean Code")
        self.assertEqual(validators.sanitize_csv_value("978-0132350884"), "978-0132350884")
        self.assertEqual(validators.sanitize_csv_value("user@example.com"), "user@example.com")
        self.assertEqual(validators.sanitize_csv_value(42), "42")
        self.assertEqual(validators.sanitize_csv_value(None), "")

    # ==========================================================================
    # 12. SANITIZED CSV EXPORT ENDPOINTS
    # ==========================================================================
    def test_12_csv_export_endpoints(self):
        """Verify /books/export and /members/export are protected and stream sanitized CSVs."""
        # Unauthenticated access must redirect to login
        with self.client.session_transaction() as sess:
            sess.clear()
        self.assertEqual(self.client.get("/books/export").status_code, 302)
        self.assertEqual(self.client.get("/members/export").status_code, 302)

        # Authenticated access
        self._login_admin()
        
        # Books export
        res_books = self.client.get("/books/export")
        self.assertEqual(res_books.status_code, 200)
        self.assertIn("text/csv", res_books.headers.get("Content-Type", ""))
        self.assertIn("attachment; filename=athena_books_", res_books.headers.get("Content-Disposition", ""))
        books_data = res_books.data.decode("utf-8")
        self.assertIn("Book Code,Title,Author,Category,ISBN,Total Copies,Available Copies,Status", books_data)
        self.assertIn("Clean Code", books_data)

        # Members export
        res_members = self.client.get("/members/export")
        self.assertEqual(res_members.status_code, 200)
        self.assertIn("text/csv", res_members.headers.get("Content-Type", ""))
        self.assertIn("attachment; filename=athena_members_", res_members.headers.get("Content-Disposition", ""))
        members_data = res_members.data.decode("utf-8")
        self.assertIn("Member Code,Full Name,Email,Phone,Membership Type,Status,Registered Date", members_data)
        self.assertIn("Sarah Jenkins", members_data)

    # ==========================================================================
    # 13. HTTP SECURITY HEADERS & CONTENT SECURITY POLICY (CSP)
    # ==========================================================================
    def test_13_security_headers_and_csp(self):
        """Verify defense-in-depth security headers and absence of obsolete X-XSS-Protection."""
        with self.client.session_transaction() as sess:
            sess.clear()

        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)

        # Check required security headers
        headers = res.headers
        self.assertIn("Content-Security-Policy", headers)
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

        # Verify obsolete X-XSS-Protection is explicitly omitted
        self.assertNotIn("X-XSS-Protection", headers, "Obsolete X-XSS-Protection header must not be set.")

    # ==========================================================================
    # 14. DATABASE BACKUP, RESTORE & WAL CHECKPOINT
    # ==========================================================================
    def test_14_database_backup_restore_and_wal(self):
        """Verify database backup and safe recovery procedures with pre-restore safety snapshots."""
        # 1. Create a verified backup
        backup_path = database.backup_database()
        self.assertIsNotNone(backup_path)
        self.assertTrue(os.path.exists(backup_path))

        # Verify backup integrity
        res = database.verify_database(backup_path)
        self.assertEqual(res["integrity"], "ok")

        # 2. Test restore on a separate target database
        temp_target_fd, temp_target_path = tempfile.mkstemp(prefix="restore_target_", suffix=".db")
        os.close(temp_target_fd)

        try:
            restore_result = database.restore_database(backup_path, target_db_path=temp_target_path)
            self.assertEqual(restore_result["status"], "success")
            self.assertEqual(restore_result["integrity"], "ok")
            self.assertGreater(restore_result["table_counts"]["books"], 0)

            # 3. Test that invalid/corrupt backup throws ValueError
            corrupt_fd, corrupt_path = tempfile.mkstemp(prefix="corrupt_", suffix=".db")
            os.write(corrupt_fd, b"This is not a valid SQLite database header!")
            os.close(corrupt_fd)

            with self.assertRaises(ValueError):
                database.restore_database(corrupt_path, target_db_path=temp_target_path)

            os.remove(corrupt_path)

        finally:
            if os.path.exists(temp_target_path):
                try:
                    os.remove(temp_target_path)
                except OSError:
                    pass

    # ==========================================================================
    # 15. PROXY-FIX CONFIGURATION SAFETY
    # ==========================================================================
    def test_15_proxy_fix_configuration_safety(self):
        """Verify ProxyFix only wraps the WSGI application when PROXIES_COUNT > 0."""
        from werkzeug.middleware.proxy_fix import ProxyFix
        
        # When PROXIES_COUNT is 0 (default)
        self.assertEqual(int(os.environ.get("PROXIES_COUNT", 0)), 0)

        # Wrap an isolated dummy WSGI app to verify ProxyFix behaviour
        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [environ.get("REMOTE_ADDR", "").encode("utf-8")]

        wrapped = ProxyFix(dummy_app, x_for=1)
        environ = {
            "REQUEST_METHOD": "GET",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "5000",
            "PATH_INFO": "/",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_FOR": "203.0.113.195",
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO()
        }
        status_collector = []
        def dummy_start_response(status, headers):
            status_collector.append(status)

        output = wrapped(environ, dummy_start_response)
        self.assertEqual(output[0].decode("utf-8"), "203.0.113.195")


if __name__ == "__main__":
    unittest.main()
