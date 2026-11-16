"""
database.py - SQLite Database Configuration, Connection Factory, Migrations & Safe Backups
Athena Library Management System - Phase 4: Production Persistence & Safe Recovery CLI
"""

import sqlite3
import os
import sys
import glob
import argparse
from datetime import datetime, date
from decimal import Decimal, ROUND_HALF_UP
from werkzeug.security import generate_password_hash


DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "library.db")
DB_PATH = os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
BACKUPS_DIR = "/tmp/backups" if os.environ.get("VERCEL") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")


def get_db_path() -> str:
    """
    Returns the configured SQLite database file path.
    Supports DATABASE_PATH environment variable for cloud persistent disk mounts (e.g. Render /var/data/library.db).
    On Vercel serverless runtime, defaults to /tmp/library.db (the only writable directory).
    Falls back to module-level DB_PATH.
    """
    env_path = os.environ.get("DATABASE_PATH")
    if env_path and env_path.strip():
        return os.path.abspath(env_path.strip())
    if os.environ.get("VERCEL"):
        return "/tmp/library.db"
    return DB_PATH


def get_db_connection(db_path: str = None):
    """
    Returns a SQLite connection with row_factory enabled and foreign keys strictly enforced.
    Configured with a 20-second timeout to handle concurrent access safely.
    """
    target_path = db_path or get_db_path()
    conn = sqlite3.connect(target_path, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def checkpoint_wal(db_path: str = None):
    """
    Flushes all Write-Ahead Log (WAL) pages into the main SQLite database file.
    Ensures safe, clean snapshot state prior to backups or restores.
    """
    target_path = db_path or get_db_path()
    if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
        try:
            conn = sqlite3.connect(target_path, timeout=10.0)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.close()
        except sqlite3.Error:
            pass


def backup_database(source_path: str = None) -> str:
    """
    Creates an automated, verified snapshot of the SQLite database.
    - Checkpoints active WAL logs into the database file.
    - Uses SQLite's online backup API to guarantee consistent snapshots without partial writes.
    - Verifies snapshot integrity with PRAGMA integrity_check.
    - Retains up to 10 recent backups and prunes older snapshots.
    """
    target_source = source_path or get_db_path()
    if not os.path.exists(target_source) or os.path.getsize(target_source) == 0:
        return None

    # Checkpoint WAL before backing up
    checkpoint_wal(target_source)

    os.makedirs(BACKUPS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"library_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUPS_DIR, backup_filename)

    # Use SQLite online backup API
    src_conn = sqlite3.connect(target_source, timeout=30.0)
    dst_conn = sqlite3.connect(backup_path)
    src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()

    # Verify backup integrity
    verify_conn = sqlite3.connect(backup_path)
    check_result = verify_conn.execute("PRAGMA integrity_check;").fetchall()
    verify_conn.close()

    if not check_result or check_result[0][0] != "ok":
        if os.path.exists(backup_path):
            os.remove(backup_path)
        raise RuntimeError(f"Database backup integrity check failed for {backup_path}")

    # Retain the 10 most recent backups
    all_backups = sorted(glob.glob(os.path.join(BACKUPS_DIR, "library_backup_*.db")), reverse=True)
    for old_backup in all_backups[10:]:
        try:
            os.remove(old_backup)
        except OSError:
            pass

    return backup_path


def restore_database(backup_filepath: str, target_db_path: str = None) -> dict:
    """
    Safely restores a database from a verified backup file.
    
    Safety Guarantees:
    1. Validates that the backup file exists and passes PRAGMA integrity_check BEFORE any modification.
    2. Automatically creates a pre-restore safety copy of the existing target database.
    3. Performs WAL checkpoint and truncates any lingering -wal or -shm sidecars.
    4. Copies data using SQLite online backup API to prevent corruption.
    5. Validates the newly restored database with PRAGMA integrity_check.
    6. Returns an audit dictionary with table counts and status.
    """
    if not backup_filepath or not os.path.exists(backup_filepath):
        raise ValueError(f"Backup file does not exist: {backup_filepath}")
    
    if os.path.getsize(backup_filepath) == 0:
        raise ValueError(f"Backup file is empty: {backup_filepath}")

    # Step 1: Pre-validation of the incoming backup file
    check_conn = None
    try:
        check_conn = sqlite3.connect(backup_filepath, timeout=15.0)
        check_res = check_conn.execute("PRAGMA integrity_check;").fetchall()
    except sqlite3.Error as e:
        raise ValueError(f"Corrupt backup file cannot be opened: {e}")
    finally:
        if check_conn:
            check_conn.close()

    if not check_res or check_res[0][0] != "ok":
        raise ValueError(f"Incoming backup file failed integrity check: {check_res}")

    target_path = target_db_path or get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    os.makedirs(BACKUPS_DIR, exist_ok=True)

    # Step 2: Automated Pre-Restore Safety Backup of current state (if target exists)
    pre_restore_backup_path = None
    if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
        checkpoint_wal(target_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pre_restore_backup_path = os.path.join(BACKUPS_DIR, f"pre_restore_safety_{timestamp}.db")
        
        src_conn = sqlite3.connect(target_path, timeout=30.0)
        dst_conn = sqlite3.connect(pre_restore_backup_path)
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

    # Step 3: Checkpoint and safely restore using online backup API
    checkpoint_wal(target_path)
    
    restore_src = sqlite3.connect(backup_filepath, timeout=30.0)
    restore_dst = sqlite3.connect(target_path, timeout=30.0)
    restore_src.backup(restore_dst)
    restore_dst.close()
    restore_src.close()

    # Step 4: Clean up any obsolete WAL/SHM sidecars from previous session
    for sidecar_ext in ["-wal", "-shm"]:
        sidecar_file = target_path + sidecar_ext
        if os.path.exists(sidecar_file):
            try:
                os.remove(sidecar_file)
            except OSError:
                pass

    # Step 5: Post-restore integrity verification
    verify_conn = get_db_connection(target_path)
    verify_res = verify_conn.execute("PRAGMA integrity_check;").fetchall()
    if not verify_res or verify_res[0][0] != "ok":
        verify_conn.close()
        raise RuntimeError("Post-restore integrity check failed on target database!")

    # Fetch restored table counts
    tables = [r["name"] for r in verify_conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
    counts = {}
    for t in tables:
        if t != "sqlite_sequence":
            cnt = verify_conn.execute(f"SELECT COUNT(*) as c FROM {t};").fetchone()["c"]
            counts[t] = cnt
    verify_conn.close()

    return {
        "status": "success",
        "target_db": target_path,
        "restored_from": backup_filepath,
        "pre_restore_backup": pre_restore_backup_path,
        "integrity": "ok",
        "table_counts": counts
    }


def verify_database(db_path: str = None) -> dict:
    """
    Performs comprehensive verification on the active or specified database.
    Checks SQLite integrity and counts records across all library tables.
    """
    target = db_path or get_db_path()
    if not os.path.exists(target):
        return {"status": "error", "message": f"Database file not found: {target}"}

    conn = get_db_connection(target)
    integrity = conn.execute("PRAGMA integrity_check;").fetchall()
    integrity_status = integrity[0][0] if integrity else "unknown"

    tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
    counts = {}
    for t in tables:
        if t != "sqlite_sequence":
            counts[t] = conn.execute(f"SELECT COUNT(*) as c FROM {t};").fetchone()["c"]

    conn.close()
    return {
        "status": "healthy" if integrity_status == "ok" else "corrupt",
        "database_path": target,
        "integrity": integrity_status,
        "table_counts": counts
    }


def init_db():
    """
    Initializes the database schema and performs migrations.
    Takes a verified backup before structural modifications if migrating an existing database.
    Does not take redundant backups on standard subsequent startups.
    """
    target_path = get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    
    conn = get_db_connection(target_path)
    cursor = conn.cursor()

    # Determine if structural changes / migrations are needed
    existing_tables = [
        row["name"] for row in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        ).fetchall()
    ]

    needs_migration = ("admins" not in existing_tables) or ("login_attempts" not in existing_tables)

    # If database file already has content and migrations are pending, create verified backup
    if needs_migration and os.path.exists(target_path) and os.path.getsize(target_path) > 0 and len(existing_tables) > 0:
        backup_database(target_path)

    # 1. System Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT
    );
    """)

    # 2. Books Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        book_code TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        category TEXT NOT NULL,
        isbn TEXT UNIQUE NOT NULL,
        total_copies INTEGER NOT NULL CHECK(total_copies >= 0),
        available_copies INTEGER NOT NULL CHECK(available_copies >= 0 AND available_copies <= total_copies),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Members Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        membership_type TEXT NOT NULL DEFAULT 'Student',
        status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active', 'Suspended')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Transactions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_code TEXT UNIQUE NOT NULL,
        book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE RESTRICT,
        member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
        issue_date DATE NOT NULL,
        due_date DATE NOT NULL,
        return_date DATE,
        fine_amount REAL DEFAULT 0.0,
        fine_paid INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active', 'Returned', 'Overdue')),
        remarks TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Admins Table (Phase 3 Authentication & Forced Password Rotation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Librarian Admin',
        must_change_password INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
    """)

    # 6. Login Attempts Table (Phase 3 Brute-Force Rate Limiting)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        username TEXT NOT NULL,
        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER NOT NULL
    );
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
    ON login_attempts (username, ip_address, attempt_time);
    """)

    conn.commit()

    # Seed initial data if settings or admins are empty
    cursor.execute("SELECT COUNT(*) as count FROM settings;")
    if cursor.fetchone()["count"] == 0:
        _seed_initial_data(conn)

    cursor.execute("SELECT COUNT(*) as count FROM admins;")
    if cursor.fetchone()["count"] == 0:
        _seed_default_admin(conn)

    conn.close()


def ensure_db_ready():
    """
    Ensures database exists and schema is initialized.
    Essential for ephemeral and serverless runtime environments (such as Vercel /tmp).
    """
    target = get_db_path()
    if not os.path.exists(target) or os.path.getsize(target) == 0:
        init_db()


def _seed_default_admin(conn):
    """
    Seeds temporary default administrator credentials.
    Enforces must_change_password = 1 so immediate password rotation is mandatory.
    """
    temp_password = "Admin@Temporary123!"
    password_hash = generate_password_hash(temp_password)
    conn.execute("""
    INSERT INTO admins (username, password_hash, full_name, role, must_change_password)
    VALUES (?, ?, ?, ?, 1);
    """, ("admin", password_hash, "Librarian Admin", "System Administrator"))
    conn.commit()


def _seed_initial_data(conn):
    """Seeds realistic library initial data."""
    cursor = conn.cursor()

    # Default settings
    settings_data = [
        ("late_fee_per_day", "0.50", "Late fee assessed per overdue day ($)"),
        ("loan_days_student", "14", "Standard loan duration for students (days)"),
        ("loan_days_faculty", "30", "Standard loan duration for faculty members (days)"),
        ("max_books_student", "3", "Maximum concurrent loans allowed for students"),
        ("max_books_faculty", "10", "Maximum concurrent loans allowed for faculty")
    ]
    cursor.executemany("INSERT INTO settings (key, value, description) VALUES (?, ?, ?);", settings_data)

    # Initial Books
    initial_books = [
        ("BK-101", "Clean Code: A Handbook of Agile Software Craftsmanship", "Robert C. Martin", "Computer Science", "978-0132350884", 10, 9),
        ("BK-102", "Introduction to Algorithms (4th Edition)", "Thomas H. Cormen et al.", "Computer Science", "978-0262046305", 8, 7),
        ("BK-103", "Design Patterns: Elements of Reusable Object-Oriented Software", "Erich Gamma et al.", "Computer Science", "978-0201633610", 6, 5),
        ("BK-104", "To Kill a Mockingbird", "Harper Lee", "Literature & Fiction", "978-0060935467", 15, 15),
        ("BK-105", "A Brief History of Time", "Stephen Hawking", "Physics & Engineering", "978-0553380163", 12, 12),
        ("BK-106", "The Pragmatic Programmer: Your Journey to Mastery", "David Thomas, Andrew Hunt", "Computer Science", "978-0135957059", 7, 6),
        ("BK-107", "Artificial Intelligence: A Modern Approach", "Stuart Russell, Peter Norvig", "Computer Science", "978-0134610993", 8, 7),
        ("BK-108", "Linear Algebra and Its Applications", "Gilbert Strang", "Mathematics", "978-0030105678", 14, 14),
        ("BK-109", "Principles of Mathematical Analysis", "Walter Rudin", "Mathematics", "978-0070542358", 9, 9),
        ("BK-110", "Sapiens: A Brief History of Humankind", "Yuval Noah Harari", "History & Philosophy", "978-0062316097", 18, 18),
        ("BK-111", "Guns, Germs, and Steel", "Jared Diamond", "History & Philosophy", "978-0393317558", 11, 11),
        ("BK-112", "Classical Mechanics", "Herbert Goldstein", "Physics & Engineering", "978-0201657029", 10, 10)
    ]
    cursor.executemany("""
    INSERT INTO books (book_code, title, author, category, isbn, total_copies, available_copies)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, initial_books)

    # Initial Members
    initial_members = [
        ("MEM-2041", "Sarah Jenkins", "sarah.jenkins@example.com", "+1 (555) 234-5678", "Student", "Active"),
        ("MEM-2015", "Michael Chen", "m.chen@example.com", "+1 (555) 345-6789", "Faculty", "Active"),
        ("MEM-2089", "Amina Al-Mansoor", "amina.mansoor@example.com", "+1 (555) 456-7890", "Student", "Active"),
        ("MEM-1980", "David Ross", "dross@example.com", "+1 (555) 567-8901", "General", "Suspended"),
        ("MEM-2102", "Elena Rostova", "elena.r@example.com", "+1 (555) 678-9012", "Student", "Active"),
        ("MEM-2115", "James Wilson", "jwilson@example.com", "+1 (555) 789-0123", "Faculty", "Active")
    ]
    cursor.executemany("""
    INSERT INTO members (member_code, name, email, phone, membership_type, status)
    VALUES (?, ?, ?, ?, ?, ?);
    """, initial_members)

    # Initial Transactions (5 active/overdue loans corresponding to initial dashboard)
    today = date.today()
    from datetime import timedelta
    initial_transactions = [
        ("ISS-1001", 1, 1, (today - timedelta(days=3)).strftime("%Y-%m-%d"), (today + timedelta(days=11)).strftime("%Y-%m-%d"), None, 0.0, 0, "Active", "Standard student loan"),
        ("ISS-1002", 3, 2, (today - timedelta(days=5)).strftime("%Y-%m-%d"), (today + timedelta(days=25)).strftime("%Y-%m-%d"), None, 0.0, 0, "Active", "Faculty curriculum preparation"),
        ("ISS-1003", 2, 3, (today - timedelta(days=10)).strftime("%Y-%m-%d"), (today + timedelta(days=4)).strftime("%Y-%m-%d"), None, 0.0, 0, "Active", "Algorithms research"),
        ("ISS-1004", 6, 4, (today - timedelta(days=20)).strftime("%Y-%m-%d"), (today - timedelta(days=6)).strftime("%Y-%m-%d"), None, 3.0, 0, "Active", "Overdue loan (6 days)"),
        ("ISS-1005", 7, 5, (today - timedelta(days=1)).strftime("%Y-%m-%d"), (today + timedelta(days=13)).strftime("%Y-%m-%d"), None, 0.0, 0, "Active", "Machine Learning seminar")
    ]
    cursor.executemany("""
    INSERT INTO transactions (transaction_code, book_id, member_id, issue_date, due_date, return_date, fine_amount, fine_paid, status, remarks)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, initial_transactions)

    conn.commit()


# ==============================================================================
# DECIMAL CURRENCY & CONFIGURATION HELPERS
# ==============================================================================

def get_late_fee_per_day(db_path: str = None) -> Decimal:
    """Fetches the configured late fee per day as an exact Python Decimal."""
    conn = get_db_connection(db_path)
    row = conn.execute("SELECT value FROM settings WHERE key = 'late_fee_per_day';").fetchone()
    conn.close()
    if row:
        try:
            return Decimal(str(row["value"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except Exception:
            return Decimal("0.50")
    return Decimal("0.50")


def set_late_fee_per_day(amount: Decimal | float | str, db_path: str = None):
    """Updates the configured late fee per day with exact Decimal representation."""
    try:
        dec_amount = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if dec_amount < Decimal("0.00"):
            raise ValueError("Late fee rate cannot be negative.")
    except Exception as e:
        raise ValueError(f"Invalid monetary value: {e}")

    conn = get_db_connection(db_path)
    conn.execute("UPDATE settings SET value = ? WHERE key = 'late_fee_per_day';", (str(dec_amount),))
    conn.commit()
    conn.close()
    return dec_amount


def calculate_fine(due_date_str: str, return_date_str: str = None, db_path: str = None) -> tuple[int, Decimal]:
    """
    Calculates overdue days and exact Decimal monetary fine based on due_date and return_date.
    Returns (overdue_days, total_fine: Decimal).
    """
    try:
        due_d = datetime.strptime(due_date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return 0, Decimal("0.00")

    if return_date_str:
        try:
            ret_d = datetime.strptime(return_date_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            ret_d = date.today()
    else:
        ret_d = date.today()

    overdue_days = (ret_d - due_d).days
    if overdue_days > 0:
        rate = get_late_fee_per_day(db_path)
        fine = (Decimal(str(overdue_days)) * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return overdue_days, fine

    return 0, Decimal("0.00")


# ==============================================================================
# CLI MANAGEMENT INTERFACE
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Athena LMS Database Maintenance, Safe Backup & Recovery CLI"
    )
    parser.add_argument("--backup", action="store_true", help="Create a verified SQLite online backup")
    parser.add_argument("--restore", type=str, metavar="BACKUP_PATH", help="Safely restore database from a verified backup")
    parser.add_argument("--verify", action="store_true", help="Verify database integrity and display record counts")
    parser.add_argument("--init", action="store_true", help="Initialize schema and seed initial data if missing")

    args = parser.parse_args()

    if args.backup:
        print("[*] Initiating verified online backup...")
        path = backup_database()
        if path:
            print(f"[+] Backup successfully created and verified at: {path}")
        else:
            print("[-] Backup failed: database does not exist or is empty.")
            sys.exit(1)

    elif args.restore:
        print(f"[*] Initiating safe restore from: {args.restore}...")
        try:
            result = restore_database(args.restore)
            print("[+] Restore completed successfully!")
            print(f"    - Target Database: {result['target_db']}")
            print(f"    - Restored From:   {result['restored_from']}")
            if result.get("pre_restore_backup"):
                print(f"    - Safety Backup:   {result['pre_restore_backup']}")
            print(f"    - Integrity:       {result['integrity']}")
            print("    - Table Counts:")
            for table, count in result["table_counts"].items():
                print(f"        * {table}: {count}")
        except Exception as e:
            print(f"[-] Restore failed: {e}")
            sys.exit(1)

    elif args.verify:
        print("[*] Verifying database integrity...")
        result = verify_database()
        print(f"    - Status:          {result['status'].upper()}")
        print(f"    - Database:        {result.get('database_path')}")
        print(f"    - Integrity:       {result.get('integrity')}")
        if "table_counts" in result:
            print("    - Record Counts:")
            for table, count in result["table_counts"].items():
                print(f"        * {table}: {count}")

    else:
        print("[*] Initializing database schema...")
        init_db()
        print("[+] Database initialization complete.")
