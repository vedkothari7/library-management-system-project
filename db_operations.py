"""
db_operations.py - High-Level Database Operations with Strong Transaction Safety
Phase 3: Robust Server-Side Validation, Decimal Currency & SQL Injection Resistance
"""

from datetime import datetime, date
from decimal import Decimal
from database import get_db_connection, calculate_fine, get_late_fee_per_day
import validators


# ==============================================================================
# BOOK MANAGEMENT OPERATIONS
# ==============================================================================

def get_all_books(search_query: str = None, category_filter: str = None):
    """Retrieves all books with parameterized search filtering by title, author, ISBN, or code."""
    conn = get_db_connection()
    sql = "SELECT * FROM books WHERE 1=1"
    params = []

    if search_query and search_query.strip():
        sql += " AND (title LIKE ? OR author LIKE ? OR isbn LIKE ? OR book_code LIKE ?)"
        wildcard = f"%{search_query.strip()}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    if category_filter and category_filter != "All":
        sql += " AND category = ?"
        params.append(category_filter.strip())

    sql += " ORDER BY id DESC"
    books = conn.execute(sql, params).fetchall()
    conn.close()

    result = []
    for b in books:
        b_dict = dict(b)
        if b_dict["available_copies"] == 0:
            b_dict["status"] = "Borrowed"
        elif b_dict["available_copies"] <= 2:
            b_dict["status"] = "Low Stock"
        else:
            b_dict["status"] = "Available"
        result.append(b_dict)

    return result


def get_book_by_id(book_id: int):
    """Retrieves a single book by ID."""
    conn = get_db_connection()
    book = conn.execute("SELECT * FROM books WHERE id = ?;", (book_id,)).fetchone()
    conn.close()
    return dict(book) if book else None


def add_book(title: str, author: str, category: str, isbn: str, total_copies: int):
    """Adds a new book with strict server-side validation and uniqueness checks."""
    cleaned = validators.validate_book(title, author, category, isbn, total_copies)

    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()
        # Check ISBN uniqueness
        existing = cursor.execute("SELECT id FROM books WHERE isbn = ?;", (cleaned["isbn"],)).fetchone()
        if existing:
            raise ValueError(f"A book with ISBN '{cleaned['isbn']}' already exists in the catalog.")

        # Generate sequential book code
        last_id = cursor.execute("SELECT MAX(id) as max_id FROM books;").fetchone()["max_id"] or 0
        book_code = f"BK-{last_id + 101}"

        cursor.execute("""
        INSERT INTO books (book_code, title, author, category, isbn, total_copies, available_copies)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            book_code,
            cleaned["title"],
            cleaned["author"],
            cleaned["category"],
            cleaned["isbn"],
            cleaned["total_copies"],
            cleaned["total_copies"]
        ))

    conn.close()
    return book_code


def update_book(book_id: int, title: str, author: str, category: str, isbn: str, total_copies: int):
    """Updates book details maintaining inventory balance consistency."""
    cleaned = validators.validate_book(title, author, category, isbn, total_copies)

    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()
        current = cursor.execute("SELECT * FROM books WHERE id = ?;", (book_id,)).fetchone()
        if not current:
            raise ValueError("Book not found.")

        # Check unique ISBN across other books
        existing_isbn = cursor.execute(
            "SELECT id FROM books WHERE isbn = ? AND id != ?;",
            (cleaned["isbn"], book_id)
        ).fetchone()
        if existing_isbn:
            raise ValueError(f"ISBN '{cleaned['isbn']}' is already assigned to another book.")

        old_total = current["total_copies"]
        old_available = current["available_copies"]
        currently_borrowed = old_total - old_available

        if cleaned["total_copies"] < currently_borrowed:
            raise ValueError(
                f"Cannot reduce total copies to {cleaned['total_copies']}. "
                f"There are currently {currently_borrowed} copies on active loan."
            )

        new_available = old_available + (cleaned["total_copies"] - old_total)

        cursor.execute("""
        UPDATE books
        SET title = ?, author = ?, category = ?, isbn = ?, total_copies = ?, available_copies = ?
        WHERE id = ?;
        """, (
            cleaned["title"],
            cleaned["author"],
            cleaned["category"],
            cleaned["isbn"],
            cleaned["total_copies"],
            new_available,
            book_id
        ))

    conn.close()


def delete_book(book_id: int):
    """Safely deletes a book only if no active loans exist."""
    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()
        book = cursor.execute("SELECT * FROM books WHERE id = ?;", (book_id,)).fetchone()
        if not book:
            raise ValueError("Book not found.")

        active_loans = cursor.execute(
            "SELECT COUNT(*) as count FROM transactions WHERE book_id = ? AND status = 'Active';",
            (book_id,)
        ).fetchone()["count"]

        if active_loans > 0:
            raise ValueError(
                f"Cannot delete '{book['title']}'. There are currently {active_loans} active loan(s) checked out."
            )

        # Remove historical closed transactions for this book so foreign key check passes
        cursor.execute("DELETE FROM transactions WHERE book_id = ?;", (book_id,))
        cursor.execute("DELETE FROM books WHERE id = ?;", (book_id,))

    conn.close()


def get_distinct_categories():
    """Returns list of distinct book categories."""
    conn = get_db_connection()
    rows = conn.execute("SELECT DISTINCT category FROM books ORDER BY category ASC;").fetchall()
    conn.close()
    return [r["category"] for r in rows]


# ==============================================================================
# MEMBER MANAGEMENT OPERATIONS
# ==============================================================================

def get_all_members(search_query: str = None, type_filter: str = None):
    """Retrieves all members with active loan counts and search filtering."""
    conn = get_db_connection()
    sql = """
    SELECT m.*,
           COUNT(CASE WHEN t.status = 'Active' THEN 1 END) as active_loans
    FROM members m
    LEFT JOIN transactions t ON m.id = t.member_id
    WHERE 1=1
    """
    params = []

    if search_query and search_query.strip():
        sql += " AND (m.name LIKE ? OR m.email LIKE ? OR m.phone LIKE ? OR m.member_code LIKE ?)"
        wildcard = f"%{search_query.strip()}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    if type_filter and type_filter != "All":
        sql += " AND m.membership_type = ?"
        params.append(type_filter.strip())

    sql += " GROUP BY m.id ORDER BY m.id DESC;"
    members = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(m) for m in members]


def get_member_by_id(member_id: int):
    """Retrieves a single member by ID."""
    conn = get_db_connection()
    member = conn.execute("SELECT * FROM members WHERE id = ?;", (member_id,)).fetchone()
    conn.close()
    return dict(member) if member else None


def add_member(name: str, email: str, phone: str, membership_type: str = "Student"):
    """Registers a new library member with validation."""
    cleaned = validators.validate_member(name, email, phone, membership_type, status="Active")

    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()
        existing = cursor.execute("SELECT id FROM members WHERE email = ?;", (cleaned["email"],)).fetchone()
        if existing:
            raise ValueError(f"A member with email '{cleaned['email']}' is already registered.")

        last_id = cursor.execute("SELECT MAX(id) as max_id FROM members;").fetchone()["max_id"] or 0
        member_code = f"MEM-{last_id + 2001}"

        cursor.execute("""
        INSERT INTO members (member_code, name, email, phone, membership_type, status)
        VALUES (?, ?, ?, ?, ?, 'Active');
        """, (member_code, cleaned["name"], cleaned["email"], cleaned["phone"], cleaned["membership_type"]))

    conn.close()
    return member_code


def update_member(member_id: int, name: str, email: str, phone: str, membership_type: str, status: str):
    """Updates member details and account status."""
    cleaned = validators.validate_member(name, email, phone, membership_type, status)

    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()
        current = cursor.execute("SELECT * FROM members WHERE id = ?;", (member_id,)).fetchone()
        if not current:
            raise ValueError("Member not found.")

        existing = cursor.execute(
            "SELECT id FROM members WHERE email = ? AND id != ?;",
            (cleaned["email"], member_id)
        ).fetchone()
        if existing:
            raise ValueError(f"Email '{cleaned['email']}' is already used by another member.")

        cursor.execute("""
        UPDATE members
        SET name = ?, email = ?, phone = ?, membership_type = ?, status = ?
        WHERE id = ?;
        """, (cleaned["name"], cleaned["email"], cleaned["phone"], cleaned["membership_type"], cleaned["status"], member_id))

    conn.close()


# ==============================================================================
# CIRCULATION: ISSUE BOOKS
# ==============================================================================

def get_active_members():
    """Returns active members eligible for book loan."""
    conn = get_db_connection()
    members = conn.execute("SELECT * FROM members WHERE status = 'Active' ORDER BY name ASC;").fetchall()
    conn.close()
    return [dict(m) for m in members]


def get_available_books():
    """Returns books that have available_copies > 0."""
    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books WHERE available_copies > 0 ORDER BY title ASC;").fetchall()
    conn.close()
    return [dict(b) for b in books]


def issue_book(book_id: int, member_id: int, issue_date_str: str, due_date_str: str, remarks: str = ""):
    """
    Issues a book to a member atomically.
    Validates member status, available quantity, date order, and duplicate loans.
    """
    issue_d, due_d = validators.validate_circulation_dates(issue_date_str, due_date_str)

    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()

        # 1. Validate Member
        member = cursor.execute("SELECT * FROM members WHERE id = ?;", (member_id,)).fetchone()
        if not member:
            raise ValueError("Selected member record was not found.")
        if member["status"] != "Active":
            raise ValueError(f"Member '{member['name']}' is suspended and cannot borrow books.")

        # 2. Validate Book
        book = cursor.execute("SELECT * FROM books WHERE id = ?;", (book_id,)).fetchone()
        if not book:
            raise ValueError("Selected book record was not found.")
        if book["available_copies"] <= 0:
            raise ValueError(f"'{book['title']}' has no available copies for loan.")

        # 3. Check duplicate active loan of the same book
        existing_loan = cursor.execute("""
        SELECT id FROM transactions
        WHERE book_id = ? AND member_id = ? AND status = 'Active';
        """, (book_id, member_id)).fetchone()
        if existing_loan:
            raise ValueError(f"Member '{member['name']}' already holds an active loan for '{book['title']}'.")

        # 4. Generate Transaction Code
        last_id = cursor.execute("SELECT MAX(id) as max_id FROM transactions;").fetchone()["max_id"] or 0
        tx_code = f"ISS-{last_id + 1001}"

        # 5. Insert Transaction
        cursor.execute("""
        INSERT INTO transactions (transaction_code, book_id, member_id, issue_date, due_date, status, remarks)
        VALUES (?, ?, ?, ?, ?, 'Active', ?);
        """, (tx_code, book_id, member_id, issue_d.strftime("%Y-%m-%d"), due_d.strftime("%Y-%m-%d"), remarks.strip() if remarks else None))

        # 6. Atomically Decrement Book Available Copies
        cursor.execute("""
        UPDATE books
        SET available_copies = available_copies - 1
        WHERE id = ? AND available_copies > 0;
        """, (book_id,))

        if cursor.rowcount == 0:
            raise ValueError("Unable to issue: book became unavailable concurrently.")

    conn.close()
    return {
        "transaction_code": tx_code,
        "book_title": book["title"],
        "member_name": member["name"],
        "due_date": due_d.strftime("%Y-%m-%d")
    }


# ==============================================================================
# CIRCULATION: RETURN BOOKS & LATE FEES
# ==============================================================================

def get_active_transactions():
    """
    Returns all active loans joining books and members.
    Dynamically computes current overdue status and real-time Decimal fine based on today.
    """
    conn = get_db_connection()
    today_str = date.today().strftime("%Y-%m-%d")
    sql = """
    SELECT t.id, t.transaction_code, t.issue_date, t.due_date, t.status, t.remarks,
           b.id as book_id, b.title as book_title, b.isbn,
           m.id as member_id, m.name as member_name, m.member_code
    FROM transactions t
    JOIN books b ON t.book_id = b.id
    JOIN members m ON t.member_id = m.id
    WHERE t.status = 'Active'
    ORDER BY t.due_date ASC;
    """
    loans = conn.execute(sql).fetchall()
    conn.close()

    result = []
    for loan in loans:
        l_dict = dict(loan)
        overdue_days, fine = calculate_fine(l_dict["due_date"], today_str)
        l_dict["overdue_days"] = overdue_days
        l_dict["calculated_fine"] = fine

        try:
            due_d = datetime.strptime(l_dict["due_date"], "%Y-%m-%d").date()
            days_left = (due_d - date.today()).days
        except Exception:
            days_left = 0
        l_dict["days_left"] = days_left

        if overdue_days > 0:
            l_dict["display_status"] = "Overdue"
            l_dict["urgency"] = "overdue"
        elif days_left <= 3:
            l_dict["display_status"] = "Due Soon"
            l_dict["urgency"] = "due_soon"
        else:
            l_dict["display_status"] = "Active"
            l_dict["urgency"] = "ok"

        result.append(l_dict)

    return result


def get_transaction_by_id(tx_id: int):
    """Fetches a single transaction with joined details."""
    conn = get_db_connection()
    sql = """
    SELECT t.*,
           b.title as book_title, b.isbn,
           m.name as member_name, m.member_code
    FROM transactions t
    JOIN books b ON t.book_id = b.id
    JOIN members m ON t.member_id = m.id
    WHERE t.id = ?;
    """
    tx = conn.execute(sql, (tx_id,)).fetchone()
    conn.close()
    return dict(tx) if tx else None


def return_book(transaction_id: int, return_date_str: str, remarks: str = ""):
    """
    Processes book return atomically.
    Computes Decimal late fees, updates status to 'Returned', and increments available copies.
    Prevents duplicate returns.
    """
    conn = get_db_connection()
    with conn:
        cursor = conn.cursor()

        tx = cursor.execute("""
        SELECT t.*, b.id as book_id, b.title as book_title, b.total_copies, b.available_copies,
               m.name as member_name
        FROM transactions t
        JOIN books b ON t.book_id = b.id
        JOIN members m ON t.member_id = m.id
        WHERE t.id = ?;
        """, (transaction_id,)).fetchone()

        if not tx:
            raise ValueError("Transaction record not found.")

        if tx["status"] != "Active":
            raise ValueError(f"Loan '{tx['transaction_code']}' has already been processed and returned.")

        ret_d = validators.validate_return_date(tx["issue_date"], return_date_str)
        ret_date_str = ret_d.strftime("%Y-%m-%d")

        # Calculate exact late fee
        overdue_days, fine_amount = calculate_fine(tx["due_date"], ret_date_str)

        # Update transaction
        cursor.execute("""
        UPDATE transactions
        SET status = 'Returned',
            return_date = ?,
            fine_amount = ?,
            fine_paid = 1,
            remarks = ?
        WHERE id = ? AND status = 'Active';
        """, (ret_date_str, float(fine_amount), remarks.strip() if remarks else None, transaction_id))

        if cursor.rowcount == 0:
            raise ValueError("Return failed: transaction was already closed concurrently.")

        # Increment available copies safely
        cursor.execute("""
        UPDATE books
        SET available_copies = MIN(total_copies, available_copies + 1)
        WHERE id = ?;
        """, (tx["book_id"],))

    conn.close()

    return {
        "transaction_code": tx["transaction_code"],
        "book_title": tx["book_title"],
        "member_name": tx["member_name"],
        "return_date": ret_date_str,
        "overdue_days": overdue_days,
        "fine_amount": fine_amount
    }


# ==============================================================================
# DASHBOARD OVERVIEW & ANALYTICS
# ==============================================================================

def get_dashboard_data():
    """
    Computes real-time dynamic dashboard statistics from SQLite.
    Returns (stats, recent_issues, categories).
    """
    conn = get_db_connection()
    today_str = date.today().strftime("%Y-%m-%d")

    total_books = conn.execute("SELECT COALESCE(SUM(total_copies), 0) as count FROM books;").fetchone()["count"]
    available_books = conn.execute("SELECT COALESCE(SUM(available_copies), 0) as count FROM books;").fetchone()["count"]
    issued_books = conn.execute("SELECT COUNT(*) as count FROM transactions WHERE status = 'Active';").fetchone()["count"]
    registered_members = conn.execute("SELECT COUNT(*) as count FROM members;").fetchone()["count"]

    stats = {
        "total_books": total_books,
        "available_books": available_books,
        "issued_books": issued_books,
        "registered_members": registered_members
    }

    recent_rows = conn.execute("""
    SELECT t.id, t.transaction_code, t.issue_date, t.due_date, t.return_date, t.status, t.fine_amount,
           b.title as book_title, b.isbn,
           m.name as member_name, m.member_code
    FROM transactions t
    JOIN books b ON t.book_id = b.id
    JOIN members m ON t.member_id = m.id
    ORDER BY t.id DESC
    LIMIT 5;
    """).fetchall()

    recent_issues = []
    for r in recent_rows:
        row_dict = dict(r)
        try:
            iss_fmt = datetime.strptime(row_dict["issue_date"], "%Y-%m-%d").strftime("%d %b %Y")
            due_fmt = datetime.strptime(row_dict["due_date"], "%Y-%m-%d").strftime("%d %b %Y")
        except Exception:
            iss_fmt = row_dict["issue_date"]
            due_fmt = row_dict["due_date"]

        row_dict["id"] = row_dict["transaction_code"]
        row_dict["issue_date"] = iss_fmt
        row_dict["due_date"] = due_fmt

        if row_dict["status"] == "Active":
            if row_dict["due_date"] and r["due_date"] < today_str:
                row_dict["status"] = "Overdue"
            else:
                row_dict["status"] = "Active"

        recent_issues.append(row_dict)

    cat_rows = conn.execute("""
    SELECT category as name, SUM(total_copies) as count
    FROM books
    GROUP BY category
    ORDER BY count DESC;
    """).fetchall()

    categories = []
    if total_books > 0:
        for cat in cat_rows:
            pct = int(round((cat["count"] / total_books) * 100))
            categories.append({
                "name": cat["name"],
                "count": cat["count"],
                "percentage": pct
            })

    conn.close()
    return stats, recent_issues, categories
