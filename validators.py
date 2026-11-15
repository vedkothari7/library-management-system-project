"""
validators.py - Centralized Server-Side Validation Suite
Phase 3: Robust Input Validation, Pattern Matching & Sanitization
"""

import re
from datetime import datetime
from decimal import Decimal


# Regular expressions for data validation
REGEX_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
REGEX_PHONE = re.compile(r"^\+?[0-9\s\-\(\)\.]{7,25}$")


def sanitize_text(text: str) -> str:
    """Strips leading/trailing whitespace and normalizes spaces."""
    if not text:
        return ""
    return " ".join(text.strip().split())


def validate_book(title: str, author: str, category: str, isbn: str, total_copies) -> dict:
    """
    Validates all book catalog input parameters.
    Returns cleaned dictionary or raises ValueError.
    """
    title = sanitize_text(title)
    author = sanitize_text(author)
    category = sanitize_text(category)
    isbn = sanitize_text(isbn)

    if not title or len(title) < 2 or len(title) > 255:
        raise ValueError("Book title must be between 2 and 255 characters.")

    if not author or len(author) < 2 or len(author) > 255:
        raise ValueError("Author name must be between 2 and 255 characters.")

    if not category or len(category) < 2 or len(category) > 100:
        raise ValueError("Category must be between 2 and 100 characters.")

    if not isbn:
        raise ValueError("ISBN is required.")

    # Validate ISBN format (ISBN-10 or ISBN-13, allowing hyphens/spaces)
    clean_isbn = re.sub(r"[-\s]", "", isbn).upper()
    if len(clean_isbn) == 10:
        if not re.match(r"^\d{9}[\dX]$", clean_isbn):
            raise ValueError("Invalid ISBN-10 format. Must contain 10 characters (digits or ending with X).")
    elif len(clean_isbn) == 13:
        if not re.match(r"^\d{13}$", clean_isbn):
            raise ValueError("Invalid ISBN-13 format. Must contain 13 digits.")
    else:
        raise ValueError(f"Invalid ISBN length ({len(clean_isbn)} chars). Standard ISBN must be 10 or 13 digits.")

    try:
        copies = int(total_copies)
        if copies < 1:
            raise ValueError("Total copies must be at least 1.")
        if copies > 10000:
            raise ValueError("Total copies cannot exceed 10,000 volumes.")
    except (TypeError, ValueError) as e:
        if "Total copies" in str(e):
            raise
        raise ValueError("Total copies must be a positive whole number.")

    return {
        "title": title,
        "author": author,
        "category": category,
        "isbn": isbn,
        "total_copies": copies
    }


def validate_member(name: str, email: str, phone: str, membership_type: str = "Student", status: str = "Active") -> dict:
    """
    Validates library patron member input parameters.
    Returns cleaned dictionary or raises ValueError.
    """
    name = sanitize_text(name)
    email = sanitize_text(email).lower()
    phone = sanitize_text(phone)

    if not name or len(name) < 2 or len(name) > 100:
        raise ValueError("Member full name must be between 2 and 100 characters.")

    if not email or not REGEX_EMAIL.match(email) or len(email) > 150:
        raise ValueError("Please provide a valid, well-formed email address.")

    if not phone or not REGEX_PHONE.match(phone):
        raise ValueError("Please provide a valid phone number (at least 7 digits, symbols + - ( ) allowed).")

    allowed_types = ["Student", "Faculty", "General"]
    if membership_type not in allowed_types:
        raise ValueError(f"Membership type must be one of: {', '.join(allowed_types)}.")

    allowed_statuses = ["Active", "Suspended"]
    if status not in allowed_statuses:
        status = "Active"

    return {
        "name": name,
        "email": email,
        "phone": phone,
        "membership_type": membership_type,
        "status": status
    }


def validate_circulation_dates(issue_date_str: str, due_date_str: str) -> tuple[datetime.date, datetime.date]:
    """Validates date format and logic for book checkout."""
    try:
        issue_d = datetime.strptime(issue_date_str.strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValueError("Invalid issue date format. Expected YYYY-MM-DD.")

    try:
        due_d = datetime.strptime(due_date_str.strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValueError("Invalid due date format. Expected YYYY-MM-DD.")

    if due_d < issue_d:
        raise ValueError("Due date cannot be earlier than the loan issue date.")

    return issue_d, due_d


def validate_return_date(issue_date_str: str, return_date_str: str) -> datetime.date:
    """Validates date format and logic for book return."""
    try:
        issue_d = datetime.strptime(issue_date_str.strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValueError("Invalid original issue date recorded.")

    try:
        ret_d = datetime.strptime(return_date_str.strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValueError("Invalid return date format. Expected YYYY-MM-DD.")

    if ret_d < issue_d:
        raise ValueError(f"Return date ({ret_d}) cannot be earlier than the issue date ({issue_d}).")

    return ret_d


def validate_password_strength(password: str) -> None:
    """
    Validates password complexity:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number (0-9).")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>?/\\|`~]", password):
        raise ValueError("Password must contain at least one special symbol (e.g. !@#$%^&*).")


def sanitize_csv_value(val) -> str:
    """
    Sanitizes values exported to CSV to prevent CSV Formula Injection (CWE-1236).
    Neutralizes formulas starting with '=', '+', '-', '@', '\\t', or '\\r',
    even when preceded by leading whitespace or control characters.
    Prepends a single quote (') to force spreadsheet processors (Excel, Calc)
    to treat the cell strictly as plain text.
    """
    if val is None:
        return ""

    text = str(val)
    # Strip leading whitespace and ASCII control characters to detect disguised trigger characters
    stripped = text.lstrip(" \t\r\n\x00\x0b\x0c")
    if stripped and stripped[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text

    return text

