"""
WSGI Entry Point for Athena Library Management System.
Used by production WSGI servers such as Gunicorn, Waitress, or uWSGI.

Usage:
    Linux / Production: gunicorn wsgi:app
    Windows development server: python wsgi.py
"""
import os
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
