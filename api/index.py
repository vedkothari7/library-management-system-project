"""
api/index.py - Vercel Serverless Function Entry Point for Athena Library Management System.
Exports WSGI Flask application callable for @vercel/python runtime.
"""
import os
import sys

# Ensure root directory is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
