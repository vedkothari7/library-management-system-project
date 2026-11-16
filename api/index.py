"""
api/index.py - Vercel Serverless Function Entry Point for Athena Library Management System.
Exports WSGI Flask application callable for @vercel/python runtime.
Includes VercelPathFixMiddleware to restore correct WSGI PATH_INFO after Vercel rewrites.
"""
import os
import sys
from urllib.parse import parse_qs, urlencode

# Ensure root directory is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app


class VercelPathFixMiddleware:
    """
    WSGI Middleware to fix Vercel internal rewrites.
    Restores the original request PATH_INFO from rewrite query parameters or Vercel headers,
    ensuring Flask routes (and static assets) match accurately.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        if path_info in ("/api/index", "/api/index.py", "/api", "/api/"):
            query_string = environ.get("QUERY_STRING", "")
            params = parse_qs(query_string, keep_blank_values=True)

            orig_path = None
            if "__vercel_original_path" in params:
                orig_path = params.pop("__vercel_original_path")[0]
                new_pairs = [(k, v) for k, vs in params.items() for v in vs]
                environ["QUERY_STRING"] = urlencode(new_pairs)
            elif "HTTP_X_MATCHED_PATH" in environ:
                orig_path = environ["HTTP_X_MATCHED_PATH"]
            elif "HTTP_X_FORWARDED_URI" in environ:
                orig_path = environ["HTTP_X_FORWARDED_URI"].split("?")[0]

            if orig_path:
                while orig_path.startswith("//"):
                    orig_path = orig_path[1:]
                if not orig_path.startswith("/"):
                    orig_path = "/" + orig_path
                environ["PATH_INFO"] = orig_path

        return self.wsgi_app(environ, start_response)


# Wrap the Flask WSGI application with path fixing middleware
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)
