"""Entry point for production WSGI servers (gunicorn, uWSGI, etc.).

    gunicorn 'wsgi:app'

run.py remains the entry point for the Flask development server.
"""
from app import create_app

app = create_app("production")
