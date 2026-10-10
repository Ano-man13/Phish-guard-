"""Application configuration.

All secrets and environment-specific values come from environment variables
(loaded from .env in development via python-dotenv). Nothing sensitive is
hard-coded here.
"""
import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    # In production SECRET_KEY must be set; ProductionConfig enforces this.
    SECRET_KEY = os.environ.get("SECRET_KEY")
    MAX_INPUT_LENGTH = int(os.environ.get("MAX_INPUT_LENGTH", "5000"))
    # Reject oversized request bodies early (well above MAX_INPUT_LENGTH).
    MAX_CONTENT_LENGTH = 64 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Optional local-AI second opinion (see app/services/ai_service.py). Off
    # by default: the app works exactly as before unless this is turned on.
    PHISHGUARD_AI_ENABLED = os.environ.get("PHISHGUARD_AI_ENABLED", "0") == "1"
    OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")
    OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "20"))


class DevelopmentConfig(Config):
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    # A throwaway key so the dev server starts without setup. Never used in prod.
    SECRET_KEY = Config.SECRET_KEY or "dev-only-insecure-key"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

    @classmethod
    def validate(cls):
        if not cls.SECRET_KEY:
            raise RuntimeError("SECRET_KEY must be set in production.")


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-key"
    # Most tests post form data directly without first fetching a CSRF token;
    # a dedicated test (test_security.py) re-enables it to verify protection
    # actually works.
    WTF_CSRF_ENABLED = False


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
