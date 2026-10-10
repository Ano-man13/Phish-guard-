"""Security-hardening checks: headers, CSRF, error pages, debug mode."""
import pytest

from app import create_app


@pytest.fixture()
def csrf_app():
    app = create_app("testing")
    app.config["WTF_CSRF_ENABLED"] = True
    return app


@pytest.fixture()
def csrf_client(csrf_app):
    return csrf_app.test_client()


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Content-Security-Policy" in response.headers
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_hsts_absent_without_secure_cookie_config(client):
    assert "Strict-Transport-Security" not in client.get("/").headers


def test_hsts_present_when_session_cookie_secure(client, app):
    app.config["SESSION_COOKIE_SECURE"] = True
    response = client.get("/")
    assert "Strict-Transport-Security" in response.headers


def test_post_without_csrf_token_is_rejected(csrf_client):
    response = csrf_client.post("/analyze", data={"scan_type": "url", "content": "https://example.com"})
    assert response.status_code == 400
    assert "session expired" in response.get_data(as_text=True).lower()


def test_post_with_valid_csrf_token_succeeds(csrf_client):
    page = csrf_client.get("/").get_data(as_text=True)
    import re
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = csrf_client.post(
        "/analyze",
        data={"scan_type": "url", "content": "https://example.com", "csrf_token": token},
    )
    assert response.status_code == 200
    assert "LOW RISK" in response.get_data(as_text=True)


def test_404_page_is_generic(client):
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "404" in body
    assert "Traceback" not in body


def test_405_page_is_generic(client):
    response = client.get("/analyze")
    assert response.status_code == 405
    assert "Traceback" not in response.get_data(as_text=True)


def test_production_requires_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app("production")


def test_production_mode_has_debug_off(monkeypatch):
    # SECRET_KEY is read from the environment once, at class-definition time
    # (so a real deployment just needs the env var set before the process
    # starts). Patching the class attribute directly here exercises the same
    # code path without needing to reload the config module mid-test.
    import config as config_module
    monkeypatch.setattr(config_module.ProductionConfig, "SECRET_KEY", "a-real-production-secret")
    app = create_app("production")
    assert app.config["DEBUG"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_development_mode_has_a_default_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    app = create_app("development")
    assert app.config["SECRET_KEY"]  # falls back to a dev-only key, never None
