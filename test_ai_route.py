"""AI second opinion wired into the /analyze route."""
from unittest.mock import patch

import pytest

from app import create_app
from app.services.ai_service import AIAssessment


@pytest.fixture()
def ai_client():
    app = create_app("testing")
    app.config["PHISHGUARD_AI_ENABLED"] = True
    app.config["OLLAMA_URL"] = "http://127.0.0.1:11434/api/chat"
    app.config["OLLAMA_MODEL"] = "qwen2.5:1.5b"
    app.config["OLLAMA_TIMEOUT"] = 5
    return app.test_client()


def post(client, content, scan_type="url"):
    return client.post("/analyze", data={"scan_type": scan_type, "content": content})


def test_ai_disabled_by_default_shows_no_ai_section(client):
    body = post(client, "https://example.com").get_data(as_text=True)
    assert "AI second opinion" not in body


def test_ai_enabled_shows_result_when_available(ai_client):
    fake = AIAssessment(available=True, indicator="PHISHING", confidence="high",
                         reasoning="Suspicious wording.", model="qwen2.5:1.5b")
    with patch("app.services.analysis_service.get_ai_assessment", return_value=fake):
        body = post(ai_client, "https://example.com").get_data(as_text=True)
    assert "AI second opinion" in body
    assert "likely phishing" in body.lower()
    assert "Suspicious wording." in body
    assert "high confidence" in body


def test_ai_enabled_shows_safe_verdict(ai_client):
    fake = AIAssessment(available=True, indicator="SAFE", confidence="medium",
                         reasoning="Nothing unusual.", model="qwen2.5:1.5b")
    with patch("app.services.analysis_service.get_ai_assessment", return_value=fake):
        body = post(ai_client, "https://example.com").get_data(as_text=True)
    assert "did not flag this" in body
    assert "Nothing unusual." in body


def test_ai_enabled_but_unreachable_falls_back_cleanly(ai_client):
    fake = AIAssessment(available=False, error="The local AI service (Ollama) couldn't be reached.")
    with patch("app.services.analysis_service.get_ai_assessment", return_value=fake):
        response = post(ai_client, "https://example.com")
        body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "AI second opinion unavailable" in body
    assert "couldn" in body and "be reached" in body  # apostrophe is HTML-escaped by Jinja
    # The deterministic result is still fully present and correct.
    assert "LOW RISK" in body
    assert "Risk Score" in body


def test_ai_failure_never_breaks_the_main_result(ai_client):
    """Even an unexpected exception from the AI layer must not break the page.

    ai_service is designed to never raise, but analysis_service still wraps
    the call in a defensive try/except as a last-resort guard, so a bug in
    the optional AI layer can never take down the deterministic result.
    """
    with patch("app.services.analysis_service.get_ai_assessment", side_effect=RuntimeError("boom")):
        response = post(ai_client, "https://example.com")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "LOW RISK" in body
    assert "AI second opinion unavailable" in body
    assert "failed unexpectedly" in body


def test_message_scan_with_ai_enabled(ai_client):
    fake = AIAssessment(available=True, indicator="UNCERTAIN", confidence="low",
                         reasoning="Could not tell.", model="qwen2.5:1.5b")
    with patch("app.services.analysis_service.get_ai_assessment", return_value=fake):
        body = post(ai_client, "Verify your account now", scan_type="message").get_data(as_text=True)
    assert "AI second opinion" in body
    assert "couldn" in body and "fully interpreted" in body  # apostrophe is HTML-escaped by Jinja
