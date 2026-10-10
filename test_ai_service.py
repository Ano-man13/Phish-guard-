"""AI second-opinion service: mocked HTTP only, no real Ollama needed."""
from unittest.mock import Mock, patch

import requests

from app.services.ai_service import get_ai_assessment

URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen2.5:1.5b"


def _ollama_response(content_str, status_code=200):
    mock = Mock()
    mock.status_code = status_code
    mock.json.return_value = {"message": {"role": "assistant", "content": content_str}}
    return mock


def test_disabled_returns_unavailable_without_network_call():
    with patch("app.services.ai_service.requests.post") as mock_post:
        result = get_ai_assessment("url", "https://example.com", enabled=False,
                                    url=URL, model=MODEL, timeout=5)
    mock_post.assert_not_called()
    assert result.available is False
    assert "turned off" in result.error


def test_missing_config_returns_unavailable():
    result = get_ai_assessment("url", "https://example.com", enabled=True,
                                url=None, model=MODEL, timeout=5)
    assert result.available is False
    assert "configured" in result.error


def test_successful_phishing_verdict():
    reply = '{"indicates_phishing": true, "confidence": "high", "reasoning": "Urgent credential request."}'
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response(reply)):
        result = get_ai_assessment("message", "Verify your password now", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is True
    assert result.indicator == "PHISHING"
    assert result.confidence == "high"
    assert "credential" in result.reasoning.lower()
    assert result.model == MODEL


def test_successful_safe_verdict():
    reply = '{"indicates_phishing": false, "confidence": "medium", "reasoning": "Looks like a normal message."}'
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response(reply)):
        result = get_ai_assessment("message", "Lunch tomorrow?", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is True
    assert result.indicator == "SAFE"
    assert result.confidence == "medium"


def test_model_reply_wrapped_in_extra_text_is_still_parsed():
    reply = 'Sure, here is my analysis:\n{"indicates_phishing": true, "confidence": "low", "reasoning": "Hmm."}\nDone.'
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response(reply)):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is True
    assert result.indicator == "PHISHING"


def test_invalid_confidence_falls_back_to_low():
    reply = '{"indicates_phishing": false, "confidence": "extremely-sure", "reasoning": "ok"}'
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response(reply)):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.confidence == "low"


def test_completely_unparseable_reply_is_uncertain_not_a_crash():
    reply = "I cannot help with that request."
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response(reply)):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is True
    assert result.indicator == "UNCERTAIN"
    assert "cannot help" in result.reasoning.lower()


def test_timeout_is_graceful():
    with patch("app.services.ai_service.requests.post", side_effect=requests.exceptions.Timeout):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=1)
    assert result.available is False
    assert "too long" in result.error


def test_connection_error_is_graceful():
    with patch("app.services.ai_service.requests.post",
               side_effect=requests.exceptions.ConnectionError):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is False
    assert "couldn't be reached" in result.error


def test_non_200_status_is_graceful():
    with patch("app.services.ai_service.requests.post", return_value=_ollama_response("{}", 500)):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is False
    assert "error" in result.error.lower()


def test_malformed_outer_json_is_graceful():
    mock = Mock()
    mock.status_code = 200
    mock.json.side_effect = ValueError("not json")
    with patch("app.services.ai_service.requests.post", return_value=mock):
        result = get_ai_assessment("url", "http://example.com", enabled=True,
                                    url=URL, model=MODEL, timeout=5)
    assert result.available is False
    assert "unexpected" in result.error.lower()


def test_long_content_is_truncated_before_sending():
    long_text = "a" * 10000
    with patch("app.services.ai_service.requests.post",
               return_value=_ollama_response('{"indicates_phishing": false, "confidence": "low", "reasoning": "fine"}')) as mock_post:
        get_ai_assessment("message", long_text, enabled=True, url=URL, model=MODEL, timeout=5)
    sent_payload = mock_post.call_args.kwargs["json"]
    user_message = sent_payload["messages"][1]["content"]
    assert len(user_message) < 2100  # prompt prefix + MAX_PROMPT_CHARS, not the full 10000
