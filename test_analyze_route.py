def post(client, content, scan_type="url"):
    return client.post("/analyze", data={"scan_type": scan_type, "content": content})


def test_normal_url_shows_low_result(client):
    response = post(client, "https://example.com")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "LOW RISK" in body
    assert "Risk Score" in body and "0/100" in body
    assert "Recommended action" in body
    assert "https://example.com" in body  # original content shown


def test_risky_url_shows_findings_and_reasoning(client):
    body = post(client, "http://192.168.1.50/login").get_data(as_text=True)
    assert "HIGH RISK" in body or "CRITICAL RISK" in body
    assert "Why we flagged this" in body
    assert "Not using HTTPS" in body
    assert "Several independent warning signs together" in body


def test_submitted_content_is_escaped_and_not_linked(client):
    payload = "https://example.com/<script>alert(1)</script>"
    body = post(client, payload).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    assert 'href="https://example.com' not in body


def test_empty_input_returns_400_with_message(client):
    response = post(client, "   ")
    assert response.status_code == 400
    assert "Paste a link to check." in response.get_data(as_text=True)


def test_malformed_input_returns_400_and_keeps_text(client):
    response = post(client, "javascript:alert(1)")
    body = response.get_data(as_text=True)
    assert response.status_code == 400
    assert "http://" in body
    assert "javascript:alert(1)" in body  # shown back, escaped by Jinja


def test_too_long_input_rejected(client):
    response = post(client, "https://example.com/" + "a" * 6000)
    assert response.status_code == 400
    assert "too long" in response.get_data(as_text=True)


def test_oversized_body_gets_friendly_413(client):
    response = post(client, "a" * 70000)
    assert response.status_code == 413
    assert "too large" in response.get_data(as_text=True)


def test_invalid_scan_type_rejected(client):
    assert post(client, "https://example.com", scan_type="bogus").status_code == 400


def test_message_analysis_now_available(client):
    response = post(client, "Verify your account password immediately or it will be suspended.",
                     scan_type="message")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "RISK" in body
    assert "Message breakdown" in body


def test_message_too_short_is_400(client):
    response = post(client, "hi", scan_type="message")
    assert response.status_code == 400
    assert "too short" in response.get_data(as_text=True)


def test_message_with_link_shows_link_list(client):
    text = "Please login here to verify: http://paypal-secure.example-verify.com/signin?password=1"
    body = post(client, text, scan_type="message").get_data(as_text=True)
    assert "Links in this message" in body
    assert "paypal-secure.example-verify.com" in body
