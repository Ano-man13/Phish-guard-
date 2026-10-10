def test_landing_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "PhishGuard" in body
    assert "Check before you click." in body
    assert "Analyze Now" in body


def test_landing_page_has_security_headers(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_analyze_rejects_get(client):
    assert client.get("/analyze").status_code == 405


def test_unknown_route_is_404(client):
    assert client.get("/nope").status_code == 404
