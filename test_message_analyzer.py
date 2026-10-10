import pytest

from app.services.errors import InvalidInput
from app.services.message_analyzer import analyze_message
from app.services.risk_engine import assess


def keys(text):
    return {f.key for f in analyze_message(text).findings}


def level(text):
    return assess(analyze_message(text).findings)


def test_benign_message_is_low():
    result = level("Hey, are we still on for lunch tomorrow at noon?")
    assert result.level == "LOW"
    assert result.score == 0


def test_too_short_raises():
    with pytest.raises(InvalidInput):
        analyze_message("hi")


def test_credential_request_detected():
    assert "credential_request" in keys("Please verify your account by entering your password.")


def test_payment_request_detected():
    assert "payment_request" in keys("Send your card details to claim your refund.")


def test_urgency_detected():
    assert "urgency" in keys("Act now, this offer expires in 2 hours!")


def test_threat_detected():
    assert "threat" in keys("Your account will be suspended unless you respond.")


def test_generic_greeting_detected():
    assert "generic_greeting" in keys("Dear valued customer, we have an update for you today.")


def test_too_good_detected():
    assert "too_good" in keys("Congratulations! You have won a free iPhone, claim your prize now.")


def test_scholarship_bait_flagged():
    text = ("Congratulations! You have been selected for a guaranteed scholarship. "
            "To claim it, verify your account and send your card details for a small processing fee.")
    result = level(text)
    assert result.level in ("HIGH", "CRITICAL")
    found = {f.key for f in result.findings}
    assert {"too_good", "credential_request", "payment_request"} <= found


def test_classic_phishing_message_is_high_or_critical():
    text = ("Dear customer, your account has been suspended due to unusual activity. "
            "Act now and verify your password within 24 hours or your account will be closed. "
            "Click here: http://192.168.1.50/login")
    result = level(text)
    assert result.level in ("HIGH", "CRITICAL")


def test_sender_mismatch_detected():
    text = ("From: PayPal Security <security@totally-not-paypal.example>\n"
            "Dear customer, please verify your paypal account.")
    assert "sender_mismatch" in keys(text)


def test_legit_sender_not_flagged_for_mismatch():
    text = "From: PayPal <service@paypal.com>\nYour paypal receipt is attached."
    assert "sender_mismatch" not in keys(text)


def test_no_brand_claim_no_mismatch_check():
    assert "sender_mismatch" not in keys("From: Jane <jane@example.com>\nSee you at 5pm!")


def test_shortened_link_detected():
    assert "shortened_link" in keys("Check this out: https://bit.ly/3xampl3")


def test_suspicious_embedded_link_detected():
    text = "Please login here to confirm: http://paypal-secure.example-verify.com/signin?password=1"
    found = keys(text)
    assert "suspicious_link" in found


def test_benign_link_not_flagged_as_suspicious():
    assert "suspicious_link" not in keys("Here's the doc: https://docs.google.com/document/d/abc")


def test_attachment_lure_detected():
    assert "attachment_lure" in keys("Please open the attached invoice right away.")


def test_unusual_contact_detected():
    assert "unusual_contact" in keys("Reply with your account number or contact us on WhatsApp immediately.")


def test_details_report_link_count_and_sender():
    analysis = analyze_message(
        "From: Amazon <noreply@amz-support.example>\n"
        "Your amazon order needs verification: http://amz-support.example/verify"
    )
    details = dict(analysis.details)
    assert details["Links found"] == "1"
    assert details["Claimed sender"] == "Amazon"


def test_unparseable_link_recorded_but_not_crashing():
    analysis = analyze_message("Click here: http://example.com:abc/ right now to verify your account")
    assert analysis.links
    assert analysis.links[0][1] is None


def test_single_weak_signal_stays_low():
    result = level("Dear customer, thanks for shopping with us.")
    assert result.level == "LOW"


def test_grammar_signal_is_weak_alone():
    result = level("Hi!!!! just checking in on the order!!!!")
    assert result.score <= 29
