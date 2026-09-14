import pytest
from engine import FraudEngine

@pytest.fixture
def engine():
    return FraudEngine()

def test_missing_at_symbol_vpa(engine):
    """Test that a VPA missing the '@' symbol is immediately rejected with a score of 100."""
    score, reasons = engine.check_vpa_risk("invalid_vpa_no_at")
    assert score == 100
    assert any("Missing '@' symbol" in r for r in reasons)

def test_self_payment_detection(engine):
    """Test that users cannot send money to their own username handle."""
    score, reasons = engine.check_vpa_risk("student1@upi", username="student1")
    assert score == 100
    assert any("SELF-PAYMENT NOT ALLOWED" in r for r in reasons)

def test_amount_tampering(engine):
    """Test that mismatched amounts between QR and user input trigger tampering alerts."""
    # QR forces 5000, but user inputs 500
    payload = "upi://pay?pa=merchant@axis&pn=Shop&am=5000.00&cu=INR"
    score, reasons, pa, pn = engine.analyze_qr_deep(payload, user_amt=500.00)
    
    assert score >= 65
    assert any("AMOUNT TAMPERING" in r for r in reasons)

def test_collect_request_scam(engine):
    """Test that reverse collect request payloads trigger critical security blocks."""
    payload = "upi://pay?pa=scammer@ybl&pn=Fraud&mode=02&sign=collect"
    score, reasons, pa, pn = engine.analyze_qr_deep(payload, user_amt=100.00)
    
    assert score == 100
    assert any("COLLECT REQUEST WARNING" in r for r in reasons)

def test_non_upi_qr_rejection(engine):
    """Test that arbitrary phishing URLs disguised as QRs are blocked."""
    payload = "http://malicious-phishing-site.com/steal"
    score, reasons, pa, pn = engine.analyze_qr_deep(payload, user_amt=100.00)
    
    assert score == 100
    assert any("NOT a UPI payment QR" in r for r in reasons)

def test_verified_merchant_reward(engine):
    """Test that a registered official merchant reduces risk score."""
    # amazon@upi is in the default seeded database
    score, reasons = engine.check_vpa_risk("amazon@upi")
    assert score < 0
    assert any("Verified Merchant" in r for r in reasons)
