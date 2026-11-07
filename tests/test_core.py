from src.feature_extraction import FEATURE_NAMES, extract_url_features
from src.hybrid_engine import hybrid_decision, label, risk_level
from src.rule_engine import evaluate_security_rules
from src.url_utils import is_valid_url, normalize_url


def test_feature_extraction_basic():
    f = extract_url_features("https://www.example.com/path?a=1")
    assert list(f) == FEATURE_NAMES
    assert f["is_https"] == 1 and f["is_ip"] == 0
    assert f["qty_dot"] == 2 and f["qty_dot_domain"] == 2
    assert f["qty_question"] == 1 and f["qty_equal"] == 1


def test_feature_extraction_ip_and_at():
    f = extract_url_features("http://user@192.168.1.10:8080/login")
    assert f["is_ip"] == 1
    assert f["qty_at"] == 1
    assert f["is_https"] == 0


def test_rules_safe_url():
    score, rules = evaluate_security_rules(extract_url_features("https://github.com"))
    assert score == 0 and rules == []


def test_rules_suspicious_url():
    score, rules = evaluate_security_rules(extract_url_features("http://123.45.67.89/login"))
    assert score == 60          # IP (50) + no HTTPS (10)
    assert len(rules) == 2


def test_hybrid_decision():
    assert hybrid_decision(0, 0.99, 60) == 1         # strong rule override
    assert hybrid_decision(0, 0.90, 35) == 1         # medium override, weak confidence
    assert hybrid_decision(0, 0.999, 35) == 0        # model very confident
    assert hybrid_decision(1, 0.80, 0) == 1          # ML decision kept
    assert label(1) == "DANGER" and label(0) == "SAFE"


def test_risk_levels():
    assert risk_level(0) == "LOW"
    assert risk_level(20) == "MEDIUM"
    assert risk_level(50) == "HIGH"


def test_url_validation():
    assert normalize_url("  google.com ") == "http://google.com"
    assert is_valid_url("https://www.example.com/x")
    assert is_valid_url("http://10.0.0.1/admin")
    assert not is_valid_url("http://notaurl")
    assert not is_valid_url("ftp://example.com")
    assert not is_valid_url("http://exa mple.com")
