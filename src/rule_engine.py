"""
Cybersecurity Rule Engine
=========================

Expert-defined rules that complement the machine learning prediction.
Each triggered rule adds its weight to a risk score.
"""

# (feature test, weight, message) — weights match Table 3.4 of the report.
RULES = [
    (lambda f: f.get("is_ip") == 1, 50, "Numeric IP address used instead of a domain name."),
    (lambda f: f.get("qty_at", 0) > 0, 40, "URL contains the '@' character."),
    (lambda f: f.get("url_length", 0) > 75, 20, "Excessively long URL (more than 75 characters)."),
    (lambda f: f.get("qty_dot", 0) >= 5, 20, "Too many dots / subdomains in the URL."),
    (lambda f: f.get("qty_hyphen", 0) >= 3, 15, "Multiple hyphens detected."),
    (lambda f: f.get("is_https") == 0, 10, "Website is not using HTTPS."),
]


def evaluate_security_rules(features: dict):
    """
    Apply the security rules to a feature dictionary.

    Returns
    -------
    risk_score : int
        Sum of the weights of all triggered rules.
    triggered_rules : list[str]
        Human-readable descriptions of the triggered rules.
    """
    risk_score = 0
    triggered_rules = []
    for test, weight, message in RULES:
        if test(features):
            risk_score += weight
            triggered_rules.append(message)
    return risk_score, triggered_rules
