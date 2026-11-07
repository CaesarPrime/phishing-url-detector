"""
Hybrid Decision Engine
======================

Combines the machine learning prediction with the rule engine risk score.

Class convention used everywhere in this project:
    1 = PHISHING (DANGER)
    0 = LEGITIMATE (SAFE)
"""

PHISHING = 1
LEGITIMATE = 0

STRONG_RULE_SCORE = 50        # rules alone are enough to flag the URL
MEDIUM_RULE_SCORE = 30        # rules flag the URL if the model is unsure
CONFIDENCE_THRESHOLD = 0.995  # "unsure" means confidence below this value


def hybrid_decision(ml_prediction: int, confidence: float, risk_score: int) -> int:
    """Return the final class (1 = phishing, 0 = legitimate)."""
    if risk_score >= STRONG_RULE_SCORE:
        return PHISHING
    if risk_score >= MEDIUM_RULE_SCORE and confidence < CONFIDENCE_THRESHOLD:
        return PHISHING
    return int(ml_prediction)


def risk_level(risk_score: int) -> str:
    """Map a rule score to a risk level (Table 3.5 of the report)."""
    if risk_score >= 50:
        return "HIGH"
    if risk_score >= 20:
        return "MEDIUM"
    return "LOW"


def label(prediction: int) -> str:
    return "DANGER" if prediction == PHISHING else "SAFE"
