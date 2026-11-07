"""
Lexical Feature Extraction Module
=================================

Converts a URL string into the eleven lexical features used by both the
training pipeline and the web application. Only the text of the URL is
examined; the website itself is never visited.
"""

import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Order matters: the model is trained on the features in this order.
FEATURE_NAMES = [
    "url_length",
    "qty_dot",
    "qty_hyphen",
    "qty_underline",
    "qty_slash",
    "qty_question",
    "qty_equal",
    "qty_at",
    "qty_dot_domain",
    "is_ip",
    "is_https",
]


def is_ip_address(hostname: str) -> int:
    """Return 1 if the host name is an IPv4 or IPv6 address, otherwise 0."""
    host = hostname.strip("[]")          # IPv6 hosts are written as [::1]
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def get_hostname(url: str) -> str:
    """Return the host part of a URL without user information or port."""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    host = host.rsplit("@", 1)[-1]       # drop "user:password@"
    if host.startswith("["):             # IPv6 literal with optional port
        return host.split("]")[0] + "]"
    return host.split(":")[0].lower()


def extract_url_features(url: str) -> dict:
    """Extract the eleven lexical features from a URL."""
    url = str(url).strip()
    parsed = urlparse(url)
    host = get_hostname(url)

    features = {
        # URL characteristics
        "url_length": len(url),
        "qty_dot": url.count("."),
        "qty_hyphen": url.count("-"),
        "qty_underline": url.count("_"),
        "qty_slash": url.count("/"),
        "qty_question": url.count("?"),
        "qty_equal": url.count("="),
        "qty_at": url.count("@"),
        # Domain characteristics
        "qty_dot_domain": host.count("."),
        "is_ip": is_ip_address(host),
        "is_https": 1 if parsed.scheme.lower() == "https" else 0,
    }
    logger.debug("Extracted %d features from URL.", len(features))
    return features
