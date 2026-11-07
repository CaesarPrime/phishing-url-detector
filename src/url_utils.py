"""URL normalization and validation."""

import re
from urllib.parse import urlparse

from .feature_extraction import get_hostname, is_ip_address

MAX_URL_LENGTH = 2048
_HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def normalize_url(url: str) -> str:
    """Trim spaces and add a scheme when the user leaves it out."""
    url = (url or "").strip()
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_valid_url(url: str) -> bool:
    """Accept only http/https URLs with a domain name, IP address or localhost."""
    if not url or len(url) > MAX_URL_LENGTH or any(c.isspace() for c in url):
        return False
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return False
    host = get_hostname(url)
    return bool(is_ip_address(host) or host == "localhost" or _HOST_RE.match(host))
