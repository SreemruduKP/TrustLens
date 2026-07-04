import re
from urllib.parse import urlparse

def extract_features(url: str) -> list:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. URL length (raw number)
    url_length = len(url)

    # 2. Dot count
    dot_count = url.count(".")

    # 3. Hyphen count
    hyphen_count = url.count("-")

    # 4. Special char count
    special_chars = re.findall(r'[@!%=?&$]', url)
    special_char_count = len(special_chars)

    # 5. HTTPS (1=yes, 0=no)
    has_https = 1 if parsed.scheme == "https" else 0

    # 6. IP address (1=yes, 0=no)
    has_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+',
                            hostname) else 0

    # 7. Suspicious words (1=yes, 0=no)
    suspicious_words = ["verify", "login", "secure",
                        "account", "update", "confirm",
                        "banking", "paypal", "password"]
    has_suspicious_words = 1 if any(
        w in url.lower() for w in suspicious_words
    ) else 0

    # 8. Subdomain count (raw number)
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # 9. URL depth
    url_depth = parsed.path.count("/")

    # 10. @ symbol (1=yes, 0=no)
    has_at = 1 if "@" in url else 0

    # 11. Double slash in path (1=yes, 0=no)
    has_double_slash = 1 if "//" in parsed.path else 0

    # 12. Shortened URL (1=yes, 0=no)
    shorteners = ["bit.ly", "tinyurl", "goo.gl",
                  "t.co", "short.link", "ow.ly"]
    is_shortened = 1 if any(
        s in url.lower() for s in shorteners
    ) else 0

    # 13. Non standard port (1=yes, 0=no)
    has_non_standard_port = 1 if parsed.port and \
        parsed.port not in [80, 443] else 0

    # 14. Suspicious TLD (1=yes, 0=no)
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga",
                       ".cf", ".gq", ".top", ".club"]
    has_suspicious_tld = 1 if any(
        hostname.endswith(tld) for tld in suspicious_tlds
    ) else 0

    # 15. Domain length
    domain_length = len(hostname)

    return [
        url_length, dot_count, hyphen_count,
        special_char_count, has_https, has_ip,
        has_suspicious_words, subdomain_count,
        url_depth, has_at, has_double_slash,
        is_shortened, has_non_standard_port,
        has_suspicious_tld, domain_length
    ]