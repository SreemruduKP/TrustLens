import re
from urllib.parse import urlparse

def extract_features(url: str) ->list:
    parsed = urlparse(url)

    #1
    url_length = len(url)
    #2
    dot_count = url.count(".")
    #3
    hyphen_count = url.count("-")
    #4
    special_chars = re.findall(r'[@!%=?&$]',url)
    special_char_count = len(special_chars)
    #5
    has_https = 1 if parsed.scheme == "https" else -1
    #6
    has_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.hostname or "") else -1
    #7
    suspicious_words = ["verify","login", "secure", "account", "update", "confirm", "banking", "paypal", "password"]
    has_suspicious_words = 1 if any(word in url.lower() for word in suspicious_words) else -1
    #8
    hostname = parsed.hostname or ""
    subdomain_count = len(hostname.split(".")) - 2
    subdomain_count = max(0, subdomain_count)
    #9
    url_depth = parsed.path.count("/")
    #10
    has_at_symbol = 1 if "@" in url else -1

    #11
    has_double_slash = 1 if "//" in parsed.path else -1
    #12
    shorteners = ["bit.ly", "tinyurl", "goo.gl", 
                "t.co", "short.link", "ow.ly"]
    is_shortened = 1 if any(
        s in url.lower() for s in shorteners
    ) else -1
    #13
    has_non_standard_port = 1 if parsed.port and \
                            parsed.port not in [80, 443] else -1
    #14
    has_credentials = 1 if parsed.username or parsed.password else -1
    #15
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga",
                       ".cf", ".gq", ".top", ".club"]
    has_suspicious_tld = 1 if any(
        hostname.endswith(tld) for tld in suspicious_tlds
    ) else -1

    return [
        url_length,
        dot_count,
        hyphen_count,
        special_char_count,
        has_https,
        has_ip,
        has_suspicious_words,
        subdomain_count,
        url_depth,
        has_at_symbol,
        has_double_slash,
        is_shortened,
        has_non_standard_port,
        has_credentials,
        has_suspicious_tld
    ]


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://login-paypal-verify.xyz/account/confirm?user=john",
        "http://192.168.1.1/login"
    ]
    for url in test_urls:
        print(f"\n{url}")
        print(extract_features(url))
