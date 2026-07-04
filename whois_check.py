import whois
from datetime import datetime

def get_domain_age(url: str) -> dict:
    try:
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        
        # Remove www.
        if hostname.startswith("www."):
            hostname = hostname[4:]
        
        # WHOIS lookup
        w = whois.whois(hostname)
        
        # Get creation date
        creation_date = w.creation_date
        
        # Sometimes returns list — take first
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date is None:
            return {
                "domain": hostname,
                "age_days": None,
                "creation_date": None,
                "registrar": w.registrar,
                "age_risk": "unknown"
            }
        
        # Calculate age
        if creation_date.tzinfo is not None:
            from datetime import timezone
            age = datetime.now(timezone.utc) - creation_date
        else:
            age = datetime.now() - creation_date
        age_days = age.days
        
        # Risk based on age
        if age_days < 30:
            age_risk = "🔴 Very New — High Risk"
        elif age_days < 180:
            age_risk = "🟠 Recent — Suspicious"
        elif age_days < 365:
            age_risk = "🟡 Less than 1 year"
        else:
            age_risk = "🟢 Established Domain"
        
        return {
            "domain": hostname,
            "age_days": age_days,
            "creation_date": str(creation_date.date()),
            "registrar": w.registrar,
            "age_risk": age_risk
        }
        
    except Exception as e:
        return {
            "domain": hostname if 'hostname' in locals() else "",
            "age_days": None,
            "creation_date": None,
            "registrar": None,
            "age_risk": "unknown",
            "error": str(e)
        }


if __name__ == "__main__":
    test_domains = [
        "https://www.google.com",
        "https://www.github.com",
    ]
    for url in test_domains:
        print(f"\n{url}")
        print(get_domain_age(url))