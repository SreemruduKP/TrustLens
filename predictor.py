import joblib
import numpy as np
from features import extract_features

# Load model once when server starts
model = joblib.load("model.pkl")

def predict_url(url: str) -> dict:
     # Normalize URL — add www if missing
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname and not parsed.hostname.startswith("www."):
        url = url.replace(parsed.hostname, "www." + parsed.hostname, 1)
    # Extract features
    my_features = extract_features(url)
    # Convert to 2D array (sklearn expects this)
    features_array = np.array(my_features).reshape(1, -1)
    
    # Predict
    prediction = model.predict(features_array)[0]
    probability = model.predict_proba(features_array)[0]
    
    # Phishing probability (index 0 = phishing class)
    phishing_prob = round(float(probability[0]) * 100, 2)
    
    # Risk score 0-100
    risk_score = phishing_prob if prediction == 0 else round(
        (1 - max(probability)) * 100, 2
    )
    
    # Risk level
    if risk_score < 30:
        risk_level = "🟢 Trusted"
    elif risk_score < 55:
        risk_level = "🟡 Caution"
    elif risk_score < 75:
        risk_level = "🟠 Suspicious"
    else:
        risk_level = "🔴 Dangerous"
    
    return {
        "prediction": "phishing" if prediction == 0 else "legitimate",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": phishing_prob
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.youtube.com",
        "http://login-paypal-verify.xyz/account/confirm?user=john",
        "http://192.168.1.1/login"
    ]
    for url in test_urls:
        print(f"\n{url}")
        print(predict_url(url))