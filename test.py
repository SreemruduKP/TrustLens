import joblib
import numpy as np
from features import extract_features

model = joblib.load("model.pkl")

urls = [
    "https://google.com",
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "http://login-paypal-verify.xyz/confirm",
]

for url in urls:
    f = extract_features(url)
    arr = np.array(f).reshape(1, -1)
    pred = model.predict(arr)[0]
    prob = model.predict_proba(arr)[0]
    label = "legitimate" if pred == 1 else "phishing"
    print(f"{url} → {label} | prob: {prob}")
    