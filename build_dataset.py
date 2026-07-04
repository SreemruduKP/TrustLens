from ucimlrepo import fetch_ucirepo
import pandas as pd
from features import extract_features

print("Downloading dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"]
labels = dataset.data.targets

print("Extracting features from", len(urls), "URLs...")

rows = []
for i, url in enumerate(urls):
    try:
        features = extract_features(str(url))
        rows.append(features)
    except:
        rows.append([0] * 15)  # if URL breaks, fill with 0
    
    if i % 10000 == 0:
        print(f"Progress: {i}/{len(urls)}")

# Create DataFrame
columns = [
    "url_length", "dot_count", "hyphen_count",
    "special_char_count", "has_https", "has_ip",
    "has_suspicious_words", "subdomain_count",
    "url_depth", "has_at", "has_double_slash",
    "is_shortened", "has_non_standard_port",
    "has_suspicious_tld", "domain_length"
]
df = pd.DataFrame(rows, columns=columns)
df["Result"] = labels.values

# Save
df.to_csv("data/my_phishing_dataset.csv", index=False)
print("\nDone! Dataset saved.")
print("Shape:", df.shape)
print(df["Result"].value_counts())