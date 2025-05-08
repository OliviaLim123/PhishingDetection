import pandas as pd
import numpy as np
import re
import math
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# 1. URL entropy calc
def calculate_entropy(url):
    # calcurating the presence rate of each character
    freq = {}
    for char in url:
        if char in freq:
            freq[char] += 1
        else:
            freq[char] = 1

    # length of the URL
    length = len(url)

    # calculating entropy
    entropy = 0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return entropy



# 2. detection of shortened URL
# shortened URL's domain list (we can add more if we want)
shortener_domains = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly"
]

def is_shortened_url(url):
    for domain in shortener_domains:
        if domain in url:
            return True
    return False

# 3. Keyword-based check for suspicious terms in URLs
def contains_suspicious_keyword(url):
    keywords = ["login", "secure", "account", "update", "verify", "bank"]
    return int(any(keyword in url.lower() for keyword in keywords))

# 4. Feature extraction
def extract_features(df):
    features = []

    for url in df['url']:
        url_length = len(url)
        subdomain_count = url.count('.') - 1
        has_https = 1 if 'https' in url else 0
        suspicious_chars = len(re.findall(r'[@#$%^&*()!;]', url))
        contains_numbers = 1 if any(char.isdigit() for char in url) else 0
        hyphen_count = url.count('-')
        # calculate URL entropy
        entropy = calculate_entropy(url)
        # detection of shortened URL
        is_shortened = 1 if is_shortened_url(url) else 0
        # check for suspicious keywords
        suspicious_keyword = contains_suspicious_keyword(url)
        # checking for any digit contain binary and count 
        digit_count = sum(char.isdigit() for char in url)
        digit_ratio = digit_count / url_length if url_length > 0 else 0.0

        features.append([
            url_length,
            subdomain_count,
            has_https,
            suspicious_chars,
            contains_numbers,
            hyphen_count,
            entropy,  # additional feature: URL entropy
            is_shortened,  # additional feature: shortened URL
            suspicious_keyword,
            digit_ratio
        ])

    feature_names = ['url_length', 'subdomain_count', 'has_https', 'suspicious_chars',
                     'contains_numbers', 'hyphen_count', 'entropy', 'is_shortened', 'suspicious_keyword','digit_ratio']

    return pd.DataFrame(features, columns=feature_names)


# 4. Model training
def train_model(df):
    # Check label distribution
    print("Label distribution:\n", df['label'].value_counts())

    # Extract features
    X = extract_features(df)
    y = df['label']  # Labels can be 0 (Legitimate) or 1 (Phishing)

    # Split the data into training (80% of all data) and test sets (only 20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Predict and evaluate
    y_pred = model.predict(X_test)

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Confusion Matrix shows:
    # [TN FP] - TN: True Negative, FP: False Positive
    # [FN TP] - FN: False Negative, TP: True Positive
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # --- Printing in the terminal ----
    # Add entropy and shortened URL status to predictions
    test_data = X_test.copy()
    test_data['predictions'] = y_pred
    test_data['entropy'] = X_test['entropy']
    test_data['is_shortened'] = X_test['is_shortened']

    print("\n--- Test Data with Added Features ---")
    print(test_data.head())

    # --- Diagram 1: Confusion Matrix Heatmap ---
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.show()

    # --- Diagram 2: Feature Importance ---
    feature_importances = model.feature_importances_
    feature_names = X.columns

    plt.figure(figsize=(8, 5))
    sns.barplot(x=feature_importances, y=feature_names)
    plt.title('Feature Importance')
    plt.xlabel('Importance Score')
    plt.ylabel('Feature')
    plt.tight_layout()
    plt.show()

    return model


# 5. Test Custom URLs
def test_custom_urls(model):
    test_urls = [
        "https://my-bank-login.com",  # Phishing example
        "https://apple.com",  # Legitimate
        "http://free-gift.com/win-now",  # Phishing example
        "https://github.com",  # Legitimate
        "http://198.51.100.5/bankofamerica/verify",  # Phishing
        "http://paypal.account.verify.com",  # Phishing example
        "https://www.google.com",  # Legitimate
        "http://login.secure-banking.com",  # Phishing example
        "https://www.amazon.com",  # Legitimate
        "http://pay-pal123445.com",  # Phishing example (similar to PayPal)
        "https://www.wikipedia.org",  # Legitimate
        "https://www.microsoft.com",  # Phishing example
        "http://winfree-iphone.com",  # Phishing example
        "https://www.nike.com",  # Legitimate
        "http://secure-google-login.com",  # Phishing example (new)
        "https://www.paypal.com",  # Legitimate
        "https://www.youtube.com",  # Legitimate 
        "https://stackoverflow.com",  # Legitimate
        "http://updateyourbanknow.ru" # Phishing
    ]


    # Convert to DataFrame
    test_df = pd.DataFrame({'url': test_urls})
    # Extract features from the URLs
    test_features = extract_features(test_df)
    # Predict the models
    predictions = model.predict(test_features)

    # Show results
    print("\n--- URL Prediction Results ---")
    for url, pred in zip(test_urls, predictions):
        label = "Phishing" if pred == 1 else "Legitimate"
        print(f"{url} → {label}")

    # --- Diagram 3: Prediction Result Pie Chart ---
    phishing_count = sum(predictions)
    legit_count = len(predictions) - phishing_count

    plt.figure(figsize=(5, 5))
    plt.pie([legit_count, phishing_count],
            labels=['Legitimate', 'Phishing'],
            autopct='%1.1f%%',
            colors=['green', 'red'])
    plt.title('Prediction Distribution (Test URLs)')
    plt.tight_layout()
    plt.show()


# 6. Main function
def main():
    try:
        # Use the datasets from the create_dataset.py output
        df = pd.read_csv("url_dataset.csv")

        # Ensure correct labels
        if 'label' not in df.columns or 'url' not in df.columns:
            print("Dataset must contain 'url' and 'label' columns.")
            return

        # Train and test the model
        model = train_model(df)
        test_custom_urls(model)

    except FileNotFoundError:
        print("Dataset file 'url_dataset.csv' not found.")
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    main()
