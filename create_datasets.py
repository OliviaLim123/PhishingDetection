import pandas as pd         # Pandas -> for data manipulation
import requests             # Requests -> send HTTP request and fetch the data from PhishTank and Tranco
from io import StringIO     # IO -> make the string data to be compatible for Pandas module 

# Download phishing URLs data from PhishTank
def fetch_phishtank_data():
    print("Fetching phishing URLs from PhishTank...")
    url = "https://data.phishtank.com/data/online-valid.csv"
    try:
        # Send HTTP Get request 
        response = requests.get(url)
        # Load the CSV content 
        df = pd.read_csv(StringIO(response.text))
        # Extract the URL column by removing empty values and obtaining unique URLs
        phishing_urls = df['url'].dropna().unique()
        return list(phishing_urls)
    except Exception as e:
        print(f"Error fetching PhishTank data: {e}")
        return []

# Download legitimate domains from Tranco
def fetch_tranco_legit_urls(limit=5000):
    print("Fetching legitimate URLs from Tranco...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        # Read zipped CSV File 
        tranco_df = pd.read_csv(tranco_url, compression='zip', header=None, names=['rank', 'domain'])
        # Focus on the top ranked domains
        tranco_df = tranco_df.head(limit)
        # Construct the URLs
        legit_urls = ["https://" + domain for domain in tranco_df['domain']]
        return legit_urls
    except Exception as e:
        print(f"Error fetching Tranco data: {e}")
        return []


# Combine datasets, Label them, and Saves into the CSV file 
# The output from this file will be used in phishing_detection.py 
def create_url_dataset():
    # Fetch from PhishTank
    phishing = fetch_phishtank_data()
    # Fetch from Tranco 
    legitimate = fetch_tranco_legit_urls(limit=len(phishing))

    # Combine the URLs
    urls = phishing + legitimate
    # Label them where 1 is phishing and 0 is legitimate
    labels = [1] * len(phishing) + [0] * len(legitimate)

    # Create a DataFrame 
    df = pd.DataFrame({'url': urls, 'label': labels})
    # Remove duplicated entries 
    df = df.drop_duplicates(subset='url').dropna()
    print(f"Total URLs: {len(df)} (Phishing: {sum(df.label==1)}, Legitimate: {sum(df.label==0)})")

    # Save into url_dataset.csv file 
    df.to_csv("url_dataset.csv", index=False)
    print("Dataset saved as 'url_dataset.csv'")

    return df

# Run the dataset creation
if __name__ == "__main__":
    create_url_dataset()
