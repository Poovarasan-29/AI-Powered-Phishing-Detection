import requests
import os
import zipfile
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def download_file(url, target_path, headers=None):
    if os.path.exists(target_path):
        logging.info(f"File {target_path} already exists. Skipping download.")
        return True
    
    logging.info(f"Downloading from {url}...")
    try:
        response = requests.get(url, headers=headers, stream=True)
        response.raise_for_status()
        with open(target_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded to {target_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to download {url}: {e}")
        return False

def prepare_datasets():
    external_dir = "data/external"
    os.makedirs(external_dir, exist_ok=True)
    
    # 1. PhishTank (Simplified lookup list)
    # Note: PhishTank rate-limits downloads, so we use cached data
    phishtank_simple_path = os.path.join(external_dir, "phishtank_simple.csv")
    phishtank_path = os.path.join(external_dir, "phishtank.csv")
    
    if os.path.exists(phishtank_simple_path):
        logging.info(f"Using existing PhishTank cache: {phishtank_simple_path}")
    elif os.path.exists(phishtank_path):
        logging.info("Processing existing PhishTank full dataset...")
        try:
            df = pd.read_csv(phishtank_path)
            # Use the full PhishTank dataset (no limit)
            urls = df['url']
            urls.to_csv(phishtank_simple_path, index=False)
            logging.info(f"PhishTank dataset prepared with {len(urls)} phishing URLs.")
        except Exception as e:
            logging.error(f"Error processing PhishTank: {e}")

    else:
        logging.warning("No PhishTank data found. Rule-based blacklist will be empty.")
        logging.info("Note: PhishTank enforces rate limits. Please download manually from:")
        logging.info("  http://data.phishtank.com/data/online-valid.csv")
        logging.info(f"  and save to: {phishtank_path}")

    # 2. Tranco (Top 1M domains)
    # Using the more stable zip download link
    tranco_zip_url = "https://tranco-list.eu/top-1m.csv.zip"
    tranco_zip_path = os.path.join(external_dir, "tranco.zip")
    tranco_csv_name = "top-1m.csv"
    tranco_path = os.path.join(external_dir, "tranco.csv")
    
    if download_file(tranco_zip_url, tranco_zip_path):
        try:
            logging.info("Extracting Tranco zip...")
            with zipfile.ZipFile(tranco_zip_path, 'r') as zip_ref:
                zip_ref.extractall(external_dir)
            
            # The extracted file is named 'top-1m.csv'
            extracted_csv = os.path.join(external_dir, "top-1m.csv")
            
            # Load and process - using full 1M for comprehensive whitelist
            df = pd.read_csv(extracted_csv, names=['rank', 'domain'], header=None)
            top_domains = df['domain'].head(1000000)  # Full 1M domains
            top_domains.to_csv(os.path.join(external_dir, "tranco_whitelist.csv"), index=False)
            logging.info(f"Tranco whitelist prepared with {len(top_domains)} domains.")
        except Exception as e:
            logging.error(f"Error processing Tranco: {e}")


    else:
        logging.warning("Tranco download failed. Falling back to a small mock whitelist.")
        # Fallback for demo stability
        mock_domains = ["google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com"]
        pd.Series(mock_domains, name='domain').to_csv(os.path.join(external_dir, "tranco_whitelist.csv"), index=False)



if __name__ == "__main__":
    prepare_datasets()
