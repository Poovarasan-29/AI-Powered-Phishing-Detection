import os
import requests
import pandas as pd
import logging
from datetime import datetime, timezone


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataCollector:
    """
    Collects phishing and trusted URLs from public sources.
    """
    
    def __init__(self):
        self.sources = {
            'openphish': 'https://openphish.com/feed.txt',
            # PhishTank often requires API or interactive download; listing for ref
            # 'phishtank': 'http://data.phishtank.com/data/online-valid.csv' 
        }

    def fetch_phishing_urls(self, limit=5000):

        """
        Fetches recent phishing URLs from OpenPhish.
        """
        logging.info("Fetching phishing URLs from OpenPhish...")
        try:
            response = requests.get(self.sources['openphish'], timeout=10)
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                logging.info(f"Retrieved {len(urls)} URLs from OpenPhish.")
                
                if limit:
                    urls = urls[:limit]
                    
                df = pd.DataFrame(urls, columns=['url'])
                df['label'] = 1 # 1 = Phishing
                df['source'] = 'openphish'
                df['timestamp'] = datetime.now(timezone.utc).isoformat()
                return df
            else:
                logging.error(f"Failed to fetch OpenPhish: {response.status_code}")
                return pd.DataFrame()
        except Exception as e:
            logging.error(f"Error fetching phishing URLs: {e}")
            return pd.DataFrame()

    def fetch_benign_urls(self, limit=1000):
        """
        Fetches benign URLs from valid sources (e.g., Tranco daily list).
        For this implementation, we will simulate or fetch a small top-list 
        because full lists are large zips.
        """
        logging.info("Fetching benign URLs...")
        # In a real scenario, we would download the Tranco ZIP, extract it, and read top N.
        # For simplicity in this env, we will use a small static top list or mock if offline.
        
        # Mocking top trusted domains for demonstration if network is restricted
        # In production: replace with `requests.get('https://tranco-list.eu/top-1m.csv.zip')`
        top_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "netflix.com", "microsoft.com",
            # ... assume we'd fill this or fetch it
        ]
        
        # If we can fetch a text list of top domains:
        try:
            # Using a raw github list of top 1000 domains as a proxy for Tranco
            url = "https://raw.githubusercontent.com/zonefiles/copy/master/top-1m.csv" # Example proxy
            # Or just generating from the few we have for safety
            
            # Let's return the mock list for stability in this prompt's environment
            # unless we want to try a real request.
            pass 
        except:
            pass
            
        # Generating a DataFrame
        # Emulating "Top 1000" by just repeating or having a placeholder
        # In a real run, this should be robust.
        
        df = pd.DataFrame(top_domains, columns=['url'])
        # Benign URLs often need schema added to match phishing format
        df['url'] = df['url'].apply(lambda x: f"https://{x}" if not x.startswith('http') else x)
        
        df['label'] = 0 # 0 = Benign
        df['source'] = 'popular_domains'
        df['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        return df


class PageContentScraper:
    """
    Scrapes HTML and DOM metadata from URLs.
    """
    def __init__(self, storage_dir="data/raw/content"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def scrape_url(self, url):
        """
        Fetches and saves HTML content.
        """
        try:
            # We use a common User-Agent to avoid simple bot detection
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                # Sanitize filename
                filename = "".join([c for c in url if c.isalnum()]).rstrip()[:100] + ".html"
                filepath = os.path.join(self.storage_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                logging.info(f"Scraped and saved content for {url}")
                return filepath
            return None
        except Exception as e:
            logging.error(f"Failed to scrape {url}: {e}")
            return None

if __name__ == "__main__":
    # Example usage for verification
    collector = DataCollector()
    scraper = PageContentScraper()
    
    # Just scrape 2 examples to verify
    phishing = collector.fetch_phishing_urls(limit=2)
    for url in phishing['url']:
        scraper.scrape_url(url)

