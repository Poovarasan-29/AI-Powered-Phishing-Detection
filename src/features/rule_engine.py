import pandas as pd
import os
import tldextract
from urllib.parse import urlparse

class RuleEngine:
    """
    Performs fast, rule-based lookups using datasets (PhishTank, Tranco).
    """
    
    def __init__(self):
        self.external_dir = "data/external"
        self.phishtank_path = os.path.join(self.external_dir, "phishtank.csv")
        self.tranco_path = os.path.join(self.external_dir, "tranco_whitelist.csv")

        
        self.blacklist = set()
        self.whitelist = set()
        self._load_datasets()

    def _load_datasets(self):
        # Load PhishTank blacklist
        if os.path.exists(self.phishtank_path):
            df = pd.read_csv(self.phishtank_path)
            self.blacklist = set(df['url'].str.lower())
            print(f"[*] Loaded {len(self.blacklist)} phishing URLs from PhishTank.")

        
        # Load Tranco whitelist
        if os.path.exists(self.tranco_path):
            df = pd.read_csv(self.tranco_path)
            self.whitelist = set(df['domain'].str.lower())

    def check_url(self, url):
        """
        Main entry point for rule-based check.
        Returns:
            -1 if Phishing (Blacklist hit)
             1 if Safe (Whitelist hit)
             0 if Unknown (Need ML analysis)
        """
        url_lower = url.lower().strip()
        
        # 1. Exact Blacklist Check (PhishTank)
        if url_lower in self.blacklist:
            return -1
            
        # 2. Whitelist Check (Tranco)
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # Shared Providers List: These are safe root domains but host user content.
        # We MUST run ML for these to check the specific subdomain/path.
        shared_providers = {
            'weebly.com', 'blogspot.com', 'github.io', 'firebaseapp.com',
            'pages.dev', 'workers.dev', 'wixsite.com', 'ukit.me', 
            'boxmode.io', '000webhostapp.com', 'web.app'
        }

        if domain in self.whitelist and domain not in shared_providers:
            return 1
            
        return 0


if __name__ == "__main__":
    engine = RuleEngine()
    print(f"Check google.com: {engine.check_url('https://google.com')}")
    # Example phishing from PhishTank if loaded
    if engine.blacklist:
        sample_phish = list(engine.blacklist)[0]
        print(f"Check known phish: {engine.check_url(sample_phish)}")
