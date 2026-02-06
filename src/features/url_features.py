import re
import math
import tldextract
from urllib.parse import urlparse
import numpy as np

class URLFeatureExtractor:
    def __init__(self):
        self.shorteners = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' \
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' \
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' \
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.ny|lnkd\.in|' \
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tiny\.cc|ow\.ly|bit\.ly|ity\.im|' \
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|' \
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
        
        self.sensitive_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'confirm', 'signin', 'ebayisapi', 'webscr']
        self.brands = ['google', 'amazon', 'microsoft', 'apple', 'facebook', 'netflix', 'paypal', 'github', 'instagram', 'twitter', 'linkedin']

    def calculate_entropy(self, text):
        if not text:
            return 0
        probabilities = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log(p, 2) for p in probabilities)

    def extract_features(self, url):
        features = {}
        
        # Parse URL
        try:
            parsed_url = urlparse(url)
            extracted = tldextract.extract(url)
            domain_part = f"{extracted.domain}.{extracted.suffix}"
            path = parsed_url.path
            query = parsed_url.query
        except Exception:
            return None

        # 1. Lexical Features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain_part)
        features['path_length'] = len(path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_at_symbols'] = url.count('@')
        
        digits = re.findall(r'\d', url)
        features['num_digits'] = len(digits)
        features['digit_ratio'] = len(digits) / len(url) if len(url) > 0 else 0
        
        special_chars = re.findall(r'[!$%^&*()_+={}\[\]:;"\'<>,.?/|`~]', url)
        features['num_special_chars'] = len(special_chars)
        
        uppercase = re.findall(r'[A-Z]', url)
        features['num_uppercase_chars'] = len(uppercase)
        
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['path_depth'] = len([p for p in path.split('/') if p])

        # 2. Structural Features
        features['has_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', extracted.domain) else 0
        features['uses_url_shortener'] = 1 if re.search(self.shorteners, url) else 0
        features['has_double_slash'] = 1 if url.find('//', 7) != -1 else 0 # Search after protocol
        
        # Suspicious prefix/suffix in domain (e.g. google-verify.com)
        features['has_suspicious_prefix_suffix'] = 1 if '-' in extracted.domain else 0
        
        features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['has_ssl_token'] = 1 if 'ssl' in url.lower() or 'secure' in url.lower() else 0
        features['has_port_number'] = 1 if parsed_url.port else 0
        
        # 3. Statistical Features
        features['url_entropy'] = self.calculate_entropy(url)
        
        # 4. Semantic Features
        features['has_encoded_chars'] = 1 if '%' in url else 0
        
        kw_count = sum(1 for kw in self.sensitive_keywords if kw in url.lower())
        features['has_sensitive_keywords'] = 1 if kw_count > 0 else 0
        
        # Brand Features
        brand_hits = [b for b in self.brands if b in url.lower()]
        features['brand_keyword_count'] = len(brand_hits)
        
        # Brand Domain Mismatch (Brand in subdomain or path, but not in main domain)
        mismatch = 0
        for b in self.brands:
            if b in url.lower() and b not in extracted.domain.lower():
                mismatch = 1
                break
        features['brand_domain_mismatch'] = mismatch

        # 5. Typo/Homoglyph (Simulated basic check)
        # In a real scenario, we'd use Levenshtein distance against top brands
        features['has_homoglyph'] = 1 if re.search(r'[01lI|]', extracted.domain) and any(b in extracted.domain for b in ['google', 'paypal', 'microsoft']) else 0

        return features

if __name__ == "__main__":
    extractor = URLFeatureExtractor()
    test_url = "http://secure-google-login.com/verify?id=123"
    print(extractor.extract_features(test_url))
