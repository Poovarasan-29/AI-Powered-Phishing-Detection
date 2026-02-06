import pandas as pd
import os
from tqdm import tqdm
from src.features.url_features import URLFeatureExtractor

def process_tranco():
    input_path = "data/external/tranco_whitelist.csv"
    output_dir = "data/processed"
    output_path = os.path.join(output_dir, "tranco_features.csv")
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return

    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Reading {input_path}...")
    df = pd.read_csv(input_path)
    # Take first 50,000 for a balanced dataset against PhishTank (~46k)
    domains = df['domain'].head(50000).tolist()
    
    extractor = URLFeatureExtractor()
    feature_list = []
    
    print(f"[*] Extracting features from {len(domains)} Safe Domains...")
    for domain in tqdm(domains, desc="Processing"):
        try:
            # Convert domain to a standard safe URL
            url = f"https://www.{domain}"
            feats = extractor.extract_features(url)
            if feats:
                feats['url'] = url
                feats['label'] = 0 # Safe
                feature_list.append(feats)
        except Exception:
            continue
            
    if not feature_list:
        print("No features extracted.")
        return

    print(f"[*] Saving {len(feature_list)} results to {output_path}...")
    output_df = pd.DataFrame(feature_list)
    cols = ['url', 'label'] + [c for c in output_df.columns if c not in ['url', 'label']]
    output_df = output_df[cols]
    output_df.to_csv(output_path, index=False)
    print("[+] Done!")

if __name__ == "__main__":
    process_tranco()
