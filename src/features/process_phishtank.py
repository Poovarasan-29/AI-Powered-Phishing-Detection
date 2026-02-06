import pandas as pd
import os
import sys
from tqdm import tqdm
from src.features.url_features import URLFeatureExtractor

def process_phishtank():
    input_path = "data/external/phishtank.csv"
    output_dir = "data/processed"
    output_path = os.path.join(output_dir, "phishtank_features.csv")
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return

    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Reading {input_path}...")
    df = pd.read_csv(input_path)
    urls = df['url'].tolist()
    
    extractor = URLFeatureExtractor()
    feature_list = []
    
    print(f"[*] Extracting features from {len(urls)} URLs...")
    # Using a subset if it's too slow, but user asked for the data
    # We'll do it in chunks or just raw
    for url in tqdm(urls, desc="Processing"):
        try:
            feats = extractor.extract_features(str(url))
            if feats:
                feats['url'] = url
                feats['label'] = 1 # PhishTank is all phishing
                feature_list.append(feats)
        except Exception as e:
            continue
            
    if not feature_list:
        print("No features extracted.")
        return

    print(f"[*] Saving {len(feature_list)} results to {output_path}...")
    output_df = pd.DataFrame(feature_list)
    
    # Reorder columns to put url and label first
    cols = ['url', 'label'] + [c for c in output_df.columns if c not in ['url', 'label']]
    output_df = output_df[cols]
    
    output_df.to_csv(output_path, index=False)
    print("[+] Done!")

if __name__ == "__main__":
    process_phishtank()
