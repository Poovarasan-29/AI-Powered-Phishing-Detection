import pandas as pd
import os

def create_full_dataset():
    processed_dir = "data/processed"
    phish_path = os.path.join(processed_dir, "phishtank_features.csv")
    safe_path = os.path.join(processed_dir, "tranco_features.csv")
    output_path = os.path.join(processed_dir, "full_dataset.csv")

    if not os.path.exists(phish_path) or not os.path.exists(safe_path):
        print("Required feature files missing.")
        return

    print("[*] Merging datasets...")
    df_phish = pd.read_csv(phish_path)
    df_safe = pd.read_csv(safe_path)
    
    full_df = pd.concat([df_phish, df_safe], ignore_index=True)
    
    # Shuffle the dataset
    full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"[*] Total dataset size: {len(full_df)}")
    print(f"    - Phishing: {len(df_phish)}")
    print(f"    - Safe: {len(df_safe)}")
    
    full_df.to_csv(output_path, index=False)
    print(f"[+] Final dataset saved to {output_path}")

if __name__ == "__main__":
    create_full_dataset()
