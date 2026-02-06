import pandas as pd
import os
from sklearn.model_selection import train_test_split
import logging

class DataStorage:
    """
    Handles storage and splitting of URL datasets.
    """
    
    def __init__(self, base_dir="data"):
        self.raw_dir = os.path.join(base_dir, "raw")
        self.processed_dir = os.path.join(base_dir, "processed")
        
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)

    def save_raw_data(self, df, filename="all_urls.csv"):
        """
        Appends new data to the raw CSV file.
        """
        path = os.path.join(self.raw_dir, filename)
        if os.path.exists(path):
            existing_df = pd.read_csv(path)
            # Concat and drop duplicates
            combined = pd.concat([existing_df, df]).drop_duplicates(subset=['url'])
            combined.to_csv(path, index=False)
            logging.info(f"Saved {len(df)} new records. Total: {len(combined)}")
            return combined
        else:
            df.to_csv(path, index=False)
            logging.info(f"Created new raw data file with {len(df)} records.")
            return df

    def create_time_based_splits(self, filename="all_urls.csv"):
        """
        Splits data into Train/Val/Test based on timestamp to simulate zero-day detection.
        """
        path = os.path.join(self.raw_dir, filename)
        if not os.path.exists(path):
            logging.error("Raw data file not found.")
            return

        df = pd.read_csv(path)
        
        # Sort by time
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp')
        
        # Split: 70% Train, 15% Val, 15% Test
        # Since we want "future" data in test, we just slice the sorted array.
        train_size = int(0.7 * len(df))
        val_size = int(0.15 * len(df))
        
        train = df.iloc[:train_size]
        val = df.iloc[train_size : train_size + val_size]
        test = df.iloc[train_size + val_size:]
        
        train.to_csv(os.path.join(self.processed_dir, "train.csv"), index=False)
        val.to_csv(os.path.join(self.processed_dir, "val.csv"), index=False)
        test.to_csv(os.path.join(self.processed_dir, "test.csv"), index=False)
        
        logging.info(f"Created splits: Train={len(train)}, Val={len(val)}, Test={len(test)}")

if __name__ == "__main__":
    storage = DataStorage()
    storage.create_time_based_splits()

