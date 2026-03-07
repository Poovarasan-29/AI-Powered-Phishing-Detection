import os
import pandas as pd

ds_path = os.path.join("./data/processed/full_dataset.csv")

ds = pd.read_csv(ds_path)
print(ds.shape)
print(ds.columns)
print(ds['label'].value_counts())

# drop_indices = ds[ds['label'] == 0].sample(n=3652, random_state=42).index
# ds = ds.drop(drop_indices)
# ds.to_csv(ds_path, index=False)


