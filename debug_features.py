from src.features.url_features import URLFeatureExtractor
import pandas as pd

extractor = URLFeatureExtractor()
urls = ["https://www.github.com", "https://github.com"]
f1 = extractor.extract_features(urls[0])
f2 = extractor.extract_features(urls[1])

print(f"{'Feature':<30} | {'With WWW':<15} | {'No WWW':<15}")
print("-" * 65)
for k in f1.keys():
    if f1[k] != f2[k]:
        print(f"{k:<30} | {f1[k]:<15} | {f2[k]:<15}")
    else:
        # print identical ones too to see the full picture
        print(f"{k:<30} | {f1[k]:<15} | {f2[k]:<15}")