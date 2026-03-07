from src.features.url_features import URLFeatureExtractor

extractor = URLFeatureExtractor()

print("--- Testing Levenshtein ---")
d = extractor.levenshtein_distance("g00gle", "google")
print(f"Distance 'g00gle' vs 'google': {d}")

d2 = extractor.levenshtein_distance("paypal", "paypol")
print(f"Distance 'paypal' vs 'paypol': {d2}")

print("\n--- Testing Extraction ---")
url = "https://www.g00gle.com"
feats = extractor.extract_features(url)
print(f"URL: {url}")
print(f"Typosquat Feature: {feats.get('typosquatting_match')}")

url2 = "https://www.paypal.com" # Exact match
feats2 = extractor.extract_features(url2)
print(f"URL: {url2}")
print(f"Typosquat Feature: {feats2.get('typosquatting_match')} (Should be 0)")
