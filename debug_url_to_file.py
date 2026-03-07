
import os
import joblib
import pandas as pd
from src.features.url_features import URLFeatureExtractor

def debug_url(url):
    extractor = URLFeatureExtractor()
    features = extractor.extract_features(url)
    
    with open("debug_results.txt", "w") as f:
        f.write(f"URL: {url}\n")
        f.write("-" * 30 + "\n")
        for k, v in features.items():
            f.write(f"{k}: {v}\n")
        
        # Check ML Prediction
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        MODEL_PATH = os.path.join(BASE_DIR, 'src', 'models', 'phishing_model.joblib')
        FEATURES_PATH = os.path.join(BASE_DIR, 'src', 'models', 'feature_names.joblib')
        
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
            model = joblib.load(MODEL_PATH)
            expected_features = joblib.load(FEATURES_PATH)
            
            input_list = [features.get(feat, 0) for feat in expected_features]
            features_df = pd.DataFrame([input_list], columns=expected_features)
            
            prob = model.predict_proba(features_df)[0][1]
            f.write("-" * 30 + "\n")
            f.write(f"ML Probability: {prob:.4f}\n")
            f.write(f"Is Phishing: {prob > 0.5}\n")

if __name__ == "__main__":
    debug_url("https://intercontrol.online/")
