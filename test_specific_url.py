
import os
import joblib
import pandas as pd
import sys
from src.features.rule_engine import RuleEngine
from src.features.url_features import URLFeatureExtractor

def analyze_url(url):
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.path.join(BASE_DIR, 'src', 'models', 'phishing_model.joblib')
    FEATURES_PATH = os.path.join(BASE_DIR, 'src', 'models', 'feature_names.joblib')

    # Initialize components
    rule_engine = RuleEngine()
    feature_extractor = URLFeatureExtractor()

    print(f"Analyzing URL: {url}\n")


    # 1. Rule Engine Check
    rule_result = rule_engine.check_url(url)
    if rule_result == -1:
        print("RESULT: PHISHING (Found in PhishTank Blacklist)")
        return
    elif rule_result == 1:
        print("RESULT: SAFE (Found in Whitelist)")
        return



    # 2. ML Model Prediction
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        print("Error: Model or feature names not found. Cannot proceed with ML analysis.")
        return

    model = joblib.load(MODEL_PATH)
    expected_features = joblib.load(FEATURES_PATH)

    features_dict = feature_extractor.extract_features(url)
    if not features_dict:
        print("Error: Failed to extract features from URL.")
        return

    # Align features
    input_list = [features_dict.get(feat, 0) for feat in expected_features]
    features_df = pd.DataFrame([input_list], columns=expected_features)

    # Predict
    probability = float(model.predict_proba(features_df)[0][1])
    is_phishing = probability > 0.5

    print(f"Method: AI-Powered (LightGBM)")
    print(f"Phishing Probability: {probability:.4f}")
    print(f"Is Phishing: {'YES' if is_phishing else 'NO'}")
    
    # Simple explanations based on features
    explanations = []
    if is_phishing:
        if features_dict.get('typosquatting_match', 0) == 1:
            explanations.append("- Typosquatting detected (similar to a popular brand).")
        if features_dict.get('brand_domain_mismatch', 0) == 1:
            explanations.append("- Brand name mismatch between domain and path/subdomain.")
        if features_dict.get('num_dots', 0) > 4:
            explanations.append(f"- High number of dots ({features_dict['num_dots']}).")
        if 'login' in url.lower() or 'verify' in url.lower():
            explanations.append("- Contains sensitive keywords (login/verify).")
    
    if explanations:
        print("\nExplanations:")
        for exp in explanations:
            print(exp)

if __name__ == "__main__":
    url_to_test = "https://netbanking.indianbank.bank.in/jsp/startIBPreview.jsp"
    analyze_url(url_to_test)
