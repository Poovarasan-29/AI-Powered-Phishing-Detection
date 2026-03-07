from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import pandas as pd
import numpy as np
import logging
from src.features.rule_engine import RuleEngine
from src.features.url_features import URLFeatureExtractor

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app) # Enable CORS for Chrome Extension

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'models', 'phishing_model.joblib')
FEATURES_PATH = os.path.join(BASE_DIR, 'src', 'models', 'feature_names.joblib')

# Initialize components
rule_engine = RuleEngine()
feature_extractor = URLFeatureExtractor()

# Load ML Model
try:
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
        model = joblib.load(MODEL_PATH)
        expected_features = joblib.load(FEATURES_PATH)
        logging.info("[SUCCESS] LightGBM Model and feature list loaded.")
    else:
        model = None
        expected_features = None
        logging.warning("[WARNING] ML Model files not found. Relying on Rule-based only.")
except Exception as e:
    model = None
    expected_features = None
    logging.error(f"[ERROR] Failed to load ML model: {e}")

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL'}), 400
        
    url = data['url']
    
    try:
        # 1. Check Rule Engine (Whitelist/Blacklist) - Highest Priority
        rule_result = rule_engine.check_url(url)

        # Blacklist hit
        if rule_result == -1:
            return jsonify({
                'url': url,
                'probability': 1.0,
                'is_phishing': True,
                'method': 'Rule-Based (Blacklist)',
                'risk_level': 'CRITICAL',
                'explanations': ['High Risk: This URL matches a verified entry in our phishing database (PhishTank).']
            })
            
        # Whitelist hit
        if rule_result == 1:
            return jsonify({
                'url': url,
                'probability': 0.0,
                'is_phishing': False,
                'method': 'Rule-Based (Whitelist)',
                'risk_level': 'SAFE',
                'explanations': ['Safe: This domain is part of our verified whitelist of trusted websites.']
            })

        # 2. ML Model Inference
        if model is not None:
            # Extract features
            features_dict = feature_extractor.extract_features(url)
            if not features_dict:
                return jsonify({'error': 'Failed to extract features from URL'}), 400

            # Prepare feature vector aligned with training data
            input_list = []
            features_present = {} # To use for explanation generation
            
            for feat in expected_features:
                val = features_dict.get(feat, 0)
                input_list.append(val)
                features_present[feat] = val
            
            # Inference
            features_df = pd.DataFrame([input_list], columns=expected_features)
            probability = float(model.predict_proba(features_df)[0][1])
            is_phishing = probability > 0.5
            
            # 3. Dynamic Explainable AI (XAI)
            explanations = []
            risk_level = "LOW"
            
            if is_phishing:
                risk_level = "HIGH" if probability > 0.8 else "MODERATE"
                explanations.append(f"Suspicious: AI detected strong phishing patterns (Confidence: {probability:.2%}).")
                
                # Check specific "Red Flag" features to explain WHY
                if features_present.get('typosquatting_match', 0) == 1:
                    explanations.append("CRITICAL: Typosquatting detected! The domain mimics a popular brand (e.g. 'g00gle' instead of 'google').")
                
                if features_present.get('brand_domain_mismatch', 0) == 1:
                    explanations.append("Warning: Brand name detected in path/subdomain, but the actual domain does not match.")
                    
                if features_present.get('uses_url_shortener', 0) == 1:
                    explanations.append("Caution: Uses a specific URL shortener often associated with hiding malicious links.")
                    
                if features_present.get('has_ip_address', 0) == 1:
                    explanations.append("Security Alert: The URL uses an IP address instead of a domain name.")
                    
                if features_present.get('num_dots', 0) > 4:
                    explanations.append("Structure: Excessive number of dots in the URL, often used to confuse users.")
                    
                if features_present.get('at_symbol', 0) or '@' in url:
                    explanations.append("Obfuscation: Uses '@' symbol to mask the true destination.")
            else:
                explanations.append(f"Safe: No significant phishing patterns found (Likelihood: {probability:.2%}).")

            return jsonify({
                'url': url,
                'probability': round(probability, 4),
                'is_phishing': is_phishing,
                'method': 'AI-Powered (LightGBM)',
                'risk_level': risk_level,
                'explanations': explanations
            })
            
        # Fallback if no model is loaded
        return jsonify({
            'url': url,
            'probability': 0.0,
            'is_phishing': False,
            'method': 'Rule-Based (Safe)',
            'risk_level': 'UNKNOWN',
            'explanations': ['This URL was not found in our threat databases and AI is offline.']
        })

    except Exception as e:
        logging.error(f"Analysis error: {e}")
        return jsonify({'error': f"Internal analysis failed: {str(e)}"}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'ml_loaded': model is not None,
        'rules_loaded': True
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
