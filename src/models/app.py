from flask import Flask, request, jsonify
from flask_cors import CORS
from src.features.rule_engine import RuleEngine
import logging

app = Flask(__name__)
CORS(app) # Enable CORS for Chrome Extension

# Initialize components
rule_engine = RuleEngine()


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL'}), 400
        
    url = data['url']
    html = data.get('html', None)
    
    try:
        # Phase 1: Rule-Based Validation
        rule_result = rule_engine.check_url(url)
        
        if rule_result == -1:
            return jsonify({
                'url': url,
                'probability': 1.0,
                'is_phishing': True,
                'method': 'rule-based (blacklist)',
                'explanations': ['This URL is found in the PhishTank phishing database.']
            })
            
        # For now, focus only on PhishTank. If not in PhishTank, treat as safe/unknown.
        return jsonify({
            'url': url,
            'probability': 0.0,
            'is_phishing': False,
            'method': 'rule-based (not-in-phishtank)',
            'explanations': ['This URL was not found in the PhishTank phishing database.']
        })


    except Exception as e:
        logging.error(f"Inference error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == "__main__":
    app.run(port=5000, debug=False)
