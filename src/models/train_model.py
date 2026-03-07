import pandas as pd
import numpy as np
import lightgbm as lgb
import joblib
import os
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, classification_report
)
from src.features.url_features import URLFeatureExtractor
import tldextract

class PhishingModelPipeline:
    """
    Production-ready pipeline for training a LightGBM model for Phishing Detection.
    Focuses on Stage 1 (Lexical/Static) features with high recall requirements.
    """
    
    def __init__(self, data_path, model_dir):
        self.data_path = data_path
        self.model_dir = model_dir
        self.model = None
        self.feature_names = []
        self.extractor = URLFeatureExtractor()
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)

    def load_and_preprocess(self):
        """
        Loads the dataset, injects new features (Typosquatting), and prepares X, y.
        """
        print(f"[*] Loading dataset from: {self.data_path}")
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Dataset not found at {self.data_path}")

        df = pd.read_csv(self.data_path).dropna(how='all')
        
        print(f"[*] Dataset loaded with {len(df)} samples.")

        # Inputs: url (ID), label (Target).
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'url' and 'label' columns.")

        # --- Inject New Feature: Typosquatting Match ---
        # Since we just added this feature to the extractor, the CSV likely doesn't have it.
        # We calculate it on the fly to ensure the model uses our latest improvements.
        if 'typosquatting_match' not in df.columns:
            print("[*] Generating new 'typosquatting_match' feature for all URLs... (This may take a moment)")
            # Create a helper to apply extraction
            def get_typo_score(url):
                try:
                    # We only need extraction for the domain logic, but let's reuse the extractor carefully
                    # To be efficient, we replicate just the needed part or call existing method
                    # But calling extract_features is heavy. Let's do a direct check.
                    extracted = tldextract.extract(url)
                    clean_domain = extracted.domain.lower()
                    
                    found = 0
                    for brand in self.extractor.brands:
                         if clean_domain == brand: continue
                         dist = self.extractor.levenshtein_distance(clean_domain, brand)
                         if dist > 0 and dist <= 2 and len(brand) > 4:
                             found = 1
                             break
                    return found
                except:
                    return 0

            df['typosquatting_match'] = df['url'].apply(get_typo_score)
            print("[*] Feature generation complete.")

        # Target variable
        y = df['label']
        
        # Feature selection: Use only numeric columns, drop identifiers
        X = df.drop(['url', 'label'], axis=1)
        X = X.select_dtypes(include=[np.number])
        
        # Handle missing values
        X = X.fillna(0)
        
        self.feature_names = X.columns.tolist()
        print(f"[*] Preprocessing complete. Feature count: {len(self.feature_names)}")
        return X, y

    def train_model(self, X, y):
        """
        Splits data, performs Hyperparameter Optimization (RandomizedSearch), and trains the best model.
        """
        # 1. Stratified Train-Test Split
        test_size = 0.2
        if len(y) < 10:
            print("[!] Warning: Dataset too small for standard split. Using all data for training.")
            X_train, X_test, y_train, y_test = X, X, y, y
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, stratify=y, random_state=42
            )

        print("[*] Starting Hyperparameter Optimization (RandomizedSearchCV)...")
        
        # 2. Define Parameter Grid
        param_grid = {
            'n_estimators': [100, 200, 500],
            'learning_rate': [0.01, 0.05, 0.1],
            'num_leaves': [31, 50, 100],
            'max_depth': [-1, 10, 20],
            'feature_fraction': [0.8, 0.9, 1.0],
            'bagging_fraction': [0.8, 0.9, 1.0],
            'bagging_freq': [5, 10],
            'is_unbalance': [True, False]
        }
        
        lgbm = lgb.LGBMClassifier(objective='binary', metric='binary_logloss', verbose=-1, random_state=42)
        
        # 3. Randomized Search
        search = RandomizedSearchCV(
            estimator=lgbm,
            param_distributions=param_grid,
            n_iter=20, # Try 20 combinations
            scoring='recall', # Optimize for Recall (Catching Phishing is priority)
            cv=3,
            verbose=1,
            random_state=42,
            n_jobs=-1
        )
        
        search.fit(X_train, y_train)
        
        print(f"[SUCCESS] Best Parameters found: {search.best_params_}")
        self.model = search.best_estimator_

        # 4. Comprehensive Evaluation
        self._evaluate(X_train, y_train, X_test, y_test)
        
        # 5. Feature Importance
        self._report_importance()

    def _evaluate(self, X_train, y_train, X_test, y_test):
        """
        Reports internal evaluation metrics.
        """
        train_preds = self.model.predict(X_train)
        test_preds = self.model.predict(X_test)
        test_probs = self.model.predict_proba(X_test)[:, 1]

        print("\n" + "="*50)
        print("MODEL PERFORMANCE EVALUATION")
        print("="*50)
        
        print(f"{'Metric':<20} | {'Train':<10} | {'Test':<10}")
        print("-" * 50)
        
        metrics = {
            'Accuracy': accuracy_score,
            'Precision': precision_score,
            'Recall': recall_score,
            'F1-Score': f1_score
        }

        for name, func in metrics.items():
            tr_score = func(y_train, train_preds)
            te_score = func(y_test, test_preds)
            print(f"{name:<20} | {tr_score:<10.4f} | {te_score:<10.4f}")

        try:
            auc = roc_auc_score(y_test, test_probs)
            print(f"{'ROC-AUC':<20} | {'-':<10} | {auc:<10.4f}")
        except:
            print("[!] ROC-AUC could not be calculated.")

        print("-" * 50)
        print("DETAILED TEST REPORT:")
        print(classification_report(y_test, test_preds, target_names=['Safe', 'Phishing']))

    def _report_importance(self):
        """
        Extends explainability by showing which features drive the model.
        """
        importances = self.model.feature_importances_
        feat_imp = pd.Series(importances, index=self.feature_names).sort_values(ascending=False)
        
        print("TOP 10 INFLUENTIAL FEATURES:")
        print(feat_imp.head(10))
        print("-" * 50)

    def save_artifacts(self):
        """
        Saves model and feature names for deployment.
        """
        model_path = os.path.join(self.model_dir, 'phishing_model.joblib')
        features_path = os.path.join(self.model_dir, 'feature_names.joblib')

        joblib.dump(self.model, model_path)
        joblib.dump(self.feature_names, features_path)

        print(f"[SUCCESS] Model artifact saved: {model_path}")
        print(f"[SUCCESS] Feature names saved: {features_path}")
        print("[READY] The system is now ready for deployment in src/models/app.py")

if __name__ == "__main__":
    # Configure paths
    BASE_DIR = r'c:\Users\S POOVARASAN\OneDrive\Desktop\AI-Phishing Detection'
    DATA_PATH = os.path.join(BASE_DIR, 'data','processed', 'full_dataset.csv')
    MODEL_DIR = os.path.join(BASE_DIR, 'src', 'models')

    # Execute Pipeline
    pipeline = PhishingModelPipeline(DATA_PATH, MODEL_DIR)
    try:
        X, y = pipeline.load_and_preprocess()
        pipeline.train_model(X, y)
        pipeline.save_artifacts()
    except Exception as e:
        print(f"[ERROR] Pipeline failed: {e}")
