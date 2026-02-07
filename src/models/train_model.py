import pandas as pd
import numpy as np
import lightgbm as lgb
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, classification_report
)

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
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)

    def load_and_preprocess(self):
        """
        Loads the dataset, selects numeric features, and handles missing values.
        """
        print(f"[*] Loading dataset from: {self.data_path}")
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Dataset not found at {self.data_path}")

        df = pd.read_csv(self.data_path).dropna(how='all')
        
        print(f"[*] Dataset loaded with {len(df)} samples and {len(df.columns)} columns.")

        # Inputs: url (ID), label (Target). Features: everything else.
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'url' and 'label' columns.")

        # Target variable
        y = df['label']
        
        # Feature selection: Use only numeric columns, drop identifiers
        X = df.drop(['url', 'label'], axis=1)
        X = X.select_dtypes(include=[np.number])
        
        # Handle missing values: Using 0 as a neutral baseline for Stage 1 features
        # (e.g., if path_depth is missing, assume 0)
        X = X.fillna(0)
        
        self.feature_names = X.columns.tolist()
        print(f"[*] Preprocessing complete. Feature count: {len(self.feature_names)}")
        return X, y

    def train_model(self, X, y):
        """
        Splits data, tunes/trains LightGBM, and evaluates performance.
        """
        # 1. Stratified Train-Test Split
        # Ensuring class distribution is preserved is critical for detection models
        # Handle cases where dataset is extremely small (like the current temp/dataset.csv)
        test_size = 0.2
        if len(y) < 10:
            print("[!] Warning: Dataset too small for standard split. Using all data for training.")
            X_train, X_test, y_train, y_test = X, X, y, y
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, stratify=y, random_state=42
            )

        # 2. Hyperparameter Configuration
        # These parameters are chosen to prevent overfitting while maintaining speed
        lgbm_params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'boosting_type': 'gbdt',
            'n_estimators': 100,
            'learning_rate': 0.05,
            'num_leaves': 31,
            'max_depth': -1,
            'feature_fraction': 0.8, # Prevent reliance on single features
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'is_unbalance': True,    # Handle imbalance between Phishing and Safe URLs
            'random_state': 42,
            'verbose': -1
        }

        print("[*] Training LightGBM model with stratified data...")
        self.model = lgb.LGBMClassifier(**lgbm_params)
        self.model.fit(X_train, y_train)

        # 3. Comprehensive Evaluation
        self._evaluate(X_train, y_train, X_test, y_test)
        
        # 4. Feature Importance
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

        # ROC-AUC is vital for checking the model's ability to rank risk
        try:
            auc = roc_auc_score(y_test, test_probs)
            print(f"{'ROC-AUC':<20} | {'-':<10} | {auc:<10.4f}")
        except:
            print("[!] ROC-AUC could not be calculated (usually due to single class in split)")

        print("-" * 50)
        print("DETAILED TEST REPORT:")
        print(classification_report(y_test, test_preds, target_names=['Safe', 'Phishing']))
        
        print("\n[CRITICAL ANALYSIS: RECALL]")
        print("In Phishing Detection, Recall for the Phishing class is our most critical metric.")
        print("A False Negative (missing a phishing site) results in a compromised user.")
        print("A False Positive (flagging a safe site) is merely an inconvenience.")
        print("Our pipeline prioritizes identifying as many threats as possible.\n")

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
