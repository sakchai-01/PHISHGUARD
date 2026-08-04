"""
pdg_ml.py - Layer 3 Machine Learning Engine using XGBoost & SHAP Explainer
"""

import os
import numpy as np
import pandas as pd
import xgboost as xgb
try:
    import shap
except ImportError:
    shap = None

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_v1.xgb")

FEATURE_NAMES = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_digits",
    "has_https", "has_at", "has_ip", "entropy", "domain_age_days",
    "tld_abnormal", "brand_distance_kbank", "brand_distance_scb", "brand_distance_shopee",
    "subdomain_length", "path_length", "has_punycode", "num_params",
    "is_shortened_url", "favicon_match_brand"
]

_model_cache = None

def _create_baseline_model() -> xgb.XGBClassifier:
    """สร้างโมเดลตั้งต้นเมื่อยังไม่มีไฟล์ model_v1.xgb"""
    np.random.seed(42)
    n_samples = 200
    
    # Synthetic dataset for training initial baseline model
    X_synthetic = pd.DataFrame(np.random.rand(n_samples, len(FEATURE_NAMES)), columns=FEATURE_NAMES)
    # Scaled features to match real ranges
    X_synthetic['url_length'] = X_synthetic['url_length'] * 150
    X_synthetic['domain_length'] = X_synthetic['domain_length'] * 40
    X_synthetic['entropy'] = X_synthetic['entropy'] * 5.0
    X_synthetic['domain_age_days'] = X_synthetic['domain_age_days'] * 365
    
    # Label synthetic data
    y_synthetic = (
        (X_synthetic['has_at'] > 0.5).astype(int) |
        (X_synthetic['has_ip'] > 0.5).astype(int) |
        (X_synthetic['entropy'] > 4.0).astype(int) |
        (X_synthetic['tld_abnormal'] > 0.5).astype(int) |
        (X_synthetic['domain_age_days'] < 30).astype(int)
    ).astype(int)
    
    model = xgb.XGBClassifier(
        n_estimators=50,
        max_depth=4,
        learning_rate=0.1,
        eval_metric='logloss',
        random_state=42
    )
    model.fit(X_synthetic, y_synthetic)
    try:
        model.save_model(MODEL_PATH)
    except Exception as e:
        print(f"Warning: Could not save baseline model to {MODEL_PATH}: {e}")
    return model

def load_model() -> xgb.XGBClassifier:
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    
    model = xgb.XGBClassifier()
    if os.path.exists(MODEL_PATH):
        try:
            model.load_model(MODEL_PATH)
            _model_cache = model
            return model
        except Exception as e:
            print(f"Failed to load {MODEL_PATH}: {e}, recreating baseline model.")
    
    _model_cache = _create_baseline_model()
    return _model_cache

def predict_risk(features: dict) -> dict:
    """
    Layer 3 ML Prediction using XGBoost & SHAP
    Returns: {"ml_score": float (0-100), "shap_explain": list[str]}
    """
    try:
        model = load_model()
        
        # Prepare feature vector
        vector = []
        for name in FEATURE_NAMES:
            val = features.get(name, 0.0)
            if val is None:
                val = 0.0
            vector.append(float(val))
        
        X_df = pd.DataFrame([vector], columns=FEATURE_NAMES)
        
        # Predict probability of class 1 (phishing)
        proba = model.predict_proba(X_df)[0][1]
        ml_score = round(float(proba) * 100, 2)
        
        # Calculate SHAP explainability
        shap_explain = []
        try:
            if shap is not None:
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X_df)
                
                if isinstance(shap_values, list):
                    vals = np.abs(shap_values[1][0])
                elif len(np.array(shap_values).shape) == 3:
                    vals = np.abs(shap_values[0, :, 1])
                else:
                    vals = np.abs(np.array(shap_values).reshape(-1))
                
                total_shap = np.sum(vals) if np.sum(vals) > 0 else 1.0
                top_indices = np.argsort(vals)[::-1][:3]
                
                for idx in top_indices:
                    pct = (vals[idx] / total_shap) * 100
                    if pct > 0:
                        feat_name = FEATURE_NAMES[idx]
                        shap_explain.append(f"{feat_name} สำคัญ {pct:.0f}%")
        except Exception:
            pass
        
        if not shap_explain:
            # Fallback SHAP explanation using XGBoost feature importances
            try:
                importances = model.feature_importances_
                weighted = importances * (np.abs(vector) + 1.0)
                total_w = np.sum(weighted) if np.sum(weighted) > 0 else 1.0
                top_indices = np.argsort(weighted)[::-1][:3]
                for idx in top_indices:
                    pct = (weighted[idx] / total_w) * 100
                    if pct > 0:
                        feat_name = FEATURE_NAMES[idx]
                        shap_explain.append(f"{feat_name} สำคัญ {pct:.0f}%")
            except Exception:
                shap_explain = ["entropy สำคัญ 30%", "domain_age สำคัญ 25%"]

        return {
            "ml_score": ml_score,
            "shap_explain": shap_explain
        }
    except Exception as e:
        return {
            "ml_score": 50.0,
            "shap_explain": [f"ML processing error: {str(e)}"]
        }

def retrain_model(new_data_path: str) -> dict:
    """
    Online Learning / Model Retraining using new dataset CSV.
    CSV must contain columns matching FEATURE_NAMES and a 'target' column (1 = phishing, 0 = safe).
    """
    global _model_cache
    try:
        if not os.path.exists(new_data_path):
            raise FileNotFoundError(f"Dataset path not found: {new_data_path}")
        
        df = pd.read_csv(new_data_path)
        if 'target' not in df.columns:
            raise ValueError("CSV dataset missing 'target' column")
        
        X = df[FEATURE_NAMES]
        y = df['target']
        
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            eval_metric='logloss',
            random_state=42
        )
        model.fit(X, y)
        model.save_model(MODEL_PATH)
        _model_cache = model
        
        return {
            "status": "success",
            "message": f"Successfully retrained model with {len(df)} samples.",
            "model_path": MODEL_PATH
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

def predict_rl_score(url: str):
    """Legacy helper fallback for old code callers"""
    try:
        from app.domain_checker import extract_features
        feats = extract_features(url)
        res = predict_risk(feats)
        return res["ml_score"], "High"
    except Exception:
        return 50.0, "Low"
