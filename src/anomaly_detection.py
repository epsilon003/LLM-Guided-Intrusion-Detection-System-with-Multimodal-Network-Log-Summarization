"""
LLM-Guided Explainable Intrusion Detection System
Module 2: Anomaly Detection Engine
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import precision_recall_fscore_support
import joblib
import json
from datetime import datetime

class AnomalyDetectionEngine:
    """
    Multi-model anomaly detection engine supporting:
    - Isolation Forest (unsupervised)
    - Random Forest (supervised)
    - Deep Neural Network (supervised)
    """
    
    def __init__(self):
        self.models = {}
        self.model_metadata = {}
        
    def train_isolation_forest(self, X_train, contamination=0.1):
        """
        Train Isolation Forest for unsupervised anomaly detection
        Good for detecting novel attacks without labels
        """
        print("[Training] Isolation Forest...")
        
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1,
            verbose=0
        )
        
        model.fit(X_train)
        self.models['isolation_forest'] = model
        
        self.model_metadata['isolation_forest'] = {
            'type': 'unsupervised',
            'trained_at': datetime.now().isoformat(),
            'n_samples': X_train.shape[0],
            'n_features': X_train.shape[1],
            'contamination': contamination
        }
        
        print("[✓] Isolation Forest trained successfully")
        return model
    
    def train_random_forest(self, X_train, y_train, n_estimators=100):
        """
        Train Random Forest classifier for supervised detection
        Excellent for feature importance and interpretability
        """
        print("[Training] Random Forest Classifier...")
        
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=4,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        
        model.fit(X_train, y_train)
        self.models['random_forest'] = model
        
        self.model_metadata['random_forest'] = {
            'type': 'supervised',
            'trained_at': datetime.now().isoformat(),
            'n_samples': X_train.shape[0],
            'n_features': X_train.shape[1],
            'n_estimators': n_estimators,
            'classes': list(np.unique(y_train))
        }
        
        print("[✓] Random Forest trained successfully")
        return model
    
    def train_deep_neural_network(self, X_train, y_train, hidden_layers=(128, 64, 32)):
        """
        Train Deep Neural Network for complex pattern recognition
        Better for capturing non-linear relationships
        """
        print("[Training] Deep Neural Network...")
        
        model = MLPClassifier(
            hidden_layer_sizes=hidden_layers,
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size='auto',
            learning_rate='adaptive',
            learning_rate_init=0.001,
            max_iter=200,
            random_state=42,
            verbose=False,
            early_stopping=True,
            validation_fraction=0.1
        )
        
        model.fit(X_train, y_train)
        self.models['dnn'] = model
        
        self.model_metadata['dnn'] = {
            'type': 'supervised',
            'trained_at': datetime.now().isoformat(),
            'n_samples': X_train.shape[0],
            'n_features': X_train.shape[1],
            'hidden_layers': hidden_layers,
            'classes': list(np.unique(y_train))
        }
        
        print("[✓] Deep Neural Network trained successfully")
        return model
    
    def predict_anomaly(self, X, model_name='random_forest', return_proba=False):
        """
        Predict anomalies using specified model
        Returns predictions and optionally probabilities
        """
        if model_name not in self.models:
            raise ValueError(f"Model '{model_name}' not found. Train it first.")
        
        model = self.models[model_name]
        
        if model_name == 'isolation_forest':
            # Isolation Forest returns -1 for anomalies, 1 for normal
            predictions = model.predict(X)
            predictions = (predictions == -1).astype(int)
            
            if return_proba:
                # Get anomaly scores
                scores = model.score_samples(X)
                # Convert to pseudo-probabilities
                proba = 1 / (1 + np.exp(scores))
                return predictions, proba
            
            return predictions
        
        else:
            # Supervised models
            predictions = model.predict(X)
            
            if return_proba:
                proba = model.predict_proba(X)
                return predictions, proba
            
            return predictions
    
    def evaluate_model(self, X_test, y_test, model_name='random_forest'):
        """
        Comprehensive model evaluation with metrics
        """
        print(f"\n[Evaluating] {model_name.upper()}")
        print("=" * 60)
        
        predictions = self.predict_anomaly(X_test, model_name)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='binary'
        )
        
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, predictions)
        print(cm)
        
        # Calculate false positive rate
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\nFalse Positive Rate: {fpr:.4f}")
        print(f"True Negatives:  {tn}")
        print(f"False Positives: {fp}")
        print(f"False Negatives: {fn}")
        print(f"True Positives:  {tp}")
        
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'false_positive_rate': fpr,
            'confusion_matrix': cm.tolist(),
            'model_name': model_name
        }
        
        return results
    
    def get_feature_importance(self, feature_names, model_name='random_forest', top_n=20):
        """
        Extract feature importance from tree-based models
        """
        if model_name not in ['random_forest']:
            print(f"Feature importance not available for {model_name}")
            return None
        
        model = self.models[model_name]
        importances = model.feature_importances_
        
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False).head(top_n)
        
        return importance_df
    
    def detect_and_explain(self, X_sample, feature_names, model_name='random_forest'):
        """
        Detect anomaly and prepare data for LLM explanation
        Returns structured information about the detection
        """
        prediction, proba = self.predict_anomaly(
            X_sample.reshape(1, -1), 
            model_name, 
            return_proba=True
        )
        
        is_anomaly = prediction[0] == 1
        confidence = proba[0][1] if len(proba.shape) > 1 else proba[0]
        
        # Get most significant features
        sample_df = pd.DataFrame([X_sample], columns=feature_names)
        
        # Sort features by absolute value (most significant)
        feature_values = {
            name: float(value) 
            for name, value in zip(feature_names, X_sample)
        }
        
        sorted_features = sorted(
            feature_values.items(), 
            key=lambda x: abs(x[1]), 
            reverse=True
        )[:10]
        
        detection_info = {
            'is_anomaly': bool(is_anomaly),
            'confidence': float(confidence),
            'model_used': model_name,
            'timestamp': datetime.now().isoformat(),
            'top_features': dict(sorted_features),
            'severity': self._calculate_severity(confidence)
        }
        
        return detection_info
    
    def _calculate_severity(self, confidence):
        """Calculate severity level based on confidence"""
        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.75:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def save_models(self, directory='models'):
        """Save trained models to disk"""
        import os
        os.makedirs(directory, exist_ok=True)
        
        for name, model in self.models.items():
            filepath = os.path.join(directory, f"{name}.pkl")
            joblib.dump(model, filepath)
            print(f"[✓] Saved {name} to {filepath}")
        
        # Save metadata
        metadata_path = os.path.join(directory, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(self.model_metadata, f, indent=2)
        print(f"[✓] Saved metadata to {metadata_path}")
    
    def load_models(self, directory='models'):
        """Load trained models from disk"""
        import os
        
        # Load metadata
        metadata_path = os.path.join(directory, 'metadata.json')
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                self.model_metadata = json.load(f)
        
        # Load models
        for filename in os.listdir(directory):
            if filename.endswith('.pkl'):
                name = filename.replace('.pkl', '')
                filepath = os.path.join(directory, filename)
                self.models[name] = joblib.load(filepath)
                print(f"[✓] Loaded {name} from {filepath}")


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("Anomaly Detection Engine - Module 2")
    print("=" * 60)
    
    # Initialize engine
    engine = AnomalyDetectionEngine()
    
    print("\n[INFO] Multi-Model Detection Engine Initialized")
    print("\nAvailable models:")
    print("  1. Isolation Forest (unsupervised)")
    print("  2. Random Forest (supervised)")
    print("  3. Deep Neural Network (supervised)")
    
    print("\n[INFO] Usage example:")
    print("  # Train models")
    print("  engine.train_isolation_forest(X_train)")
    print("  engine.train_random_forest(X_train, y_train)")
    print("  engine.train_deep_neural_network(X_train, y_train)")
    print("\n  # Evaluate")
    print("  results = engine.evaluate_model(X_test, y_test, 'random_forest')")
    print("\n  # Detect and prepare for explanation")
    print("  info = engine.detect_and_explain(X_sample, feature_names)")
    
    print("\n" + "=" * 60)