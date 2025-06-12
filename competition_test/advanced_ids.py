#!/usr/bin/env python3
"""
Advanced Network Intrusion Detection System
NetSec Lab Competition - SomSem 2025

Features:
- Advanced feature engineering for network flows
- Multiple ML models with hyperparameter optimization
- Custom scoring function matching competition requirements
- Ensemble methods and stacking
- Real-time flow processing from PCAP files
"""

import pandas as pd
import numpy as np
import pickle
import json
import subprocess
import sys
import time
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Any

# ML and preprocessing
from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV, cross_val_score
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, make_scorer
from sklearn.utils.class_weight import compute_class_weight
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer

# Advanced ML
import xgboost as xgb
from sklearn.ensemble import StackingClassifier
from sklearn.model_selection import cross_validate
from sklearn.base import BaseEstimator, TransformerMixin

# Feature engineering
from scipy import stats
from scipy.stats import entropy
import ipaddress

warnings.filterwarnings("ignore")


class NetworkFlowFeatureExtractor(BaseEstimator, TransformerMixin):
    """Advanced feature extractor for network flows"""

    def __init__(self):
        self.feature_names = []
        self.ip_encoder = {}
        self.port_encoder = {}

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        """Transform raw flow data into advanced features"""
        features = []

        for _, row in X.iterrows():
            flow_features = self._extract_flow_features(row)
            features.append(flow_features)

        return np.array(features)

    def _extract_flow_features(self, flow) -> List[float]:
        """Extract comprehensive features from a single flow"""
        features = []

        # Basic flow statistics
        features.extend(self._basic_flow_stats(flow))

        # Temporal features
        features.extend(self._temporal_features(flow))

        # Protocol and port features
        features.extend(self._protocol_port_features(flow))

        # IP address features
        features.extend(self._ip_address_features(flow))

        # Statistical features
        features.extend(self._statistical_features(flow))

        # Behavioral features
        features.extend(self._behavioral_features(flow))

        return features

    def _basic_flow_stats(self, flow) -> List[float]:
        """Basic flow statistics"""
        return [
            flow.get("totalPackets", 0),
            flow.get("totalBytes", 0),
            flow.get("flowDuration", 0),
            flow.get("forwardPackets", 0),
            flow.get("backwardPackets", 0),
            flow.get("forwardBytes", 0),
            flow.get("backwardBytes", 0),
            # Ratios
            flow.get("forwardBytes", 0) / max(flow.get("totalBytes", 1), 1),
            flow.get("forwardPackets", 0) /
            max(flow.get("totalPackets", 1), 1),
        ]

    def _temporal_features(self, flow) -> List[float]:
        """Temporal and timing features"""
        return [
            flow.get("flowDuration", 0),
            flow.get("avgPacketSize", 0),
            flow.get("packetLengthVariance", 0),
            flow.get("avgInterArrivalTime", 0),
            flow.get("interArrivalTimeStd", 0),
            # Flow rate features
            flow.get("totalPackets", 0) / max(flow.get("flowDuration", 1), 1),
            flow.get("totalBytes", 0) / max(flow.get("flowDuration", 1), 1),
        ]

    def _protocol_port_features(self, flow) -> List[float]:
        """Protocol and port-based features"""
        src_port = flow.get("sourceTransportPort", 0)
        dst_port = flow.get("destinationTransportPort", 0)

        return [
            src_port,
            dst_port,
            1 if src_port < 1024 else 0,  # Well-known source port
            1 if dst_port < 1024 else 0,  # Well-known dest port
            1 if src_port == dst_port else 0,  # Same port
            abs(src_port - dst_port),  # Port difference
            # Common service ports
            1 if dst_port in [21, 22, 23, 25, 53,
                              80, 110, 143, 443, 993, 995] else 0,
            # High ports
            1 if src_port > 32768 else 0,
            1 if dst_port > 32768 else 0,
        ]

    def _ip_address_features(self, flow) -> List[float]:
        """IP address-based features"""
        try:
            src_ip = ipaddress.ip_address(
                flow.get("sourceIPAddress", "0.0.0.0"))
            dst_ip = ipaddress.ip_address(
                flow.get("destinationIPAddress", "0.0.0.0"))

            return [
                1 if src_ip.is_private else 0,
                1 if dst_ip.is_private else 0,
                1 if src_ip.is_loopback else 0,
                1 if dst_ip.is_loopback else 0,
                1 if src_ip.is_multicast else 0,
                1 if dst_ip.is_multicast else 0,
                # IP similarity (same subnet)
                1 if str(src_ip).split(".")[0] == str(
                    dst_ip).split(".")[0] else 0,
            ]
        except:
            return [0] * 7

    def _statistical_features(self, flow) -> List[float]:
        """Statistical features from packet data"""
        packet_lengths = flow.get("packetLengths", [])
        if not packet_lengths:
            return [0] * 8

        packet_lengths = np.array(packet_lengths)

        return [
            np.mean(packet_lengths),
            np.std(packet_lengths),
            np.min(packet_lengths),
            np.max(packet_lengths),
            np.median(packet_lengths),
            stats.skew(packet_lengths),
            stats.kurtosis(packet_lengths),
            entropy(
                np.histogram(packet_lengths, bins=10)[0] + 1
            ),  # Packet size entropy
        ]

    def _behavioral_features(self, flow) -> List[float]:
        """Behavioral and anomaly features"""
        return [
            flow.get("synCount", 0),
            flow.get("ackCount", 0),
            flow.get("finCount", 0),
            flow.get("rstCount", 0),
            flow.get("pushCount", 0),
            flow.get("urgCount", 0),
            # Flag ratios
            flow.get("synCount", 0) / max(flow.get("totalPackets", 1), 1),
            flow.get("ackCount", 0) / max(flow.get("totalPackets", 1), 1),
            # Connection establishment pattern
            1 if flow.get("synCount", 0) > 0 and flow.get(
                "ackCount", 0) > 0 else 0,
            # Unusual patterns
            1 if flow.get("totalPackets", 0) == 1 else 0,  # Single packet flow
            # Long duration flow
            1 if flow.get("flowDuration", 0) > 1000 else 0,
        ]


class CompetitionScorer:
    """Custom scorer matching competition requirements"""

    @staticmethod
    def score(y_true, y_pred):
        """
        Competition scoring:
        - Correct prediction: 0 points
        - False Positive: 3 points
        - Wrong attack class: 1 point
        - False Negative: 40 points
        Lower score is better
        """
        score = 0

        for true_label, pred_label in zip(y_true, y_pred):
            if true_label == pred_label:
                # Correct prediction
                score += 0
            elif true_label == 0 and pred_label != 0:
                # False Positive (normal labeled as attack)
                score += 3
            elif true_label != 0 and pred_label == 0:
                # False Negative (attack labeled as normal)
                score += 40
            elif true_label != 0 and pred_label != 0 and true_label != pred_label:
                # Wrong attack class
                score += 1

        return -score  # Negative because sklearn maximizes scores


class AdvancedIDSModel:
    """Advanced IDS with multiple ML models and optimization"""

    def __init__(self):
        self.feature_extractor = NetworkFlowFeatureExtractor()
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.models = {}
        self.best_model = None
        self.ensemble_model = None

    def prepare_data(self, df):
        """Prepare and engineer features from raw flow data"""
        print("Engineering features...")

        # Extract advanced features
        X = self.feature_extractor.fit_transform(df)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled

    def optimize_hyperparameters(self, X, y):
        """Hyperparameter optimization for multiple models"""
        print("Optimizing hyperparameters...")

        # Custom scorer
        custom_scorer = make_scorer(
            CompetitionScorer.score, greater_is_better=True)

        # Model configurations
        models_config = {
            "random_forest": {
                "model": RandomForestClassifier(random_state=42, n_jobs=-1),
                "params": {
                    "n_estimators": [100, 200, 300],
                    "max_depth": [10, 15, 20, None],
                    "min_samples_split": [2, 5, 10],
                    "min_samples_leaf": [1, 2, 4],
                    "class_weight": ["balanced", "balanced_subsample"],
                },
            },
            "xgboost": {
                "model": xgb.XGBClassifier(random_state=42, n_jobs=-1),
                "params": {
                    "n_estimators": [100, 200, 300],
                    "max_depth": [6, 8, 10],
                    "learning_rate": [0.01, 0.1, 0.2],
                    "subsample": [0.8, 0.9, 1.0],
                    "colsample_bytree": [0.8, 0.9, 1.0],
                    "scale_pos_weight": [1, 3, 5, 10],
                },
            },
            "gradient_boosting": {
                "model": GradientBoostingClassifier(random_state=42),
                "params": {
                    "n_estimators": [100, 200],
                    "learning_rate": [0.05, 0.1, 0.15],
                    "max_depth": [5, 7, 9],
                    "subsample": [0.8, 0.9, 1.0],
                },
            },
            "neural_network": {
                "model": MLPClassifier(random_state=42, max_iter=1000),
                "params": {
                    "hidden_layer_sizes": [(100,), (100, 50), (200, 100)],
                    "alpha": [0.0001, 0.001, 0.01],
                    "learning_rate": ["constant", "adaptive"],
                    "activation": ["relu", "tanh"],
                },
            },
        }

        # Optimize each model
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        for name, config in models_config.items():
            print(f"Optimizing {name}...")

            search = RandomizedSearchCV(
                config["model"],
                config["params"],
                n_iter=20,  # Reduced for speed
                cv=cv,
                scoring=custom_scorer,
                n_jobs=-1,
                random_state=42,
                verbose=0,
            )

            search.fit(X, y)
            self.models[name] = search.best_estimator_
            print(f"{name} best score: {search.best_score_:.4f}")

        return self.models

    def create_ensemble(self, X, y):
        """Create ensemble model with stacking"""
        print("Creating ensemble model...")

        # Base models for stacking
        base_models = [
            ("rf", self.models["random_forest"]),
            ("xgb", self.models["xgboost"]),
            ("gb", self.models["gradient_boosting"]),
        ]

        # Meta-learner
        meta_learner = LogisticRegression(
            class_weight="balanced", random_state=42)

        # Stacking classifier
        self.ensemble_model = StackingClassifier(
            estimators=base_models, final_estimator=meta_learner, cv=3, n_jobs=-1
        )

        self.ensemble_model.fit(X, y)

        # Also create a voting classifier as backup
        voting_model = VotingClassifier(
            estimators=base_models, voting="soft", n_jobs=-1
        )
        voting_model.fit(X, y)

        # Compare ensemble methods
        custom_scorer = make_scorer(
            CompetitionScorer.score, greater_is_better=True)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

        stacking_score = cross_val_score(
            self.ensemble_model, X, y, cv=cv, scoring=custom_scorer
        ).mean()
        voting_score = cross_val_score(
            voting_model, X, y, cv=cv, scoring=custom_scorer
        ).mean()

        print(f"Stacking score: {stacking_score:.4f}")
        print(f"Voting score: {voting_score:.4f}")

        # Choose best ensemble method
        if stacking_score >= voting_score:
            self.best_model = self.ensemble_model
            print("Selected: Stacking Classifier")
        else:
            self.best_model = voting_model
            print("Selected: Voting Classifier")

    def train(self, training_data_path):
        """Complete training pipeline"""
        print("Loading training data...")

        # Load training data
        df = pd.read_csv(training_data_path)

        # Prepare features
        X = self.prepare_data(df)

        # Encode labels
        y = self.label_encoder.fit_transform(df["Attack_Type_enc"])

        print(f"Training data shape: {X.shape}")
        print(f"Class distribution: {np.bincount(y)}")

        # Optimize individual models
        self.optimize_hyperparameters(X, y)

        # Create ensemble
        self.create_ensemble(X, y)

        # Final evaluation
        self.evaluate_model(X, y)

        return self.best_model

    def evaluate_model(self, X, y):
        """Comprehensive model evaluation"""
        print("\n=== Model Evaluation ===")

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        custom_scorer = make_scorer(
            CompetitionScorer.score, greater_is_better=True)

        # Cross-validation scores
        cv_scores = cross_val_score(
            self.best_model, X, y, cv=cv, scoring=custom_scorer)
        print(
            f"CV Score (competition metric): {
                cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})"
        )

        # Detailed classification report
        y_pred = cross_val_predict(self.best_model, X, y, cv=cv)
        print("\nClassification Report:")
        print(
            classification_report(
                y, y_pred, target_names=self.label_encoder.classes_)
        )

        # Competition score breakdown
        comp_score = -CompetitionScorer.score(y, y_pred)
        print(f"Total Competition Score: {comp_score}")

    def predict(self, flow_data):
        """Make predictions on new flow data"""
        X = self.feature_extractor.transform(flow_data)
        X_scaled = self.scaler.transform(X)

        predictions = self.best_model.predict(X_scaled)
        predictions_labels = self.label_encoder.inverse_transform(predictions)

        return predictions_labels

    def save_model(self, path):
        """Save trained model and preprocessing components"""
        model_data = {
            "feature_extractor": self.feature_extractor,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "best_model": self.best_model,
        }

        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {path}")

    def load_model(self, path):
        """Load trained model and preprocessing components"""
        with open(path, "rb") as f:
            model_data = pickle.load(f)

        self.feature_extractor = model_data["feature_extractor"]
        self.scaler = model_data["scaler"]
        self.label_encoder = model_data["label_encoder"]
        self.best_model = model_data["best_model"]
        print(f"Model loaded from {path}")


def extract_flows_from_pcap(pcap_file, config_file="4tuple_bidi.json"):
    """Extract flows from PCAP using Go-Flows"""
    print(f"Extracting flows from {pcap_file}...")

    output_file = "extracted_flows.csv"

    try:
        # Run Go-Flows
        cmd = [
            "go-flows",
            "-pcap",
            pcap_file,
            "-config",
            config_file,
            "-output",
            output_file,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            print(f"Go-Flows error: {result.stderr}")
            return None

        # Load extracted flows
        df = pd.read_csv(output_file)
        print(f"Extracted {len(df)} flows")
        return df

    except subprocess.TimeoutExpired:
        print("Flow extraction timed out")
        return None
    except Exception as e:
        print(f"Error extracting flows: {e}")
        return None


def create_goflows_config():
    """Create Go-Flows configuration file matching competition requirements"""
    config = {
        "flows": {
            "features": [
                "sourceIPAddress",
                "destinationIPAddress",
                "sourceTransportPort",
                "destinationTransportPort",
                "flowStartMilliseconds",
                "flowEndMilliseconds",
                "totalPackets",
                "totalBytes",
                "forwardPackets",
                "backwardPackets",
                "forwardBytes",
                "backwardBytes",
                "flowDuration",
                "avgPacketSize",
                "packetLengthVariance",
                "avgInterArrivalTime",
                "interArrivalTimeStd",
                "synCount",
                "ackCount",
                "finCount",
                "rstCount",
                "pushCount",
                "urgCount",
            ],
            "active_timeout": 1000,
            "idle_timeout": 1000,
            "bidirectional": True,
            "key_features": [
                "sourceIPAddress",
                "destinationIPAddress",
                "sourceTransportPort",
                "destinationTransportPort",
            ],
        }
    }

    with open("4tuple_bidi.json", "w") as f:
        json.dump(config, f, indent=2)


def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_ids.py <command> [args]")
        print("Commands:")
        print("  train <training_csv>  - Train the model")
        print("  predict <pcap_file>   - Predict on new PCAP file")
        sys.exit(1)

    command = sys.argv[1]

    if command == "train":
        if len(sys.argv) != 3:
            print("Usage: python3 advanced_ids.py train <training_csv>")
            sys.exit(1)

        training_file = sys.argv[2]

        # Create and train model
        ids = AdvancedIDSModel()
        ids.train(training_file)
        ids.save_model("trained_ids_model.pkl")

    elif command == "predict":
        if len(sys.argv) != 3:
            print("Usage: python3 advanced_ids.py predict <pcap_file>")
            sys.exit(1)

        pcap_file = sys.argv[2]
        start_time = time.time()

        # Create Go-Flows config
        create_goflows_config()

        # Extract flows from PCAP
        flow_data = extract_flows_from_pcap(pcap_file)
        if flow_data is None:
            print("Failed to extract flows")
            sys.exit(1)

        # Load trained model
        ids = AdvancedIDSModel()
        if not Path("trained_ids_model.pkl").exists():
            print("No trained model found. Please train first.")
            sys.exit(1)

        ids.load_model("trained_ids_model.pkl")

        # Make predictions
        predictions = ids.predict(flow_data)

        # Create output DataFrame matching competition format
        output_df = pd.DataFrame(
            {
                "flowStartMilliseconds": flow_data.get("flowStartMilliseconds", 0),
                "sourceIPAddress": flow_data.get("sourceIPAddress", ""),
                "destinationIPAddress": flow_data.get("destinationIPAddress", ""),
                "sourceTransportPort": flow_data.get("sourceTransportPort", 0),
                "destinationTransportPort": flow_data.get(
                    "destinationTransportPort", 0
                ),
                "Binary_Label": [0 if pred == "Normal" else 1 for pred in predictions],
                "Attack_Type_enc": predictions,
                "prediction": predictions,  # Competition requirement
            }
        )

        # Save results
        output_df.to_csv("output.csv", index=False)

        execution_time = time.time() - start_time
        print(f"Prediction completed in {execution_time:.2f} seconds")
        print(f"Results saved to output.csv")
        print(f"Predicted {len(predictions)} flows")
        print(f"Attack distribution: {pd.Series(
            predictions).value_counts().to_dict()}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
