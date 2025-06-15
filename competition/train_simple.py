import ipaddress
import warnings

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectKBest, VarianceThreshold, f_classif
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_recall_curve)
from sklearn.model_selection import (GridSearchCV, StratifiedKFold,
                                     train_test_split)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tqdm.auto import tqdm

warnings.filterwarnings("ignore")


def load_and_preprocess_data(file_path):
    """Load and preprocess the network flow data with advanced features"""
    print("Loading data...")
    df = pd.read_csv(file_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")

    if "Attack_Type_enc" in df.columns:
        print(f"Attack types distribution:\n{
              df['Attack_Type_enc'].value_counts()}")

    # === TIME-BASED FEATURES ===
    df["flowStartTime"] = pd.to_datetime(
        df["flowStartMilliseconds"], unit="ms")
    if "flowEndMilliseconds" in df.columns:
        df["flowEndTime"] = pd.to_datetime(
            df["flowEndMilliseconds"], unit="ms")
        df["flow_duration"] = (
            df["flowEndTime"] - df["flowStartTime"]
        ).dt.total_seconds()
    elif "flowDurationMilliseconds" in df.columns:
        df["flow_duration"] = df["flowDurationMilliseconds"] / 1000.0
    else:
        df["flow_duration"] = 0

    df["hour"] = df["flowStartTime"].dt.hour
    df["minute"] = df["flowStartTime"].dt.minute
    df["day_of_week"] = df["flowStartTime"].dt.dayofweek
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)

    # === IP ADDRESS FEATURES ===
    # Extract octets
    df["src_ip_first_octet"] = df["sourceIPAddress"].str.split(
        ".").str[0].astype(int)
    df["src_ip_second_octet"] = df["sourceIPAddress"].str.split(
        ".").str[1].astype(int)
    df["src_ip_third_octet"] = df["sourceIPAddress"].str.split(
        ".").str[2].astype(int)
    df["dst_ip_first_octet"] = (
        df["destinationIPAddress"].str.split(".").str[0].astype(int)
    )
    df["dst_ip_second_octet"] = (
        df["destinationIPAddress"].str.split(".").str[1].astype(int)
    )
    df["dst_ip_third_octet"] = (
        df["destinationIPAddress"].str.split(".").str[2].astype(int)
    )

    # Network class detection (useful for C2 - horizontal probing)
    df["src_is_private"] = df["sourceIPAddress"].apply(is_private_ip)
    df["dst_is_private"] = df["destinationIPAddress"].apply(is_private_ip)
    df["cross_network"] = (df["src_is_private"] !=
                           df["dst_is_private"]).astype(int)

    # Same subnet detection
    df["same_subnet_24"] = (
        (df["src_ip_first_octet"] == df["dst_ip_first_octet"])
        & (df["src_ip_second_octet"] == df["dst_ip_second_octet"])
        & (df["src_ip_third_octet"] == df["dst_ip_third_octet"])
    ).astype(int)

    # === PORT-BASED FEATURES ===
    # Common service ports
    common_ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        443,
        993,
        995,
        1433,
        3306,
        3389,
        5432,
    ]
    df["src_is_common_port"] = df["sourceTransportPort"].isin(
        common_ports).astype(int)
    df["dst_is_common_port"] = (
        df["destinationTransportPort"].isin(common_ports).astype(int)
    )

    # High ports (ephemeral)
    df["src_is_high_port"] = (df["sourceTransportPort"] > 1024).astype(int)
    df["dst_is_high_port"] = (
        df["destinationTransportPort"] > 1024).astype(int)

    # Port ranges for different services
    df["dst_is_web_port"] = (
        df["destinationTransportPort"].isin([80, 443, 8080, 8443]).astype(int)
    )
    df["dst_is_db_port"] = (
        df["destinationTransportPort"].isin(
            [1433, 3306, 5432, 1521]).astype(int)
    )
    df["dst_is_file_port"] = (
        df["destinationTransportPort"].isin([21, 22, 445, 139]).astype(int)
    )

    df["port_diff"] = abs(df["sourceTransportPort"] -
                          df["destinationTransportPort"])

    # === TRAFFIC VOLUME FEATURES ===
    if "octetTotalCount" in df.columns and "packetTotalCount" in df.columns:
        df["bytes_per_packet"] = df["octetTotalCount"] / df["packetTotalCount"].replace(
            0, 1
        )
        df["packets_per_second"] = df["packetTotalCount"] / df["flow_duration"].replace(
            0, 1
        )
        df["bytes_per_second"] = df["octetTotalCount"] / df["flow_duration"].replace(
            0, 1
        )

        # Log transformations for skewed distributions
        df["log_bytes"] = np.log1p(df["octetTotalCount"])
        df["log_packets"] = np.log1p(df["packetTotalCount"])
        df["log_duration"] = np.log1p(df["flow_duration"])
    else:
        df["bytes_per_packet"] = 0
        df["packets_per_second"] = 0
        df["bytes_per_second"] = 0
        df["log_bytes"] = 0
        df["log_packets"] = 0
        df["log_duration"] = 0

    # === TCP FLAGS FEATURES (for C6 - slow connection attacks) ===
    # Note: tcpControlBits not available, will use other indicators
    # for slow connection detection like long duration + low packet rate
    # Placeholder for when TCP flags become available
    df["tcp_flags_available"] = 0

    # === PACKET SIZE FEATURES (for C5 - amplification attacks) ===
    if "minimumIpTotalLength" in df.columns and "maximumIpTotalLength" in df.columns:
        df["packet_size_range"] = (
            df["maximumIpTotalLength"] - df["minimumIpTotalLength"]
        )
        df["min_packet_size"] = df["minimumIpTotalLength"]
        df["max_packet_size"] = df["maximumIpTotalLength"]
        # Estimate mean packet size
        df["estimated_mean_packet_size"] = (
            df["minimumIpTotalLength"] + df["maximumIpTotalLength"]
        ) / 2
    else:
        df["packet_size_range"] = 0
        df["min_packet_size"] = 0
        df["max_packet_size"] = 0
        df["estimated_mean_packet_size"] = 0

    return df


def is_private_ip(ip_str):
    """Check if IP is in private range"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def create_aggregated_features(df):
    """Create aggregated features for detecting attack patterns"""
    print("Creating aggregated features...")

    # For C1 (DDoS): Count connections per source IP
    src_counts = df.groupby("sourceIPAddress").size().rename(
        "src_connection_count")
    df = df.merge(src_counts.to_frame(),
                  left_on="sourceIPAddress", right_index=True)

    # For C2 (Horizontal probing): Unique destinations per source
    src_dst_counts = (
        df.groupby("sourceIPAddress")["destinationIPAddress"]
        .nunique()
        .rename("unique_dst_per_src")
    )
    df = df.merge(
        src_dst_counts.to_frame(), left_on="sourceIPAddress", right_index=True
    )

    # For C3 (Vertical enumeration): Unique ports per destination
    dst_port_counts = (
        df.groupby("destinationIPAddress")["destinationTransportPort"]
        .nunique()
        .rename("unique_ports_per_dst")
    )
    df = df.merge(
        dst_port_counts.to_frame(), left_on="destinationIPAddress", right_index=True
    )

    # For C6 (Connection saturation): Long duration, low packet rate connections
    df["is_long_connection"] = (
        df["flow_duration"] > df["flow_duration"].quantile(0.95)
    ).astype(int)
    df["is_slow_connection"] = (
        (df["flow_duration"] > 10) & (df["packets_per_second"] < 1)
    ).astype(int)

    return df


def select_features_for_training(df):
    """Select relevant features for training"""
    base_features = [
        "sourceTransportPort",
        "destinationTransportPort",
        "src_ip_first_octet",
        "src_ip_second_octet",
        "src_ip_third_octet",
        "dst_ip_first_octet",
        "dst_ip_second_octet",
        "dst_ip_third_octet",
        "hour",
        "minute",
        "day_of_week",
        "is_weekend",
        "src_is_private",
        "dst_is_private",
        "cross_network",
        "same_subnet_24",
        "src_is_common_port",
        "dst_is_common_port",
        "src_is_high_port",
        "dst_is_high_port",
        "dst_is_web_port",
        "dst_is_db_port",
        "dst_is_file_port",
        "port_diff",
        "flow_duration",
        "bytes_per_packet",
        "packets_per_second",
        "bytes_per_second",
        "log_bytes",
        "log_packets",
        "log_duration",
        "packet_size_range",
        "min_packet_size",
        "max_packet_size",
        "estimated_mean_packet_size",
        "src_connection_count",
        "unique_dst_per_src",
        "unique_ports_per_dst",
        "is_long_connection",
        "is_slow_connection",
    ]

    # Only include features that exist in the dataframe
    available_features = [f for f in base_features if f in df.columns]
    print(f"Selected {len(available_features)} features for training")

    return available_features


def create_custom_class_weights(y):
    """Create custom class weights that heavily penalize false negatives"""
    from sklearn.utils.class_weight import compute_class_weight

    # Get unique classes
    classes = np.unique(y)

    # Calculate balanced weights as baseline
    balanced_weights = compute_class_weight("balanced", classes=classes, y=y)

    # Create custom weights dictionary
    class_weights = {}

    for i, cls in enumerate(classes):
        if cls == "Normal":
            # Lower weight for Normal class to reduce false negatives
            class_weights[cls] = balanced_weights[i] * \
                0.3  # Reduce Normal class weight
        else:
            # Higher weights for attack classes
            class_weights[cls] = (
                balanced_weights[i] * 2.0
            )  # Increase attack class weights

    print(f"Custom class weights: {class_weights}")
    return class_weights


def train_enhanced_model(X_train, y_train):
    """Train model optimized for low false negatives"""
    print("Training enhanced model optimized for low false negatives...")

    # Create custom class weights
    custom_weights = create_custom_class_weights(y_train)

    # Create pipeline with SMOTE for oversampling minority classes
    pipeline = ImbPipeline(
        [
            ("var_thresh", VarianceThreshold(threshold=0.0)),
            ("scaler", StandardScaler()),
            (
                "smote",
                SMOTE(random_state=42, k_neighbors=3),
            ),  # Oversample minority classes
            ("feature_selection", SelectKBest(f_classif, k="all")),
            (
                "clf",
                RandomForestClassifier(
                    random_state=42,
                    class_weight=custom_weights,  # Use custom weights
                    n_jobs=-1,
                    # Parameters optimized for sensitivity
                    n_estimators=300,  # More trees for better detection
                    max_depth=None,  # Allow deeper trees
                    min_samples_split=2,  # Lower threshold for splits
                    min_samples_leaf=1,  # Allow smaller leaves
                    max_features="sqrt",
                ),
            ),
        ]
    )

    # Parameter grid optimized for recall/sensitivity
    param_grid = {
        "feature_selection__k": [20, 25, "all"],
        "clf__n_estimators": [100, 200],
        "clf__max_depth": [10, 20],
        "clf__min_samples_split": [2, 5],
        # "clf__min_samples_leaf": [2, 5],
        "clf__max_features": ["sqrt", "log2"],
    }

    param_grid = {
        "feature_selection__k": [25],
        "clf__n_estimators": [200],
        "clf__max_depth": [20],
        "clf__min_samples_split": [2],
        # "clf__min_samples_leaf": [2, 5],
        "clf__max_features": ["sqrt"],
    }

    # Use StratifiedKFold for cross-validation
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    # Custom scoring function that prioritizes recall
    def custom_scorer(estimator, X, y):
        from sklearn.metrics import fbeta_score

        y_pred = estimator.predict(X)
        # F2 score gives more weight to recall than precision
        return fbeta_score(y, y_pred, beta=2, average="weighted")

    # Create GridSearchCV
    grid_search = GridSearchCV(
        pipeline,
        param_grid,
        cv=cv,
        scoring=custom_scorer,  # Use custom scorer that prioritizes recall
        n_jobs=1,
        verbose=1,
        error_score="raise",
    )

    start_time = pd.Timestamp.now()

    # Fit the model
    grid_search.fit(X_train, y_train)

    end_time = pd.Timestamp.now()

    print(f"Training completed in {end_time - start_time}")
    print(f"Best parameters: {grid_search.best_params_}")
    print(f"Best cross-validation score: {grid_search.best_score_:.4f}")

    return grid_search.best_estimator_


def find_optimal_threshold(model, X_val, y_val):
    """Find optimal threshold to minimize false negatives"""
    print("Finding optimal threshold for prediction...")

    # Get prediction probabilities
    if hasattr(model, "predict_proba"):
        # For multiclass, we need to handle this differently
        y_proba = model.predict_proba(X_val)

        # Convert to binary problem: Normal vs Any Attack
        y_binary = (y_val != "Normal").astype(int)

        # Get probability of "any attack" (1 - prob of Normal)
        if "Normal" in model.classes_:
            normal_idx = list(model.classes_).index("Normal")
            attack_proba = 1 - y_proba[:, normal_idx]
        else:
            attack_proba = np.sum(
                y_proba[:, 1:], axis=1
            )  # Sum all non-normal probabilities

        # Find threshold that maximizes recall while maintaining reasonable precision
        from sklearn.metrics import precision_recall_curve

        precision, recall, thresholds = precision_recall_curve(
            y_binary, attack_proba)

        # Find threshold where recall is at least 0.95 (minimize false negatives)
        high_recall_indices = recall >= 0.95
        if np.any(high_recall_indices):
            # Among high recall thresholds, pick the one with best precision
            best_idx = np.argmax(precision[high_recall_indices])
            optimal_threshold = thresholds[np.where(
                high_recall_indices)[0][best_idx]]
        else:
            # If we can't achieve 95% recall, pick threshold with best F2 score
            f2_scores = (5 * precision * recall) / \
                (4 * precision + recall + 1e-8)
            best_idx = np.argmax(f2_scores)
            optimal_threshold = thresholds[best_idx]

        print(f"Optimal threshold: {optimal_threshold:.4f}")
        print(
            f"At this threshold - Precision: {
                precision[best_idx]:.4f}, Recall: {recall[best_idx]:.4f}"
        )

        return optimal_threshold
    else:
        return 0.5  # Default threshold


class ThresholdClassifier:
    """Wrapper class to apply custom threshold"""

    def __init__(self, model, threshold=0.5):
        self.model = model
        self.threshold = threshold
        self.classes_ = model.classes_

    def predict(self, X):
        if hasattr(self.model, "predict_proba"):
            y_proba = self.model.predict_proba(X)

            # Get probability of "any attack"
            if "Normal" in self.classes_:
                normal_idx = list(self.classes_).index("Normal")
                attack_proba = 1 - y_proba[:, normal_idx]
            else:
                attack_proba = np.sum(y_proba[:, 1:], axis=1)

            # Apply threshold
            predictions = []
            for i, prob in enumerate(attack_proba):
                if prob >= self.threshold:
                    # Predict the most likely attack class (excluding Normal)
                    non_normal_probs = y_proba[i].copy()
                    if "Normal" in self.classes_:
                        non_normal_probs[normal_idx] = 0
                    predicted_class = self.classes_[
                        np.argmax(non_normal_probs)]
                else:
                    predicted_class = "Normal"
                predictions.append(predicted_class)

            return np.array(predictions)
        else:
            return self.model.predict(X)


def evaluate_model_detailed(model, X_test, y_test, feature_names):
    """Comprehensive model evaluation with focus on false negatives"""
    print("Evaluating model...")

    y_pred = model.predict(X_test)

    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, output_dict=True)
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # Calculate false negative rate for each class
    print("\nFalse Negative Analysis:")
    for i, class_name in enumerate(model.classes_):
        if class_name != "Normal":
            # True Positives + False Negatives = All actual instances of this class
            actual_class_mask = y_test == class_name
            if np.sum(actual_class_mask) > 0:
                predicted_class_mask = y_pred == class_name
                true_positives = np.sum(
                    actual_class_mask & predicted_class_mask)
                false_negatives = np.sum(
                    actual_class_mask & ~predicted_class_mask)
                fnr = false_negatives / (true_positives + false_negatives)
                print(
                    f"{class_name}: False Negative Rate = {
                        fnr:.4f} ({false_negatives}/{true_positives + false_negatives})"
                )

    # Overall attack detection rate
    y_test_binary = (y_test != "Normal").astype(int)
    y_pred_binary = (y_pred != "Normal").astype(int)

    from sklearn.metrics import classification_report as cr

    print("\nBinary Classification (Normal vs Attack):")
    print(cr(y_test_binary, y_pred_binary, target_names=["Normal", "Attack"]))

    # Feature importance (if available)
    if hasattr(model.named_steps["clf"], "feature_importances_"):
        # Get the selected feature names after feature selection
        if hasattr(model.named_steps["feature_selection"], "get_support"):
            feature_mask = model.named_steps["feature_selection"].get_support()
            selected_feature_names = [
                feature_names[i] for i in range(len(feature_names)) if feature_mask[i]
            ]
        else:
            selected_feature_names = feature_names

        importances = model.named_steps["clf"].feature_importances_

        feature_importance_df = pd.DataFrame(
            {"feature": selected_feature_names, "importance": importances}
        ).sort_values("importance", ascending=False)

        print("\nTop 10 Most Important Features:")
        print(feature_importance_df.head(10))

    return y_pred


def preprocess_features(df):
    """Preprocess features and handle missing values"""
    # Select features
    feature_columns = select_features_for_training(df)
    X = df[feature_columns].fillna(0)  # Handle any missing values

    # Remove constant features
    constant_filter = VarianceThreshold(threshold=0.0)
    X_filtered = constant_filter.fit_transform(X)

    # Get the names of remaining features
    selected_features = constant_filter.get_support(indices=True)
    remaining_feature_names = [feature_columns[i] for i in selected_features]

    print(f"Features after removing constants: {len(remaining_feature_names)}")

    return X_filtered, remaining_feature_names


if __name__ == "__main__":
    print(
        "Starting enhanced network threat detection (optimized for low false negatives)..."
    )

    # Load and preprocess data
    df = load_and_preprocess_data("merged_train.csv")

    # Create aggregated features
    df = create_aggregated_features(df)

    # Preprocess features
    X, feature_names = preprocess_features(df)

    if "Attack_Type_enc" in df.columns:
        y = df["Attack_Type_enc"]
    else:
        print(
            "Warning: No 'Attack_Type_enc' column found. Creating dummy labels for testing."
        )
        y = np.random.randint(0, 8, size=len(df))  # 8 threat categories

    print(f"Final feature matrix shape: {X.shape}")
    print(f"Target distribution:\n{pd.Series(y).value_counts()}")

    # Split the data - use stratification to maintain class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Further split training data to create validation set for threshold tuning
    X_train_final, X_val, y_train_final, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )

    # Train model
    best_model = train_enhanced_model(X_train_final, y_train_final)

    # Find optimal threshold using validation set
    optimal_threshold = find_optimal_threshold(best_model, X_val, y_val)

    # Create threshold-optimized classifier
    threshold_model = ThresholdClassifier(best_model, optimal_threshold)

    # Evaluate both models
    print("\n" + "=" * 50)
    print("EVALUATION WITH DEFAULT THRESHOLD:")
    print("=" * 50)
    y_pred_default = evaluate_model_detailed(
        best_model, X_test, y_test, feature_names)

    # print("\n" + "=" * 50)
    # print("EVALUATION WITH OPTIMIZED THRESHOLD:")
    # print("=" * 50)
    # y_pred_optimized = evaluate_model_detailed(
    #     threshold_model, X_test, y_test, feature_names
    # )

    # Save model
    import pickle

    # Save both models and metadata
    model_data = {
        "model": best_model,
        "threshold_model": threshold_model,
        "feature_names": feature_names,
        "optimal_threshold": optimal_threshold,
    }

    with open("enhanced_threat_detection_model_low_fn.pkl", "wb") as f:
        pickle.dump(model_data, f)

    print(f"\nModels saved as 'enhanced_threat_detection_model_low_fn.pkl'")
    print("Enhanced threat detection training completed!")
    print(f"Use optimal threshold: {optimal_threshold:.4f} for deployment")
