import ipaddress
import warnings
import pickle
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm.auto import tqdm

warnings.filterwarnings("ignore")

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

def is_private_ip(ip_str):
    """Check if IP is in private range"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def load_and_preprocess_data(file_path):
    """Load and preprocess the network flow data with advanced features"""
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")

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
    return available_features


def preprocess_features_for_inference(df, model_feature_names):
    """Preprocess features for inference using the same features as training"""
    # Select the same features that were used during training
    available_features = select_features_for_training(df)

    # Create a dataframe with all required features, filling missing ones with 0
    X = pd.DataFrame(index=df.index)

    for feature in model_feature_names:
        if feature in available_features:
            X[feature] = df[feature].fillna(0)
        else:
            print(f"Warning: Feature '{
                  feature}' not found in data, filling with 0")
            X[feature] = 0

    # Return in the same order as training
    return X[model_feature_names].values


def load_model(model_path):
    """Load the trained model and feature names"""
    print(f"Loading model from {model_path}...")

    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)

    # Handle both old and new model formats
    if isinstance(model_data, dict) and 'model' in model_data:
        model = model_data['model']
        feature_names = model_data.get('feature_names', None)
    else:
        # Old format - just the model
        model = model_data
        feature_names = None
        print("Warning: Model file doesn't contain feature names. This may cause issues.")

    print("Model loaded successfully!")
    return model, feature_names


def predict_batch(model, X, batch_size=10000):
    """Make predictions in batches to handle large datasets"""
    n_samples = X.shape[0]
    predictions = []

    print(f"Making predictions for {n_samples} samples...")

    # Process in batches with progress bar
    for i in tqdm(range(0, n_samples, batch_size), desc="Predicting", unit="batch"):
        end_idx = min(i + batch_size, n_samples)
        batch_X = X[i:end_idx]
        batch_pred = model.predict(batch_X)
        predictions.extend(batch_pred)

    return np.array(predictions)


def main():
    parser = argparse.ArgumentParser(
        description='Apply trained model to new data')
    parser.add_argument('--model', '-m', required=True,
                        help='Path to the trained model file (.pkl)')
    parser.add_argument('--input', '-i', required=True,
                        help='Path to the input CSV file')
    parser.add_argument('--output', '-o', required=True,
                        help='Path to the output CSV file')
    parser.add_argument('--batch-size', '-b', type=int, default=10000,
                        help='Batch size for prediction (default: 10000)')

    args = parser.parse_args()

    # Check if files exist
    if not Path(args.model).exists():
        print(f"Error: Model file '{args.model}' not found!")
        sys.exit(1)

    if not Path(args.input).exists():
        print(f"Error: Input file '{args.input}' not found!")
        sys.exit(1)

    try:
        # Load the trained model
        model, feature_names = load_model(args.model)

        # Load and preprocess the new data
        df = load_and_preprocess_data(args.input)
        df = create_aggregated_features(df)

        # Prepare features for inference
        if feature_names is not None:
            X = preprocess_features_for_inference(df, feature_names)
            print(f"Prepared feature matrix shape: {X.shape}")
        else:
            print("Error: Cannot determine feature names from model file.")
            print(
                "Please ensure you're using a model saved with the updated training script.")
            sys.exit(1)

        # Make predictions
        predictions = predict_batch(model, X, args.batch_size)

        # Add predictions to the original dataframe
        df_output = df.copy()
        df_output['prediction'] = predictions

        # Save the results
        print(f"Saving results to {args.output}...")
        df_output.to_csv(args.output, index=False)

        # Print summary
        print(f"\nPrediction Summary:")
        print(f"Total samples: {len(predictions)}")
        print(f"Prediction distribution:")
        prediction_counts = pd.Series(predictions).value_counts().sort_index()
        for pred, count in prediction_counts.items():
            percentage = (count / len(predictions)) * 100
            print(f"  Class {pred}: {count} samples ({percentage:.2f}%)")

        print(f"\nResults saved to: {args.output}")
        print("Inference completed successfully!")

    except Exception as e:
        print(f"Error during inference: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
