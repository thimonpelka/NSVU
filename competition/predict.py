import ipaddress
import pickle

import numpy as np
import pandas as pd


def is_private_ip(ip_str):
    """Check if IP is in private range"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def load_and_preprocess_data(file_path):
    """Load and preprocess the network flow data with advanced features"""
    print("Loading data...")
    df = pd.read_csv(file_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")

    if "Attack_Type_enc" in df.columns:
        print(
            f"Attack types distribution:\n{
                df['Attack_Type_enc'].value_counts()}"
        )

    # === TIME-BASED FEATURES ===
    df["flowStartTime"] = pd.to_datetime(df["flowStartMilliseconds"], unit="ms")
    if "flowEndMilliseconds" in df.columns:
        df["flowEndTime"] = pd.to_datetime(df["flowEndMilliseconds"], unit="ms")
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
    df["src_ip_first_octet"] = df["sourceIPAddress"].str.split(".").str[0].astype(int)
    df["src_ip_second_octet"] = df["sourceIPAddress"].str.split(".").str[1].astype(int)
    df["src_ip_third_octet"] = df["sourceIPAddress"].str.split(".").str[2].astype(int)
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
    df["cross_network"] = (df["src_is_private"] != df["dst_is_private"]).astype(int)

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
    df["src_is_common_port"] = df["sourceTransportPort"].isin(common_ports).astype(int)
    df["dst_is_common_port"] = (
        df["destinationTransportPort"].isin(common_ports).astype(int)
    )

    # High ports (ephemeral)
    df["src_is_high_port"] = (df["sourceTransportPort"] > 1024).astype(int)
    df["dst_is_high_port"] = (df["destinationTransportPort"] > 1024).astype(int)

    # Port ranges for different services
    df["dst_is_web_port"] = (
        df["destinationTransportPort"].isin([80, 443, 8080, 8443]).astype(int)
    )
    df["dst_is_db_port"] = (
        df["destinationTransportPort"].isin([1433, 3306, 5432, 1521]).astype(int)
    )
    df["dst_is_file_port"] = (
        df["destinationTransportPort"].isin([21, 22, 445, 139]).astype(int)
    )

    df["port_diff"] = abs(df["sourceTransportPort"] - df["destinationTransportPort"])

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

    # === AGGREGATED FEATURES ===
    print("Creating aggregated features...")

    # For C1 (DDoS): Count connections per source IP
    src_counts = df.groupby("sourceIPAddress").size().rename("src_connection_count")
    df = df.merge(src_counts.to_frame(), left_on="sourceIPAddress", right_index=True)

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

    # Only include features that exist in the dataframe
    available_features = select_features_for_training(df)

    # Handle any missing values
    X_test = df[available_features].fillna(0)

    print(f"Final feature matrix shape: {X_test.shape}")

    return X_test, df


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


def predict(
    file_path="test.csv",
    model_path="enhanced_threat_detection_model.pkl",
    output_path="output.csv",
):
    print("Loading test data...")
    df = pd.read_csv(file_path)
    print(f"Loaded {len(df)} rows")

    print("Loading trained model...")
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    print("Preprocessing test data...")
    X_test, original_df = load_and_preprocess_data(df)

    print("Making predictions...")
    predictions = model.predict(X_test)
    prediction_probabilities = model.predict_proba(X_test)

    # Add predictions to original dataframe
    original_df["prediction"] = predictions

    # Add prediction probabilities (confidence scores)
    prob_columns = [f"prob_class_{i}" for i in range(prediction_probabilities.shape[1])]
    prob_df = pd.DataFrame(prediction_probabilities, columns=prob_columns)
    original_df = pd.concat([original_df, prob_df], axis=1)

    # Add max probability (confidence)
    original_df["confidence"] = prediction_probabilities.max(axis=1)

    print(f"Prediction distribution:")
    print(original_df["prediction"].value_counts())

    print(f"Saving predictions to {output_path}...")
    original_df.to_csv(output_path, index=False)

    print("Prediction completed successfully!")

    # Summary statistics
    print(f"\nPrediction Summary:")
    print(f"Total flows analyzed: {len(original_df)}")
    print(
        f"Unique threat types detected: {
            original_df['prediction'].nunique()}"
    )
    print(f"Average confidence: {original_df['confidence'].mean():.3f}")
    print(
        f"Low confidence predictions (< 0.5): {
            (original_df['confidence'] < 0.5).sum()}"
    )


if __name__ == "__main__":
    predict()
