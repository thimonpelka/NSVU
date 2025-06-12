import ipaddress
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import (GridSearchCV, StratifiedKFold,
                                     train_test_split)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")


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

    # === PROTOCOL FEATURES ===
    if "protocolIdentifier" in df.columns:
        df["is_tcp"] = (df["protocolIdentifier"] == 6).astype(int)
        df["is_udp"] = (df["protocolIdentifier"] == 17).astype(int)
        df["is_icmp"] = (df["protocolIdentifier"] == 1).astype(int)
    else:
        df["is_tcp"] = 1  # assume TCP if not specified
        df["is_udp"] = 0
        df["is_icmp"] = 0

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
    if "tcpControlBits" in df.columns:
        df["tcp_syn"] = ((df["tcpControlBits"] & 0x02) != 0).astype(int)
        df["tcp_ack"] = ((df["tcpControlBits"] & 0x10) != 0).astype(int)
        df["tcp_fin"] = ((df["tcpControlBits"] & 0x01) != 0).astype(int)
        df["tcp_rst"] = ((df["tcpControlBits"] & 0x04) != 0).astype(int)
        df["tcp_psh"] = ((df["tcpControlBits"] & 0x08) != 0).astype(int)
    else:
        df["tcp_syn"] = 0
        df["tcp_ack"] = 0
        df["tcp_fin"] = 0
        df["tcp_rst"] = 0
        df["tcp_psh"] = 0

    # === PACKET SIZE FEATURES (for C5 - amplification attacks) ===
    if "meanIpTotalLength" in df.columns:
        df["mean_packet_size"] = df["meanIpTotalLength"]
        if "standardDeviationIpTotalLength" in df.columns:
            df["packet_size_variance"] = df["standardDeviationIpTotalLength"]
        else:
            df["packet_size_variance"] = 0
    else:
        df["mean_packet_size"] = 0
        df["packet_size_variance"] = 0

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

    # For C6 (Connection saturation): Long duration connections
    df["is_long_connection"] = (
        df["flow_duration"] > df["flow_duration"].quantile(0.95)
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
        "is_tcp",
        "is_udp",
        "is_icmp",
        "flow_duration",
        "bytes_per_packet",
        "packets_per_second",
        "bytes_per_second",
        "log_bytes",
        "log_packets",
        "log_duration",
        "tcp_syn",
        "tcp_ack",
        "tcp_fin",
        "tcp_rst",
        "tcp_psh",
        "mean_packet_size",
        "packet_size_variance",
        "src_connection_count",
        "unique_dst_per_src",
        "unique_ports_per_dst",
        "is_long_connection",
    ]

    # Only include features that exist in the dataframe
    available_features = [f for f in base_features if f in df.columns]
    print(f"Selected {len(available_features)} features for training")

    return available_features


def train_enhanced_model(X_train, y_train):
    """Train model with enhanced pipeline"""
    print("Training enhanced model...")

    # Create pipeline with feature selection
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("feature_selection", SelectKBest(f_classif, k="all")),
            ("clf", RandomForestClassifier(random_state=42, class_weight="balanced")),
        ]
    )

    # Enhanced parameter grid
    param_grid = {
        "feature_selection__k": [15, 20, 25, "all"],
        "clf__n_estimators": [100, 200],
        "clf__max_depth": [10, 20, None],
        "clf__min_samples_split": [2, 5],
        "clf__min_samples_leaf": [1, 2],
        "clf__max_features": ["sqrt", "log2"],
    }

    # Use stratified cross-validation
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    grid_search = GridSearchCV(
        pipeline, param_grid, cv=cv, scoring="f1_macro", verbose=1, n_jobs=-1
    )

    start_time = pd.Timestamp.now()
    grid_search.fit(X_train, y_train)
    end_time = pd.Timestamp.now()

    print(f"Training completed in {end_time - start_time}")
    print(f"Best parameters: {grid_search.best_params_}")
    print(f"Best cross-validation score: {grid_search.best_score_:.4f}")

    return grid_search.best_estimator_


def evaluate_model(model, X_test, y_test):
    """Comprehensive model evaluation"""
    print("Evaluating model...")

    y_pred = model.predict(X_test)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # Feature importance (if available)
    if hasattr(model.named_steps["clf"], "feature_importances_"):
        feature_names = model.named_steps["feature_selection"].get_feature_names_out()
        importances = model.named_steps["clf"].feature_importances_

        feature_importance_df = pd.DataFrame(
            {"feature": feature_names, "importance": importances}
        ).sort_values("importance", ascending=False)

        print("\nTop 10 Most Important Features:")
        print(feature_importance_df.head(10))

    return y_pred


if __name__ == "__main__":
    print("Starting enhanced network threat detection...")

    # Load and preprocess data
    df = load_and_preprocess_data("data/flowkeys_training_labeled_enc.csv")

    # Create aggregated features
    df = create_aggregated_features(df)

    # Select features
    feature_columns = select_features_for_training(df)
    X = df[feature_columns].fillna(0)  # Handle any missing values

    if "Attack_Type_enc" in df.columns:
        y = df["Attack_Type_enc"]
    else:
        print(
            "Warning: No 'Attack_Type_enc' column found. Creating dummy labels for testing."
        )
        y = np.random.randint(0, 8, size=len(df))  # 8 threat categories

    print(f"Final feature matrix shape: {X.shape}")
    print(f"Target distribution:\n{pd.Series(y).value_counts()}")

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    best_model = train_enhanced_model(X_train, y_train)

    # Evaluate model
    y_pred = evaluate_model(best_model, X_test, y_test)

    # Save model
    import pickle

    with open("enhanced_threat_detection_model.pkl", "wb") as f:
        pickle.dump(best_model, f)

    print("\nModel saved as 'enhanced_threat_detection_model.pkl'")
    print("Enhanced threat detection training completed!")
