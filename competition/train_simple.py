import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def load_and_preprocess_data(file_path):
    """Load and preprocess the network flow data"""
    print("Loading data...")
    df = pd.read_csv(file_path)

    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    print(
        f"Attack types distribution:\n{
            df['Attack_Type_enc'].value_counts()}"
    )

    # Create additional features from IP addresses
    df["src_ip_first_octet"] = df["sourceIPAddress"].str.split(".").str[0].astype(int)
    df["src_ip_second_octet"] = df["sourceIPAddress"].str.split(".").str[1].astype(int)
    df["dst_ip_first_octet"] = (
        df["destinationIPAddress"].str.split(".").str[0].astype(int)
    )
    df["dst_ip_second_octet"] = (
        df["destinationIPAddress"].str.split(".").str[1].astype(int)
    )

    # Create time-based features
    df["hour"] = pd.to_datetime(df["flowStartMilliseconds"], unit="ms").dt.hour
    df["minute"] = pd.to_datetime(df["flowStartMilliseconds"], unit="ms").dt.minute

    # Port-based features
    df["is_common_src_port"] = (
        df["sourceTransportPort"].isin([80, 443, 22, 21, 25, 53, 110, 143]).astype(int)
    )
    df["is_common_dst_port"] = (
        df["destinationTransportPort"]
        .isin([80, 443, 22, 21, 25, 53, 110, 143])
        .astype(int)
    )
    df["port_diff"] = abs(df["sourceTransportPort"] - df["destinationTransportPort"])

    # Select features for training
    feature_columns = [
        "sourceTransportPort",
        "destinationTransportPort",
        # "Binary_Label",
        "src_ip_first_octet",
        "src_ip_second_octet",
        "dst_ip_first_octet",
        "dst_ip_second_octet",
        "hour",
        "minute",
        "is_common_src_port",
        "is_common_dst_port",
        "port_diff",
    ]

    X = df[feature_columns]
    y = df["Attack_Type_enc"]

    return X, y, df


def train_model():
    # === Build Pipeline ===
    pipeline = Pipeline(
        [("scaler", StandardScaler()), ("clf", RandomForestClassifier(random_state=42))]
    )

    # === Hyperparameter Grid ===
    param_grid = {
        "clf__n_estimators": [50, 100],
        "clf__max_depth": [None, 10, 20],
        "clf__min_samples_split": [2, 5],
    }

    start_time = pd.Timestamp.now()

    # === Grid Search ===
    grid_search = GridSearchCV(
        pipeline, param_grid, cv=3, scoring="accuracy", verbose=1
    )
    grid_search.fit(X_train, y_train)

    end_time = pd.Timestamp.now()
    print(f"Training completed in {end_time - start_time}")

    return grid_search.best_estimator_


if __name__ == "__main__":
    # === Load and Preprocess Data ===
    print("Starting data loading and preprocessing...")

    # Load and preprocess data
    X, y, df = load_and_preprocess_data("data/flowkeys_training_labeled_enc.csv")

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    best_model = train_model()

    # Evaluation
    print("Test Set Evaluation:")
    y_pred = best_model.predict(X_test)

    with open("best_model.pkl", "wb") as f:
        import pickle
        pickle.dump(best_model, f)

    print(classification_report(y_test, y_pred))
