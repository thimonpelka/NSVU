import pickle

import pandas as pd


def preprocess_test_data(df):
    """Apply the same feature engineering as in the training script."""

    # IP features
    df["src_ip_first_octet"] = df["sourceIPAddress"].str.split(".").str[0].astype(int)
    df["src_ip_second_octet"] = df["sourceIPAddress"].str.split(".").str[1].astype(int)
    df["dst_ip_first_octet"] = (
        df["destinationIPAddress"].str.split(".").str[0].astype(int)
    )
    df["dst_ip_second_octet"] = (
        df["destinationIPAddress"].str.split(".").str[1].astype(int)
    )

    # Time features
    df["hour"] = pd.to_datetime(df["flowStartMilliseconds"], unit="ms").dt.hour
    df["minute"] = pd.to_datetime(df["flowStartMilliseconds"], unit="ms").dt.minute

    # Port features
    df["is_common_src_port"] = (
        df["sourceTransportPort"].isin([80, 443, 22, 21, 25, 53, 110, 143]).astype(int)
    )
    df["is_common_dst_port"] = (
        df["destinationTransportPort"]
        .isin([80, 443, 22, 21, 25, 53, 110, 143])
        .astype(int)
    )
    df["port_diff"] = abs(df["sourceTransportPort"] - df["destinationTransportPort"])

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

    return df[feature_columns], df


def predict(
    file_path="test.csv", model_path="best_model.pkl", output_path="output.csv"
):
    print("Loading test data...")
    df = pd.read_csv(file_path)

    print("Loading trained model...")
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    print("Preprocessing test data...")
    X_test, original_df = preprocess_test_data(df)

    print("Predicting...")
    predictions = model.predict(X_test)
    original_df["prediction"] = predictions

    print(f"Saving predictions to {output_path}...")
    original_df.to_csv(output_path, index=False)
    print("Done.")


if __name__ == "__main__":
    predict()
