# predict_with_attack_label_and_severity.py
import pandas as pd
import joblib
import numpy as np

# ---------------- Load model and preprocessors ----------------
xgb_model = joblib.load("xgb_model.pkl")
scaler = joblib.load("scaler.pkl")
selected_features = joblib.load("selected_features.pkl")

# ---------------- Load extracted features ----------------
df = pd.read_csv("extracted_features.csv")

# Drop identifiers (not used for prediction)
drop_cols = [col for col in ["src_ip", "dst_ip"] if col in df.columns]
df = df.drop(columns=drop_cols, errors='ignore')

# Ensure all selected features exist
for feat in selected_features:
    if feat not in df.columns:
        df[feat] = 0

# Align feature order with training
df_scaled = scaler.transform(df[selected_features])

# ---------------- Predict Attack vs Normal ----------------
predictions = xgb_model.predict(df_scaled)
df["prediction"] = predictions

# Add readable label
df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})

# ---------------- Compute Attack Severity ----------------
# Normalize key continuous metrics
for col in ["byte_count", "packet_count", "duration", "payload_entropy"]:
    if col in df.columns:
        col_min, col_max = df[col].min(), df[col].max()
        df[f"{col}_norm"] = (df[col] - col_min) / (col_max - col_min + 1e-9)

# Weighted severity formula (tunable)
df["severity_percent"] = (
    0.4 * df.get("byte_count_norm", 0) +
    0.3 * df.get("packet_count_norm", 0) +
    0.2 * df.get("duration_norm", 0) +
    0.1 * df.get("payload_entropy_norm", 0)
) * 100

# Only attacks get severity > 0
df["severity_percent"] = np.where(df["prediction"] == 1, df["severity_percent"].round(2), 0)

# ---------------- Save & Summary ----------------
df.to_csv("predicted_flows_with_severity.csv", index=False)

print("Predictions with severity saved to predicted_flows_with_severity.csv\n")
print("--- Prediction Summary ---")
print(df["label"].value_counts())
print("\nAverage attack severity: %.2f%%" % df.loc[df["label"] == "Attack", "severity_percent"].mean())