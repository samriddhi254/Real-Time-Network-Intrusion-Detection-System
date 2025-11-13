import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import itertools
import joblib

# ---------------- Load data ----------------
train = pd.read_csv("Train_data.csv")
test = pd.read_csv("Test_data.csv")

def label_encode(df):
    for col in df.columns:
        if df[col].dtype == "object":
            df[col] = LabelEncoder().fit_transform(df[col])
label_encode(train)
label_encode(test)

train.drop(['num_outbound_cmds'], axis=1, inplace=True, errors='ignore')
test.drop(['num_outbound_cmds'], axis=1, inplace=True, errors='ignore')

X_train = train.drop(['class'], axis=1)
Y_train = train['class']

# ---------------- Feature selection ----------------
rfc = RandomForestClassifier()
rfe = RFE(rfc, n_features_to_select=10)
rfe = rfe.fit(X_train, Y_train)
selected_features = [v for i, v in itertools.zip_longest(rfe.get_support(), X_train.columns) if i]

# ---------------- Scale features ----------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train[selected_features])
test_scaled = scaler.transform(test[selected_features])

# ---------------- Train/Test Split ----------------
x_train, x_test, y_train, y_test = train_test_split(X_scaled, Y_train, train_size=0.7, random_state=2)

# ---------------- Train XGBoost ----------------
xgb_model = XGBClassifier(objective="binary:logistic", random_state=42)
xgb_model.fit(x_train, y_train)

print("Train Accuracy:", xgb_model.score(x_train, y_train))
print("Test Accuracy:", xgb_model.score(x_test, y_test))

# ---------------- Save ----------------
joblib.dump(xgb_model, "xgb_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(selected_features, "selected_features.pkl")

print("Model and preprocessors saved successfully!")
