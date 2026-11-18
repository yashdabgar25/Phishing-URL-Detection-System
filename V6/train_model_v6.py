import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

# Load updated training data
train_df = pd.read_csv("V6/train_features_v6_new.csv")

X_train = train_df.drop(columns=["label"])
y_train = train_df["label"]

print("Training rows:", len(X_train))
print("Number of features:", len(X_train.columns))

# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\nTraining V6 model...")
model.fit(X_train, y_train)

# Save new model separately
joblib.dump(model, "phishing_model_v6_updated.pkl")
joblib.dump(list(X_train.columns), "feature_names_v6_updated.pkl")

print("\nUpdated model saved successfully!")

# Load updated testing data
test_df = pd.read_csv("V6/test_features_v6_new.csv")

X_test = test_df.drop(columns=["label"])
y_test = test_df["label"]

# Predict
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\n========== V6 UPDATED MODEL EVALUATION ==========")

print("Accuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Phishing", "Legitimate"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nROC-AUC:", roc_auc_score(y_test, y_prob))

print("\nV6 Training and evaluation completed!")