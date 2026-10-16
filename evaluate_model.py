import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

# Load the same cleaned dataset and saved model.
df = pd.read_csv("data/processed/emails.csv")
model = joblib.load("models/phishing_classifier.joblib")

X = df["email_text"]
y = df["label"]

# Recreate the same test split used during training.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

# Evaluate only on the held-out test set.
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)

classes = list(model.classes_)
phishing_index = classes.index("Phishing Email")
phishing_probabilities = probabilities[:, phishing_index]

print("PHISHGUARD AI — MODEL EVALUATION")
print("=" * 40)
print("Training emails:", len(X_train))
print("Testing emails:", len(X_test))

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    zero_division=0,
))

print("Confusion matrix:")
print("Label order:", classes)
print(confusion_matrix(y_test, predictions, labels=classes))

actual_phishing = (y_test == "Phishing Email").astype(int)

print(
    "\nROC-AUC:",
    round(roc_auc_score(actual_phishing, phishing_probabilities), 4),
)

print("\nEvaluation complete.")
