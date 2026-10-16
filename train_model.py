
import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# Load the cleaned dataset.
df = pd.read_csv("data/processed/emails.csv")

X = df["email_text"]
y = df["label"]

# Reserve 20% of the data for testing.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

# Convert email text into numerical features and train a classifier.
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        max_features=50000,
        ngram_range=(1, 2),
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
    )),
])

print("Training model...")
model.fit(X_train, y_train)

# Evaluate on emails the model has not seen during training.
predictions = model.predict(X_test)

print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
print("\nClassification report:")
print(classification_report(y_test, predictions, zero_division=0))
print("Confusion matrix (label order):")
print(model.named_steps["classifier"].classes_)
print(confusion_matrix(y_test, predictions))

# Save the trained model locally.
output_dir = Path("models")
output_dir.mkdir(exist_ok=True)

model_path = output_dir / "phishing_classifier.joblib"
joblib.dump(model, model_path)

print("\nModel saved to:", model_path)
