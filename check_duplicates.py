
import pandas as pd

from sklearn.model_selection import train_test_split
from difflib import SequenceMatcher


# Load the cleaned dataset.
df = pd.read_csv("data/processed/emails.csv")

X = df["email_text"].astype(str)
y = df["label"]

# Reproduce the same train/test split.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

# Normalize case and whitespace.
def normalize_email(email):
    return " ".join(email.lower().split())


train_emails = {
    normalize_email(email)
    for email in X_train
}

test_emails = {
    normalize_email(email)
    for email in X_test
}

overlap = train_emails.intersection(test_emails)

print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))
print("Exact normalized overlap:", len(overlap))

# Check a small sample for very similar emails.
# This is a diagnostic sample, not a full dataset-wide audit.
train_sample = list(train_emails)[:500]
test_sample = list(test_emails)[:100]

near_duplicates = []

for test_email in test_sample:
    for train_email in train_sample:
        similarity = SequenceMatcher(
            None,
            test_email,
            train_email,
        ).ratio()

        if similarity >= 0.90 and test_email != train_email:
            near_duplicates.append(
                (round(similarity, 3), test_email, train_email)
            )
            break

print("\nNear-duplicate pairs found in sample:", len(near_duplicates))

for similarity, test_email, train_email in near_duplicates[:5]:
    print("\nSimilarity:", similarity)
    print("TEST :", test_email[:200])
    print("TRAIN:", train_email[:200])
