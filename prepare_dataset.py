
from datasets import load_dataset
import pandas as pd
from pathlib import Path

print("Loading phishing email dataset...")

dataset = load_dataset(
    "ansulev/phishing-email-dataset",
    split="train",
    download_mode="reuse_dataset_if_exists",
)

df = dataset.to_pandas()

# Keep only the columns needed for training.
df = df[["Email Text", "Email Type"]].copy()

# Give the columns simpler names.
df.columns = ["email_text", "label"]

# Remove missing and empty emails.
df = df.dropna(subset=["email_text", "label"])
df["email_text"] = df["email_text"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip()
df = df[df["email_text"] != ""]

# Remove rows with labels we do not expect.
valid_labels = {"Phishing Email", "Safe Email"}
df = df[df["label"].isin(valid_labels)].copy()

# Normalize text for duplicate detection.
# This ignores capitalization and differences in whitespace.
df["_normalized_email"] = (
    df["email_text"]
    .str.lower()
    .str.split()
    .str.join(" ")
)

# Keep the first copy of each normalized email.
before_deduplication = len(df)
df = df.drop_duplicates(subset=["_normalized_email"]).copy()
removed_duplicates = before_deduplication - len(df)

# Remove the temporary comparison column.
df = df.drop(columns=["_normalized_email"])

# Create the output directory if needed.
output_dir = Path("data/processed")
output_dir.mkdir(parents=True, exist_ok=True)

output_file = output_dir / "emails.csv"
df.to_csv(output_file, index=False)

print("\nDataset preparation complete!")
print("Rows after cleaning:", len(df))
print("Duplicate rows removed:", removed_duplicates)
print("\nLabel distribution:")
print(df["label"].value_counts())
print("\nSaved to:", output_file)

