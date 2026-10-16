
from datasets import load_dataset

dataset = load_dataset(
    "ansulev/phishing-email-dataset",
    split="train",
)

print("Dataset loaded successfully!")
print("Number of rows:", len(dataset))
print("Columns:", dataset.column_names)
print("\nFirst example:")
print(dataset[0])

print("\nLabel distribution:")
from collections import Counter

print(Counter(dataset["Email Type"]))

