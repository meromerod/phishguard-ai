
from pathlib import Path

import joblib


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "phishing_classifier.joblib"
)


def predict_email(email_text: str) -> dict:
    """Predict phishing risk and explain influential text features."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run python train_model.py first."
        )

    model = joblib.load(MODEL_PATH)

    prediction = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]

    classes = list(model.classes_)
    phishing_index = classes.index("Phishing Email")
    phishing_probability = float(probabilities[phishing_index])

    # Get the TF-IDF values for this email.
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]

    vector = vectorizer.transform([email_text])
    feature_names = vectorizer.get_feature_names_out()

    # Logistic Regression's single coefficient row describes
    # class 1 relative to class 0.
    # Here, class 0 is "Phishing Email" and class 1 is "Safe Email".
    weights = classifier.coef_[0]
    contributions = vector.toarray()[0] * weights

    # Negative contributions favor phishing; positive favor safe.
    phishing_terms = []
    safe_terms = []

    for index, contribution in enumerate(contributions):
        if contribution < 0:
            phishing_terms.append({
                "term": feature_names[index],
                "contribution": round(float(-contribution), 4),
            })
        elif contribution > 0:
            safe_terms.append({
                "term": feature_names[index],
                "contribution": round(float(contribution), 4),
            })

    phishing_terms.sort(
        key=lambda item: item["contribution"],
        reverse=True,
    )
    safe_terms.sort(
        key=lambda item: item["contribution"],
        reverse=True,
    )

    return {
        "prediction": prediction,
        "phishing_probability": round(phishing_probability, 4),
        "phishing_terms": phishing_terms[:5],
        "safe_terms": safe_terms[:5],
    }
