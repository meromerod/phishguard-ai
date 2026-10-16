
import joblib

model = joblib.load("models/phishing_classifier.joblib")

emails = [
    """
    Subject: Urgent action required

    Your account has been suspended.
    Verify your account and confirm your password immediately:
    http://secure-account.example/login
    """,
    """
    Subject: Meeting notes

    Hi team,

    Please find the meeting notes attached.
    Our next project review is scheduled for Thursday.

    Regards,
    Alex
    """,
]

for number, email in enumerate(emails, start=1):
    prediction = model.predict([email])[0]
    probabilities = model.predict_proba([email])[0]
    classes = model.classes_

    phishing_index = list(classes).index("Phishing Email")
    phishing_probability = probabilities[phishing_index]

    print(f"\nEmail {number}")
    print("Prediction:", prediction)
    print(f"Phishing probability: {phishing_probability:.2%}")
