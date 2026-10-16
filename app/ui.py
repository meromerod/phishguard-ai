
import streamlit as st

from app.main import analyze_message
from app.ml_detector import predict_email


st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PhishGuard AI")
st.subheader("Agentic AI-Based Phishing Email Detection")

st.write(
    "Analyze suspicious emails using machine learning "
    "and explainable rule-based detection."
)

st.info(
    "For safety, paste email text only. "
    "Do not open suspicious links or attachments."
)

email_text = st.text_area(
    "Paste the email you want to analyze",
    height=250,
    placeholder=(
        "From: sender@example.com\n"
        "Subject: Verify your account\n\n"
        "Paste the email body here..."
    ),
)

if st.button("Analyze Email", type="primary"):
    if not email_text.strip():
        st.warning("Please paste an email before analyzing.")
    else:
        with st.spinner("Analyzing email..."):
            try:
                # Run the main detection pipeline.
                result = analyze_message(email_text)

                st.divider()
                st.header("Analysis Results")

                # Display the three main metrics.
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        "Rule-Based Risk Score",
                        f"{result['risk_score']}/100",
                    )

                with col2:
                    st.metric(
                        "Rule-Based Risk Level",
                        result["risk_level"].upper(),
                    )

                with col3:
                    st.metric(
                        "ML Phishing Probability",
                        f"{result['ml_phishing_probability']:.1%}",
                    )

                st.write(
                    "**ML Prediction:**",
                    result["ml_prediction"],
                )

                # Explain which text features influenced the ML model.
                ml_details = predict_email(email_text)

                st.subheader(
                    "Why did the ML model make this prediction?"
                )

                st.caption(
                    "These terms influenced the classifier's output. "
                    "They are statistical signals, not proof of "
                    "malicious intent."
                )

                col_phishing, col_safe = st.columns(2)

                with col_phishing:
                    st.markdown("**Terms supporting phishing**")

                    if ml_details["phishing_terms"]:
                        for item in ml_details["phishing_terms"]:
                            st.write(
                                f"- `{item['term']}` "
                                f"(influence: "
                                f"{item['contribution']:.3f})"
                            )
                    else:
                        st.write(
                            "No strong phishing-supporting terms found."
                        )

                with col_safe:
                    st.markdown("**Terms supporting safe email**")

                    if ml_details["safe_terms"]:
                        for item in ml_details["safe_terms"]:
                            st.write(
                                f"- `{item['term']}` "
                                f"(influence: "
                                f"{item['contribution']:.3f})"
                            )
                    else:
                        st.write(
                            "No strong safe-supporting terms found."
                        )

                # Display parsed email information.
                st.subheader("Email Details")

                st.write(
                    "**Sender:**",
                    result["email"]["sender"] or "Not detected",
                )

                st.write(
                    "**Subject:**",
                    result["email"]["subject"] or "Not detected",
                )

                # Display rule-based detection indicators.
                st.subheader("Detection Indicators")

                if result["indicators"]:
                    for indicator in result["indicators"]:
                        st.warning(
                            f"**{indicator['type'].replace('_', ' ').title()}**"
                            f"\n\nEvidence: {indicator['evidence']}"
                            f"\n\nReason: {indicator['reason']}"
                        )
                else:
                    st.success(
                        "No configured rule-based indicators "
                        "were detected."
                    )

                st.caption(
                    "These results are automated assessments, not a "
                    "guarantee that an email is safe or malicious."
                )

            except Exception as exc:
                st.error(f"Analysis failed: {exc}")
