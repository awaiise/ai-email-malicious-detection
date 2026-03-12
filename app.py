import streamlit as st
import joblib
import plotly.graph_objects as go
import time
from email import policy
from email.parser import BytesParser
import pandas as pd

# ---------- THEME ----------

st.set_page_config(
    page_title="Cyber AI Email Security",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.big-title {
    font-size:40px;
    color:#00ffcc;
    font-weight:700;
}
.sub-text {
    color:#9aa0a6;
}
</style>
""", unsafe_allow_html=True)

# ---------- MODEL ----------

model = joblib.load("logistic_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ---------- HISTORY ----------

if "history" not in st.session_state:
    st.session_state.history = []

# ---------- SIDEBAR ----------

st.sidebar.title("🛡️ Cyber Security Console")

page = st.sidebar.radio(
    "Navigation",
    ["📧 Threat Detection", "📜 Monitoring Log", "📘 System Info"]
)

# ====================================================
# DETECTION
# ====================================================

if page == "📧 Threat Detection":

    st.markdown('<p class="big-title">AI Email Threat Scanner</p>',
                unsafe_allow_html=True)

    st.markdown('<p class="sub-text">Analyse suspicious emails in real-time</p>',
                unsafe_allow_html=True)

    email_text = st.text_area("Paste Email Content", height=200)

    subject = ""
    sender = ""

    txt_file = st.file_uploader("Upload Email (.txt)", type=["txt"])
    if txt_file:
        email_text = txt_file.read().decode("utf-8")
        st.success("TXT email loaded")

    eml_file = st.file_uploader("Upload Email (.eml)", type=["eml"])
    if eml_file:
        msg = BytesParser(policy=policy.default).parse(eml_file)

        subject = msg["subject"]
        sender = msg["from"]

        try:
            email_text = msg.get_body(preferencelist=('plain')).get_content()
        except:
            email_text = msg.as_string()

        st.success("EML email loaded")

        if subject:
            st.info(f"📌 Subject: {subject}")

        if sender:
            st.info(f"👤 Sender: {sender}")

    if st.button("🚀 Scan Email Threat"):

        if email_text.strip() == "":
            st.warning("Please provide email content")
        else:
            with st.spinner("Scanning email for threats..."):
                time.sleep(1)

            vec = vectorizer.transform([email_text])
            prob = model.predict_proba(vec)[0]

            malicious_prob = prob[1]
            legit_prob = prob[0]

            if malicious_prob < 0.40:
                risk = "LOW"
                result = "Legitimate"
                st.success(f"SAFE EMAIL ({legit_prob:.2f})")

            elif malicious_prob < 0.70:
                risk = "MEDIUM"
                result = "Suspicious"
                st.warning(f"SUSPICIOUS EMAIL ({malicious_prob:.2f})")

            else:
                risk = "HIGH"
                result = "Malicious"
                st.error(f"MALICIOUS EMAIL ({malicious_prob:.2f})")

            # ---------- SAVE HISTORY ----------
            st.session_state.history.append({
                "Subject": subject if subject else "N/A",
                "Sender": sender if sender else "N/A",
                "Result": result,
                "Risk": risk,
                "Confidence": round(max(malicious_prob, legit_prob), 2)
            })

            # ---------- GAUGE ----------
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=malicious_prob * 100,
                title={'text': f"Threat Risk ({risk})"},
                gauge={'axis': {'range': [0, 100]}}
            ))

            st.plotly_chart(fig, use_container_width=True)

            # ---------- EXPORT REPORT ----------
            report = f"""
Email Threat Analysis Report

Subject: {subject}
Sender: {sender}

Prediction: {result}
Risk Level: {risk}
Confidence: {round(max(malicious_prob, legit_prob),2)}
"""

            st.download_button(
                label="📥 Download Report",
                data=report,
                file_name="email_threat_report.txt",
                mime="text/plain"
            )

# ====================================================
# HISTORY
# ====================================================

elif page == "📜 Monitoring Log":

    st.markdown('<p class="big-title">Threat Monitoring Log</p>',
                unsafe_allow_html=True)

    if len(st.session_state.history) == 0:
        st.info("No emails analysed yet")
    else:
        df = pd.DataFrame(st.session_state.history)
        st.dataframe(df, use_container_width=True)

# ====================================================
# INFO
# ====================================================

else:

    st.markdown('<p class="big-title">System Overview</p>',
                unsafe_allow_html=True)

    st.write("""
This AI prototype detects phishing and spam emails in real-time and allows exportable threat reports for cybersecurity analysis.
    """)