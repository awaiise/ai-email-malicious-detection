import streamlit as st
import joblib
import numpy as np
import plotly.graph_objects as go
import pandas as pd
import time
import os
from email import policy
from email.parser import BytesParser

# ---------- PAGE CONFIG ----------

st.set_page_config(
    page_title="Cyber AI Email Security",
    page_icon="🛡️",
    layout="wide"
)

# ---------- LOAD MODEL ----------

model = joblib.load("logistic_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ---------- HISTORY FILE ----------

HISTORY_FILE = "threat_history.csv"

if not os.path.exists(HISTORY_FILE):
    df_init = pd.DataFrame(columns=["text","prediction","malicious_prob"])
    df_init.to_csv(HISTORY_FILE, index=False)

history_df = pd.read_csv(HISTORY_FILE)

# ---------- SIDEBAR ----------

st.sidebar.title("🛡 Cyber Security Console")

page = st.sidebar.radio(
    "Navigation",
    ["Threat Detection","Monitoring Log","System Info"]
)

# =========================================================
# PAGE 1 — THREAT DETECTION
# =========================================================

if page == "Threat Detection":

    st.title("🛡 AI Email Threat Scanner")
    st.write("Analyse suspicious emails in real-time")

    email_text = st.text_area(
        "Paste Email Content",
        height=200
    )

    txt_file = st.file_uploader("Upload Email (.txt)", type=["txt"])
    eml_file = st.file_uploader("Upload Email (.eml)", type=["eml"])

    subject = ""
    sender = ""

    if txt_file:
        email_text = txt_file.read().decode("utf-8")
        st.success("TXT email loaded")

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
            prediction = 1 if malicious_prob > 0.5 else 0

            if prediction == 1:
                st.error(f"🚨 Malicious Email Detected (Risk: {malicious_prob:.2f})")
            else:
                st.success(f"✅ Legitimate Email (Confidence: {1-malicious_prob:.2f})")

            # ---------- SAVE HISTORY ----------
            new_row = pd.DataFrame(
                [[email_text, prediction, malicious_prob]],
                columns=["text","prediction","malicious_prob"]
            )

            new_row.to_csv(HISTORY_FILE, mode='a', header=False, index=False)

            # ---------- RISK GAUGE ----------
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=malicious_prob*100,
                title={'text': "Threat Risk Score"},
                gauge={
                    'axis': {'range': [0,100]},
                    'bar': {'color': "red"},
                    'steps': [
                        {'range':[0,40],'color':'green'},
                        {'range':[40,70],'color':'orange'},
                        {'range':[70,100],'color':'red'}
                    ]
                }
            ))

            st.plotly_chart(fig, use_container_width=True)

# =========================================================
# PAGE 2 — MONITORING LOG
# =========================================================

elif page == "Monitoring Log":

    st.title("📊 Threat Monitoring Dashboard")

    df = pd.read_csv(HISTORY_FILE)

    total_scanned = len(df)
    total_malicious = len(df[df["prediction"]==1])

    threat_rate = 0
    if total_scanned > 0:
        threat_rate = total_malicious / total_scanned

    col1,col2,col3 = st.columns(3)

    col1.metric("Emails Scanned", total_scanned)
    col2.metric("Threats Detected", total_malicious)
    col3.metric("Threat Rate", f"{threat_rate:.2%}")

    if total_scanned > 0:

        st.subheader("Threat Risk Distribution")

        fig = go.Figure()
        fig.add_trace(go.Histogram(x=df["malicious_prob"]))
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent Scan History")
        st.dataframe(df.tail(20))

# =========================================================
# PAGE 3 — SYSTEM INFO
# =========================================================

else:

    st.title("📘 System Information")

    st.write("""
    This AI system detects phishing and spam emails using machine learning.

    Developed as part of MSc research on:
    • Robustness of malicious email detection  
    • Cross-domain generalisation  
    • Practical cyber-security deployment  
    """)

    st.success("System demonstrates feasibility of AI-driven cyber defence.")