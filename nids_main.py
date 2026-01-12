import streamlit as st
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# -------------------------
# Page Config
# -------------------------
st.set_page_config(page_title="AI NIDS", layout="wide")
st.title("AI-Based Network Intrusion Detection System")

# -------------------------
# Load Real Dataset
# -------------------------
def load_data():
    df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    # clean column names
    df.columns = df.columns.str.strip()

    # select useful columns
    df = df[
        [
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Label"
        ]
    ]

    # rename
    df.columns = [
        "flow_duration",
        "fwd_pkts",
        "bwd_pkts",
        "fwd_bytes",
        "bwd_bytes",
        "label"
    ]

    # label encoding
    df["label"] = df["label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    return df

# -------------------------
# Sidebar
# -------------------------
st.sidebar.header("Controls")
train_btn = st.sidebar.button("Train Model Now")

# -------------------------
# Session State
# -------------------------
if "model" not in st.session_state:
    st.session_state.model = None

# -------------------------
# Train Model
# -------------------------
if train_btn:
    with st.spinner("Training model..."):
        df = load_data()

        X = df.drop("label", axis=1)
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42
        )

        model = RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train, y_train)

        acc = accuracy_score(y_test, model.predict(X_test))
        st.session_state.model = model

    st.success(f"Model trained! Accuracy: {acc:.2f}")

# -------------------------
# Live Traffic Simulator
# -------------------------
st.subheader("Live Traffic Simulator")

col1, col2, col3 = st.columns(3)

with col1:
    flow_duration = st.number_input("Flow Duration", value=1000.0)
with col2:
    fwd_pkts = st.number_input("Total Fwd Packets", value=10.0)
with col3:
    bwd_pkts = st.number_input("Total Backward Packets", value=5.0)

col4, col5 = st.columns(2)
with col4:
    fwd_bytes = st.number_input("Total Length of Fwd Packets", value=2000.0)
with col5:
    bwd_bytes = st.number_input("Total Length of Bwd Packets", value=1500.0)

# -------------------------
# Detection Logic
# -------------------------
if st.button("Analyze Traffic"):
    if st.session_state.model is None:
        st.warning("⚠️ Train the model first.")
    else:
        sample = np.array([[flow_duration, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes]])

        # ML probability
        attack_prob = st.session_state.model.predict_proba(sample)[0][1]

        # ---- HARD RULE FOR DEMO (anti-foolproof) ----
        rule_attack = (
            flow_duration > 50000 or
            fwd_pkts > 1000 or
            fwd_bytes > 500000
        )

        st.write(f"🔍 Attack Probability: {attack_prob:.2f}")

        # ---- FINAL DECISION ----
        if attack_prob > 0.45 or rule_attack:
            st.error("🚨 INTRUSION DETECTED!")
        else:
            st.success("✅ Traffic is Normal")
