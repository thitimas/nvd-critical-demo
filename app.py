"""Streamlit app: will a newly published CVE be rated Critical?  Run with:  streamlit run app.py"""
import json
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

HERE = Path(__file__).parent

st.set_page_config(page_title="CVE Critical-severity predictor", page_icon="🛡️")


@st.cache_resource
def load_model():
    return joblib.load(HERE / "critical_model.joblib")


@st.cache_data
def load_options():
    return json.loads((HERE / "app_options.json").read_text())


try:
    model, opt = load_model(), load_options()
except FileNotFoundError:
    st.error("Model files not found. Run the notebook `nvd_critical_demo.ipynb` first; "
             "it creates `critical_model.joblib` and `app_options.json`.")
    st.stop()

st.title("🛡️ Will this vulnerability be rated Critical?")
st.write("Describe a newly published CVE. The model estimates the chance that NVD rates it "
         "**Critical** (CVSS v3 score 9.0 or higher), using only three facts about it.")
st.info("This is an **educational project** (CS383). Do not use it for real security, medical, legal, "
        "financial, employment, or public-safety decisions.")

with st.form("cve"):
    c1, c2 = st.columns(2)
    cwe = c1.selectbox("Weakness type (CWE)", opt["cwe_primary"])
    vendor = c2.selectbox("Vendor", opt["vendor"])
    source = st.selectbox("Reported by", opt["source"])
    go = st.form_submit_button("Predict")

if go:
    row = pd.DataFrame([{"cwe_primary": cwe, "vendor": vendor, "source": source}])
    p = float(model.predict_proba(row)[0, 1])
    base = opt["critical_share"]
    st.metric("Estimated chance of Critical", f"{p:.0%}", delta=f"{(p - base) * 100:+.0f} pts vs. all CVEs ({base:.0%})")
    st.progress(min(max(p, 0.0), 1.0))
    if p >= 0.5:
        st.warning("Worth a closer look first.")
    else:
        st.info("Less likely to be Critical, but not ruled out.")

with st.expander("About this model"):
    st.write(
        f"Model: **{opt['best_model']}**, trained on CVEs published {opt['years'][0]}–{opt['years'][1]} "
        f"that have a CVSS v3 rating. Held-out test F1 for the Critical class: **{opt['test_f1']}**. "
        "It is a triage aid, not a verdict: it cannot see how a bug can actually be exploited, which is what "
        "drives the real score. Do not use it for real security decisions.")

st.divider()
st.caption("Data: NVD CVE API 2.0. This product uses data from the NVD API but is not endorsed or "
           "certified by the NVD.")
