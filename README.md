# Demo: Will this CVE be rated Critical?

A complete example of the capstone workflow, from a real public dataset to a live Streamlit app. Use it alongside the *Deploying Your Model* slides.

**Question:** from what is known when a vulnerability is published (weakness type, vendor, product type, reporter, year), can we predict whether it will be rated **Critical** (CVSS v3 score 9.0 or higher)?

| File | What it is |
|---|---|
| `pull_nvd.py` | Pulls CVEs from the NVD API 2.0 into `nvd_cves.csv` (run once) |
| `nvd_critical_demo.ipynb` | The 8-step workflow: problem, data, cleaning, EDA, model, evaluation, leakage trap, saving the model |
| `app.py` | The Streamlit app |
| `requirements.txt` | Packages Streamlit Community Cloud installs |

## Run it

```bash
pip install -r requirements.txt requests jupyter matplotlib

python pull_nvd.py            # creates nvd_cves.csv; slow without an API key (see below)
jupyter notebook nvd_critical_demo.ipynb      # Run All; creates critical_model.joblib and app_options.json
streamlit run app.py
```

**The pull.** By default it fetches CVEs published 2023-01-01 to 2024-12-31 (tens of thousands of records). The API allows 5 requests per 30 seconds without a key, so expect a long run. A free key makes it about 10x faster: request one at https://nvd.nist.gov/developers/request-an-api-key, then `export NVD_API_KEY="your-key"` (Windows PowerShell: `$env:NVD_API_KEY="your-key"`). If it stops part-way, rerun with `--resume`. For a quick test, try `--start 2024-10-01 --end 2024-12-31`.

## Deploy it

Push `app.py`, `requirements.txt`, `critical_model.joblib`, and `app_options.json` to a public GitHub repo (the CSV is git-ignored; the app does not need it), then create the app on Streamlit Community Cloud. The `scikit-learn` version in `requirements.txt` must match the one that trained the model; the notebook prints your version in its last cell.

## Credit

Data: NVD CVE API 2.0. This product uses data from the NVD API but is not endorsed or certified by the NVD.
