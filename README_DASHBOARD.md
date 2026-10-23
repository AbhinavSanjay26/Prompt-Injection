# ATHS Dashboard + XAI

This is a dashboard layer to copy into your existing `ATHS_Complete` project. It does not replace the existing engine, model files, or dataset.

## Pages
- Overview
- Live Detection
- Explainability (XAI)
- Hypothesis Analysis
- Dataset / Analytics

## Install (PowerShell)
From the **ATHS_Complete project root**, activate your existing venv and run:

```powershell
python -m pip install -r dashboard/requirements-dashboard.txt
```

If the requirements file is at the root after copying, adjust the path accordingly. Recommended: copy `requirements-dashboard.txt` to your project root or merge these packages into your existing deployment requirements.

## Run locally
From the project root:

```powershell
python -m streamlit run dashboard/streamlit_app.py
```

## Railway start command

```bash
streamlit run dashboard/streamlit_app.py --server.address 0.0.0.0 --server.port $PORT
```

Deploy the whole project root containing `aths_engine.py`, `preprocessing/`, `detection/`, `hypothesis/`, `models/`, `dataset/`, `evaluation/`, and `dashboard/`.

## Important engine integration note
The adapter tries common function and class names in `aths_engine.py`. Since this zip contains the dashboard layer rather than your existing engine source, verify `dashboard/services/engine_adapter.py` against the callable used by your working `demo.py`. If the entry point differs, update `_callable()` to call the exact same engine function/class. It shows an error rather than fabricating detection results.

Expected data paths relative to the project root: `dataset/processed/features.csv` and `evaluation/evaluation.json`.

## Railway persistence
Scan history uses SQLite at `dashboard/aths_history.db`. Railway local files may not survive redeploys unless you configure a persistent volume. Add a Railway volume if you need persistent history.

## XAI limitations
Rule points are shown as rule contributions, not learned feature importance. This version does not claim SHAP values. Multi-turn timelines require actual conversation-turn data. Heuristic scores are not calibrated probabilities unless separately validated.
