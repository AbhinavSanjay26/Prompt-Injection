
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.services.engine_adapter import (
    analyze_prompt,
    EngineIntegrationError,
)
from dashboard.components.charts import gauge


# Project root: ATHS_Complete
ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = ROOT / "dataset" / "processed" / "features.csv"


@st.cache_data
def load_prompt_dataset():
    """Load prompts and labels from the processed ATHS dataset."""
    if not DATASET_PATH.exists():
        return pd.DataFrame()

    df = pd.read_csv(DATASET_PATH)

    text_col = next(
        (col for col in ["text", "prompt", "input"] if col in df.columns),
        None,
    )
    label_col = next(
        (col for col in ["label", "target", "class"] if col in df.columns),
        None,
    )

    if text_col is None or label_col is None:
        return pd.DataFrame()

    df = df[[text_col, label_col]].copy()
    df.columns = ["text", "label"]

    df["text"] = df["text"].fillna("").astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")

    df = df[
        (df["text"] != "")
        & df["label"].isin([0, 1])
    ].copy()

    return df


def select_random_prompt():
    """Select a random dataset sample when the sample option changes."""
    choice = st.session_state.get("sample_choice", "— Select —")

    if choice == "— Select —":
        st.session_state["sample_error"] = ""
        return

    df = load_prompt_dataset()

    if df.empty:
        st.session_state["sample_error"] = (
            "Could not load prompts from dataset/processed/features.csv. "
            "Check that the file contains text and label columns."
        )
        return

    # Dataset convention: 0 = benign, 1 = malicious.
    target_label = 0 if choice == "Benign example" else 1
    matching = df[df["label"] == target_label]

    if matching.empty:
        st.session_state["sample_error"] = (
            f"No dataset samples found for {choice}."
        )
        return

    selected = matching.sample(n=1).iloc[0]

    st.session_state["prompt_input"] = selected["text"]
    st.session_state["sample_error"] = ""

    # A new sample should not leave the previous result on screen.
    st.session_state["latest"] = None
    st.session_state["latest_prompt"] = ""


def render():
    st.title("Live Detection")
    st.caption("Run the existing ATHS analysis pipeline")

    # Initialize persistent state.
    if "latest" not in st.session_state:
        st.session_state["latest"] = None

    if "latest_prompt" not in st.session_state:
        st.session_state["latest_prompt"] = ""

    if "prompt_input" not in st.session_state:
        st.session_state["prompt_input"] = ""

    if "sample_error" not in st.session_state:
        st.session_state["sample_error"] = ""

    st.selectbox(
        "Optional sample prompt",
        [
            "— Select —",
            "Benign example",
            "Prompt-injection example",
        ],
        key="sample_choice",
        on_change=select_random_prompt,
    )

    prompt = st.text_area(
        "Prompt to analyze",
        key="prompt_input",
        height=160,
        max_chars=12000,
        placeholder="Enter a prompt…",
    )

    if st.session_state.get("sample_error"):
        st.warning(st.session_state["sample_error"])

    analyze_clicked = st.button(
        "Analyze prompt",
        type="primary",
    )

    # Run the engine only after an explicit button click.
    if analyze_clicked:
        if not prompt.strip():
            st.warning("Enter a prompt first.")
            return None

        # Clear old results so a failed analysis cannot show stale output.
        st.session_state["latest"] = None
        st.session_state["latest_prompt"] = ""

        try:
            with st.spinner(
                "Running preprocessing, detection, and hypothesis generation…"
            ):
                result = analyze_prompt(prompt.strip())

            result["_dashboard_prompt"] = prompt.strip()

            # Save the result before the app reruns.
            st.session_state["latest"] = result
            st.session_state["latest_prompt"] = prompt.strip()

            # Let streamlit_app.py add this new result to history once.
            return result

        except EngineIntegrationError as error:
            st.error(f"ATHS analysis failed: {error}")
            st.caption(
                "Check dashboard/services/engine_adapter.py against "
                "the callable used in demo.py."
            )
            return None

        except Exception as error:
            st.error(f"ATHS analysis failed: {error}")
            return None

    # Render the stored result on subsequent reruns.
    result = st.session_state.get("latest")

    if not result:
        st.info("Enter a prompt and click Analyze prompt.")
        return None

    detection = result.get("detection", {})
    recommendation = result.get("recommendation", {})

    st.success("Analysis completed by ATHS engine.")

    # Main detection results.
    columns = st.columns(3)

    columns[0].metric(
        "Classification",
        str(detection.get("label", "N/A")).upper(),
    )
    columns[1].metric(
        "Threat score",
        detection.get("threat_score", "N/A"),
    )
    columns[2].metric(
        "Severity",
        str(detection.get("severity", "N/A")).upper(),
    )

    threat_score = detection.get("threat_score")

    if isinstance(threat_score, (int, float)):
        st.plotly_chart(
            gauge(threat_score),
            width="stretch",
        )

    # Detection component scores.
    columns = st.columns(3)

    columns[0].metric(
        "ML probability",
        detection.get("ml_probability", "N/A"),
    )
    columns[1].metric(
        "Rule score",
        detection.get("rule_score", "N/A"),
    )
    columns[2].metric(
        "Semantic score",
        detection.get("semantic_score", "N/A"),
    )

    # Recommended action.
    st.subheader("Recommended action")

    st.info(
        f"{recommendation.get('action', 'N/A')} — "
        f"{recommendation.get('note', 'No note supplied by engine.')}"
    )

    # Attack hypotheses.
    st.subheader("Attack hypotheses")

    hypotheses = result.get("hypotheses", [])

    if not hypotheses:
        st.info("No hypotheses were returned by the engine.")

    for hypothesis in hypotheses:
        name = hypothesis.get(
            "name",
            hypothesis.get("type", "Hypothesis"),
        )

        with st.expander(
            f"{name} · {hypothesis.get('confidence_label', 'N/A')}"
        ):
            score = hypothesis.get("confidence_score")

            if isinstance(score, (int, float)):
                st.write(
                    f"Heuristic ranking score: {score * 100:.1f}%"
                )

            st.write(hypothesis.get("description", ""))

            st.write(
                hypothesis.get(
                    "evidence_descriptions",
                    hypothesis.get("evidence", []),
                )
            )

    st.caption(
        "Heuristic scores are advisory and are not necessarily "
        "calibrated probabilities."
    )

    # Do not return the saved result again on ordinary reruns.
    # This prevents duplicate history entries.
    return None
