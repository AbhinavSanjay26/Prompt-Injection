
import streamlit as st
import pandas as pd

from dashboard.components.charts import bars


def render(r, prompt):
    st.title("Explainability (XAI)")
    st.caption("Why did ATHS make this decision?")

    if not r:
        st.info("Analyze a prompt on Live Detection first.")
        return

    d = r.get("detection", {})
    x = r.get("explainability", {})
    recommendation = r.get("recommendation") or {}

    # Prompt and overall decision
    analyzed_prompt = (
        prompt
        or (r.get("input") or {}).get("prompt", "")
        or r.get("_dashboard_prompt", "")
    )
    st.code(analyzed_prompt, language=None)

    columns = st.columns(4)
    labels = ["Classification", "Threat score", "Severity", "Action"]
    values = [
        d.get("label", "N/A"),
        d.get("threat_score", "N/A"),
        d.get("severity", "N/A"),
        recommendation.get("action", "N/A"),
    ]

    for col, label, value in zip(columns, labels, values):
        col.metric(label, value)

    # Threat-score components
    sc = d.get("score_components", {})
    weights = sc.get("weights", {})
    components = []

    for key, label, fallback_key, weight_key in [
        ("ml_percent", "ML percentage", "ml_probability", "ml"),
        ("rule_score", "Rule score", "rule_score", "rules"),
        ("semantic_score", "Semantic score", "semantic_score", "semantic"),
    ]:
        value = sc.get(key, d.get(fallback_key))

        if value is not None:
            components.append({
                "Component": label,
                "Score": float(value),
                "Fusion weight": weights.get(weight_key, "N/A"),
            })

    if components:
        st.subheader("Threat-score components")

        st.plotly_chart(
            bars(
                [item["Component"] for item in components],
                [item["Score"] for item in components],
                "Component scores",
            ),
            width="stretch",
        )

        st.dataframe(
            pd.DataFrame(components),
            hide_index=True,
            width="stretch",
        )

    st.caption(
        d.get(
            "calibration_note",
            "Component scores may be heuristic, not calibrated probabilities.",
        )
    )

    # Rule evidence
    evidence = x.get("evidence", [])

    if evidence:
        st.subheader("Triggered rule evidence")

        df = pd.DataFrame([
            {
                "Feature": item.get("feature", "Unknown"),
                "Description": item.get("description", ""),
                "Rule contribution points": item.get("points", "N/A"),
            }
            for item in evidence
        ])

        st.plotly_chart(
            bars(
                df["Feature"].tolist(),
                [
                    float(value)
                    if isinstance(value, (int, float))
                    else 0
                    for value in df["Rule contribution points"]
                ],
                "Rule contributions",
                "Points",
            ),
            width="stretch",
        )

        st.dataframe(df, hide_index=True, width="stretch")
    else:
        st.info("The engine did not return a separate evidence list.")

    # Feature analysis
    feature_analysis = x.get("feature_analysis", {})
    feature_values = feature_analysis.get("feature_values", {})

    if feature_values:
        st.subheader("Feature analysis")

        st.dataframe(
            pd.DataFrame([
                {
                    "Feature": key,
                    "Value": value,
                    "Triggered": (
                        bool(value)
                        if isinstance(value, (int, float, bool))
                        else "N/A"
                    ),
                }
                for key, value in feature_values.items()
            ]),
            hide_index=True,
            width="stretch",
        )

    # Linguistic analysis
    nlp = feature_analysis.get(
        "nlp_summary",
        x.get("nlp_features", {}),
    )

    if nlp:
        st.subheader("Linguistic analysis")
        columns = st.columns(min(4, len(nlp)))

        for i, (key, value) in enumerate(nlp.items()):
            display_value = (
                value
                if isinstance(value, (str, int, float))
                else str(value)
            )

            columns[i % len(columns)].metric(
                key.replace("_", " ").title(),
                display_value,
            )

    # Semantic analysis
    semantic = x.get("semantic_similarity", {})

    if semantic:
        st.subheader("Semantic analysis")
        columns = st.columns(4)

        fields = [
            ("score", "Semantic score"),
            ("benign_centroid_similarity", "Benign similarity"),
            ("malicious_centroid_similarity", "Malicious similarity"),
            ("margin", "Margin"),
        ]

        for col, (key, label) in zip(columns, fields):
            col.metric(label, semantic.get(key, "N/A"))

        st.caption(
            semantic.get(
                "note",
                "Semantic scores are heuristic indicators.",
            )
        )

    # Security and obfuscation indicators
    with st.expander("Security indicators"):
        st.json(x.get("security_features", {}))

    with st.expander("Obfuscation indicators"):
        st.json(
            x.get(
                "obfuscation_features",
                feature_analysis.get("obfuscation_features", {}),
            )
        )

    # Updated context trust analysis
    st.subheader("Context trust analysis")

    context = r.get("context") or {}

    source = context.get("source", "user_prompt")
    trust_level = context.get("trust_level", "untrusted")

    threat_score = d.get("threat_score")
    if isinstance(threat_score, (int, float)):
        if threat_score < 25:
            threat_assessment = "Low risk"
        elif threat_score < 50:
            threat_assessment = "Moderate risk"
        elif threat_score < 75:
            threat_assessment = "High risk"
        else:
            threat_assessment = "Critical risk"
    else:
        threat_assessment = str(d.get("severity", "Not assessed"))

    action = recommendation.get("action", "N/A")
    action_note = recommendation.get("note", "")

    # Use readable labels without changing the engine's trust metadata.
    source_display = {
        "user_prompt": "User prompt",
    }.get(source, str(source).replace("_", " ").title())

    trust_display = {
        "untrusted": "Untrusted external input",
        "trusted": "Trusted input",
    }.get(str(trust_level).lower(), str(trust_level).replace("_", " ").title())

    columns = st.columns(2)
    columns[0].metric("Input source", source_display)
    columns[1].metric("Source trust", trust_display)

    columns = st.columns(2)
    columns[0].metric("Threat assessment", threat_assessment)
    columns[1].metric("Policy decision", str(action).replace("_", " ").title())

    if action_note:
        st.caption(action_note)

    st.caption(
        "Source trust describes where input originates; threat assessment "
        "describes the detector's evaluation. Untrusted input is not "
        "necessarily malicious."
    )

    st.caption(
        "Only context metadata supplied by the engine is shown; "
        "no external document scan is implied."
    )

    # XAI limitations
    with st.expander("XAI limitations"):
        st.write(
            "Rule contribution points are not learned feature importance. "
            "This dashboard does not claim SHAP values unless SHAP is "
            "actually implemented. Hypotheses are evidence-supported "
            "inferences, not confirmed attribution. Heuristic scores are "
            "not calibrated probabilities unless separately validated."
        )
