from pathlib import Path
import sys, streamlit as st
ROOT=Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
st.set_page_config(page_title='ATHS | Threat Intelligence', page_icon='🛡️', layout='wide')
st.markdown('''<style>.stApp{background:#0b1120;color:#e5edf8}[data-testid="stSidebar"]{background:#101a2d;border-right:1px solid #26354d}.block-container{max-width:1500px;padding-top:2rem} [data-testid="stMetric"]{background:#111d32;padding:16px;border:1px solid #273b57;border-radius:14px} h1,h2,h3{color:#f2f7ff}</style>''',unsafe_allow_html=True)
from dashboard.services.engine_adapter import analyze_prompt, EngineIntegrationError
from dashboard.services.data_service import load_data
from dashboard.services.history_service import get_history, add_history, clear_history
from dashboard.pages.overview import render
from dashboard.pages.live_detection import render as live
from dashboard.pages.explainability import render as xai
from dashboard.pages.hypothesis_analysis import render as hypotheses
from dashboard.pages.dataset_analytics import render as analytics
if 'latest' not in st.session_state: st.session_state.latest=None
if 'latest_prompt' not in st.session_state: st.session_state.latest_prompt=''
with st.sidebar:
 st.markdown('## 🛡️ ATHS'); st.caption('Autonomous Threat Hypothesis System'); page=st.radio('NAVIGATION',['Overview','Live Detection','Explainability (XAI)','Hypothesis Analysis','Dataset / Analytics']); st.divider(); st.caption('Hybrid prompt-injection analysis')
history=get_history(); data, eval_data, messages=load_data(ROOT)
if page=='Overview': render(history,data,messages)
elif page=='Live Detection':
 result=live()
 if result:
  st.session_state.latest=result; st.session_state.latest_prompt=result.get('_dashboard_prompt',''); add_history(result); st.rerun()
elif page=='Explainability (XAI)': xai(st.session_state.latest,st.session_state.latest_prompt)
elif page=='Hypothesis Analysis': hypotheses(st.session_state.latest,st.session_state.latest_prompt)
else: analytics(data,eval_data,messages)
