import streamlit as st, pandas as pd, plotly.express as px
from dashboard.services.history_service import clear_history

def render(history,data,messages):
 st.title('ATHS — Security Overview'); st.caption('Hybrid prompt-injection detection and evidence-based threat analysis'); st.divider()
 def val(x,k): return (x['result'].get('detection') or {}).get(k,'')
 total=len(history); threats=sum(str(val(x,'label')).lower()=='malicious' for x in history); benign=sum(str(val(x,'label')).lower()=='benign' for x in history); severe=sum(str(val(x,'severity')).upper() in ('HIGH','CRITICAL') for x in history)
 cols=st.columns(5)
 for c,label,value in zip(cols,['Recorded live scans','Threats detected','Benign scans','High / critical','Live threat rate'],[total,threats,benign,severe,f'{threats/total*100:.1f}%' if total else '—']): c.metric(label,value)
 st.caption('These cards summarize recorded live scans, not dataset samples.')
 a,b=st.columns(2)
 with a:
  if history:
   df=pd.Series([str(val(x,'label')).upper() or 'UNKNOWN' for x in history]).value_counts().rename_axis('Class').reset_index(name='Scans'); st.plotly_chart(px.pie(df,names='Class',values='Scans',hole=.5,title='Live scan distribution'),use_container_width=True)
  else: st.info('No live scans recorded. Open Live Detection to analyze a prompt.')
 with b:
  if data is not None and 'category' in data: df=data.category.fillna('Unknown').astype(str).value_counts().head(12).rename_axis('Category').reset_index(name='Samples'); st.plotly_chart(px.bar(df,x='Category',y='Samples',title='Dataset attack categories'),use_container_width=True)
  else: st.info('Dataset category chart unavailable until dataset is loaded.')
 st.subheader('Recent analyses')
 if history:
  rows=[]
  for x in history[:10]:
   d=x['result'].get('detection',{}); rows.append({'Timestamp':x['timestamp'][:19],'Prompt preview':x['prompt'][:80],'Classification':d.get('label','N/A'),'Score':d.get('threat_score','N/A'),'Severity':d.get('severity','N/A'),'Action':(x['result'].get('recommendation') or {}).get('action','N/A')})
  st.dataframe(pd.DataFrame(rows),use_container_width=True,hide_index=True)
  if st.button('Clear saved scan history'): st.session_state.confirm_clear=True
  if st.session_state.get('confirm_clear'):
   st.warning('Delete all saved local scan history?')
   if st.button('Confirm clear'): clear_history(); st.session_state.confirm_clear=False; st.rerun()
 else: st.info('History will appear after the first successful scan.')
 if data is not None: st.caption(f'Processed dataset loaded: {len(data):,} rows.')
 if messages: st.caption(messages)
