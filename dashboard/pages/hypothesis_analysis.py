import streamlit as st,pandas as pd
def render(r,prompt):
 st.title('Hypothesis Analysis'); st.caption('Ranked threat hypotheses and supporting evidence')
 if not r: st.info('Analyze a prompt on Live Detection first.'); return
 d=r.get('detection',{}); c=st.columns(3); c[0].metric('Threat score',d.get('threat_score','N/A')); c[1].metric('Severity',d.get('severity','N/A')); c[2].metric('Classification',d.get('label','N/A')); st.write('Prompt:',prompt or (r.get('input') or {}).get('prompt','N/A'))
 hs=r.get('hypotheses',[])
 if not hs: st.info('No hypotheses were returned by the engine.'); return
 rows=[]
 for i,h in enumerate(hs,1):
  s=h.get('confidence_score'); rows.append({'Rank':i,'Hypothesis':h.get('name',h.get('type','Unknown')),'Confidence':f'{s*100:.1f}%' if isinstance(s,(int,float)) else 'N/A','Label':h.get('confidence_label','N/A'),'Evidence count':len(h.get('evidence',[])),'Global score':h.get('global_threat_score',d.get('threat_score','N/A'))})
 st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True); names=[x['Hypothesis'] for x in rows]; selected=st.selectbox('Inspect hypothesis',names); h=hs[names.index(selected)]; st.subheader(selected); st.write(h.get('description','No description supplied.')); s=h.get('confidence_score')
 if isinstance(s,(int,float)): st.progress(max(0,min(100,int(s*100)))); st.caption(f"Heuristic ranking score: {s*100:.1f}% · {h.get('confidence_label','N/A')}")
 st.markdown('#### Supporting evidence')
 for e in h.get('evidence_descriptions') or h.get('evidence') or ['No evidence supplied.']: st.markdown(f'- {e}')
 st.caption(h.get('scoring_note','Confidence scores may be heuristic rankings, not calibrated probabilities.')); st.subheader('Attack progression timeline'); st.info('A genuine timeline requires multi-turn conversation data. No progression is inferred from a single prompt.')
