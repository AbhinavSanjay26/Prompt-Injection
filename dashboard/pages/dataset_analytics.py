import streamlit as st,pandas as pd,plotly.express as px,plotly.graph_objects as go
def chart(fig): fig.update_layout(paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',font_color='#e5edf8'); st.plotly_chart(fig,use_container_width=True)
def render(data,ev,messages):
 st.title('Dataset / Analytics'); st.caption('Processed dataset and held-out model evaluation')
 if data is None: st.warning('Dataset unavailable. '+messages)
 else:
  counts=data.label.value_counts() if 'label' in data else {}; c=st.columns(3); c[0].metric('Samples loaded',f'{len(data):,}'); c[1].metric('Malicious (label 1)',f'{int(counts.get(1,0)):,}' if 'label' in data else 'N/A'); c[2].metric('Benign (label 0)',f'{int(counts.get(0,0)):,}' if 'label' in data else 'N/A')
  a,b=st.columns(2)
  with a:
   if 'label' in data: d=data.label.map({0:'Benign',1:'Malicious'}).fillna(data.label.astype(str)).value_counts().rename_axis('Class').reset_index(name='Samples'); chart(px.pie(d,names='Class',values='Samples',hole=.5,title='Class distribution'))
   if 'category' in data: d=data.category.fillna('Unknown').astype(str).value_counts().head(15).rename_axis('Category').reset_index(name='Samples'); chart(px.bar(d,x='Category',y='Samples',title='Attack categories'))
  with b:
   if 'source' in data: d=data.source.fillna('Unknown').astype(str).value_counts().head(15).rename_axis('Source').reset_index(name='Samples'); chart(px.bar(d,x='Source',y='Samples',title='Dataset sources'))
   if 'severity' in data: d=data.severity.fillna('Unknown').astype(str).value_counts().rename_axis('Severity').reset_index(name='Samples'); chart(px.bar(d,x='Severity',y='Samples',title='Severity distribution'))
  numeric=data.select_dtypes(include='number')
  if len(numeric.columns):
   with st.expander('Numeric feature distributions'): key=st.selectbox('Feature',list(numeric.columns)); chart(px.histogram(data,x=key,color='label' if 'label' in data else None,title=key))
  st.subheader('Dataset preview'); st.dataframe(data.head(100),use_container_width=True,hide_index=True); st.download_button('Download first 1,000 rows as CSV',data.head(1000).to_csv(index=False).encode(),'aths_dataset_preview.csv','text/csv')
 st.divider(); st.subheader('Model evaluation')
 if not ev: st.warning('Evaluation report unavailable.'); return
 m=ev.get('test_metrics',ev); keys=[('accuracy','Accuracy'),('precision_malicious','Malicious precision'),('recall_malicious','Malicious recall'),('f1_malicious','Malicious F1'),('roc_auc','ROC-AUC'),('false_positive_rate','False-positive rate'),('false_negative_rate','False-negative rate')]; vals=[(k,l,m[k]) for k,l in keys if isinstance(m.get(k),(int,float))]; c=st.columns(min(4,len(vals))) if vals else []
 for i,(k,l,v) in enumerate(vals): c[i%len(c)].metric(l,f'{v*100:.2f}%' if abs(v)<=1 else f'{v:.3f}')
 matrix=m.get('confusion_matrix_labels_0_1')
 if matrix:
  f=go.Figure(data=go.Heatmap(z=matrix,x=['Predicted benign (0)','Predicted malicious (1)'],y=['Actual benign (0)','Actual malicious (1)'],text=matrix,texttemplate='%{text}',colorscale='Blues')); f.update_layout(title='Confusion matrix'); chart(f)
 report=m.get('classification_report')
 if isinstance(report,dict):
  rows=[{'Class':k,**{x:v.get(x) for x in ('precision','recall','f1-score','support')}} for k,v in report.items() if isinstance(v,dict)]
  if rows: st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
 st.caption('Evaluation metrics are from the saved report, not a guarantee of live or real-world performance.')
