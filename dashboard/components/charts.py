import plotly.graph_objects as go, plotly.express as px
def gauge(score):
 f=go.Figure(go.Indicator(mode='gauge+number',value=max(0,min(100,float(score))),number={'suffix':'/100'},gauge={'axis':{'range':[0,100]},'bar':{'color':'#37c6f4'},'steps':[{'range':[0,20],'color':'#173c32'},{'range':[20,45],'color':'#55471f'},{'range':[45,70],'color':'#61391f'},{'range':[70,100],'color':'#5b2636'}]})); f.update_layout(height=250,paper_bgcolor='rgba(0,0,0,0)',font_color='#e5edf8'); return f
def bars(labels,values,title,xlabel='Score'):
 f=px.bar(x=values,y=labels,orientation='h',title=title,labels={'x':xlabel,'y':''}); f.update_layout(yaxis={'autorange':'reversed'},paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',font_color='#e5edf8'); return f
