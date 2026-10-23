from pathlib import Path
import json, pandas as pd

def load_data(root):
 data=eval_data=None; messages=[]
 p=root/'dataset'/'processed'/'features.csv'
 if p.exists():
  try: data=pd.read_csv(p)
  except Exception as e: messages.append(f'Dataset could not be loaded: {e}')
 else: messages.append(f'Dataset not found: {p}')
 p=root/'evaluation'/'evaluation.json'
 if p.exists():
  try: eval_data=json.loads(p.read_text(encoding='utf-8'))
  except Exception as e: messages.append(f'Evaluation report could not be loaded: {e}')
 else: messages.append(f'Evaluation report not found: {p}')
 return data,eval_data,'\n'.join(messages)
