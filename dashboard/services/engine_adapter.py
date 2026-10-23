"""Adapter to your existing aths_engine.py. Does not implement detection itself."""
import importlib
class EngineIntegrationError(RuntimeError): pass

def _callable():
 try: mod=importlib.import_module('aths_engine')
 except Exception as e: raise EngineIntegrationError(f'Could not import aths_engine.py from project root: {e}') from e
 for name in ('analyze_prompt','analyze','run_analysis','detect_threat'):
  fn=getattr(mod,name,None)
  if callable(fn): return lambda prompt,fn=fn: fn(prompt)
 for cn in ('ATHSEngine','ThreatAnalysisEngine','AutonomousThreatHypothesisSystem'):
  cls=getattr(mod,cn,None)
  if cls:
   try: obj=cls()
   except Exception as e: raise EngineIntegrationError(f'{cn} initialization failed: {e}') from e
   for mn in ('analyze_prompt','analyze','run_analysis','process_prompt'):
    fn=getattr(obj,mn,None)
    if callable(fn): return lambda prompt,fn=fn: fn(prompt)
 raise EngineIntegrationError('Could not identify the public engine callable. Edit dashboard/services/engine_adapter.py and map _callable() to the same function used by demo.py.')

def analyze_prompt(prompt):
 if not prompt or not prompt.strip(): raise EngineIntegrationError('Enter a non-empty prompt.')
 try: result=_callable()(prompt.strip())
 except EngineIntegrationError: raise
 except Exception as e: raise EngineIntegrationError(f'ATHS analysis failed: {e}') from e
 if hasattr(result,'model_dump'): result=result.model_dump()
 if not isinstance(result,dict): raise EngineIntegrationError(f'Engine returned {type(result).__name__}, expected a dictionary.')
 result=dict(result); result['_dashboard_prompt']=prompt.strip(); return result
