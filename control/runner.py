"""Bounded operation runner using native repository instructions and read-only tools."""
import asyncio,json,os,time
from pathlib import Path
import httpx
from .db import connect,init,audit
from .security import secret

WORKSPACE=Path(os.getenv('AGENT_WORKSPACE','/workspace'))
ROLES={'platform-health':{'skill':'platform-health','tool':'platform_health'},'soc-triage':{'skill':'soc-triage','tool':'siem_alerts'}}

def instructions(role):
 # Read only standard locations; user content cannot choose a filesystem path.
 policy=(WORKSPACE/'AGENTS.md').read_text()[:16000]
 skill=(WORKSPACE/'.agents/skills'/ROLES[role]['skill']/'SKILL.md').read_text()[:16000]
 return policy+'\n\n'+skill

async def run(role):
 start=time.time()
 with connect() as db:cur=db.execute('INSERT INTO runs(role,status,started) VALUES(?,?,?)',(role,'running',start));ident=cur.lastrowid
 try:
  token=secret('AGENT_TOKEN');headers={'Authorization':'Bearer '+token}
  async with httpx.AsyncClient(timeout=180,trust_env=False) as c:
   path='/_kt88/agent/health' if role=='platform-health' else '/_kt88/agent/siem'
   r=await c.get(os.getenv('CONTROL_URL','http://control:8000')+path,headers=headers);r.raise_for_status();evidence=r.json()
   base=os.getenv('LLM_URL','').rstrip('/')
   if not base:raise RuntimeError('Inference model not configured')
   tools=[{'type':'function','function':{'name':ROLES[role]['tool'],'description':'Read current bounded operational evidence','parameters':{'type':'object','properties':{},'additionalProperties':False}}}]
   messages=[{'role':'system','content':instructions(role)+'\n개인정보·토큰 출력 금지. 허용된 읽기 도구만 사용. 적용 권한 없음.'},{'role':'user','content':'현재 운영 상태를 확인하고 한국어로 근거·미확인 범위·권장 조치를 보고하세요.'}]
   # First let the model request a bounded tool; server validates exact name/arguments.
   response=await c.post(base+'/api/chat',json={'model':os.getenv('LLM_MODEL','qwen3:8b'),'messages':messages,'tools':tools,'think':False,'stream':False,'options':{'num_ctx':8192,'num_predict':700,'temperature':0}});response.raise_for_status();message=response.json()['message']
   calls=message.get('tool_calls',[])
   if not calls or len(calls)>2 or any(call.get('function',{}).get('name')!=ROLES[role]['tool'] or call.get('function',{}).get('arguments',{})!={} for call in calls):raise RuntimeError('Model did not request valid read-only tool')
   messages.append(message)
   messages.append({'role':'tool','tool_name':ROLES[role]['tool'],'content':json.dumps(evidence,ensure_ascii=False)[:24000]})
   response=await c.post(base+'/api/chat',json={'model':os.getenv('LLM_MODEL','qwen3:8b'),'messages':messages,'think':False,'stream':False,'options':{'num_ctx':8192,'num_predict':1000,'temperature':0.1}});response.raise_for_status()
   result={'evidence_at':start,'evidence':evidence,'assessment':response.json()['message']['content'][:8000],'authority':'read-only; no changes applied'}
   status='completed'
 except Exception as e:status='error';result={'error_type':type(e).__name__,'message':str(e)[:300] if not isinstance(e,httpx.HTTPError) else 'Operational upstream failed'}
 with connect() as db:db.execute('UPDATE runs SET status=?,finished=?,result=? WHERE id=?',(status,time.time(),json.dumps(result,ensure_ascii=False),ident))
 audit('agent:'+role,'run_finished',{'run_id':ident,'status':status})

async def main():
 init()
 while True:
  for role in ROLES:await run(role)
  await asyncio.sleep(int(os.getenv('AGENT_INTERVAL','900')))
if __name__=='__main__':asyncio.run(main())
