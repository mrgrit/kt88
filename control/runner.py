"""Bounded operation runner using native repository instructions and read-only tools."""
import asyncio,json,os,time,datetime,fcntl
from pathlib import Path
import httpx
from .db import connect,init,audit
from .security import secret
from .agents import read,definitions,KINDS,models

WORKSPACE=Path(os.getenv('AGENT_WORKSPACE','/workspace'))


def normalized(value):
 if isinstance(value,dict):
  return {k:datetime.datetime.fromtimestamp(v,datetime.timezone.utc).isoformat() if k in ('updated','started','finished','evidence_at') and isinstance(v,(int,float)) else normalized(v) for k,v in value.items()}
 if isinstance(value,list):return [normalized(v) for v in value]
 return value

def instructions(definition):
 policy=(WORKSPACE/'AGENTS.md').read_text()[:16000]
 return policy+'\n\n'+definition['instructions']

async def run(role,ident,job):
 start=time.time();definition=job['definition'];kind=definition['kind'];usage=[]
 try:
  token=secret('AGENT_TOKEN');headers={'Authorization':'Bearer '+token}
  async with httpx.AsyncClient(timeout=180,trust_env=False) as c:
   path=KINDS[kind][2]
   if definition['model'] not in models():raise RuntimeError('Model is outside configured allowlist')
   r=await c.get(os.getenv('CONTROL_URL','http://control:8000')+path,headers=headers);r.raise_for_status();evidence=r.json()
   base=os.getenv('LLM_URL','').rstrip('/')
   if not base:raise RuntimeError('Inference model not configured')
   model_headers={'Host':os.environ['MODEL_HTTP_HOST']} if os.getenv('MODEL_HTTP_HOST') else {}
   tools=[{'type':'function','function':{'name':KINDS[kind][1],'description':'Read current bounded operational evidence','parameters':{'type':'object','properties':{},'additionalProperties':False}}}]
   messages=[{'role':'system','content':instructions(definition)+'\n개인정보·토큰 출력 금지. 허용된 읽기 도구만 사용. 적용 권한 없음. 시각은 제공한 ISO 문자열 그대로 인용하고 변환하지 말 것. endpoint healthy는 내부 upstream 측정이며 공개 DNS/인증서 상태를 의미하지 않는다. 경보 목록은 표본이므로 전체 경보 구성으로 일반화하지 말 것.'},{'role':'user','content':job['request']}]
   # First let the model request a bounded tool; server validates exact name/arguments.
   response=await c.post(base+'/api/chat',headers=model_headers,json={'model':definition['model'],'messages':messages,'tools':tools,'think':False,'stream':False,'options':{'num_ctx':8192,'num_predict':700,'temperature':0}});response.raise_for_status();message=response.json()['message'];usage.append({k:response.json().get(k) for k in ('prompt_eval_count','eval_count','total_duration')})
   calls=message.get('tool_calls',[])
   if not calls or len(calls)>2 or any(call.get('function',{}).get('name')!=KINDS[kind][1] or call.get('function',{}).get('arguments',{})!={} for call in calls):raise RuntimeError('Model did not request valid read-only tool')
   messages.append(message)
   messages.append({'role':'tool','tool_name':KINDS[kind][1],'content':json.dumps(normalized(evidence),ensure_ascii=False)[:24000]})
   response=await c.post(base+'/api/chat',headers=model_headers,json={'model':definition['model'],'messages':messages,'think':False,'stream':False,'options':{'num_ctx':8192,'num_predict':1000,'temperature':0.1}});response.raise_for_status()
   usage.append({k:response.json().get(k) for k in ('prompt_eval_count','eval_count','total_duration')})
   result={**job,'usage':usage,'evidence_at':start,'evidence':evidence,'assessment':response.json()['message']['content'][:8000],'authority':'read-only; no changes applied','assessment_status':'draft_requires_review'}
   status='completed'
 except Exception as e:status='error';result={**job,'error_type':type(e).__name__,'message':str(e)[:300] if not isinstance(e,httpx.HTTPError) else 'Operational upstream failed'}
 with connect() as db:db.execute('UPDATE runs SET status=?,finished=?,result=? WHERE id=?',(status,time.time(),json.dumps(result,ensure_ascii=False),ident))
 audit('agent:'+role,'run_finished',{'run_id':ident,'status':status})

async def heartbeat():
 while True:
  with connect() as db:db.execute('INSERT OR REPLACE INTO runtime_state VALUES(?,?)',('runner',json.dumps({'heartbeat':time.time(),'model_configured':bool(os.getenv('LLM_URL')),'models':models()})))
  await asyncio.sleep(5)

def next_job():
 rows,_=definitions();now=time.time()
 with connect() as db:
  db.execute('BEGIN IMMEDIATE')
  row=db.execute("SELECT * FROM runs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
  if row:
   try:enabled=read(row['role'])['enabled']
   except Exception:enabled=False
   if not enabled:
    db.execute("UPDATE runs SET status='cancelled',finished=? WHERE id=?",(now,row['id']));return None
   db.execute("UPDATE runs SET status='running',started=? WHERE id=?",(now,row['id']))
   return row['role'],row['id'],json.loads(row['result'])
  for d in rows:
   if not d['enabled']:continue
   last=db.execute('SELECT started FROM runs WHERE role=? ORDER BY id DESC LIMIT 1',(d['id'],)).fetchone()
   if last and last[0]>now-d['interval']:continue
   job={'definition':d,'trigger':'schedule','actor':'scheduler','request':'현재 운영 상태를 확인하고 한국어로 근거·미확인 범위·권장 조치를 보고하세요.'}
   cur=db.execute('INSERT INTO runs(role,status,started,result) VALUES(?,?,?,?)',(d['id'],'running',now,json.dumps(job,ensure_ascii=False)))
   return d['id'],cur.lastrowid,job
 return None

async def main():
 init()
 # One runner per data volume. A restart marks interrupted work explicitly.
 from .db import ROOT
 with (ROOT/'runner.lock').open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with connect() as db:db.execute("UPDATE runs SET status='interrupted',finished=? WHERE status='running'",(time.time(),))
  beat=asyncio.create_task(heartbeat())
  try:
   while True:
    job=next_job()
    if job:await run(*job)
    else:await asyncio.sleep(5)
  finally:beat.cancel()
if __name__=='__main__':asyncio.run(main())
