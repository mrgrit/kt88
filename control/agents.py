"""Native skill files are the source of truth for bounded operation agents."""
import hashlib,json,os,re,threading,time
from pathlib import Path
from typing import Literal
import yaml
from fastapi import APIRouter,HTTPException,Request
from pydantic import BaseModel,Field
from . import auth
from .db import connect,audit

router=APIRouter(prefix='/_kt88/api')
WORKSPACE=Path(os.getenv('AGENT_WORKSPACE','/workspace'))
LOCK=threading.RLock()
KINDS={'platform-health':('서비스 운영','platform_health','/_kt88/agent/health'),'soc-triage':('SOC 분석','siem_alerts','/_kt88/agent/siem')}
SLUG=re.compile(r'^[a-z][a-z0-9-]{1,47}$')

def models():return [s.strip() for s in os.getenv('AGENT_MODELS','qwen3:8b,qwen3:14b').split(',') if re.fullmatch(r'[A-Za-z0-9_.:/-]{1,100}',s.strip())]

class Definition(BaseModel):
 name:str=Field(min_length=1,max_length=80)
 description:str=Field(min_length=1,max_length=300)
 kind:Literal['platform-health','soc-triage']
 model:str=Field(min_length=1,max_length=100)
 interval:int=Field(ge=60,le=86400,default=900)
 enabled:bool=True
 instructions:str=Field(min_length=10,max_length=12000)
 version:str|None=None

def skill_path(ident):
 if not SLUG.fullmatch(ident):raise HTTPException(422,'ID는 영문 소문자·숫자·하이픈으로 2~48자입니다.')
 base=WORKSPACE/'.agents/skills';p=base/ident/'SKILL.md'
 if not p.resolve().is_relative_to(base.resolve()) or p.is_symlink() or p.parent.is_symlink():raise HTTPException(422,'허용되지 않은 스킬 경로입니다.')
 return p

def read(ident):
 p=skill_path(ident)
 if not p.exists():raise HTTPException(404,'에이전트 정의가 없습니다.')
 if p.stat().st_size>20000:raise HTTPException(422,'스킬 파일이 너무 큽니다.')
 raw=p.read_text();parts=raw.split('---',2)
 try:
  front=yaml.safe_load(parts[1]);meta=front.get('metadata',{});kind=meta.get('kt88-kind',ident)
  if kind not in KINDS:raise ValueError()
  d=Definition(name=meta.get('kt88-display-name',KINDS[kind][0]),description=front['description'],kind=kind,model=meta.get('kt88-model',os.getenv('LLM_MODEL','qwen3:8b')),interval=meta.get('kt88-interval',900),enabled=meta.get('kt88-enabled',True),instructions=parts[2].strip())
 except (ValueError,TypeError,KeyError,IndexError,AttributeError,yaml.YAMLError):raise HTTPException(422,'SKILL.md 형식을 확인하세요.')
 return {'id':ident,**d.model_dump(exclude={'version'}),'version':hashlib.sha256(raw.encode()).hexdigest(),'source':f'.agents/skills/{ident}/SKILL.md','persona':f'.claude/agents/{ident}.md','tool':KINDS[kind][1],'authority':'read-only'}

def definitions():
 rows=[];issues=[]
 base=WORKSPACE/'.agents/skills'
 if base.exists():
  for p in sorted(base.glob('*/SKILL.md')):
   try:rows.append(read(p.parent.name))
   except HTTPException as e:issues.append({'id':p.parent.name,'message':e.detail})
 return rows,issues

def write(ident,data):
 p=skill_path(ident)
 if data.model not in models():raise HTTPException(422,'설치된 모델 목록에서 선택하세요.')
 with LOCK:
  if p.exists() and data.version!=read(ident)['version']:raise HTTPException(409,'정의가 변경되었습니다. 새로고침 후 수정하세요.')
  if not p.exists() and len(definitions()[0])>=24:raise HTTPException(422,'에이전트는 최대 24개입니다.')
  meta={'kt88-kind':data.kind,'kt88-display-name':data.name,'kt88-model':data.model,'kt88-interval':data.interval,'kt88-enabled':data.enabled}
  body='---\n'+yaml.safe_dump({'name':ident,'description':data.description,'metadata':meta},allow_unicode=True,sort_keys=False)+'---\n\n'+data.instructions.strip()+'\n'
  persona=WORKSPACE/'.claude/agents'/f'{ident}.md'
  if persona.is_symlink() or not persona.resolve().is_relative_to((WORKSPACE/'.claude/agents').resolve()):raise HTTPException(422,'허용되지 않은 페르소나 경로입니다.')
  p.parent.mkdir(parents=True,exist_ok=True);persona.parent.mkdir(parents=True,exist_ok=True)
  text='---\n'+yaml.safe_dump({'name':ident,'description':data.description},allow_unicode=True,sort_keys=False)+'---\n\nAGENTS.md 및 '+f'.agents/skills/{ident}/SKILL.md'+'를 읽고 역할과 보고 형식을 따르세요. 운영 도구 권한은 서버가 결정합니다.\n'
  tmp=persona.with_suffix('.tmp');tmp.write_text(text);tmp.replace(persona)
  tmp=p.with_suffix('.tmp');tmp.write_text(body);tmp.replace(p)
 return read(ident)

@router.get('/agents')
def list_agents(request:Request):
 auth.user(request);rows,issues=definitions()
 with connect() as db:
  for a in rows:
   row=db.execute('SELECT id,status,started,finished FROM runs WHERE role=? ORDER BY id DESC LIMIT 1',(a['id'],)).fetchone();a['last_run']=dict(row) if row else None
  heartbeat=db.execute("SELECT value FROM runtime_state WHERE key='runner'").fetchone()
 return {'agents':rows,'issues':issues,'models':models(),'runner':json.loads(heartbeat[0]) if heartbeat else None}

@router.put('/agents/{ident}')
def save_agent(ident:str,data:Definition,request:Request):
 u=auth.user(request,('admin',));result=write(ident,data);audit(u['username'],'agent_definition_saved',{'id':ident,'version':result['version'],'enabled':data.enabled});return result

class Task(BaseModel):
 request:str=Field(default='현재 상태를 확인하고 근거·미확인 범위·권장 조치를 보고하세요.',min_length=1,max_length=2000)

@router.post('/agents/{ident}/run',status_code=202)
def queue_agent(ident:str,data:Task,request:Request):
 u=auth.user(request,('admin','operator'));d=read(ident)
 if not d['enabled']:raise HTTPException(409,'중지된 에이전트입니다. 정의에서 활성화하세요.')
 with connect() as db:
  db.execute('BEGIN IMMEDIATE')
  if db.execute("SELECT 1 FROM runs WHERE role=? AND status IN ('running','queued')",(ident,)).fetchone():raise HTTPException(409,'이미 진행 중이거나 대기 중인 작업이 있습니다.')
  if db.execute("SELECT count(*) FROM runs WHERE status='queued'").fetchone()[0]>=24:raise HTTPException(429,'대기 작업이 많습니다.')
  meta={'definition':d,'request':data.request,'trigger':'manual','actor':u['username']}
  cur=db.execute('INSERT INTO runs(role,status,started,result) VALUES(?,?,?,?)',(ident,'queued',time.time(),json.dumps(meta,ensure_ascii=False)))
 audit(u['username'],'agent_run_queued',{'id':ident,'run_id':cur.lastrowid});return {'id':cur.lastrowid,'status':'queued'}

@router.get('/runs/{ident}')
def run_detail(ident:int,request:Request):
 auth.user(request)
 with connect() as db:row=db.execute('SELECT * FROM runs WHERE id=?',(ident,)).fetchone()
 if not row:raise HTTPException(404)
 result=dict(row);result['result']=json.loads(result['result'] or '{}');return result
