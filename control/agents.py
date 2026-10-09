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
 skills:list[str]=Field(default_factory=list,max_length=20)
 team:str=Field(default="",max_length=48)
 assets:list[str]=Field(default_factory=list,max_length=30)

def skill_path(ident):
 if not SLUG.fullmatch(ident):raise HTTPException(422,'ID는 영문 소문자·숫자·하이픈으로 2~48자입니다.')
 base=WORKSPACE/'.agents/skills';p=base/ident/'SKILL.md'
 if not p.resolve().is_relative_to(base.resolve()) or p.is_symlink() or p.parent.is_symlink():raise HTTPException(422,'허용되지 않은 스킬 경로입니다.')
 return p

def read(ident):
 from . import native
 p=native.path('.claude/agents/'+native.identifier(ident)+'.md')
 front={}
 if p.exists():
  raw=p.read_text();front,instructions=native.split(raw)
 if 'kt88-kind' not in front.get('metadata',{}):
  p=skill_path(ident)
  if not p.exists():raise HTTPException(404,'에이전트 정의가 없습니다.')
  raw=p.read_text();front,instructions=native.split(raw)
 meta=front.get('metadata',{});kind=meta.get('kt88-kind',ident)
 if kind not in KINDS:raise HTTPException(422,'지원하지 않는 보안 직무입니다.')
 try:
  d=Definition(name=meta.get('kt88-display-name',KINDS[kind][0]),description=front['description'],kind=kind,model=meta.get('kt88-model',os.getenv('LLM_MODEL','qwen3:8b')),interval=meta.get('kt88-interval',900),enabled=meta.get('kt88-enabled',True),instructions=instructions,skills=front.get('skills',[ident] if p.name=='SKILL.md' else []),team=meta.get('kt88-team','soc-team' if kind=='soc-triage' else 'systems-team'),assets=meta.get('kt88-assets',[]))
 except (ValueError,TypeError,KeyError):raise HTTPException(422,'에이전트 정의 형식 오류')
 return {'id':ident,**d.model_dump(exclude={'version'}),'version':hashlib.sha256(raw.encode()).hexdigest(),'source':str(p.relative_to(WORKSPACE)),'persona':f'.claude/agents/{ident}.md','tool':KINDS[kind][1],'authority':'read-only'}

def definitions():
 from . import native
 rows=[];issues=[];ids=set()
 for p in (WORKSPACE/'.claude/agents').glob('*.md'):
  try:
   front,_=native.split(p.read_text())
   if front.get('metadata',{}).get('kt88-kind') and not front.get('metadata',{}).get('kt88-archived'):ids.add(p.stem)
  except HTTPException:issues.append({'id':p.stem,'message':'페르소나 파일 형식 오류'})
 for p in (WORKSPACE/'.agents/skills').glob('*/SKILL.md'):
  try:
   front,_=native.split(p.read_text())
   if front.get('metadata',{}).get('kt88-kind'):ids.add(p.parent.name)
   elif p.parent.name in KINDS:
    persona=WORKSPACE/'.claude/agents'/f'{p.parent.name}.md'
    meta=native.split(persona.read_text())[0].get('metadata',{}) if persona.exists() else {}
    if not meta.get('kt88-kind'):ids.add(p.parent.name)
  except HTTPException:continue
 for ident in sorted(ids):
  try:rows.append(read(ident))
  except HTTPException as error:issues.append({'id':ident,'message':error.detail})
 return rows,issues

def write(ident,data):
 from . import native
 native.identifier(ident)
 if data.model not in models():raise HTTPException(422,'설치된 모델 목록에서 선택하세요.')
 for name in data.skills:native.skill(name)
 if data.team and data.team not in {t['id'] for t in native.organization()['teams']['teams']}:raise HTTPException(422,'등록된 팀을 선택하세요.')
 with LOCK:
  try:existing=read(ident)
  except HTTPException as error:
   if error.status_code!=404:raise
   existing=None
  if existing and data.version!=existing['version']:raise HTTPException(409,'정의가 변경되었습니다. 새로고침 후 수정하세요.')
  if not existing and len(definitions()[0])>=24:raise HTTPException(422,'에이전트는 최대 24개입니다.')
  meta={'kt88-kind':data.kind,'kt88-display-name':data.name,'kt88-model':data.model,'kt88-interval':data.interval,'kt88-enabled':data.enabled,'kt88-team':data.team or ('soc-team' if data.kind=='soc-triage' else 'systems-team'),'kt88-assets':data.assets}
  body='---\n'+yaml.safe_dump({'name':ident,'description':data.description,'model':'inherit','tools':['Read'],'skills':data.skills,'metadata':meta},allow_unicode=True,sort_keys=False)+'---\n\n'+data.instructions.strip()+'\n'
  native.write('.claude/agents/'+ident+'.md',body)
  # Remove legacy agent metadata from the reusable skill while preserving its procedure.
  legacy=skill_path(ident)
  if legacy.exists():
   text=legacy.read_text();front,procedure=native.split(text)
   if any(k.startswith('kt88-') for k in front.get('metadata',{})):
    front['metadata']={k:v for k,v in front.get('metadata',{}).items() if not k.startswith('kt88-')}
    native.write('.agents/skills/'+ident+'/SKILL.md','---\n'+yaml.safe_dump(front,allow_unicode=True,sort_keys=False)+'---\n\n'+procedure+'\n')
  result=read(ident);native.export_skills();native.export_agent(result)
 return result

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
