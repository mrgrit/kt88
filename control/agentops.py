"""kt66 organization/skills UI contract adapted to standard native files and kt88 auth."""
import copy,json,time
from pathlib import Path
import yaml
from fastapi import APIRouter,Body,Depends,HTTPException,Request
from fastapi.responses import FileResponse,PlainTextResponse
from . import auth,agents,native
from .db import connect,audit

STATIC=Path(__file__).parent/'static'
def session(request:Request):return auth.user(request,('admin',) if request.method not in ('GET','HEAD') else ('admin','operator','viewer'))
router=APIRouter(prefix='/_kt88/agentops',dependencies=[Depends(session)])

def worker(d):
 return {'id':d['id'],'name':d['name'],'team':d['team'],'runtime':'ollama','model':d['model'],'autonomy':'L1','security_role':d['kind'],'floor':'운영사무실','zone':'management','assets':d['assets'],'loops':['schedule-'+d['id']] if d['enabled'] else [],'enabled':d['enabled']}

def harness():
 return {'defaults':{'constrain':{'permission':{'platform_health':'read','siem_alerts':'read','shell':'deny','security_write':'deny'}},'inform':{'surfaces':['AGENTS.md','.claude/agents/*.md','.agents/skills/*/SKILL.md']},'verify':{'gates':['도구 이름·인자 검증','실행 근거 기록']},'correct':{},'escalate':{'to':'운영자'}},'security':{'roles':{k:{'label':v[0],'tools':[v[1]]} for k,v in agents.KINDS.items()}}}

def org():
 value=native.organization();rows,errors=agents.definitions();value=copy.deepcopy(value)
 for t in value['teams']['teams']:t['members']=[d['id'] for d in rows if d['team']==t['id']]
 for dept in value['departments']['departments']:dept['teams']=[t['id'] for t in value['teams']['teams'] if t['department']==dept['id']]
 value.update(roster={'workers':[worker(d) for d in rows],'runtimes':{'ollama':{'name':'Thor · Open model','note':'실제 설치된 오픈모델 운영 실행기'}},'models':{m:{'name':m,'endpoint':'thor'} for m in agents.models()},'endpoints':{'thor':{'base_url':'운영 환경에 설정된 전용 추론 경로'}}},harness=harness(),personas=[d['id'] for d in rows],loops=['schedule-'+d['id'] for d in rows],loop_details=[{'id':'schedule-'+d['id'],'owner':d['id'],'cadence':str(d['interval'])+'초'} for d in rows],skill_catalog=native.library(),errors=[str(e) for e in errors])
 return value

@router.get('/')
def console():return FileResponse(STATIC/'agentops/index.html')
@router.get('/static/{name}')
def static(name:str):
 if name not in ('agentops.js','agentops.css','settings.js','teams.js'):raise HTTPException(404)
 return FileResponse(STATIC/'agentops'/name)
@router.get('/api/org')
def organization():return org()
@router.get('/api/roster')
def roster():return org()['roster']

@router.get('/api/file/{name}',response_class=PlainTextResponse)
def get_file(name:str):
 value=org()
 if name in ('company','departments','teams','roster','harness'):return yaml.safe_dump(value[name],allow_unicode=True,sort_keys=False)
 if name=='graph':return json.dumps(value[name],ensure_ascii=False,indent=2)
 if name.startswith('persona:'):return native.path('.claude/agents/'+native.identifier(name[8:])+'.md').read_text()
 if name.startswith('loop:schedule-'):
  d=agents.read(name[len('loop:schedule-'):]);return yaml.safe_dump({'id':'schedule-'+d['id'],'owner':d['id'],'interval':d['interval'],'enabled':d['enabled'],'steps':[{'tool':d['tool']}]},allow_unicode=True)
 raise HTTPException(404)

@router.post('/api/file/{name}')
def save_file(name:str,request:Request,body:dict=Body(...)):
 text=body.get('text','')
 if not isinstance(text,str) or len(text)>40000:raise HTTPException(422,'설정 크기 제한 초과')
 with agents.LOCK:
  try:
   if name in ('company','departments','teams','graph'):
    value=native.organization();parsed=json.loads(text) if name=='graph' else yaml.safe_load(text)
    if not isinstance(parsed,dict):raise ValueError('설정은 객체여야 합니다.')
    value[name]=parsed;native.save_org(value)
   elif name.startswith('persona:'):
    ident=native.identifier(name[8:]);current=agents.read(ident);front,instructions=native.split(text);meta=front.get('metadata',{})
    data=agents.Definition(**{**current,'description':front.get('description',current['description']),'instructions':instructions,'skills':front.get('skills',[]),'kind':meta.get('kt88-kind',current['kind']),'model':meta.get('kt88-model',current['model']),'interval':meta.get('kt88-interval',current['interval']),'enabled':meta.get('kt88-enabled',current['enabled']),'team':meta.get('kt88-team',current['team']),'assets':meta.get('kt88-assets',current['assets'])})
    agents.write(ident,data)
   elif name.startswith('loop:schedule-'):
    ident=name[len('loop:schedule-'):];current=agents.read(ident);value=yaml.safe_load(text)
    if value.get('owner')!=ident or value.get('id')!='schedule-'+ident or value.get('steps')!=[{'tool':current['tool']}]:raise ValueError('담당자와 서버 도구 범위는 유지하세요.')
    agents.write(ident,agents.Definition(**{**current,'interval':value['interval'],'enabled':value['enabled']}))
   else:raise HTTPException(422,'근무자는 R&R 화면에서, 도구 권한은 서버 설정에서 관리합니다.')
  except (ValueError,TypeError,KeyError,yaml.YAMLError) as e:raise HTTPException(422,str(e)[:300])
 audit(session(request)['username'],'agentops_file_saved',{'name':name})
 return {'ok':True,'errors':org()['errors']}

@router.post('/api/worker')
def add_worker(request:Request,body:dict=Body(...)):
 ident=native.identifier(body.get('id'));kind=body.get('security_role','platform-health')
 with agents.LOCK:
  if ident in {d['id'] for d in agents.definitions()[0]}:raise HTTPException(409,'이미 등록된 에이전트입니다.')
  if body.get('runtime','ollama')!='ollama' or body.get('autonomy','L1')!='L1':raise HTTPException(422,'현재 운영 실행기는 오픈모델 읽기 조사 권한입니다.')
  data=agents.Definition(name=body.get('name',ident),description=body.get('name',ident)+' 담당 운영 에이전트',kind=kind,model=body.get('model',agents.models()[0]),enabled=False,instructions='담당 범위와 연결 스킬을 확인하고, 허용된 읽기 도구로 조사한 근거와 미확인 범위를 보고하세요.',team=body.get('team',''))
  agents.write(ident,data)
 audit(session(request)['username'],'agent_registered',{'id':ident});return {'id':ident,'note':'표준 페르소나를 생성했습니다. R&R·스킬 연결과 정기 작업을 설정하세요.'}

@router.patch('/api/worker/{ident}')
def patch_worker(ident:str,request:Request,body:dict=Body(...)):
 allowed={'name','runtime','model','autonomy','team','security_role'}
 if set(body)-allowed or body.get('runtime','ollama')!='ollama' or body.get('autonomy','L1')!='L1':raise HTTPException(422,'지원하지 않는 설정입니다.')
 with agents.LOCK:
  d=agents.read(ident);change={k:v for k,v in body.items() if k in ('name','model','team')}
  if 'security_role' in body:change['kind']=body['security_role']
  result=agents.write(ident,agents.Definition(**{**d,**change}))
 audit(session(request)['username'],'agent_updated',{'id':ident});return {'ok':True,'worker':worker(result)}

@router.delete('/api/worker/{ident}')
def delete_worker(ident:str,request:Request):
 with agents.LOCK:
  d=agents.read(ident)
  with connect() as db:
   if db.execute("SELECT 1 FROM runs WHERE role=? AND status IN ('queued','running')",(ident,)).fetchone():raise HTTPException(409,'진행 중인 작업 완료 후 삭제하세요.')
  agents.write(ident,agents.Definition(**{**d,'enabled':False}))
  p=native.path('.claude/agents/'+ident+'.md');front,body=native.split(p.read_text());front['metadata']['kt88-archived']=True
  native.write(str(p.relative_to(native.root())),'---\n'+yaml.safe_dump(front,allow_unicode=True,sort_keys=False)+'---\n\n'+body+'\n')
 audit(session(request)['username'],'agent_archived',{'id':ident});return {'ok':True}

@router.get('/api/skills')
def skills():return native.library()
@router.get('/api/skills/{name}')
def skill(name:str):return native.skill(name)
@router.post('/api/skills')
def create_skill(request:Request,body:dict=Body(...)):
 with agents.LOCK:
  if native.skill_path(body.get('name')).exists():raise HTTPException(409,'이미 존재하는 스킬입니다.')
  value=native.save_skill(body['name'],body.get('content'))
 audit(session(request)['username'],'skill_created',{'name':value['name'],'sha256':value['sha256']});return value
@router.put('/api/skills/{name}')
def edit_skill(name:str,request:Request,body:dict=Body(...)):
 with agents.LOCK:
  value=native.save_skill(name,body.get('content'),body.get('sha256'))
  for d in agents.definitions()[0]:
   if name in d.get('skills',[]):native.export_agent(d)
 audit(session(request)['username'],'skill_updated',{'name':name,'sha256':value['sha256']});return value
@router.delete('/api/skills/{name}')
def delete_skill(name:str,request:Request,body:dict=Body(...)):
 with agents.LOCK:
  value=native.skill(name)
  if value['sha256']!=body.get('sha256'):raise HTTPException(409,'스킬이 변경되었습니다.')
  # Include archived personas, just as kt66 did: do not break restored agents.
  for p in (native.root()/'.claude/agents').glob('*.md'):
   if name in native.split(p.read_text())[0].get('skills',[]):raise HTTPException(409,'먼저 연결된 에이전트·보관 페르소나에서 스킬을 해제하세요.')
  native.backup(value['path']);native.skill_path(name).unlink()
  for relative in ('.claude/skills/'+name+'/SKILL.md','.hermes/skills/'+name+'/SKILL.md'):native.path(relative).unlink(missing_ok=True)
 audit(session(request)['username'],'skill_deleted',{'name':name});return {'deleted':True}

def assignment(ident):
 d=agents.read(ident);organization=org();team=next((t for t in organization['teams']['teams'] if t['id']==d['team']),{})
 department=next((t for t in organization['departments']['departments'] if t['id']==team.get('department')),{})
 return {'worker':worker(d),'description':d['description'],'instructions':d['instructions'],'skills':d['skills'],'sha256':d['version'],'team':team,'department':department,'authorization':{'tools':[d['tool']],'mode':'read-only'},'policy':{'kind':d['kind']},'available_tools':[d['tool']],'sources':[d['source'],*[native.skill(n)['path'] for n in d['skills']]]}
@router.get('/api/assignments/{ident}')
def get_assignment(ident:str):return assignment(ident)
@router.put('/api/assignments/{ident}')
def put_assignment(ident:str,request:Request,body:dict=Body(...)):
 with agents.LOCK:
  d=agents.read(ident)
  if body.get('sha256')!=d['version']:raise HTTPException(409,'설정이 변경되었습니다.')
  if set(body.get('loops',[]))-{'schedule-'+ident}:raise HTTPException(422,'다른 에이전트의 정기 작업을 연결할 수 없습니다.')
  agents.write(ident,agents.Definition(**{**d,'description':body['description'],'instructions':body['instructions'],'skills':body['skills'],'assets':body.get('assets',[]),'enabled':'schedule-'+ident in body.get('loops',[])}))
 audit(session(request)['username'],'agent_assignment_saved',{'id':ident});return assignment(ident)

@router.get('/api/activation')
def activation():return {'workers':{d['id']:{'version':d['version'],'source':d['source']} for d in agents.definitions()[0]}}
@router.post('/api/render')
def render(request:Request):
 for d in agents.definitions()[0]:agents.write(d['id'],agents.Definition(**d))
 audit(session(request)['username'],'native_profiles_exported',{})
 return {'ok':True,'stdout':json.dumps(activation(),ensure_ascii=False,indent=2)}
@router.get('/api/loop-status')
def loop_status():
 with connect() as db:
  heartbeat=db.execute("SELECT value FROM runtime_state WHERE key='runner'").fetchone();active=[r[0] for r in db.execute("SELECT role FROM runs WHERE status='running'")];queue={r[0]:r[1] for r in db.execute('SELECT status,count(*) FROM runs GROUP BY status')}
 value=json.loads(heartbeat[0]) if heartbeat else {}
 return {'status':'running' if value else 'not_started','heartbeat_recent':time.time()-value.get('heartbeat',0)<45,'active_workers':active,'queue':queue}
@router.get('/api/config-audit')
def config_audit():
 rows,errors=agents.definitions()
 return {'errors':[str(e) for e in errors],'files':[{'path':'.claude/agents/*.md','screen':'근무자·R&R','purpose':'역할과 연결 스킬','support':'편집'},{'path':'.agents/skills/*/SKILL.md','screen':'업무 스킬','purpose':'재사용 절차','support':'편집'},{'path':'.codex/agents/*.toml · .claude/skills/ · .hermes/profiles/','screen':'적용','purpose':'각 프레임워크 표준 설정','support':'원본에서 반영'}],'workers':[{'name':d['name'],'current':native.path('.codex/agents/'+d['id']+'.toml').exists()} for d in rows],'notes':['조직·팀·KPI·복원 기록은 플랫폼 DB의 운영 데이터입니다. 역할과 스킬은 표준 파일이 원본입니다.','현재 자동 업무는 Thor 오픈모델 실행기입니다. Claude Code·Codex·Hermes CLI를 실행했다고 표시하지 않습니다.']}
@router.get('/api/backups')
def backups():
 with connect() as db:rows=db.execute('SELECT id,path,length(content) AS size,created AS mtime FROM config_backups ORDER BY id DESC LIMIT 60').fetchall()
 return {'backups':[{'file':str(r['id'])+' · '+r['path'],'size':r['size'],'mtime':r['mtime']} for r in rows]}
@router.post('/api/restore')
def restore(request:Request,name:str):
 try:ident=int(name.split(' · ')[0])
 except ValueError:raise HTTPException(422)
 with connect() as db:row=db.execute('SELECT * FROM config_backups WHERE id=?',(ident,)).fetchone()
 if not row:raise HTTPException(404)
 p=row['path']
 if p=='organization':native.save_org(json.loads(row['content']))
 elif p.startswith('.agents/skills/'):
  skill_name=Path(p).parent.name;current=native.skill_path(skill_name);native.save_skill(skill_name,row['content'],native.sha(current.read_text()) if current.exists() else None)
 elif p.startswith('.claude/agents/'):save_file('persona:'+Path(p).stem,request,{'text':row['content']})
 else:raise HTTPException(422,'복원 대상이 아닙니다.')
 audit(session(request)['username'],'configuration_restored',{'backup':ident});return {'ok':True}
