"""The inherited kt66 execution observatory, backed by actual kt88 run records."""
import hashlib,json,time
from collections import Counter
from fastapi import APIRouter,Depends,HTTPException,Query,Request
from fastapi.responses import FileResponse
from .agentops import STATIC,session,worker,loop_status
from . import agents
from .db import connect
router=APIRouter(dependencies=[Depends(session)])

@router.get('/_kt88/evidence/')
def screen():return FileResponse(STATIC/'evidence/index.html')
@router.get('/_kt88/evidence/static/{name}')
def static(name:str):
 if name not in ('agent-control.css','agent-control.js','agent-sprites.js'):raise HTTPException(404)
 return FileResponse(STATIC/'evidence'/name)

def unpack(row):
 data=json.loads(row['result'] or '{}');d=data.get('definition',{});usage=data.get('usage',[])
 known=bool(usage) and all(u.get('prompt_eval_count') is not None and u.get('eval_count') is not None for u in usage)
 count={'input':sum(u.get('prompt_eval_count',0) or 0 for u in usage),'output':sum(u.get('eval_count',0) or 0 for u in usage)}
 proof={'state':'observed' if data.get('evidence') is not None else 'failed' if row['status']=='error' else 'unverified','observations':[{'tool':d.get('tool','operational_read'),'reference':'result.json'}] if data.get('evidence') is not None else [],'skills':[{'name':s['name'],'resource':'SKILL.md','reference':'result.json'} for s in data.get('loaded_skills',[])],'checks':[],'errors':[],'note':'실제 도구 응답과 실행 시점 스킬 읽기 기록. 모델의 자기 보고와 구분합니다.'}
 status={'error':'failed','interrupted':'unknown'}.get(row['status'],row['status']);findings=[]
 if status in ('failed','unknown'):findings.append({'severity':'medium','title':'실행 실패 또는 종료 미확인','evidence_refs':['result.json']})
 return {'id':str(row['id']),'worker':row['role'],'kind':'periodic:'+row['role'] if data.get('trigger')=='schedule' else 'manual','trigger':'periodic' if data.get('trigger')=='schedule' else 'manual','status':status,'started':row['started'],'finished':row['finished'],'updated':row['finished'] or row['started'],'job_id':str(row['id']),'session_id':str(row['id']),'runtime':'Thor / Ollama','model':d.get('model'),'attempt':1,'usage':{**count,'known':known,'total':sum(count.values()) if known else None,'cache_read':0,'cache_write':0,'reasoning_subset':None},'findings':findings,'execution_evidence':proof},data

@router.get('/_kt88/agentops/api/agent-control/runs')
def runs(worker:str='',trigger:str='',status:str='',hours:int=Query(24,ge=0,le=8760),q:str=Query('',max_length=150),limit:int=Query(40,ge=1,le=100),cursor:int|None=None):
 conditions=['1=1'];params=[]
 if worker:conditions.append('role=?');params.append(worker)
 if hours:conditions.append('started>?');params.append(time.time()-hours*3600)
 with connect() as db:rows=db.execute('SELECT * FROM runs WHERE '+' AND '.join(conditions)+' ORDER BY id DESC',params).fetchall()
 items=[unpack(r)[0] for r in rows];items=[r for r in items if (not trigger or r['trigger']==trigger) and (not status or r['status']==status or status=='attention' and r['status'] in ('failed','unknown','needs_review')) and (not q or q.lower() in (r['worker']+' '+r['kind']+' '+r['status']).lower())]
 summary={'runs':len(items),'statuses':dict(Counter(r['status'] for r in items)),'tokens':sum(r['usage']['total'] or 0 for r in items),'usage_known':sum(r['usage']['known'] for r in items),'usage_unknown':sum(not r['usage']['known'] for r in items)}
 selected=[r for r in items if cursor is None or int(r['id'])<cursor];page=selected[:limit];engine=loop_status()
 return {'items':page,'total':len(items),'next_cursor':int(page[-1]['id']) if len(selected)>limit else None,'summary':summary,'engine':{'status':engine['status'],'stale':not engine['heartbeat_recent']},'source':{'status':'ok','errors':[],'job_count':len(items),'run_count':len(items)}}

def detail(ident):
 with connect() as db:row=db.execute('SELECT * FROM runs WHERE id=?',(ident,)).fetchone()
 if not row:raise HTTPException(404)
 run,data=unpack(row);definition=data.get('definition',{});receipts=data.get('receipts',[])
 text=json.dumps(data,ensure_ascii=False,indent=2)
 timeline=[{'type':'tool','name':r.get('tool','unknown'),'at':r['at'],'source':'result.json#'+str(i),'arguments':r.get('arguments',{}),'authorization':{'mode':'read'},'result':r.get('result',{})} for i,r in enumerate(receipts) if r.get('type')=='tool']
 if not timeline and data.get('evidence') is not None:timeline=[{'type':'tool','name':definition.get('tool','operational_read'),'at':data.get('evidence_at',row['started']),'source':'result.json','arguments':{},'authorization':{'mode':'read'},'result':{'status':'observed','evidence':data['evidence'],'note':'이전 실행: 상세 도구 타임라인은 미수집'}}]
 return {'run':run,'request':{'captured':bool(data.get('request')),'requested_at':row['started'],'trigger_payload':{'trigger':data.get('trigger'),'actor':data.get('actor')},'source':'platform.sqlite / runs','record':{'prompt':data.get('request')}},'declared':[],'timeline':timeline,'outcome':{'body':data.get('assessment') or data.get('message'),'verification':{'status':data.get('assessment_status'),'authority':data.get('authority')}},'coverage':{'issues':['비공개 내부 추론·OS 전체 파일 접근은 수집하지 않습니다.']},'execution_evidence':run['execution_evidence'],'policy':{'effective':{'autonomy':'L1','permission':{definition.get('tool','operational_read'):'read'},'sandbox':{'shell':False,'changes':False}},'version':definition.get('version'),'source':definition.get('source'),'native':{'persona':definition.get('persona'),'skills':definition.get('skills',[])},'source_files':data.get('loaded_skills',[])},'accesses':[{'operation':'read','tool':'skill_load','path':s['path'],'evidence_ref':'result.json','basis':'실행기가 읽은 스킬 원문','sha256':s['sha256']} for s in data.get('loaded_skills',[])],'artifacts':[{'name':'result.json','bytes':len(text.encode())}],'context':{},'attempts':[run],'previous_cycle':None}

@router.get('/_kt88/agentops/api/agent-control/runs/{ident}')
def run(ident:int):return detail(ident)
@router.get('/_kt88/agentops/api/agent-control/runs/{ident}/artifacts/{name}')
def artifact(ident:int,name:str):
 if name!='result.json':raise HTTPException(404)
 with connect() as db:row=db.execute('SELECT result FROM runs WHERE id=?',(ident,)).fetchone()
 if not row:raise HTTPException(404)
 text=row[0];return {'text':text,'truncated':False,'sha256':hashlib.sha256(text.encode()).hexdigest()}
@router.get('/_kt88/agentops/api/agent-control/schema')
def schema():return {'name':'kt88.activity.v1','source':'platform.sqlite/runs','fields':['run','request','timeline','policy','accesses','artifacts','outcome'],'authority':'read-only'}
