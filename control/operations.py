"""Device policy lifecycle, measured NMS/SMS inventory and bounded log search."""
import asyncio
import copy
import fcntl
import ipaddress
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
import httpx
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field
from . import auth
from .db import connect, audit
from .security import secret
from security.policy_model import DEVICES, revision, device_revision, validate_rule, firewall_rules, ips_rules, waf_rules

router=APIRouter(prefix='/_kt88/api')
BASELINES={
 'fw':[{'name':'기본 거부','detail':'기본 INPUT/FORWARD DROP · 기존 연결 추적 · 제한된 ICMP'}, {'name':'웹서비스 허용','detail':'TCP 80/443 → 10.88.32.80, 지정 DNS/HTTPS 반환 경로'}, {'name':'기존 차단 목록','detail':'등록된 차단 CIDR은 사용자 정책보다 먼저 평가'}],
 'ips':[{'name':'ET Open','detail':'이미지 빌드 시 설치한 탐지 규칙 · 엔진 실제 로드 수는 대시보드에서 확인'}, {'name':'운영 차단 규칙','detail':'HTTP IPS 검증 헤더 및 명시적 경로 탐색 패턴 차단'}, {'name':'NFQUEUE','detail':'인라인 검사 · 엔진 중단 시 통과 금지'}],
 'waf':[{'name':'OWASP CRS','detail':'기본 검사 + 요청·응답 검사 · 관리 화면의 확인된 오탐만 제한적 예외'}, {'name':'JSON 및 메서드 검사','detail':'API 경로 메서드 및 JSON 본문 처리'}]}

def directory():
 from .app import POLICIES
 return POLICIES

def read_policy():
 p=directory()/'policy.json'
 value=json.loads(p.read_text()) if p.exists() else {'blocked_cidrs':[],'paranoia':2,'inbound_threshold':5}
 value.setdefault('rules',{})
 for device in DEVICES:value['rules'].setdefault(device,[])
 return value

@contextmanager
def policy_lock():
 directory().mkdir(parents=True,exist_ok=True)
 with (directory()/'policy.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  yield

def write_policy(value):
 tmp=directory()/'policy-api.tmp';tmp.write_text(json.dumps(value,ensure_ascii=False));tmp.replace(directory()/'policy.json')

def check_device(device):
 if device not in DEVICES:raise HTTPException(404,'장비를 찾을 수 없습니다.')

def read_json(name):
 try:return json.loads((directory()/name).read_text())
 except (OSError,ValueError):return {}

def inventory():
 now=time.time();result={};document=read_policy()
 for device in (*DEVICES,'edge'):
  observed=read_json(device+'-telemetry.json');apply=read_json(device+'-status.json')
  age=now-observed.get('observed_at',0);fresh=0<=age<45
  desired=device_revision(document,device) if device in DEVICES else None
  state='unknown' if not observed else 'stale' if not fresh else 'error' if not observed.get('engine',{}).get('alive') or apply.get('status')=='error' else 'pending' if desired and observed.get('applied_revision')!=desired else 'healthy'
  result[device]={**observed,'device':device,'state':state,'fresh':fresh,'age_seconds':round(age) if observed else None,'apply':apply,'desired_revision':desired}
 host=read_json('host-telemetry.json');age=now-host.get('observed_at',0)
 host['state']='unknown' if not host else 'stale' if not 0<=age<45 else 'error' if host.get('error') else 'healthy'
 return result,host

@router.get('/devices/{device}/policies')
def policies(device:str,request:Request):
 auth.user(request);check_device(device);doc=read_policy();items,_=inventory()
 return {'device':device,'version':revision(doc),'rules':doc['rules'][device],'baseline':BASELINES[device],
         'settings':{k:doc[k] for k in ('blocked_cidrs','paranoia','inbound_threshold')},'apply':items[device]['apply'],'desired_revision':device_revision(doc,device)}

class Change(BaseModel):
 version:str=Field(min_length=64,max_length=64)
 rule:dict=Field(default_factory=dict)
 operation:str=Field(pattern='^(create|update|delete|settings)$')
 rule_id:int|None=None
 settings:dict=Field(default_factory=dict)

def changed(device,change,request):
 check_device(device);before=read_policy()
 if revision(before)!=change.version:raise HTTPException(409,'정책이 변경되었습니다. 새로고침한 후 다시 검토하세요.')
 after=copy.deepcopy(before);rules=after['rules'][device]
 if change.operation=='settings':
  if device!='waf' or set(change.settings)!={'paranoia','inbound_threshold'}:raise HTTPException(422,'설정 필드를 확인하세요.')
  if any(type(v) is not int for v in change.settings.values()):raise HTTPException(422,'설정은 정수여야 합니다.')
  after.update(change.settings)
 else:
  index=next((i for i,r in enumerate(rules) if r['id']==change.rule_id),None)
  if change.operation!='create' and index is None:raise HTTPException(404,'정책을 찾을 수 없습니다.')
  if change.operation=='delete':rules.pop(index)
  else:
   if change.operation=='create' and len(rules)>=200:raise HTTPException(422,'장비별 최대 200개 정책입니다.')
   ids={r['id'] for rows in after['rules'].values() for r in rows}
   identifier=change.rule_id
   if change.operation=='create':
    # Preview and save produce the same ID for the same version and input.
    identifier=1000000+int(revision([device,change.version,change.rule])[:12],16)%1000000
    while identifier in ids:identifier=1000000+(identifier-1000000+1)%1000000
   try:r=validate_rule(device,{**change.rule,'id':identifier})
   except (TypeError,ValueError) as error:raise HTTPException(422,str(error))
   # Avoid disabling the administrator's current access by an address rule.
   source=r.get('source') if device!='waf' else r.get('value') if r.get('match')=='source_ip' else None
   if source and r['enabled'] and r['action'] in ('drop','reject','deny'):
    try:
     client=ipaddress.ip_address(request.client.host)
     if client in ipaddress.ip_network(source):raise HTTPException(422,'현재 접속 IP를 차단하는 정책입니다. 별도 관리 경로를 확보한 뒤 콘솔에서 처리하세요.')
    except ValueError:pass
   if index is None:rules.append(r)
   else:rules[index]=r
 try:
  generated={'fw':firewall_rules,'ips':ips_rules,'waf':waf_rules}[device](after)
 except (TypeError,ValueError) as error:raise HTTPException(422,str(error))
 return before,after,generated

@router.post('/devices/{device}/policies/preview')
def preview(device:str,change:Change,request:Request):
 auth.user(request,('admin',))
 before,after,generated=changed(device,change,request)
 return {'device':device,'before':before['rules'][device],'after':after['rules'][device],'settings':{k:after[k] for k in ('paranoia','inbound_threshold')},'generated':generated,'note':'등록 순서대로 평가합니다. 저장 후 엔진 구문 검사와 적용 결과를 확인하세요.'}

@router.post('/devices/{device}/policies')
def create(device:str,change:Change,request:Request):
 return commit(device,change,request,'create')

@router.put('/devices/{device}/policies/{rule_id}')
def update(device:str,rule_id:int,change:Change,request:Request):
 if rule_id!=change.rule_id:raise HTTPException(422,'정책 ID가 다릅니다.')
 return commit(device,change,request,'update')

@router.delete('/devices/{device}/policies/{rule_id}')
def delete(device:str,rule_id:int,change:Change,request:Request):
 if rule_id!=change.rule_id:raise HTTPException(422,'정책 ID가 다릅니다.')
 return commit(device,change,request,'delete')

@router.put('/devices/{device}/settings')
def settings(device:str,change:Change,request:Request):
 return commit(device,change,request,'settings')

def commit(device,change,request,operation):
 user=auth.user(request,('admin',))
 if change.operation!=operation:raise HTTPException(422,'요청 동작이 다릅니다.')
 with policy_lock():
  before,after,_=changed(device,change,request);write_policy(after)
 audit(user['username'],'device_policy_'+operation,{'device':device,'before':before['rules'][device],'after':after['rules'][device], 'settings':{k:after[k] for k in ('paranoia','inbound_threshold')},'revision':device_revision(after,device)})
 return {'ok':True,'version':revision(after),'status':'pending_device_apply','desired_revision':device_revision(after,device)}

async def device_logs(device='all',hours=1,level=0,source='',size=50):
 filters=[{'range':{'timestamp':{'gte':f'now-{hours}h'}}},{'range':{'rule.level':{'gte':level}}}]
 if device=='fw':filters.append({'term':{'data.component':'fw'}})
 elif device=='ips':filters.append({'term':{'rule.groups':'suricata'}})
 elif device=='waf':filters.append({'bool':{'should':[{'term':{'rule.id':'110010'}},{'term':{'rule.groups':'modsecurity'}}],'minimum_should_match':1}})
 if source:
  try:source=str(ipaddress.ip_address(source))
  except ValueError:raise HTTPException(422,'올바른 IP 주소를 입력하세요.')
  filters.append({'bool':{'should':[{'term':{'data.srcip':source}},{'term':{'data.src_ip':source}},{'term':{'data.transaction.client_ip':source}}],'minimum_should_match':1}})
 url=os.getenv('INDEXER_URL','').rstrip('/')
 if not url:raise HTTPException(503,'SIEM 연결이 설정되지 않았습니다.')
 try:
  async with httpx.AsyncClient(timeout=10,verify=os.getenv('INDEXER_CA') or True,trust_env=False) as client:
   response=await client.post(url+'/wazuh-alerts-*/_search',auth=(os.getenv('SIEM_READER_USER','soc-reader'),secret('SIEM_READER_PASSWORD')),json={
    'size':size,'track_total_hits':True,'sort':[{'timestamp':'desc'}],'query':{'bool':{'filter':filters}},
    '_source':['timestamp','rule.id','rule.level','rule.description','rule.groups','agent.name','data.srcip','data.src_ip','data.dest_ip','data.dstip','data.alert.signature','data.alert.action','data.blocked_packets','data.transaction.client_ip'],
    'aggs':{'timeline':{'date_histogram':{'field':'timestamp','fixed_interval':'5m','min_doc_count':0}},'high':{'filter':{'range':{'rule.level':{'gte':10}}}}}})
   response.raise_for_status();value=response.json()
   return {'total':value['hits']['total']['value'],'window_hours':hours,'alerts':[h['_source'] for h in value['hits']['hits']], 'timeline':[{'time':b['key'],'count':b['doc_count']} for b in value['aggregations']['timeline']['buckets']], 'high':value['aggregations']['high']['doc_count']}
 except httpx.HTTPError:raise HTTPException(502,'SIEM 로그 조회 실패. 연결 및 읽기 권한을 확인하세요.')

@router.get('/devices/{device}/logs')
async def logs(device:str,request:Request,hours:int=Query(1,ge=1,le=168),level:int=Query(0,ge=0,le=15),source:str=Query('',max_length=45)):
 auth.user(request);check_device(device)
 return await device_logs(device,hours,level,source)

async def probe(name,host,port):
 start=time.monotonic()
 try:
  _,writer=await asyncio.wait_for(asyncio.open_connection(host,port),2)
  writer.close();await writer.wait_closed()
  return {'name':name,'host':host,'port':port,'status':'reachable','latency_ms':round((time.monotonic()-start)*1000,1),'check':'TCP 연결'}
 except (OSError,asyncio.TimeoutError):return {'name':name,'host':host,'port':port,'status':'unreachable','check':'TCP 연결'}

_snapshot={};_snapshot_time=0
async def sample():
 global _snapshot,_snapshot_time
 from .app import health
 devices,host=inventory()
 checks=[probe('플랫폼 API','127.0.0.1',8000)]
 if os.getenv('INDEXER_URL'):checks += [probe('Wazuh Indexer','wazuh.indexer',9200),probe('Wazuh Dashboard','wazuh.dashboard',5601),probe('Wazuh Manager API','wazuh.manager',55000)]
 services=await asyncio.gather(*checks)
 endpoints=(await health())['endpoints']
 now=time.time();issues=[]
 for name,item in devices.items():
  if item['state']!='healthy':issues.append({'severity':'warning','component':name,'message':'장비 상태: '+item['state']})
  for interface in item.get('interfaces',[]):
   if interface['state'] not in ('UP','UNKNOWN'):issues.append({'severity':'warning','component':name,'message':interface['name']+' 링크 '+interface['state']})
 for item in services+endpoints:
  if item['status'] in ('unreachable','degraded'):issues.append({'severity':'critical','component':item['name'],'message':'서비스 응답 실패'})
 if host['state']!='healthy':issues.append({'severity':'warning','component':'host','message':'호스트 수집: '+host['state']})
 if host.get('disk',{}).get('total') and host['disk']['used']/host['disk']['total']>.9:issues.append({'severity':'warning','component':'host','message':'데이터 파일시스템 사용률 90% 초과'})
 for field,label in [('cpu_percent','CPU')]:
  if host.get(field,0) and host[field]>90:issues.append({'severity':'warning','component':'host','message':label+' 사용률 90% 초과'})
 if host.get('memory_total_bytes') and host['memory_bytes']/host['memory_total_bytes']>.9:issues.append({'severity':'warning','component':'host','message':'메모리 사용률 90% 초과'})
 _snapshot={'observed_at':now,'devices':devices,'host':host,'services':services,'endpoints':endpoints,'issues':issues}
 _snapshot_time=now
 with connect() as db:
  for name,item in devices.items():
   if item['fresh']:
    resource=item.get('resources',{});interfaces=item.get('interfaces',[])
    rates=[i.get('rx_bps') for i in interfaces if i.get('rx_bps') is not None]
    tx=[i.get('tx_bps') for i in interfaces if i.get('tx_bps') is not None]
    db.execute('INSERT INTO metrics(timestamp,device,cpu,memory,rx,tx) VALUES(?,?,?,?,?,?)',(now,name,resource.get('cpu_percent'),resource.get('memory_bytes'),sum(rates) if rates else None,sum(tx) if tx else None))
  db.execute('DELETE FROM metrics WHERE timestamp<?',(now-86400,))
 return _snapshot

async def monitor_loop():
 while True:
  try:await sample()
  except Exception:pass # Existing snapshot ages out; never invent a healthy measurement.
  await asyncio.sleep(10)

@router.get('/monitoring')
async def monitoring(request:Request):
 auth.user(request)
 result=copy.deepcopy(_snapshot) if _snapshot else await sample()
 result['stale']=time.time()-result['observed_at']>45
 # Re-evaluate heartbeat age even if background collection has stalled.
 result['devices'],result['host']=inventory()
 return result

@router.get('/monitoring/history/{device}')
def history(device:str,request:Request):
 auth.user(request)
 if device not in (*DEVICES,'edge'):raise HTTPException(404)
 with connect() as db:rows=db.execute('SELECT CAST(timestamp/60 AS INTEGER)*60 AS timestamp,AVG(cpu) AS cpu,AVG(memory) AS memory,AVG(rx) AS rx,AVG(tx) AS tx FROM metrics WHERE device=? AND timestamp>? GROUP BY CAST(timestamp/60 AS INTEGER) ORDER BY timestamp',(device,time.time()-3600)).fetchall()
 return {'scope':'최근 1시간 · 1분 평균 · CPU 100% = 코어 1개','samples':[dict(r) for r in rows]}

@router.get('/monitoring/security')
async def security_summary(request:Request):
 auth.user(request);return await device_logs()

# Native Suricata signatures are persisted independently of the simple rule builder.
from security.local_rules import digest as local_digest, validate_text, atomic, write_json

class LocalRulesChange(BaseModel):
 version: str = Field(min_length=64,max_length=64)
 content: str = Field(max_length=262144)

class LocalRulesApply(BaseModel):
 validation_id: str = Field(pattern='^[a-f0-9]{32}$')

@router.get('/devices/ips/local-rules')
def local_rules_get(request:Request):
 auth.user(request)
 with policy_lock():
  doc=read_policy();path=directory()/'local.rules'
  content=path.read_text() if path.exists() else ''
  return {'content':content,'version':revision(doc),'sha256':local_digest(content),'file':'local.rules',
          'validation':{k:v for k,v in read_json('local-rules-result.json').items() if k!='content'},'apply':read_json('ips-status.json')}

@router.post('/devices/ips/local-rules/validate',status_code=202)
def local_rules_validate(change:LocalRulesChange,request:Request):
 user=auth.user(request,('admin',))
 try:validate_text(change.content)
 except ValueError as error:raise HTTPException(422,str(error))
 with policy_lock():
  doc=read_policy()
  if revision(doc)!=change.version:raise HTTPException(409,'정책이 변경되었습니다. 다시 불러온 후 검사하세요.')
  job=read_json('local-rules-job.json');result=read_json('local-rules-result.json')
  if job and job.get('id')!=result.get('id') and time.time()-job.get('created',0)<120:raise HTTPException(409,'규칙 검사 중입니다. 잠시 후 다시 시도하세요.')
  job={'id':secrets.token_hex(16),'version':change.version,'content':change.content,'sha256':local_digest(change.content),'created':time.time()}
  write_json(directory()/'local-rules-job.json',job)
 audit(user['username'],'ips_local_rules_validate',{'id':job['id'],'sha256':job['sha256']})
 return {'id':job['id'],'status':'pending'}

@router.get('/devices/ips/local-rules/validation/{validation_id}')
def local_rules_validation(validation_id:str,request:Request):
 auth.user(request)
 result=read_json('local-rules-result.json')
 if result.get('id')==validation_id:return result
 job=read_json('local-rules-job.json')
 if job.get('id')!=validation_id:raise HTTPException(404,'검사 요청을 찾을 수 없습니다.')
 return {'id':validation_id,'status':'pending' if time.time()-job['created']<120 else 'expired'}

@router.post('/devices/ips/local-rules/apply')
def local_rules_apply(change:LocalRulesApply,request:Request):
 user=auth.user(request,('admin',))
 with policy_lock():
  doc=read_policy();job=read_json('local-rules-job.json');result=read_json('local-rules-result.json')
  if job.get('id')!=change.validation_id or result.get('id')!=change.validation_id or result.get('status')!='valid':raise HTTPException(409,'구문 검사를 통과한 변경안만 적용할 수 있습니다.')
  if revision(doc)!=job['version'] or time.time()-result.get('updated',0)>600:raise HTTPException(409,'정책이 변경되었거나 검사 유효 시간이 지났습니다. 다시 검사하세요.')
  content=validate_text(job['content'])
  if local_digest(content)!=result.get('sha256'):raise HTTPException(409,'검사 결과가 변경안과 다릅니다.')
  atomic(directory()/'local.rules',content)
  doc['local_rules_sha256']=local_digest(content);write_policy(doc)
 audit(user['username'],'ips_local_rules_apply',{'id':change.validation_id,'sha256':doc['local_rules_sha256']})
 return {'ok':True,'status':'pending_device_apply','desired_revision':device_revision(doc,'ips')}
