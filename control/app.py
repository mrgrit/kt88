import asyncio
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from . import auth
from .db import init, connect, audit, ROOT
from .security import domain, target, cidr, digest, password_verify, password_hash

STATIC = Path(__file__).parent / 'static'
POLICIES = Path(os.getenv('POLICY_DIR','/policies'))

def render_internal_sites():
    internal=os.getenv('INTERNAL_DOMAIN','platform.example.internal')
    with connect() as db:domains=[r[0] for r in db.execute("SELECT domain FROM endpoints WHERE enabled=1 AND visibility='internal'") if r[0]!=internal]
    blocks=[]
    for value in domains:
        host=domain(value)
        blocks.append('https://'+host+' {\n tls internal\n reverse_proxy waf:8080 {\n  header_up X-Forwarded-For {remote_host}\n  header_up X-Forwarded-Proto https\n  header_up -Forwarded\n  header_up -X-Real-IP\n }\n}\n')
    POLICIES.mkdir(parents=True,exist_ok=True);temp=POLICIES/'internal-sites.tmp';temp.write_text('\n'.join(blocks));temp.replace(POLICIES/'internal-sites.caddy')

@asynccontextmanager
async def lifespan(app):
    init();render_internal_sites()
    app.state.http = httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False)
    from .operations import monitor_loop
    monitor=asyncio.create_task(monitor_loop())
    yield
    monitor.cancel()
    try:await monitor
    except asyncio.CancelledError:pass
    await app.state.http.aclose()

app = FastAPI(title='kt88 Platform API', docs_url='/_kt88/docs', openapi_url='/_kt88/openapi.json', lifespan=lifespan)

@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.url.path.startswith('/_kt88'):
        response.headers['Cache-Control'] = 'no-store'
    if request.url.path.startswith('/_kt88') and not request.url.path.startswith('/_kt88/wazuh/'):
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response

class Login(BaseModel):
    username: str = Field(min_length=1,max_length=80)
    password: str = Field(min_length=1,max_length=256)

@app.post('/_kt88/api/login')
def login(data: Login, request: Request):
    if request.headers.get('origin') != 'https://' + request.headers.get('host',''):
        raise HTTPException(403,'동일 출처 로그인만 허용합니다.')
    key = digest(data.username + ':' + (request.client.host if request.client else 'unknown'))
    with connect() as db:
        limit = db.execute('SELECT * FROM login_limits WHERE key=?',(key,)).fetchone()
        if limit and limit['failures'] >= 5 and limit['updated'] > time.time()-900:
            raise HTTPException(429,'15분 뒤 다시 시도하세요.')
        row = db.execute('SELECT * FROM users WHERE username=? AND disabled=0',(data.username,)).fetchone()
        # Comparable hashing work even for unknown usernames.
        fallback = '00'*16 + ':' + '00'*64
        if not password_verify(data.password,row['password'] if row else fallback):
            failures = limit['failures'] + 1 if limit and limit['updated'] > time.time()-900 else 1
            db.execute('INSERT OR REPLACE INTO login_limits VALUES(?,?,?)',(key,failures,time.time()))
            db.commit()
            raise HTTPException(401,'계정 또는 비밀번호가 올바르지 않습니다.')
        db.execute('DELETE FROM login_limits WHERE key=?',(key,))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(token),row['id'],csrf,time.time()+28800))
    response = JSONResponse({'csrf':csrf,'role':row['role'],'must_change':bool(row['must_change'])})
    response.set_cookie(auth.COOKIE,token,secure=True,httponly=True,samesite='strict',max_age=28800,path='/')
    audit(data.username,'login',{})
    return response

@app.get('/_kt88/api/me')
def me(request: Request):
    u=auth.user(request)
    return {k:u[k] for k in ('username','role','csrf','must_change')}

@app.post('/_kt88/api/logout')
def logout(request: Request):
    auth.user(request)
    with connect() as db: db.execute('DELETE FROM sessions WHERE token=?',(digest(request.cookies.get(auth.COOKIE,'')),))
    r=JSONResponse({'ok':True});r.delete_cookie(auth.COOKIE,secure=True,httponly=True,samesite='strict');return r

class Password(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=12,max_length=256)

@app.post('/_kt88/api/password')
def change_password(data: Password, request: Request):
    u=auth.user(request)
    if not password_verify(data.current,u['password']): raise HTTPException(403,'현재 비밀번호를 확인하세요.')
    with connect() as db:
        db.execute('UPDATE users SET password=?,must_change=0 WHERE id=?',(password_hash(data.new),u['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
    audit(u['username'],'password_changed',{})
    return {'ok':True,'login_required':True}

class NewUser(BaseModel):
    username: str = Field(pattern=r'^[a-zA-Z0-9_-]{3,60}$')
    password: str = Field(min_length=12,max_length=256)
    role: str = Field(pattern=r'^(admin|operator|viewer)$')

@app.get('/_kt88/api/users')
def users(request: Request):
    auth.user(request,('admin',))
    with connect() as db: return [dict(r) for r in db.execute('SELECT id,username,role,disabled,must_change FROM users')]

@app.post('/_kt88/api/users')
def create_user(data: NewUser, request: Request):
    u=auth.user(request,('admin',))
    with connect() as db:
        if db.execute('SELECT 1 FROM users WHERE username=?',(data.username,)).fetchone(): raise HTTPException(409,'이미 존재하는 계정입니다.')
        db.execute('INSERT INTO users(username,password,role,must_change) VALUES(?,?,?,1)',(data.username,password_hash(data.password),data.role))
    audit(u['username'],'user_created',{'username':data.username,'role':data.role});return {'ok':True}

class Endpoint(BaseModel):
    name: str = Field(min_length=1,max_length=80)
    domain: str = Field(max_length=253)
    upstream: str = Field(max_length=256)
    visibility: str = Field(pattern=r'^(internal|public)$')

@app.get('/_kt88/api/endpoints')
def endpoints(request: Request):
    auth.user(request)
    with connect() as db: return [dict(r) for r in db.execute('SELECT * FROM endpoints')]

@app.post('/_kt88/api/endpoints')
def add_endpoint(data: Endpoint, request: Request):
    u=auth.user(request,('admin',));host=domain(data.domain);target(data.upstream)
    if data.visibility=='internal' and not host.endswith('.internal'): raise HTTPException(422,'내부 도메인은 .internal로 끝나야 합니다.')
    if data.visibility=='public' and host.endswith('.internal'): raise HTTPException(422,'public 도메인을 입력하세요.')
    with connect() as db:
        if db.execute('SELECT 1 FROM endpoints WHERE domain=?',(host,)).fetchone(): raise HTTPException(409,'이미 등록된 도메인입니다.')
        cur=db.execute('INSERT INTO endpoints(name,domain,upstream,visibility,created) VALUES(?,?,?,?,?)',(data.name,host,data.upstream,data.visibility,time.time()))
    render_internal_sites()
    audit(u['username'],'endpoint_added',{'domain':host,'upstream':data.upstream});return {'id':cur.lastrowid,'ok':True}

@app.delete('/_kt88/api/endpoints/{endpoint_id}')
def remove_endpoint(endpoint_id:int,request:Request):
    u=auth.user(request,('admin',))
    with connect() as db: db.execute('DELETE FROM endpoints WHERE id=?',(endpoint_id,))
    render_internal_sites()
    audit(u['username'],'endpoint_removed',{'id':endpoint_id});return {'ok':True}

@app.get('/_kt88/internal/tls-allow')
def tls_allow(domain:str):
    with connect() as db: row=db.execute("SELECT 1 FROM endpoints WHERE domain=? AND visibility='public' AND enabled=1",(domain,)).fetchone()
    if not row: raise HTTPException(403,'도메인이 등록되지 않았습니다.')
    return {'ok':True}

class Policy(BaseModel):
    blocked_cidrs:list[str]=Field(default_factory=list,max_length=500)
    paranoia:int=Field(ge=1,le=4,default=2)
    inbound_threshold:int=Field(ge=5,le=20,default=5)

def policy_read():
    p=POLICIES/'policy.json'
    return json.loads(p.read_text()) if p.exists() else {'blocked_cidrs':[],'paranoia':2,'inbound_threshold':5}

def policy_write(data):
    from .operations import policy_lock,read_policy,write_policy
    with policy_lock():
        value=read_policy();value.update(data.model_dump());value['blocked_cidrs']=[cidr(c) for c in value['blocked_cidrs']]
        write_policy(value)

@app.get('/_kt88/api/policy')
def get_policy(request:Request):
    auth.user(request);return policy_read()

@app.put('/_kt88/api/policy')
def put_policy(data:Policy,request:Request):
    u=auth.user(request,('admin',));policy_write(data);audit(u['username'],'security_policy_saved',data.model_dump())
    return {'ok':True,'status':'pending_device_apply','note':'장비 적용 로그에서 성공 여부를 확인하세요.'}

@app.get('/_kt88/api/status')
async def status(request:Request):
    auth.user(request);return await health()

async def health():
    checks=[]
    with connect() as db: eps=[dict(r) for r in db.execute('SELECT * FROM endpoints WHERE enabled=1')]
    for ep in eps:
        try:
            ip,port,host=target(ep['upstream'])
            started=time.monotonic()
            r=await app.state.http.get(f'http://{ip}:{port}/',headers={'Host':host},timeout=3)
            state='healthy' if r.status_code<500 else 'degraded'
            latency=round((time.monotonic()-started)*1000,1)
        except Exception: state='unreachable';latency=None
        checks.append({'name':ep['name'],'domain':ep['domain'],'upstream':ep['upstream'],'status':state,'latency_ms':latency})
    applied={}
    for name in ('fw','ips','waf'):
        p=POLICIES/(name+'-status.json')
        try: applied[name]=json.loads(p.read_text())
        except (OSError,ValueError): applied[name]={'status':'unknown'}
    return {'endpoints':checks,'devices':applied,'floors':[{'id':'datacenter','name':'전산실','systems':['FW','IPS','WAF','SIEM','웹서비스','모델 추론']},{'id':'operations','name':'운영사무실','systems':['SOC 분석','운영 관리','감사','에이전트 작업']}],'policy':policy_read()}

@app.get('/_kt88/api/audit')
def audit_log(request:Request):
    auth.user(request,('admin','viewer'))
    with connect() as db: return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]

@app.get('/_kt88/api/siem')
async def siem_alerts(request:Request):
    auth.user(request,('admin','operator','viewer'))
    from .siem import alerts
    return await alerts()

@app.get('/_kt88/agent/siem')
async def agent_siem(request:Request):
    auth.machine(request)
    from .siem import alerts
    return await alerts()

@app.get('/_kt88/api/runs')
def runs(request:Request):
    auth.user(request)
    with connect() as db: return [dict(r) for r in db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 50')]

@app.get('/_kt88/agent/health')
async def agent_health(request:Request):
    auth.machine(request);return await health()

@app.post('/_kt88/mcp')
async def mcp(request:Request):
    """Stateless Streamable HTTP MCP, JSON response mode; read-only service scope."""
    auth.machine(request)
    if request.headers.get('origin'):
        if request.headers['origin'] != 'https://' + request.headers.get('host',''): raise HTTPException(403,'Origin rejected')
    body=await request.json()
    if not isinstance(body,dict): raise HTTPException(400,'JSON-RPC object required')
    method=body.get('method');reqid=body.get('id')
    if method=='notifications/initialized': return JSONResponse({},status_code=202)
    if method=='initialize': result={'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'kt88','version':'1.0.0'}}
    elif method=='ping':result={}
    elif method=='tools/list':result={'tools':[{'name':'platform_health','description':'Read measured endpoint health and device apply status','inputSchema':{'type':'object','properties':{},'additionalProperties':False}}]}
    elif method=='tools/call' and body.get('params',{}).get('name')=='platform_health':result={'content':[{'type':'text','text':json.dumps(await health(),ensure_ascii=False)}]}
    else:return JSONResponse({'jsonrpc':'2.0','id':reqid,'error':{'code':-32601,'message':'Unknown method or read-only tool'}})
    return {'jsonrpc':'2.0','id':reqid,'result':result}

@app.get('/_kt88/healthz')
def healthz():return {'ok':True}

@app.get('/_kt88')
@app.get('/_kt88/')
def console():return FileResponse(STATIC/'index.html')

@app.get('/_kt88/static/{name}')
def static(name:str):
    if name not in ('app.js','style.css','datacenter.js','agents.js','operations.js'):raise HTTPException(404)
    return FileResponse(STATIC/name)

from .agents import router as agent_router
from .dashboard import router as dashboard_router
from .operations import router as operations_router
app.include_router(agent_router)
app.include_router(dashboard_router)
app.include_router(operations_router)

# These paths are infrastructure only; never leak to user-controlled upstreams.
@app.api_route('/_kt88/{rest:path}',methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def unknown_control(rest:str):raise HTTPException(404)

@app.api_route('/{path:path}',methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
async def proxy(path:str,request:Request):
    host=request.headers.get('host','').split(':')[0].lower()
    with connect() as db: ep=db.execute('SELECT * FROM endpoints WHERE domain=? AND enabled=1',(host,)).fetchone()
    if not ep:raise HTTPException(404,'등록된 사이트가 없습니다. /_kt88에서 엔드포인트를 추가하세요.')
    ip,port,_=target(ep['upstream'])
    headers={k:v for k,v in request.headers.items() if k.lower() not in {'connection','keep-alive','transfer-encoding','upgrade','proxy-authorization','proxy-connection','te','trailer','x-forwarded-for','x-forwarded-host','x-forwarded-proto','forwarded','x-real-ip'}}
    # Client address has already been set by trusted Uvicorn proxy configuration.
    headers['x-forwarded-for']=request.client.host if request.client else ''
    headers['x-forwarded-proto']='https'
    url=httpx.URL(f'http://{ip}:{port}').copy_with(raw_path=request.url.path.encode()+ (b'?'+request.url.query.encode() if request.url.query else b''))
    try:
        req=app.state.http.build_request(request.method,url,headers=headers,content=request.stream())
        upstream=await app.state.http.send(req,stream=True)
    except httpx.HTTPError:raise HTTPException(502,'엔드포인트 응답 실패')
    async def stream():
        try:
            async for chunk in upstream.aiter_raw():yield chunk
        finally:await upstream.aclose()
    response=StreamingResponse(stream(),status_code=upstream.status_code)
    response.raw_headers=[(k,v) for k,v in upstream.headers.raw if k.lower() not in (b'connection',b'transfer-encoding',b'keep-alive')]
    return response
