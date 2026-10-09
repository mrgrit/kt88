"""Authenticated fixed-origin Wazuh reverse proxy, never an arbitrary URL proxy."""
import os,ssl,logging
import httpx
from http.cookies import SimpleCookie
from fastapi import APIRouter,Request,HTTPException
from fastapi.responses import StreamingResponse,RedirectResponse
from . import auth
from .security import secret
from .db import audit
router=APIRouter()
PREFIX='/_kt88/wazuh'
HOP={'host','connection','keep-alive','transfer-encoding','upgrade','proxy-authorization','proxy-connection','te','trailer','authorization','cookie','x-csrf-token','x-forwarded-for','x-forwarded-host','x-forwarded-proto','forwarded','x-real-ip'}

@router.get(PREFIX)
def slash(request:Request):
 auth.user(request,('admin',));return RedirectResponse(PREFIX+'/app/wz-home',status_code=307)

@router.api_route(PREFIX+'/{path:path}',methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
async def dashboard(path:str,request:Request):
 # Native dashboard uses its own XSRF header. Exact Origin is additionally required.
 user=auth.user(request,('admin',),csrf=False)
 if not path:return RedirectResponse(PREFIX+'/app/wz-home',status_code=307)
 if request.method not in ('GET','HEAD','OPTIONS'):
  if request.headers.get('origin')!='https://'+request.headers.get('host','') or not (request.headers.get('osd-xsrf') or request.headers.get('kbn-xsrf')):raise HTTPException(403,'Wazuh 요청 출처 검증 실패')
 base=os.getenv('WAZUH_DASHBOARD_URL','').rstrip('/')
 password=secret('WAZUH_DASHBOARD_PASSWORD')
 if not base or not password:raise HTTPException(503,'Wazuh 대시보드 연결이 설정되지 않았습니다.')
 headers={k:v for k,v in request.headers.items() if k.lower() not in HOP}
 # Forward only the native plugin's session cookies, never platform credentials.
 native=SimpleCookie()
 for name in ('wz-token','wz-api','wz-user'):
  if name in request.cookies:native[name]=request.cookies[name]
 if native:headers['cookie']='; '.join(m.OutputString() for m in native.values())
 headers.update({'x-forwarded-proto':'https','x-forwarded-host':request.headers.get('host','')})
 context=ssl.create_default_context(cafile=os.getenv('INDEXER_CA','/certs/root-ca.pem'))
 client=httpx.AsyncClient(verify=context,timeout=90,trust_env=False,follow_redirects=False,auth=(os.getenv('WAZUH_DASHBOARD_USER','admin'),password))
 url=httpx.URL(base+PREFIX+'/'+path).copy_with(query=request.url.query.encode())
 try:
  content=None if request.method in ('GET','HEAD') else request.stream()
  upstream=await client.send(client.build_request(request.method,url,headers=headers,content=content),stream=True)
 except httpx.HTTPError as error:
  logging.getLogger(__name__).warning('Wazuh upstream %s at %s',type(error).__name__,path[:200])
  await client.aclose();raise HTTPException(502,'Wazuh 대시보드가 준비 중이거나 응답하지 않습니다.')
 if request.method not in ('GET','HEAD','OPTIONS'):
  audit(user['username'],'wazuh_request',{'method':request.method,'path':path[:200],'status':upstream.status_code})
 async def stream():
  try:
   async for chunk in upstream.aiter_raw():yield chunk
  finally:await upstream.aclose();await client.aclose()
 response=StreamingResponse(stream(),status_code=upstream.status_code)
 response.raw_headers=[(k,v) for k,v in upstream.headers.raw if k.decode().lower() not in {'connection','transfer-encoding','keep-alive','set-cookie','x-frame-options'}]
 # Keep upstream's script policy; embedding is restricted to this console's origin.
 policy=response.headers.get('Content-Security-Policy',"script-src 'self' 'unsafe-eval' 'unsafe-inline'; object-src 'none'")
 policy='; '.join(p.strip() for p in policy.split(';') if p.strip() and not p.strip().startswith('frame-ancestors'))
 response.headers['Content-Security-Policy']=policy+"; frame-ancestors 'self'"
 response.headers['X-Frame-Options']='SAMEORIGIN'
 return response
