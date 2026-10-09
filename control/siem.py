import os
import httpx
from fastapi import HTTPException
from .security import secret

async def alerts():
 url=os.getenv('INDEXER_URL','').rstrip('/')
 if not url:raise HTTPException(503,'SIEM 연결을 설정하세요.')
 try:
  async with httpx.AsyncClient(timeout=20,verify=os.getenv('INDEXER_CA') or True,trust_env=False) as c:
   r=await c.post(url+'/wazuh-alerts-*/_search',auth=(os.getenv('SIEM_READER_USER','soc-reader'),secret('SIEM_READER_PASSWORD')),json={'size':30,'sort':[{'timestamp':'desc'}],'query':{'range':{'timestamp':{'gte':'now-1h'}}},'_source':['timestamp','rule.id','rule.level','rule.description','agent.name','data.srcip','data.dstip','data.action']})
   r.raise_for_status();d=r.json()
   return {'window':'last hour','total':d['hits']['total'],'alerts':[h['_source'] for h in d['hits']['hits']]}
 except httpx.HTTPError:raise HTTPException(502,'SIEM 경보 조회 실패. 연결·권한·인증서를 확인하세요.')
