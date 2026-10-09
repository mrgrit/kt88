import os
import socket
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

os.environ['DATA_DIR']=tempfile.mkdtemp()
os.environ['POLICY_DIR']=tempfile.mkdtemp()
os.environ['ADMIN_PASSWORD']='test-initial-password'
os.environ['AGENT_TOKEN']='test-read-token'
from control.app import app
from control.security import domain,target,cidr,password_hash,password_verify

@pytest.fixture
def client():
 with TestClient(app,base_url='https://platform.example.internal') as c:yield c

def signed(c):
 r=c.post('/_kt88/api/login',json={'username':'admin','password':'test-initial-password'},headers={'Origin':'https://platform.example.internal'})
 assert r.status_code==200
 return {'Origin':'https://platform.example.internal','X-CSRF-Token':r.json()['csrf']}

def test_password_hash():
 value=password_hash('one');assert password_verify('one',value);assert not password_verify('two',value)

def test_session_change_and_csrf(client):
 headers=signed(client)
 assert client.get('/_kt88/api/endpoints').status_code==403
 assert client.post('/_kt88/api/password',json={'current':'test-initial-password','new':'a-different-test-password'}).status_code==403
 assert client.post('/_kt88/api/password',json={'current':'test-initial-password','new':'a-different-test-password'},headers=headers).status_code==200
 assert client.get('/_kt88/api/me').status_code==401
 # Reset persistent fixture for other tests.
 from control.db import connect
 with connect() as db:db.execute('UPDATE users SET password=?,must_change=1 WHERE username="admin"',(password_hash('test-initial-password'),))

def test_endpoint_ssrf(monkeypatch):
 monkeypatch.setattr(socket,'getaddrinfo',lambda *a:[(2,1,6,'',('127.0.0.1',80))])
 with pytest.raises(Exception):target('http://localhost:80')
 monkeypatch.setattr(socket,'getaddrinfo',lambda *a:[(2,1,6,'',('169.254.169.254',80))])
 with pytest.raises(Exception):target('http://metadata:80')
 monkeypatch.setattr(socket,'getaddrinfo',lambda *a:[(2,1,6,'',('10.88.40.20',8080))])
 assert target('http://site:8080')==('10.88.40.20',8080,'site')
 with pytest.raises(Exception):target('http://site:8080/?url=foo')
 monkeypatch.setattr(socket,'getaddrinfo',lambda *a:[(2,1,6,'',('10.88.40.2',8000))])
 with pytest.raises(Exception):target('http://control:8000')

def test_machine_token_scope(client):
 assert client.post('/_kt88/mcp',json={'method':'tools/list','id':1}).status_code==401
 r=client.post('/_kt88/mcp',json={'method':'tools/list','id':1},headers={'Authorization':'Bearer test-read-token'})
 assert r.json()['result']['tools'][0]['name']=='platform_health'
 r=client.post('/_kt88/mcp',json={'method':'tools/call','id':2,'params':{'name':'shell'}},headers={'Authorization':'Bearer test-read-token'})
 assert r.json()['error']['code']==-32601
 assert client.post('/_kt88/api/users',json={'username':'bad','password':'test-password','role':'admin'},headers={'Authorization':'Bearer test-read-token'}).status_code==401

def test_input_injection():
 assert domain('website.example.internal')=='website.example.internal'
 for value in ['x\nHeader:evil','x/../../','localhost','*.example.com']:
  with pytest.raises(Exception):domain(value)
 assert cidr('203.0.113.2')=='203.0.113.2/32'
 with pytest.raises(Exception):cidr('0.0.0.0/0')

@pytest.fixture
def operator_console(client):
 from control.db import connect
 with connect() as db:db.execute("UPDATE users SET must_change=0 WHERE username='admin'")
 headers=signed(client)
 try:yield client,headers
 finally:
  with connect() as db:
   db.execute("UPDATE users SET role='admin',must_change=1 WHERE username='admin'")
   db.execute("DELETE FROM runs WHERE role='test-reviewer'")

def test_native_agent_edit_queue_and_permissions(operator_console,tmp_path,monkeypatch):
 from control import agents
 from control.db import connect
 monkeypatch.setattr(agents,'WORKSPACE',tmp_path)
 c,h=operator_console
 body={'name':'관제 담당','description':'경보 조사','kind':'soc-triage','model':'qwen3:8b','interval':900,'enabled':True,'instructions':'관찰 사실과 근거, 미확인 범위를 구분하여 보고하세요.'}
 url='/_kt88/api/agents/test-reviewer'
 assert c.put(url,json=body).status_code==403
 r=c.put(url,json=body,headers=h);assert r.status_code==200,r.text
 assert (tmp_path/'.agents/skills/test-reviewer/SKILL.md').exists()
 assert (tmp_path/'.claude/agents/test-reviewer.md').exists()
 assert c.put(url,json=body,headers=h).status_code==409
 body['version']=r.json()['version'];body['model']='unapproved-model'
 assert c.put(url,json=body,headers=h).status_code==422
 r=c.post(url+'/run',json={'request':'최근 경보를 조사하세요.'},headers=h);assert r.status_code==202
 assert c.post(url+'/run',json={'request':'중복'},headers=h).status_code==409
 detail=c.get('/_kt88/api/runs/'+str(r.json()['id'])).json()
 assert detail['result']['definition']['instructions']==body['instructions']
 with connect() as db:db.execute("UPDATE users SET role='viewer' WHERE username='admin'")
 assert c.get('/_kt88/api/agents').status_code==200
 assert c.post(url+'/run',json={'request':'조회자 실행 금지'},headers=h).status_code==403
 assert c.put(url,json=body,headers=h).status_code==403
 with pytest.raises(Exception):agents.skill_path('../escape')
 (tmp_path/'.agents/skills/symlink').symlink_to(tmp_path,target_is_directory=True)
 with pytest.raises(Exception):agents.skill_path('symlink')

def test_wazuh_proxy_auth_csrf_and_secret_boundary(operator_console,monkeypatch):
 import httpx,ssl
 from control import dashboard
 from control.db import connect
 c,h=operator_console;original=httpx.AsyncClient;context=ssl.create_default_context()
 monkeypatch.setenv('WAZUH_DASHBOARD_URL','https://wazuh.dashboard:5601')
 monkeypatch.setenv('WAZUH_DASHBOARD_PASSWORD','internal-test-only')
 monkeypatch.setattr(dashboard.ssl,'create_default_context',lambda **kw:context)
 c.cookies.set('wz-token','native-test')
 class NativeStream(httpx.AsyncByteStream):
  async def __aiter__(self):yield b'native console'
 def upstream(request):
  assert request.url.host=='wazuh.dashboard'
  assert request.url.path=='/_kt88/wazuh/app/wz-home'
  assert request.headers.get('cookie')=='wz-token=native-test'
  assert request.headers['authorization'].startswith('Basic ')
  return httpx.Response(200,stream=NativeStream(),headers=[('content-security-policy',"script-src 'self'; frame-ancestors 'none'"),('set-cookie','security_authentication=private'),('set-cookie','wz-token=native-test; Path=/')])
 monkeypatch.setattr(dashboard.httpx,'AsyncClient',lambda **kw:original(**kw,transport=httpx.MockTransport(upstream)))
 r=c.get('/_kt88/wazuh/app/wz-home');assert r.status_code==200
 assert "frame-ancestors 'self'" in r.headers['content-security-policy']
 cookies=r.headers.get_list('set-cookie');assert len(cookies)==1 and cookies[0].startswith('wz-token=')
 assert 'Path=/_kt88/wazuh' in cookies[0] and 'HttpOnly' in cookies[0] and 'Secure' in cookies[0] and 'SameSite=Strict' in cookies[0]
 assert c.post('/_kt88/wazuh/app/wz-home').status_code==403
 assert c.post('/_kt88/wazuh/app/wz-home',headers={'Origin':'https://evil.example','osd-xsrf':'true'}).status_code==403
 assert c.post('/_kt88/wazuh/app/wz-home',headers={'Origin':'https://platform.example.internal','osd-xsrf':'true'}).status_code==200
 with connect() as db:db.execute("UPDATE users SET role='operator' WHERE username='admin'")
 assert c.get('/_kt88/wazuh/app/wz-home').status_code==403
 c.cookies.clear();assert c.get('/_kt88/wazuh/app/wz-home').status_code==401

def test_device_policy_lifecycle_and_boundary(operator_console,tmp_path,monkeypatch):
 from control import app as module
 from control import operations
 from security.policy_model import firewall_rules,ips_rules,waf_rules
 from control.db import connect
 monkeypatch.setattr(module,'POLICIES',tmp_path)
 c,h=operator_console
 for device,rule in [
  ('fw',{'name':'검증 차단','source':'203.0.113.42','port':80,'action':'drop'}),
  ('ips',{'name':'검증 탐지','source':'203.0.113.42','port':443,'action':'alert'}),
  ('waf',{'name':'검증 경로','match':'path','value':'/test-private','action':'deny'})]:
  url='/_kt88/api/devices/'+device+'/policies'
  version=c.get(url).json()['version'];body={'version':version,'operation':'create','rule':rule}
  assert c.post(url,json=body).status_code==403
  preview=c.post(url+'/preview',json=body,headers=h);assert preview.status_code==200,preview.text
  identifier=preview.json()['after'][-1]['id']
  r=c.post(url,json=body,headers=h);assert r.status_code==200,r.text
  assert c.post(url,json=body,headers=h).status_code==409
  stored=c.get(url).json();assert stored['rules'][-1]['id']==identifier
  body={'version':stored['version'],'operation':'update','rule_id':identifier,'rule':{**stored['rules'][-1],'enabled':False}}
  assert c.put(url+'/'+str(identifier),json=body,headers=h).status_code==200
  assert not c.get(url).json()['rules'][-1]['enabled']
  body={'version':c.get(url).json()['version'],'operation':'delete','rule_id':identifier}
  assert c.delete(url+'/'+str(identifier),headers=h).status_code==422
  assert c.request('DELETE',url+'/'+str(identifier),json=body,headers=h).status_code==200
  assert c.get(url).json()['rules']==[]
 # Arbitrary native configuration injection and control-plane blanket blocks fail.
 url='/_kt88/api/devices/waf/policies'
 for value in ['/','/_kt88','/x"\nSecRuleEngine Off']:
  body={'version':c.get(url).json()['version'],'operation':'create','rule':{'name':'bad','match':'path','value':value,'action':'deny'}}
  assert c.post(url,json=body,headers=h).status_code==422
 # Legacy API preserves new rules instead of deleting another administrator's entries.
 url='/_kt88/api/devices/ips/policies';body={'version':c.get(url).json()['version'],'operation':'create','rule':{'name':'preserve','source':'203.0.113.42','port':0,'action':'drop'}}
 assert c.post(url,json=body,headers=h).status_code==200
 assert c.put('/_kt88/api/policy',json={'blocked_cidrs':[],'paranoia':2,'inbound_threshold':5},headers=h).status_code==200
 assert len(c.get(url).json()['rules'])==1
 with connect() as db:db.execute("UPDATE users SET role='operator' WHERE username='admin'")
 assert c.get(url).status_code==200
 assert c.post(url,json=body,headers=h).status_code==403
 assert c.get('/_kt88/api/devices/not-a-device/policies').status_code==404

def test_monitoring_staleness_and_renderers(tmp_path,monkeypatch):
 import json,time
 from control import app as module
 from control.operations import inventory
 from security.policy_model import validate_rule,firewall_rules,ips_rules,waf_rules,device_revision
 monkeypatch.setattr(module,'POLICIES',tmp_path)
 rule=validate_rule('fw',{'id':1000001,'name':'source allow','action':'accept','source':'203.0.113.4/32','port':443})
 document={'rules':{'fw':[rule]}}
 rendered=firewall_rules(document)
 assert 'ip daddr 10.88.32.80 tcp dport 443' in rendered
 assert 'accept' in rendered
 (tmp_path/'policy.json').write_text(json.dumps(document))
 data={'observed_at':time.time(),'engine':{'alive':True},'applied_revision':device_revision(document,'fw')}
 (tmp_path/'fw-telemetry.json').write_text(json.dumps(data))
 assert inventory()[0]['fw']['state']=='healthy'
 data['observed_at']-=120;(tmp_path/'fw-telemetry.json').write_text(json.dumps(data))
 assert inventory()[0]['fw']['state']=='stale'
 assert inventory()[0]['ips']['state']=='unknown'
 for device,extra in [('fw',{'source':'0.0.0.0/0','action':'accept'}),('ips',{'source':'203.0.113.1;evil','action':'drop'}),('waf',{'match':'user_agent','value':'x";SecRuleEngine Off','action':'deny'})]:
  with pytest.raises(ValueError):validate_rule(device,{'id':1000002,'name':'invalid',**extra})
