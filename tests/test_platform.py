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
