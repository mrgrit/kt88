import importlib.util,json,time
from pathlib import Path
import pytest
from test_platform import client,operator_console
from security.rule_builder import build_ips,build_waf
from security.waf_native import validate_text

@pytest.mark.parametrize('values,expected',[
 ({'content':'probe'},'content:"probe"'),
 ({'proto':'http','buffer':'http.uri','content':'/example','content2':'token','pcre':'/example/i','nocase':True},'http.uri; content:'),
 ({'proto':'dns','buffer':'dns.query','content':'example.invalid'},'dns.query; content:'),
 ({'proto':'tls','buffer':'tls.sni','content':'example.invalid'},'tls.sni; content:'),
 ({'flags':'S','flow':'stateless','threshold_count':10},'threshold:type both, track by_src, count 10, seconds 60'),
 ({'content':'a";\\b','src':'[192.0.2.1,198.51.100.0/24]','dport':'[80,8000:8080]'},'content:"a|22||3B||5C|b"'),
])
def test_ips_template_conditions(values,expected):
 rule=build_ips(values);assert expected in rule and 'sid:9000000; rev:1;' in rule

@pytest.mark.parametrize('values',[
 {'src':'any any -> any any (sid:1;)','content':'test'}, {'content':'bad|XX|'},
 {'sid':1,'content':'x'}, {'proto':'tcp','buffer':'http.uri','content':'x'},
 {'msg':'a";sid:1;','content':'x'}, {'pcre':'";sid:1;'}, {'content':'x\ndrop ip any any'},
 {'flags':'S','proto':'udp'}, {'content':'x','dport':'65536'}, {'content':'x','nocase':'false'}, {},
])
def test_ips_rejects_injected_or_mismatched_fields(values):
 with pytest.raises(ValueError):build_ips(values)

@pytest.mark.parametrize('values',[
 {'pattern':'probe'}, {'operator':'@rx','pattern':r'(?i)union\s+select','action':'deny'},
 {'operator':'@detectSQLi'}, {'operator':'@detectXSS','variable':'ARGS|ARGS_NAMES'},
 {'variable':'REQUEST_HEADERS:User-Agent','operator':'@contains','pattern':'scanner','phase':1},
 {'variable':'RESPONSE_BODY','pattern':'secret','phase':4},
])
def test_waf_templates_are_native_rules(values):
 rule=build_waf(values);assert rule.startswith('SecRule ');assert validate_text(rule)==rule

@pytest.mark.parametrize('value',[
 'Include /etc/passwd','SecRuleEngine Off',
 'SecRule ARGS "@inspectFile /tmp/run" "id:9000001,phase:2,deny"',
 'SecRule ARGS "@pmFromFile /etc/passwd" "id:9000001,phase:2,deny"',
 'SecAction "id:9000001,phase:1,exec:/tmp/run"',
 'SecAction "id:9000001,phase:1,ctl:ruleEngine=Off"',
 'SecAction "id:9000001,phase:1,allow"','SecAction "id:1,phase:1,pass"',
 'SecAction "id:9000001,phase:1,pass"\nSecAction "id:9000001,phase:1,pass"',
])
def test_waf_full_editor_rejects_external_execution_and_baseline_overrides(value):
 with pytest.raises(ValueError):validate_text(value)


def test_full_waf_chain_and_comments_preserved():
 rule='# example\nSecRule REQUEST_URI "@beginsWith /demo" \\\n "id:9000001,phase:2,deny,chain,msg:\'a,b\'"\n SecRule ARGS "@contains example" "t:none"\nSecMarker END_DEMO\n'
 assert validate_text(rule)==rule


def test_template_api_permissions_and_waf_validation_lifecycle(operator_console,tmp_path,monkeypatch):
 from control import operations as ops
 from control.db import connect
 from security.local_rules import digest
 monkeypatch.setattr(ops,'directory',lambda:tmp_path)
 monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'security'))
 spec=importlib.util.spec_from_file_location('test_waf_worker',Path(__file__).resolve().parents[1]/'security/waf.py')
 worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker);monkeypatch.setattr(worker,'POL',tmp_path)
 seen=[];monkeypatch.setattr(worker,'test_config',lambda content:seen.append(content))
 c,h=operator_console;preview='/_kt88/api/devices/waf/rule-preview';base='/_kt88/api/devices/waf/local-rules'
 assert c.post(preview,json={'pattern':'example'}).status_code==403
 assert c.post(preview,json={'pattern':'example'},headers={**h,'Origin':'https://evil.example'}).status_code==403
 response=c.post(preview,json={'pattern':'example'},headers=h);assert response.status_code==200
 content=response.json()['rule']+'\n';saved=c.get(base).json()
 assert saved['content']=='' and not (tmp_path/'waf-local.conf').exists()
 assert c.post(base+'/apply',json={'validation_id':'a'*32},headers=h).status_code==409
 job=c.post(base+'/validate',json={'version':saved['version'],'content':content},headers=h).json()
 assert not (tmp_path/'waf-local.conf').exists()
 worker.process_validation(ops.read_policy());assert 'SecAction' in seen[0] and content in seen[0]
 assert c.get(base+'/validation/'+job['id']).json()['status']=='valid'
 result=c.post(base+'/apply',json={'validation_id':job['id']},headers=h);assert result.status_code==200
 assert (tmp_path/'waf-local.conf').read_text()==content
 assert ops.read_policy()['waf_local_rules_sha256']==digest(content)
 assert c.post(base+'/apply',json={'validation_id':job['id']},headers=h).status_code==409
 # Invalid native syntax keeps the last approved text and never enables apply.
 def reject(content):raise ValueError('Apache syntax error')
 monkeypatch.setattr(worker,'test_config',reject)
 current=c.get(base).json();bad=c.post(base+'/validate',json={'version':current['version'],'content':'SecRule ARGS "@rx [" "id:9000002,phase:2,deny"'},headers=h).json()
 worker.process_validation(ops.read_policy());assert c.get(base+'/validation/'+bad['id']).json()['status']=='invalid'
 assert c.post(base+'/apply',json={'validation_id':bad['id']},headers=h).status_code==409
 assert (tmp_path/'waf-local.conf').read_text()==content
 for role in ('operator','viewer'):
  with connect() as db:db.execute('UPDATE users SET role=? WHERE username=?',(role,'admin'))
  assert c.post(preview,json={'pattern':'example'},headers=h).status_code==403
  assert c.post('/_kt88/api/devices/ips/rule-preview',json={'content':'example'},headers=h).status_code==403
  assert c.post(base+'/validate',json={'version':current['version'],'content':content},headers=h).status_code==403
  assert c.post(base+'/apply',json={'validation_id':bad['id']},headers=h).status_code==403


def test_isolated_apache_check_never_changes_active_files(tmp_path):
 from security.waf_native import test_config
 root=tmp_path/'apache';(root/'sites-enabled').mkdir(parents=True)
 (root/'apache2.conf').write_text('IncludeOptional sites-enabled/*.conf\n')
 (root/'sites-enabled/kt88.conf').write_text('Include /etc/modsecurity/kt88.conf\n')
 modsec=tmp_path/'modsecurity.conf';modsec.write_text('Include /policies/waf.conf\nInclude /opt/owasp-crs/rules/*.conf\n')
 def run(args,**kwargs):
  candidate=Path(args[-1]);assert candidate!=root/'apache2.conf'
  assert 'Include /opt/owasp-crs/rules/*.conf' in (candidate.parent/'modsecurity.conf').read_text()
  assert (candidate.parent/'rules.conf').read_text()=='candidate'
  return type('Result',(),{'returncode':1,'stdout':'','stderr':'invalid syntax'})()
 with pytest.raises(ValueError):test_config('candidate',root,modsec,run)
 assert modsec.read_text().startswith('Include /policies/waf.conf')
 assert (root/'apache2.conf').read_text()=='IncludeOptional sites-enabled/*.conf\n'
