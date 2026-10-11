import fcntl,json,os,signal,subprocess,time
from pathlib import Path
from policy_model import device_revision,revision,waf_rules
from telemetry import collect
from local_rules import digest,atomic,write_json
from waf_native import validate_text,test_config
POL=Path('/policies');CONF=POL/'waf.conf';applied=None

def status(state,detail=''):
 write_json(POL/'waf-status.json',{'status':state,'detail':detail,'updated':time.time(),'applied_revision':applied})

def snapshot():
 with (POL/'policy.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH)
  doc=json.loads((POL/'policy.json').read_text());doc.setdefault('rules',{})
  for device in ('fw','ips','waf'):doc['rules'].setdefault(device,[])
  path=POL/'waf-local.conf';local=path.read_text() if path.exists() else ''
  if digest(local)!=doc.get('waf_local_rules_sha256',digest('')):raise RuntimeError('WAF 전문 규칙과 저장된 정책 해시가 다릅니다.')
  return doc,local

def rendered(document,local):
 validate_text(local)
 return waf_rules(document)+'\n# User SecRules\n'+local+'\n'

def configure(document,local):
 candidate=rendered(document,local);test_config(candidate);atomic(CONF,candidate)

def process_validation(document):
 path=POL/'waf-local-rules-job.json';target=POL/'waf-local-rules-result.json'
 if not path.exists():return
 job=json.loads(path.read_text())
 if target.exists() and json.loads(target.read_text()).get('id')==job['id']:return
 result={'id':job['id'],'sha256':job['sha256'],'updated':time.time()}
 try:
  if revision(document)!=job['version']:raise ValueError('정책이 변경되었습니다. 다시 검사하세요.')
  if time.time()-job['created']>120:raise ValueError('검사 요청이 만료되었습니다.')
  test_config(rendered(document,job['content']))
  result.update(status='valid',detail='Apache · ModSecurity · OWASP CRS · 사용자 SecRule 통합 검사 통과')
 except Exception as error:result.update(status='invalid',detail=str(error)[-5000:])
 result['updated']=time.time();write_json(target,result)

def main():
 global applied
 os.makedirs('/var/run/apache2',exist_ok=True)
 os.environ.update(APACHE_RUN_USER='www-data',APACHE_RUN_GROUP='www-data',APACHE_PID_FILE='/var/run/apache2/apache2.pid',APACHE_RUN_DIR='/var/run/apache2',APACHE_LOCK_DIR='/var/lock/apache2',APACHE_LOG_DIR='/var/log/apache2')
 document,local=snapshot();configure(document,local)
 proc=subprocess.Popen(['apache2','-DFOREGROUND']);applied=device_revision(document,'waf');status('applied')
 signal.signal(signal.SIGTERM,lambda *_:proc.terminate());last=applied
 while proc.poll() is None:
  try:
   document,local=snapshot();process_validation(document);current=device_revision(document,'waf')
   if current!=last:
    old=CONF.read_text()
    try:
     configure(document,local)
     subprocess.run(['apache2','-k','graceful'],check=True,capture_output=True,timeout=15)
     applied=current;status('applied')
    except Exception as error:
     atomic(CONF,old);status('error',str(error)[-5000:])
    last=current
  except Exception as error:status('error',str(error)[-5000:])
  collect('waf',extra={'engine':{'name':'ModSecurity / OWASP CRS','alive':True},'applied_revision':applied})
  time.sleep(3)
 status('error','Apache exited');raise SystemExit(1)

if __name__=='__main__':main()
