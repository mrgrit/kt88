import json,os,signal,subprocess,time
from pathlib import Path
from policy_model import device_revision,waf_rules
from telemetry import collect,atomic
POL=Path('/policies');CONF=POL/'waf.conf';applied=None

def status(state,detail=''):
 atomic(POL/'waf-status.json',{'status':state,'detail':detail,'updated':time.time(),'applied_revision':applied})

def configure(document):
 old=CONF.read_text() if CONF.exists() else ''
 temp=POL/'waf-render.tmp';temp.write_text(waf_rules(document));temp.replace(CONF)
 result=subprocess.run(['apache2','-t'],capture_output=True,text=True,timeout=15)
 if result.returncode:
  temp.write_text(old);temp.replace(CONF)
  raise RuntimeError(result.stderr[-400:])

os.makedirs('/var/run/apache2',exist_ok=True)
os.environ.update(APACHE_RUN_USER='www-data',APACHE_RUN_GROUP='www-data',APACHE_PID_FILE='/var/run/apache2/apache2.pid',APACHE_RUN_DIR='/var/run/apache2',APACHE_LOCK_DIR='/var/lock/apache2',APACHE_LOG_DIR='/var/log/apache2')
document=json.loads((POL/'policy.json').read_text());configure(document)
p=subprocess.Popen(['apache2','-DFOREGROUND']);applied=device_revision(document,'waf');status('applied')
signal.signal(signal.SIGTERM,lambda *_:p.terminate());last=applied
while p.poll() is None:
 document=json.loads((POL/'policy.json').read_text());current=device_revision(document,'waf')
 if current!=last:
  old=CONF.read_text()
  try:
   configure(document)
   subprocess.run(['apache2','-k','graceful'],check=True,capture_output=True,timeout=15)
   applied=current;status('applied')
  except Exception as error:
   temp=POL/'waf-render.tmp';temp.write_text(old);temp.replace(CONF);status('error',str(error)[:400])
  last=current
 collect('waf',extra={'engine':{'name':'ModSecurity / OWASP CRS','alive':True},'applied_revision':applied})
 time.sleep(3)
status('error','Apache exited');raise SystemExit(1)
