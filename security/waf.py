import hashlib,json,os,signal,subprocess,time
from pathlib import Path
POL=Path('/policies');CONF=Path('/policies/waf.conf')
def status(s,d=''):
 p=POL/'waf-status.tmp';p.write_text(json.dumps({'status':s,'detail':d,'updated':time.time()}));p.replace(POL/'waf-status.json')
if not CONF.exists():
 raise RuntimeError('Run installer to initialize WAF policy')
os.makedirs('/var/run/apache2',exist_ok=True)
os.environ.update(APACHE_RUN_USER='www-data',APACHE_RUN_GROUP='www-data',APACHE_PID_FILE='/var/run/apache2/apache2.pid',APACHE_RUN_DIR='/var/run/apache2',APACHE_LOCK_DIR='/var/lock/apache2',APACHE_LOG_DIR='/var/log/apache2')
p=subprocess.Popen(['apache2','-DFOREGROUND'])
signal.signal(signal.SIGTERM,lambda *_:p.terminate())
last=None
while p.poll() is None:
 raw=CONF.read_bytes();current=hashlib.sha256(raw).hexdigest()
 if current!=last:
  result=subprocess.run(['apache2','-t'],capture_output=True,text=True)
  if result.returncode:status('error',result.stderr[-400:])
  else:
   if last is not None:subprocess.run(['apache2','-k','graceful'],check=True)
   status('applied');last=current
 time.sleep(3)
status('error','Apache exited');raise SystemExit(1)
