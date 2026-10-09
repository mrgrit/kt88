import hashlib,signal,subprocess,time,os,re
from pathlib import Path
subprocess.run(['ip','route','replace','default','via','10.88.32.1'],check=True)
config=Path('/policies/internal-sites.caddy')
for _ in range(30):
 if config.exists():break
 time.sleep(1)
email=os.getenv('ACME_EMAIL','')
if email and not re.fullmatch(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+',email):raise RuntimeError('Invalid ACME contact')
line=('    email '+email+'\n') if email and not email.endswith('.invalid') else ''
base=Path('/tmp/kt88.Caddyfile');base.write_text(Path('/etc/caddy/Caddyfile').read_text().replace('    email {$ACME_EMAIL}\n',line))
p=subprocess.Popen(['caddy','run','--config',str(base),'--adapter','caddyfile'])
signal.signal(signal.SIGTERM,lambda *_:p.terminate())
last=hashlib.sha256(config.read_bytes()).hexdigest()
while p.poll() is None:
 current=hashlib.sha256(config.read_bytes()).hexdigest()
 if current!=last:
  result=subprocess.run(['caddy','reload','--config',str(base),'--adapter','caddyfile'],capture_output=True,text=True)
  if result.returncode==0:last=current
  else:print('Internal domain TLS reload failed',flush=True)
 time.sleep(3)
raise SystemExit(p.returncode or 0)
