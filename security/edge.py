import hashlib,signal,subprocess,time
from pathlib import Path
subprocess.run(['ip','route','replace','default','via','10.88.32.1'],check=True)
config=Path('/policies/internal-sites.caddy')
for _ in range(30):
 if config.exists():break
 time.sleep(1)
p=subprocess.Popen(['caddy','run','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'])
signal.signal(signal.SIGTERM,lambda *_:p.terminate())
last=hashlib.sha256(config.read_bytes()).hexdigest()
while p.poll() is None:
 current=hashlib.sha256(config.read_bytes()).hexdigest()
 if current!=last:
  result=subprocess.run(['caddy','reload','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'],capture_output=True,text=True)
  if result.returncode==0:last=current
  else:print('Internal domain TLS reload failed',flush=True)
 time.sleep(3)
raise SystemExit(p.returncode or 0)
