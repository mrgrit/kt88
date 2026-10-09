#!/usr/bin/env python3
"""One-command installer. Run as root; --prepare-only for validation without deployment."""
import argparse,getpass,json,os,re,secrets,subprocess,sys,time,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def run(*args):subprocess.run(args,cwd=ROOT,check=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--prepare-only',action='store_true');p.add_argument('--without-siem',action='store_true');p.add_argument('--internal-domain',default='platform.example.internal');p.add_argument('--web-bind',default='0.0.0.0');p.add_argument('--http-port',default='80');p.add_argument('--https-port',default='443');p.add_argument('--admin-user',default='admin');p.add_argument('--admin-password-file');args=p.parse_args()
 if not re.fullmatch(r'[a-z0-9.-]+\.internal',args.internal_domain):p.error('internal domain must end in .internal')
 state=ROOT/'.runtime';private=ROOT/'.secrets';private.mkdir(exist_ok=True,mode=0o700);os.chmod(private,0o700)
 from prepare_agent_workspace import prepare
 prepare(ROOT)
 for directory in ['data','policies','logs/ips','logs/waf','logs/fw']:
  d=state/directory;d.mkdir(parents=True,exist_ok=True)
  if os.geteuid()==0:os.chown(d,10001,10001)
 if not (private/'admin_password').exists():
  password=Path(args.admin_password_file).read_text().strip() if args.admin_password_file else getpass.getpass('Initial admin password (8+ characters): ')
  if len(password)<8:p.error('Password must have at least 8 characters')
  (private/'admin_password').write_text(password)
 if not (private/'agent_token').exists():(private/'agent_token').write_text(secrets.token_urlsafe(48))
 for f in private.iterdir():
  os.chmod(f,0o400)
  if os.geteuid()==0:os.chown(f,10001,10001)
 policies=state/'policies'
 if not (policies/'internal-sites.caddy').exists():(policies/'internal-sites.caddy').write_text('')
 if not (policies/'policy.json').exists():(policies/'policy.json').write_text(json.dumps({'blocked_cidrs':[],'paranoia':2,'inbound_threshold':5}))
 if not (policies/'waf.conf').exists():(policies/'waf.conf').write_text('SecAction "id:900000,phase:1,pass,nolog,t:none,setvar:tx.paranoia_level=2"\nSecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"\n')
 for f in policies.iterdir():
  if os.geteuid()==0:os.chown(f,10001,10001)
 env=ROOT/'.env'
 if not env.exists():
  env.write_text(f'INTERNAL_DOMAIN={args.internal_domain}\nADMIN_USER={args.admin_user}\nWEB_BIND={args.web_bind}\nHTTP_PORT={args.http_port}\nHTTPS_PORT={args.https_port}\nACME_EMAIL=\n')
  os.chmod(env,0o600)
 if not args.prepare_only:
  if os.geteuid()!=0:p.error('Run installer with sudo')
  # Narrow change needed for routed Docker bridge path. Do not disable host firewall.
  run('modprobe','br_netfilter')
  run('sysctl','-w','net.bridge.bridge-nf-call-iptables=0')
  files=['-f','compose.yaml'];services=['fw','ips','edge','waf','control','host-monitor']
  if not args.without_siem:
   venv=state/'install-venv'
   if not (venv/'bin/python').exists():run(sys.executable,'-m','venv',str(venv))
   run(str(venv/'bin/pip'),'install','--quiet','PyYAML==6.0.3','bcrypt==5.0.0')
   run(str(venv/'bin/python'),str(ROOT/'scripts/prepare_siem.py'))
   certs=state/'siem/config/wazuh_indexer_ssl_certs';(state/'certs').mkdir(exist_ok=True);shutil.copyfile(certs/'root-ca.pem',state/'certs/root-ca.pem');os.chmod(state/'certs/root-ca.pem',0o644)
   text=env.read_text()
   if 'INDEXER_URL=' not in text:env.write_text(text+'INDEXER_URL=https://wazuh.indexer:9200\n')
   files+=['-f','compose.agents.yaml','-f',str(state/'siem/compose.overlay.yaml')];services+=['wazuh.indexer','wazuh.manager','wazuh.dashboard']
   if re.search(r'^LLM_URL=.+',env.read_text(),re.M):services+=['operation-agents']
  run('docker','compose',*files,'config','--quiet')
  run('docker','compose',*files,'up','-d','--build','--wait',*services)
  if not args.without_siem:
   run('docker','compose',*files,'restart','wazuh.dashboard')
   for attempt in range(24):
    try:
     run('docker','run','--rm','--network','kt88_management','--user','0','--entrypoint','python','-v',str(ROOT/'scripts/setup_indexer.py')+':/setup.py:ro','-v',str(certs)+':/admin-certs:ro','-v',str(private)+':/output','kt88-control','/setup.py','--url','https://wazuh.indexer:9200','--ca','/admin-certs/root-ca.pem','--cert','/admin-certs/admin.pem','--key','/admin-certs/admin-key.pem','--secrets-dir','/output')
     break
    except subprocess.CalledProcessError:
     if attempt==23:raise
     time.sleep(5)
   run('docker','compose',*files,'restart','control')
  run('sysctl','-w','net.bridge.bridge-nf-call-iptables=0')
  override=Path('/etc/systemd/system/docker.service.d/kt88-network.conf');override.parent.mkdir(parents=True,exist_ok=True)
  override.write_text('[Service]\nExecStartPost=/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=0\n')
  run('systemctl','daemon-reload')
 print('Prepared.' if args.prepare_only else 'Installed. Open https://'+args.internal_domain+'/_kt88/. Trust the exported internal CA for internal domains.')
if __name__=='__main__':main()
