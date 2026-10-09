#!/usr/bin/env python3
"""One-command installer. Run as root; --prepare-only for validation without deployment."""
import argparse,getpass,json,os,re,secrets,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def run(*args):subprocess.run(args,cwd=ROOT,check=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--prepare-only',action='store_true');p.add_argument('--internal-domain',default='platform.example.internal');p.add_argument('--web-bind',default='0.0.0.0');p.add_argument('--http-port',default='80');p.add_argument('--https-port',default='443');p.add_argument('--admin-user',default='admin');p.add_argument('--admin-password-file');args=p.parse_args()
 if not re.fullmatch(r'[a-z0-9.-]+\.internal',args.internal_domain):p.error('internal domain must end in .internal')
 state=ROOT/'.runtime';private=ROOT/'.secrets';private.mkdir(exist_ok=True,mode=0o700);os.chmod(private,0o700)
 for directory in ['data','policies','logs/ips','logs/waf']:
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
  env.write_text(f'INTERNAL_DOMAIN={args.internal_domain}\nADMIN_USER={args.admin_user}\nWEB_BIND={args.web_bind}\nHTTP_PORT={args.http_port}\nHTTPS_PORT={args.https_port}\nACME_EMAIL=admin@example.invalid\n')
  os.chmod(env,0o600)
 if not args.prepare_only:
  if os.geteuid()!=0:p.error('Run installer with sudo')
  # Narrow change needed for routed Docker bridge path. Do not disable host firewall.
  run('modprobe','br_netfilter')
  run('sysctl','-w','net.bridge.bridge-nf-call-iptables=0')
  run('docker','compose','config','--quiet')
  run('docker','compose','up','-d','--build','--wait')
  run('sysctl','-w','net.bridge.bridge-nf-call-iptables=0')
  override=Path('/etc/systemd/system/docker.service.d/kt88-network.conf');override.parent.mkdir(parents=True,exist_ok=True)
  override.write_text('[Service]\nExecStartPost=/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=0\n')
  run('systemctl','daemon-reload')
 print('Prepared.' if args.prepare_only else 'Installed. Open https://'+args.internal_domain+'/_kt88/. Trust the exported internal CA for internal domains.')
if __name__=='__main__':main()
