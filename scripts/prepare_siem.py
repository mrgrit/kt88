#!/usr/bin/env python3
"""Download official versioned Wazuh stack; generate private config and certs locally."""
import argparse,json,os,secrets,subprocess,tarfile,tempfile,urllib.request
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
VERSION='v4.14.8'

def main():
 p=argparse.ArgumentParser();p.add_argument('--prepare-only',action='store_true');args=p.parse_args()
 dest=ROOT/'.runtime/siem';dest.mkdir(parents=True,exist_ok=True)
 if not (dest/'generate-indexer-certs.yml').exists():
  with urllib.request.urlopen('https://github.com/wazuh/wazuh-docker/archive/refs/tags/'+VERSION+'.tar.gz') as r, tempfile.TemporaryFile() as f:
   f.write(r.read());f.seek(0)
   with tarfile.open(fileobj=f,mode='r:gz') as archive:
    prefix='wazuh-docker-'+VERSION.lstrip('v')+'/single-node/'
    for member in archive.getmembers():
     if not member.name.startswith(prefix) or not member.isfile():continue
     relative=Path(member.name[len(prefix):])
     if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Unsafe upstream archive')
     target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
 private=ROOT/'.secrets';private.mkdir(exist_ok=True,mode=0o700)
 for name in ['siem_admin_password','siem_api_password','siem_dashboard_password','siem_reader_password','security_writer_password']:
  target=private/name
  if not target.exists():target.write_text(secrets.token_urlsafe(40)+'aA1!')
  os.chmod(target,0o400)
  if os.geteuid()==0:os.chown(target,10001,10001)
 # Passwords are local environment settings; never downloaded default credentials.
 compose=yaml.safe_load((dest/'docker-compose.yml').read_text())
 for name,service in compose['services'].items():
  service.pop('ports',None)
  if name=='wazuh.dashboard':service['ports']=['127.0.0.1:5601:5601']
  service['networks']={'management':{'aliases':[name]}}
  env=service.get('environment',[]);values={}
  if isinstance(env,list):
   for item in env:
    key,value=item.split('=',1);values[key]=value.strip('"')
  else:values=env
  for key,secret_name in [('INDEXER_PASSWORD','siem_admin_password'),('API_PASSWORD','siem_api_password'),('DASHBOARD_PASSWORD','siem_dashboard_password')]:
   if key in values:values[key]=(private/secret_name).read_text()
  service['environment']=values
  service['volumes']=[str((dest/v.split(':')[0]).resolve())+':'+':'.join(v.split(':')[1:]) if v.startswith('./') else v for v in service.get('volumes',[])]
 compose['networks']={'management':{'internal':True,'ipam':{'config':[{'subnet':'10.88.60.0/24'}]}}}
 compose.pop('networks',None)
 out=dest/'compose.overlay.yaml';out.write_text(yaml.safe_dump(compose,sort_keys=False));os.chmod(out,0o600)
 if not args.prepare_only:
  if os.geteuid()!=0:p.error('Run with sudo')
  # bcrypt hashes generated using standard crypt (host python3 <=3.12).
  import crypt
  users=yaml.safe_load((dest/'config/wazuh_indexer/internal_users.yml').read_text())
  for name,filename in [('admin','siem_admin_password'),('kibanaserver','siem_dashboard_password')]:users[name]['hash']=crypt.crypt((private/filename).read_text(),crypt.mksalt(crypt.METHOD_BLOWFISH))
  (dest/'config/wazuh_indexer/internal_users.yml').write_text(yaml.safe_dump(users,sort_keys=False))
  subprocess.run(['sysctl','-w','vm.max_map_count=262144'],check=True)
  subprocess.run(['docker','compose','-f','generate-indexer-certs.yml','run','--rm','generator'],cwd=dest,check=True)
 print('Prepared official Wazuh '+VERSION+' with private credentials and no public SIEM ports.')
if __name__=='__main__':main()
