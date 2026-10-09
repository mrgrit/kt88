#!/usr/bin/env python3
"""Run against private indexer with admin mTLS; provision separated machine roles."""
import argparse,json,os,secrets,ssl,re
from pathlib import Path
import httpx

def main():
 p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--analytics-prefix',default='site-analytics');p.add_argument('--ca',required=True);p.add_argument('--cert',required=True);p.add_argument('--key',required=True);p.add_argument('--secrets-dir',required=True);args=p.parse_args()
 if not re.fullmatch(r'[a-z][a-z0-9-]{1,50}',args.analytics_prefix):p.error('Invalid analytics prefix')
 pattern=args.analytics_prefix+'-*'
 directory=Path(args.secrets_dir)
 context=ssl.create_default_context(cafile=args.ca);context.load_cert_chain(args.cert,args.key)
 with httpx.Client(base_url=args.url,verify=context,timeout=30,trust_env=False) as c:
  def put(path,value):r=c.put(path,json=value);r.raise_for_status()
  roles={
   'analytics-writer':{'cluster_permissions':['cluster_composite_ops'],'index_permissions':[{'index_patterns':[pattern],'allowed_actions':['crud','create_index','indices:admin/delete','indices:data/write/delete/byquery','indices:admin/mappings/put']}]},
   'soc-reader':{'cluster_permissions':[],'index_permissions':[{'index_patterns':['wazuh-alerts-*','kt88-security-*'],'allowed_actions':['read']}]},
   'security-writer':{'cluster_permissions':['cluster_composite_ops'],'index_permissions':[{'index_patterns':['kt88-security-*'],'allowed_actions':['crud','create_index']}]}
  }
  for name,role in roles.items():
   filename={'analytics-writer':'indexer_password','soc-reader':'siem_reader_password','security-writer':'security_writer_password'}[name];path=directory/filename
   if not path.exists() or not path.read_text().strip():path.write_text(secrets.token_urlsafe(40));os.chmod(path,0o400)
   if os.geteuid()==0:os.chown(path,10001,10001)
   put('/_plugins/_security/api/roles/'+name,role)
   put('/_plugins/_security/api/internalusers/'+name,{'password':path.read_text().strip(),'backend_roles':[name]})
   put('/_plugins/_security/api/rolesmapping/'+name,{'backend_roles':[name],'users':[name]})
  put('/_index_template/'+args.analytics_prefix,{'index_patterns':[pattern],'template':{'settings':{'number_of_shards':1,'number_of_replicas':0},'mappings':{'dynamic':'strict','properties':{'id':{'type':'keyword'},'visitor':{'type':'keyword'},'timestamp':{'type':'date'},'name':{'type':'keyword'},'page':{'type':'keyword'},'album':{'type':'integer'},'attribution':{'type':'object','enabled':False}}}}})
  policy={'policy':{'description':'Delete analytics after 365 days','default_state':'active','states':[{'name':'active','actions':[],'transitions':[{'state_name':'delete','conditions':{'min_index_age':'365d'}}]},{'name':'delete','actions':[{'delete':{}}],'transitions':[]}],'ism_template':[{'index_patterns':[pattern],'priority':101}]}}
  path='/_plugins/_ism/policies/'+args.analytics_prefix+'-retention'
  current=c.get(path);params={}
  if current.status_code==200:
   stored=current.json();params={'if_seq_no':stored['_seq_no'],'if_primary_term':stored['_primary_term']}
  elif current.status_code!=404:current.raise_for_status()
  r=c.put(path,params=params,json=policy);r.raise_for_status()
 print('Configured separate analytics writer, SOC reader, security writer and 365-day retention.')
if __name__=='__main__':main()
