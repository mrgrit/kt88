#!/usr/bin/env python3
"""Run against private indexer with admin mTLS; provision separated machine roles."""
import argparse,json,os,secrets
from pathlib import Path
import httpx

def main():
 p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--ca',required=True);p.add_argument('--cert',required=True);p.add_argument('--key',required=True);p.add_argument('--secrets-dir',required=True);args=p.parse_args()
 directory=Path(args.secrets_dir)
 with httpx.Client(base_url=args.url,verify=args.ca,cert=(args.cert,args.key),timeout=30,trust_env=False) as c:
  def put(path,value):r=c.put(path,json=value);r.raise_for_status()
  roles={
   'analytics-writer':{'cluster_permissions':['cluster_composite_ops'],'index_permissions':[{'index_patterns':['ycdc-analytics-*'],'allowed_actions':['crud','create_index','indices:admin/delete','indices:data/write/delete/byquery','indices:admin/mappings/put']}]},
   'soc-reader':{'cluster_permissions':[],'index_permissions':[{'index_patterns':['wazuh-alerts-*','kt88-security-*'],'allowed_actions':['read']}]},
   'security-writer':{'cluster_permissions':['cluster_composite_ops'],'index_permissions':[{'index_patterns':['kt88-security-*'],'allowed_actions':['crud','create_index']}]}
  }
  for name,role in roles.items():
   filename={'analytics-writer':'indexer_password','soc-reader':'siem_reader_password','security-writer':'security_writer_password'}[name];path=directory/filename
   if not path.exists() or not path.read_text().strip():path.write_text(secrets.token_urlsafe(40));os.chmod(path,0o400)
   put('/_plugins/_security/api/roles/'+name,role)
   put('/_plugins/_security/api/internalusers/'+name,{'password':path.read_text().strip(),'backend_roles':[name]})
   put('/_plugins/_security/api/rolesmapping/'+name,{'backend_roles':[name],'users':[name]})
  put('/_index_template/ycdc-analytics',{'index_patterns':['ycdc-analytics-*'],'template':{'settings':{'number_of_shards':1,'number_of_replicas':0},'mappings':{'dynamic':'strict','properties':{'id':{'type':'keyword'},'visitor':{'type':'keyword'},'timestamp':{'type':'date'},'name':{'type':'keyword'},'page':{'type':'keyword'},'album':{'type':'integer'},'attribution':{'type':'object','enabled':False}}}}})
  policy={'policy':{'description':'Delete analytics after 365 days','default_state':'active','states':[{'name':'active','actions':[],'transitions':[{'state_name':'delete','conditions':{'min_index_age':'365d'}}]},{'name':'delete','actions':[{'delete':{}}],'transitions':[]}],'ism_template':[{'index_patterns':['ycdc-analytics-*'],'priority':100}]}}
  r=c.put('/_plugins/_ism/policies/ycdc-retention',json=policy)
  if r.status_code not in (200,201,409):r.raise_for_status()
 print('Configured separate analytics writer, SOC reader, security writer and 365-day retention.')
if __name__=='__main__':main()
