#!/usr/bin/env python3
"""Run inside control after native archives have reached the indexer."""
import argparse,json,os
import httpx
from control.security import secret

VIEW='kt88-security-events'
PATTERN='wazuh-archives-*'
LOCATIONS=['/var/log/kt88/ips/eve.json','/var/log/kt88/waf/modsec_audit.log','/var/log/kt88/fw/fw.json']


def field_list(capabilities):
    fields=[]
    for name,variants in capabilities.get('fields',{}).items():
        if name.startswith('_'):continue
        types=list(variants);kind=types[0] if len(types)==1 else 'conflict'
        display='date' if kind=='date' else 'number' if kind in ('long','integer','float','double','short','byte','half_float','scaled_float') else 'boolean' if kind=='boolean' else 'ip' if kind=='ip' else 'string' if kind in ('text','keyword') else kind
        fields.append({'name':name,'type':display,'esTypes':types,'searchable':all(v.get('searchable',False) for v in variants.values()),'aggregatable':all(v.get('aggregatable',False) for v in variants.values()),'readFromDocValues':all(v.get('aggregatable',False) for v in variants.values()),'count':0})
    if not any(f['name']=='timestamp' and f['type']=='date' for f in fields):raise RuntimeError('Archive timestamp mapping is not ready')
    return fields


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--set-default',action='store_true');args=parser.parse_args()
    dashboard=os.environ['WAZUH_DASHBOARD_URL'].rstrip('/')+'/_kt88/wazuh/api/saved_objects/'
    indexer=os.environ['INDEXER_URL'].rstrip('/')
    auth=(os.getenv('WAZUH_DASHBOARD_USER','admin'),secret('WAZUH_DASHBOARD_PASSWORD'))
    with httpx.Client(auth=auth,headers={'osd-xsrf':'security-views-setup'},verify=os.environ['INDEXER_CA'],trust_env=False,timeout=30) as c:
        def get(url,**kwargs):
            r=c.get(url,**kwargs);r.raise_for_status();return r.json()
        fields=field_list(get(indexer+'/'+PATTERN+'/_field_caps',params={'fields':'*'}))
        def upsert(kind,ident,body,refresh=False):
            path=dashboard+kind+'/'+ident;current=c.get(path)
            if current.status_code==200:
                if refresh:
                    r=c.put(path,json=body);r.raise_for_status()
            elif current.status_code==404:
                r=c.post(path,json=body);r.raise_for_status()
            else:current.raise_for_status()
        upsert('index-pattern',VIEW,{'attributes':{'title':PATTERN,'timeFieldName':'timestamp','fields':json.dumps(fields)}},refresh=True)
        reference='kibanaSavedObjectMeta.searchSourceJSON.index'
        search={'indexRefName':reference,'query':{'language':'lucene','query':'location:('+ ' OR '.join('"'+p+'"' for p in LOCATIONS)+')'},'filter':[]}
        upsert('search','kt88-device-events',{'attributes':{'title':'보안장비 전체 로그 · FW / IPS / WAF','description':'경보 발생 여부와 관계없이 수집한 보안장비 이벤트','columns':['location','data.event_type','data.component','data.blocked_packets','rule.description'],'sort':[['timestamp','desc']],'kibanaSavedObjectMeta':{'searchSourceJSON':json.dumps(search)}},'references':[{'name':reference,'type':'index-pattern','id':VIEW}]})
        # Add archive read access without replacing any existing SOC role grants.
        role_url=indexer+'/_plugins/_security/api/roles/soc-reader'
        role=get(role_url)['soc-reader'];role={k:role[k] for k in ['cluster_permissions','index_permissions','tenant_permissions','description'] if k in role}
        grants=role.setdefault('index_permissions',[])
        if not any(PATTERN in p.get('index_patterns',[]) for p in grants):
            grants.append({'index_patterns':[PATTERN],'allowed_actions':['read']});r=c.put(role_url,json=role);r.raise_for_status()
        if args.set_default:
            settings=get(dashboard+'_find',params={'type':'config','per_page':100})['saved_objects']
            if not settings:raise RuntimeError('Dashboard settings are not initialized')
            for obj in settings:
                r=c.put(dashboard+'config/'+obj['id'],json={'attributes':{'defaultIndex':VIEW}});r.raise_for_status()
    print('Security archive data view, device-log search and SOC read access configured.')

if __name__=='__main__':main()
