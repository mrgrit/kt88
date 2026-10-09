"""Shared, shell-free policy validation/rendering for API and device workers."""
import hashlib
import ipaddress
import json
import re

DEVICES = ('fw', 'ips', 'waf')

def revision(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def device_revision(document, device):
    value = {'rules': document.get('rules', {}).get(device, [])}
    if device == 'ips': value['local_rules_sha256'] = document.get('local_rules_sha256', hashlib.sha256(b'').hexdigest())
    if device == 'fw': value['blocked_cidrs'] = document.get('blocked_cidrs', [])
    if device == 'waf': value.update(paranoia=document.get('paranoia', 2), inbound_threshold=document.get('inbound_threshold', 5))
    return revision(value)

def network(value):
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4 or net.prefixlen < 8: raise ValueError('IPv4 /8 이상 범위만 지원합니다.')
    return str(net)

def validate_rule(device, value):
    if device not in DEVICES: raise ValueError('지원하지 않는 장비입니다.')
    allowed = {'id','name','enabled','action','source','port','match','value','note'}
    if set(value) - allowed: raise ValueError('지원하지 않는 정책 필드입니다.')
    rule = {'id': value.get('id'), 'name': value.get('name',''), 'enabled': value.get('enabled',True),
            'action': value.get('action'), 'note': value.get('note','')}
    if not isinstance(rule['id'], int) or not 1000000 <= rule['id'] <= 1999999: raise ValueError('정책 ID 범위 오류')
    if not isinstance(rule['enabled'], bool): raise ValueError('활성화 값 오류')
    for key, maximum in [('name',80),('note',300)]:
        if not isinstance(rule[key],str) or len(rule[key]) > maximum or any(ord(c)<32 for c in rule[key]): raise ValueError('정책 이름/설명 오류')
    if not rule['name'].strip(): raise ValueError('정책 이름을 입력하세요.')
    if device in ('fw','ips'):
        rule['source'] = network(value.get('source',''))
        rule['port'] = value.get('port',0)
        if type(rule['port']) is not int or rule['port'] not in (0,80,443): raise ValueError('서비스 포트는 80/443 또는 전체입니다.')
        actions = ('drop','reject','accept') if device == 'fw' else ('drop','alert')
        if rule['action'] not in actions: raise ValueError('지원하지 않는 동작입니다.')
    else:
        rule.update(match=value.get('match'), value=value.get('value',''))
        if rule['action'] not in ('deny','log'): raise ValueError('지원하지 않는 동작입니다.')
        if rule['match'] == 'source_ip': rule['value'] = network(rule['value'])
        elif rule['match'] == 'path':
            if not re.fullmatch(r'/[a-zA-Z0-9/_.~-]{0,179}',rule['value']): raise ValueError('경로는 /로 시작하고 영문·숫자·/_.~-만 허용합니다.')
            if rule['value'] == '/' or rule['value'].startswith('/_kt88') or '/_kt88'.startswith(rule['value']): raise ValueError('관리 경로 전체를 차단할 수 없습니다.')
        elif rule['match'] == 'user_agent':
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9 ._/:()-]{2,119}',rule['value']): raise ValueError('User-Agent 값 형식을 확인하세요.')
        else: raise ValueError('지원하지 않는 조건입니다.')
    return rule

def firewall_rules(document):
    lines=[]
    for raw in document.get('rules',{}).get('fw',[]):
        r=validate_rule('fw',raw)
        if not r['enabled']: continue
        port=str(r['port']) if r['port'] else '{ 80,443 }'
        action='reject with tcp reset' if r['action']=='reject' else r['action']
        # All custom rules remain inside the existing routed web service boundary.
        lines.append(f'ip saddr {r["source"]} ip daddr 10.88.32.80 tcp dport {port} counter {action} comment "policy-{r["id"]}"')
    return '\n'.join(lines)

def ips_rules(document):
    lines=[]
    for raw in document.get('rules',{}).get('ips',[]):
        r=validate_rule('ips',raw)
        if not r['enabled']: continue
        port=str(r['port']) if r['port'] else '[80,443]'
        lines.append(f'{r["action"]} tcp {r["source"]} any -> 10.88.32.80 {port} (msg:"KT88 policy {r["id"]}"; sid:{r["id"]}; rev:1;)')
    return '\n'.join(lines)+'\n'

def waf_rules(document):
    paranoia=int(document.get('paranoia',2));threshold=int(document.get('inbound_threshold',5))
    if not 1<=paranoia<=4 or not 5<=threshold<=20: raise ValueError('CRS 설정 범위 오류')
    lines=[f'SecAction "id:900000,phase:1,pass,nolog,t:none,setvar:tx.paranoia_level={paranoia}"',f'SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold={threshold},setvar:tx.outbound_anomaly_score_threshold=4"']
    for raw in document.get('rules',{}).get('waf',[]):
        r=validate_rule('waf',raw)
        if not r['enabled']: continue
        variable,operator={'source_ip':('REMOTE_ADDR','@ipMatch'),'path':('REQUEST_FILENAME','@beginsWith'),'user_agent':('REQUEST_HEADERS:User-Agent','@contains')}[r['match']]
        action='deny,status:403' if r['action']=='deny' else 'pass'
        lines.append(f'SecRule {variable} "{operator} {r["value"]}" "id:{r["id"]},phase:1,t:none,{action},log,auditlog,msg:\'KT88 policy {r["id"]}\'"')
    return '\n'.join(lines)+'\n'
