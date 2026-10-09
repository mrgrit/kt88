"""Narrow privileged component: only generated routes and validated CIDR sets."""
import hashlib
import fcntl
import datetime
import ipaddress
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from policy_model import device_revision, firewall_rules, ips_rules
from telemetry import collect
from local_rules import digest, validate_text, write_json, check_signature_ids
ROLE=os.environ['ROUTER_ROLE'];POL=Path('/policies');proc=None
applied=None

def run(args,input=None):
    result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=60)
    if result.returncode:raise RuntimeError(result.stderr[-500:])
    return result

def status(state,detail=''):
    tmp=POL/(ROLE+'-status.tmp');tmp.write_text(json.dumps({'status':state,'updated':time.time(),'detail':detail,'applied_revision':applied}));tmp.replace(POL/(ROLE+'-status.json'))

def route():
    if ROLE=='fw':
        run(['ip','route','replace','10.88.32.0/24','via','10.88.31.2'])
    else:
        run(['ip','route','replace','default','via','10.88.31.1'])

def rules(blocked,document=None):
    custom=firewall_rules(document or {})
    entries=('elements = { ' + ', '.join(blocked) + ' };') if blocked else ''
    if ROLE=='fw':
        return f'''flush ruleset
        table inet kt88 {{
          set blocked {{ type ipv4_addr; flags interval; {entries} }}
          chain input {{ type filter hook input priority 0; policy drop;
            ct state established,related accept
            iifname "lo" accept
            ip protocol icmp limit rate 10/second accept
          }}
          chain forward {{ type filter hook forward priority 0; policy drop;
            ip saddr @blocked counter log prefix "KT88_FW_BLOCK " drop
            {custom}
            ct state invalid counter drop
            ct state established,related accept
            ip daddr 10.88.32.80 tcp dport {{ 80,443 }} ct state new limit rate 300/second burst 600 packets accept
            ip saddr 10.88.32.80 tcp dport {{ 80,443 }} accept
            ip saddr 10.88.32.80 udp dport 53 accept
            ip saddr 10.88.32.80 tcp dport 53 accept
          }}
        }}
        table ip nat {{
          chain prerouting {{ type nat hook prerouting priority dstnat;
            ip daddr 10.88.30.2 tcp dport 80 dnat to 10.88.32.80:80
            ip daddr 10.88.30.2 tcp dport 443 dnat to 10.88.32.80:443
          }}
          chain postrouting {{ type nat hook postrouting priority srcnat;
            ip saddr 10.88.32.80 ip daddr != 10.88.31.0/24 ip daddr != 10.88.32.0/24 masquerade
          }}
        }}'''
    return '''flush ruleset
    table inet kt88 {
      chain input { type filter hook input priority 0; policy drop; ct state established,related accept; iifname "lo" accept; ip protocol icmp accept; }
      chain forward { type filter hook forward priority 0; policy drop;
        ct state invalid drop
        ip daddr 10.88.32.80 tcp dport {80,443} queue num 0
        ip saddr 10.88.32.80 ct state established,related queue num 0
        ip saddr 10.88.32.80 tcp dport {80,443} queue num 0
        ip saddr 10.88.32.80 udp dport 53 queue num 0
        ip saddr 10.88.32.80 tcp dport 53 queue num 0
      }
    }'''

def apply(blocked,document=None):
    for value in blocked:
        n=ipaddress.ip_network(value)
        if n.version!=4 or n.prefixlen<8:raise ValueError('Invalid CIDR')
    text=rules(blocked,document)
    run(['nft','-c','-f','-'],text)
    run(['nft','-f','-'],text)

def start_ips():
    # ET Open download is explicit; failure cannot silently become "all rules current".
    if not Path('/var/lib/suricata/rules/suricata.rules').exists():raise RuntimeError('Build image with ET Open rules first')
    config=Path('/etc/suricata/suricata.yaml')
    text=config.read_text().replace('HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"','HOME_NET: "[10.88.32.0/24]"')
    import yaml
    parsed=yaml.safe_load(text)
    for output in parsed.get('outputs',[]):
        eve=output.get('eve-log')
        if eve:eve['types']=[t for t in eve.get('types',[]) if t!='stats' and not (isinstance(t,dict) and 'stats' in t)]
    parsed['unix-command']={'enabled':True,'filename':'/var/run/suricata-command.socket'}
    parsed['rule-files']=[f for f in parsed.get('rule-files',[]) if f not in ('/opt/ips-active.rules','/opt/local.rules')]+['/opt/ips-active.rules','/opt/local.rules']
    config.write_text('%YAML 1.1\n---\n'+yaml.safe_dump(parsed,sort_keys=False))
    run(['suricata','-T','-c',str(config)])
    Path('/var/log/suricata').mkdir(parents=True,exist_ok=True)
    return subprocess.Popen(['suricata','-q','0','-c',str(config),'-l','/var/log/suricata'])

def terminate(*_):
    if proc:proc.terminate()
    raise SystemExit(0)

def ips_command(command):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(45);client.connect('/var/run/suricata-command.socket')
        def exchange(value):
            client.sendall(json.dumps(value).encode()+b'\n');data=b''
            while len(data)<1024*1024:
                chunk=client.recv(65536)
                if not chunk:raise RuntimeError('Suricata socket closed')
                data+=chunk
                try:result=json.loads(data)
                except ValueError:continue
                if result.get('return')!='OK':raise RuntimeError('Suricata command failed: '+str(result.get('message',''))[:200])
                return result.get('message')
            raise RuntimeError('Suricata response too large')
        exchange({'version':'0.2'})
        return exchange({'command':command})

def policy_snapshot():
    with (POL/'policy.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_SH)
        p=POL/'policy.json';document=json.loads(p.read_text()) if p.exists() else {'blocked_cidrs':[]}
        document.setdefault('blocked_cidrs',[])
        document.setdefault('paranoia',2);document.setdefault('inbound_threshold',5)
        document.setdefault('rules',{})
        for device in ('fw','ips','waf'):document['rules'].setdefault(device,[])
        path=POL/'local.rules';local=path.read_text() if path.exists() else ''
        if digest(local)!=document.get('local_rules_sha256',digest('')):raise RuntimeError('local.rules content differs from saved policy revision')
        return document,local

def test_rules(document,local):
    validate_text(local)
    candidate=Path('/opt/validation.rules')
    baseline=Path('/var/lib/suricata/rules/suricata.rules').read_text()+'\n'+Path('/opt/ips.rules').read_text()+'\n'+ips_rules(document)
    check_signature_ids(baseline,local)
    candidate.write_text(baseline+'\n'+local)
    try:
        result=subprocess.run(['suricata','-T','--init-errors-fatal','-c','/etc/suricata/suricata.yaml','-S',str(candidate)],text=True,capture_output=True,timeout=60)
        output=result.stdout+'\n'+result.stderr
        if result.returncode or 'duplicate signature' in output.lower():
            raise ValueError(output[-5000:])
    finally:candidate.unlink(missing_ok=True)

def process_validation(document):
    job_path=POL/'local-rules-job.json'
    if not job_path.exists():return
    job=json.loads(job_path.read_text());result_path=POL/'local-rules-result.json'
    if result_path.exists() and json.loads(result_path.read_text()).get('id')==job['id']:return
    result={'id':job['id'],'sha256':job['sha256'],'updated':time.time()}
    try:
        from policy_model import revision
        if revision(document)!=job['version']:raise ValueError('정책이 변경되었습니다. 다시 검사하세요.')
        if time.time()-job['created']>120:raise ValueError('검사 요청이 만료되었습니다.')
        test_rules(document,job['content'])
        result.update(status='valid',detail='ET Open · 기본 규칙 · 사용자 정책 · local.rules 통합 검사 통과')
    except Exception as error:result.update(status='invalid',detail=str(error)[-5000:])
    result['updated']=time.time();write_json(result_path,result)

def main():
    global proc,applied
    signal.signal(signal.SIGTERM,terminate)
    route();apply([])
    if ROLE=='ips':
        document,local=policy_snapshot()
        Path('/opt/ips-active.rules').write_text(Path('/opt/ips.rules').read_text()+'\n'+ips_rules(document))
        Path('/opt/local.rules').write_text(local)
        proc=start_ips()
        for _ in range(60):
            if Path('/var/run/suricata-command.socket').exists():break
            time.sleep(1)
    last=None;last_log=0;engine={}
    while True:
        if proc and proc.poll() is not None:raise RuntimeError('Suricata exited: queue is fail closed')
        document,local=policy_snapshot()
        if ROLE=='ips':process_validation(document)
        current=device_revision(document,ROLE)
        if current!=last:
            try:
                if ROLE=='fw':apply(document.get('blocked_cidrs',[]),document)
                else:
                    test_rules(document,local)
                    active=Path('/opt/ips-active.rules');old=active.read_text()
                    local_path=Path('/opt/local.rules');old_local=local_path.read_text()
                    local_path.write_text(local)
                    active.write_text(Path('/opt/ips.rules').read_text()+'\n'+ips_rules(document))
                    try:
                        # Full combined rule set was checked before either active file changed.
                        ips_command('reload-rules')
                        engine['ruleset']=ips_command('ruleset-stats')
                    except Exception:
                        active.write_text(old);local_path.write_text(old_local)
                        ips_command('reload-rules')
                        raise
                applied=current;status('applied')
            except Exception as error:status('error',str(error)[:400])
            last=current
        counters=[]
        if ROLE=='fw':
            rules_json=json.loads(run(['nft','-j','list','ruleset']).stdout)
            for item in rules_json.get('nftables',[]):
                rule=item.get('rule',{});expressions=rule.get('expr',[])
                for expr in expressions:
                    if 'counter' in expr:
                        counters.append({'rule':rule.get('comment','baseline'),**expr['counter'],'action':next((k for e in expressions for k in ('drop','reject','accept') if k in e),'other')})
            if time.time()-last_log>=30:
                log=Path('/var/log/kt88/fw.json');log.parent.mkdir(exist_ok=True)
                with log.open('a') as f:f.write(json.dumps({'component':'fw','event':'blocked_counter','timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'blocked_packets':sum(c.get('packets',0) for c in counters if c['action'] in ('drop','reject'))})+'\n')
                if log.stat().st_size>10*1024*1024:log.replace(log.with_suffix('.json.1'))
                last_log=time.time()
        collect(ROLE,extra={'engine':{'name':'nftables' if ROLE=='fw' else 'Suricata','alive':proc is None or proc.poll() is None,**engine},'counters':counters,'applied_revision':applied})
        time.sleep(3)

if __name__=='__main__':
    try:main()
    except Exception as error:
        status('error',str(error)[:400]);raise
