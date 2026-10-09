"""Narrow privileged component: only generated routes and validated CIDR sets."""
import hashlib
import datetime
import ipaddress
import json
import os
import signal
import subprocess
import time
from pathlib import Path

ROLE=os.environ['ROUTER_ROLE'];POL=Path('/policies');proc=None

def run(args,input=None):
    result=subprocess.run(args,input=input,text=True,capture_output=True)
    if result.returncode:raise RuntimeError(result.stderr[-500:])
    return result

def status(state,detail=''):
    tmp=POL/(ROLE+'-status.tmp');tmp.write_text(json.dumps({'status':state,'updated':time.time(),'detail':detail}));tmp.replace(POL/(ROLE+'-status.json'))

def route():
    if ROLE=='fw':
        run(['ip','route','replace','10.88.32.0/24','via','10.88.31.2'])
    else:
        run(['ip','route','replace','default','via','10.88.31.1'])

def rules(blocked):
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
            ct state invalid drop
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

def apply(blocked):
    for value in blocked:
        n=ipaddress.ip_network(value)
        if n.version!=4 or n.prefixlen<8:raise ValueError('Invalid CIDR')
    text=rules(blocked)
    run(['nft','-c','-f','-'],text)
    run(['nft','-f','-'],text)
    status('applied')

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
    config.write_text('%YAML 1.1\n---\n'+yaml.safe_dump(parsed,sort_keys=False))
    run(['suricata','-T','-c',str(config),'-s','/opt/ips.rules'])
    Path('/var/log/suricata').mkdir(parents=True,exist_ok=True)
    return subprocess.Popen(['suricata','-q','0','-c',str(config),'-s','/opt/ips.rules','-l','/var/log/suricata'])

def terminate(*_):
    if proc:proc.terminate()
    raise SystemExit(0)

signal.signal(signal.SIGTERM,terminate)
try:
    route();apply([])
    if ROLE=='ips':proc=start_ips()
    last=None
    while True:
        if proc and proc.poll() is not None:raise RuntimeError('Suricata exited: queue is fail closed')
        p=POL/'policy.json'
        raw=p.read_bytes() if p.exists() else b'{"blocked_cidrs":[]}'
        current=hashlib.sha256(raw).hexdigest()
        if current!=last:apply(json.loads(raw)['blocked_cidrs']);last=current
        if ROLE=='fw':
            rules_json=json.loads(run(['nft','-j','list','ruleset']).stdout)
            counters=[]
            for item in rules_json.get('nftables',[]):
                rule=item.get('rule',{})
                for expr in rule.get('expr',[]):
                    if 'counter' in expr:counters.append(expr['counter'])
            if counters and int(time.time()) % 30 < 3:
                log=Path('/var/log/kt88/fw.json');log.parent.mkdir(exist_ok=True)
                with log.open('a') as f:f.write(json.dumps({'component':'fw','event':'blocked_counter','timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'blocked_packets':sum(c.get('packets',0) for c in counters)})+'\n')
                if log.stat().st_size>10*1024*1024:log.replace(log.with_suffix('.json.1'))
        time.sleep(3)
except Exception as e:
    status('error',str(e)[:400]);raise
