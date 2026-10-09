"""Local measurements only. No shell, Docker socket or remote command execution."""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

_previous={}
STARTED=time.time()

def atomic(path, value):
    path=Path(path);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value));tmp.replace(path)

def command(args):
    return json.loads(subprocess.run(args,check=True,capture_output=True,text=True,timeout=3).stdout)

def collect(role, directory='/policies', extra=None):
    now=time.time();interfaces=[];routes=[];errors=[]
    try:
        for item in command(['ip','-j','-s','address','show']):
            if item['ifname']=='lo': continue
            stats=item.get('stats64',item.get('stats',{}));rx=stats.get('rx',{});tx=stats.get('tx',{})
            key=(role,item['ifname']);old=_previous.get(key);rates={'rx_bps':None,'tx_bps':None}
            if old and now>old[0]:
                for label,current,previous in [('rx',rx.get('bytes',0),old[1]),('tx',tx.get('bytes',0),old[2])]:
                    if current>=previous:rates[label+'_bps']=round((current-previous)*8/(now-old[0]),2)
            _previous[key]=(now,rx.get('bytes',0),tx.get('bytes',0))
            interfaces.append({'name':item['ifname'],'state':item.get('operstate','UNKNOWN'),'mac':item.get('address'),
                'mtu':item.get('mtu'),'addresses':[f'{a["local"]}/{a["prefixlen"]}' for a in item.get('addr_info',[])],
                'rx_bytes':rx.get('bytes',0),'tx_bytes':tx.get('bytes',0),'rx_packets':rx.get('packets',0),'tx_packets':tx.get('packets',0),
                'errors':rx.get('errors',0)+tx.get('errors',0),'drops':rx.get('dropped',0)+tx.get('dropped',0),**rates})
        routes=command(['ip','-j','route','show'])
    except (OSError,ValueError,subprocess.SubprocessError): errors.append('인터페이스 수집 실패')
    resources={'scope':'container','uptime_seconds':round(now-STARTED),'cpu_percent':None,'memory_bytes':None,'memory_limit_bytes':None}
    try:
        root=Path('/sys/fs/cgroup');usage=int(dict(line.split() for line in (root/'cpu.stat').read_text().splitlines())['usage_usec'])
        old=_previous.get((role,'cpu'))
        if old and usage>=old[1]: resources['cpu_percent']=round((usage-old[1])/((now-old[0])*10000),2)
        _previous[(role,'cpu')]=(now,usage)
        resources['memory_bytes']=int((root/'memory.current').read_text())
        limit=(root/'memory.max').read_text().strip();resources['memory_limit_bytes']=int(limit) if limit!='max' else None
    except (OSError,ValueError,KeyError): errors.append('cgroup v2 자원 수집 불가')
    disk=shutil.disk_usage(directory);resources['disk']={'total':disk.total,'used':disk.used,'free':disk.free,'scope':'정책 볼륨이 위치한 파일시스템'}
    result={'device':role,'observed_at':now,'interfaces':interfaces,'routes':routes,'resources':resources,'errors':errors,**(extra or {})}
    atomic(Path(directory)/(role+'-telemetry.json'),result)
    return result
