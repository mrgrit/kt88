"""Read only the four mounted host proc metrics files; publish no network service."""
import time
import shutil
from pathlib import Path
from security.telemetry import atomic

def main():
    previous=None
    while True:
        now=time.time();root=Path('/host-metrics')
        try:
            # Exclude guest/guest_nice, already included in user/nice.
            cpu=list(map(int,(root/'stat').read_text().splitlines()[0].split()[1:9]));total=sum(cpu);idle=cpu[3]+cpu[4]
            percent=None
            if previous and total>previous[0]:percent=round(100*(1-(idle-previous[1])/(total-previous[0])),2)
            previous=(total,idle)
            mem={line.split(':')[0]:int(line.split()[1])*1024 for line in (root/'meminfo').read_text().splitlines() if len(line.split())>=3}
            disk=shutil.disk_usage('/telemetry')
            value={'observed_at':now,'scope':'host','cpu_percent':percent,'memory_bytes':mem['MemTotal']-mem['MemAvailable'],'memory_total_bytes':mem['MemTotal'],
                   'uptime_seconds':float((root/'uptime').read_text().split()[0]),'load_average':list(map(float,(root/'loadavg').read_text().split()[:3])),
                   'disk':{'total':disk.total,'used':disk.used,'free':disk.free,'scope':'플랫폼 데이터 파일시스템'}}
            atomic('/telemetry/host-telemetry.json',value)
        except (OSError,ValueError,KeyError):
            atomic('/telemetry/host-telemetry.json',{'observed_at':now,'error':'호스트 지표 수집 실패'})
        time.sleep(10)

if __name__=='__main__':main()
