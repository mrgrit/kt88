"""Bounded SecRule text and isolated Apache/CRS validation, without reload."""
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

MAX_BYTES=256*1024


def actions(value):
    result=[];part='';quote=None;escaped=False
    for char in value:
        if escaped:part+=char;escaped=False;continue
        if char=='\\':part+=char;escaped=True;continue
        if quote:
            part+=char
            if char==quote:quote=None
        elif char in "'\"":quote=char;part+=char
        elif char==',':result.append(part.strip());part=''
        else:part+=char
    if quote or escaped:raise ValueError('액션 문자열의 따옴표/역슬래시를 확인하세요.')
    result.append(part.strip());return result


def validate_text(value):
    if not isinstance(value,str) or len(value.encode())>MAX_BYTES or any(ord(c)<32 and c not in '\r\n\t' for c in value):raise ValueError('규칙 파일은 UTF-8 256 KiB 이하이며 제어 문자를 포함할 수 없습니다.')
    code=re.sub(r'\\\r?\n',' ',value)
    seen=set()
    for line in code.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        try:parts=shlex.split(line,comments=False)
        except ValueError:raise ValueError('규칙 따옴표 또는 줄 연결 문법을 확인하세요.')
        if not parts or parts[0] not in ('SecRule','SecAction','SecMarker'):raise ValueError('전문 편집에서는 SecRule, SecAction, SecMarker만 지원합니다. 엔진·파일 설정은 배포 콘솔에서 관리하세요.')
        if parts[0]=='SecMarker':
            if len(parts)!=2 or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',parts[1]):raise ValueError('SecMarker 이름 오류')
            continue
        if len(parts)!=(4 if parts[0]=='SecRule' else 2):raise ValueError('SecRule 변수 "연산자 패턴" "액션" 형식을 확인하세요.')
        if parts[0]=='SecRule' and re.match(r'!?@(?:inspectFile|pmFromFile|ipMatchFromFile|rbl|fuzzyHash|gsbLookup|validateDTD|validateSchema)\b',parts[2],re.I):raise ValueError('외부 파일·실행·네트워크 조회 연산자는 웹 편집기에서 지원하지 않습니다.')
        for item in actions(parts[-1]):
            key=item.split(':',1)[0].strip().lower()
            if key in ('exec','ctl','allow','skip','skipafter','proxy','redirect'):raise ValueError('실행·엔진 우회·이동 액션은 웹 편집기에서 지원하지 않습니다.')
            if key=='id':
                ident=item.split(':',1)[1].strip()
                if not ident.isdecimal() or not 9000000<=int(ident)<=99999999:raise ValueError('사용자 WAF 룰 ID는 9000000~99999999 범위를 사용하세요.')
                if int(ident) in seen:raise ValueError('중복된 WAF 룰 ID입니다.')
                seen.add(int(ident))
    return value


def test_config(content, apache_root=Path('/etc/apache2'), modsecurity=Path('/etc/modsecurity/kt88.conf'), runner=subprocess.run):
    """Copy only config entrypoints; load the real modules and full CRS unchanged."""
    with tempfile.TemporaryDirectory(prefix='kt88-waf-check-') as name:
        root=Path(name);candidate=root/'rules.conf';candidate.write_text(content)
        modsec=modsecurity.read_text()
        if 'Include /policies/waf.conf' not in modsec:raise RuntimeError('WAF include 위치를 확인하세요.')
        (root/'modsecurity.conf').write_text(modsec.replace('Include /policies/waf.conf','Include '+str(candidate)))
        site=(apache_root/'sites-enabled/kt88.conf').read_text()
        (root/'site.conf').write_text(site.replace('Include /etc/modsecurity/kt88.conf','Include '+str(root/'modsecurity.conf')))
        main=(apache_root/'apache2.conf').read_text()
        pattern=r'(?m)^\s*IncludeOptional\s+sites-enabled/\*\.conf\s*$'
        main,count=re.subn(pattern,'Include '+str(root/'site.conf'),main)
        if count!=1:raise RuntimeError('Apache 가상호스트 include 위치를 확인하세요.')
        (root/'apache2.conf').write_text(main)
        result=runner(['apache2','-t','-f',str(root/'apache2.conf')],capture_output=True,text=True,timeout=30)
        if result.returncode:raise ValueError((result.stdout+'\n'+result.stderr)[-5000:])
