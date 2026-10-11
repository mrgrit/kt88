"""Generate native detection rules from bounded, explicit template fields."""
import ipaddress
import re


def text(value, maximum=500):
    if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('문자열 길이 또는 제어 문자를 확인하세요.')
    return value


def choice(data,key,values,default):
    value=data.get(key,default)
    if value not in values:raise ValueError(key+' 값이 지원 범위에 없습니다.')
    return value


def number(data,key,default,low,high):
    value=data.get(key,default)
    if type(value) is not int or not low<=value<=high:raise ValueError(key+' 숫자 범위를 확인하세요.')
    return value


def address(value):
    value=text(value,200).strip()
    if value.startswith('!'):return '!'+address(value[1:])
    if value.startswith('[') and value.endswith(']'):
        parts=value[1:-1].split(',')
        if not 1<=len(parts)<=16 or any('[' in p or ']' in p for p in parts):raise ValueError('주소 목록 형식 오류')
        return '['+','.join(address(p) for p in parts)+']'
    if value in ('any','$HOME_NET','$EXTERNAL_NET'):return value
    try:return str(ipaddress.ip_network(value,strict=False))
    except ValueError:raise ValueError('IP/CIDR, any, $HOME_NET, $EXTERNAL_NET을 사용하세요.')


def port(value):
    value=text(value,100).strip()
    if value in ('any','$HTTP_PORTS','$HTTPS_PORTS'):return value
    if value.startswith('[') and value.endswith(']'):
        parts=value[1:-1].split(',')
        if not 1<=len(parts)<=16 or any('[' in p or ']' in p for p in parts):raise ValueError('포트 목록 형식 오류')
        return '['+','.join(port(p) for p in parts)+']'
    if not re.fullmatch(r'\d{1,5}(?::\d{1,5})?',value):raise ValueError('포트는 any, 숫자, 시작:끝, [목록] 형식입니다.')
    parts=list(map(int,value.split(':')))
    if any(not 0<=p<=65535 for p in parts) or parts[0]>parts[-1]:raise ValueError('포트 범위 오류')
    return value


def suricata_string(value):
    value=text(value)
    # Preserve explicit hex blocks; escape literal syntax bytes as hex content.
    pieces=value.split('|')
    if len(pieces)%2==0 or any(not re.fullmatch(r'(?:[0-9a-fA-F]{2}\s*)+',p.strip()) for p in pieces[1::2]):raise ValueError('content의 |hex| 형식을 확인하세요.')
    for i in range(0,len(pieces),2):
        pieces[i]=''.join('|%02X|'%ord(c) if c in '"\\;' else c for c in pieces[i])
    return '|'.join(pieces)


def build_ips(data):
    allowed={'action','proto','src','sport','direction','dst','dport','msg','flow','buffer','content','content2','pcre','nocase','flags','threshold_type','threshold_track','threshold_count','threshold_seconds','classtype','sid','rev'}
    if set(data)-allowed:raise ValueError('지원하지 않는 템플릿 필드입니다.')
    action=choice(data,'action',('alert','drop','reject'),'alert')
    proto=choice(data,'proto',('tcp','udp','icmp','ip','http','dns','tls'),'tcp')
    direction=choice(data,'direction',('->','<>'),'->')
    msg=text(data.get('msg','Custom IPS detection'),120)
    if not msg.strip() or any(c in msg for c in '"\\;'):raise ValueError('탐지 메시지에 따옴표·역슬래시·세미콜론을 사용할 수 없습니다.')
    opts=['msg:"'+msg+'"']
    flow=choice(data,'flow',('','to_server','to_client','established,to_server','established,to_client','stateless'),'')
    if flow:opts.append('flow:'+flow)
    buffers={'':'','http.uri':'http','http.method':'http','http.user_agent':'http','http.request_body':'http','http.header':'http','dns.query':'dns','tls.sni':'tls'}
    buffer=choice(data,'buffer',buffers,'')
    if buffer and buffers[buffer]!=proto:raise ValueError('선택한 버퍼와 프로토콜을 맞추세요.')
    contents=[text(data.get(key,'')) for key in ('content','content2')]
    pcre=text(data.get('pcre',''))
    if buffer and not any(contents) and not pcre:raise ValueError('검사 버퍼에서 찾을 content 또는 PCRE를 입력하세요.')
    if buffer:opts.append(buffer)
    nocase=data.get('nocase',False)
    if type(nocase) is not bool:raise ValueError('nocase는 참/거짓 값입니다.')
    for content in contents:
        if content:
            opts.append('content:"'+suricata_string(content)+'"')
            if nocase:opts.append('nocase')
    if pcre:
        if '"' in pcre or not re.fullmatch(r'/.*?/[imsxAEGRUVPHDMCSYBO]*',pcre):raise ValueError('PCRE는 /정규식/옵션 형식이며 큰따옴표는 허용하지 않습니다.')
        opts.append('pcre:"'+pcre+'"')
    flags=choice(data,'flags',('','S','SA','A','F','R','P'),'')
    if flags:
        if proto!='tcp':raise ValueError('TCP flags는 tcp 프로토콜에서만 사용하세요.')
        opts.append('flags:'+flags)
    count=number(data,'threshold_count',0,0,1000000)
    if count:
        mode=choice(data,'threshold_type',('limit','threshold','both'),'both')
        track=choice(data,'threshold_track',('by_src','by_dst'),'by_src')
        seconds=number(data,'threshold_seconds',60,1,86400)
        opts.append(f'threshold:type {mode}, track {track}, count {count}, seconds {seconds}')
    category=choice(data,'classtype',('','web-application-attack','attempted-recon','attempted-dos','bad-unknown','policy-violation','trojan-activity'),'')
    if category:opts.append('classtype:'+category)
    if not any(contents) and not pcre and not flags:raise ValueError('탐지할 content, PCRE 또는 TCP flags 조건을 지정하세요.')
    sid=number(data,'sid',9000000,9000000,99999999);rev=number(data,'rev',1,1,65535)
    opts.extend([f'sid:{sid}',f'rev:{rev}'])
    header=[action,proto,address(data.get('src','any')),port(data.get('sport','any')),direction,address(data.get('dst','$HOME_NET')),port(data.get('dport','any'))]
    return ' '.join(header)+' ('+'; '.join(opts)+';)'


VARIABLES={'REQUEST_URI','REQUEST_FILENAME','ARGS','ARGS_NAMES','QUERY_STRING','REQUEST_BODY','REQUEST_HEADERS','REQUEST_COOKIES','REQUEST_METHOD','REMOTE_ADDR','RESPONSE_STATUS','RESPONSE_HEADERS','RESPONSE_BODY'}
TRANSFORMS={'none','lowercase','urlDecodeUni','removeNulls','compressWhitespace','htmlEntityDecode','normalizePath','removeWhitespace'}


def quoted(value):
    return text(value).replace('\\','\\\\').replace('"','\\"')


def build_waf(data):
    allowed={'variable','operator','pattern','negate','transforms','action','phase','status','severity','msg','id'}
    if set(data)-allowed:raise ValueError('지원하지 않는 템플릿 필드입니다.')
    variable=text(data.get('variable','ARGS'),200)
    for item in variable.split('|'):
        if not re.fullmatch(r'!?[A-Z_]+(?::[a-zA-Z0-9_.-]+)?',item) or item.lstrip('!').split(':')[0] not in VARIABLES:raise ValueError('검사 변수 형식을 확인하세요.')
    operator=choice(data,'operator',('@rx','@contains','@pm','@streq','@beginsWith','@endsWith','@detectSQLi','@detectXSS','@ipMatch','@eq','@gt','@lt'),'@contains')
    pattern=text(data.get('pattern',''))
    if operator in ('@detectSQLi','@detectXSS'):
        if pattern:raise ValueError('detectSQLi / detectXSS는 패턴 입력이 필요 없습니다.')
    elif not pattern:raise ValueError('탐지 패턴을 입력하세요.')
    negate=data.get('negate',False)
    if type(negate) is not bool:raise ValueError('부정 조건은 참/거짓 값입니다.')
    phase=number(data,'phase',2,1,4)
    if phase==1 and any(v in variable for v in ('ARGS','REQUEST_BODY','RESPONSE_')):raise ValueError('본문·인자 검사는 phase 2, 응답 검사는 phase 3/4를 사용하세요.')
    if 'RESPONSE_' in variable and phase<3:raise ValueError('응답 변수는 phase 3/4에서 검사하세요.')
    action=choice(data,'action',('deny','pass'),'pass');status=number(data,'status',403,400,599)
    transforms=data.get('transforms',['none'])
    if not isinstance(transforms,list) or len(transforms)>8 or any(t not in TRANSFORMS for t in transforms):raise ValueError('지원하지 않는 변환입니다.')
    severity=choice(data,'severity',('CRITICAL','ERROR','WARNING','NOTICE','INFO'),'WARNING')
    msg=text(data.get('msg','Custom WAF detection'),120)
    if not msg.strip() or any(c in msg for c in "'\"\\"):raise ValueError('탐지 메시지의 따옴표·역슬래시를 제거하세요.')
    ident=number(data,'id',9000000,9000000,99999999)
    acts=[f'id:{ident}',f'phase:{phase}',action]
    if action=='deny':acts.append(f'status:{status}')
    acts+=['log','auditlog']+['t:'+t for t in transforms]+["severity:'"+severity+"'","msg:'"+msg+"'"]
    expression=('!' if negate else '')+operator+(' '+pattern if pattern else '')
    return 'SecRule '+variable+' "'+quoted(expression)+'" "'+','.join(acts)+'"'
