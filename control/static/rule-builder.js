/* Detection templates append reviewed native text; only the engine-tested editor applies it. */
window.renderRuleBuilder=function(device,root,editor,role,api){
 const make=(tag,value,cls)=>{const n=document.createElement(tag);if(value!==undefined)n.textContent=value;if(cls)n.className=cls;return n};
 const section=make('section',undefined,'rule-builder'),form=make('form',undefined,'grid-form');form.id=device+'-rule-builder';section.id=device+'-builder';
 section.append(make('h3',device==='ips'?'IPS 탐지룰 템플릿':'WAF SecRule 템플릿'),make('p','템플릿 선택 → 탐지 조건 구성 → 룰 미리보기 → 아래 전문에 추가 → 엔진 구문 검사 → 저장·적용'));
 if(device==='ips')section.append(make('p','IPS는 TLS 종료 전 트래픽을 검사합니다. HTTP content는 평문 HTTP에 적용되며 HTTPS 내부 URI·본문은 WAF에서 검사하세요. threshold는 경보 빈도 조건이며 drop의 차단 시작 횟수와 같지 않습니다.','rule-help'));
 const fields={};function field(label,key,value,options){const wrap=make('label',label),n=make(options?'select':'input');n.name=key;n.id=device+'-builder-'+key;if(options)for(const [v,t] of options){const o=make('option',t);o.value=v;n.append(o)}else{n.type='text';n.maxLength=500}n.value=value;wrap.append(n);form.append(wrap);fields[key]=n;return n}
 const presets=device==='ips'?[
  ['payload','TCP 페이로드 문자열'],['http','HTTP URI 문자열'],['agent','HTTP User-Agent'],['dns','DNS 질의 도메인'],['tls','TLS SNI 도메인'],['syn','TCP SYN 빈도']
 ]:[['contains','요청 인자 문자열'],['sqli','SQL 삽입 탐지 · libinjection'],['xss','XSS 탐지 · libinjection'],['path','요청 경로 접두어'],['agent','User-Agent 문자열'],['regex','요청 정규식']];
 const preset=field('빠른 템플릿','template',presets[0][0],presets);
 const nextId=()=>Math.max(8999999,...[...editor.value.matchAll(device==='ips'?/\bsid\s*:\s*(\d+)/g:/\bid\s*:\s*(\d+)/g)].map(m=>Number(m[1])).filter(n=>n>=9000000&&n<99999999))+1;
 field('동작','action',device==='ips'?'alert':'pass',device==='ips'?[['alert','탐지 · 경보'],['drop','차단 · drop'],['reject','차단 · reject']]:[['pass','탐지 · 로그'],['deny','차단 · deny']]);
 field('탐지 메시지 · msg','msg',device==='ips'?'Custom IPS detection':'Custom WAF detection');
 if(device==='ips'){
  field('프로토콜','proto','tcp',['tcp','udp','icmp','ip','http','dns','tls'].map(v=>[v,v]));
  field('출발 주소 / CIDR','src','any');field('출발 포트','sport','any');field('방향','direction','->',[['->','출발 → 목적'],['<>','양방향 ↔']]);field('목적 주소 / CIDR','dst','$HOME_NET');field('목적 포트','dport','any');
  field('흐름 · flow','flow','established,to_server',[['','제한 없음'],['established,to_server','연결 수립 · 서버 방향'],['established,to_client','연결 수립 · 클라이언트 방향'],['to_server','서버 방향'],['to_client','클라이언트 방향'],['stateless','상태 제한 없음']]);
  field('검사 버퍼','buffer','',[['','패킷 페이로드'],...['http.uri','http.method','http.user_agent','http.request_body','http.header','dns.query','tls.sni'].map(v=>[v,v])]);
  field('찾을 문자열 · content','content','KT88_TEST');field('추가 문자열 · AND 조건','content2','');field('PCRE · /정규식/옵션 (선택)','pcre','');field('대소문자 무시 · nocase','nocase','true',[['true','사용'],['false','사용 안 함']]);
  field('TCP flags (선택)','flags','',[['','없음'],...['S','SA','A','F','R','P'].map(v=>[v,v])]);
  field('경보 빈도 · threshold','threshold_type','both',[['both','both · 기준 충족 후 제한'],['threshold','threshold · N건마다'],['limit','limit · 최대 N건']]);
  field('집계 기준','threshold_track','by_src',[['by_src','출발 주소별'],['by_dst','목적 주소별']]);field('횟수 · 0이면 사용 안 함','threshold_count','0');field('시간 · 초','threshold_seconds','60');
  field('분류 · classtype','classtype','',[['','없음'],...['web-application-attack','attempted-recon','attempted-dos','bad-unknown','policy-violation','trojan-activity'].map(v=>[v,v])]);field('SID · 9000000 이상','sid',nextId());field('규칙 버전 · rev','rev','1');
 }else{
  field('검사 변수 · |로 여러 변수 연결','variable','ARGS');field('연산자','operator','@contains',['@contains','@rx','@pm','@streq','@beginsWith','@endsWith','@detectSQLi','@detectXSS','@ipMatch','@eq','@gt','@lt'].map(v=>[v,v]));
  field('탐지 패턴','pattern','KT88_TEST');field('부정 조건','negate','false',[['false','일치할 때'],['true','일치하지 않을 때']]);
  field('처리 단계 · phase','phase','2',[[1,'1 · 요청 헤더'],[2,'2 · 요청 본문·인자'],[3,'3 · 응답 헤더'],[4,'4 · 응답 본문']]);field('변환 · 쉼표로 순서 지정','transforms','none,urlDecodeUni,lowercase');
  field('차단 응답 상태','status','403');field('심각도','severity','WARNING',['CRITICAL','ERROR','WARNING','NOTICE','INFO'].map(v=>[v,v]));field('룰 ID · 9000000 이상','id',nextId());
  section.append(make('p','변수 예: ARGS, REQUEST_URI, REQUEST_HEADERS:User-Agent, REQUEST_COOKIES. 변환: none, lowercase, urlDecodeUni, removeNulls, compressWhitespace, htmlEntityDecode, normalizePath, removeWhitespace.','rule-help'));
 }
 const controls=make('div',undefined,'button-row rule-full'),preview=make('button','룰 미리보기'),append=make('button','아래 전문에 룰 추가','secondary'),code=make('pre','탐지 조건을 구성하고 미리보기를 누르세요.','report rule-full'),status=make('p','','rule-full');code.id=device+'-rule-preview';status.id=device+'-builder-status';status.setAttribute('role','status');append.type='button';append.disabled=true;preview.id=device+'-preview-rule';append.id=device+'-append-rule';let generated=null,serial=0;
 function invalidate(){serial++;generated=null;append.disabled=true;code.textContent='입력값이 변경되었습니다. 미리보기를 다시 생성하세요.';status.textContent=''}
 function applyPreset(){
  const value=preset.value;let values;
  if(device==='ips'){
   values={proto:'tcp',flow:'established,to_server',buffer:'',content:'KT88_TEST',content2:'',pcre:'',flags:'',threshold_count:'0',msg:'Custom payload detection'};
   if(value==='http')Object.assign(values,{proto:'http',buffer:'http.uri',content:'/example',msg:'HTTP URI detection'});
   if(value==='agent')Object.assign(values,{proto:'http',buffer:'http.user_agent',content:'ExampleScanner',msg:'HTTP User-Agent detection'});
   if(value==='dns')Object.assign(values,{proto:'dns',flow:'to_server',buffer:'dns.query',content:'example.invalid',msg:'DNS query detection'});
   if(value==='tls')Object.assign(values,{proto:'tls',buffer:'tls.sni',content:'example.invalid',msg:'TLS SNI detection'});
   if(value==='syn')Object.assign(values,{proto:'tcp',flow:'stateless',content:'',flags:'S',threshold_count:'10',msg:'TCP SYN rate detection'});
  }else{
   values={variable:'ARGS',operator:'@contains',pattern:'KT88_TEST',phase:'2',transforms:'none,urlDecodeUni,lowercase',msg:'Request argument detection'};
   if(value==='sqli')Object.assign(values,{variable:'ARGS|ARGS_NAMES',operator:'@detectSQLi',pattern:'',msg:'SQL injection detection'});
   if(value==='xss')Object.assign(values,{variable:'ARGS|ARGS_NAMES',operator:'@detectXSS',pattern:'',msg:'XSS detection'});
   if(value==='path')Object.assign(values,{variable:'REQUEST_URI',operator:'@beginsWith',pattern:'/example',phase:'1',msg:'Request path detection'});
   if(value==='agent')Object.assign(values,{variable:'REQUEST_HEADERS:User-Agent',operator:'@contains',pattern:'examplescanner',phase:'1',msg:'User-Agent detection'});
   if(value==='regex')Object.assign(values,{operator:'@rx',pattern:'(?i)(union.+select)',msg:'Request regex detection'});
  }
  for(const [key,value] of Object.entries(values))fields[key].value=value;invalidate();
 }
 preset.addEventListener('change',applyPreset);form.addEventListener('input',invalidate);
 form.onsubmit=async event=>{event.preventDefault();if(role!=='admin')return;invalidate();const generation=serial;preview.disabled=true;status.textContent='룰 생성 중…';try{
  const data=Object.fromEntries(new FormData(form));delete data.template;
  for(const key of device==='ips'?['sid','rev','threshold_count','threshold_seconds']:['id','phase','status'])data[key]=Number(data[key]);
  if(device==='ips')data.nocase=data.nocase==='true';else{data.negate=data.negate==='true';data.transforms=data.transforms.split(',').map(v=>v.trim()).filter(Boolean)}
  const result=await api('devices/'+device+'/rule-preview','POST',data);if(generation!==serial)return;
  generated=result.rule;code.textContent=generated;append.disabled=false;status.textContent='미리보기입니다. 전문에 추가한 후 엔진 검사를 진행하세요.';
 }catch(error){if(generation===serial)status.textContent=error.message}finally{preview.disabled=role!=='admin'}};
 append.onclick=()=>{if(!generated||role!=='admin'||editor.readOnly)return;const key=device==='ips'?'sid':'id',id=fields[key].value,pattern=new RegExp('\\b'+key+'\\s*:\\s*'+id+'\\b');if(pattern.test(editor.value)){status.textContent='같은 SID / 룰 ID가 이미 있습니다. 번호를 변경하세요.';return}editor.value=editor.value+(editor.value&&!editor.value.endsWith('\n')?'\n':'')+generated+'\n';editor.dispatchEvent(new Event('input',{bubbles:true}));fields[key].value=nextId();invalidate();status.textContent='전문에 추가했습니다. 아래에서 구문 검사 후 저장·적용하세요.';editor.scrollIntoView({block:'center',behavior:'smooth'})};
 controls.append(preview,append);form.append(controls,code,status);section.append(form);root.append(section);
 if(role!=='admin')for(const control of form.elements)control.disabled=true;
};
