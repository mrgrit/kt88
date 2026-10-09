"""Standard agent/skill files; organization and history stay in the platform DB."""
import hashlib,json,os,re,time
from pathlib import Path
import yaml
from fastapi import HTTPException
from .db import connect

SLUG=re.compile(r'^[a-z][a-z0-9-]{1,47}$')
def root():
 from .agents import WORKSPACE
 return WORKSPACE

def path(relative):
 base=root();p=base/relative
 if not p.resolve().is_relative_to(base.resolve()) or any(q.is_symlink() for q in [p,*list(p.parents)[:len(p.relative_to(base).parts)]]):raise HTTPException(422,'허용되지 않은 설정 경로입니다.')
 return p

def sha(text):return hashlib.sha256(text.encode()).hexdigest()

def split(text):
 if not isinstance(text,str) or len(text)>30000 or not text.startswith('---\n'):raise HTTPException(422,'YAML frontmatter가 있는 Markdown (최대 30,000자)이 필요합니다.')
 parts=text.split('---',2)
 try:
  header=yaml.safe_load(parts[1]);body=parts[2].strip()
  if not isinstance(header,dict) or not body:raise ValueError()
 except (ValueError,IndexError,yaml.YAMLError):raise HTTPException(422,'Markdown frontmatter 및 본문을 확인하세요.')
 return header,body

def identifier(value):
 if not isinstance(value,str) or not SLUG.fullmatch(value):raise HTTPException(422,'ID는 소문자·숫자·하이픈 2~48자입니다.')
 return value

def skill_path(name):return path('.agents/skills/'+identifier(name)+'/SKILL.md')

def skill(name):
 p=skill_path(name)
 if not p.exists():raise HTTPException(404,'스킬이 없습니다.')
 text=p.read_text();header,body=split(text)
 if header.get('name')!=name or not isinstance(header.get('description'),str):raise HTTPException(422,'스킬 이름과 설명을 확인하세요.')
 return {'name':name,'description':header['description'],'content':text,'body':body,'path':str(p.relative_to(root())),'sha256':sha(text)}

def backup(relative):
 p=path(relative)
 if p.exists():
  with connect() as db:
   db.execute('INSERT INTO config_backups(path,content,created) VALUES(?,?,?)',(relative,p.read_text(),time.time()))
   db.execute('DELETE FROM config_backups WHERE path=? AND id NOT IN (SELECT id FROM config_backups WHERE path=? ORDER BY id DESC LIMIT 20)',(relative,relative))

def write(relative,text):
 p=path(relative);backup(relative);p.parent.mkdir(parents=True,exist_ok=True);temp=p.with_suffix('.tmp');temp.write_text(text);temp.replace(p)

def library():
 from .agents import definitions
 agents,errors=definitions();rows=[]
 for p in sorted((root()/'.agents/skills').glob('*/SKILL.md')):
  try:
   s=skill(p.parent.name);workers=[{'id':a['id'],'name':a['name'],'active':a['enabled']} for a in agents if s['name'] in a.get('skills',[])]
   rows.append({k:s[k] for k in ('name','description','path','sha256')}|{'workers':workers,'automatic':[],'deletable':not workers})
  except HTTPException as e:errors.append({'id':p.parent.name,'message':e.detail})
 return {'skills':rows,'errors':[str(e) for e in errors]}

def save_skill(name,text,version=None):
 identifier(name);header,body=split(text)
 if header.get('name')!=name or not isinstance(header.get('description'),str) or not 1<=len(header['description'])<=1000:raise HTTPException(422,'name은 폴더명과 같고 description이 필요합니다.')
 p=skill_path(name)
 if p.exists() and sha(p.read_text())!=version:raise HTTPException(409,'스킬이 변경되었습니다. 다시 불러오세요.')
 write(str(p.relative_to(root())),text)
 # Each framework gets its native skill path. These are derived, never independent edits.
 export_skills()
 return skill(name)

def export_skills():
 import shutil
 for p in (root()/'.agents/skills').glob('*/SKILL.md'):
  identifier(p.parent.name)
  source=skill(p.parent.name)
  for relative in ('.claude/skills/'+p.parent.name+'/SKILL.md','.hermes/skills/'+p.parent.name+'/SKILL.md'):
   target=path(relative);target.parent.mkdir(parents=True,exist_ok=True);target.write_text(source['content'])

def export_agent(definition):
 d=definition;ident=identifier(d['id']);instruction=d['instructions']+'\n\n연결 스킬: '+', '.join(d.get('skills',[]))+'\n운영 권한은 kt88 서버의 도구 범위로 제한됩니다.'
 # Codex custom agents inherit the caller's configured model/provider.
 toml='name = '+json.dumps(ident)+'\ndescription = '+json.dumps(d['description'],ensure_ascii=False)+'\ndeveloper_instructions = '+json.dumps(instruction,ensure_ascii=False)+'\nsandbox_mode = "read-only"\n'
 p=path('.codex/agents/'+ident+'.toml');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(toml)
 profile=path('.hermes/profiles/'+ident+'/SOUL.md');profile.parent.mkdir(parents=True,exist_ok=True);profile.write_text(instruction+'\n')
 config=path('.hermes/profiles/'+ident+'/config.yaml')
 config.write_text(yaml.safe_dump({'model':{'default':d['model']},'agent':{'max_turns':8}},allow_unicode=True))
 # Profile-local skills are independent in Hermes; populate only assigned procedures.
 skills=path('.hermes/profiles/'+ident+'/skills');skills.mkdir(exist_ok=True)
 for p in skills.glob('*/SKILL.md'):
  if p.parent.name not in d.get('skills',[]):path(str(p.relative_to(root()))).unlink()
 for name in d.get('skills',[]):
  s=skill(name);p=path('.hermes/profiles/'+ident+'/skills/'+name+'/SKILL.md');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s['content'])

def default_org():
 return {'company':{'company':{'vision':'안전하고 지속 가능한 웹서비스 운영','priority_order':['서비스와 데이터 보호','근거 기반 판단','운영 효율'],'goals':[],'operating_principles':[]}},
 'departments':{'departments':[{'id':'infra','name':'인프라운영','floor':'전산실','mission':'네트워크·서버·서비스 운영','not_our_job':'콘텐츠 임의 공개','teams':['systems-team']},{'id':'xoc','name':'통합관제','floor':'운영사무실','mission':'보안 경보와 에이전트 실행 조사','not_our_job':'근거 없는 자동 변경','teams':['soc-team']}]},
 'teams':{'teams':[{'id':'systems-team','name':'시스템·네트워크팀','department':'infra','members':[],'kpi':[]},{'id':'soc-team','name':'SOC팀','department':'xoc','members':[],'kpi':[]}]},'graph':{'nodes':[],'edges':[],'open_questions':[]}}

def organization():
 with connect() as db:row=db.execute("SELECT value FROM runtime_state WHERE key='agent-organization'").fetchone()
 return json.loads(row[0]) if row else default_org()

def save_org(value):
 from .agents import definitions
 departments=value.get('departments',{}).get('departments',[]);teams=value.get('teams',{}).get('teams',[])
 if len(teams)>40 or len(departments)>20:raise HTTPException(422,'조직 크기 제한 초과')
 dept_ids=[identifier(d['id']) for d in departments];team_ids=[identifier(t['id']) for t in teams]
 if len(set(dept_ids))!=len(dept_ids) or len(set(team_ids))!=len(team_ids):raise HTTPException(422,'중복 조직 ID')
 for team in teams:
  if team['department'] not in dept_ids:raise HTTPException(422,'팀의 부서가 없습니다.')
 for agent in definitions()[0]:
  if agent.get('team') and agent['team'] not in team_ids:raise HTTPException(409,'소속 에이전트가 있는 팀은 먼저 소속을 변경하세요.')
 graph=value.get('graph',{});ids={n['id'] for n in graph.get('nodes',[])}
 for edge in graph.get('edges',[]):
  if edge.get('from') not in ids or edge.get('to') not in ids or not edge.get('source'):raise HTTPException(422,'경험 그래프 연결에는 양 끝 노드와 출처가 필요합니다.')
 with connect() as db:
  db.execute('INSERT INTO config_backups(path,content,created) VALUES(?,?,?)',('organization',json.dumps(organization(),ensure_ascii=False),time.time()))
  db.execute("INSERT OR REPLACE INTO runtime_state VALUES('agent-organization',?)",(json.dumps(value,ensure_ascii=False),))
