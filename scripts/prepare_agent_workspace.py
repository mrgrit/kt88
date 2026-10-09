"""Seed standard agent files once; preserve GUI edits on reinstall."""
import os,shutil
from pathlib import Path

def prepare(root):
 workspace=root/'.runtime/agent-workspace'
 for relative in ('AGENTS.md','CLAUDE.md','.agents/skills/platform-health/SKILL.md','.agents/skills/soc-triage/SKILL.md'):
  source=root/relative;target=workspace/relative
  if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
 (workspace/'.claude/agents').mkdir(parents=True,exist_ok=True)
 for role in ('platform-health','soc-triage'):
  p=workspace/'.claude/agents'/f'{role}.md'
  if not p.exists():p.write_text(f'---\nname: {role}\ndescription: {role} 운영 조사\n---\n\nAGENTS.md와 .agents/skills/{role}/SKILL.md를 읽고 근거를 보고하세요.\n')
 if os.geteuid()==0:
  os.chown(workspace,10001,10001)
  for p in workspace.rglob('*'):os.chown(p,10001,10001)
 return workspace
if __name__=='__main__':prepare(Path(__file__).resolve().parents[1])
