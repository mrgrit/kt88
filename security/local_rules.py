"""Native rule text and safe, atomic file exchange with the IPS worker."""
import hashlib
import json
import re
from pathlib import Path

MAX_BYTES = 256 * 1024

def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def validate_text(text):
    if len(text.encode('utf-8')) > MAX_BYTES or '\x00' in text:
        raise ValueError('규칙 파일은 UTF-8 256 KiB 이하이며 NUL 문자를 포함할 수 없습니다.')
    # Native signatures are supported; local script/file access stays outside the web editor.
    code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    if re.search(r'(?:[;(]\s*|\n\s*)(?:lua|luajit|dataset)\s*:', code, re.I):
        raise ValueError('스크립트 실행 및 외부 파일을 읽거나 쓰는 lua/luajit/dataset 규칙은 콘솔에서 관리하세요.')
    return text

def atomic(path, content):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(content, encoding='utf-8')
    tmp.replace(path)

def write_json(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False))
