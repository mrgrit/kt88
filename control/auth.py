import hmac
import time
from fastapi import Request, HTTPException
from .db import connect
from .security import digest, secret

COOKIE = '__Host-kt88'

def user(request: Request, roles=('admin','operator','viewer'), *, csrf=True):
    token = request.cookies.get(COOKIE, '')
    with connect() as db:
        row = db.execute('SELECT u.*,s.csrf,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE token=?', (digest(token),)).fetchone()
    if not row or row['expires'] < time.time() or row['disabled']:
        raise HTTPException(401, '로그인이 필요합니다.')
    if row['role'] not in roles:
        raise HTTPException(403, '이 작업에 대한 권한이 없습니다.')
    if row['must_change'] and request.url.path not in ('/_kt88/api/password','/_kt88/api/me','/_kt88/api/logout'):
        raise HTTPException(403, '초기 비밀번호를 먼저 변경하세요.')
    if csrf and request.method not in ('GET','HEAD','OPTIONS'):
        origin = request.headers.get('origin', '')
        # No wildcard or forwarded-host trust. Browser writes require exact site origin.
        expected = 'https://' + request.headers.get('host', '')
        if origin != expected or not hmac.compare_digest(request.headers.get('x-csrf-token',''), row['csrf']):
            raise HTTPException(403, 'CSRF 검증 실패')
    return dict(row)

def machine(request, scope='read'):
    name = 'AGENT_TOKEN' if scope == 'read' else 'INSTALL_TOKEN'
    expected = secret(name)
    if not expected or not hmac.compare_digest(request.headers.get('authorization',''), 'Bearer ' + expected):
        raise HTTPException(401, '유효한 서비스 토큰이 필요합니다.')
