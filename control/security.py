"""Shared security primitives. No shell, pickle or client-selected upstream URLs."""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
from urllib.parse import urlsplit
from fastapi import HTTPException

HOST_RE = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')

def secret(name, default=''):
    path = os.environ.get(name + '_FILE')
    return open(path).read().strip() if path else os.environ.get(name, default)

def password_hash(value):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + ':' + digest.hex()

def password_verify(value, encoded):
    try:
        salt, expected = encoded.split(':')
        actual = hashlib.scrypt(value.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def domain(value):
    value = value.lower().rstrip('.')
    if not HOST_RE.fullmatch(value) or value.endswith(('.localhost', '.local')):
        raise HTTPException(422, '올바른 FQDN을 입력하세요. 내부 도메인은 .internal을 사용하세요.')
    return value

def target(value, cidrs=None):
    """Validate at registration AND every connection, then connect to the pinned IP."""
    u = urlsplit(value)
    if u.scheme != 'http' or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise HTTPException(422, '내부 HTTP 서비스 주소만 등록할 수 있습니다.')
    try:
        port = u.port or 80
        host = u.hostname
        if not host or not re.fullmatch(r'[a-zA-Z0-9.-]+', host):
            raise ValueError()
        networks = [ipaddress.ip_network(c) for c in (cidrs or os.getenv('ENDPOINT_CIDRS', '10.88.40.0/24').split(','))]
        addresses = {item[4][0] for item in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)}
        if not addresses or any(not any(ipaddress.ip_address(a) in n for n in networks) for a in addresses):
            raise ValueError()
        # Reserved management addresses cannot become endpoint services.
        reserved = set(os.getenv('RESERVED_UPSTREAM_IPS', '10.88.40.1,10.88.40.2,10.88.40.3').split(','))
        if addresses & reserved or not 1 <= port <= 65535:
            raise ValueError()
        return sorted(addresses)[0], port, host
    except (ValueError, OSError):
        raise HTTPException(422, '엔드포인트는 승인된 내부 앱 네트워크에 있어야 합니다.')

def cidr(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or network.prefixlen < 8:
            raise ValueError()
        return str(network)
    except ValueError:
        raise HTTPException(422, 'IPv4 주소 또는 /8 이상 CIDR을 입력하세요.')
