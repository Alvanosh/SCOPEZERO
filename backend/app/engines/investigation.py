"""Evidence-led investigation helpers. No exploit payload generation or automatic exploitation."""
import hashlib, ipaddress, socket
from urllib.parse import urlparse

def sha256_text(value: str) -> str:
    return hashlib.sha256((value or '').encode('utf-8', errors='replace')).hexdigest()

def confidence_from_evidence(evidence, source_count=1):
    text=str(evidence or '').lower(); score=25
    if any(k in text for k in ('http_status','response','dns','certificate','version')): score += 20
    if any(k in text for k in ('reproduced','confirmed','matched')): score += 25
    score += min(max(int(source_count)-1,0)*10,20)
    return min(score,90)

def risk_score(severity, epss=None, kev=False, internet_facing=True, confidence=50):
    base={'Critical':95,'High':78,'Medium':55,'Low':30,'Info':10}.get(str(severity).title(),20)
    score=base*.55 + (min(max(float(epss or 0),0),1)*100)*.20 + (15 if kev else 0) + (8 if internet_facing else 0)
    return round(min(100,score*(.65+.35*min(max(confidence,0),100)/100)))

def validate_public_target(host):
    try:
        infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
        ips={ipaddress.ip_address(x[4][0]) for x in infos}
        return bool(ips) and all(x.is_global for x in ips)
    except Exception: return False

def url_host(url):
    p=urlparse(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password: return None
    return p.hostname.lower().rstrip('.')
