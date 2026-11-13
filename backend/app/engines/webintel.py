"""Bounded, non-destructive web surface discovery for explicitly authorized domains."""
import ipaddress, re, socket, time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import requests
from .discovery import resolver
from ..config import UA

# Deliberately small wordlists: no recursion, brute-force expansion, auth bypass or payloads.
DIRECTORY_CANDIDATES = (
    "api", "api/v1", "api/v2", "docs", "swagger", "swagger-ui", "openapi.json",
    "openapi.yaml", "redoc", "graphql", "graphiql", "health", "status", "metrics",
    "admin", "login", "robots.txt", "sitemap.xml", ".well-known/security.txt",
    ".well-known/openid-configuration", "actuator/health", "server-status"
)
API_CANDIDATES = ("openapi.json", "swagger.json", "api-docs", "v3/api-docs", "swagger/v1/swagger.json",
                  "graphql", "graphiql", "api/openapi.json", "api/swagger.json")

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links=[]; self.scripts=[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag.lower()=="a" and a.get("href"): self.links.append(a["href"])
        if tag.lower()=="script" and a.get("src"): self.scripts.append(a["src"])

def _public_host(host):
    try:
        r=resolver(); ips=[]
        for qtype in ("A", "AAAA"):
            try:
                ans=r.resolve(host, qtype, raise_on_no_answer=False)
                if ans.rrset: ips.extend(str(x) for x in ans)
            except Exception: pass
        # Fail closed if any returned address is private, loopback, link-local or reserved.
        return bool(ips) and all(ipaddress.ip_address(x).is_global for x in ips)
    except Exception: return False

def _safe_url(host, path):
    return f"https://{host}/" + path.lstrip("/")

def _get(url, timeout=4):
    p=urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname: return None
    try:
        # Redirects are disabled to avoid leaving the authorized host scope.
        r=requests.get(url, headers={"User-Agent":UA,"Accept":"*/*"}, timeout=timeout,
                       allow_redirects=False, stream=True, verify=True)
        length=int(r.headers.get("Content-Length", "0") or 0)
        body=b""
        if length<=512000:
            body=r.raw.read(512000, decode_content=True)
        result={"status":r.status_code,"content_type":r.headers.get("Content-Type",""),
                "server":r.headers.get("Server"),"location":r.headers.get("Location"),
                "bytes_read":len(body),"body":body.decode("utf-8","replace")}
        r.close(); return result
    except Exception as e: return {"error":type(e).__name__}

def enumerate_directories(host, max_requests=22):
    if not _public_host(host): return {"host":host,"skipped":"Host did not resolve to a public IP address.","results":[]}
    out=[]
    for path in DIRECTORY_CANDIDATES[:max_requests]:
        url=_safe_url(host,path); r=_get(url)
        if r and (r.get("status") in (200,201,202,204,301,302,307,308,401,403) or r.get("error")):
            out.append({"path":"/"+path,"url":url,"status":r.get("status"),"content_type":r.get("content_type"),
                        "server":r.get("server"),"location":r.get("location"),"error":r.get("error"),
                        "source":"bounded-path-check"})
        time.sleep(.12)
    return {"host":host,"checked":min(max_requests,len(DIRECTORY_CANDIDATES)),"results":out}

def discover_api(host, max_requests=12):
    if not _public_host(host): return {"host":host,"skipped":"Host did not resolve to a public IP address.","endpoints":[]}
    found=[]; candidates=list(API_CANDIDATES)
    # Read only robots.txt and sitemap.xml to collect publicly advertised API/documentation paths.
    for p in ("robots.txt","sitemap.xml"):
        r=_get(_safe_url(host,p))
        if r and r.get("status")==200:
            for path in re.findall(r"(?im)(?:Disallow:|Allow:|<loc>)([^\s<]+)",r.get("body", "")):
                u=urlparse(path)
                if u.scheme and u.hostname!=host: continue
                clean=(u.path if u.scheme else path).strip()
                if clean.startswith("/") and any(k in clean.lower() for k in ("api","swagger","openapi","graphql")):
                    candidates.append(clean.lstrip("/"))
    seen=set()
    for path in candidates:
        if path in seen: continue
        seen.add(path); url=_safe_url(host,path); r=_get(url)
        if r and r.get("status") in (200,301,302,401,403):
            ctype=(r.get("content_type") or "").lower(); body=r.get("body","")
            indicative=any(x in path.lower() for x in ("api","swagger","openapi","graphql","redoc")) or "openapi" in body[:10000].lower() or '"paths"' in body[:10000]
            if indicative:
                found.append({"path":"/"+path,"url":url,"status":r["status"],"content_type":ctype,
                              "spec_indicator":("openapi" in body[:10000].lower() or '"paths"' in body[:10000]),
                              "source":"public-http-observation"})
        time.sleep(.12)
        if len(seen)>=max_requests: break
    return {"host":host,"checked":len(seen),"endpoints":found}

def email_posture(domain, dns_records):
    txt=dns_records.get("TXT",[]); mx=dns_records.get("MX",[])
    spf=[x for x in txt if "v=spf1" in x.lower()]
    dmarc=[]
    try:
        ans=resolver().resolve("_dmarc."+domain,"TXT",raise_on_no_answer=False)
        dmarc=[str(x).strip('"') for x in ans] if ans.rrset else []
    except Exception: pass
    dkim_status="not assessed"  # Selector discovery is organization-specific; never claim absence from a guessed selector list.
    mta=[]
    try:
        ans=resolver().resolve("_mta-sts."+domain,"TXT",raise_on_no_answer=False)
        mta=[str(x).strip('"') for x in ans] if ans.rrset else []
    except Exception: pass
    try:
        ans=resolver().resolve("_smtp._tls."+domain,"TXT",raise_on_no_answer=False)
        tlsrpt=[str(x).strip('"') for x in ans] if ans.rrset else []
    except Exception: tlsrpt=[]
    return {"domain":domain,"mx_records":mx,"spf":{"present":bool(spf),"records":spf},
            "dmarc":{"present":bool(dmarc),"records":dmarc,"policy":next((re.search(r"(?:^|;)\s*p=([^;]+)",x,re.I).group(1) for x in dmarc if re.search(r"(?:^|;)\s*p=([^;]+)",x,re.I)),None)},
            "dkim":{"status":dkim_status,"note":"DKIM selectors are provider-specific; configure known selectors for definitive assessment."},
            "mta_sts":{"present":bool(mta),"records":mta},"tls_reporting":{"present":bool(tlsrpt),"records":tlsrpt},
            "limitations":["DNS presence checks do not prove correct SPF/DKIM/DMARC alignment.","DKIM was not assessed because selectors were not supplied."]}

CLOUD_SUFFIXES={"amazonaws.com":"AWS","cloudfront.net":"AWS CloudFront","azurewebsites.net":"Microsoft Azure App Service",
                "blob.core.windows.net":"Azure Blob Storage","trafficmanager.net":"Azure Traffic Manager",
                "googleapis.com":"Google Cloud","appspot.com":"Google App Engine","cloudfunctions.net":"Google Cloud Functions",
                "herokuapp.com":"Heroku","vercel.app":"Vercel","netlify.app":"Netlify","fastly.net":"Fastly","cloudflare.net":"Cloudflare"}
def cloud_indicators(host, records):
    indicators=[]
    for cname in records.get("CNAME",[]):
        target=cname.lower().rstrip(".")
        for suffix,provider in CLOUD_SUFFIXES.items():
            if target==suffix or target.endswith("."+suffix):
                indicators.append({"type":"provider-cname","provider":provider,"target":target,"confidence":"high","evidence":"DNS CNAME points to a recognized provider hostname."})
    return {"host":host,"indicators":indicators,"note":"Provider association is an infrastructure clue, not proof of account ownership or a cloud misconfiguration. No storage buckets or cloud resources are actively probed."}
