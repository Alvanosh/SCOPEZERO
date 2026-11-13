import re, requests, dns.resolver as dnsmod, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from ..config import UA
WORDS="""www api app admin portal mail webmail smtp ftp vpn remote dev development test testing stage staging uat qa preprod beta old legacy internal secure login auth sso dashboard panel docs help support status cdn static assets images media backup db git gitlab jenkins monitor grafana kibana search sandbox demo preview api-dev api-test dev-api staging-api mobile shop payment billing cloud storage origin gateway autodiscover owa exchange""".split()
_DNS_POOL=ThreadPoolExecutor(max_workers=32)
def normalize(value):
    v=value.strip().lower()
    if "://" in v: v=urlparse(v).hostname or ""
    v=v.rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",v):
        raise ValueError("Enter a valid domain, such as example.com.")
    return v
def resolver():
    r=dnsmod.Resolver()
    r.timeout=0.65
    r.lifetime=1.0
    return r
def ct(domain):
    try:
        r=requests.get("https://crt.sh/",params={"q":f"%.{domain}","output":"json"},headers={"User-Agent":UA},timeout=15)
        r.raise_for_status()
        names={domain}
        for row in r.json():
            for raw in str(row.get("name_value","")).splitlines():
                h=raw.strip().lower().lstrip("*.")
                if (h==domain or h.endswith("."+domain)) and re.fullmatch(r"[a-z0-9.-]+",h):
                    names.add(h)
        return names,None
    except Exception as e:
        return {domain},type(e).__name__
def dns_records(host):
    # Independent record types are queried concurrently with bounded deadlines.
    def query(typ):
        try:
            ans=resolver().resolve(host,typ,raise_on_no_answer=False)
            return typ,[str(x).strip('"') for x in ans] if ans.rrset else []
        except Exception:
            return typ,[]
    out={}
    for typ,values in _DNS_POOL.map(query,("A","AAAA","CNAME","MX","NS","TXT","CAA","SOA")):
        if values: out[typ]=values
    return out
def wordlist(domain, progress=None):
    found=set()
    def probe(item):
        i,w=item; h=f"{w}.{domain}"
        try:
            r=resolver()
            for typ in ("A","AAAA","CNAME"):
                ans=r.resolve(h,typ,raise_on_no_answer=False)
                if ans.rrset: return i,h
        except Exception: pass
        return i,None
    with ThreadPoolExecutor(max_workers=16) as pool:
        for done,(i,h) in enumerate(pool.map(probe,enumerate(WORDS,1)),1):
            if h: found.add(h)
            if progress: progress(done,len(WORDS))
    return found

def permutations(domain, discovered):
    # Generate candidate names only; no network requests are made here.
    roots=("dev","test","stage","staging","api","admin","portal","uat","qa")
    suffixes=("","-dev","-test","-stage","-staging","-old","-v2")
    return {f"{r}{s}.{domain}" for r in roots for s in suffixes if f"{r}{s}.{domain}" not in discovered}


import subprocess, shutil, ipaddress
from .process import run_binary

def external_enumerators(domain, timeout=90):
    """Run installed passive enumerators concurrently with bounded process cleanup."""
    def run(item):
        tool,args=item
        result=run_binary(tool,args,timeout=timeout)
        hosts=set()
        for line in result.get("stdout","").splitlines():
            h=line.strip().lower().rstrip(".")
            if h and (h==domain or h.endswith("."+domain)) and re.fullmatch(r"[a-z0-9.-]+",h):
                hosts.add(h)
        return tool,{"available":result.get("available",False),"status":result.get("status"),
            "hosts":sorted(hosts),"returncode":result.get("returncode"),
            "error":result.get("error"),"stderr_tail":result.get("stderr","")[-1500:],
            "diagnostics":result.get("diagnostics"),"elapsed_seconds":result.get("elapsed_seconds")}
    commands=(("subfinder",["-d",domain,"-silent","-timeout","10","-max-time","1","-duc"]),
              ("amass",["enum","-passive","-d",domain,"-timeout","2","-silent"]))
    with ThreadPoolExecutor(max_workers=2) as pool:
        return dict(pool.map(run,commands))

def shodan_internetdb(ip, timeout=5):
    """Query public Shodan InternetDB metadata for an already-discovered global IP."""
    try:
        if not ipaddress.ip_address(ip).is_global: return None
        r=requests.get(f"https://internetdb.shodan.io/{ip}",headers={"User-Agent":UA},timeout=timeout)
        if r.status_code==404:return {"ip":ip,"found":False}
        r.raise_for_status(); d=r.json()
        return {"ip":ip,"found":True,"ports":d.get("ports",[]),"hostnames":d.get("hostnames",[]),
          "tags":d.get("tags",[]),"vulns":d.get("vulns",[]),"source":"Shodan InternetDB"}
    except Exception as e:return {"ip":ip,"error":type(e).__name__}
