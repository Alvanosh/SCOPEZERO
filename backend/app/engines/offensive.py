"""Controlled, non-destructive assessment adapters for explicitly authorized assets."""
import json, os, re, shutil, subprocess, tempfile, ipaddress
from pathlib import Path
import requests
from ..config import UA
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import dns.resolver

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

def is_public_host(host):
    try:
        answers=[]
        r=dns.resolver.Resolver(); r.timeout=1; r.lifetime=2
        for typ in ("A","AAAA"):
            try: answers += [ipaddress.ip_address(x.to_text()) for x in r.resolve(host,typ)]
            except Exception: pass
        return bool(answers) and all(x.is_global for x in answers)
    except Exception: return False

def run_tool(name, args, timeout=180):
    path=shutil.which(name)
    if not path: return {"available":False,"error":f"{name} is not installed or not on PATH."}
    try:
        p=subprocess.run([path,*args],capture_output=True,text=True,timeout=timeout,check=False,
                         env={**os.environ,"NO_COLOR":"1"})
        return {"available":True,"returncode":p.returncode,"stdout":p.stdout[-200000:],"stderr":p.stderr[-20000:]}
    except subprocess.TimeoutExpired:
        return {"available":True,"error":f"{name} timed out after {timeout} seconds."}
    except Exception as e: return {"available":True,"error":f"{type(e).__name__}: {e}"}

def nmap_scan(hosts):
    hosts=[h for h in hosts if is_public_host(h)]
    if not hosts: return {"available":shutil.which('nmap') is not None,"hosts_scanned":0,"results":[],"message":"No discovered public hosts eligible for scanning."}
    with tempfile.TemporaryDirectory(prefix="scopezero-nmap-") as td:
        out=Path(td)/"scan.xml"
        res=run_tool("nmap",["-sT","-sV","--version-light","--top-ports","100","-T3","--host-timeout","90s","-oX",str(out),*hosts],timeout=240)
        parsed=[]
        if out.exists():
            import xml.etree.ElementTree as ET
            try:
                root=ET.parse(out).getroot()
                for h in root.findall('host'):
                    addr=h.find('address'); name=h.find('hostnames/hostname')
                    for p in h.findall('ports/port'):
                        state=p.find('state'); svc=p.find('service')
                        parsed.append({"host":name.get('name') if name is not None else (addr.get('addr') if addr is not None else "unknown"),
                          "port":int(p.get('portid')),"protocol":p.get('protocol'),"state":state.get('state') if state is not None else "unknown",
                          "service":svc.get('name') if svc is not None else "unknown","product":svc.get('product') if svc is not None else None,
                          "version":svc.get('version') if svc is not None else None})
            except Exception: pass
        return {"available":res.get("available",False),"hosts_scanned":len(hosts),"results":parsed,"tool_error":res.get('error'),"returncode":res.get('returncode'),"mode":"TCP connect, top 100 ports, light service detection"}

def nuclei_scan(hosts):
    hosts=[h for h in hosts if is_public_host(h)]
    if not hosts:
        return {"available":shutil.which("nuclei") is not None,"status":"no_targets","targets_count":0,
                "results":[],"message":"No discovered public hostnames are eligible for this check."}
    with tempfile.TemporaryDirectory(prefix="scopezero-nuclei-") as td:
        targets=Path(td)/"targets.txt"
        targets.write_text("\n".join("https://"+h for h in hosts)+"\n")
        # Restrict checks to non-intrusive misconfiguration, exposure and TLS templates.
        args=["-list",str(targets),"-tags","misconfig,exposure,ssl",
              "-exclude-tags","dos,intrusive,fuzz","-severity","info,low,medium,high,critical",
              "-rl","5","-c","3","-timeout","5","-retries","1",
              "-jsonl","-silent","-no-interactsh","-no-color","-disable-update-check"]
        res=run_tool("nuclei",args,timeout=300)
        if not res.get("available"):
            return {"available":False,"status":"not_installed","targets_count":len(hosts),"results":[],
                    "message":"Nuclei is not installed or not available on PATH."}
        findings=[]; parsed=0; unparsed=0
        stdout=res.get("stdout","")
        for line in stdout.splitlines():
            line=line.strip()
            if not line: continue
            try:
                x=json.loads(line); parsed+=1; info=x.get("info") or {}
                refs=info.get("reference") or []
                if isinstance(refs,str): refs=[refs]
                findings.append({"host":x.get("host") or x.get("matched-at"),
                  "template_id":x.get("template-id") or x.get("templateID"),
                  "name":info.get("name") or x.get("template"),
                  "severity":info.get("severity","unknown"),
                  "matched_at":x.get("matched-at") or x.get("matched"),
                  "type":x.get("type"),"matcher_name":x.get("matcher-name"),
                  "description":info.get("description"),
                  "reference":refs[:5],
                  "classification":info.get("classification")})
            except Exception:
                unparsed+=1
        rc=res.get("returncode")
        if res.get("error") or rc not in (0,None):
            status="failed"
            message=res.get("error") or f"Nuclei exited with code {rc}. Check diagnostics."
        elif unparsed and not parsed:
            status="parse_warning"
            message="Nuclei returned output, but SCOPEZERO could not parse it as JSONL. Review the diagnostics."
        elif findings:
            status="matches_found"
            message=f"Nuclei completed against {len(hosts)} public in-scope hostname(s) and reported {len(findings)} matching template result(s). Review and validate each result."
        else:
            status="no_matches"
            message=("Nuclei completed successfully against the configured non-intrusive template set; "
                     "no matching results were returned. This does not prove the hosts are vulnerability-free.")
        return {"available":True,"status":status,"targets_count":len(hosts),"results":findings,
                "parsed_lines":parsed,"unparsed_lines":unparsed,"stdout_bytes":len(stdout.encode("utf-8","replace")),
                "stderr_tail":res.get("stderr","")[-1500:],"tool_error":res.get("error"),
                "returncode":rc,"message":message,
                "mode":"Non-intrusive misconfiguration, exposure and TLS templates only"}

def katana_crawl(hosts):
    hosts=[h for h in hosts if is_public_host(h)]
    if not hosts:return {"available":shutil.which('katana') is not None,"urls":[],"message":"No eligible public hosts."}
    urls=[]
    for host in hosts[:25]:
        res=run_tool('katana',["-u","https://"+host,"-d","2","-jc","-silent","-crawl-scope",r".*\."+re.escape(host)+r"$|https?://"+re.escape(host)+r"(/|$)"],timeout=90)
        if res.get('stdout'):
            for u in res['stdout'].splitlines():
                p=urlparse(u.strip())
                if p.hostname==host or (p.hostname and p.hostname.endswith('.'+host)): urls.append(u.strip())
    return {"available":shutil.which('katana') is not None,"hosts_crawled":min(len(hosts),25),"urls":sorted(set(urls))[:3000],"mode":"Depth-2 crawl; same-host URLs retained"}

def scan_secrets(repo_path):
    root=Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir(): return {"error":"Repository path must be an existing directory."}
    # Bound traversal and avoid common dependency/build and VCS directories.
    ignored={'.git','.venv','venv','node_modules','dist','build','.next','__pycache__'}
    findings=[]; scanned=0; max_files=5000; max_bytes=2_000_000
    for base,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in ignored]
        for fn in files:
            if scanned>=max_files: break
            p=Path(base)/fn
            try:
                if p.is_symlink() or p.stat().st_size>max_bytes: continue
                data=p.read_text(errors='ignore')
            except Exception: continue
            scanned+=1
            for lineno,line in enumerate(data.splitlines(),1):
                for label,pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append({"file":str(p.relative_to(root)),"line":lineno,"type":label,"snippet":"[REDACTED: potential secret material]","status":"Needs manual validation"})
                        break
    return {"repository":str(root),"files_scanned":scanned,"truncated":scanned>=max_files,"findings":findings[:1000],
            "note":"Heuristic local scan. Values are never returned; matches may be false positives. Use only on repositories you are authorized to inspect."}



_API_PATHS=(
    "api","api/","api/v1","api/v2","v1","v2","api/docs","api-docs",
    "api/swagger","swagger","swagger.json","openapi.json","openapi.yaml",
    "api/openapi.json","graphql","graphiql","health","status",
    ".well-known/openid-configuration","api/health","api/status"
)
def api_endpoint_probe(hosts, max_hosts=8, timeout=4):
    """Non-destructive GET-only checks for common API/spec endpoints on in-scope public hosts."""
    eligible=[h for h in hosts if is_public_host(h)][:max_hosts]
    if not eligible:
        return {"available":True,"status":"no_targets","hosts_checked":0,"endpoints":[],
                "message":"No discovered public in-scope hostnames are eligible for API endpoint checks."}
    candidates=[(host,path) for host in eligible for path in _API_PATHS]
    def probe(item):
        host,path=item
        url=f"https://{host}/{path.lstrip('/')}"
        try:
            response=requests.get(url,headers={"User-Agent":UA,
                "Accept":"application/json, application/yaml, text/plain;q=0.8, */*;q=0.2"},
                timeout=timeout,allow_redirects=False,stream=True)
            try:
                status=response.status_code
                ctype=response.headers.get("Content-Type","")
                length=response.headers.get("Content-Length")
                location=response.headers.get("Location","")
                # Do not collect response bodies. Use headers + a tiny bounded sample for JSON signature.
                sample=b""
                if "json" in ctype.lower() or path in ("graphql","openapi.json","swagger.json","api/openapi.json"):
                    try: sample=next(response.iter_content(256),b"")[:256]
                    except Exception: pass
                positive=status in (200,201,202,204,301,302,307,308,401,403,405)
                spec_hint=path in ("openapi.json","openapi.yaml","swagger.json","api/openapi.json","api/docs","api/swagger","api-docs")
                json_hint="json" in ctype.lower() or "yaml" in ctype.lower() or b'"openapi"' in sample.lower() or b'"swagger"' in sample.lower()
                if not positive or not (json_hint or spec_hint or path in ("graphql","graphiql")):
                    return None
                return {"host":host,"path":"/"+path,"url":url,"status":status,
                        "content_type":ctype[:120],"content_length":length,
                        "signal":"API/spec indicator" if (json_hint or spec_hint) else "GraphQL path indicator",
                        "confidence":90 if json_hint else 70,
                        "redirect_location":location[:250] if status in (301,302,307,308) else None,
                        "method":"GET","source":"SCOPEZERO bounded API endpoint probe"}
            finally: response.close()
        except requests.RequestException:
            return None
    found=[]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures=[pool.submit(probe,item) for item in candidates]
        for future in as_completed(futures):
            try:
                item=future.result()
                if item: found.append(item)
            except Exception: pass
    found.sort(key=lambda x:(x["host"],x["path"]))
    return {"available":True,"status":"matches_found" if found else "no_matches",
            "hosts_checked":len(eligible),"paths_checked":len(candidates),"endpoints":found,
            "message":f"Checked {len(candidates)} bounded API paths across {len(eligible)} public host(s); found {len(found)} candidate endpoint(s).",
             "mode":"GET-only, no authentication attempts, at most a 256-byte signature sample for API/spec classification, no redirect following"}

def subfinder_scan(domain, timeout=90):
    """Passive Subfinder enumeration restricted to the supplied root domain."""
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",domain):
        return {"available":False,"status":"invalid_scope","hosts":[],"message":"Invalid root domain."}
    path=shutil.which("subfinder")
    if not path:
        return {"available":False,"status":"not_installed","hosts":[],"message":"Subfinder is not installed or not available on PATH."}
    res=run_tool("subfinder",["-d",domain,"-silent","-timeout","10","-max-time","1","-duc"],timeout=timeout)
    hosts=set()
    for line in res.get("stdout","").splitlines():
        h=line.strip().lower().rstrip(".")
        if h and (h==domain or h.endswith("."+domain)) and re.fullmatch(r"[a-z0-9.-]+",h):
            hosts.add(h)
    status="failed" if res.get("error") or res.get("returncode") not in (0,None) else ("matches_found" if hosts else "no_matches")
    if res.get("error"):
        message=res["error"]
    elif res.get("returncode") not in (0,None):
        message=f"Subfinder exited with code {res.get('returncode')}."
    elif hosts:
        message=f"Subfinder returned {len(hosts)} in-scope hostname candidate(s)."
    else:
        message="Subfinder completed successfully but returned no in-scope hostnames from its configured passive sources."
    return {"available":True,"status":status,"hosts":sorted(hosts),"count":len(hosts),
            "returncode":res.get("returncode"),"stderr_tail":res.get("stderr","")[-1000:],
            "message":message,"mode":"Passive subdomain enumeration; results are candidates requiring DNS/ownership verification"}

_GOBUSTER_WORDS=("admin","api","assets","backup","config","dashboard","docs","health",
                 "login","portal","robots.txt","sitemap.xml","static","status","uploads",
                 "user","users","v1","v2","well-known")
def gobuster_scan(hosts, max_hosts=6, timeout=150):
    """Low-rate, bounded directory discovery against public hosts already in scan scope."""
    hosts=[h for h in hosts if is_public_host(h)]
    if not hosts:
        return {"available":shutil.which("gobuster") is not None,"status":"no_targets","hosts_scanned":0,
                "results":[],"message":"No discovered public hostnames are eligible for directory discovery."}
    path=shutil.which("gobuster")
    if not path:
        return {"available":False,"status":"not_installed","hosts_scanned":0,"results":[],
                "message":"Gobuster is not installed or not available on PATH."}
    results=[]; host_errors=[]; scanned=[]
    with tempfile.TemporaryDirectory(prefix="scopezero-gobuster-") as td:
        wordfile=Path(td)/"bounded-paths.txt"
        wordfile.write_text("\n".join(_GOBUSTER_WORDS)+"\n")
        for host in hosts[:max_hosts]:
            url="https://"+host
            args=["dir","-u",url,"-w",str(wordfile),"-x","json,yaml,yml,xml,txt",
                  "-t","5","--delay","100ms","--timeout","5s","--no-progress","-q","--no-error"]
            res=run_tool("gobuster",args,timeout=min(timeout,45))
            if not res.get("available"):
                return {"available":False,"status":"not_installed","hosts_scanned":0,"results":[],
                        "message":"Gobuster is not installed or not available on PATH."}
            scanned.append(host)
            if res.get("error") or res.get("returncode") not in (0,None):
                host_errors.append({"host":host,"error":res.get("error") or f"exit code {res.get('returncode')}",
                                    "stderr":res.get("stderr","")[-500:]})
            for line in res.get("stdout","").splitlines():
                match=re.search(r"^(/\S+)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?",line.strip())
                if match:
                    results.append({"host":host,"path":match.group(1),"url":url+match.group(1),
                                    "status":int(match.group(2)),"size":int(match.group(3)) if match.group(3) else None,
                                    "source":"Gobuster"})
    status="failed" if not scanned and host_errors else ("matches_found" if results else "no_matches")
    message=(f"Gobuster checked {len(scanned)} host(s) and found {len(results)} path response(s)." if results else
             f"Gobuster completed its bounded wordlist against {len(scanned)} host(s) with no matching path responses." if scanned else
             "Gobuster could not complete against any eligible host.")
    return {"available":True,"status":status,"hosts_scanned":len(scanned),"host_limit":max_hosts,
             "word_count":len(_GOBUSTER_WORDS),"extensions":["json","yaml","yml","xml","txt"],"results":results,"host_errors":host_errors,
            "message":message,"mode":"Bounded 19-path wordlist, 5 workers, 100 ms delay; public in-scope discovered hosts only"}
