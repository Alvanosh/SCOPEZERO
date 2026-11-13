"""Controlled, non-destructive assessment adapters for explicitly authorized assets."""
import json, os, re, shutil, subprocess, tempfile, ipaddress
from pathlib import Path
import requests
from ..config import UA
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import dns.resolver
from .process import run_binary

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

_PUBLIC_DNS_CACHE = {}

def is_public_host(host):
    """Resolve a hostname quickly and reject private, loopback and mixed answers."""
    key=str(host).lower().rstrip('.')
    if key in _PUBLIC_DNS_CACHE:
        return _PUBLIC_DNS_CACHE[key]
    try:
        try:
            ip=ipaddress.ip_address(key)
            result=ip.is_global
            _PUBLIC_DNS_CACHE[key]=result
            return result
        except ValueError:
            pass
        resolver=dns.resolver.Resolver()
        resolver.timeout=0.7
        resolver.lifetime=1.2
        answers=[]
        for typ in ("A", "AAAA"):
            try:
                answers.extend(ipaddress.ip_address(x.to_text()) for x in resolver.resolve(key, typ, lifetime=1.2))
            except Exception:
                continue
        result=bool(answers) and all(x.is_global for x in answers)
    except Exception:
        result=False
    _PUBLIC_DNS_CACHE[key]=result
    if len(_PUBLIC_DNS_CACHE)>5000:
        _PUBLIC_DNS_CACHE.clear()
    return result

def public_hosts(hosts, limit=50, workers=16):
    """Bound and parallelize DNS eligibility checks without changing scope."""
    all_candidates=list(dict.fromkeys(str(h).lower().rstrip('.') for h in hosts if h))
    candidates=all_candidates[:max(limit*2,limit)]
    if not candidates:
        return [], 0
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(workers,len(candidates))) as pool:
        flags=list(pool.map(is_public_host,candidates))
    eligible=[h for h,ok in zip(candidates,flags) if ok]
    return eligible[:limit], max(0,len(eligible)-limit), max(0,len(all_candidates)-len(candidates))

def run_tool(name, args, timeout=180):
    return run_binary(name,args,timeout=timeout)

def nmap_scan(hosts):
    hosts,omitted,not_checked=public_hosts(hosts,limit=40)
    if not hosts: return {"available":shutil.which('nmap') is not None,"status":"preflight_incomplete" if not_checked else "no_targets","hosts_scanned":0,"not_checked_during_preflight":not_checked,"results":[],"message":"Preflight limit reached before any eligible host was confirmed; narrow the asset set and retry." if not_checked else "No discovered public hosts eligible for scanning."}
    with tempfile.TemporaryDirectory(prefix="scopezero-nmap-") as td:
        out=Path(td)/"scan.xml"
        res=run_tool("nmap",["-sT","-sV","--version-light","--top-ports","100","-T3","--host-timeout","35s","--max-retries","1","--max-rate","40","-oX",str(out),*hosts],timeout=180)
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
        status=res.get("status") if res.get("status") not in ("completed",None) else ("matches_found" if parsed else "no_matches")
        return {"available":res.get("available",False),"status":status,"hosts_scanned":len(hosts),"omitted_after_target_cap":omitted,"not_checked_during_preflight":not_checked,"results":parsed,"tool_error":res.get('error'),"returncode":res.get('returncode'),"stderr_tail":res.get("stderr","")[-4000:],"diagnostics":res.get("diagnostics"),"elapsed_seconds":res.get("elapsed_seconds"),"message":res.get("error") or f"Nmap completed against {len(hosts)} public in-scope host(s); {len(parsed)} port/service observations recorded.","mode":"TCP connect, top 100 ports, light service detection; max 40 hosts per run"}

def nuclei_scan(hosts):
    """Run bounded HTTP-focused Nuclei templates in small batches.

    Includes HTTP, misconfiguration and vulnerability-tagged templates while
    excluding known intrusive classes. Results are observations requiring
    analyst validation, not proof of exploitability.
    """
    hosts, omitted, not_checked = public_hosts(hosts, limit=25)
    if not hosts:
        return {"available": shutil.which("nuclei") is not None,
                "status": "preflight_incomplete" if not_checked else "no_targets",
                "targets_count": 0, "not_checked_during_preflight": not_checked,
                "results": [],
                "message": "Preflight limit reached before any eligible host was confirmed; narrow the asset set and retry." if not_checked else "No discovered public hostnames are eligible for this check."}

    path = shutil.which("nuclei")
    if not path:
        return {"available": False, "status": "not_installed", "targets_count": len(hosts),
                "results": [], "message": "Nuclei is not installed or not available on PATH."}

    findings = []
    batch_diagnostics = []
    parsed = unparsed = 0
    completed_batches = timed_out_batches = failed_batches = 0
    # Small batches avoid a single slow host holding up the entire assessment.
    batch_size = 5
    with tempfile.TemporaryDirectory(prefix="scopezero-nuclei-") as td:
        for offset in range(0, len(hosts), batch_size):
            batch = hosts[offset:offset + batch_size]
            targets = Path(td) / f"targets-{offset // batch_size + 1}.txt"
            targets.write_text("\n".join("https://" + h for h in batch) + "\n")
            args = [
                "-list", str(targets),
                # Nuclei tag selectors are OR-based: cover HTTP checks,
                # common misconfigurations and vulnerability templates.
                "-tags", "http,misconfig,vuln,exposure,ssl",
                "-exclude-tags", "dos,intrusive,fuzz,bruteforce,headless,code,file,network,workflow",
                "-severity", "info,low,medium,high,critical",
                "-rl", "10", "-c", "10", "-bulk-size", "5",
                "-timeout", "7", "-retries", "0",
                "-jsonl", "-silent", "-no-interactsh", "-no-color",
                "-disable-update-check",
            ]
            res = run_tool("nuclei", args, timeout=120)
            if res.get("status") == "timeout":
                timed_out_batches += 1
            elif res.get("error") or res.get("returncode") not in (0, None):
                failed_batches += 1
            else:
                completed_batches += 1

            batch_parsed = batch_unparsed = 0
            for line in res.get("stdout", "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    x = json.loads(line)
                    batch_parsed += 1
                    info = x.get("info") or {}
                    refs = info.get("reference") or []
                    if isinstance(refs, str):
                        refs = [refs]
                    findings.append({
                        "host": x.get("host") or x.get("matched-at"),
                        "template_id": x.get("template-id") or x.get("templateID"),
                        "name": info.get("name") or x.get("template"),
                        "severity": info.get("severity", "unknown"),
                        "matched_at": x.get("matched-at") or x.get("matched"),
                        "type": x.get("type"), "matcher_name": x.get("matcher-name"),
                        "description": info.get("description"), "reference": refs[:5],
                        "classification": info.get("classification"),
                    })
                except Exception:
                    batch_unparsed += 1
            parsed += batch_parsed
            unparsed += batch_unparsed
            batch_diagnostics.append({
                "batch": offset // batch_size + 1, "targets": len(batch),
                "status": res.get("status"), "returncode": res.get("returncode"),
                "elapsed_seconds": res.get("elapsed_seconds"),
                "error": res.get("error"),
                "stderr_tail": res.get("stderr", "")[-1200:],
                "stdout_bytes": len(res.get("stdout", "").encode("utf-8", "replace")),
            })

    total_batches = len(batch_diagnostics)
    if findings and (timed_out_batches or failed_batches):
        status = "partial_results"
        message = f"Nuclei returned {len(findings)} result(s); {completed_batches}/{total_batches} batches completed, {timed_out_batches} timed out and {failed_batches} failed. Review batch diagnostics."
    elif timed_out_batches and not completed_batches:
        status = "timeout"
        message = f"All {timed_out_batches} Nuclei batch(es) timed out. Reduce the target set or check network reachability."
    elif failed_batches and not completed_batches:
        status = "failed"
        message = f"All {failed_batches} Nuclei batch(es) failed. Review stderr and batch diagnostics."
    elif timed_out_batches or failed_batches:
        status = "partial_results"
        message = f"Nuclei completed {completed_batches}/{total_batches} batches; {timed_out_batches} timed out and {failed_batches} failed. No complete assessment can be claimed."
    elif unparsed and not parsed:
        status = "parse_warning"
        message = "Nuclei returned output, but SCOPEZERO could not parse it as JSONL. Review diagnostics."
    elif findings:
        status = "matches_found"
        message = f"Nuclei completed against {len(hosts)} public in-scope host(s) and reported {len(findings)} matching template result(s). Validate each result."
    else:
        status = "no_matches"
        message = "Nuclei completed the selected HTTP, misconfiguration, vulnerability, exposure and TLS template checks without matches. This does not prove the hosts are vulnerability-free."

    return {
        "available": True, "status": status, "targets_count": len(hosts),
        "omitted_after_target_cap": omitted, "not_checked_during_preflight": not_checked,
        "results": findings, "parsed_lines": parsed, "unparsed_lines": unparsed,
        "completed_batches": completed_batches, "total_batches": total_batches,
        "timed_out_batches": timed_out_batches, "failed_batches": failed_batches,
        "batch_diagnostics": batch_diagnostics, "message": message,
        "mode": "HTTP-focused Nuclei templates tagged http, misconfig, vuln, exposure and ssl; intrusive classes excluded; batches of 5; findings require analyst validation",
    }

def katana_crawl(hosts):
    hosts,omitted,not_checked=public_hosts(hosts,limit=25)
    if not hosts:return {"available":shutil.which('katana') is not None,"status":"preflight_incomplete" if not_checked else "no_targets","urls":[],"not_checked_during_preflight":not_checked,"message":"Preflight limit reached before any eligible host was confirmed; narrow the asset set and retry." if not_checked else "No eligible public hosts."}
    urls=[]; errors=[]
    for host in hosts[:25]:
        res=run_tool('katana',["-u","https://"+host,"-d","2","-jc","-silent","-crawl-scope",r".*\."+re.escape(host)+r"$|https?://"+re.escape(host)+r"(/|$)"],timeout=90)
        if res.get('stdout'):
            for u in res['stdout'].splitlines():
                p=urlparse(u.strip())
                if p.hostname==host or (p.hostname and p.hostname.endswith('.'+host)): urls.append(u.strip())
        if res.get("error") or res.get("returncode") not in (0,None): errors.append({"host":host,"status":res.get("status"),"error":res.get("error"),"stderr_tail":res.get("stderr","")[-1000:]})
    return {"available":shutil.which('katana') is not None,"status":("timeout" if errors and not urls and all("timed out" in str(x.get("error","")).lower() for x in errors) else "execution_error") if errors and not urls else "partial_results" if errors and urls else "matches_found" if urls else "no_matches","hosts_crawled":len(hosts),"omitted_after_target_cap":omitted,"not_checked_during_preflight":not_checked,"urls":sorted(set(urls))[:3000],"errors":errors,"mode":"Depth-2 crawl; same-host URLs retained"}

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
    status=(res.get("status") if res.get("status") not in (None,"completed") else ("failed" if res.get("error") or res.get("returncode") not in (0,None) else ("matches_found" if hosts else "no_matches")))
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
    """Run compatibility-focused, low-rate Gobuster directory discovery."""
    hosts, omitted, not_checked = public_hosts(hosts, limit=max_hosts)
    path = shutil.which("gobuster")
    if not hosts:
        return {"available": bool(path), "status": "preflight_incomplete" if not_checked else "no_targets",
                "hosts_scanned": 0, "not_checked_during_preflight": not_checked, "results": [],
                "message": "Preflight limit reached; narrow the asset set and retry." if not_checked else "No discovered public hostnames are eligible."}
    if not path:
        return {"available": False, "status": "not_installed", "hosts_scanned": 0, "results": [],
                "message": "Gobuster is not installed or not available on PATH."}
    results, host_errors, scanned = [], [], []
    with tempfile.TemporaryDirectory(prefix="scopezero-gobuster-") as td:
        wordfile = Path(td) / "bounded-paths.txt"
        wordfile.write_text("\n".join(_GOBUSTER_WORDS) + "\n")
        for host in hosts[:max_hosts]:
            url = "https://" + host
            # Avoid optional flags that vary between distro-packaged Gobuster builds.
            args = ["dir", "-u", url, "-w", str(wordfile), "-x", "json,yaml,yml,xml,txt",
                    "-t", "5", "--delay", "100ms", "--timeout", "8s", "-q"]
            res = run_tool("gobuster", args, timeout=min(max(15, int(timeout)), 60))
            if not res.get("available"):
                return {"available": False, "status": "not_installed", "hosts_scanned": len(scanned),
                        "results": results, "message": "Gobuster executable could not be resolved at launch."}
            if res.get("error") or res.get("returncode") not in (0, None):
                host_errors.append({"host": host, "status": res.get("status", "execution_error"),
                                    "error": res.get("error") or f"exit code {res.get('returncode')}",
                                    "stderr": res.get("stderr", "")[-1500:], "diagnostics": res.get("diagnostics")})
            else:
                scanned.append(host)
            # Gobuster v3 output: /path (Status: 200) [Size: 123].
            for line in res.get("stdout", "").splitlines():
                match = re.search(r"(/\S+)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?", line.strip())
                if match:
                    results.append({"host": host, "path": match.group(1), "url": url + match.group(1),
                                    "status": int(match.group(2)), "size": int(match.group(3)) if match.group(3) else None,
                                    "source": "Gobuster"})
    if host_errors and results:
        status = "partial_results"
    elif host_errors and not scanned:
        kinds = {x.get("status") for x in host_errors}
        status = "timeout" if kinds == {"timeout"} else ("permission_error" if kinds == {"permission_error"} else "execution_error")
    else:
        status = "matches_found" if results else "no_matches"
    message = (f"Gobuster found {len(results)} path response(s) across {len(scanned)} completed host(s)." if results else
               f"Gobuster completed its bounded wordlist against {len(scanned)} host(s) with no matching path responses." if scanned else
               "Gobuster did not complete against any eligible host; inspect per-host diagnostics.")
    return {"available": True, "status": status, "hosts_scanned": len(scanned), "host_limit": max_hosts,
            "word_count": len(_GOBUSTER_WORDS), "extensions": ["json", "yaml", "yml", "xml", "txt"],
            "results": results, "host_errors": host_errors, "omitted_after_target_cap": omitted,
            "not_checked_during_preflight": not_checked, "message": message,
            "mode": "Bounded 19-path wordlist, 5 workers, 100 ms delay; public in-scope discovered hosts only"}
