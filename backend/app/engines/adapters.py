"""Bounded command adapters for explicitly authorized engagement assets."""
import json, shutil, subprocess, tempfile, re
from .process import run_binary
from pathlib import Path

WORDS = ("admin", "api", "docs", "health", "login", "robots.txt", "sitemap.xml", "status", "swagger", "v1", "v2")

def _run(binary, args, timeout=180):
    return run_binary(binary,args,timeout=timeout)

def findomain(domain, timeout=120):
    r = _run("findomain", ["-t", domain, "-q"], timeout)
    hosts = sorted({x.strip().lower().rstrip('.') for x in r.get('stdout','').splitlines()
                    if re.fullmatch(r"[a-z0-9.-]+", x.strip().lower().rstrip('.')) and
                    (x.strip().lower().rstrip('.') == domain or x.strip().lower().rstrip('.').endswith('.'+domain))})
    status = r.get('status') if r.get('status') not in (None,"completed") else ("failed" if r.get('returncode') not in (0,None) else "matches_found" if hosts else "no_matches")
    return {"tool":"findomain", "status":status, "hosts":hosts, "result_count":len(hosts),
            "stderr_tail":r.get('stderr','')[-1500:], "mode":"Passive subdomain enumeration; candidates only" , **{k:v for k,v in r.items() if k in ('available','error','returncode','diagnostics','elapsed_seconds')}}

def naabu(hosts, timeout=180):
    if not hosts: return {"tool":"naabu","status":"no_targets","results":[],"result_count":0}
    selected=list(dict.fromkeys(hosts))[:80]
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt') as f:
        f.write('\n'.join(selected)); f.flush()
        r = _run("naabu", ["-list", f.name, "-top-ports", "100", "-scan-type", "c", "-rate", "30", "-c", "5", "-retries", "1", "-silent", "-json"], timeout)
    out=[]
    for line in r.get('stdout','').splitlines():
        try:
            x=json.loads(line); host=x.get('host') or x.get('ip'); port=int(x.get('port'))
            services={21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",3389:"rdp",5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt",9200:"elasticsearch"}
            if host and 1 <= port <= 65535: out.append({"host":str(host).lower(),"port":port,"protocol":"tcp","state":"open","service":services.get(port,"unknown")})
        except Exception: pass
    status=(r.get('status') if r.get('status') not in (None,"completed") else ("failed" if r.get('returncode') not in (0,None) else "matches_found" if out else "no_matches"))
    return {"tool":"naabu","status":status,"results":out,"result_count":len(out),"targets_count":len(selected),"omitted_after_target_cap":max(0,len(set(hosts))-len(selected)),"mode":"TCP connect scan, top-100 ports; 30 packets/s, concurrency 5 (does not require raw-packet privileges)","diagnostics":r.get("diagnostics"),"stderr_tail":r.get("stderr","")[-3000:],"elapsed_seconds":r.get("elapsed_seconds"),**{k:v for k,v in r.items() if k in ('available','error','returncode','diagnostics','elapsed_seconds')}}

def httpx_probe(hosts, timeout=180):
    if not hosts: return {"tool":"httpx","status":"no_targets","results":[],"result_count":0}
    selected=list(dict.fromkeys(hosts))[:100]
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt') as f:
        f.write('\n'.join('https://'+h for h in selected)); f.flush()
        r=_run("httpx",["-l",f.name,"-json","-silent","-status-code","-title","-tech-detect","-follow-redirects","-rate-limit","8","-threads","8","-timeout","6","-retries","0"],timeout)
    out=[]
    for line in r.get('stdout','').splitlines():
        try:
            x=json.loads(line); url=x.get('url') or x.get('input')
            if url: out.append({"url":url,"host":x.get('host'),"status":x.get('status_code'),"title":x.get('title'),"technologies":x.get('tech',[])})
        except Exception: pass
    status=(r.get('status') if r.get('status') not in (None,"completed") else ("failed" if r.get('returncode') not in (0,None) else "matches_found" if out else "no_matches"))
    return {"tool":"httpx","status":status,"results":out,"result_count":len(out),"targets_count":len(selected),"omitted_after_target_cap":max(0,len(set(hosts))-len(selected)),"mode":"HTTP metadata only; 8 requests/s, 8 threads", "diagnostics":r.get("diagnostics"),"stderr_tail":r.get("stderr","")[-3000:],"elapsed_seconds":r.get("elapsed_seconds"),**{k:v for k,v in r.items() if k in ('available','error','returncode','diagnostics','elapsed_seconds')}}

def feroxbuster(hosts, timeout=180, max_hosts=3):
    if not hosts: return {"tool":"feroxbuster","status":"no_targets","results":[],"result_count":0}
    found=[]; errors=[]; scanned=[]
    with tempfile.TemporaryDirectory(prefix='scopezero-ferox-') as td:
        wordfile=Path(td)/'words.txt'; wordfile.write_text('\n'.join(WORDS)+'\n')
        for host in hosts[:max_hosts]:
            r=_run('feroxbuster',["-u","https://"+host,"-w",str(wordfile),"-t","2","--rate-limit","2","--time-limit","45s","--no-recursion","--silent","--json"],min(timeout,55))
            if not r.get('available'): return {"tool":"feroxbuster","status":"not_installed","results":[],"result_count":0,"error":r.get('error')}
            scanned.append(host)
            if r.get('error') or r.get('returncode') not in (0,None): errors.append({"host":host,"error":r.get('error') or r.get('stderr','')[-500:]})
            for line in r.get('stdout','').splitlines():
                try:
                    x=json.loads(line); url=x.get('url')
                    if url: found.append({"host":host,"url":url,"status":x.get('status'),"content_length":x.get('content_length'),"source":"feroxbuster"})
                except Exception: pass
    status=("timeout" if errors and all("timed out" in str(x.get("error","")).lower() for x in errors) else "execution_error") if errors and not found else ("partial_results" if errors and found else "matches_found" if found else "no_matches")
    return {"tool":"feroxbuster","status":status,"results":found,"result_count":len(found),"hosts_scanned":scanned,"host_limit":max_hosts,"errors":errors,"mode":"11-path bounded wordlist, 2 threads, 2 requests/s, no recursion"}
