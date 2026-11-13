"""Additional bounded reconnaissance and external intelligence adapters."""
import os, re, json, shutil, subprocess, tempfile, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus
import requests
import dns.resolver
from .offensive import run_tool, is_public_host

TIMEOUT=12

def _domain_ok(domain):
    return bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", (domain or "").lower()))

def _hosts_ok(hosts, domain, limit=80):
    return sorted({h.lower().rstrip('.') for h in hosts if isinstance(h,str) and (h.lower().rstrip('.')==domain or h.lower().rstrip('.').endswith('.'+domain))})[:limit]

def amass_passive(domain, timeout=95):
    """Run bounded passive Amass enumeration and preserve partial results."""
    if not _domain_ok(domain):
        return {"available": False, "status": "invalid_scope", "hosts": [], "message": "Invalid root domain."}
    if not shutil.which("amass"):
        return {"available": False, "status": "not_installed", "hosts": [], "message": "Amass is not installed or not on PATH."}
    # Amass enum's timeout is in minutes. Keep its internal limit below the
    # subprocess watchdog; cap wall time so one provider cannot stall a scan.
    outer_timeout = min(max(int(timeout), 30), 110)
    r = run_tool("amass", ["enum", "-passive", "-d", domain, "-timeout", "1", "-silent"], timeout=outer_timeout)
    hosts = _hosts_ok(r.get("stdout", "").splitlines(), domain)
    raw_status = r.get("status")
    if raw_status == "timeout" and hosts:
        status = "partial_results"
        message = f"Amass timed out after returning {len(hosts)} in-scope hostname candidate(s); partial output was retained."
    elif raw_status not in (None, "completed"):
        status = raw_status
        message = r.get("error") or f"Amass ended with status {raw_status}."
    elif r.get("error") or r.get("returncode") not in (0, None):
        status = "execution_error"
        message = r.get("error") or f"Amass exited with code {r.get('returncode')}."
    else:
        status = "matches_found" if hosts else "no_matches"
        message = f"Amass passive mode completed and returned {len(hosts)} in-scope hostname candidate(s)."
    return {"available": True, "status": status, "hosts": hosts, "count": len(hosts),
            "returncode": r.get("returncode"), "stderr_tail": r.get("stderr", "")[-3000:],
            "diagnostics": r.get("diagnostics"), "elapsed_seconds": r.get("elapsed_seconds"),
            "message": message, "mode": "Passive only; one-minute internal limit and bounded subprocess watchdog; no brute force, port scans or active validation"}

def dnsx_records(hosts, domain, timeout=90):
    if not shutil.which('dnsx'): return {"available":False,"status":"not_installed","records":[],"message":"dnsx is not installed or not on PATH."}
    targets=_hosts_ok(hosts,domain,100)
    if not targets: return {"available":True,"status":"no_targets","records":[],"message":"No in-scope hostnames are available."}
    with tempfile.TemporaryDirectory(prefix='scopezero-dnsx-') as td:
        src=Path(td)/'hosts.txt'; src.write_text('\n'.join(targets)+'\n')
        r=run_tool('dnsx',['-l',str(src),'-a','-aaaa','-cname','-mx','-ns','-txt','-resp','-silent'],timeout=timeout)
    records=[]
    for line in r.get('stdout','').splitlines():
        line=line.strip()
        if not line: continue
        m=re.match(r'^(\S+)\s+\[(.*)\]$',line)
        if m:
            records.append({"host":m.group(1),"response":m.group(2)[:500],"source":"dnsx"})
        else: records.append({"host":line.split()[0],"response":line[:500],"source":"dnsx"})
    status=(r.get('status') if r.get('status') not in (None,'completed') else ('failed' if r.get('error') or r.get('returncode') not in (0,None) else ('matches_found' if records else 'no_matches')))
    return {"available":True,"status":status,"hosts_checked":len(targets),"records":records[:500],"count":len(records),"returncode":r.get('returncode'),"stderr_tail":r.get('stderr','')[-3000:],"diagnostics":r.get('diagnostics'),"elapsed_seconds":r.get('elapsed_seconds'),"message":r.get('error') or f"dnsx checked {len(targets)} in-scope hostnames and returned {len(records)} record lines."}

_CLOUD_WORDS=('www','api','cdn','assets','static','media','files','storage','backup','dev','stage','staging','test','portal','app','uploads','docs','images','s3','blob','cloud')
_CLOUD_SUFFIXES=('amazonaws.com','cloudfront.net','azurewebsites.net','blob.core.windows.net','storage.googleapis.com','appspot.com','digitaloceanspaces.com')
def cloud_dns_enum(domain, existing_hosts, max_candidates=24):
    if not _domain_ok(domain): return {"available":True,"status":"invalid_scope","results":[],"message":"Invalid root domain."}
    candidates=list(_hosts_ok(existing_hosts,domain,40))
    candidates += [f'{w}.{domain}' for w in _CLOUD_WORDS]
    candidates=list(dict.fromkeys(candidates))[:max_candidates]
    def check(host):
        resolver=dns.resolver.Resolver(); resolver.timeout=.6; resolver.lifetime=1.1
        rec={"host":host,"addresses":[],"cname":None,"provider_signals":[]}
        for typ in ('A','AAAA','CNAME'):
            try:
                ans=resolver.resolve(host,typ)
                vals=[x.to_text().rstrip('.') for x in ans]
                if typ=='CNAME': rec['cname']=vals[0] if vals else None
                else: rec['addresses'].extend(vals)
            except Exception: pass
        cname=(rec['cname'] or '').lower()
        rec['provider_signals']=[suffix for suffix in _CLOUD_SUFFIXES if cname.endswith(suffix)]
        if rec['addresses'] or rec['cname']:
            rec['signal']='DNS-resolved cloud/provider candidate' if rec['provider_signals'] else 'DNS-resolved hostname'
            return rec
        return None
    out=[]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures=[pool.submit(check,host) for host in candidates]
        for f in as_completed(futures):
            try:
                item=f.result()
                if item: out.append(item)
            except Exception: pass
    out.sort(key=lambda x:x['host'])
    return {"available":True,"status":"matches_found" if out else "no_matches","results":out,"count":len(out),"candidates_checked":len(candidates),"message":f"DNS-only check of {len(candidates)} bounded names returned {len(out)} resolvable candidates. No buckets, cloud accounts or storage objects were accessed.","mode":"DNS-only; provider CNAMEs are heuristic indicators, not proof of ownership or exposure"}

def crt_hosts(domain):
    if not _domain_ok(domain): return {"available":True,"status":"invalid_scope","hosts":[]}
    try:
        r=requests.get('https://crt.sh/',params={'q':f'%.{domain}','output':'json'},headers={'User-Agent':'SCOPEZERO/8.4.0'},timeout=18)
        if r.status_code!=200: return {"available":True,"status":"failed","hosts":[],"message":f"crt.sh returned HTTP {r.status_code}."}
        data=r.json(); names=set()
        for row in data[:3000]:
            for name in (row.get('name_value') or '').splitlines():
                n=name.lower().strip().lstrip('*.').rstrip('.')
                if n==domain or n.endswith('.'+domain): names.add(n)
        hosts=sorted(names)[:1000]
        return {"available":True,"status":"matches_found" if hosts else "no_matches","hosts":hosts,"count":len(hosts),"message":f"Certificate Transparency returned {len(hosts)} unique in-scope DNS names.","mode":"Public CT log search; certificate presence does not prove current DNS or ownership"}
    except requests.Timeout: return {"available":True,"status":"network_error","hosts":[],"message":"Certificate Transparency lookup timed out; the remote service may be slow or unreachable."}
    except requests.RequestException as e: return {"available":True,"status":"network_error","hosts":[],"message":f"Certificate Transparency network request failed: {type(e).__name__}"}
    except Exception as e: return {"available":True,"status":"failed","hosts":[],"message":f"CT lookup failed: {type(e).__name__}"}

def securitytrails_domain(domain):
    key=os.getenv('SECURITYTRAILS_API_KEY')
    if not key: return {"available":False,"status":"not_configured","hosts":[],"message":"Set SECURITYTRAILS_API_KEY to enable this provider."}
    try:
        r=requests.get(f'https://api.securitytrails.com/v1/domain/{domain}/subdomains',headers={'APIKEY':key,'Accept':'application/json'},timeout=TIMEOUT)
        if r.status_code!=200: return {"available":True,"status":"failed","hosts":[],"http_status":r.status_code,"message":f"SecurityTrails returned HTTP {r.status_code}."}
        data=r.json(); hosts=_hosts_ok([f'{x}.{domain}' for x in data.get('subdomains',[])],domain)
        return {"available":True,"status":"matches_found" if hosts else "no_matches","hosts":hosts,"count":len(hosts),"message":f"SecurityTrails returned {len(hosts)} hostname candidates."}
    except Exception as e: return {"available":True,"status":"failed","hosts":[],"message":f"SecurityTrails request failed: {type(e).__name__}"}

def github_recon(domain):
    token=os.getenv('GITHUB_TOKEN')
    if not token: return {"available":False,"status":"not_configured","results":[],"message":"Set GITHUB_TOKEN to enable authenticated GitHub code search."}
    try:
        r=requests.get('https://api.github.com/search/code',params={'q':f'"{domain}"','per_page':10},headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},timeout=TIMEOUT)
        if r.status_code!=200: return {"available":True,"status":"failed","results":[],"http_status":r.status_code,"message":f"GitHub code search returned HTTP {r.status_code}. Check token permissions and rate limits."}
        items=[]
        for x in r.json().get('items',[])[:10]:
            items.append({"repository":(x.get('repository') or {}).get('full_name'),"path":x.get('path'),"url":x.get('html_url'),"source":"GitHub code search"})
        return {"available":True,"status":"matches_found" if items else "no_matches","results":items,"count":len(items),"message":f"GitHub code search returned {len(items)} path-level matches. File contents are not copied."}
    except Exception as e: return {"available":True,"status":"failed","results":[],"message":f"GitHub request failed: {type(e).__name__}"}

def shodan_ips(ips):
    key=os.getenv('SHODAN_API_KEY')
    if not key: return {"available":False,"status":"not_configured","results":[],"message":"Set SHODAN_API_KEY to enable Shodan host lookups."}
    results=[]
    for ip in list(dict.fromkeys(ips))[:5]:
        try:
            if not ipaddress.ip_address(ip).is_global: continue
            r=requests.get(f'https://api.shodan.io/shodan/host/{ip}',params={'key':key,'minify':'true'},timeout=TIMEOUT)
            if r.status_code==200:
                x=r.json(); results.append({"ip":ip,"ports":x.get('ports',[])[:40],"hostnames":x.get('hostnames',[])[:30],"org":x.get('org'),"isp":x.get('isp'),"asn":x.get('asn'),"country_code":x.get('country_code'),"last_update":x.get('last_update'),"source":"Shodan API"})
            else: results.append({"ip":ip,"http_status":r.status_code,"error":"Provider did not return host data."})
        except Exception as e: results.append({"ip":ip,"error":type(e).__name__})
    ok=[x for x in results if 'error' not in x and 'http_status' not in x]
    return {"available":True,"status":"matches_found" if ok else "no_matches","results":results,"count":len(ok),"message":f"Shodan returned host metadata for {len(ok)} of {len(results)} queried public IPs."}

def censys_ips(ips):
    api_id=os.getenv('CENSYS_API_ID'); secret=os.getenv('CENSYS_API_SECRET')
    if not api_id or not secret: return {"available":False,"status":"not_configured","results":[],"message":"Set CENSYS_API_ID and CENSYS_API_SECRET to enable Censys host lookups."}
    results=[]
    for ip in list(dict.fromkeys(ips))[:5]:
        try:
            if not ipaddress.ip_address(ip).is_global: continue
            r=requests.get(f'https://search.censys.io/api/v2/hosts/{ip}',auth=(api_id,secret),timeout=TIMEOUT)
            if r.status_code==200:
                x=r.json().get('result',{}); results.append({"ip":ip,"name":x.get('name'),"location":x.get('location'),"autonomous_system":x.get('autonomous_system'),"services":[{"port":s.get('port'),"service_name":s.get('service_name'),"transport_protocol":s.get('transport_protocol')} for s in x.get('services',[])[:40]],"source":"Censys Hosts API"})
            else: results.append({"ip":ip,"http_status":r.status_code,"error":"Provider did not return host data."})
        except Exception as e: results.append({"ip":ip,"error":type(e).__name__})
    ok=[x for x in results if 'error' not in x and 'http_status' not in x]
    return {"available":True,"status":"matches_found" if ok else "no_matches","results":results,"count":len(ok),"message":f"Censys returned host metadata for {len(ok)} of {len(results)} queried public IPs."}

def reverse_whois(identifier_type, identifier):
    key=os.getenv('WHOOXY_API_KEY')
    if not key: return {"available":False,"status":"not_configured","results":[],"message":"Set WHOOXY_API_KEY to enable paid reverse-WHOIS lookups."}
    if identifier_type not in ('company','email','name','keyword') or not identifier or len(identifier)>180:
        return {"available":True,"status":"invalid_input","results":[],"message":"Provide a valid company, email, owner name or domain-name keyword."}
    try:
        r=requests.get('https://api.whoxy.com/',params={'key':key,'reverse':'whois',identifier_type:identifier,'mode':'micro'},timeout=20)
        if r.status_code!=200: return {"available":True,"status":"failed","results":[],"http_status":r.status_code,"message":f"Whoxy returned HTTP {r.status_code}."}
        data=r.json()
        if data.get('status')!=1: return {"available":True,"status":"no_matches","results":[],"message":data.get('error') or 'No reverse-WHOIS matches returned.'}
        domains=[]
        for x in data.get('search_result',[])[:100]:
            d=x.get('domain_name') or x.get('domain')
            if d: domains.append({"domain":d,"source":"Whoxy reverse WHOIS"})
        return {"available":True,"status":"matches_found" if domains else "no_matches","results":domains,"count":len(domains),"message":f"Whoxy returned {len(domains)} domain records. Validate ownership independently."}
    except Exception as e: return {"available":True,"status":"failed","results":[],"message":f"Whoxy request failed: {type(e).__name__}"}

def google_dorks(domain):
    if not _domain_ok(domain): return {"status":"invalid_scope","queries":[]}
    specs=[('Indexed subdomains',f'site:*.{domain}'),('Login portals',f'site:{domain} inurl:login OR inurl:signin'),('Public documents',f'site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx'),('API documentation',f'site:{domain} (inurl:swagger OR inurl:openapi OR inurl:api-docs)'),('Configuration references',f'site:{domain} (inurl:config OR inurl:environment)')]
    return {"status":"ready","queries":[{"label":label,"query":q,"url":"https://www.google.com/search?q="+quote_plus(q)} for label,q in specs],"message":"Prepared manual Google search links. Queries are not executed or scraped by SCOPEZERO."}
