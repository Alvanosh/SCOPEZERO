import json, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime,timezone
from .database import db
from .engines.discovery import ct,dns_records,wordlist,external_enumerators,shodan_internetdb
from .engines.assessment import attribution,tls_info,web_observations,dns_observations
from .engines.risk import summarize
from .engines.vulnintel import correlate
from .engines.webintel import enumerate_directories, discover_api, email_posture, cloud_indicators
_LOCK=threading.Lock()
def now(): return datetime.now(timezone.utc).isoformat()
def emit(sid,event_type,severity,title,message,payload=None):
    with db() as c:
        c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
          (sid,event_type,severity,title,message,json.dumps(payload or {}),now()))
def update(sid,progress,stage):
    with _LOCK,db() as c:
        c.execute("UPDATE scans SET progress=?,stage=? WHERE id=?",(progress,stage,sid))
    emit(sid,"stage","info","Stage update",stage,{"progress":progress})
def run_scan(sid,root,options,engagement_id=None):
    try:
        emit(sid,"scan_started","success","Assessment started",f"Authorized assessment started for {root}.",{"domain":root})
        exclusions=[]
        if engagement_id:
            with db() as c:
                er=c.execute("SELECT exclusions_json FROM engagements WHERE id=?",(engagement_id,)).fetchone()
                if er:
                    try: exclusions=json.loads(er["exclusions_json"] or "[]")
                    except Exception: exclusions=[]
        def in_scope(host):
            h=host.lower().rstrip(".")
            return (h==root or h.endswith("."+root)) and not any(h==x or h.endswith("."+x) for x in exclusions)
        update(sid,3,"Certificate Transparency discovery")
        names,ct_error=ct(root); ct_names=set(names)
        names={h for h in names if in_scope(h)}
        source_results={"crt.sh":{"available":True,"hosts":sorted(ct_names),"error":ct_error}}
        if options.get("external_tools"):
            update(sid,8,"Passive Subfinder and Amass discovery")
            ext=external_enumerators(root,timeout=options.get("tool_timeout",90))
            source_results.update(ext)
            for item in ext.values(): names.update(item.get("hosts",[]))
            names={h for h in names if in_scope(h)}
        update(sid,15,"DNS intelligence")
        if options.get("wordlist"):
            names |= wordlist(root,lambda i,n:update(sid,15+int(25*i/n),"Bounded DNS wordlist discovery"))
            names={h for h in names if in_scope(h)}
        names.add(root)
        assets=[];edges=[];findings=[];ip_intel=[];surface=[];email_data={};cloud_data=[]
        total=max(1,len(names))
        content_hosts={root} | set(sorted([h for h in names if h!=root and h.endswith("."+root)])[:11])
        profile=options.get("speed_profile","fast")
        workers=max(4,min(int(options.get("workers",12)),24))
        def assess_one(host):
            records=dns_records(host)
            score,label,evidence=attribution(host,root,host in ct_names,records)
            tls=tls_info(host) if records.get("A") or records.get("AAAA") else {}
            local_findings=dns_observations(host,records)
            if options.get("web_checks") and (records.get("A") or records.get("AAAA")):
                local_findings.extend(web_observations(host))
            # Suppress purely informational header omissions by default; retain actionable low+ observations.
            local_findings=[f for f in local_findings if str(f.get("severity","")).lower()!="info"]
            local_surface=[]; local_cloud=[]
            cloud=cloud_indicators(host,records)
            for item in cloud.get("indicators",[]):
                local_cloud.append({"host":host,**item})
                local_surface.append({"host":host,"category":"cloud-indicator","target":item["target"],"status":None,"source":"DNS CNAME","confidence":85,"evidence":item})
            local_email=email_posture(root,records) if host==root else {}
            if host==root:
                local_surface.append({"host":root,"category":"email-posture","target":root,"status":None,"source":"DNS TXT/MX","confidence":90,"evidence":local_email})
            local_dirs=[]; local_apis=[]
            if options.get("content_discovery") and host in content_hosts and (records.get("A") or records.get("AAAA")):
                dirs=enumerate_directories(host)
                local_dirs=[{"host":host,"category":"directory","target":item["path"],"status":item.get("status"),"source":item["source"],"confidence":90 if item.get("status")==200 else 65,"evidence":item} for item in dirs.get("results",[])]
                api=discover_api(host)
                local_apis=[{"host":host,"category":"api-endpoint","target":item["path"],"status":item.get("status"),"source":item["source"],"confidence":90 if item.get("spec_indicator") else 70,"evidence":item} for item in api.get("endpoints",[])]
            return host,records,score,label,evidence,tls,local_findings,local_surface+local_dirs+local_apis,local_email,local_cloud
        # Network-bound work is parallelized but concurrency is capped to avoid overwhelming
        # resolvers or target infrastructure. Results are persisted in deterministic host order.
        completed=[]; assessment_errors=[]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures={pool.submit(assess_one,h):h for h in sorted(names) if in_scope(h)}
            for n,future in enumerate(as_completed(futures),1):
                try:
                    host,records,score,label,evidence,tls,local_findings,local_surface,local_email,local_cloud=future.result()
                    completed.append((host,records,score,label,evidence,tls))
                    findings.extend({"host":host,**f} for f in local_findings)
                    surface.extend(local_surface); cloud_data.extend(local_cloud)
                    if local_email: email_data=local_email
                except Exception as error:
                    assessment_errors.append({"host":futures[future],"error":type(error).__name__})
                    emit(sid,"scan_error","warning","Asset assessment error",f"{futures[future]}: {type(error).__name__}",{"host":futures[future]})
                update(sid,40+int(48*n/total),f"Parallel asset assessment ({n}/{total}) · {workers} workers")
        for host,records,score,label,evidence,tls in sorted(completed):
            assets.append({"host":host,"kind":"domain" if host==root else "subdomain",
                "source":"Operator-supplied root" if host==root else ("Certificate Transparency" if host in ct_names else ("Passive enumerator" if options.get("external_tools") else "DNS wordlist" if options.get("wordlist") else "Certificate Transparency / DNS")),
                "dns":records,"ownership":label,"confidence":score,"evidence":evidence,"tls":tls})
            edges.append((root,host,"contains","Hostname observed beneath the authorized root domain."))
            for typ in ("A","AAAA"):
                for ip in records.get(typ,[]):
                    assets.append({"host":ip,"kind":"ip","source":f"DNS {typ} answer for {host}","dns":{},
                      "ownership":"Unverified","confidence":0,"evidence":[f"{typ} answer observed for {host}"],"tls":{}})
                    edges.append((host,ip,"resolves_to",f"{typ} DNS answer observed for {host}"))
            for cname in records.get("CNAME",[]):
                edges.append((host,cname.rstrip("."),"cname_to",f"CNAME observed for {host}"))
        # Deduplicate public IP lookups: one request per unique discovered address.
        unique_ips=sorted({a["host"] for a in assets if a["kind"]=="ip"})
        if options.get("shodan_intel") and unique_ips:
            update(sid,89,"Parallel Shodan metadata enrichment")
            with ThreadPoolExecutor(max_workers=min(8,len(unique_ips))) as pool:
                ip_intel=[x for x in pool.map(shodan_internetdb,unique_ips) if x]
                # Collapse repeated IP answers across hostnames while preserving all provenance.
        asset_index={}
        for asset in assets:
            key=(asset["host"],asset["kind"])
            if key not in asset_index:
                asset_index[key]=asset
            else:
                prior=asset_index[key]
                if asset.get("source") and asset["source"] not in (prior.get("source") or ""):
                    prior["source"]=(prior.get("source") or "")+"; "+asset["source"]
                prior["evidence"]=list(dict.fromkeys((prior.get("evidence") or [])+(asset.get("evidence") or [])))
        assets=list(asset_index.values())
        edges=list({(e[0],e[1],e[2],e[3]):e for e in edges}.values())
        cves=sorted({c for item in ip_intel for c in item.get("vulns",[])})
        vuln_items=[]
        if options.get("vuln_intel") and cves:
            update(sid,91,"CVE / CVSS / EPSS / CISA KEV enrichment")
            vuln_items=correlate(cves)
        dedup={}
        for finding in findings:
            dedup[(finding.get("host"),finding.get("category"),finding.get("title"))]=finding
        findings=list(dedup.values())
        risk=summarize(findings)
        summary={"asset_count":len(assets),"hostname_count":sum(a["kind"] in ("domain","subdomain") for a in assets),
          "speed_profile":profile,"parallel_workers":workers,"unique_ip_lookups":len(unique_ips),
          "assessment_errors":assessment_errors,"assessment_error_count":len(assessment_errors),
          "ip_count":sum(a["kind"]=="ip" for a in assets),"finding_count":len(findings),
          "risk":risk,"ct_error":ct_error,"ct_source":"crt.sh",
          "sources":{k:{"available":v.get("available",True),"host_count":len(v.get("hosts",[])),"error":v.get("error")} for k,v in source_results.items()},
          "shodan_ip_lookups":len(ip_intel),"observed_cve_count":len(cves),"vulnerability_enrichment_count":len(vuln_items),
          "surface_observation_count":len(surface),"directory_observation_count":sum(x["category"]=="directory" for x in surface),
          "api_endpoint_count":sum(x["category"]=="api-endpoint" for x in surface),"cloud_indicator_count":len(cloud_data),
          "email_posture_assessed":bool(email_data)}
        with _LOCK,db() as c:
            for a in assets:
                c.execute("""INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls)
                  VALUES(?,?,?,?,?,?,?,?,?)""",(sid,a["host"],a["kind"],a["source"],json.dumps(a["dns"]),a["ownership"],a["confidence"],json.dumps(a["evidence"]),json.dumps(a["tls"])))
            for s,t,r,e in edges:
                c.execute("INSERT INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",(sid,s,t,r,e))
            for host in sorted(names):
                srcs=[source for source,data in source_results.items() if host in data.get("hosts",[])]
                if options.get("wordlist") and host not in ct_names and not srcs: srcs=["DNS wordlist"]
                for source in (srcs or ["DNS resolution"]):
                    c.execute("INSERT INTO asset_observations(scan_id,host,source,observed_at,evidence) VALUES(?,?,?,?,?)",
                      (sid,host,source,now(),json.dumps({"source":source})))
            for item in ip_intel:
                for cve in item.get("vulns",[]):
                    c.execute("INSERT INTO asset_observations(scan_id,host,source,observed_at,evidence) VALUES(?,?,?,?,?)",
                      (sid,item["ip"],"Shodan InternetDB",now(),json.dumps(item)))
            for item in surface:
                c.execute("INSERT INTO surface_observations(scan_id,host,category,target,status,source,confidence,evidence,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (sid,item["host"],item["category"],item["target"],item.get("status"),item["source"],item["confidence"],json.dumps(item["evidence"]),now()))
            for v in vuln_items:
                for item in ip_intel:
                    if v["cve"] in item.get("vulns",[]):
                        c.execute("""INSERT OR IGNORE INTO vulnerability_intel(scan_id,host,cve,description,cvss,severity,epss,kev,source,confidence)
                          VALUES(?,?,?,?,?,?,?,?,?,?)""",(sid,item["ip"],v["cve"],v.get("description"),v.get("cvss"),v.get("severity"),v.get("epss"),int(v.get("kev",False)),v.get("source"),v.get("confidence")))
            for f in findings:
                c.execute("""INSERT INTO findings(scan_id,host,category,title,severity,score,description,evidence,recommendation)
                  VALUES(?,?,?,?,?,?,?,?,?)""",(sid,f["host"],f["category"],f["title"],f["severity"],f["score"],f["description"],json.dumps(f["evidence"]),f["recommendation"]))
            for f in findings:
                sev=str(f.get("severity","info")).lower()
                alert="critical" if sev=="critical" else "danger" if sev=="high" else "warning" if sev=="medium" else "info"
                c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
                  (sid,"finding",alert,"Security observation",f"{f.get('host')}: {f.get('title')}",json.dumps({"host":f.get("host"),"category":f.get("category"),"severity":sev}),now()))
            for err in assessment_errors:
                c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
                  (sid,"scan_error","warning","Partial assessment error",f"{err['host']}: {err['error']}",json.dumps(err),now()))
            c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
              (sid,"scan_completed","success","Assessment completed",f"Collected {len(assets)} assets and {len(findings)} observations.",json.dumps(summary),now()))
            c.execute("UPDATE scans SET status='completed',progress=100,stage='Completed',finished=?,summary=? WHERE id=?",(now(),json.dumps(summary),sid))
    except Exception as e:
        with _LOCK,db() as c:
            message=f"{type(e).__name__}: {str(e)[:500]}"
            c.execute("UPDATE scans SET status='failed',stage='Failed',error=?,finished=? WHERE id=?",(message,now(),sid))
            c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
              (sid,"scan_error","critical","Scan failed",message,json.dumps({"exception":type(e).__name__}),now()))
