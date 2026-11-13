
"""End-to-end, engagement-scoped SCOPEZERO workflow.

Pipeline stages: discover -> resolve -> probe -> correlate -> assess -> validate -> report.
Validation is deliberately analyst-led; no exploit or intrusive verification is automated.
"""
import json, threading, ipaddress
from datetime import datetime, timezone
from .database import db
from .worker import run_scan
from .engines.adapters import findomain, naabu, httpx_probe, feroxbuster

def now():
    return datetime.now(timezone.utc).isoformat()



def _emit(scan_id,event_type,severity,title,message,payload=None):
    with db() as c:
        c.execute("INSERT INTO live_events(scan_id,event_type,severity,title,message,payload_json,created) VALUES(?,?,?,?,?,?,?)",
          (scan_id,event_type,severity,title,message,json.dumps(payload or {}),now()))

def _set(pid, status=None, stage=None, progress=None, error=None, stages=None, started=False, finished=False):
    fields=[]; vals=[]
    if status is not None: fields.append("status=?"); vals.append(status)
    if stage is not None: fields.append("stage=?"); vals.append(stage)
    if progress is not None: fields.append("progress=?"); vals.append(progress)
    if error is not None: fields.append("error=?"); vals.append(error)
    if stages is not None: fields.append("stages_json=?"); vals.append(json.dumps(stages))
    if started: fields.append("started=?"); vals.append(now())
    if finished: fields.append("finished=?"); vals.append(now())
    if fields:
        vals.append(pid)
        with db() as c: c.execute("UPDATE pipeline_runs SET "+",".join(fields)+" WHERE id=?", vals)

    if stage is not None:
        with db() as c:
            r=c.execute("SELECT scan_id FROM pipeline_runs WHERE id=?",(pid,)).fetchone()
        if r:
            _emit(r["scan_id"],"pipeline_stage","info","Pipeline stage",stage,{"progress":progress,"status":status})

def _scope(scan_id):
    with db() as c:
        scan=c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        eng=c.execute("SELECT * FROM engagements WHERE id=?", (scan["engagement_id"],)).fetchone() if scan and scan["engagement_id"] else None
    if not scan or not eng or not eng["authorized"]:
        raise RuntimeError("Engagement authorization is missing or inactive.")
    if eng["expires"]:
        exp=datetime.fromisoformat(eng["expires"].replace("Z","+00:00"))
        if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc): raise RuntimeError("Engagement authorization expired.")
    exclusions=json.loads(eng["exclusions_json"] or "[]")
    root=scan["domain"]
    def allowed(host):
        h=str(host or "").lower().rstrip(".")
        return (h==root or h.endswith("."+root)) and not any(h==x or h.endswith("."+x) for x in exclusions)
    return scan, eng, allowed

def _record_job(scan_id, engagement_id, tool, result):
    stamp=now()
    with db() as c:
        cur=c.execute("""INSERT INTO tool_jobs(scan_id,engagement_id,tool,status,progress,stage,result_json,created,started,finished)
          VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (scan_id,engagement_id,tool,result.get("status","completed"),100,"Completed",json.dumps(result),stamp,stamp,stamp))
        job_id=cur.lastrowid
        c.execute("INSERT INTO offensive_runs(scan_id,module,status,results,created) VALUES(?,?,?,?,?)",
                  (scan_id,tool,result.get("status","completed"),json.dumps(result),stamp))
    _emit(scan_id,"tool_result","success",f"{tool} completed",f"{tool} returned {len(result.get('results',result.get('hosts',[])))} result items.",{"job_id":job_id,"tool":tool,"status":result.get("status")})
    return job_id

def _persist_tool(scan_id, job_id, tool, result, allowed):
    stamp=now(); accepted=0
    with db() as c:
        for host in result.get("hosts",[]):
            h=str(host).lower().rstrip(".")
            if not allowed(h): continue
            c.execute("""INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls)
              VALUES(?,?,?,?,?,?,?,?,?)""",(scan_id,h,"subdomain",tool,"{}","Candidate — verify",65,
              json.dumps([f"{tool} discovery candidate"]), "{}"))
            c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                      (scan_id, _root(scan_id), h, "contains", f"Discovered by {tool}"))
            c.execute("""INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json)
              VALUES(?,?,?,?,?,?,?,?,?)""",(scan_id,job_id,h,"hostname","contains",tool,stamp,65,json.dumps({"status":"candidate"})))
            accepted+=1
        for item in result.get("results",[]):
            host=str(item.get("host") or item.get("ip") or "").lower().rstrip(".")
            if not host or not allowed(host): continue
            if tool=="naabu":
                try: port=int(item.get("port"))
                except (TypeError,ValueError): continue
                if not 1<=port<=65535: continue
                entity=f"{host}:{port}/tcp"
                c.execute("INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls) VALUES(?,?,?,?,?,?,?,?,?)",
                          (scan_id,entity,"port",tool,"{}","In-scope observation",85,json.dumps(item),"{}"))
                c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                          (scan_id,host,entity,"exposes_port",f"TCP/{port} observed by {tool}"))
                svc=item.get("service") or "unknown"
                if svc!="unknown":
                    service=f"service:{svc}"
                    c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                              (scan_id,entity,service,"service_hint",f"Port-based hint only; no banner validation"))
                    c.execute("""INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json)
                      VALUES(?,?,?,?,?,?,?,?,?)""",(scan_id,job_id,service,"service","service_hint",tool,stamp,55,
                      json.dumps({"port":port,"banner_validated":False})))
                etype="port"
            elif tool=="httpx":
                entity=item.get("url") or host; etype="http_service"
                c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                          (scan_id,host,entity,"serves_http","HTTP metadata from httpx"))
            else:
                entity=item.get("url") or item.get("path") or host; etype="web_path"
            c.execute("""INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json)
              VALUES(?,?,?,?,?,?,?,?,?)""",(scan_id,job_id,entity,etype,"observed_on",tool,stamp,80,json.dumps(item)))
            accepted+=1
    return accepted

def _root(scan_id):
    with db() as c: r=c.execute("SELECT domain FROM scans WHERE id=?", (scan_id,)).fetchone()
    return r["domain"]

def run_pipeline(pid, scan_id, root, options, engagement_id):
    stages={"discover":"queued","resolve":"queued","probe":"queued","correlate":"queued","assess":"queued","validate":"analyst_review","report":"queued"}
    try:
        _set(pid,"running","Discover",2,stages=stages,started=True)
        # Existing discovery engine performs CT, optional passive sources, DNS resolution,
        # TLS/HTTP observations, and first-pass DNS/web assessment.
        run_scan(scan_id,root,options,engagement_id)
        with db() as c: scan=c.execute("SELECT status,error FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan or scan["status"]!="completed":
            raise RuntimeError("Discovery/resolution stage failed: "+str(scan["error"] or "unknown error"))
        stages["discover"]="completed"; stages["resolve"]="completed"
        _set(pid,stage="Probe",progress=45,stages=stages)
        _,eng,allowed=_scope(scan_id)
        with db() as c:
            hosts=[r["host"] for r in c.execute("SELECT host FROM assets WHERE scan_id=? AND kind IN ('domain','subdomain')",(scan_id,))]
        hosts=sorted({h for h in hosts if allowed(h)})[:80]
        # Run the four adapters sequentially to keep a predictable resource ceiling.
        results={}
        tool_steps=[("findomain",lambda:findomain(root,timeout=90))]
        if options.get("run_naabu",True): tool_steps.append(("naabu",lambda:naabu(hosts,timeout=150)))
        if options.get("run_httpx",True): tool_steps.append(("httpx",lambda:httpx_probe(hosts,timeout=150)))
        if options.get("run_feroxbuster",True): tool_steps.append(("feroxbuster",lambda:feroxbuster(hosts,timeout=150,max_hosts=3)))
        for idx,(tool,fn) in enumerate(tool_steps,1):
            _scope(scan_id)  # Recheck active authorization and exclusions before each tool.
            result=fn()
            # Defend again at the persistence boundary.
            _,_,current_allowed=_scope(scan_id)
            jid=_record_job(scan_id,engagement_id,tool,result)
            accepted=_persist_tool(scan_id,jid,tool,result,current_allowed)
            result["accepted_observations"]=accepted
            results[tool]=result
            stages["probe"]="running"
            _set(pid,stage=f"Probe · {tool}",progress=45+idx*8,stages=stages)
        stages["probe"]="completed"
        _set(pid,stage="Correlate",progress=80,stages=stages)
        # Correlation is materialized as a normalized graph: host -> port -> service,
        # host -> HTTP URL -> path. Deduplicate graph edges.
        with db() as c:
            c.execute("""DELETE FROM edges WHERE scan_id=? AND id NOT IN
              (SELECT MIN(id) FROM edges WHERE scan_id=? GROUP BY source,target,relation)""",(scan_id,scan_id))
            n=c.execute("SELECT COUNT(*) n FROM normalized_observations WHERE scan_id=?",(scan_id,)).fetchone()["n"]
            a=c.execute("SELECT COUNT(*) n FROM assets WHERE scan_id=?",(scan_id,)).fetchone()["n"]
            e=c.execute("SELECT COUNT(*) n FROM edges WHERE scan_id=?",(scan_id,)).fetchone()["n"]
        stages["correlate"]="completed"
        _set(pid,stage="Assess",progress=86,stages=stages)
        # Existing assessment findings are retained. The pipeline does not turn a port,
        # path, banner hint, 401/403, or missing header into a confirmed vulnerability.
        with db() as c:
            findings=c.execute("SELECT COUNT(*) n FROM findings WHERE scan_id=?",(scan_id,)).fetchone()["n"]
            c.execute("INSERT INTO audit_events(scan_id,event_type,entity,details,created) VALUES(?,?,?,?,?)",
                      (scan_id,"pipeline_assessment","scan",json.dumps({"findings":findings,"assets":a,"edges":e}),now()))
        stages["assess"]="completed"
        stages["validate"]="analyst_review"
        _set(pid,stage="Validate · analyst review required",progress=94,stages=stages)
        # Report stage is complete when report endpoints can render the final persisted state.
        stages["report"]="completed"
        summary={"assets":a,"relationships":e,"normalized_observations":n,"findings":findings,
                 "tool_results":{k:{"status":v.get("status"),"result_count":v.get("result_count",len(v.get("results",v.get("hosts",[]))))} for k,v in results.items()},
                 "report_html":f"/api/scans/{scan_id}/pentest-report",
                 "report_studio":f"/api/scans/{scan_id}/report-studio"}
        _set(pid,"completed","Complete · report ready",100,stages=stages,finished=True)
        with db() as c:
            c.execute("UPDATE pipeline_runs SET stages_json=? WHERE id=?",(json.dumps({**stages,"summary":summary}),pid))
    except Exception as exc:
        stages["current"]="failed"
        _set(pid,"failed","Pipeline failed",100,error=f"{type(exc).__name__}: {str(exc)[:500]}",stages=stages,finished=True)
