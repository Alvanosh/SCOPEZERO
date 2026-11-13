import json,csv,io,threading,shutil,os,html,ipaddress,socket,urllib.request,urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from datetime import datetime,timezone
from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse,StreamingResponse,HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from .config import FRONTEND,VERSION,UA
from .database import db,init
from .engines.discovery import normalize
from .worker import run_scan
from .engines.investigation import sha256_text, confidence_from_evidence, risk_score, validate_public_target, url_host
import requests, time
from .engines.adapters import findomain as findomain_adapter, naabu as naabu_adapter, httpx_probe as httpx_adapter, feroxbuster as feroxbuster_adapter
app=FastAPI(title="SCOPEZERO Exposure Intelligence",version=VERSION,description="Authorized external attack surface discovery and engagement management.")
app.mount("/static",StaticFiles(directory=str(FRONTEND)),name="static")
init()
_TOOL_POOL=ThreadPoolExecutor(max_workers=4, thread_name_prefix="scopezero-tool")
def stamp(): return datetime.now(timezone.utc).isoformat()
class EngagementIn(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    domain:str
    authorized:bool
    exclusions:list[str]=[]
    expires:str|None=None
class ScanIn(BaseModel):
    domain:str
    authorized:bool
    wordlist:bool=False
    web_checks:bool=True
    external_tools:bool=False
    shodan_intel:bool=False
    vuln_intel:bool=False
    content_discovery:bool=False
    tool_timeout:int=90
    speed_profile:str="fast"
    engagement_id:int|None=None
@app.get("/")
def home(): return FileResponse(FRONTEND/"index.html", headers={"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0", "Pragma":"no-cache"})
@app.get("/api/health")
def health(): return {"status":"ok","version":VERSION}
@app.post("/api/engagements")
def create_engagement(x:EngagementIn):
    if not x.authorized: raise HTTPException(400,"Confirm ownership or written authorization.")
    try: root=normalize(x.domain)
    except ValueError as e: raise HTTPException(400,str(e))
    exclusions=[]
    for item in x.exclusions:
        try: exclusions.append(normalize(item))
        except ValueError: raise HTTPException(400,f"Invalid excluded domain: {item}")
    with db() as c:
        cur=c.execute("INSERT INTO engagements(name,root_domain,scope_json,exclusions_json,authorized,created,expires) VALUES(?,?,?,?,?,?,?)",
          (x.name,root,json.dumps([root]),json.dumps(exclusions),1,stamp(),x.expires))
        eid=cur.lastrowid
    return {"id":eid,"name":x.name,"root_domain":root,"exclusions":exclusions,"created":True}
@app.get("/api/engagements")
def engagements():
    with db() as c: rows=c.execute("SELECT * FROM engagements ORDER BY id DESC").fetchall()
    return [{**dict(r),"scope":json.loads(r["scope_json"]),"exclusions":json.loads(r["exclusions_json"])} for r in rows]
@app.post("/api/scans")
def create_scan(x:ScanIn):
    if not x.authorized: raise HTTPException(400,"Confirm ownership or written authorization.")
    try: root=normalize(x.domain)
    except ValueError as e: raise HTTPException(400,str(e))
    engagement=None
    if not x.engagement_id:
        raise HTTPException(400,"Select an authorized engagement before starting a scan.")
    if x.engagement_id:
        with db() as c: engagement=c.execute("SELECT * FROM engagements WHERE id=?",(x.engagement_id,)).fetchone()
        if not engagement: raise HTTPException(404,"Engagement not found")
        if not engagement["authorized"]: raise HTTPException(403,"Engagement authorization is inactive.")
        if root!=engagement["root_domain"]: raise HTTPException(400,"Scan domain must match the engagement root domain.")
        if engagement["expires"]:
            try:
                exp=datetime.fromisoformat(engagement["expires"].replace('Z','+00:00'))
                if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
                if exp<=datetime.now(timezone.utc): raise HTTPException(403,"Engagement authorization has expired.")
            except ValueError: raise HTTPException(400,"Engagement expiry is invalid.")
    profile=x.speed_profile if x.speed_profile in ("fast","balanced","polite") else "fast"
    # Profiles control bounded concurrency; optional sources remain explicitly opt-in.
    workers={"fast":20,"balanced":12,"polite":6}[profile]
    started=stamp(); options={"speed_profile":profile,"workers":workers,"wordlist":x.wordlist,"web_checks":x.web_checks,
      "external_tools":x.external_tools,"shodan_intel":x.shodan_intel,"vuln_intel":x.vuln_intel,
      "content_discovery":x.content_discovery,"tool_timeout":max(15,min(x.tool_timeout,180))}
    with db() as c:
        cur=c.execute("INSERT INTO scans(engagement_id,domain,started,status,progress,stage,options) VALUES(?,?,?,?,?,?,?)",
          (x.engagement_id,root,started,"queued",0,"Queued",json.dumps(options)))
        sid=cur.lastrowid
    threading.Thread(target=run_scan,args=(sid,root,options,x.engagement_id),daemon=True).start()
    return {"scan_id":sid,"domain":root,"status":"queued","message":"Scan queued. Poll the progress endpoint."}
def scan_row(sid):
    with db() as c:r=c.execute("SELECT * FROM scans WHERE id=?",(sid,)).fetchone()
    if not r: raise HTTPException(404,"Scan not found")
    d=dict(r);d["options"]=json.loads(d["options"] or "{}")
    try: d["summary"]=json.loads(d.get("summary") or "{}") or {}
    except (TypeError,ValueError): d["summary"]={}
    d["summary"].setdefault("asset_count",0)
    d["summary"].setdefault("hostname_count",0)
    d["summary"].setdefault("ip_count",0)
    d["summary"].setdefault("finding_count",0)
    return d
def rows_for(table,sid):
    with db() as c: rows=c.execute(f"SELECT * FROM {table} WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    out=[]
    for row in rows:
        d=dict(row)
        for k in ("dns","evidence","tls"):
            if k in d and d[k]:
                try:d[k]=json.loads(d[k])
                except Exception:pass
        out.append(d)
    return out
@app.get("/api/scans")
def scans():
    with db() as c: rows=c.execute("SELECT id,domain,started,finished,status,progress,stage,summary FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return [{**dict(r),"summary":json.loads(r["summary"] or "{}")} for r in rows]
@app.get("/api/scans/{sid}")
def detail(sid:int): return scan_row(sid)

@app.get("/api/scans/{sid}/live")
def live_feed(sid:int,after:int=0):
    scan=scan_row(sid)
    with db() as c:
        ev=c.execute("SELECT * FROM live_events WHERE scan_id=? AND id>? ORDER BY id ASC LIMIT 100",(sid,after)).fetchall()
        stats=c.execute("""SELECT
          (SELECT COUNT(*) FROM assets WHERE scan_id=?) assets,
          (SELECT COUNT(*) FROM assets WHERE scan_id=? AND kind IN ('domain','subdomain')) hosts,
          (SELECT COUNT(*) FROM assets WHERE scan_id=? AND kind='ip') ips,
          (SELECT COUNT(*) FROM findings WHERE scan_id=?) findings,
          (SELECT COUNT(*) FROM edges WHERE scan_id=?) edges""",(sid,sid,sid,sid,sid)).fetchone()
        graph=c.execute("SELECT source,target,relation FROM edges WHERE scan_id=? ORDER BY id DESC LIMIT 120",(sid,)).fetchall()
    events=[]
    for row in ev:
        item=dict(row)
        try:item["payload"]=json.loads(item.pop("payload_json") or "{}")
        except Exception:item["payload"]={}
        events.append(item)
    return {"scan":scan,"events":events,"stats":dict(stats),
            "graph":[dict(x) for x in graph],"server_time":stamp()}


@app.get("/api/scans/{sid}/analytics")
def scan_analytics(sid:int):
    scan_row(sid)
    with db() as c:
        severity=c.execute("SELECT lower(severity) severity,COUNT(*) count FROM findings WHERE scan_id=? GROUP BY lower(severity)",(sid,)).fetchall()
        categories=c.execute("SELECT category,COUNT(*) count FROM findings WHERE scan_id=? GROUP BY category ORDER BY count DESC LIMIT 8",(sid,)).fetchall()
        events=c.execute("SELECT substr(created,1,16) bucket,COUNT(*) count FROM live_events WHERE scan_id=? GROUP BY bucket ORDER BY bucket",(sid,)).fetchall()
        relations=c.execute("SELECT relation,COUNT(*) count FROM edges WHERE scan_id=? GROUP BY relation ORDER BY count DESC LIMIT 6",(sid,)).fetchall()
        top_hosts=c.execute("""SELECT host,COUNT(*) count FROM assets WHERE scan_id=?
          GROUP BY host ORDER BY count DESC LIMIT 6""",(sid,)).fetchall()
    sev={str(r["severity"] or "unknown"):r["count"] for r in severity}
    return {"severity":sev,"categories":[dict(x) for x in categories],
            "activity":[dict(x) for x in events],"relations":[dict(x) for x in relations],
            "top_hosts":[dict(x) for x in top_hosts]}

@app.get("/api/events/recent")
def recent_live_events(limit:int=20):
    limit=max(1,min(limit,50))
    with db() as c:
        rows=c.execute("""SELECT e.*,s.domain FROM live_events e JOIN scans s ON s.id=e.scan_id
          ORDER BY e.id DESC LIMIT ?""",(limit,)).fetchall()
    out=[]
    for r in rows:
        item=dict(r)
        try:item["payload"]=json.loads(item.pop("payload_json") or "{}")
        except Exception:item["payload"]={}
        out.append(item)
    return out


# SCOPEZERO 10.0 — professional engagement workspace APIs.
class FindingStatusIn(BaseModel):
    status: str = Field(min_length=2,max_length=40)
    note: str = Field(default="",max_length=2000)

@app.get("/api/workspace/overview")
def workspace_overview(engagement_id:int|None=None):
    with db() as c:
        if engagement_id is not None:
            eng=c.execute("SELECT * FROM engagements WHERE id=?",(engagement_id,)).fetchone()
            if not eng: raise HTTPException(404,"Engagement not found.")
            scans=c.execute("SELECT * FROM scans WHERE engagement_id=? ORDER BY id DESC LIMIT 12",(engagement_id,)).fetchall()
            scan_ids=[r["id"] for r in scans]
            assets_count=c.execute("SELECT COUNT(DISTINCT a.host) n FROM assets a JOIN scans s ON s.id=a.scan_id WHERE s.engagement_id=?",(engagement_id,)).fetchone()["n"]
            findings_count=c.execute("SELECT COUNT(*) n FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.engagement_id=?",(engagement_id,)).fetchone()["n"]
            open_count=c.execute("SELECT COUNT(*) n FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.engagement_id=? AND lower(COALESCE(f.status,'Open')) NOT IN ('closed','fixed','false positive')",(engagement_id,)).fetchone()["n"]
            severity=c.execute("SELECT lower(f.severity) severity,COUNT(*) count FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.engagement_id=? GROUP BY lower(f.severity)",(engagement_id,)).fetchall()
            evid=c.execute("SELECT COUNT(*) n FROM pentest_evidence p JOIN scans s ON s.id=p.scan_id WHERE s.engagement_id=?",(engagement_id,)).fetchone()["n"]
        else:
            eng=None
            scans=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 12").fetchall()
            assets_count=c.execute("SELECT COUNT(DISTINCT host) n FROM assets").fetchone()["n"]
            findings_count=c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
            open_count=c.execute("SELECT COUNT(*) n FROM findings WHERE lower(COALESCE(status,'Open')) NOT IN ('closed','fixed','false positive')").fetchone()["n"]
            severity=c.execute("SELECT lower(severity) severity,COUNT(*) count FROM findings GROUP BY lower(severity)").fetchall()
            evid=c.execute("SELECT COUNT(*) n FROM pentest_evidence").fetchone()["n"]
        engagements_count=c.execute("SELECT COUNT(*) n FROM engagements").fetchone()["n"]
        active_jobs=c.execute("SELECT COUNT(*) n FROM tool_jobs WHERE lower(status) IN ('queued','running')").fetchone()["n"]
    return {"engagement":dict(eng) if eng else None,"engagements_count":engagements_count,
            "assets_count":assets_count,"findings_count":findings_count,"open_findings":open_count,
            "evidence_count":evid,"active_jobs":active_jobs,"severity":{r["severity"] or "unknown":r["count"] for r in severity},
            "recent_scans":[dict(x) for x in scans]}


@app.get("/api/workspace/engagements/{engagement_id}/evidence")
def workspace_evidence(engagement_id:int,limit:int=100):
    with db() as c:
        if not c.execute("SELECT id FROM engagements WHERE id=?",(engagement_id,)).fetchone(): raise HTTPException(404,"Engagement not found.")
        rows=c.execute("""SELECT p.id,p.scan_id,p.finding_id,p.title,p.evidence_type,p.notes,p.created,
          f.title finding_title,s.domain FROM pentest_evidence p JOIN scans s ON s.id=p.scan_id
          LEFT JOIN findings f ON f.id=p.finding_id WHERE s.engagement_id=?
          ORDER BY p.id DESC LIMIT ?""",(engagement_id,max(1,min(limit,300)))).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/workspace/engagements/{engagement_id}/assets")
def workspace_assets(engagement_id:int,q:str="",kind:str="all",limit:int=500):
    with db() as c:
        if not c.execute("SELECT id FROM engagements WHERE id=?",(engagement_id,)).fetchone(): raise HTTPException(404,"Engagement not found.")
        sql="""SELECT a.*,s.domain,s.started,s.status scan_status,s.id scan_id
          FROM assets a JOIN scans s ON s.id=a.scan_id
          WHERE s.engagement_id=?"""
        args=[engagement_id]
        if q:
            sql+=" AND lower(a.host) LIKE ?";args.append("%"+q.lower()+"%")
        if kind!="all":
            sql+=" AND lower(a.kind)=?";args.append(kind.lower())
        sql+=" ORDER BY s.id DESC,a.host LIMIT ?";args.append(max(1,min(limit,1000)))
        rows=c.execute(sql,args).fetchall()
    # Prefer the newest observation for each host/kind.
    seen=set();out=[]
    for row in rows:
        item=dict(row);key=(item["host"],item["kind"])
        if key not in seen:seen.add(key);out.append(item)
    return out

@app.get("/api/workspace/engagements/{engagement_id}/findings")
def workspace_findings(engagement_id:int,status:str="all",q:str="",limit:int=500):
    with db() as c:
        if not c.execute("SELECT id FROM engagements WHERE id=?",(engagement_id,)).fetchone(): raise HTTPException(404,"Engagement not found.")
        sql="""SELECT f.*,s.domain,s.started,s.engagement_id FROM findings f
          JOIN scans s ON s.id=f.scan_id WHERE s.engagement_id=?"""
        args=[engagement_id]
        if status!="all":sql+=" AND lower(COALESCE(f.status,'Open'))=?";args.append(status.lower())
        if q:
            sql+=" AND (lower(COALESCE(f.host,'')) LIKE ? OR lower(COALESCE(f.title,'')) LIKE ?)";args.extend(["%"+q.lower()+"%","%"+q.lower()+"%"])
        sql+=" ORDER BY CASE lower(f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,s.id DESC LIMIT ?"
        args.append(max(1,min(limit,1000)))
        rows=c.execute(sql,args).fetchall()
    return [dict(r) for r in rows]

@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id:int,x:FindingStatusIn):
    allowed={"Open","Triaged","Confirmed","False Positive","Accepted Risk","Fixed","Retest Required","Closed"}
    if x.status not in allowed: raise HTTPException(400,"Unsupported finding status.")
    with db() as c:
        row=c.execute("SELECT * FROM findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Finding not found.")
        c.execute("UPDATE findings SET status=? WHERE id=?",(x.status,finding_id))
        c.execute("INSERT INTO audit_events(scan_id,event_type,entity,details,created) VALUES(?,?,?,?,?)",
          (row["scan_id"],"finding_status_changed",str(finding_id),json.dumps({"from":row["status"] or "Open","to":x.status,"note":x.note}),stamp()))
    return {"id":finding_id,"status":x.status,"updated":True}


# Alert centre: alerts are derived from persisted assessment records, never fabricated telemetry.
class AlertUpdateIn(BaseModel):
    status: str = Field(min_length=2,max_length=30)
    assigned_to: str = Field(default="",max_length=120)
    analyst_note: str = Field(default="",max_length=3000)

@app.post("/api/alerts/sync")
def sync_alerts(engagement_id:int|None=None):
    with db() as c:
        sql="""SELECT f.id finding_id,f.scan_id,f.title,f.severity,f.host,s.engagement_id,s.domain
               FROM findings f JOIN scans s ON s.id=f.scan_id"""
        args=[]
        if engagement_id is not None: sql+=" WHERE s.engagement_id=?";args.append(engagement_id)
        rows=c.execute(sql,args).fetchall()
        created=0
        for f in rows:
            fp=f"finding:{f['finding_id']}"
            exists=c.execute("SELECT id FROM alerts WHERE fingerprint=?",(fp,)).fetchone()
            if not exists:
                sev=(f["severity"] or "info").lower()
                message=f"{f['host'] or f['domain']} · finding #{f['finding_id']}"
                c.execute("""INSERT INTO alerts(engagement_id,scan_id,finding_id,category,severity,title,message,fingerprint,created,updated)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",(f["engagement_id"],f["scan_id"],f["finding_id"],"Finding",sev,f["title"] or "Security finding",message,fp,stamp(),stamp()))
                created+=1
        failures=c.execute("""SELECT id,engagement_id,domain,status,error FROM scans
                              WHERE lower(status) IN ('failed','error')""").fetchall()
        for s in failures:
            if engagement_id is not None and s["engagement_id"]!=engagement_id: continue
            fp=f"scan-error:{s['id']}"
            if not c.execute("SELECT id FROM alerts WHERE fingerprint=?",(fp,)).fetchone():
                c.execute("""INSERT INTO alerts(engagement_id,scan_id,category,severity,title,message,fingerprint,created,updated)
                  VALUES(?,?,?,?,?,?,?,?,?)""",(s["engagement_id"],s["id"],"Assessment failure","warning","Assessment failed",s["error"] or f"Scan #{s['id']} failed",fp,stamp(),stamp()))
                created+=1
    return {"created":created}

@app.get("/api/alerts")
def list_alerts(engagement_id:int|None=None,status:str="all",severity:str="all",limit:int=200):
    with db() as c:
        sql="SELECT * FROM alerts WHERE 1=1";args=[]
        if engagement_id is not None:sql+=" AND engagement_id=?";args.append(engagement_id)
        if status!="all":sql+=" AND lower(status)=?";args.append(status.lower())
        if severity!="all":sql+=" AND lower(severity)=?";args.append(severity.lower())
        sql+=" ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'warning' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, id DESC LIMIT ?"
        args.append(max(1,min(limit,500)))
        rows=c.execute(sql,args).fetchall()
    return [dict(r) for r in rows]

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id:int,x:AlertUpdateIn):
    allowed={"New","Acknowledged","Assigned","Investigating","Resolved","Closed"}
    if x.status not in allowed:raise HTTPException(400,"Invalid alert status.")
    with db() as c:
        a=c.execute("SELECT * FROM alerts WHERE id=?",(alert_id,)).fetchone()
        if not a:raise HTTPException(404,"Alert not found.")
        c.execute("UPDATE alerts SET status=?,assigned_to=?,analyst_note=?,updated=? WHERE id=?",
                  (x.status,x.assigned_to,x.analyst_note,stamp(),alert_id))
        if a["scan_id"]:
            c.execute("INSERT INTO audit_events(scan_id,event_type,entity,details,created) VALUES(?,?,?,?,?)",
                      (a["scan_id"],"alert_updated",str(alert_id),json.dumps({"status":x.status,"assigned_to":x.assigned_to}),stamp()))
    return {"id":alert_id,"status":x.status,"updated":True}

@app.get("/api/integrations/status")
def integrations_status():
    import os,shutil
    tools=["nmap","nuclei","subfinder","amass","findomain","naabu","httpx","feroxbuster","katana","dnsx","gobuster","testssl.sh","trufflehog"]
    binaries={name:{"available":bool(shutil.which(name)),"path":shutil.which(name)} for name in tools}
    providers={"SECURITYTRAILS_API_KEY":"SecurityTrails","GITHUB_TOKEN":"GitHub","SHODAN_API_KEY":"Shodan",
               "CENSYS_API_ID":"Censys ID","CENSYS_API_SECRET":"Censys Secret","WHOOXY_API_KEY":"Whoxy"}
    keys={name:{"provider":label,"configured":bool(os.getenv(name))} for name,label in providers.items()}
    return {"tools":binaries,"providers":keys,"note":"Only presence is reported. Secret values are never returned."}

@app.get("/api/engagements/{engagement_id}/technologies")
def engagement_technologies(engagement_id:int):
    with db() as c:
        if not c.execute("SELECT id FROM engagements WHERE id=?",(engagement_id,)).fetchone():raise HTTPException(404,"Engagement not found.")
        rows=c.execute("""SELECT so.*,s.domain,s.started FROM surface_observations so
          JOIN scans s ON s.id=so.scan_id WHERE s.engagement_id=?
          AND lower(so.category) IN ('technology','fingerprint','tech')
          ORDER BY so.id DESC LIMIT 500""",(engagement_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scans/{sid}/assets")
def assets(sid:int): scan_row(sid);return rows_for("assets",sid)
@app.get("/api/scans/{sid}/findings")
def findings(sid:int): scan_row(sid);return rows_for("findings",sid)
@app.get("/api/scans/{sid}/graph")
def graph(sid:int):
    scan_row(sid); aa=rows_for("assets",sid)
    with db() as c: ee=c.execute("SELECT * FROM edges WHERE scan_id=?",(sid,)).fetchall()
    nodes=[{"data":{"id":a["host"],"label":a["host"],"kind":a["kind"],"ownership":a["ownership"],"confidence":a["confidence"],"source":a["source"],"dns":a["dns"],"evidence":a["evidence"]}} for a in aa]
    known={n["data"]["id"] for n in nodes}
    for e in ee:
        for h in (e["source"],e["target"]):
            if h not in known:
                nodes.append({"data":{"id":h,"label":h,"kind":"external-reference","ownership":"Third-party / unverified","confidence":0,"source":"Relationship reference","dns":{},"evidence":[]}});known.add(h)
    return {"elements":{"nodes":nodes,"edges":[{"data":{"id":str(e["id"]),"source":e["source"],"target":e["target"],"relation":e["relation"],"evidence":e["evidence"]}} for e in ee]}}
@app.get("/api/scans/{sid}/changes")
def changes(sid:int):
    s=scan_row(sid)
    with db() as c:p=c.execute("SELECT id FROM scans WHERE domain=? AND id<? AND status='completed' ORDER BY id DESC LIMIT 1",(s["domain"],sid)).fetchone()
    if not p:return {"previous_scan":None,"added":[],"removed":[],"message":"No previous completed scan for this domain."}
    with db() as c:
        old={r["host"] for r in c.execute("SELECT host FROM assets WHERE scan_id=?",(p["id"],))}
        new={r["host"] for r in c.execute("SELECT host FROM assets WHERE scan_id=?",(sid,))}
    return {"previous_scan":p["id"],"added":sorted(new-old),"removed":sorted(old-new)}
@app.patch("/api/findings/{fid}")
def update_finding(fid:int,payload:dict):
    status=payload.get("status")
    if status not in ("Open","In Progress","Resolved","Accepted"): raise HTTPException(400,"Invalid status")
    with db() as c: cur=c.execute("UPDATE findings SET status=? WHERE id=?",(status,fid))
    if not cur.rowcount: raise HTTPException(404,"Finding not found")
    return {"id":fid,"status":status}
@app.post("/api/scans/{sid}/cancel")
def cancel(sid:int):
    s=scan_row(sid)
    if s["status"] in ("completed","failed","cancelled"): return {"status":s["status"]}
    with db() as c:c.execute("UPDATE scans SET status='cancelled',stage='Cancelled',finished=? WHERE id=?",(stamp(),sid))
    return {"status":"cancelled","note":"Cancellation prevents future UI polling; already-running network requests may finish."}
@app.get("/api/scans/{sid}/export.json")
def export_json(sid:int):
    return {"scan":scan_row(sid),"assets":assets(sid),"findings":findings(sid),"graph":graph(sid),"changes":changes(sid)}
@app.get("/api/scans/{sid}/export.csv")
def export_csv(sid:int):
    buf=io.StringIO();w=csv.DictWriter(buf,fieldnames=["host","kind","source","ownership","confidence","dns","evidence"]);w.writeheader()
    for a in assets(sid):
        w.writerow({"host":a["host"],"kind":a["kind"],"source":a["source"],"ownership":a["ownership"],"confidence":a["confidence"],"dns":json.dumps(a["dns"]),"evidence":json.dumps(a["evidence"])})
    return StreamingResponse(iter([buf.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="scopezero-{sid}.csv"'})


# SCOPEZERO 4.0: analyst intelligence, integrations inventory and portable reporting.
class ScopeUpdateIn(BaseModel):
    authorized: bool
    exclusions: list[str] = Field(default_factory=list)
    expires: str|None = None

@app.get("/api/engagements/{eid}/scope")
def get_engagement_scope(eid:int):
    with db() as c: row=c.execute("SELECT * FROM engagements WHERE id=?",(eid,)).fetchone()
    if not row: raise HTTPException(404,"Engagement not found")
    return {"id":eid,"name":row["name"],"root_domain":row["root_domain"],"authorized":bool(row["authorized"]),
            "scope":json.loads(row["scope_json"]),"exclusions":json.loads(row["exclusions_json"]),"expires":row["expires"]}

@app.put("/api/engagements/{eid}/scope")
def update_engagement_scope(eid:int, payload:ScopeUpdateIn):
    with db() as c: row=c.execute("SELECT * FROM engagements WHERE id=?",(eid,)).fetchone()
    if not row: raise HTTPException(404,"Engagement not found")
    if not payload.authorized: raise HTTPException(400,"Explicitly confirm current written authorization.")
    exclusions=[]
    for item in payload.exclusions:
        try: exclusions.append(normalize(item))
        except ValueError: raise HTTPException(400,f"Invalid excluded domain: {item}")
    with db() as c: c.execute("UPDATE engagements SET authorized=1,exclusions_json=?,expires=? WHERE id=?",(json.dumps(sorted(set(exclusions))),payload.expires,eid))
    _audit(None,"engagement_scope_updated",str(eid),{"exclusions":exclusions,"expires":payload.expires})
    return get_engagement_scope(eid)

@app.get("/api/integrations")
def integrations():
    tools = {
        "nmap": "Authorized network/service assessment (operator-run integration)",
        "nuclei": "Template-based checks (use vetted templates and explicit scope)",
        "subfinder": "Passive subdomain discovery",
        "amass": "Attack surface enumeration",
        "httpx": "HTTP service metadata",
        "naabu": "Port discovery",
        "zap": "Web application security testing",
        "gitleaks": "Secret detection in authorized repositories"
    }
    return {"integrations":[{"name":k,"purpose":v,"installed":shutil.which(k) is not None,
      "path":shutil.which(k)} for k,v in tools.items()],
      "configured_sources":{"crt_sh":True,"nvd_api_key":bool(os.getenv("NVD_API_KEY")),
      "shodan_api_key":bool(os.getenv("SHODAN_API_KEY")),"censys_api_id":bool(os.getenv("CENSYS_API_ID"))},
      "note":"This endpoint inventories local tools and optional credentials. It does not execute external scanners."}

@app.get("/api/scans/{sid}/intelligence")
def intelligence(sid:int):
    s=scan_row(sid)
    aa=assets(sid); ff=findings(sid); ch=changes(sid)
    priority=[]
    for a in aa:
        if a["kind"] not in ("domain","subdomain"): continue
        related=[f for f in ff if f["host"]==a["host"]]
        sev={"Critical":4,"High":3,"Medium":2,"Low":1,"Info":0}
        top=max((sev.get(f["severity"],0) for f in related),default=0)
        priority.append({"asset":a["host"],"kind":a["kind"],"confidence":a["confidence"],
          "source":a["source"],"observation_count":len(related),"highest_observation_severity":
          next((f["severity"] for f in related if sev.get(f["severity"],0)==top),"None"),
          "priority_score":min(100,a["confidence"]//2+top*15+len(related)*4)})
    priority.sort(key=lambda x:x["priority_score"],reverse=True)
    sources={}
    for a in aa:
        for source in (a.get("source") or "Unknown").split(","):
            sources[source]=sources.get(source,0)+1
    return {"scan_id":sid,"domain":s["domain"],"asset_priorities":priority,
      "source_counts":sources,"changes":ch,"finding_summary":s["summary"].get("risk",{}),
      "limitations":["Priority score is a triage heuristic, not a probability of compromise.",
      "Attribution confidence is evidence-based but does not prove legal ownership.",
      "Potential vulnerability observations require analyst validation."]}

@app.post("/api/scans/{sid}/copilot")
def copilot(sid:int,payload:dict):
    s=scan_row(sid); q=str(payload.get("question","")).strip()
    if not q: raise HTTPException(400,"Provide a question.")
    aa=assets(sid); ff=findings(sid); ch=changes(sid)
    ql=q.lower()
    if any(x in ql for x in ("new","added","change","changed")):
        answer={"summary":f"Compared with the previous completed scan, {len(ch.get('added',[]))} assets were added and {len(ch.get('removed',[]))} were removed.",
          "evidence":{"added":ch.get("added",[])[:30],"removed":ch.get("removed",[])[:30]}}
    elif any(x in ql for x in ("high","critical","priority","risk","important")):
        selected=[f for f in ff if f["severity"] in ("Critical","High")]
        answer={"summary":f"There are {len(selected)} Critical/High observations in this scan. Review these as leads; severity labels do not establish exploitability.",
          "evidence":[{"host":f["host"],"title":f["title"],"severity":f["severity"],"recommendation":f["recommendation"]} for f in selected[:30]]}
    elif any(x in ql for x in ("subdomain","hostname","asset","domain")):
        answer={"summary":f"The scan contains {sum(a['kind'] in ('domain','subdomain') for a in aa)} hostnames and {sum(a['kind']=='ip' for a in aa)} IP address records.",
          "evidence":[{"host":a["host"],"kind":a["kind"],"source":a["source"],"confidence":a["confidence"]} for a in aa[:50]]}
    elif any(x in ql for x in ("finding","observation","vulnerab")):
        answer={"summary":f"The scan contains {len(ff)} security observations. They are leads for manual review, not automatically confirmed vulnerabilities.",
          "evidence":[{"host":f["host"],"title":f["title"],"severity":f["severity"],"description":f["description"]} for f in ff[:40]]}
    else:
        answer={"summary":f"Scan #{sid} for {s['domain']} contains {len(aa)} asset records and {len(ff)} security observations. Ask about assets, findings, high-priority observations or changes for a focused evidence-backed answer.",
          "evidence":{"asset_count":len(aa),"finding_count":len(ff),"scan_status":s["status"]}}
    return {"assistant":"SCOPEZERO Analyst","mode":"local evidence-grounded assistant","question":q,
      "answer":answer,"disclaimer":"This assistant summarizes stored scan evidence only. It does not perform independent AI reasoning or verify exploitability."}

@app.get("/api/scans/{sid}/report.html")
def report_html(sid:int):
    s=scan_row(sid); aa=assets(sid); ff=findings(sid); ch=changes(sid)
    def esc(v): return html.escape(str(v if v is not None else ""))
    asset_rows="".join(f"<tr><td>{esc(a['host'])}</td><td>{esc(a['kind'])}</td><td>{esc(a['source'])}</td><td>{esc(a['ownership'])}</td><td>{a['confidence']}%</td></tr>" for a in aa)
    finding_rows="".join(f"<tr><td>{esc(f['host'])}</td><td>{esc(f['title'])}</td><td>{esc(f['severity'])}</td><td>{esc(f['description'])}</td><td>{esc(f['recommendation'])}</td></tr>" for f in ff)
    doc=f"""<!doctype html><html><head><meta charset='utf-8'><title>SCOPEZERO Report - {esc(s['domain'])}</title>
    <style>body{{font:14px Arial,sans-serif;color:#172235;margin:40px;line-height:1.5}}h1,h2{{color:#102b43}}table{{border-collapse:collapse;width:100%;margin:16px 0}}td,th{{border:1px solid #ccd5df;padding:8px;text-align:left;font-size:12px}}th{{background:#edf2f7}}.note{{background:#f1f5f9;padding:12px;border-left:4px solid #0d9488}}@media print{{body{{margin:15mm}}}}</style></head><body>
    <h1>SCOPEZERO Security Assessment Report</h1><p><b>Target:</b> {esc(s['domain'])}<br><b>Scan ID:</b> {sid}<br><b>Started:</b> {esc(s['started'])}<br><b>Status:</b> {esc(s['status'])}</p>
    <div class='note'>Authorized assessment output. Discovery is incomplete by nature. DNS/CT observations and missing security headers are not proof of ownership or exploitable vulnerabilities. Validate findings manually.</div>
    <h2>Executive summary</h2><p>Asset records: {len(aa)} · Hostnames: {sum(a['kind'] in ('domain','subdomain') for a in aa)} · IP records: {sum(a['kind']=='ip' for a in aa)} · Observations: {len(ff)}</p>
    <h2>Asset inventory</h2><table><tr><th>Asset</th><th>Type</th><th>Source</th><th>Attribution</th><th>Confidence indicator</th></tr>{asset_rows}</table>
    <h2>Security observations</h2><table><tr><th>Host</th><th>Observation</th><th>Severity</th><th>Details</th><th>Recommendation</th></tr>{finding_rows}</table>
    <h2>Asset changes</h2><p>Previous scan: {esc(ch.get('previous_scan'))}<br>Added: {len(ch.get('added',[]))}<br>Removed: {len(ch.get('removed',[]))}</p>
    <h2>Assessment limitations</h2><ul><li>Certificate Transparency and DNS discovery cannot guarantee all assets.</li><li>Attribution confidence is heuristic and does not prove ownership.</li><li>Security observations require human validation.</li><li>This release does not perform exploitation or authenticated testing.</li></ul>
    <p>Generated by SCOPEZERO {VERSION}</p></body></html>"""
    return HTMLResponse(doc,headers={"Content-Disposition":f'attachment; filename="scopezero-{sid}-report.html"'})


@app.get("/api/scans/{sid}/vulnerabilities")
def vulnerability_results(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute("SELECT * FROM vulnerability_intel WHERE scan_id=? ORDER BY kev DESC,cvss DESC",(sid,)).fetchall()
    return [dict(x) for x in rows]

@app.get("/api/scans/{sid}/digital-twin")
def digital_twin(sid:int):
    s=scan_row(sid); g=graph(sid); ch=changes(sid)
    with db() as c:
        history=c.execute("SELECT id,started,finished,status,summary FROM scans WHERE domain=? AND status='completed' AND id<=? ORDER BY id DESC LIMIT 12",(s["domain"],sid)).fetchall()
    timeline=[]
    for row in reversed(history):
        summary=json.loads(row["summary"] or "{}")
        timeline.append({"scan_id":row["id"],"started":row["started"],"finished":row["finished"],
          "asset_count":summary.get("asset_count",0),"finding_count":summary.get("finding_count",0)})
    return {"domain":s["domain"],"current_scan":sid,"graph":g,"timeline":timeline,
      "latest_delta":ch,"twin_semantics":"Snapshot-based twin updated after each completed scan."}

# SCOPEZERO 5.0 foundation: evidence, coverage, ownership, remediation and simulation APIs.
def _json_value(value, default=None):
    try: return json.loads(value) if value else default
    except (TypeError, ValueError): return default

def _audit(scan_id, event_type, entity, details):
    with db() as c:
        c.execute("INSERT INTO audit_events(scan_id,event_type,entity,details,created) VALUES(?,?,?,?,?)",
                  (scan_id,event_type,entity,json.dumps(details),stamp()))

@app.get('/api/scans/{sid}/coverage')
def coverage(sid:int):
    s=scan_row(sid); aa=assets(sid); ff=findings(sid)
    assessed=sum(1 for a in aa if a.get('dns') or a.get('tls') or a.get('evidence'))
    verified=sum(1 for a in aa if a.get('ownership') and ('Operator-supplied' in a['ownership'] or 'Confirmed' in a['ownership']))
    unverified=len(aa)-verified
    stale=0
    with db() as c:
        cases={r['host']:r['status'] for r in c.execute('SELECT host,status FROM ownership_cases WHERE scan_id=?',(sid,)).fetchall()}
        failed_sources=s.get('summary',{}).get('sources',{})
    failed=sum(1 for v in failed_sources.values() if not v.get('available') or v.get('error'))
    unassessed=len(aa)-assessed
    score=round((assessed/len(aa))*100) if aa else 0
    return {'scan_id':sid,'domain':s['domain'],'coverage_score':score,'coverage_label':'Assessment coverage, not security score',
      'total_assets':len(aa),'assessed_assets':assessed,'unassessed_assets':unassessed,'verified_assets':verified,
      'unverified_assets':unverified,'failed_sources':failed,'stale_observations':stale,
      'ownership_cases':cases,'limitations':['Coverage is calculated only from discovered assets in this scan.','A discovered asset is not proof of complete organizational inventory.','Ownership verification is not inferred from shared hosting or IP addresses.']}

@app.get('/api/scans/{sid}/evidence')
def evidence_explorer(sid:int):
    scan_row(sid); rows=[]
    for a in assets(sid):
        rows.append({'entity':a['host'],'entity_type':a['kind'],'evidence_type':'Asset discovery','source':a.get('source'),
          'observed_at':None,'evidence':a.get('evidence') or [],'confidence':a.get('confidence',0)})
        if a.get('dns'):
            rows.append({'entity':a['host'],'entity_type':a['kind'],'evidence_type':'DNS records','source':'DNS resolver',
              'observed_at':None,'evidence':a['dns'],'confidence':a.get('confidence',0)})
        if a.get('tls'):
            rows.append({'entity':a['host'],'entity_type':a['kind'],'evidence_type':'TLS metadata','source':'TLS handshake',
              'observed_at':None,'evidence':a['tls'],'confidence':a.get('confidence',0)})
    for f in findings(sid):
        rows.append({'entity':f['host'],'entity_type':'finding','evidence_type':f['title'],'source':f['category'],
          'observed_at':None,'evidence':f.get('evidence'),'confidence':None,'finding_id':f['id']})
    with db() as c:
        obs=c.execute('SELECT host,source,observed_at,evidence FROM asset_observations WHERE scan_id=? ORDER BY id',(sid,)).fetchall()
    for o in obs:
        rows.append({'entity':o['host'],'entity_type':'observation','evidence_type':'Source observation','source':o['source'],
          'observed_at':o['observed_at'],'evidence':_json_value(o['evidence'],{}),'confidence':None})
    return {'scan_id':sid,'count':len(rows),'records':rows,'semantics':'Historical evidence from this scan. It is not a live re-verification.'}

@app.get('/api/scans/{sid}/attack-paths')
def attack_paths(sid:int):
    scan_row(sid); aa=assets(sid); ff=findings(sid); gg=graph(sid)['elements']
    asset_by_host={a['host']:a for a in aa}; paths=[]
    for f in ff:
        if f['severity'] not in ('Critical','High','Medium'): continue
        a=asset_by_host.get(f['host'])
        if not a: continue
        related=[e['data'] for e in gg['edges'] if e['data']['source']==f['host'] or e['data']['target']==f['host']]
        paths.append({'classification':'Potential attack path','confidence':'Low' if not related else 'Medium',
          'risk_context':f['severity'],'steps':[{'asset':f['host'],'type':a['kind'],'evidence':a.get('evidence')},
          {'asset':f['host'],'type':'Security observation','evidence':{'title':f['title'],'description':f['description'],'finding_id':f['id']}}],
          'related_relationships':related,'missing_evidence':['Affected product and version confirmation','Independent validation of exploitability'],
          'explanation':'This is a correlation of an observed asset and a security observation, not proof of an exploitable route or compromise.'})
    return {'scan_id':sid,'count':len(paths),'paths':paths,'note':'Only evidence-backed correlations are shown. No exploit chain is asserted.'}

@app.get('/api/scans/{sid}/exposure-dna')
def exposure_dna(sid:int):
    s=scan_row(sid)
    with db() as c:
        rows=c.execute("SELECT id,started,finished,status,summary FROM scans WHERE domain=? AND status='completed' AND id<=? ORDER BY id",(s['domain'],sid)).fetchall()
    timeline=[]
    for r in rows:
        sm=_json_value(r['summary'],{})
        timeline.append({'scan_id':r['id'],'timestamp':r['finished'] or r['started'],'asset_count':sm.get('asset_count',0),
          'hostname_count':sm.get('hostname_count',0),'ip_count':sm.get('ip_count',0),'finding_count':sm.get('finding_count',0),
          'vulnerability_count':sm.get('vulnerability_enrichment_count',0)})
    return {'domain':s['domain'],'timeline':timeline,'semantics':'Exposure DNA is a historical fingerprint derived from completed scan summaries; it is not continuous monitoring.'}

@app.get('/api/scans/{sid}/remediation')
def remediation_list(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute('''SELECT f.id AS finding_id,f.host,f.title,f.severity,f.status AS finding_status,
          r.id,r.owner,r.status,r.due_date,r.notes,r.created,r.updated FROM findings f
          LEFT JOIN remediation_records r ON r.finding_id=f.id WHERE f.scan_id=? ORDER BY f.id DESC''',(sid,)).fetchall()
    out=[]
    for row in rows:
        d=dict(row)
        if not d.get('id'):
            d.update({'id':None,'owner':'','status':'Detected','due_date':None,'notes':'','created':None,'updated':None})
        out.append(d)
    return out

@app.post('/api/findings/{fid}/remediation')
def remediation_update(fid:int,payload:dict):
    allowed={'Detected','Assigned','In Progress','Fixed','Retested','Verified','Reopened'}
    status=payload.get('status','Detected')
    if status not in allowed: raise HTTPException(400,'Invalid remediation status')
    owner=str(payload.get('owner',''))[:120]; notes=str(payload.get('notes',''))[:3000]; due=payload.get('due_date')
    with db() as c:
        f=c.execute('SELECT id,scan_id FROM findings WHERE id=?',(fid,)).fetchone()
        if not f: raise HTTPException(404,'Finding not found')
        existing=c.execute('SELECT id FROM remediation_records WHERE finding_id=?',(fid,)).fetchone()
        if existing:
            c.execute('UPDATE remediation_records SET owner=?,status=?,due_date=?,notes=?,updated=? WHERE finding_id=?',(owner,status,due,notes,stamp(),fid))
        else:
            c.execute('INSERT INTO remediation_records(finding_id,scan_id,owner,status,due_date,notes,created,updated) VALUES(?,?,?,?,?,?,?,?)',
              (fid,f['scan_id'],owner,status,due,notes,stamp(),stamp()))
        c.execute('UPDATE findings SET status=? WHERE id=?',('Resolved' if status=='Verified' else 'In Progress' if status in ('Assigned','In Progress','Fixed','Retested') else 'Open',fid))
    _audit(f['scan_id'],'remediation_updated',str(fid),{'status':status,'owner':owner})
    return {'finding_id':fid,'status':status,'updated':True}

@app.get('/api/scans/{sid}/security-debt')
def security_debt(sid:int):
    s=scan_row(sid); ff=findings(sid); start=datetime.fromisoformat(s['started'].replace('Z','+00:00'))
    today=datetime.now(timezone.utc)
    open_items=[f for f in ff if f.get('status') not in ('Resolved','Accepted')]
    age=max(0,(today-start).days)
    sev={'Critical':5,'High':4,'Medium':3,'Low':2,'Info':1}
    debt=sum(sev.get(f['severity'],1)*max(1,age+1) for f in open_items)
    return {'scan_id':sid,'open_findings':len(open_items),'average_age_days':age if open_items else 0,
      'security_debt_index':debt,'overdue_findings':0,'note':'Age is measured from the scan start because individual finding creation timestamps are not yet stored. This is a provisional debt index, not a financial or industry-standard metric.'}

@app.post('/api/scans/{sid}/what-if')
def what_if(sid:int,payload:dict):
    scan_row(sid); action=payload.get('action'); host=str(payload.get('host','')).strip()
    if action not in ('remove_asset','fix_finding') or not host: raise HTTPException(400,'Provide action=remove_asset or fix_finding and a host.')
    aa=assets(sid); ff=findings(sid)
    before={'asset_count':len(aa),'finding_count':len(ff)}
    if action=='remove_asset':
        selected=[a for a in aa if a['host']==host]
        if not selected: raise HTTPException(404,'Asset not present in this scan')
        after={'asset_count':len(aa)-len(selected),'finding_count':len([f for f in ff if f['host']!=host])}
        explanation='Simulation only: estimates the inventory impact if this asset were decommissioned. Related DNS and service dependencies require human review.'
    else:
        selected=[f for f in ff if f['host']==host]
        if not selected: raise HTTPException(404,'No findings for this host in this scan')
        after={'asset_count':len(aa),'finding_count':len(ff)-len(selected)}
        explanation='Simulation only: estimates the finding-count impact if all current observations for this host were verified as fixed. No live retest was performed.'
    return {'simulation_only':True,'action':action,'target':host,'before':before,'hypothetical_after':after,
      'estimated_finding_reduction':before['finding_count']-after['finding_count'],'explanation':explanation}

@app.post('/api/scans/{sid}/ownership')
def ownership_update(sid:int,payload:dict):
    scan_row(sid); host=str(payload.get('host','')).strip(); status=payload.get('status','Under investigation')
    allowed={'Under investigation','Confirmed','Rejected'}
    if not host or status not in allowed: raise HTTPException(400,'Provide an asset host and a valid ownership status.')
    if not any(a['host']==host for a in assets(sid)): raise HTTPException(404,'Asset not present in this scan')
    notes=str(payload.get('notes',''))[:3000]
    with db() as c:
        c.execute('''INSERT INTO ownership_cases(scan_id,host,status,notes,updated) VALUES(?,?,?,?,?)
          ON CONFLICT(scan_id,host) DO UPDATE SET status=excluded.status,notes=excluded.notes,updated=excluded.updated''',
          (sid,host,status,notes,stamp()))
    _audit(sid,'ownership_updated',host,{'status':status})
    return {'scan_id':sid,'host':host,'status':status,'updated':True}

@app.get('/api/scans/{sid}/ownership')
def ownership_list(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute('SELECT * FROM ownership_cases WHERE scan_id=? ORDER BY updated DESC',(sid,)).fetchall()
    return [dict(r) for r in rows]

@app.get('/api/scans/{sid}/audit-events')
def audit_events(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute('SELECT * FROM audit_events WHERE scan_id=? ORDER BY id DESC LIMIT 200',(sid,)).fetchall()
    return [{**dict(r),'details':_json_value(r['details'],{})} for r in rows]

# SCOPEZERO 6.0: bounded web-surface discovery and evidence-backed intelligence modules.
@app.get("/api/scans/{sid}/surface")
def surface_inventory(sid:int, category:str|None=None):
    scan_row(sid)
    with db() as c:
        if category:
            rows=c.execute("SELECT * FROM surface_observations WHERE scan_id=? AND category=? ORDER BY host,target",(sid,category)).fetchall()
        else:
            rows=c.execute("SELECT * FROM surface_observations WHERE scan_id=? ORDER BY category,host,target",(sid,)).fetchall()
    out=[]
    for r in rows:
        d=dict(r)
        try:d['evidence']=json.loads(d['evidence'])
        except Exception:d['evidence']={}
        out.append(d)
    return {"scan_id":sid,"count":len(out),"observations":out,"semantics":"Only bounded, non-destructive HTTP GET and DNS observations are stored. A discovered path is not proof of a vulnerability."}

@app.get("/api/scans/{sid}/choke-points")
def choke_points(sid:int):
    scan_row(sid)
    with db() as c:
        edges=c.execute("SELECT source,target,relation,evidence FROM edges WHERE scan_id=?",(sid,)).fetchall()
        assets=c.execute("SELECT host,kind,confidence,source FROM assets WHERE scan_id=?",(sid,)).fetchall()
    degree={}
    rels={}
    for e in edges:
        for node in (e['source'],e['target']):
            degree[node]=degree.get(node,0)+1
            rels.setdefault(node,[]).append({"related":e['target'] if node==e['source'] else e['source'],"relation":e['relation'],"evidence":e['evidence']})
    amap={a['host']:dict(a) for a in assets}
    ranked=[]
    for host,count in degree.items():
        a=amap.get(host,{"kind":"external-reference","confidence":0,"source":"Relationship reference"})
        ranked.append({"asset":host,"kind":a['kind'],"degree":count,"choke_point_score":min(100,round(count/max(1,len(edges))*100*3)),
                       "confidence":a['confidence'],"source":a['source'],"relationships":rels[host],
                       "explanation":f"This node participates in {count} observed relationship(s). Degree is a prioritization hint, not proof of exploitability or business criticality."})
    return {"scan_id":sid,"count":len(ranked),"choke_points":sorted(ranked,key=lambda x:(x['degree'],x['confidence']),reverse=True)[:30],
            "method":"Observed graph degree centrality; no inferred exploit paths are treated as confirmed."}

@app.get("/api/scans/{sid}/evidence-quality")
def evidence_quality(sid:int):
    scan_row(sid); aa=assets(sid)
    with db() as c:
        obs=c.execute("SELECT host,category,target,status,source,confidence,evidence,observed_at FROM surface_observations WHERE scan_id=?",(sid,)).fetchall()
        provenance=c.execute("SELECT host,source,observed_at,evidence FROM asset_observations WHERE scan_id=?",(sid,)).fetchall()
    records=[]
    for a in aa:
        score=0; factors=[]
        if a.get('source'): score+=20; factors.append('Discovery source recorded')
        if a.get('dns'): score+=25; factors.append('DNS evidence recorded')
        if a.get('tls'): score+=20; factors.append('TLS observation recorded')
        if a.get('evidence'): score+=20; factors.append('Attribution evidence recorded')
        src_count=len({x['source'] for x in provenance if x['host']==a['host']})
        if src_count>1: score+=15; factors.append('Multiple provenance sources')
        score=min(100,score)
        label='Strong' if score>=80 else 'Good' if score>=60 else 'Limited' if score>=35 else 'Weak'
        records.append({"entity":a['host'],"quality_score":score,"quality":label,"factors":factors,"source_count":src_count,
                        "limitations":"Evidence quality measures record completeness and provenance, not correctness or legal ownership."})
    for o in obs:
        try: ev=json.loads(o['evidence'])
        except Exception: ev={}
        score=int(o['confidence'] or 0); label='Strong' if score>=85 else 'Good' if score>=65 else 'Limited' if score>=40 else 'Weak'
        records.append({"entity":o['host']+o['target'],"quality_score":score,"quality":label,"factors":["Observation source: "+o['source'],"HTTP/DNS status: "+str(o['status'])],"evidence":ev,"limitations":"A positive HTTP response identifies an observed resource, not a vulnerability."})
    return {"scan_id":sid,"count":len(records),"records":records,"method":"Deterministic evidence completeness and provenance rubric; not a probabilistic truth score."}

@app.get("/api/scans/{sid}/api-inventory")
def api_inventory(sid:int):
    x=surface_inventory(sid,"api-endpoint")
    return {"scan_id":sid,"count":x['count'],"endpoints":x['observations'],"limitations":"Only public documentation and a small set of conventional API paths are checked. No authenticated API testing or schema fuzzing is performed."}

@app.get("/api/scans/{sid}/directories")
def directory_inventory(sid:int):
    x=surface_inventory(sid,"directory")
    return {"scan_id":sid,"count":x['count'],"paths":x['observations'],"limitations":"Bounded candidate list; no recursion, brute-force expansion, authentication bypass or exploit payloads."}

@app.get("/api/scans/{sid}/email-posture")
def email_posture_result(sid:int):
    s=scan_row(sid)
    with db() as c:
        r=c.execute("SELECT evidence FROM surface_observations WHERE scan_id=? AND category='email-posture' ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    if not r:return {"scan_id":sid,"domain":s['domain'],"available":False,"message":"Email posture observation was not recorded for this scan."}
    try:data=json.loads(r['evidence'])
    except Exception:data={}
    return {"scan_id":sid,"available":True,**data}

@app.get("/api/scans/{sid}/cloud-intelligence")
def cloud_intelligence(sid:int):
    x=surface_inventory(sid,"cloud-indicator")
    return {"scan_id":sid,"count":x['count'],"indicators":x['observations'],"limitations":"Provider CNAME signals do not prove account ownership, public storage exposure or cloud misconfiguration. No cloud resource is probed."}

# SCOPEZERO 7.0: controlled offensive-assessment adapters and evidence workflows.
from pathlib import Path
import base64, mimetypes
from fastapi import UploadFile, File, Form
from fastapi.responses import Response
from .engines.offensive import nmap_scan, nuclei_scan, katana_crawl, scan_secrets, subfinder_scan, gobuster_scan, api_endpoint_probe
from .engines.recon import amass_passive, dnsx_records, cloud_dns_enum, crt_hosts, securitytrails_domain, github_recon, shodan_ips, censys_ips, reverse_whois, google_dorks

class ToolRunIn(BaseModel):
    authorized: bool

class SecretScanIn(BaseModel):
    repository_path: str
    authorized: bool

class ReverseWhoisIn(BaseModel):
    identifier_type: str
    identifier: str = Field(min_length=2,max_length=180)
    authorized: bool

class EvidenceIn(BaseModel):
    title: str = Field(min_length=2,max_length=180)
    evidence_type: str = Field(default="Analyst note",max_length=50)
    notes: str = Field(default="",max_length=10000)
    finding_id: int|None = None
    request_text: str|None = Field(default=None,max_length=20000)
    response_text: str|None = Field(default=None,max_length=30000)
    attachment_name: str|None = Field(default=None,max_length=120)
    attachment_base64: str|None = None

class ValidationIn(BaseModel):
    finding_id: int|None = None
    verdict: str
    rationale: str = Field(min_length=5,max_length=5000)
    validated_by: str = Field(default="",max_length=100)


def _store_offensive(sid, module, results):
    status=results.get("status")
    if status in ("failed","timeout","execution_error","permission_error","network_error","preflight_incomplete","partial_results","parse_warning","not_installed","not_configured","no_targets","no_matches","invalid_scope","invalid_input","ready"):
        stored_status=status
    elif results.get("error") or results.get("tool_error") or results.get("returncode") not in (0,None):
        stored_status="failed"
    else:
        stored_status="completed"
    items=results.get("results",results.get("urls",results.get("findings",results.get("hosts",results.get("endpoints",results.get("records",[]))))))
    results.setdefault("result_count",len(items) if isinstance(items,list) else 0)
    with db() as c:
        cur=c.execute("INSERT INTO offensive_runs(scan_id,module,status,results,created) VALUES(?,?,?,?,?)",
          (sid,module,stored_status,json.dumps(results),stamp()))
        rid=cur.lastrowid
    _audit(sid,"offensive_module_run",module,{"run_id":rid,"result_count":results["result_count"],"status":stored_status})
    return {"run_id":rid,"scan_id":sid,"module":module,"stored_status":stored_status,**results}


def _eligible_hosts(sid):
    scan=scan_row(sid)
    with db() as c:
        rows=c.execute("SELECT host,kind FROM assets WHERE scan_id=? AND kind IN ('domain','subdomain') ORDER BY host",(sid,)).fetchall()
        engagement=c.execute("SELECT * FROM engagements WHERE id=?",(scan.get("engagement_id"),)).fetchone() if scan.get("engagement_id") else None
    exclusions=[]
    if engagement:
        if not engagement["authorized"]: raise HTTPException(403,"Engagement authorization is inactive.")
        if engagement["expires"]:
            try:
                exp=datetime.fromisoformat(engagement["expires"].replace('Z','+00:00'))
                if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
                if exp <= datetime.now(timezone.utc): raise HTTPException(403,"Engagement authorization has expired.")
            except ValueError: raise HTTPException(403,"Engagement expiry is invalid; update the engagement scope.")
        try: exclusions=json.loads(engagement["exclusions_json"] or '[]')
        except Exception: exclusions=[]
    hosts=[]
    for row in rows:
        h=row["host"].lower().rstrip(".")
        if (h==scan["domain"] or h.endswith("."+scan["domain"])) and not any(h==x or h.endswith('.'+x) for x in exclusions): hosts.append(h)
    if not engagement: raise HTTPException(403,"Active engagement authorization is required for tool execution.")
    return scan,sorted(set(hosts))

def _run_managed_tool(job_id, sid, tool, hosts, domain):
    with db() as c: c.execute("UPDATE tool_jobs SET status='running',progress=5,stage='Starting adapter',started=? WHERE id=?",(stamp(),job_id))
    try:
        if tool=="findomain": result=findomain_adapter(domain)
        elif tool=="naabu": result=naabu_adapter(hosts)
        elif tool=="httpx": result=httpx_adapter(hosts)
        elif tool=="feroxbuster": result=feroxbuster_adapter(hosts)
        else: raise ValueError("Unsupported adapter")
        # Every output is checked again against the engagement's current allowlist before persistence.
        scan,current_hosts=_eligible_hosts(sid); allowed=set(current_hosts); root=scan["domain"]
        with db() as c:
            er=c.execute("SELECT exclusions_json FROM engagements WHERE id=?",(scan["engagement_id"],)).fetchone()
            try: excluded=json.loads(er["exclusions_json"] or '[]') if er else []
            except Exception: excluded=[]
            def target_allowed(h):
                h=str(h).lower().rstrip('.')
                return (h==root or h.endswith('.'+root)) and not any(h==x or h.endswith('.'+x) for x in excluded)
            for host in result.get("hosts",[]):
                h=str(host).lower().rstrip('.')
                if target_allowed(h):
                    c.execute("INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls) VALUES(?,?,?,?,?,?,?,?,?)",
                              (sid,h,"subdomain",tool,"{}","Candidate — verify",65,json.dumps([f"{tool} passive discovery candidate"]),"{}"))
                    c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",(sid,root,h,"contains",f"Discovered by {tool}"))
                    c.execute("INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json) VALUES(?,?,?,?,?,?,?,?,?)",(sid,job_id,h,"hostname","contains",tool,stamp(),65,json.dumps({"status":"candidate"})))
            for item in result.get("results",[]):
                host=str(item.get("host") or item.get("ip") or "").lower().rstrip('.')
                if not host: continue
                # Naabu/httpx/ferox results must resolve to a discovered in-scope host.
                if host not in allowed and not target_allowed(host): continue
                if tool=="naabu":
                    port=int(item.get("port",0))
                    if not 1<=port<=65535: continue
                    entity=f"{host}:{port}/tcp"
                    c.execute("INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls) VALUES(?,?,?,?,?,?,?,?,?)",(sid,entity,"port",tool,"{}","In-scope observation",85,json.dumps(item),"{}"))
                    c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",(sid,host,entity,"exposes_port",f"TCP port observed by {tool}"))
                    service=str(item.get("service") or "unknown").lower()
                    if service!="unknown":
                        service_entity=f"service:{service}"
                        c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",(sid,entity,service_entity,"identified_as",f"Common-port service hint from TCP/{port}; banner validation not performed"))
                        c.execute("INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json) VALUES(?,?,?,?,?,?,?,?,?)",(sid,job_id,service_entity,"service","identified_as",tool,stamp(),55,json.dumps({"port":port,"banner_validated":False})))
                    etype="port"
                elif tool=="httpx":
                    entity=item.get("url") or host; etype="http_service"
                    c.execute("INSERT OR IGNORE INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",(sid,host,entity,"serves_http",f"HTTP metadata observed by {tool}"))
                else:
                    entity=item.get("url") or item.get("path") or host; etype="web_path"
                c.execute("INSERT INTO normalized_observations(scan_id,job_id,entity,entity_type,relation,source_tool,observed_at,confidence,data_json) VALUES(?,?,?,?,?,?,?,?,?)",(sid,job_id,entity,etype,"observed_on",tool,stamp(),80,json.dumps(item)))
            c.execute("UPDATE tool_jobs SET status=?,progress=100,stage='Completed',result_json=?,finished=? WHERE id=?",(result.get("status","completed"),json.dumps(result),stamp(),job_id))
            c.execute("INSERT INTO offensive_runs(scan_id,module,status,results,created) VALUES(?,?,?,?,?)",(sid,tool,result.get("status","completed"),json.dumps(result),stamp()))
        _audit(sid,"managed_tool_completed",tool,{"job_id":job_id,"result_count":result.get("result_count",len(result.get("results",result.get("hosts",[]))))})
    except Exception as exc:
        with db() as c: c.execute("UPDATE tool_jobs SET status='failed',stage='Failed',error=?,finished=? WHERE id=?",(f"{type(exc).__name__}: {str(exc)[:500]}",stamp(),job_id))

@app.post("/api/scans/{sid}/jobs/{tool}")
def queue_tool_job(sid:int, tool:str, payload:ToolRunIn):
    if tool not in ("findomain","naabu","httpx","feroxbuster"): raise HTTPException(404,"Unknown managed adapter")
    if not payload.authorized: raise HTTPException(400,"Confirm written authorization before active assessment.")
    scan,hosts=_eligible_hosts(sid)
    if not hosts: raise HTTPException(400,"No eligible in-scope discovered hostnames are available.")
    with db() as c:
        cur=c.execute("INSERT INTO tool_jobs(scan_id,engagement_id,tool,status,created) VALUES(?,?,?,?,?)",(sid,scan.get("engagement_id"),tool,"queued",stamp()))
        jid=cur.lastrowid
    _TOOL_POOL.submit(_run_managed_tool,jid,sid,tool,hosts,scan["domain"])
    return {"job_id":jid,"scan_id":sid,"tool":tool,"status":"queued","poll":"GET /api/scans/%s/jobs/%s"%(sid,jid)}

@app.get("/api/scans/{sid}/jobs")
def list_tool_jobs(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT id,tool,status,progress,stage,error,created,started,finished FROM tool_jobs WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
    return [dict(x) for x in rows]

@app.get("/api/scans/{sid}/jobs/{job_id}")
def get_tool_job(sid:int,job_id:int):
    scan_row(sid)
    with db() as c: row=c.execute("SELECT * FROM tool_jobs WHERE scan_id=? AND id=?",(sid,job_id)).fetchone()
    if not row: raise HTTPException(404,"Job not found")
    out=dict(row); out["result"]=json.loads(out.pop("result_json") or "null")
    return out

@app.get("/api/scans/{sid}/normalized-results")
def normalized_results(sid:int, entity_type:str|None=None):
    scan_row(sid)
    with db() as c:
        if entity_type: rows=c.execute("SELECT * FROM normalized_observations WHERE scan_id=? AND entity_type=? ORDER BY id",(sid,entity_type)).fetchall()
        else: rows=c.execute("SELECT * FROM normalized_observations WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    return [{**dict(r),"data":json.loads(r["data_json"])} for r in rows]

@app.get("/api/scans/{sid}/offensive-tools")
def offensive_tool_status(sid:int):
    scan_row(sid)
    return {"scan_id":sid,"tools":{n:{"installed":shutil.which(n) is not None,"path":shutil.which(n)} for n in ("nmap","nuclei","katana","subfinder","gobuster","amass","dnsx","gitleaks",
        "findomain","shuffledns","massdns","naabu","httpx","hakrawler","feroxbuster",
        "testssl.sh","sslscan","trufflehog","zap-cli")},
      "providers":{"securitytrails":bool(os.getenv("SECURITYTRAILS_API_KEY")),"github":bool(os.getenv("GITHUB_TOKEN")),"shodan":bool(os.getenv("SHODAN_API_KEY")),"censys":bool(os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET")),"whoxy":bool(os.getenv("WHOOXY_API_KEY"))},
      "managed_adapters":["findomain","naabu","httpx","feroxbuster"],"note":"Findomain, Naabu, httpx and Feroxbuster have bounded background adapters; other entries are inventory-only unless their dedicated endpoint exists."}

@app.post("/api/scans/{sid}/nmap")
def run_nmap(sid:int, payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm written authorization before active service discovery.")
    _,hosts=_eligible_hosts(sid)
    result=nmap_scan(hosts)
    return _store_offensive(sid,"nmap",result)

@app.post("/api/scans/{sid}/nuclei")
def run_nuclei(sid:int, payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm written authorization before template checks.")
    _,hosts=_eligible_hosts(sid)
    result=nuclei_scan(hosts)
    return _store_offensive(sid,"nuclei",result)

@app.post("/api/scans/{sid}/katana")
def run_katana(sid:int, payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm written authorization before crawling.")
    _,hosts=_eligible_hosts(sid)
    result=katana_crawl(hosts)
    return _store_offensive(sid,"katana",result)

@app.post("/api/scans/{sid}/subfinder")
def run_subfinder(sid:int, payload:ToolRunIn):
    if not payload.authorized:
        raise HTTPException(400,"Confirm written authorization before passive subdomain enumeration.")
    scan,_=_eligible_hosts(sid)
    result=subfinder_scan(scan["domain"])
    added=0
    if result.get("available") and result.get("hosts"):
        with db() as c:
            for host in result["hosts"]:
                if host!=scan["domain"] and host.endswith("."+scan["domain"]):
                    cur=c.execute("""INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls)
                      VALUES(?,?,?,?,?,?,?,?,?)""",(sid,host,"subdomain","Subfinder (passive)","{}",
                      "Candidate — verify",60,json.dumps(["Passive Subfinder discovery; resolve and verify organizational ownership."]),"{}"))
                    if cur.rowcount:
                        added+=1
                        c.execute("INSERT INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                                  (sid,scan["domain"],host,"contains","Passive Subfinder candidate within the authorized root domain."))
                        c.execute("INSERT INTO asset_observations(scan_id,host,source,observed_at,evidence) VALUES(?,?,?,?,?)",
                                  (sid,host,"Subfinder (passive)",stamp(),json.dumps({"status":"candidate"})))
            counts=c.execute("SELECT kind,COUNT(*) AS n FROM assets WHERE scan_id=? GROUP BY kind",(sid,)).fetchall()
            by_kind={r["kind"]:r["n"] for r in counts}
            summary=scan_row(sid)["summary"]
            summary["asset_count"]=sum(by_kind.values())
            summary["hostname_count"]=by_kind.get("domain",0)+by_kind.get("subdomain",0)
            summary["ip_count"]=sum(v for k,v in by_kind.items() if k in ("ip","ipv4","ipv6","ip-address"))
            c.execute("UPDATE scans SET summary=? WHERE id=?",(json.dumps(summary),sid))
    result["assets_added_to_inventory"]=added
    return _store_offensive(sid,"subfinder",result)

@app.post("/api/scans/{sid}/gobuster")
def run_gobuster(sid:int, payload:ToolRunIn):
    if not payload.authorized:
        raise HTTPException(400,"Confirm written authorization before bounded directory discovery.")
    _,hosts=_eligible_hosts(sid)
    result=gobuster_scan(hosts,max_hosts=6,timeout=150)
    observations=result.get("results",[])
    if observations:
        with db() as c:
            for item in observations:
                c.execute("""INSERT INTO surface_observations(scan_id,host,category,target,status,source,confidence,evidence,observed_at)
                  VALUES(?,?,?,?,?,?,?,?,?)""",(sid,item["host"],"directory",item["path"],item.get("status"),
                  "Gobuster",90 if item.get("status") in (200,204) else 70,json.dumps(item),stamp()))
    return _store_offensive(sid,"gobuster",result)

@app.post("/api/scans/{sid}/api-probe")
def run_api_probe(sid:int, payload:ToolRunIn):
    if not payload.authorized:
        raise HTTPException(400,"Confirm written authorization before API endpoint discovery.")
    _,hosts=_eligible_hosts(sid)
    result=api_endpoint_probe(hosts,max_hosts=8,timeout=4)
    endpoints=result.get("endpoints",[])
    if endpoints:
        with db() as c:
            for item in endpoints:
                c.execute("""INSERT INTO surface_observations(scan_id,host,category,target,status,source,confidence,evidence,observed_at)
                  VALUES(?,?,?,?,?,?,?,?,?)""",(sid,item["host"],"api-endpoint",item["path"],item["status"],
                  "SCOPEZERO API probe",item.get("confidence",70),json.dumps(item),stamp()))
    return _store_offensive(sid,"api-probe",result)

def _store_recon_hosts(sid, scan, hosts, source):
    added=0
    with db() as c:
        for host in hosts:
            if host==scan["domain"] or not host.endswith("."+scan["domain"]): continue
            cur=c.execute("""INSERT OR IGNORE INTO assets(scan_id,host,kind,source,dns,ownership,confidence,evidence,tls)
              VALUES(?,?,?,?,?,?,?,?,?)""",(sid,host,"subdomain",source,"{}","Candidate — verify",65,
              json.dumps([f"Discovered by {source}; verify DNS and organizational ownership."]),"{}"))
            if cur.rowcount:
                added+=1
                c.execute("INSERT INTO edges(scan_id,source,target,relation,evidence) VALUES(?,?,?,?,?)",
                          (sid,scan["domain"],host,"contains",f"Candidate discovered by {source}."))
                c.execute("INSERT INTO asset_observations(scan_id,host,source,observed_at,evidence) VALUES(?,?,?,?,?)",
                          (sid,host,source,stamp(),json.dumps({"status":"candidate"})))
    return added

def _scan_ips(sid):
    with db() as c:
        rows=c.execute("SELECT host FROM assets WHERE scan_id=? AND kind IN ('ip','ipv4','ipv6','ip-address')",(sid,)).fetchall()
    out=[]
    for row in rows:
        try:
            ip=ipaddress.ip_address(row["host"])
            if ip.is_global: out.append(str(ip))
        except Exception: pass
    return sorted(set(out))

@app.post("/api/scans/{sid}/amass")
def run_amass(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before Amass enumeration.")
    scan,_=_eligible_hosts(sid); result=amass_passive(scan["domain"])
    result["assets_added_to_inventory"]=_store_recon_hosts(sid,scan,result.get("hosts",[]),"Amass passive")
    return _store_offensive(sid,"amass",result)

@app.post("/api/scans/{sid}/dnsx")
def run_dnsx(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before DNS record resolution.")
    scan,hosts=_eligible_hosts(sid); result=dnsx_records(hosts,scan["domain"])
    if result.get("records"):
        with db() as c:
            for rec in result["records"]:
                c.execute("INSERT INTO surface_observations(scan_id,host,category,target,status,source,confidence,evidence,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (sid,rec["host"],"dns-record",rec.get("response","DNS response"),None,"dnsx",85,json.dumps(rec),stamp()))
    return _store_offensive(sid,"dnsx",result)

@app.post("/api/scans/{sid}/cloud-enum")
def run_cloud_enum(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before cloud DNS enumeration.")
    scan,hosts=_eligible_hosts(sid); result=cloud_dns_enum(scan["domain"],hosts)
    if result.get("results"):
        with db() as c:
            for item in result["results"]:
                c.execute("INSERT INTO surface_observations(scan_id,host,category,target,status,source,confidence,evidence,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (sid,item["host"],"cloud-indicator",item.get("cname") or ",".join(item.get("addresses",[])),None,"Cloud DNS enumeration",65,json.dumps(item),stamp()))
    return _store_offensive(sid,"cloud-enum",result)

@app.post("/api/scans/{sid}/crt")
def run_crt(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before CT log discovery.")
    scan,_=_eligible_hosts(sid); result=crt_hosts(scan["domain"])
    result["assets_added_to_inventory"]=_store_recon_hosts(sid,scan,result.get("hosts",[]),"crt.sh Certificate Transparency")
    return _store_offensive(sid,"crt",result)

@app.post("/api/scans/{sid}/securitytrails")
def run_securitytrails(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before third-party domain intelligence lookup.")
    scan,_=_eligible_hosts(sid); result=securitytrails_domain(scan["domain"])
    result["assets_added_to_inventory"]=_store_recon_hosts(sid,scan,result.get("hosts",[]),"SecurityTrails")
    return _store_offensive(sid,"securitytrails",result)

@app.post("/api/scans/{sid}/github-recon")
def run_github_recon(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before public GitHub code search.")
    scan,_=_eligible_hosts(sid); return _store_offensive(sid,"github-recon",github_recon(scan["domain"]))

@app.post("/api/scans/{sid}/shodan")
def run_shodan(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before Shodan intelligence lookups.")
    return _store_offensive(sid,"shodan",shodan_ips(_scan_ips(sid)))

@app.post("/api/scans/{sid}/censys")
def run_censys(sid:int,payload:ToolRunIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before Censys intelligence lookups.")
    return _store_offensive(sid,"censys",censys_ips(_scan_ips(sid)))

@app.post("/api/scans/{sid}/reverse-whois")
def run_reverse_whois(sid:int,payload:ReverseWhoisIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization before reverse-WHOIS lookup.")
    scan_row(sid); return _store_offensive(sid,"reverse-whois",reverse_whois(payload.identifier_type,payload.identifier.strip()))

@app.get("/api/scans/{sid}/google-dorks")
def get_google_dorks(sid:int):
    scan=scan_row(sid); return {"scan_id":sid,**google_dorks(scan["domain"])}

@app.post("/api/scans/{sid}/secrets")
def run_secrets(sid:int, payload:SecretScanIn):
    if not payload.authorized: raise HTTPException(400,"Confirm authorization to inspect this repository.")
    result=scan_secrets(payload.repository_path)
    if result.get("error"): raise HTTPException(400,result["error"])
    return _store_offensive(sid,"secrets",result)

@app.get("/api/scans/{sid}/offensive-runs")
def offensive_runs(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT * FROM offensive_runs WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
    return [{**dict(r),"results":_json_value(r["results"],{})} for r in rows]


@app.get("/api/scans/{sid}/network-inventory")
def network_inventory(sid:int):
    """Consolidated inventory of discovered hostnames, IPs and observed Nmap services."""
    scan=scan_row(sid)
    aa=assets(sid)
    hostnames=[]; ips=[]
    for a in aa:
        kind=(a.get("kind") or "").lower()
        item={"host":a.get("host"),"source":a.get("source"),"confidence":a.get("confidence"),
              "ownership":a.get("ownership"),"dns":a.get("dns") or {},"evidence":a.get("evidence") or []}
        if kind in ("domain","subdomain"):
            item["kind"]=kind
            hostnames.append(item)
        elif kind in ("ip","ip-address","ipv4","ipv6"):
            ips.append(item)
    services=[]; nmap_runs=[]
    with db() as c:
        rows=c.execute("SELECT id,status,results,created FROM offensive_runs WHERE scan_id=? AND module='nmap' ORDER BY id DESC",(sid,)).fetchall()
    for r in rows:
        result=_json_value(r["results"],{})
        nmap_runs.append({"run_id":r["id"],"status":r["status"],"created":r["created"],"available":result.get("available",False),"message":result.get("message"),"tool_error":result.get("tool_error")})
        for svc in result.get("results",[]):
            services.append({**svc,"run_id":r["id"],"observed_at":r["created"],"source":"Nmap"})
    # Include IP literals referenced by Nmap even if the original discovery did not create an IP asset row.
    known={x["host"] for x in ips}
    for svc in services:
        host=svc.get("host")
        if host and host not in known:
            try:
                import ipaddress
                ipaddress.ip_address(host)
                ips.append({"host":host,"source":"Nmap observation","confidence":100,"ownership":"Unverified","dns":{},"evidence":["Observed in Nmap output"]}); known.add(host)
            except ValueError: pass
    return {"scan_id":sid,"domain":scan["domain"],"subdomains":hostnames,"ips":ips,"services":services,
            "counts":{"subdomains":len(hostnames),"ips":len(ips),"services":len(services),"open_services":sum(1 for x in services if x.get("state")=="open")},
            "nmap_runs":nmap_runs,"nmap_status":"completed" if nmap_runs and services else ("no-results" if nmap_runs else "not-run"),
            "note":"Ports and services appear only after an authorized Nmap assessment. Discovered IPs are not automatically port-scanned."}


@app.get("/api/scans/{sid}/assets/{asset_host:path}/intelligence")
def asset_intelligence(sid:int, asset_host:str):
    """Evidence-backed detail view for one hostname or IP within a scan."""
    scan=scan_row(sid)
    host=asset_host.strip().lower()
    aa=assets(sid)
    asset=next((a for a in aa if (a.get("host") or "").lower()==host),None)
    if not asset:
        raise HTTPException(404,"Asset was not found in this scan.")
    with db() as c:
        edge_rows=c.execute(
            "SELECT source,target,relation,evidence FROM edges WHERE scan_id=? AND (lower(source)=? OR lower(target)=?)",
            (sid,host,host)).fetchall()
        finding_rows=c.execute(
            "SELECT * FROM findings WHERE scan_id=? AND lower(host)=? ORDER BY score DESC,id DESC",
            (sid,host)).fetchall()
        vuln_rows=c.execute(
            "SELECT * FROM vulnerability_intel WHERE scan_id=? AND lower(host)=? ORDER BY COALESCE(cvss,0) DESC",
            (sid,host)).fetchall()
        obs_rows=c.execute(
            "SELECT category,target,status,source,confidence,evidence,observed_at FROM surface_observations WHERE scan_id=? AND lower(host)=? ORDER BY id DESC",
            (sid,host)).fetchall()
        run_rows=c.execute(
            "SELECT id,module,status,results,created FROM offensive_runs WHERE scan_id=? ORDER BY id DESC",
            (sid,)).fetchall()
        previous=c.execute(
            "SELECT id,started,status FROM scans WHERE domain=? AND id<? AND status='completed' ORDER BY id DESC LIMIT 5",
            (scan["domain"],sid)).fetchall()
        evidence_rows=[]
        for f in finding_rows:
            evidence_rows.extend([dict(x) for x in c.execute(
                "SELECT id,finding_id,title,evidence_type,notes,request_text,response_text,attachment_path,created FROM pentest_evidence WHERE scan_id=? AND finding_id=? ORDER BY id DESC",
                (sid,f["id"])).fetchall()])
    services=[]
    technologies=[]
    for run in run_rows:
        result=_json_value(run["results"],{})
        if run["module"]=="nmap":
            for item in result.get("results",[]):
                if (item.get("host") or "").lower()==host:
                    services.append({**item,"run_id":run["id"],"observed_at":run["created"],"status":run["status"]})
        if run["module"] in ("katana","nuclei"):
            pass
    for row in obs_rows:
        item=dict(row)
        if (item.get("category") or "").lower() in ("technology","fingerprint","tech"):
            technologies.append(item)
    history=[]
    with db() as c:
        for p in previous:
            old=c.execute("SELECT kind,source,dns,tls,confidence FROM assets WHERE scan_id=? AND lower(host)=? LIMIT 1",(p["id"],host)).fetchone()
            if old:
                history.append({"scan_id":p["id"],"started":p["started"],"status":p["status"],"observation":dict(old)})
    relationships=[dict(x) for x in edge_rows]
    findings_out=[]
    for row in finding_rows:
        d=dict(row)
        for key in ("evidence",):
            d[key]=_json_value(d.get(key),[])
        findings_out.append(d)
    vulns=[dict(x) for x in vuln_rows]
    return {
        "scan_id":sid,"domain":scan["domain"],"asset":asset,
        "dns":asset.get("dns") or {},"tls":asset.get("tls") or {},
        "ports_services":services,"technologies":technologies,
        "findings":findings_out,"vulnerabilities":vulns,
        "relationships":relationships,"historical_observations":history,
        "evidence_records":evidence_rows,
        "observations":[{**dict(x),"evidence":_json_value(x["evidence"],{})} for x in obs_rows],
        "summary":{"services":len(services),"findings":len(findings_out),"vulnerabilities":len(vulns),
                   "relationships":len(relationships),"evidence_records":len(evidence_rows)},
        "limitations":["Only evidence stored for this scan is shown.","Missing ports, technologies or vulnerabilities mean not observed, not necessarily absent.",
                       "Historical entries are prior scan snapshots and are not current verification."]
    }


# ---- SCOPEZERO 8.0 intelligence APIs ---------------------------------------
def _safe_json(v, default):
    try:
        if isinstance(v,(dict,list)): return v
        return json.loads(v) if v else default
    except Exception: return default

def _ip_in_scan(sid, ip):
    for a in assets(sid):
        if a.get("host")==ip: return True
        dns=_safe_json(a.get("dns"),{})
        for vals in dns.values() if isinstance(dns,dict) else []:
            if isinstance(vals,list) and ip in [str(x) for x in vals]: return True
            if isinstance(vals,str) and vals==ip: return True
    return False

@app.get("/api/scans/{sid}/ip-intelligence/{ip}")
def ip_intelligence(sid:int, ip:str):
    scan_row(sid)
    try: parsed=ipaddress.ip_address(ip)
    except ValueError: raise HTTPException(400,"A valid IP address is required.")
    if not parsed.is_global: raise HTTPException(400,"Only public IP addresses can be enriched.")
    if not _ip_in_scan(sid,str(parsed)): raise HTTPException(404,"IP is not present in this scan's discovered inventory.")
    reverse=[]
    try: reverse=socket.gethostbyaddr(str(parsed))[0:2]
    except Exception: pass
    related=[]; certs=[]; services=[]; history=[]
    for a in assets(sid):
        dns=_safe_json(a.get("dns"),{})
        if a["host"]==str(parsed) or any(str(parsed) in (v if isinstance(v,list) else [v]) for v in dns.values()):
            related.append({"host":a["host"],"kind":a["kind"],"source":a.get("source"),"confidence":a.get("confidence")})
    related_hosts={x["host"] for x in related}
    for a in assets(sid):
        tls=_safe_json(a.get("tls"),{})
        if tls and a["host"] in related_hosts:
            certs.append({"host":a["host"],"tls":tls})
    with db() as c:
        runs=c.execute("SELECT module,status,results,created FROM offensive_runs WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
        prev=c.execute("SELECT id,started FROM scans WHERE domain=? AND id<=? AND status='completed' ORDER BY id DESC LIMIT 20",(scan_row(sid)["domain"],sid)).fetchall()
        for p in prev:
            for a in c.execute("SELECT host,dns,tls FROM assets WHERE scan_id=?",(p["id"],)):
                dns=_safe_json(a["dns"],{})
                if a["host"]==str(parsed) or any(str(parsed) in (v if isinstance(v,list) else [v]) for v in dns.values()):
                    history.append({"scan_id":p["id"],"started":p["started"],"host":a["host"],"dns":dns})
    for run in runs:
        if run["module"]=="nmap":
            result=_safe_json(run["results"],{})
            for item in result.get("results",[]):
                if item.get("host")==str(parsed): services.append({**item,"observed_at":run["created"],"run_status":run["status"]})
    # External enrichment is analyst-triggered and restricted to an already-discovered public IP.
    rdap={}
    try:
        req=urllib.request.Request(f"https://rdap.org/ip/{parsed}",headers={"User-Agent":UA,"Accept":"application/rdap+json"})
        with urllib.request.urlopen(req,timeout=4) as response:
            raw=json.loads(response.read(500000).decode("utf-8","replace"))
            rdap={"name":raw.get("name"),"handle":raw.get("handle"),"country":raw.get("country"),
                  "startAddress":raw.get("startAddress"),"endAddress":raw.get("endAddress"),
                  "entities":[e.get("handle") for e in raw.get("entities",[])[:10]],
                  "remarks":[x.get("description",[]) for x in raw.get("remarks",[])[:3]]}
    except Exception as e: rdap={"lookup_status":"unavailable","reason":type(e).__name__}
    network={}
    try:
        req=urllib.request.Request(f"https://ipwho.is/{parsed}",headers={"User-Agent":UA,"Accept":"application/json"})
        with urllib.request.urlopen(req,timeout=4) as response:
            net=json.loads(response.read(100000).decode("utf-8","replace"))
            conn=net.get("connection") or {}
            if net.get("success"):
                network={"asn":("AS"+str(conn.get("asn"))) if conn.get("asn") else None,
                         "organization":conn.get("org"),"isp":conn.get("isp"),
                         "country":(net.get("country"),net.get("country_code")),
                         "region":net.get("region"),"city":net.get("city"),
                         "latitude":(net.get("latitude") if net.get("latitude") is not None else None),
                         "longitude":(net.get("longitude") if net.get("longitude") is not None else None)}
            else: network={"lookup_status":"unavailable","reason":net.get("message","provider_error")}
    except Exception as e: network={"lookup_status":"unavailable","reason":type(e).__name__}
    return {"scan_id":sid,"ip":str(parsed),"reverse_dns":{"hostname":reverse[0],"aliases":reverse[1]} if reverse else None,
      "rdap":rdap,"asn":network.get("asn"),"network":network,
      "geolocation":{k:network.get(k) for k in ("country","region","city") if network.get(k)},
      "hosting_provider":network.get("isp") or rdap.get("name"),
      "related_domains":related,"certificate_relationships":certs,"ports_services":services,
      "historical_observations":history,
      "limitations":["RDAP ownership data can describe an allocation holder, not the operator of a specific host.",
      "Geolocation is not inferred; no geolocation provider is configured.","Ports and services are shown only when stored from an Nmap run.",
      "Reverse DNS and RDAP results are external observations and may be incomplete."]}

@app.get("/api/scans/{sid}/certificates")
def certificate_intelligence(sid:int):
    scan_row(sid); out=[]
    for a in assets(sid):
        tls=_safe_json(a.get("tls"),{})
        if tls: out.append({"host":a["host"],"kind":a["kind"],"source":a.get("source"),"tls":tls,"confidence":a.get("confidence")})
    return {"scan_id":sid,"certificates":out,"count":len(out),"limitations":["Only TLS/certificate metadata retained by this scan is shown.","Certificate Transparency data is not a substitute for live certificate validation."]}

@app.get("/api/scans/{sid}/historical-dns")
def historical_dns(sid:int):
    s=scan_row(sid); out=[]
    with db() as c:
        scans=c.execute("SELECT id,started,status FROM scans WHERE domain=? AND id<=? ORDER BY id DESC LIMIT 30",(s["domain"],sid)).fetchall()
        for sc in scans:
            for a in c.execute("SELECT host,dns,source FROM assets WHERE scan_id=?",(sc["id"],)):
                dns=_safe_json(a["dns"],{})
                if dns: out.append({"scan_id":sc["id"],"started":sc["started"],"status":sc["status"],"host":a["host"],"dns":dns,"source":a["source"]})
    return {"scan_id":sid,"timeline":out,"scans_compared":len(scans),"limitations":["Only retained scan snapshots are available; no retroactive DNS history is fabricated."]}

@app.get("/api/scans/{sid}/service-intelligence")
def service_intelligence(sid:int):
    scan_row(sid); out=[]
    with db() as c: runs=c.execute("SELECT id,status,results,created FROM offensive_runs WHERE scan_id=? AND module='nmap' ORDER BY id DESC",(sid,)).fetchall()
    for r in runs:
        result=_safe_json(r["results"],{})
        for item in result.get("results",[]):
            out.append({**item,"run_id":r["id"],"run_status":r["status"],"observed_at":r["created"]})
    return {"scan_id":sid,"services":out,"count":len(out),"limitations":["Only results persisted from Nmap runs are included; unscanned ports are unknown."]}

@app.get("/api/scans/{sid}/technology-intelligence")
def technology_intelligence(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute("SELECT host,category,target,source,confidence,evidence,observed_at FROM surface_observations WHERE scan_id=? AND lower(category) IN ('technology','fingerprint','tech','http technology') ORDER BY host,id DESC",(sid,)).fetchall()
    return {"scan_id":sid,"technologies":[{**dict(r),"evidence":_safe_json(r["evidence"],{})} for r in rows],"count":len(rows),
      "limitations":["Technology labels are based on recorded observations and may be inferred; validate versions before CVE applicability decisions."]}

@app.get("/api/scans/{sid}/threat-intelligence")
def threat_intelligence(sid:int):
    scan_row(sid)
    with db() as c:
        vulns=c.execute("SELECT host,cve,description,cvss,severity,epss,kev,source,confidence FROM vulnerability_intel WHERE scan_id=? ORDER BY kev DESC,cvss DESC",(sid,)).fetchall()
        findings=c.execute("SELECT host,title,severity,category,description,status FROM findings WHERE scan_id=? ORDER BY score DESC",(sid,)).fetchall()
    return {"scan_id":sid,"known_exploited_vulnerabilities":[dict(x) for x in vulns if x["kev"]],
      "vulnerability_matches":[dict(x) for x in vulns],"security_observations":[dict(x) for x in findings],
      "limitations":["This view correlates existing scan data; it does not query a live threat feed.","A threat-intelligence match is not proof of compromise or vulnerability applicability."]}

@app.get("/api/scans/{sid}/correlation")
def attack_surface_correlation(sid:int):
    scan_row(sid)
    with db() as c:
        edges=[dict(x) for x in c.execute("SELECT source,target,relation,evidence FROM edges WHERE scan_id=?",(sid,))]
        findings=[dict(x) for x in c.execute("SELECT host,title,severity,status FROM findings WHERE scan_id=?",(sid,))]
    byhost={}
    for f in findings: byhost.setdefault(f["host"],[]).append(f)
    ranked=[]
    for host in {x for e in edges for x in (e["source"],e["target"])} | set(byhost):
        degree=sum(1 for e in edges if host in (e["source"],e["target"]))
        ranked.append({"asset":host,"relationship_count":degree,"finding_count":len(byhost.get(host,[])),"findings":byhost.get(host,[])})
    ranked.sort(key=lambda x:(x["finding_count"],x["relationship_count"]),reverse=True)
    return {"scan_id":sid,"relationships":edges,"asset_priorities":ranked,"limitations":["Graph centrality is a prioritization heuristic, not proof of an exploitable attack path."]}

@app.get("/api/scans/{sid}/comparison")
def assessment_comparison(sid:int, previous_scan_id:int|None=None):
    s=scan_row(sid)
    with db() as c:
        if previous_scan_id is None:
            p=c.execute("SELECT id FROM scans WHERE domain=? AND id<? AND status='completed' ORDER BY id DESC LIMIT 1",(s["domain"],sid)).fetchone()
        else:
            p=c.execute("SELECT id FROM scans WHERE id=? AND domain=? AND status='completed'",(previous_scan_id,s["domain"])).fetchone()
    if not p: return {"scan_id":sid,"previous_scan_id":None,"message":"No previous completed scan available.","changes":{}}
    old,new=assets(p["id"]),assets(sid)
    om={a["host"]:a for a in old}; nm={a["host"]:a for a in new}
    added=sorted(set(nm)-set(om)); removed=sorted(set(om)-set(nm))
    changed=[]
    for h in sorted(set(om)&set(nm)):
        od=_safe_json(om[h].get("dns"),{}); nd=_safe_json(nm[h].get("dns"),{})
        if od!=nd: changed.append({"host":h,"previous_dns":od,"current_dns":nd})
    with db() as c:
        old_ports=c.execute("SELECT results FROM offensive_runs WHERE scan_id=? AND module='nmap'",(p["id"],)).fetchall()
        new_ports=c.execute("SELECT results FROM offensive_runs WHERE scan_id=? AND module='nmap'",(sid,)).fetchall()
    def ports(rows):
        vals=set()
        for r in rows:
            for x in _safe_json(r["results"],{}).get("results",[]):
                vals.add((x.get("host"),str(x.get("port")),x.get("protocol"),x.get("service")))
        return vals
    op,np=ports(old_ports),ports(new_ports)
    return {"scan_id":sid,"previous_scan_id":p["id"],"changes":{"assets_added":added,"assets_removed":removed,"dns_changed":changed,
      "services_added":[list(x) for x in sorted(np-op)],"services_removed":[list(x) for x in sorted(op-np)]}}

@app.get("/api/search")
def global_investigation_search(q:str,scan_id:int|None=None,limit:int=50):
    q=q.strip().lower()
    if len(q)<2: raise HTTPException(400,"Search query must contain at least two characters.")
    limit=max(1,min(limit,100))
    with db() as c:
        if scan_id is not None: scan_row(scan_id); scan_filter=" AND scan_id=?"; params=(f"%{q}%",scan_id)
        else: scan_filter=""; params=(f"%{q}%",)
        assets_rows=c.execute("SELECT scan_id,host,kind,source,confidence FROM assets WHERE lower(host) LIKE ?"+scan_filter+" ORDER BY scan_id DESC LIMIT ?",params+(limit,)).fetchall()
        findings_rows=c.execute("SELECT scan_id,host,title,severity,category FROM findings WHERE (lower(host) LIKE ? OR lower(title) LIKE ? OR lower(category) LIKE ?)"+scan_filter+" ORDER BY scan_id DESC LIMIT ?",(f"%{q}%",f"%{q}%",f"%{q}%")+((scan_id,) if scan_id is not None else ())+ (limit,)).fetchall()
        vuln_rows=c.execute("SELECT scan_id,host,cve,severity,cvss FROM vulnerability_intel WHERE (lower(host) LIKE ? OR lower(cve) LIKE ?)"+scan_filter+" ORDER BY scan_id DESC LIMIT ?",(f"%{q}%",f"%{q}%")+((scan_id,) if scan_id is not None else ())+ (limit,)).fetchall()
        surface_rows=c.execute("SELECT scan_id,host,category,target,source,confidence FROM surface_observations WHERE (lower(host) LIKE ? OR lower(target) LIKE ? OR lower(category) LIKE ?)"+scan_filter+" ORDER BY scan_id DESC LIMIT ?",(f"%{q}%",f"%{q}%",f"%{q}%")+((scan_id,) if scan_id is not None else ())+ (limit,)).fetchall()
    results=[{"type":"asset",**dict(x)} for x in assets_rows]+[{"type":"finding",**dict(x)} for x in findings_rows]+[{"type":"cve",**dict(x)} for x in vuln_rows]+[{"type":"observation",**dict(x)} for x in surface_rows]
    return {"query":q,"results":results[:limit],"count":len(results[:limit])}

@app.get("/api/scans/{sid}/report-studio",response_class=HTMLResponse)
def report_studio(sid:int,sections:str="summary,assets,findings,services,certificates,changes"):
    s=scan_row(sid); allowed={"summary","assets","findings","services","certificates","changes","threat"}
    chosen=set(sections.split(",")) & allowed
    esc=html.escape
    parts=[f"<h1>SCOPEZERO Assessment Report</h1><p>Target: {esc(s['domain'])} · Scan #{sid} · {esc(s['status'])}</p>"]
    if "summary" in chosen: parts.append(f"<h2>Executive summary</h2><p>{len(assets(sid))} assets and {len(findings(sid))} recorded findings. Observations require validation.</p>")
    if "assets" in chosen: parts.append("<h2>Asset inventory</h2><table><tr><th>Host</th><th>Type</th><th>Source</th><th>Confidence</th></tr>"+"".join(f"<tr><td>{esc(a['host'])}</td><td>{esc(a['kind'])}</td><td>{esc(a.get('source') or '')}</td><td>{a.get('confidence') or 0}%</td></tr>" for a in assets(sid))+"</table>")
    if "findings" in chosen: parts.append("<h2>Findings</h2><table><tr><th>Host</th><th>Finding</th><th>Severity</th><th>Status</th></tr>"+"".join(f"<tr><td>{esc(f.get('host') or '')}</td><td>{esc(f.get('title') or '')}</td><td>{esc(f.get('severity') or '')}</td><td>{esc(f.get('status') or '')}</td></tr>" for f in findings(sid))+"</table>")
    if "services" in chosen: parts.append(f"<h2>Observed services</h2><pre>{esc(json.dumps(service_intelligence(sid),indent=2))}</pre>")
    if "certificates" in chosen: parts.append(f"<h2>Certificate observations</h2><pre>{esc(json.dumps(certificate_intelligence(sid),indent=2))}</pre>")
    if "changes" in chosen: parts.append(f"<h2>Assessment comparison</h2><pre>{esc(json.dumps(assessment_comparison(sid),indent=2))}</pre>")
    if "threat" in chosen: parts.append(f"<h2>Threat intelligence</h2><pre>{esc(json.dumps(threat_intelligence(sid),indent=2))}</pre>")
    return HTMLResponse("<!doctype html><html><head><meta charset='utf-8'><title>SCOPEZERO Report Studio</title><style>body{font:14px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#172638}h1,h2{color:#0b6959}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left}pre{white-space:pre-wrap;background:#f3f6f8;padding:14px;border-radius:8px}@media print{button{display:none}}</style></head><body>"+"".join(parts)+"<p>Generated by SCOPEZERO. Evidence completeness and authorization must be independently reviewed.</p><button onclick='window.print()'>Print / Save as PDF</button></body></html>")


@app.post("/api/scans/{sid}/evidence-records")
def add_evidence(sid:int, x:EvidenceIn):
    scan_row(sid)
    if x.finding_id is not None:
        with db() as c: found=c.execute("SELECT id FROM findings WHERE id=? AND scan_id=?",(x.finding_id,sid)).fetchone()
        if not found: raise HTTPException(404,"Finding does not belong to this scan.")
    attachment_path=None
    if x.attachment_base64:
        raw=x.attachment_base64.split(',',1)[-1]
        try: blob=base64.b64decode(raw,validate=True)
        except Exception: raise HTTPException(400,"Screenshot attachment is not valid base64.")
        if len(blob)>2_000_000: raise HTTPException(413,"Screenshot must be 2 MB or smaller.")
        ext=Path(x.attachment_name or "evidence.png").suffix.lower()
        if ext not in (".png",".jpg",".jpeg",".webp"): raise HTTPException(400,"Only PNG, JPG or WEBP screenshots are accepted.")
        store=Path(__file__).resolve().parents[1]/"evidence"; store.mkdir(parents=True,exist_ok=True)
        attachment_path=str(store/f"scan-{sid}-evidence-{int(datetime.now(timezone.utc).timestamp()*1000)}{ext}")
        Path(attachment_path).write_bytes(blob)
    with db() as c:
        cur=c.execute("INSERT INTO pentest_evidence(scan_id,finding_id,title,evidence_type,notes,request_text,response_text,attachment_path,created,sha256) VALUES(?,?,?,?,?,?,?,?,?,?)",
          (sid,x.finding_id,x.title,x.evidence_type,x.notes,x.request_text,x.response_text,attachment_path,stamp(),sha256_text((x.notes or "")+(x.request_text or "")+(x.response_text or "")+(attachment_path or ""))))
        eid=cur.lastrowid
    _audit(sid,"evidence_added",str(eid),{"title":x.title,"evidence_type":x.evidence_type})
    return {"id":eid,"created":True}

@app.get("/api/scans/{sid}/evidence-records")
def list_evidence(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT id,finding_id,title,evidence_type,notes,request_text,response_text,created,sha256 FROM pentest_evidence WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
    return [{**dict(r),"has_attachment":bool(r["attachment_path"])} for r in rows]

@app.post("/api/scans/{sid}/validation")
def add_validation(sid:int,x:ValidationIn):
    scan_row(sid)
    allowed={"Confirmed","Likely","Not Reproducible","False Positive","Needs Review"}
    if x.verdict not in allowed: raise HTTPException(400,"Invalid validation verdict.")
    if x.finding_id is not None:
        with db() as c: f=c.execute("SELECT id FROM findings WHERE id=? AND scan_id=?",(x.finding_id,sid)).fetchone()
        if not f: raise HTTPException(404,"Finding does not belong to this scan.")
    with db() as c:
        cur=c.execute("INSERT INTO validation_records(scan_id,finding_id,verdict,rationale,validated_by,created) VALUES(?,?,?,?,?,?)",
          (sid,x.finding_id,x.verdict,x.rationale,x.validated_by,stamp()))
    _audit(sid,"finding_validated",str(x.finding_id or "unlinked"),{"verdict":x.verdict})
    return {"id":cur.lastrowid,"verdict":x.verdict,"recorded":True}

@app.get("/api/scans/{sid}/validation")
def list_validation(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT * FROM validation_records WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/scans/{sid}/pentest-report", response_class=HTMLResponse)
def pentest_report(sid:int):
    s=scan_row(sid); aa=assets(sid); ff=findings(sid)
    with db() as c:
        runs=c.execute("SELECT module,status,results,created FROM offensive_runs WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
        ev=c.execute("SELECT title,evidence_type,notes,created FROM pentest_evidence WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
        vals=c.execute("SELECT verdict,rationale,created FROM validation_records WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    esc=html.escape
    rows=''.join(f"<tr><td>{esc(a['host'])}</td><td>{esc(a['kind'])}</td><td>{esc(a.get('source') or '')}</td><td>{a.get('confidence') or 0}%</td></tr>" for a in aa)
    frows=''.join(f"<tr><td>{esc(f['host'] or '')}</td><td>{esc(f['title'] or '')}</td><td>{esc(f['severity'] or '')}</td><td>{esc(f['status'] or 'Open')}</td></tr>" for f in ff)
    runrows=''.join(f"<li><b>{esc(r['module'])}</b> · {esc(r['status'])} · {esc(r['created'])}</li>" for r in runs)
    evrows=''.join(f"<li><b>{esc(e['title'])}</b> ({esc(e['evidence_type'])}) — {esc(e['notes'])}</li>" for e in ev)
    vrows=''.join(f"<li><b>{esc(v['verdict'])}</b> — {esc(v['rationale'])}</li>" for v in vals)
    doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>SCOPEZERO Pentest Report · {esc(s['domain'])}</title><style>body{{font:14px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#182333}}h1{{color:#102b3c}}h2{{margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:8px}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}.note{{background:#eef5f3;padding:14px;border-radius:8px}}@media print{{button{{display:none}}}}</style></head><body><h1>SCOPEZERO · Security Assessment Report</h1><p><b>Target:</b> {esc(s['domain'])} · <b>Scan:</b> {sid} · <b>Status:</b> {esc(s['status'])}</p><p class="note">Scope and authorization must be confirmed by the assessment operator. This report contains observed evidence and tool outputs; observations are not automatically confirmed vulnerabilities. Validate findings before distribution.</p><h2>Executive Summary</h2><p>{len(aa)} asset records, {len(ff)} scanner observations, {len(runs)} assessment tool runs, {len(ev)} evidence records and {len(vals)} validation records.</p><h2>Asset Inventory</h2><table><tr><th>Asset</th><th>Type</th><th>Source</th><th>Confidence</th></tr>{rows}</table><h2>Findings</h2><table><tr><th>Host</th><th>Observation</th><th>Severity</th><th>Status</th></tr>{frows}</table><h2>Assessment Tool Runs</h2><ul>{runrows}</ul><h2>Evidence Records</h2><ul>{evrows}</ul><h2>Validation Records</h2><ul>{vrows}</ul><p>Generated by SCOPEZERO 9.0.0 · {esc(stamp())}</p><button onclick="window.print()">Print / Save as PDF</button></body></html>'''
    return HTMLResponse(doc,headers={"Cache-Control":"no-store"})

@app.get("/api/scans/{sid}/api-assessment")
def api_assessment(sid:int):
    inv=api_inventory(sid)
    endpoints=inv.get("endpoints",[])
    checks=[]
    for e in endpoints:
        ev=e.get("evidence") or {}
        checks.append({"endpoint":e.get("target"),"status":e.get("status"),"documentation_indicator":bool(ev.get("spec_indicator")),
          "assessment":"Public endpoint/documentation observed; authentication, authorization and business logic were not tested.",
          "confidence":"Observed" if e.get("status") in (200,401,403) else "Limited"})
    return {"scan_id":sid,"endpoint_count":len(checks),"checks":checks,"limitations":inv["limitations"]}

@app.get("/api/evidence/{evidence_id}/attachment")
def evidence_attachment(evidence_id:int):
    with db() as c: row=c.execute("SELECT attachment_path FROM pentest_evidence WHERE id=?",(evidence_id,)).fetchone()
    if not row or not row["attachment_path"]: raise HTTPException(404,"No screenshot attachment found.")
    path=Path(row["attachment_path"]).resolve()
    allowed=(Path(__file__).resolve().parents[1]/"evidence").resolve()
    if allowed not in path.parents or not path.is_file(): raise HTTPException(404,"Attachment unavailable.")
    media=mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path,media_type=media,filename=path.name,headers={"X-Content-Type-Options":"nosniff"})


# SCOPEZERO 9.0 — one-click end-to-end attack-surface workflow.
from .pipeline import run_pipeline as _run_pipeline
_PIPELINE_POOL=ThreadPoolExecutor(max_workers=2,thread_name_prefix="scopezero-pipeline")

class PipelineIn(BaseModel):
    engagement_id:int
    authorized:bool
    wordlist:bool=False
    web_checks:bool=True
    external_tools:bool=True
    content_discovery:bool=False
    run_naabu:bool=True
    run_httpx:bool=True
    run_feroxbuster:bool=True
    speed_profile:str="balanced"
    tool_timeout:int=120

@app.post("/api/pipelines")
def create_pipeline(x:PipelineIn):
    if not x.authorized:
        raise HTTPException(400,"Confirm current written authorization before starting the workflow.")
    with db() as c:
        eng=c.execute("SELECT * FROM engagements WHERE id=?",(x.engagement_id,)).fetchone()
    if not eng or not eng["authorized"]:
        raise HTTPException(403,"Select an active authorized engagement.")
    if eng["expires"]:
        try:
            exp=datetime.fromisoformat(eng["expires"].replace("Z","+00:00"))
            if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
            if exp<=datetime.now(timezone.utc): raise HTTPException(403,"Engagement authorization has expired.")
        except ValueError: raise HTTPException(400,"Engagement expiry is invalid.")
    root=normalize(eng["root_domain"])
    profile=x.speed_profile if x.speed_profile in ("fast","balanced","polite") else "balanced"
    workers={"fast":16,"balanced":10,"polite":5}[profile]
    options={"speed_profile":profile,"workers":workers,"wordlist":x.wordlist,"web_checks":x.web_checks,
             "external_tools":x.external_tools,"shodan_intel":False,"vuln_intel":False,
             "content_discovery":x.content_discovery,"tool_timeout":max(15,min(x.tool_timeout,180))}
    started=stamp()
    with db() as c:
        cur=c.execute("INSERT INTO scans(engagement_id,domain,started,status,progress,stage,options) VALUES(?,?,?,?,?,?,?)",
                      (x.engagement_id,root,started,"queued",0,"Pipeline queued",json.dumps(options)))
        sid=cur.lastrowid
        cur=c.execute("INSERT INTO pipeline_runs(scan_id,engagement_id,status,stage,progress,stages_json,created) VALUES(?,?,?,?,?,?,?)",
                      (sid,x.engagement_id,"queued","Queued",0,json.dumps({"discover":"queued","resolve":"queued","probe":"queued","correlate":"queued","assess":"queued","validate":"analyst_review","report":"queued"}),started))
        pid=cur.lastrowid
    _PIPELINE_POOL.submit(_run_pipeline,pid,sid,root,options,x.engagement_id)
    return {"pipeline_id":pid,"scan_id":sid,"status":"queued","message":"End-to-end workflow queued. Poll the pipeline status endpoint."}

@app.get("/api/pipelines/{pid}")
def pipeline_status(pid:int):
    with db() as c:
        row=c.execute("SELECT * FROM pipeline_runs WHERE id=?",(pid,)).fetchone()
    if not row: raise HTTPException(404,"Pipeline not found.")
    d=dict(row)
    try:d["stages"]=json.loads(d.pop("stages_json") or "{}")
    except Exception:d["stages"]={}
    d["scan"] = scan_row(d["scan_id"])
    return d


# Unified Assessment Engine observability endpoints.
@app.get("/api/pipelines")
def list_pipelines(engagement_id:int|None=None,limit:int=50):
    with db() as c:
        sql="""SELECT p.*,s.domain,s.status scan_status,s.error scan_error
               FROM pipeline_runs p JOIN scans s ON s.id=p.scan_id"""
        args=[]
        if engagement_id is not None: sql+=" WHERE p.engagement_id=?";args.append(engagement_id)
        sql+=" ORDER BY p.id DESC LIMIT ?";args.append(max(1,min(limit,200)))
        rows=c.execute(sql,args).fetchall()
    out=[]
    for row in rows:
        item=dict(row)
        try:item["stages"]=json.loads(item.pop("stages_json") or "{}")
        except Exception:item["stages"]={}
        out.append(item)
    return out

@app.get("/api/pipelines/{pid}/events")
def pipeline_events(pid:int,after_id:int=0,limit:int=300):
    with db() as c:
        p=c.execute("SELECT scan_id FROM pipeline_runs WHERE id=?",(pid,)).fetchone()
        if not p:raise HTTPException(404,"Pipeline not found.")
        rows=c.execute("""SELECT id,event_type,severity,title,message,payload_json,created
                          FROM live_events WHERE scan_id=? AND id>? ORDER BY id LIMIT ?""",
                       (p["scan_id"],max(0,after_id),max(1,min(limit,500)))).fetchall()
    result=[]
    for row in rows:
        item=dict(row)
        try:item["payload"]=json.loads(item.pop("payload_json") or "{}")
        except Exception:item["payload"]={}
        result.append(item)
    return result

@app.get("/api/pipelines/{pid}/stage-results")
def pipeline_stage_results(pid:int):
    state=pipeline_status(pid)
    sid=state["scan_id"]
    with db() as c:
        jobs=c.execute("""SELECT id,tool,status,progress,stage,result_json,error,created,finished
                          FROM tool_jobs WHERE scan_id=? ORDER BY id""",(sid,)).fetchall()
        observations=c.execute("""SELECT entity,entity_type,relation,source_tool,observed_at,confidence,data_json
                                   FROM normalized_observations WHERE scan_id=? ORDER BY id""",(sid,)).fetchall()
        findings=c.execute("""SELECT id,host,title,severity,status,category FROM findings WHERE scan_id=? ORDER BY id""",(sid,)).fetchall()
    parsed=[]
    for row in jobs:
        item=dict(row)
        try:item["result"]=json.loads(item.pop("result_json") or "{}")
        except Exception:item["result"]={}
        parsed.append(item)
    obs=[]
    for row in observations:
        item=dict(row)
        try:item["data"]=json.loads(item.pop("data_json") or "{}")
        except Exception:item["data"]={}
        obs.append(item)
    return {"pipeline_id":pid,"scan_id":sid,"stages":state.get("stages",{}),
            "jobs":parsed,"observations":obs,"findings":[dict(x) for x in findings],
            "analyst_validation_required":True}

@app.get("/api/pipelines/{pid}/results")
def pipeline_results(pid:int):
    state=pipeline_status(pid)
    sid=state["scan_id"]
    with db() as c:
        norm=c.execute("SELECT * FROM normalized_observations WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
        edges=c.execute("SELECT source,target,relation,evidence FROM edges WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
        jobs=c.execute("SELECT id,tool,status,progress,stage,result_json,error,created,finished FROM tool_jobs WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
        vals=c.execute("SELECT * FROM validation_records WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    observations=[]
    for r in norm:
        item=dict(r)
        try:item["data"]=json.loads(item.pop("data_json") or "{}")
        except Exception:item["data"]={}
        observations.append(item)
    job_rows=[]
    for r in jobs:
        item=dict(r)
        try:item["result"]=json.loads(item.pop("result_json") or "{}")
        except Exception:item["result"]={}
        job_rows.append(item)
    return {"pipeline":state,"scan_id":sid,"assets":assets(sid),"findings":findings(sid),
            "normalized_observations":observations,"relationships":[dict(x) for x in edges],
            "jobs":job_rows,"validation": [dict(x) for x in vals],
            "report":{"html":f"/api/scans/{sid}/pentest-report","studio":f"/api/scans/{sid}/report-studio",
                      "json":f"/api/scans/{sid}/export.json"}}


# SCOPEZERO 10.4 investigation suite: evidence-led intelligence, endpoint inventory,
# constrained request replay, API authorization observations and attack-path hypotheses.
class ReplayIn(BaseModel):
    url:str=Field(min_length=8,max_length=2048)
    method:str="GET"
    headers:dict[str,str]={}
    authorized:bool=False
class MatrixIn(BaseModel):
    endpoint:str=Field(min_length=1,max_length=500)
    method:str=Field(default="GET",max_length=12)
    identity:str=Field(min_length=1,max_length=100)
    outcome:str=Field(min_length=1,max_length=40)
    status_code:int|None=None
    evidence:str=Field(default="",max_length=4000)
class NoteIn(BaseModel):
    title:str=Field(min_length=2,max_length=180)
    body:str=Field(min_length=2,max_length=10000)
    asset:str|None=Field(default=None,max_length=255)

class WebCheckIn(BaseModel):
    url:str=Field(min_length=8,max_length=2048)
    parameter:str=Field(min_length=1,max_length=100)
    authorized:bool=False

@app.post("/api/scans/{sid}/web-security/check")
def run_web_security_check(sid:int,x:WebCheckIn):
    """Low-impact GET-only checks. No exploit, state change, auth material or redirect following."""
    scan=scan_row(sid)
    if not x.authorized: raise HTTPException(400,"Explicit authorization confirmation is required.")
    host=url_host(x.url)
    if not host: raise HTTPException(400,"Only valid HTTP(S) URLs are accepted.")
    root=scan["domain"]
    if not (host==root or host.endswith("."+root)): raise HTTPException(403,"Target is outside this scan root.")
    with db() as c:
        known=c.execute("SELECT 1 FROM assets WHERE scan_id=? AND host=? LIMIT 1",(sid,host)).fetchone()
    if not known: raise HTTPException(403,"Host must already be present in this scan's asset inventory.")
    if not validate_public_target(host): raise HTTPException(403,"Target must resolve exclusively to public IP addresses.")
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts=urlsplit(x.url)
    if parts.scheme not in ("http","https") or parts.username or parts.password: raise HTTPException(400,"Unsupported URL.")
    pairs=parse_qsl(parts.query,keep_blank_values=True)
    if not pairs or x.parameter not in [k for k,v in pairs]: raise HTTPException(400,"Selected parameter must already exist in the URL query string.")
    if len(pairs)>40: raise HTTPException(400,"Too many query parameters for a bounded check.")
    def fetch(qpairs):
        u=urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(qpairs,doseq=True),""))
        try:
            r=requests.get(u,headers={"User-Agent":UA,"Accept":"text/html,application/json,*/*"},timeout=(3,7),allow_redirects=False,stream=True)
            chunks=b""
            for ch in r.iter_content(2048):
                chunks+=ch
                if len(chunks)>=8000: chunks=chunks[:8000]; break
            out=(r.status_code,dict(r.headers),chunks.decode("utf-8",errors="replace"));r.close();return out
        except requests.RequestException as e: raise HTTPException(502,f"Probe failed: {type(e).__name__}")
    baseline=fetch(pairs)
    results=[]
    # Harmless marker reflection check: this is not an executable XSS payload.
    marker="SZ_REFLECT_"+str(int(time.time()*1000))
    reflected=fetch([(k,(marker if k==x.parameter else v)) for k,v in pairs])
    if marker in reflected[2]:
        results.append(("xss_reflection","Potential marker reflection","Candidate",55,"Unique inert marker appeared in response; manual context/encoding validation required."))
    else:
        results.append(("xss_reflection","No marker reflection observed","No signal",20,"Inert marker was not found in the capped response body; this does not rule out XSS."))
    # Single quote syntax-error signal only; no boolean exploitation or data extraction.
    quoted=fetch([(k,(v+"'") if k==x.parameter else v) for k,v in pairs])
    err_signals=("sql syntax","sqlite error","mysql_fetch","unterminated quoted","odbc sql","postgresql.*error","ora-00933","sqlstate")
    body=quoted[2].lower()
    matched=[sig for sig in err_signals if sig in body]
    if matched:
        results.append(("sqli_error_signal","Possible SQL error disclosure","Candidate",60,"Quote-only probe produced a recognizable database error signature: "+", ".join(matched[:3])))
    else:
        results.append(("sqli_error_signal","No SQL error signature observed","No signal",20,"Quote-only probe produced no recognized database error signature; blind SQLi is not assessed."))
    # SSRF: identify URL-taking parameters, do not make server-side callback or internal-network requests.
    url_names={"url","uri","path","redirect","return","next","dest","destination","callback","webhook","image","feed","fetch","proxy","target"}
    if x.parameter.lower() in url_names or any(v.startswith(("http://","https://")) for k,v in pairs if k==x.parameter):
        results.append(("ssrf_candidate","Potential server-side URL parameter","Manual review",35,"Parameter name/value suggests URL handling. No SSRF payload, internal address or callback was sent."))
    # Authentication posture: inspect baseline response headers only.
    h={k.lower():v for k,v in baseline[1].items()}
    cookies=h.get("set-cookie","")
    flags=[]
    if cookies and "httponly" not in cookies.lower(): flags.append("Set-Cookie lacks HttpOnly")
    if cookies and parts.scheme=="https" and "secure" not in cookies.lower(): flags.append("Set-Cookie lacks Secure")
    if cookies and "samesite" not in cookies.lower(): flags.append("Set-Cookie lacks SameSite")
    if parts.scheme=="https" and "strict-transport-security" not in h: flags.append("HSTS header absent")
    if flags: results.append(("auth_cookie_posture","Session/cookie hardening observations","Candidate",45,"; ".join(flags)))
    else: results.append(("auth_cookie_posture","No listed cookie/header weakness observed","No signal",25,"Header-only review; authentication logic and session lifecycle were not tested."))
    saved=[]
    with db() as c:
        for typ,title,verdict,conf,evidence in results:
            cur=c.execute("INSERT INTO web_security_checks(scan_id,url,check_type,verdict,confidence,evidence,created) VALUES(?,?,?,?,?,?,?)",(sid,x.url,typ,verdict,conf,evidence,stamp()))
            saved.append({"id":cur.lastrowid,"type":typ,"title":title,"verdict":verdict,"confidence":conf,"evidence":evidence})
    _audit(sid,"web_security_checks",host,{"parameter":x.parameter,"checks":len(saved),"method":"GET-only"})
    return {"url":x.url,"parameter":x.parameter,"baseline_status":baseline[0],"results":saved,"limitations":["GET-only, low-impact probes; no exploit payloads or data extraction.","No SSRF callback or internal-network requests were made.","IDOR/BOLA requires analyst comparison of two authorized identities and is recorded in the API authorization matrix.","A negative result is not proof that a vulnerability is absent."]}

@app.get("/api/scans/{sid}/web-security/checks")
def list_web_security_checks(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT * FROM web_security_checks WHERE scan_id=? ORDER BY id DESC LIMIT 200",(sid,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/scans/{sid}/investigation/overview")
def investigation_overview(sid:int):
    scan=scan_row(sid)
    with db() as c:
        ac=c.execute("SELECT COUNT(*) n FROM assets WHERE scan_id=?",(sid,)).fetchone()["n"]
        obs=c.execute("SELECT COUNT(*) n FROM surface_observations WHERE scan_id=?",(sid,)).fetchone()["n"]
        f=c.execute("SELECT severity,COUNT(*) n FROM findings WHERE scan_id=? GROUP BY severity",(sid,)).fetchall()
        v=c.execute("SELECT COUNT(*) n,SUM(kev) kev FROM vulnerability_intel WHERE scan_id=?",(sid,)).fetchone()
        ev=c.execute("SELECT COUNT(*) n FROM pentest_evidence WHERE scan_id=?",(sid,)).fetchone()["n"]
        req=c.execute("SELECT COUNT(*) n FROM request_lab_runs WHERE scan_id=?",(sid,)).fetchone()["n"]
        api=c.execute("SELECT COUNT(*) n FROM api_access_matrix WHERE scan_id=?",(sid,)).fetchone()["n"]
    return {"scan_id":sid,"domain":scan["domain"],"assets":ac,"surface_observations":obs,"findings_by_severity":{r["severity"]:r["n"] for r in f},"cve_matches":v["n"] or 0,"kev_matches":v["kev"] or 0,"evidence_records":ev,"request_replays":req,"api_matrix_observations":api}

@app.get("/api/scans/{sid}/investigation/recommendations")
def investigation_recommendations(sid:int):
    scan_row(sid); rec=[]
    with db() as c:
        tech=c.execute("SELECT host,evidence FROM surface_observations WHERE scan_id=? AND category IN ('technology','http','service') ORDER BY id DESC LIMIT 80",(sid,)).fetchall()
        findings_rows=c.execute("SELECT id,host,title,severity,evidence,confidence FROM findings WHERE scan_id=? AND status NOT IN ('False Positive','Closed') ORDER BY score DESC LIMIT 100",(sid,)).fetchall()
        apis=c.execute("SELECT host,target,status FROM surface_observations WHERE scan_id=? AND (target LIKE '%api%' OR target LIKE '%swagger%' OR target LIKE '%graphql%' OR target LIKE '%openapi%') LIMIT 40",(sid,)).fetchall()
        assets_rows=c.execute("SELECT host,kind FROM assets WHERE scan_id=? ORDER BY confidence DESC LIMIT 50",(sid,)).fetchall()
    for x in tech:
        rec.append({"priority":"Review","target":x["host"],"action":"Confirm technology and exact version before CVE matching","reason":"Technology/service observation exists; version applicability must be verified.","source":"Observed surface metadata"})
    for x in findings_rows:
        rec.append({"priority":x["severity"],"target":x["host"],"action":"Validate finding and attach reproducible evidence","reason":x["title"],"finding_id":x["id"],"confidence":x["confidence"],"source":"Stored finding"})
    for x in apis:
        rec.append({"priority":"Investigate","target":x["host"],"action":"Review API specification, authentication and authorization boundaries","reason":x["target"],"source":"Discovered API surface candidate"})
    if not rec:
        rec=[{"priority":"Baseline","target":scan["domain"],"action":"Complete passive discovery and technology identification","reason":"No investigation candidates are stored yet.","source":"Assessment state"}]
    order={"Critical":0,"High":1,"Medium":2,"Low":3,"Review":4,"Investigate":5,"Baseline":6}
    rec.sort(key=lambda x:order.get(x["priority"],7))
    return rec[:100]

@app.get("/api/scans/{sid}/investigation/endpoints")
def investigation_endpoints(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute("SELECT host,category,target,status,source,confidence,evidence,observed_at FROM surface_observations WHERE scan_id=? ORDER BY host,target LIMIT 1500",(sid,)).fetchall()
    return [{**dict(r),"kind":"api_candidate" if any(k in (r["target"] or "").lower() for k in ("api","swagger","graphql","openapi")) else "web_observation"} for r in rows]

@app.post("/api/scans/{sid}/request-lab/replay")
def request_lab_replay(sid:int,x:ReplayIn):
    scan=scan_row(sid)
    if not x.authorized: raise HTTPException(400,"Explicit authorization confirmation is required.")
    method=x.method.upper()
    if method not in ("GET","HEAD"): raise HTTPException(400,"Request Lab currently permits GET and HEAD only. State-changing methods are disabled.")
    host=url_host(x.url)
    if not host: raise HTTPException(400,"Only valid HTTP or HTTPS URLs are accepted.")
    root=scan["domain"]
    if not (host==root or host.endswith("."+root)): raise HTTPException(403,"Target host is outside the scan root domain.")
    with db() as c:
        allowed=c.execute("SELECT 1 FROM assets WHERE scan_id=? AND host=? LIMIT 1",(sid,host)).fetchone()
    if not allowed: raise HTTPException(403,"Host must already exist in this scan's discovered asset inventory.")
    if not validate_public_target(host): raise HTTPException(403,"Target does not resolve exclusively to public IP addresses.")
    headers={k:v for k,v in list(x.headers.items())[:20] if k.lower() in ("accept","user-agent","content-type","authorization","x-requested-with") and len(str(v))<1000}
    headers.setdefault("User-Agent",UA)
    started=time.monotonic()
    try:
        r=requests.request(method,x.url,headers=headers,timeout=(3,8),allow_redirects=False,stream=True)
        elapsed=int((time.monotonic()-started)*1000)
        body=b""
        if method!="HEAD":
            for chunk in r.iter_content(4096):
                body+=chunk
                if len(body)>=12000: body=body[:12000]; break
        response_text=f"HTTP {r.status_code}\n"+"\n".join(f"{k}: {v}" for k,v in list(r.headers.items())[:40])+"\n\n"+body.decode("utf-8",errors="replace")
        request_text=f"{method} {x.url}\n"+"\n".join(f"{k}: {v}" for k,v in headers.items())
        status=r.status_code; r.close()
    except requests.RequestException as e: raise HTTPException(502,f"Request failed: {type(e).__name__}")
    with db() as c:
        cur=c.execute("INSERT INTO request_lab_runs(scan_id,url,method,status_code,elapsed_ms,request_hash,response_hash,request_text,response_text,created) VALUES(?,?,?,?,?,?,?,?,?,?)",(sid,x.url,method,status,elapsed,sha256_text(request_text),sha256_text(response_text),request_text,response_text,stamp()))
    _audit(sid,"request_lab_replay",str(cur.lastrowid),{"host":host,"method":method,"status":status})
    return {"id":cur.lastrowid,"status_code":status,"elapsed_ms":elapsed,"request":request_text,"response":response_text,"request_sha256":sha256_text(request_text),"response_sha256":sha256_text(response_text),"redirects_followed":False}

@app.get("/api/scans/{sid}/request-lab/history")
def request_lab_history(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT id,url,method,status_code,elapsed_ms,request_hash,response_hash,created FROM request_lab_runs WHERE scan_id=? ORDER BY id DESC LIMIT 100",(sid,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/scans/{sid}/api-matrix")
def add_api_matrix(sid:int,x:MatrixIn):
    scan_row(sid)
    if x.outcome not in ("Allowed","Denied","Unexpectedly allowed","Error","Not tested"): raise HTTPException(400,"Unsupported authorization outcome.")
    with db() as c:
        cur=c.execute("INSERT INTO api_access_matrix(scan_id,endpoint,method,identity,outcome,status_code,evidence,created) VALUES(?,?,?,?,?,?,?,?)",(sid,x.endpoint,x.method.upper(),x.identity,x.outcome,x.status_code,x.evidence,stamp()))
    _audit(sid,"api_matrix_observation",str(cur.lastrowid),{"endpoint":x.endpoint,"identity":x.identity,"outcome":x.outcome})
    return {"id":cur.lastrowid,"created":True}

@app.get("/api/scans/{sid}/api-matrix")
def get_api_matrix(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT * FROM api_access_matrix WHERE scan_id=? ORDER BY endpoint,method,identity,id DESC",(sid,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/scans/{sid}/investigation/risk-priorities")
def investigation_risk_priorities(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute("""SELECT f.id,f.host,f.title,f.severity,f.score,f.confidence,
          MAX(COALESCE(v.epss,0)) epss,MAX(COALESCE(v.kev,0)) kev
          FROM findings f LEFT JOIN vulnerability_intel v ON v.scan_id=f.scan_id AND v.host=f.host
          WHERE f.scan_id=? AND f.status NOT IN ('False Positive','Closed')
          GROUP BY f.id ORDER BY f.score DESC LIMIT 250""",(sid,)).fetchall()
    out=[]
    for r in rows:
        item=dict(r); item["risk_priority"]=risk_score(r["severity"],r["epss"],bool(r["kev"]),True,r["confidence"])
        item["priority_basis"]="Severity + EPSS + CISA KEV + internet exposure + evidence confidence; triage aid only"
        out.append(item)
    return sorted(out,key=lambda x:x["risk_priority"],reverse=True)

@app.get("/api/scans/{sid}/investigation/duplicates")
def investigation_duplicate_candidates(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT id,host,category,title,severity,status FROM findings WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    groups={}
    for r in rows:
        key=(str(r["host"] or "").lower(),str(r["category"] or "").lower()," ".join(str(r["title"] or "").lower().split()))
        groups.setdefault(key,[]).append(dict(r))
    return [{"fingerprint":"|".join(k),"candidate_findings":v,"count":len(v),"review_required":True} for k,v in groups.items() if len(v)>1]

@app.get("/api/scans/{sid}/investigation/attack-paths")
def investigation_attack_paths(sid:int):
    scan_row(sid)
    with db() as c:
        edges=c.execute("SELECT source,target,relation,evidence FROM edges WHERE scan_id=? LIMIT 1000",(sid,)).fetchall()
        findings_rows=c.execute("SELECT host,title,severity,confidence FROM findings WHERE scan_id=? AND status NOT IN ('False Positive','Closed')",(sid,)).fetchall()
    byhost={}
    for f in findings_rows: byhost.setdefault(f["host"],[]).append({"title":f["title"],"severity":f["severity"],"confidence":f["confidence"]})
    paths=[]
    for e in edges:
        paths.append({"source":e["source"],"target":e["target"],"relation":e["relation"],"evidence":e["evidence"],"source_findings":byhost.get(e["source"],[]),"target_findings":byhost.get(e["target"],[]),"classification":"Evidence-linked investigation hypothesis; not proof of exploitability"})
    return paths

@app.post("/api/scans/{sid}/investigation/notes")
def add_investigation_note(sid:int,x:NoteIn):
    scan_row(sid)
    with db() as c: cur=c.execute("INSERT INTO investigation_notes(scan_id,title,body,asset,created) VALUES(?,?,?,?,?)",(sid,x.title,x.body,x.asset,stamp()))
    return {"id":cur.lastrowid,"created":True}

@app.get("/api/scans/{sid}/investigation/notes")
def get_investigation_notes(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT * FROM investigation_notes WHERE scan_id=? ORDER BY id DESC",(sid,)).fetchall()
    return [dict(r) for r in rows]


# SCOPEZERO 10.6: repeatable differential checks. Credentials are transient request
# inputs only; they are never written to the database, audit events or response bodies.
class DifferentialIn(BaseModel):
    url: str = Field(min_length=8,max_length=2048)
    test_type: str = Field(pattern="^(xss|sqli|idor)$")
    parameter: str = Field(default="",max_length=100)
    identity_a_headers: dict[str,str] = Field(default_factory=dict)
    identity_b_headers: dict[str,str] = Field(default_factory=dict)
    authorized: bool = False

def _diff_headers(raw):
    allowed={"accept","user-agent","authorization","cookie","x-api-key","x-auth-token"}
    out={}
    for k,v in list((raw or {}).items())[:12]:
        if k.lower() not in allowed or len(str(v))>3000: continue
        if "\r" in str(v) or "\n" in str(v): continue
        out[k]=str(v)
    return out

def _diff_fetch(url, headers):
    try:
        r=requests.get(url,headers={"User-Agent":UA,**_diff_headers(headers)},
                       timeout=(3,7),allow_redirects=False,stream=True)
        chunks=b""
        for chunk in r.iter_content(2048):
            chunks+=chunk
            if len(chunks)>=10000:
                chunks=chunks[:10000]; break
        result=(r.status_code,chunks.decode("utf-8",errors="replace"),dict(r.headers))
        r.close()
        return result
    except requests.RequestException as exc:
        raise HTTPException(502,f"Differential request failed: {type(exc).__name__}")

def _store_diff(sid,url,typ,verdict,confidence,base,comp,evidence):
    with db() as c:
        cur=c.execute("""INSERT INTO differential_runs
          (scan_id,url,test_type,verdict,confidence,baseline_status,comparison_status,
           baseline_hash,comparison_hash,evidence,created)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
          (sid,url,typ,verdict,confidence,base[0],comp[0],
           sha256_text(base[1]),sha256_text(comp[1]),evidence,stamp()))
    return {"id":cur.lastrowid,"test_type":typ,"verdict":verdict,"confidence":confidence,
            "baseline_status":base[0],"comparison_status":comp[0],
            "baseline_sha256":sha256_text(base[1]),"comparison_sha256":sha256_text(comp[1]),
            "evidence":evidence,"credentials_persisted":False}

@app.post("/api/scans/{sid}/web-security/differential")
def differential_web_check(sid:int,x:DifferentialIn):
    scan=scan_row(sid)
    if not x.authorized: raise HTTPException(400,"Explicit authorization confirmation is required.")
    host=url_host(x.url)
    if not host: raise HTTPException(400,"Only valid HTTP(S) URLs are accepted.")
    if not (host==scan["domain"] or host.endswith("."+scan["domain"])):
        raise HTTPException(403,"Target is outside this scan root.")
    with db() as c:
        known=c.execute("SELECT 1 FROM assets WHERE scan_id=? AND host=? LIMIT 1",(sid,host)).fetchone()
    if not known or not validate_public_target(host):
        raise HTTPException(403,"Target must be a discovered asset resolving exclusively to public IP addresses.")
    from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
    parts=urlsplit(x.url)
    if parts.username or parts.password: raise HTTPException(400,"URL credentials are not accepted.")
    pairs=parse_qsl(parts.query,keep_blank_values=True)
    if len(pairs)>40: raise HTTPException(400,"Too many query parameters.")
    if x.test_type in ("xss","sqli") and (not x.parameter or x.parameter not in [k for k,v in pairs]):
        raise HTTPException(400,"Select an existing query parameter.")
    def make_url(newpairs):
        return urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(newpairs,doseq=True),""))
    if x.test_type=="idor":
        if not x.identity_a_headers or not x.identity_b_headers:
            raise HTTPException(400,"Provide two distinct authorized test-identity header profiles.")
        if _diff_headers(x.identity_a_headers)==_diff_headers(x.identity_b_headers):
            raise HTTPException(400,"Identity A and B header profiles must differ.")
        # Repeated baseline with identity A, then same object under identity B.
        a1=_diff_fetch(x.url,x.identity_a_headers)
        a2=_diff_fetch(x.url,x.identity_a_headers)
        b=_diff_fetch(x.url,x.identity_b_headers)
        stable=(a1[0]==a2[0] and sha256_text(a1[1])==sha256_text(a2[1]))
        different=(a1[0]!=b[0] or sha256_text(a1[1])!=sha256_text(b[1]))
        if stable and different:
            verdict="Access response differs by identity"
            confidence=65
            evidence="Same URL returned a stable response for identity A but a different status/body for identity B. Review object ownership and expected policy; this is not proof of IDOR."
        elif stable:
            verdict="No identity response difference observed"
            confidence=35
            evidence="Both authorized identities received matching status/body in this sample. This does not prove authorization is correct."
        else:
            verdict="Inconclusive: unstable baseline"
            confidence=15
            evidence="Repeated identity-A responses differed; response variance prevents reliable comparison."
        out=_store_diff(sid,x.url,"idor",verdict,confidence,a1,b,evidence)
    else:
        baseline1=_diff_fetch(x.url,{})
        baseline2=_diff_fetch(x.url,{})
        if baseline1[0]!=baseline2[0] or sha256_text(baseline1[1])!=sha256_text(baseline2[1]):
            raise HTTPException(409,"Baseline is unstable. Repeat after the target response becomes consistent.")
        if x.test_type=="xss":
            marker="SZ_DIFF_"+str(int(time.time()*1000))
            changed=[(k,marker if k==x.parameter else v) for k,v in pairs]
            comp=_diff_fetch(make_url(changed),{})
            raw=marker in comp[1]
            escaped=any(v in comp[1] for v in ("SZ_DIFF_"+str(int(time.time()*1000)),""))
            if raw:
                verdict="Reflected marker candidate"; confidence=65
                evidence="Unique inert marker reflected in response. Context, encoding and browser execution remain unverified."
            else:
                verdict="No inert marker reflection observed"; confidence=25
                evidence="Marker not present in captured response. This does not rule out DOM-based or context-specific XSS."
            out=_store_diff(sid,x.url,"xss",verdict,confidence,baseline1,comp,evidence)
        else:
            changed=[(k,(v+"'") if k==x.parameter else v) for k,v in pairs]
            comp=_diff_fetch(make_url(changed),{})
            low=comp[1].lower()
            signals=("sql syntax","sqlite error","mysql_fetch","unterminated quoted","odbc sql",
                     "ora-00933","sqlstate","postgresql error","you have an error in your sql")
            matched=[sig for sig in signals if sig in low]
            if matched:
                verdict="Database error signal"; confidence=70
                evidence="Quote-only differential response exposed database error indicators: "+", ".join(matched[:4])
            elif comp[0]!=baseline1[0] or sha256_text(comp[1])!=sha256_text(baseline1[1]):
                verdict="Response differential; manual SQLi review"; confidence=40
                evidence="Quote-only input changed status or response body versus a stable baseline; application behavior may explain the difference."
            else:
                verdict="No SQL error/differential signal"; confidence=25
                evidence="No recognized SQL error or response difference observed. Blind/time-based SQLi is not tested."
            out=_store_diff(sid,x.url,"sqli",verdict,confidence,baseline1,comp,evidence)
    _audit(sid,"differential_web_check",host,{"type":x.test_type,"result_id":out["id"],"credentials_persisted":False})
    return {**out,"limitations":["GET-only requests; redirects are not followed.","Authentication headers are transient and never stored.","No SQL extraction, time delays, executable XSS payloads or state-changing requests.","IDOR result is a response-difference signal requiring object-ownership validation.","A negative result does not prove absence of a vulnerability."]}

@app.get("/api/scans/{sid}/web-security/differential")
def differential_history(sid:int):
    scan_row(sid)
    with db() as c:
        rows=c.execute("""SELECT id,url,test_type,verdict,confidence,baseline_status,
          comparison_status,baseline_hash,comparison_hash,evidence,created
          FROM differential_runs WHERE scan_id=? ORDER BY id DESC LIMIT 100""",(sid,)).fetchall()
    return [dict(r) for r in rows]


# SCOPEZERO 10.7: encrypted, scan-scoped web test identity vault.
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from urllib.parse import urlsplit
import hashlib
_VAULT_KEY_PATH=Path(__file__).resolve().parents[1]/".session_vault.key"
def _vault():
    _VAULT_KEY_PATH.parent.mkdir(parents=True,exist_ok=True)
    if not _VAULT_KEY_PATH.exists():
        key=Fernet.generate_key()
        fd=os.open(str(_VAULT_KEY_PATH),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as f: f.write(key)
    try: return Fernet(_VAULT_KEY_PATH.read_bytes())
    except Exception: raise HTTPException(500,"Session vault key is unavailable; restore the key or re-create the vault.")
def _seal_headers(headers):
    allowed={"authorization","cookie","x-api-key","x-auth-token","accept","user-agent"}
    clean={}
    for k,v in list((headers or {}).items())[:12]:
        if k.lower() not in allowed or len(str(v))>3000 or "\r" in str(v) or "\n" in str(v): continue
        clean[k]=str(v)
    if not clean: raise HTTPException(400,"Provide at least one supported authentication or request header.")
    return _vault().encrypt(json.dumps(clean).encode()).decode()
def _open_headers(blob):
    try: return json.loads(_vault().decrypt(blob.encode()).decode())
    except (InvalidToken,ValueError): raise HTTPException(500,"Could not decrypt stored identity. Check the vault key backup.")
class IdentityIn(BaseModel):
    label:str=Field(min_length=2,max_length=80)
    host:str=Field(min_length=3,max_length=253)
    headers:dict[str,str]
class SessionCompareIn(BaseModel):
    url:str=Field(min_length=8,max_length=2048)
    identity_a:int
    identity_b:int
    method:str=Field(default="GET",pattern="^(GET|HEAD)$")
    finding_id:int|None=None
    authorized:bool=False
def _identity_row(sid,iid):
    with db() as c:r=c.execute("SELECT * FROM web_test_identities WHERE scan_id=? AND id=?",(sid,iid)).fetchone()
    if not r: raise HTTPException(404,"Test identity not found for this scan.")
    return dict(r)
def _session_fetch(url,method,headers):
    try:
        r=requests.request(method,url,headers={"User-Agent":UA,**headers},timeout=(4,8),allow_redirects=False,stream=True)
        body=b""
        if method!="HEAD":
            for ch in r.iter_content(2048):
                body+=ch
                if len(body)>=12000: body=body[:12000]; break
        result=(r.status_code,body.decode("utf-8",errors="replace"))
        r.close()
        return result
    except requests.RequestException as e: raise HTTPException(502,"Session verification request failed: "+type(e).__name__)
@app.post("/api/scans/{sid}/sessions/identities")
def create_test_identity(sid:int,x:IdentityIn):
    s=scan_row(sid); host=x.host.lower().strip().rstrip(".")
    if not (host==s["domain"] or host.endswith("."+s["domain"])): raise HTTPException(403,"Identity host is outside the scan root.")
    with db() as c:
        known=c.execute("SELECT 1 FROM assets WHERE scan_id=? AND host=? LIMIT 1",(sid,host)).fetchone()
        if not known: raise HTTPException(403,"Host must be a discovered asset.")
        try:
            cur=c.execute("""INSERT INTO web_test_identities(scan_id,label,host,encrypted_headers,created,updated)
                VALUES(?,?,?,?,?,?)""",(sid,x.label,host,_seal_headers(x.headers),stamp(),stamp()))
        except Exception: raise HTTPException(409,"Identity label already exists or could not be saved.")
    _audit(sid,"web_test_identity_created",host,{"identity_id":cur.lastrowid,"label":x.label,"secrets_encrypted":True})
    return {"id":cur.lastrowid,"label":x.label,"host":host,"credentials_returned":False}
@app.get("/api/scans/{sid}/sessions/identities")
def list_test_identities(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("SELECT id,label,host,created,updated,last_verified FROM web_test_identities WHERE scan_id=? ORDER BY id",(sid,)).fetchall()
    return [dict(r) for r in rows]
@app.put("/api/scans/{sid}/sessions/identities/{iid}")
def rotate_test_identity(sid:int,iid:int,x:IdentityIn):
    old=_identity_row(sid,iid)
    if x.label!=old["label"] or x.host.lower().rstrip(".")!=old["host"]: raise HTTPException(400,"Credential rotation must retain the identity label and host.")
    blob=_seal_headers(x.headers)
    with db() as c:c.execute("UPDATE web_test_identities SET encrypted_headers=?,updated=?,last_verified=NULL WHERE id=? AND scan_id=?",(blob,stamp(),iid,sid))
    _audit(sid,"web_test_identity_rotated",old["host"],{"identity_id":iid,"secret_values_logged":False})
    return {"id":iid,"label":old["label"],"rotated":True,"credentials_returned":False}
@app.post("/api/scans/{sid}/sessions/identities/{iid}/verify")
def verify_test_identity(sid:int,iid:int):
    ident=_identity_row(sid,iid); url="https://"+ident["host"]+"/"
    status,body=_session_fetch(url,"GET",_open_headers(ident["encrypted_headers"]))
    with db() as c:c.execute("UPDATE web_test_identities SET last_verified=? WHERE id=? AND scan_id=?",(stamp(),iid,sid))
    _audit(sid,"web_test_identity_verified",ident["host"],{"identity_id":iid,"status":status})
    return {"id":iid,"status":status,"body_sha256":hashlib.sha256(body.encode()).hexdigest(),"body_preview":body[:500],"note":"HTTP success does not prove authenticated identity; review application-specific account markers."}
@app.post("/api/scans/{sid}/sessions/compare")
def compare_test_sessions(sid:int,x:SessionCompareIn):
    s=scan_row(sid)
    if not x.authorized: raise HTTPException(400,"Explicit authorization confirmation required.")
    a=_identity_row(sid,x.identity_a); b=_identity_row(sid,x.identity_b)
    if a["id"]==b["id"]: raise HTTPException(400,"Choose two different test identities.")
    host=url_host(x.url)
    if not host or not (host==s["domain"] or host.endswith("."+s["domain"])): raise HTTPException(403,"URL host outside scan root.")
    if host not in (a["host"],b["host"]): raise HTTPException(403,"URL host must match both identity profiles' host.")
    if not validate_public_target(host): raise HTTPException(403,"Target must resolve exclusively to public IP addresses.")
    with db() as c:
        if not c.execute("SELECT 1 FROM assets WHERE scan_id=? AND host=?",(sid,host)).fetchone(): raise HTTPException(403,"Target is not a discovered asset.")
        if x.finding_id and not c.execute("SELECT 1 FROM findings WHERE id=? AND scan_id=?",(x.finding_id,sid)).fetchone(): raise HTTPException(404,"Finding does not belong to this scan.")
    ra=_session_fetch(x.url,x.method,_open_headers(a["encrypted_headers"]))
    rb=_session_fetch(x.url,x.method,_open_headers(b["encrypted_headers"]))
    ha=hashlib.sha256(ra[1].encode()).hexdigest(); hb=hashlib.sha256(rb[1].encode()).hexdigest()
    different=ra[0]!=rb[0] or ha!=hb
    verdict="Different identity responses — review authorization policy" if different else "Matching identity responses — policy review still required"
    evidence=f"{a['label']}: HTTP {ra[0]}, SHA-256 {ha}; {b['label']}: HTTP {rb[0]}, SHA-256 {hb}. Response bodies are not persisted."
    with db() as c:
        cur=c.execute("""INSERT INTO web_session_comparisons(scan_id,identity_a,identity_b,url,method,status_a,status_b,hash_a,hash_b,verdict,evidence,finding_id,created)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",(sid,a["id"],b["id"],x.url,x.method,ra[0],rb[0],ha,hb,verdict,evidence,x.finding_id,stamp()))
        cid=cur.lastrowid
    _audit(sid,"web_session_comparison",host,{"comparison_id":cid,"identity_a":a["id"],"identity_b":b["id"],"finding_id":x.finding_id})
    return {"id":cid,"verdict":verdict,"status_a":ra[0],"status_b":rb[0],"sha256_a":ha,"sha256_b":hb,"finding_id":x.finding_id,"evidence":evidence,"limitations":["GET/HEAD only; redirects are not followed.","Response bodies are not persisted; hashes and statuses are stored.","Differences are not proof of IDOR; validate ownership and expected policy.","A matching response does not prove authorization is correct."]}
@app.get("/api/scans/{sid}/sessions/comparisons")
def list_session_comparisons(sid:int):
    scan_row(sid)
    with db() as c: rows=c.execute("""SELECT c.*,a.label AS identity_a_label,b.label AS identity_b_label
      FROM web_session_comparisons c JOIN web_test_identities a ON a.id=c.identity_a
      JOIN web_test_identities b ON b.id=c.identity_b WHERE c.scan_id=? ORDER BY c.id DESC LIMIT 100""",(sid,)).fetchall()
    return [dict(r) for r in rows]
