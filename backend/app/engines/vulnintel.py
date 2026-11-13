import requests, os, re
from ..config import UA
TIMEOUT=12
def kev_catalog():
    u="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r=requests.get(u,headers={"User-Agent":UA},timeout=TIMEOUT);r.raise_for_status()
    return {x["cveID"]:x for x in r.json().get("vulnerabilities",[])}
def epss_scores(cves):
    out={}
    for i in range(0,len(cves),100):
        r=requests.get("https://api.first.org/data/v1/epss",params={"cve":",".join(cves[i:i+100])},
          headers={"User-Agent":UA},timeout=TIMEOUT);r.raise_for_status()
        for x in r.json().get("data",[]):
            try:out[x["cve"]]=float(x["epss"])
            except Exception:pass
    return out
def nvd_lookup(cve):
    h={"User-Agent":UA}
    if os.getenv("NVD_API_KEY"):h["apiKey"]=os.getenv("NVD_API_KEY")
    r=requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params={"cveId":cve},headers=h,timeout=TIMEOUT)
    r.raise_for_status();items=r.json().get("vulnerabilities",[])
    if not items:return None
    c=items[0]["cve"];metrics=c.get("metrics",{});cvss=None;severity="Unknown"
    for group in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        if metrics.get(group):
            d=metrics[group][0].get("cvssData",{});cvss=d.get("baseScore");severity=d.get("baseSeverity",severity);break
    desc=next((x.get("value","") for x in c.get("descriptions",[]) if x.get("lang")=="en"),"")
    return {"cve":cve,"description":desc,"cvss":cvss,"severity":severity}
def correlate(cves):
    cves=sorted({x.upper() for x in cves if re.fullmatch(r"CVE-\\d{4}-\\d{4,}",x,re.I)})
    if not cves:return []
    kev=kev_catalog()
    try:epss=epss_scores(cves)
    except Exception:epss={}
    out=[]
    for cve in cves:
        try:item=nvd_lookup(cve) or {"cve":cve,"description":"No NVD record returned","cvss":None,"severity":"Unknown"}
        except Exception as e:item={"cve":cve,"description":"NVD enrichment unavailable: "+type(e).__name__,"cvss":None,"severity":"Unknown"}
        item.update({"epss":epss.get(cve),"kev":cve in kev,"kev_due_date":kev.get(cve,{}).get("dueDate"),
          "source":"NVD / FIRST EPSS / CISA KEV",
          "confidence":"CVE identifier observed in IP intelligence; software applicability is unverified"})
        out.append(item)
    return out
