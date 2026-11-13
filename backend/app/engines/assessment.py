import requests, socket, ssl, dns.resolver
from ..config import UA
def attribution(host,root,ct_seen,records):
    if host==root: return 100,"Operator-supplied root",["Exact root domain supplied by operator"]
    ev=["Hostname is beneath supplied root domain"]
    if ct_seen: ev.append("Observed in Certificate Transparency data")
    if records.get("A") or records.get("AAAA"): ev.append("DNS address resolution observed")
    if records.get("CNAME"): ev.append("CNAME relationship observed")
    score=45+(25 if ct_seen else 0)+(20 if records.get("A") or records.get("AAAA") else 0)+(10 if records.get("CNAME") else 0)
    return min(score,95),"Candidate — verify",ev
def tls_info(host):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=2.5) as s:
            with ctx.wrap_socket(s,server_hostname=host) as t:
                cert=t.getpeercert()
                return {"issuer":cert.get("issuer"),"subject":cert.get("subject"),"not_after":cert.get("notAfter"),"protocol":t.version()}
    except Exception as e: return {"observation":"TLS metadata unavailable","reason":type(e).__name__}
def web_observations(host):
    out=[]
    try:
        r=requests.get(f"https://{host}/",headers={"User-Agent":UA},timeout=4,allow_redirects=False,stream=True)
        h={k.lower():v for k,v in r.headers.items()}
        ev={"url":f"https://{host}/","status":r.status_code,"server_header":h.get("server","not disclosed")}
        checks=[
          ("strict-transport-security","HSTS header not observed","Low",20,"Review HSTS suitability after confirming HTTPS coverage."),
          ("content-security-policy","Content-Security-Policy not observed","Info",10,"Review whether a Content Security Policy is suitable."),
          ("x-content-type-options","X-Content-Type-Options not observed","Info",10,"Consider nosniff where appropriate."),
          ("referrer-policy","Referrer-Policy not observed","Info",10,"Review referrer information leakage controls.")
        ]
        for key,title,sev,score,rec in checks:
            if key not in h:
                out.append({"category":"Web","title":title,"severity":sev,"score":score,
                  "description":f"The HTTPS response did not include {key}. This is an observation, not proof of a vulnerability.",
                  "evidence":ev,"recommendation":rec})
        r.close()
    except requests.RequestException: pass
    return out
def dns_observations(host,records):
    out=[]
    if host.count(".")==1:
        if not any(x.lower().startswith("v=spf1") for x in records.get("TXT",[])):
            out.append({"category":"DNS","title":"SPF record not observed","severity":"Low","score":20,
              "description":"No SPF TXT record was observed at the root domain.","evidence":records.get("TXT",[]),
              "recommendation":"If this domain sends email, configure SPF after reviewing authorized mail sources."})
        try:
            ans=dns.resolver.resolve("_dmarc."+host,"TXT",raise_on_no_answer=False)
            if not ans.rrset: raise LookupError()
        except Exception:
            out.append({"category":"DNS","title":"DMARC record not observed","severity":"Low","score":20,
              "description":"No DMARC TXT record was observed.","evidence":{"query":"_dmarc."+host},
              "recommendation":"If this domain sends email, configure DMARC after validating SPF and DKIM alignment."})
    return out
