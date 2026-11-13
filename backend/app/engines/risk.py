def summarize(findings):
    counts={x:0 for x in ("Critical","High","Medium","Low","Info")}
    for f in findings: counts[f["severity"]]=counts.get(f["severity"],0)+1
    score=min(100,counts["Critical"]*25+counts["High"]*15+counts["Medium"]*8+counts["Low"]*3)
    return {"score":score,"label":"Elevated" if score>=50 else "Moderate" if score>=20 else "Low","severity_counts":counts}
