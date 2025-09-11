#!/usr/bin/env python3
import json
import os
import sys
import hashlib

SEVERITY_MAPPING = {
    "CRITICAL": ("error","10.0"),
    "HIGH": ("error","8.9"),
    "MEDIUM": ("warning","6.9"),
    "LOW": ("note","3.9"),
    "INFO": ("note","0.0"),
    "UNKNOWN": ("note","0.0"),
}

def norm(p: str) -> str:
    return p.lstrip("./").replace("\\", "/")

def main(src_json: str, out_sarif: str):
    if not os.path.isfile(src_json):
        print(f"ERROR: {src_json} not found", file=sys.stderr)
        sys.exit(2)
    with open(src_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    queries = data.get("queries", [])
    rules = []
    rule_index = {}
    results = []

    for q in queries:
        qid = q.get("query_id") or hashlib.sha256((q.get("query_name") or "").encode()).hexdigest()[:16]
        raw_sev = (q.get("severity") or "UNKNOWN").upper()
        level, secsev = SEVERITY_MAPPING.get(raw_sev, SEVERITY_MAPPING["UNKNOWN"])
        desc = q.get("description") or ""
        q_name = q.get("query_name") or qid

        if qid not in rule_index:
            rule_index[qid] = len(rules)
            rules.append({
                "id": qid,
                "name": q_name,
                "shortDescription": {"text": q_name},
                "fullDescription": {"text": desc},
                "help": {"text": desc, "markdown": f"**Description:** {desc}"},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "problem.severity": raw_sev,
                    "security-severity": secsev,
                    "tags": list(filter(None, ["kics", q.get("platform",""), q.get("category",""), raw_sev]))
                }
            })

        for fitem in q.get("files", []):
            file_name = norm(fitem.get("file_name", "UNKNOWN"))
            line = fitem.get("line") or 1
            if not isinstance(line, int) or line < 1:
                line = 1
            msg = f"{q_name} - {desc or 'No description'}"
            results.append({
                "ruleId": qid,
                "ruleIndex": rule_index[qid],
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_name},
                        "region": {"startLine": line}
                    }
                }],
                "properties": {
                    "kics_severity": raw_sev,
                    "security-severity": secsev,
                    "category": q.get("category",""),
                    "platform": q.get("platform",""),
                    "cwe": q.get("cwe","")
                }
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "KICS (custom severity mapped)",
                    "informationUri": "https://github.com/Checkmarx/kics",
                    "rules": rules
                }
            },
            "results": results
        }]
    }

    os.makedirs(os.path.dirname(out_sarif), exist_ok=True)
    with open(out_sarif, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"Custom SARIF written: {out_sarif} (rules={len(rules)} results={len(results)})")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: kics_json_to_sarif.py <results.json> <out.sarif>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
