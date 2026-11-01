"""SBOM Sleuth: offline CycloneDX/SPDX JSON metadata and reference checks."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from dataclasses import asdict, dataclass
from typing import Any

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    component: str
    message: str
    def to_dict(self) -> dict[str,str]: return asdict(self)

def license_present(value: Any) -> bool:
    if value is None: return False
    if isinstance(value,str): return value.strip().upper() not in {"","NONE","NOASSERTION"}
    if isinstance(value,list): return any(license_present(v) for v in value)
    if isinstance(value,dict):
        if "license" in value: return license_present(value["license"])
        return bool(value.get("id") or value.get("name") or value.get("expression"))
    return False

def identity(item: dict[str,Any], spdx: bool=False) -> str:
    if spdx:
        refs=item.get("externalRefs",[])
        purls=[r.get("referenceLocator") for r in refs if isinstance(r,dict) and str(r.get("referenceType","")).lower()=="purl"] if isinstance(refs,list) else []
        purl=next((p for p in purls if p),None)
    else: purl=item.get("purl")
    if purl: return "purl:"+str(purl).strip().lower()
    name=str(item.get("name") or "unknown").strip().lower()
    version=str(item.get("versionInfo" if spdx else "version") or "").strip().lower()
    return f"name:{name}@{version}"

def analyze_cyclonedx(doc: dict[str,Any]) -> tuple[list[Finding],int]:
    components=doc.get("components",[])
    if not isinstance(components,list): raise ValueError("CycloneDX components must be an array.")
    findings=[]; known={str(c["bom-ref"]) for c in components if isinstance(c,dict) and c.get("bom-ref")}; seen={}
    for i,c in enumerate(components,1):
        if not isinstance(c,dict):
            findings.append(Finding("SB000","high",f"component[{i}]","Component entry is not an object.")); continue
        name=str(c.get("name") or f"component[{i}]")
        if not c.get("version"): findings.append(Finding("SB001","high",name,"Component has no version."))
        if not license_present(c.get("licenses")): findings.append(Finding("SB002","medium",name,"No declared license metadata found."))
        if not c.get("purl"): findings.append(Finding("SB003","medium",name,"No package URL (purl) found."))
        key=identity(c)
        if key in seen: findings.append(Finding("SB004","medium",name,f"Duplicate identity also used by '{seen[key]}'."))
        else: seen[key]=name
    deps=doc.get("dependencies",[])
    if not isinstance(deps,list): raise ValueError("CycloneDX dependencies must be an array.")
    for dep in deps:
        if not isinstance(dep,dict): continue
        refs=[dep.get("ref")]+(dep.get("dependsOn") or [])
        for ref in refs:
            if ref and ref not in known: findings.append(Finding("SB005","high",str(ref),"Dependency references an undeclared bom-ref."))
    return findings,len(components)

def analyze_spdx(doc: dict[str,Any]) -> tuple[list[Finding],int]:
    packages=doc.get("packages",[])
    if not isinstance(packages,list): raise ValueError("SPDX packages must be an array.")
    known={str(p["SPDXID"]) for p in packages if isinstance(p,dict) and p.get("SPDXID")}
    if doc.get("SPDXID"): known.add(str(doc["SPDXID"]))
    findings=[]; seen={}
    for i,p in enumerate(packages,1):
        if not isinstance(p,dict):
            findings.append(Finding("SB000","high",f"package[{i}]","Package entry is not an object.")); continue
        name=str(p.get("name") or f"package[{i}]")
        if not p.get("versionInfo"): findings.append(Finding("SB001","high",name,"Package has no versionInfo."))
        if not license_present(p.get("licenseDeclared")): findings.append(Finding("SB002","medium",name,"No declared license metadata found."))
        refs=p.get("externalRefs",[])
        purls=[r.get("referenceLocator") for r in refs if isinstance(r,dict) and str(r.get("referenceType","")).lower()=="purl"] if isinstance(refs,list) else []
        if not any(purls): findings.append(Finding("SB003","medium",name,"No package URL external reference found."))
        key=identity(p,True)
        if key in seen: findings.append(Finding("SB004","medium",name,f"Duplicate identity also used by '{seen[key]}'."))
        else: seen[key]=name
    relationships=doc.get("relationships",[])
    if not isinstance(relationships,list): raise ValueError("SPDX relationships must be an array.")
    for rel in relationships:
        if not isinstance(rel,dict): continue
        for field in ("spdxElementId","relatedSpdxElement"):
            ref=rel.get(field)
            if ref and ref not in known: findings.append(Finding("SB005","high",str(ref),f"Relationship references unknown SPDX ID in {field}."))
    return findings,len(packages)

def analyze_document(doc: Any) -> dict[str,Any]:
    if not isinstance(doc,dict): raise ValueError("SBOM root must be a JSON object.")
    if str(doc.get("bomFormat","")).lower()=="cyclonedx": fmt="CycloneDX"; findings,count=analyze_cyclonedx(doc)
    elif "spdxVersion" in doc: fmt="SPDX"; findings,count=analyze_spdx(doc)
    else: raise ValueError("Unsupported SBOM: expected bomFormat='CycloneDX' or spdxVersion.")
    findings.sort(key=lambda f:(f.rule_id,f.component,f.message))
    return {"format":fmt,"component_count":count,"finding_count":len(findings),"findings":[f.to_dict() for f in findings]}

def analyze_text(text: str) -> dict[str,Any]:
    try: doc=json.loads(text)
    except json.JSONDecodeError as exc: raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    return analyze_document(doc)

def main(argv: list[str]|None=None) -> int:
    parser=argparse.ArgumentParser(description="Inspect CycloneDX and SPDX JSON SBOM files offline.")
    parser.add_argument("file",type=Path); parser.add_argument("--format",choices=("text","json"),default="text")
    parser.add_argument("--strict",action="store_true",help="Return 1 when findings exist.")
    args=parser.parse_args(argv)
    try: report=analyze_text(args.file.read_text(encoding="utf-8"))
    except (OSError,ValueError) as exc: print(f"sbom-sleuth: {exc}",file=sys.stderr); return 2
    if args.format=="json": print(json.dumps(report,indent=2))
    else:
        print(f"{args.file}: SBOM format: {report['format']}")
        for f in report["findings"]: print(f"[{f['severity']}] {f['rule_id']} {f['component']}: {f['message']}")
        print(f"Summary: {report['finding_count']} finding(s) across {report['component_count']} component(s).")
    return 1 if args.strict and report["finding_count"] else 0

if __name__=="__main__": raise SystemExit(main())
