"""Build the ATT&CK Navigator layer and the dashboard data from the replay results.

Inputs:  build/results.json (replay), build/conversions.json (convert), ATT&CK STIX.
Outputs: coverage/picket-attack-layer.json and site/data/dashboard.json.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX = ROOT / ".cache" / "enterprise-attack.json"
REPO = "https://github.com/alok-kul5/picket"


def load_attack() -> dict:
    if not STIX.exists():
        STIX.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "picket-coverage/1.0"})
        with urllib.request.urlopen(req, timeout=300) as r:
            STIX.write_bytes(r.read())
    bundle = json.loads(STIX.read_text(encoding="utf-8"))
    version = "?"
    tactics = {}
    order: list[str] = []
    techniques = {}
    for o in bundle["objects"]:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        t = o.get("type")
        if t == "x-mitre-collection":
            version = o.get("x_mitre_version", version)
        elif t == "x-mitre-matrix":
            order = o.get("tactic_refs", [])
        elif t == "x-mitre-tactic":
            ext = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
            tactics[o["id"]] = {"id": ext, "short": o["x_mitre_shortname"], "name": o["name"]}
        elif t == "attack-pattern":
            refs = [r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
            if not refs or "enterprise-attack" not in o.get("x_mitre_domains", ["enterprise-attack"]):
                continue
            tid = refs[0]["external_id"]
            techniques[tid] = {
                "id": tid,
                "name": o["name"],
                "url": refs[0].get("url"),
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
                "sub": bool(o.get("x_mitre_is_subtechnique")),
            }
    ordered = [tactics[r] for r in order if r in tactics] or list(tactics.values())
    return {"version": version, "tactics": ordered, "techniques": techniques}


def _git_sha() -> str:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha[:7]
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "local"


def build() -> dict:
    results = json.loads((ROOT / "build" / "results.json").read_text(encoding="utf-8"))
    conv_path = ROOT / "build" / "conversions.json"
    conversions = json.loads(conv_path.read_text(encoding="utf-8")) if conv_path.exists() else {"summary": {}, "rules": {}}
    attack = load_attack()
    techs = attack["techniques"]

    rules_by_tech: dict[str, list[dict]] = defaultdict(list)
    for r in results["rules"]:
        for t in r["techniques"]:
            if t not in techs:
                raise SystemExit(f"{r['slug']}: {t} is not in ATT&CK {attack['version']}")
            rules_by_tech[t].append(r)

    # ---- Navigator layer ----
    layer_techs = []
    for tid, rs in sorted(rules_by_tech.items()):
        tested = all(x["passed"] for x in rs)
        layer_techs.append({
            "techniqueID": tid,
            "score": len(rs),
            "color": "",
            "comment": "; ".join(f"{x['title']} ({x['detected']}/{x['scenarios']} scenarios, {x['fp']} FP)" for x in rs),
            "enabled": True,
            "metadata": [{"name": "rule", "value": x["slug"]} for x in rs] + [{"name": "replay", "value": "pass" if tested else "fail"}],
            "showSubtechniques": True,
        })
        parent = tid.split(".")[0]
        if "." in tid and parent not in rules_by_tech:
            layer_techs.append({"techniqueID": parent, "showSubtechniques": True, "enabled": True})
    layer = {
        "name": "Picket detection coverage",
        "versions": {"attack": str(attack["version"]).split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{len(results['rules'])} Sigma rules, replay-tested against public attack telemetry. Score = number of rules covering the technique.",
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True, "aggregateFunction": "max"},
        "hideDisabled": False,
        "techniques": layer_techs,
        "gradient": {"colors": ["#fff1c1", "#ffb020", "#d9480f"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "covered by 1 rule", "color": "#fff1c1"}, {"label": "3+ rules", "color": "#d9480f"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0b0f14",
        "selectTechniquesAcrossTactics": True,
    }
    (ROOT / "coverage").mkdir(exist_ok=True)
    (ROOT / "coverage" / "picket-attack-layer.json").write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")

    # ---- matrix for the dashboard heatmap ----
    matrix = []
    for tac in attack["tactics"]:
        parents = sorted((t for t in techs.values() if not t["sub"] and tac["short"] in t["tactics"]), key=lambda t: t["name"])
        cells = []
        for p in parents:
            subs = sorted((t for t in techs.values() if t["sub"] and t["id"].startswith(p["id"] + ".")), key=lambda t: t["id"])
            covered_ids = [tid for tid in [p["id"], *[s["id"] for s in subs]] if tid in rules_by_tech]
            slugs = sorted({x["slug"] for tid in covered_ids for x in rules_by_tech[tid]})
            cells.append({
                "id": p["id"], "name": p["name"],
                "rules": slugs,
                "covered": [{"id": tid, "name": techs[tid]["name"]} for tid in covered_ids],
                "subs": len(subs),
            })
        matrix.append({"id": tac["id"], "short": tac["short"], "name": tac["name"], "techniques": cells,
                       "covered": sum(1 for c in cells if c["rules"])})

    covered_parents = {tid.split(".")[0] for tid in rules_by_tech}
    total_parents = sum(1 for t in techs.values() if not t["sub"])

    rules_out = []
    for r in results["rules"]:
        conv = conversions["rules"].get(r["slug"], {})
        rules_out.append({
            **r,
            "technique_names": {t: techs[t]["name"] for t in r["techniques"]},
            "queries": {k: v.get("query") for k, v in conv.items() if v.get("ok")},
            "query_errors": {k: v.get("error") for k, v in conv.items() if not v.get("ok")},
            "source_url": f"{REPO}/blob/main/{r['file']}",
            "doc_url": f"{REPO}/blob/main/docs/rules/{r['slug']}.md",
        })

    s = results["summary"]
    dashboard = {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "commit": _git_sha(),
        "repo": REPO,
        "attack_version": attack["version"],
        "summary": {
            **s,
            "techniques": len(rules_by_tech),
            "parent_techniques": len(covered_parents),
            "matrix_parent_total": total_parents,
            "tactics": sum(1 for m in matrix if m["covered"]),
            "tactic_total": len(matrix),
            "conversions": conversions["summary"],
        },
        "matrix": matrix,
        "rules": rules_out,
        "datasets": results["datasets"],
    }
    out = ROOT / "site" / "data"
    out.mkdir(parents=True, exist_ok=True)
    (out / "dashboard.json").write_text(json.dumps(dashboard), encoding="utf-8")
    (out / "picket-attack-layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return dashboard


def main(argv: list[str] | None = None) -> int:
    d = build()
    s = d["summary"]
    print(f"ATT&CK {d['attack_version']}: {s['techniques']} techniques ({s['parent_techniques']} parent) across "
          f"{s['tactics']}/{s['tactic_total']} tactics; layer at coverage/picket-attack-layer.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
