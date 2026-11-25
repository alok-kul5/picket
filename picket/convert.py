"""Convert every rule with pySigma into Splunk SPL, Elastic Lucene and Microsoft KQL.

Queries land in build/queries/<backend>/<rule>.<ext>; build/conversions.json
records which rule converted for which backend. Splunk must succeed for every
rule; the other two are reported per rule because some log sources have no
mapping there (for example auditd in Defender XDR).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "queries"


def _backends() -> dict[str, dict]:
    return {
        "splunk": {
            "label": "Splunk SPL",
            "ext": "spl",
            "required": True,
            "make": lambda product: SplunkBackend(splunk_windows_pipeline()) if product == "windows" else SplunkBackend(),
        },
        "elastic": {
            "label": "Elastic Lucene (ECS)",
            "ext": "lucene",
            "required": False,
            "make": lambda product: LuceneBackend(ecs_windows()) if product == "windows" else LuceneBackend(),
        },
        "kql": {
            "label": "Microsoft Defender XDR KQL",
            "ext": "kql",
            "required": False,
            "make": lambda product: KustoBackend(microsoft_xdr_pipeline()) if product == "windows" else None,
        },
    }


def convert_all() -> dict:
    results: dict[str, dict] = {}
    backends = _backends()
    for path in sorted((ROOT / "rules").rglob("*.yml")):
        text_yaml = path.read_text(encoding="utf-8")
        rule = SigmaCollection.from_yaml(text_yaml).rules[0]
        product = rule.logsource.product or ""
        entry: dict[str, dict] = {}
        for name, b in backends.items():
            make: Callable = b["make"]
            backend = make(product)
            if backend is None:
                entry[name] = {"ok": False, "error": f"no {b['label']} mapping for {product}"}
                continue
            try:
                # pipelines rewrite rules in place, so every backend gets a fresh parse
                queries = backend.convert(SigmaCollection.from_yaml(text_yaml))
                text = "\n".join(str(q) for q in queries)
                dest = OUT / name / f"{path.stem}.{b['ext']}"
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text + "\n", encoding="utf-8")
                entry[name] = {"ok": True, "query": text}
            except Exception as exc:  # pySigma raises many specific errors
                entry[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
        results[path.stem] = entry
    summary = {
        name: {"label": b["label"], "converted": sum(r[name]["ok"] for r in results.values()), "total": len(results)}
        for name, b in backends.items()
    }
    out = {"summary": summary, "rules": results}
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "conversions.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    out = convert_all()
    failed = []
    for name, s in out["summary"].items():
        print(f"{s['label']:<28} {s['converted']}/{s['total']} rules")
    for slug, entry in out["rules"].items():
        for name, b in _backends().items():
            if b["required"] and not entry[name]["ok"]:
                failed.append(f"{slug} [{name}]: {entry[name]['error']}")
    for f in failed:
        print("FAIL", f)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
