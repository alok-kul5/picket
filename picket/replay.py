"""Replay every dataset through every rule and score detection and false positives.

Writes build/results.json and exits non-zero if any rule misses an attack
scenario or goes over its false-positive budget.
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import yaml

from .engine import CompiledRule, load_rules
from .fetch import EVENTS, ROOT, manifest
from .normalize import read_jsonl

BUILD = ROOT / "build"
MAX_SAMPLES = 3


def techniques(rule: CompiledRule) -> list[str]:
    out = []
    for t in rule.rule.tags:
        if t.namespace == "attack" and t.name.lower().startswith("t"):
            out.append(t.name.upper())
    return out


def tactics(rule: CompiledRule) -> list[str]:
    return [t.name for t in rule.rule.tags if t.namespace == "attack" and not t.name.lower().startswith("t")]


def _sample(e: dict) -> dict:
    keep = ("Image", "CommandLine", "ParentImage", "TargetObject", "Details", "SourceImage", "GrantedAccess",
            "ImagePath", "ServiceName", "SubjectUserName", "eventName", "userAgent", "a0", "a1", "a2", "a3")
    return {k: str(e[k])[:200] for k in keep if e.get(k) not in (None, "")}


def replay(require_all: bool = True) -> dict:
    started = time.time()
    m = manifest()
    cases = yaml.safe_load((ROOT / "tests" / "replay_cases.yml").read_text(encoding="utf-8"))
    defaults = cases.get("defaults", {})
    rules = load_rules(ROOT / "rules")
    by_stem = {r.path.stem: r for r in rules}
    unknown = set(cases["rules"]) - set(by_stem)
    if unknown:
        raise SystemExit(f"replay_cases.yml names unknown rules: {sorted(unknown)}")

    by_channel: dict[str, list[CompiledRule]] = defaultdict(list)
    for r in rules:
        by_channel[r.channel].append(r)

    hits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    applicable: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    samples: dict[str, list[dict]] = defaultdict(list)
    datasets = {d["id"]: d for d in m["datasets"]}
    sizes: dict[str, int] = {}
    missing: list[str] = []

    for ds_id, ds in datasets.items():
        path = EVENTS / f"{ds_id}.jsonl.gz"
        if not path.exists():
            missing.append(ds_id)
            continue
        n = 0
        for e in read_jsonl(path):
            n += 1
            for r in by_channel.get(e.get("Channel", ""), ()):
                if not r.applies(e):
                    continue
                applicable[r.id][ds_id] += 1
                if r.predicate(e):
                    hits[r.id][ds_id] += 1
                    if ds["kind"] == "benign" and len(samples[r.id]) < MAX_SAMPLES:
                        samples[r.id].append({"dataset": ds_id, **_sample(e)})
        sizes[ds_id] = n

    results = []
    for stem, case in cases["rules"].items():
        r = by_stem[stem]
        case = {**defaults, **(case or {})}
        positives = []
        for ds_id in case["positives"]:
            n = hits[r.id].get(ds_id, 0)
            positives.append({
                "dataset": ds_id,
                "source": datasets[ds_id]["source"],
                "hits": n,
                "events": sizes.get(ds_id),
                "available": ds_id in sizes,
                "passed": n >= case["min_hits"],
            })
        scored = [p for p in positives if p["available"]]
        benign_ids = [d for d, ds in datasets.items() if ds["kind"] == "benign" and d in sizes]
        benign_events = sum(applicable[r.id].get(d, 0) for d in benign_ids)
        fp = sum(hits[r.id].get(d, 0) for d in benign_ids)
        other = {d: n for d, n in hits[r.id].items()
                 if datasets[d]["kind"] == "attack" and d not in case["positives"]}
        detected = sum(p["passed"] for p in scored)
        ok = (detected == len(scored) and fp <= case["max_fp"]
              and (not require_all or len(scored) == len(positives)))
        results.append({
            "id": r.id,
            "file": r.path.relative_to(ROOT).as_posix(),
            "slug": stem,
            "title": r.rule.title,
            "level": str(r.rule.level.name).lower() if r.rule.level else "",
            "status": str(r.rule.status.name).lower() if r.rule.status else "",
            "product": r.rule.logsource.product,
            "logsource": r.rule.logsource.category or r.rule.logsource.service,
            "techniques": techniques(r),
            "tactics": tactics(r),
            "positives": positives,
            "scenarios": len(scored),
            "detected": detected,
            "tpr": round(detected / len(scored), 4) if scored else None,
            "benign_events": benign_events,
            "fp": fp,
            "fp_budget": case["max_fp"],
            "fp_rate": (fp / benign_events) if benign_events else 0.0,
            "fp_samples": samples.get(r.id, []),
            "other_attack_hits": other,
            "passed": ok,
        })

    summary = {
        "rules": len(results),
        "passed": sum(r["passed"] for r in results),
        "scenarios": sum(r["scenarios"] for r in results),
        "scenarios_detected": sum(r["detected"] for r in results),
        "benign_events": sum(sizes.get(d, 0) for d, ds in datasets.items() if ds["kind"] == "benign"),
        "attack_events": sum(sizes.get(d, 0) for d, ds in datasets.items() if ds["kind"] == "attack"),
        "datasets": len(sizes),
        "missing_datasets": missing,
        "fp_total": sum(r["fp"] for r in results),
        "seconds": round(time.time() - started, 1),
    }
    out = {"summary": summary, "rules": results,
           "datasets": [{**datasets[d], "events": sizes.get(d)} for d in datasets]}
    BUILD.mkdir(exist_ok=True)
    (BUILD / "results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


def print_table(out: dict) -> None:
    print(f"{'rule':<46} {'detect':>7} {'fp':>4} {'benign ev':>10}  result")
    for r in out["rules"]:
        det = f"{r['detected']}/{r['scenarios']}"
        flag = "PASS" if r["passed"] else "FAIL"
        print(f"{r['slug'][:46]:<46} {det:>7} {r['fp']:>4} {r['benign_events']:>10,}  {flag}")
    s = out["summary"]
    print(f"\n{s['passed']}/{s['rules']} rules pass | {s['scenarios_detected']}/{s['scenarios']} attack scenarios detected"
          f" | {s['fp_total']} FP over {s['benign_events']:,} benign events | {s['seconds']}s")
    if s["missing_datasets"]:
        print("missing datasets (run `python -m picket fetch`):", ", ".join(s["missing_datasets"]))


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    out = replay(require_all="--allow-missing" not in argv)
    print_table(out)
    return 0 if out["summary"]["passed"] == out["summary"]["rules"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
