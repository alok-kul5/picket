"""Print the replay results as a Markdown table (for the GitHub Actions job summary)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    path = ROOT / "build" / "results.json"
    if not path.exists():
        print("No replay results (the replay step did not run).")
        return
    out = json.loads(path.read_text(encoding="utf-8"))
    s = out["summary"]
    conv_path = ROOT / "build" / "conversions.json"
    conv = json.loads(conv_path.read_text(encoding="utf-8"))["summary"] if conv_path.exists() else {}
    print("## Picket replay\n")
    print(f"**{s['passed']}/{s['rules']} rules pass** · {s['scenarios_detected']}/{s['scenarios']} attack scenarios detected · "
          f"{s['fp_total']} FP over {s['benign_events']:,} benign events · {s['attack_events']:,} attack events\n")
    if conv:
        print(" · ".join(f"{v['label']}: {v['converted']}/{v['total']}" for v in conv.values()) + "\n")
    print("| Rule | Technique | Detected | FP / budget | Result |")
    print("|---|---|---|---|---|")
    for r in out["rules"]:
        print(f"| {r['title']} | {', '.join(r['techniques'])} | {r['detected']}/{r['scenarios']} | {r['fp']} / {r['fp_budget']} | "
              f"{'✅' if r['passed'] else '❌'} |")


if __name__ == "__main__":
    main()
