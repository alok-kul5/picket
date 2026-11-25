"""Lint every rule: pySigma's built-in validators plus house rules.

House rules: every rule has an ATT&CK technique tag, a description, references,
false positives, a level, a replay case and a write-up in docs/rules/.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.validators.core import validators as core_validators
from sigma.validation import SigmaValidator

ROOT = Path(__file__).resolve().parent.parent

# Validators that do not fit this repo's conventions.
SKIP = {
    "filename_length",  # SigmaHQ naming; this repo uses short descriptive names
}
REQUIRED = ("title", "id", "status", "description", "references", "author", "date", "tags", "logsource",
            "detection", "falsepositives", "level")
FILENAME = re.compile(r"^(proc|reg|sec|sys|wmi|aws)_[a-z0-9_]+\.yml$")


def lint() -> list[str]:
    problems: list[str] = []
    paths = sorted((ROOT / "rules").rglob("*.yml"))
    cases = yaml.safe_load((ROOT / "tests" / "replay_cases.yml").read_text(encoding="utf-8"))["rules"]

    coll = SigmaCollection.load_ruleset([str(p) for p in paths])
    validator = SigmaValidator([v for k, v in core_validators.items() if k not in SKIP])
    for issue in validator.validate_rules(coll):
        where = ", ".join(str(r.source.path.name) if r.source and r.source.path else r.title for r in issue.rules)
        problems.append(f"{where}: {type(issue).__name__}: {issue.description}")

    for p in paths:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        name = p.name
        for key in REQUIRED:
            if not doc.get(key):
                problems.append(f"{name}: missing '{key}'")
        if not FILENAME.match(name):
            problems.append(f"{name}: file name should look like proc_|reg_|sec_|sys_|wmi_|aws_<words>.yml")
        tags = doc.get("tags") or []
        if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in tags):
            problems.append(f"{name}: needs at least one ATT&CK technique tag")
        if doc.get("level") not in {"informational", "low", "medium", "high", "critical"}:
            problems.append(f"{name}: unknown level {doc.get('level')!r}")
        if p.stem not in cases:
            problems.append(f"{name}: no replay case in tests/replay_cases.yml")
        if not (ROOT / "docs" / "rules" / f"{p.stem}.md").exists():
            problems.append(f"{name}: no write-up at docs/rules/{p.stem}.md")
        text = p.read_text(encoding="utf-8")
        if "\t" in text:
            problems.append(f"{name}: contains tab characters")
    return problems


def main(argv: list[str] | None = None) -> int:
    problems = lint()
    n = len(list((ROOT / "rules").rglob("*.yml")))
    for msg in problems:
        print("LINT", msg)
    print(f"{n} rules linted, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
