"""A small, dependency-light Sigma evaluator for offline log replay.

pySigma parses each rule and expands modifiers, so a rule's condition becomes a
tree of AND / OR / NOT nodes over (field, value) leaves. This module compiles
that tree into plain Python predicates and runs them over normalised events.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
)

Event = dict[str, Any]
Predicate = Callable[[Event], bool]

# Which normalised events each Sigma logsource applies to.
# Keys are (product, category or service); values are (channel, event ids).
SYSMON = "Microsoft-Windows-Sysmon/Operational"
LOGSOURCES: dict[tuple[str, str], tuple[str, set[int] | None]] = {
    ("windows", "process_creation"): (SYSMON, {1}),
    ("windows", "network_connection"): (SYSMON, {3}),
    ("windows", "image_load"): (SYSMON, {7}),
    ("windows", "process_access"): (SYSMON, {10}),
    ("windows", "file_event"): (SYSMON, {11}),
    ("windows", "registry_add"): (SYSMON, {12}),
    ("windows", "registry_set"): (SYSMON, {13}),
    ("windows", "registry_event"): (SYSMON, {12, 13, 14}),
    ("windows", "wmi_event"): (SYSMON, {19, 20, 21}),
    ("windows", "security"): ("Security", None),
    ("windows", "system"): ("System", None),
    ("linux", "auditd"): ("linux/auditd", None),
    ("aws", "cloudtrail"): ("aws/cloudtrail", None),
}


def logsource_key(rule: SigmaRule) -> tuple[str, set[int] | None]:
    ls = rule.logsource
    key = (ls.product or "", ls.category or ls.service or "")
    if key not in LOGSOURCES:
        raise ValueError(f"{rule.title}: unsupported logsource {key}")
    return LOGSOURCES[key]


def get_field(event: Event, name: str) -> Any:
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _string_matcher(value: SigmaString) -> Callable[[Any], bool]:
    if not value.contains_special():
        plain = value.to_plain().lower()
        return lambda v: str(v).lower() == plain
    rx = re.compile(value.to_regex().regexp.to_plain(), re.IGNORECASE | re.DOTALL)
    return lambda v: rx.fullmatch(str(v)) is not None


def _regex_matcher(value: SigmaRegularExpression) -> Callable[[Any], bool]:
    flags = 0
    if SigmaRegularExpressionFlag.IGNORECASE in value.flags:
        flags |= re.IGNORECASE
    if SigmaRegularExpressionFlag.MULTILINE in value.flags:
        flags |= re.MULTILINE
    if SigmaRegularExpressionFlag.DOTALL in value.flags:
        flags |= re.DOTALL
    rx = re.compile(value.regexp.to_plain(), flags)
    return lambda v: rx.search(str(v)) is not None


def _number(v: Any) -> float | None:
    try:
        s = str(v)
        return float(int(s, 16)) if s.lower().startswith("0x") else float(s)
    except (TypeError, ValueError):
        return None


def _value_matcher(value: Any) -> Callable[[Any], bool]:
    if isinstance(value, SigmaString):
        return _string_matcher(value)
    if isinstance(value, SigmaRegularExpression):
        return _regex_matcher(value)
    if isinstance(value, SigmaNumber):
        target = float(value.number)
        return lambda v: _number(v) == target
    if isinstance(value, SigmaBool):
        return lambda v: str(v).lower() == str(value.boolean).lower()
    if isinstance(value, SigmaCIDRExpression):
        net = value.network

        def cidr(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return cidr
    if isinstance(value, SigmaCompareExpression):
        n = float(value.number.number)
        op = value.op
        ops = {
            SigmaCompareExpression.CompareOperators.LT: lambda x: x < n,
            SigmaCompareExpression.CompareOperators.LTE: lambda x: x <= n,
            SigmaCompareExpression.CompareOperators.GT: lambda x: x > n,
            SigmaCompareExpression.CompareOperators.GTE: lambda x: x >= n,
        }
        f = ops[op]
        return lambda v: (x := _number(v)) is not None and f(x)
    raise TypeError(f"unsupported Sigma value type {type(value).__name__}")


def _compile(node: Any) -> Predicate:
    if isinstance(node, ConditionAND):
        parts = [_compile(a) for a in node.args]
        return lambda e: all(p(e) for p in parts)
    if isinstance(node, ConditionOR):
        parts = [_compile(a) for a in node.args]
        return lambda e: any(p(e) for p in parts)
    if isinstance(node, ConditionNOT):
        inner = _compile(node.args[0])
        return lambda e: not inner(e)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        name, value = node.field, node.value
        if isinstance(value, SigmaNull):
            return lambda e: get_field(e, name) in (None, "")
        if isinstance(value, SigmaExists):
            want = value.exists
            return lambda e: (get_field(e, name) is not None) == want
        if isinstance(value, SigmaFieldReference):
            other = value.field
            return lambda e: get_field(e, name) is not None and str(get_field(e, name)).lower() == str(get_field(e, other)).lower()
        m = _value_matcher(value)
        return lambda e: any(m(v) for v in _as_list(get_field(e, name)))
    if isinstance(node, ConditionValueExpression):
        m = _value_matcher(node.value)
        return lambda e: any(m(v) for v in e.values() if isinstance(v, (str, int)))
    raise TypeError(f"unsupported condition node {type(node).__name__}")


@dataclass
class CompiledRule:
    rule: SigmaRule
    path: Path
    channel: str
    event_ids: set[int] | None
    predicate: Predicate
    hits: list[Event] = field(default_factory=list)

    @property
    def id(self) -> str:
        return str(self.rule.id)

    def applies(self, event: Event) -> bool:
        if event.get("Channel") != self.channel:
            return False
        return self.event_ids is None or event.get("EventID") in self.event_ids

    def matches(self, event: Event) -> bool:
        return self.applies(event) and self.predicate(event)


def compile_rule(path: Path) -> CompiledRule:
    rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
    channel, ids = logsource_key(rule)
    conds = [_compile(c.parsed) for c in rule.detection.parsed_condition]
    pred: Predicate = conds[0] if len(conds) == 1 else (lambda e: any(c(e) for c in conds))
    return CompiledRule(rule, path, channel, ids, pred)


def load_rules(root: Path) -> list[CompiledRule]:
    return [compile_rule(p) for p in sorted(root.rglob("*.yml"))]


def run(rules: Iterable[CompiledRule], events: Iterable[Event]) -> dict[str, int]:
    """Count matches per rule id over an event stream."""
    rules = list(rules)
    by_channel: dict[str, list[CompiledRule]] = {}
    for r in rules:
        by_channel.setdefault(r.channel, []).append(r)
    counts = {r.id: 0 for r in rules}
    for e in events:
        for r in by_channel.get(e.get("Channel", ""), ()):
            if r.matches(e):
                counts[r.id] += 1
    return counts
