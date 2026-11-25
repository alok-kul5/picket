"""Turn raw telemetry (OTRF JSON, EVTX, auditd, CloudTrail, CSV) into flat events.

Every event gets a ``Channel`` so rules can be routed by logsource:
Windows channels keep their real names; Linux auditd uses ``linux/auditd``
and AWS CloudTrail uses ``aws/cloudtrail``.
"""
from __future__ import annotations

import ast
import csv
import io
import json
import re
from pathlib import Path
from typing import Any, Iterator

Event = dict[str, Any]

KEEP_CHANNELS = {
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "System",
}


def _fix_ids(e: Event) -> Event:
    eid = e.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    try:
        e["EventID"] = int(eid)
    except (TypeError, ValueError):
        pass
    return e


def otrf_json(text: str) -> Iterator[Event]:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "eventSource" in e and "eventName" in e:
            e["Channel"] = "aws/cloudtrail"
            yield e
            continue
        if "Channel" not in e and "log_name" in e:
            # winlogbeat 6.x layout used by the older Mordor captures
            flat = dict(e.get("event_data") or {})
            flat.update(Channel=e["log_name"], EventID=e.get("event_id"), Hostname=e.get("computer_name"))
            e = flat
        e = _fix_ids(e)
        if e.get("Channel") in KEEP_CHANNELS:
            yield e


def evtx_records(data: bytes) -> Iterator[Event]:
    from evtx import PyEvtxParser

    parser = PyEvtxParser(io.BytesIO(data))
    for rec in parser.records_json():
        try:
            doc = json.loads(rec["data"])["Event"]
        except (KeyError, json.JSONDecodeError):
            continue
        system = doc.get("System", {})
        channel = system.get("Channel")
        if channel not in KEEP_CHANNELS:
            continue
        e: Event = {
            "Channel": channel,
            "EventID": system.get("EventID"),
            "Computer": system.get("Computer"),
            "Provider_Name": (system.get("Provider") or {}).get("#attributes", {}).get("Name"),
            "TimeCreated": (system.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime"),
        }
        data_block = doc.get("EventData") or doc.get("UserData") or {}
        if isinstance(data_block, dict):
            for k, v in data_block.items():
                if k == "#attributes":
                    continue
                if isinstance(v, dict) and len(data_block) == 1:
                    # UserData wraps fields one level deeper
                    for k2, v2 in v.items():
                        if k2 != "#attributes":
                            e[k2] = v2
                else:
                    e[k] = v
        yield _fix_ids(e)


_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def auditd_lines(text: str) -> Iterator[Event]:
    for line in text.splitlines():
        if not line.startswith("type="):
            continue
        e: Event = {"Channel": "linux/auditd"}
        for k, v in _KV.findall(line):
            e[k] = v[1:-1] if v.startswith('"') else v
        yield e


def honeybucket_csv(text: str) -> Iterator[Event]:
    """The OTRF S3 honey-bucket export is a CSV summary; map it onto CloudTrail names."""
    for row in csv.DictReader(io.StringIO(text)):
        try:
            identity = ast.literal_eval(row.get("User ID") or "{}")
            params = ast.literal_eval(row.get("Request Parameters") or "{}")
        except (ValueError, SyntaxError):
            identity, params = {}, {}
        yield {
            "Channel": "aws/cloudtrail",
            "eventSource": "s3.amazonaws.com",
            "eventType": row.get("Event Type"),
            "eventName": row.get("Event Name"),
            "eventTime": row.get("Event DateTime"),
            "sourceIPAddress": row.get("Source IP"),
            "userAgent": row.get("Request User Agent"),
            "userIdentity": identity,
            "requestParameters": params,
        }


def jsonl(text: str) -> Iterator[Event]:
    for line in text.splitlines():
        if line.strip():
            yield _fix_ids(json.loads(line))


def by_name(name: str, data: bytes) -> Iterator[Event]:
    lower = name.lower()
    if lower.endswith(".evtx"):
        yield from evtx_records(data)
        return
    text = data.decode("utf-8", errors="replace")
    if lower.endswith(".csv"):
        yield from honeybucket_csv(text)
    elif lower.endswith(".log"):
        yield from auditd_lines(text)
    elif lower.endswith((".json", ".jsonl")):
        yield from otrf_json(text)


def read_jsonl(path: Path) -> Iterator[Event]:
    import gzip

    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)
