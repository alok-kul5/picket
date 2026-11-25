"""Unit tests for the offline Sigma evaluator and the log normalisers."""
from pathlib import Path

import pytest

from picket.engine import SYSMON, compile_rule
from picket import normalize


def rule(tmp_path: Path, detection: str, logsource: str = "category: process_creation\n  product: windows") -> object:
    p = tmp_path / "proc_test_rule.yml"
    p.write_text(
        "title: test\n"
        "id: 00000000-0000-4000-8000-000000000001\n"
        "status: test\n"
        f"logsource:\n  {logsource}\n"
        f"detection:\n{detection}\n"
        "level: low\n",
        encoding="utf-8",
    )
    return compile_rule(p)


def proc(**fields):
    return {"Channel": SYSMON, "EventID": 1, **fields}


def test_endswith_is_case_insensitive(tmp_path):
    r = rule(tmp_path, "  sel:\n    Image|endswith: '\\rundll32.exe'\n  condition: sel")
    assert r.matches(proc(Image="C:\\WINDOWS\\System32\\RUNDLL32.EXE"))
    assert not r.matches(proc(Image="C:\\Windows\\System32\\rundll32.exe.bak"))


def test_contains_all_and_lists(tmp_path):
    r = rule(tmp_path, "  sel:\n    CommandLine|contains|all: ['ifm', 'create']\n  condition: sel")
    assert r.matches(proc(CommandLine='ntdsutil "ac i ntds" "ifm" "create full c:\\x" q q'))
    assert not r.matches(proc(CommandLine="ntdsutil ifm"))


def test_not_filter_and_one_of(tmp_path):
    det = (
        "  sel_a:\n    Image|endswith: '\\a.exe'\n"
        "  sel_b:\n    Image|endswith: '\\b.exe'\n"
        "  filter:\n    User: 'SYSTEM'\n"
        "  condition: 1 of sel_* and not filter"
    )
    r = rule(tmp_path, det)
    assert r.matches(proc(Image="c:\\b.exe", User="alice"))
    assert not r.matches(proc(Image="c:\\b.exe", User="system"))
    assert not r.matches(proc(Image="c:\\c.exe", User="alice"))


def test_regex_is_case_sensitive_by_default(tmp_path):
    r = rule(tmp_path, "  sel:\n    CommandLine|re: 'i-[0-9a-f]{8}$'\n  condition: sel")
    assert r.matches(proc(CommandLine="role/i-0a1b2c3d"))
    assert not r.matches(proc(CommandLine="role/I-0A1B2C3D"))


def test_numbers_and_logsource_routing(tmp_path):
    r = rule(tmp_path, "  sel:\n    EventID: 4719\n  condition: sel", logsource="product: windows\n  service: security")
    assert r.matches({"Channel": "Security", "EventID": 4719})
    assert not r.matches({"Channel": "System", "EventID": 4719})


def test_escaped_wildcard_is_literal(tmp_path):
    # Sigma: a backslash before * escapes it
    r = rule(tmp_path, "  sel:\n    CommandLine: 'a\\*b'\n  condition: sel")
    assert r.matches(proc(CommandLine="a*b"))
    assert not r.matches(proc(CommandLine="axxb"))


def test_wildcard_in_value(tmp_path):
    # a doubled backslash is a literal backslash, so the * after it stays a wildcard
    r = rule(tmp_path, "  sel:\n    TargetObject: 'HKLM\\\\*\\\\PortProxy\\\\*'\n  condition: sel",
             logsource="category: registry_set\n  product: windows")
    assert r.matches({"Channel": SYSMON, "EventID": 13, "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp"})
    assert not r.matches({"Channel": SYSMON, "EventID": 12, "TargetObject": "HKLM\\x\\PortProxy\\y"})


def test_dotted_fields_for_cloudtrail(tmp_path):
    r = rule(tmp_path, "  sel:\n    userIdentity.accountId: 'ANONYMOUS_PRINCIPAL'\n  condition: sel",
             logsource="product: aws\n  service: cloudtrail")
    assert r.matches({"Channel": "aws/cloudtrail", "userIdentity": {"accountId": "ANONYMOUS_PRINCIPAL"}})
    assert not r.matches({"Channel": "aws/cloudtrail", "userIdentity": {"accountId": "1234"}})


def test_auditd_line_parsing():
    line = 'type=EXECVE msg=audit(1604996384.965:93777): argc=4 a0="dd" a1="if=/dev/zero" a2="bs=1" a3="count=1"'
    (e,) = list(normalize.auditd_lines(line))
    assert e["Channel"] == "linux/auditd" and e["type"] == "EXECVE"
    assert (e["a0"], e["a1"], e["a3"]) == ("dd", "if=/dev/zero", "count=1")


def test_winlogbeat6_layout_is_flattened():
    text = '{"log_name":"Microsoft-Windows-Sysmon/Operational","event_id":13,"computer_name":"h","event_data":{"TargetObject":"x"}}'
    (e,) = list(normalize.otrf_json(text))
    assert e["EventID"] == 13 and e["TargetObject"] == "x" and e["Channel"].startswith("Microsoft-Windows-Sysmon")


def test_honeybucket_csv_maps_to_cloudtrail():
    csv_text = (
        "Event Type,Event Name,Request ID,User ID,Request Parameters,Alert,Event ID,Event DateTime,Alarm DateTime,Source IP,Request User Agent,Repeated Attempts\n"
        "AwsApiCall,ListObjects,R1,\"{'type': 'AWSAccount', 'principalId': '', 'accountId': 'ANONYMOUS_PRINCIPAL'}\","
        "\"{'bucketName': 'b'}\",x,e1,2022-02-18T17:34:57Z,t,1.2.3.4,curl,1\n"
    )
    (e,) = list(normalize.honeybucket_csv(csv_text))
    assert e["userIdentity"]["accountId"] == "ANONYMOUS_PRINCIPAL"
    assert e["requestParameters"]["bucketName"] == "b"


@pytest.mark.parametrize("path", sorted(Path(__file__).resolve().parent.parent.joinpath("rules").rglob("*.yml")))
def test_every_rule_compiles(path):
    assert compile_rule(path).predicate is not None
