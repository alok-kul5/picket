"""Regenerate the small synthetic fixtures in this folder.

These cover cases no public capture provides: benign Linux and AWS activity,
Windows look-alikes of each attack, and a couple of attack shapes that are
missing from the public datasets. Every record is made up and marked synthetic.
"""
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYS32 = "C:\\Windows\\System32\\"
random.seed(7)


def write(name: str, rows: list[dict]) -> None:
    path = HERE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps({**r, "_synthetic": True}) + "\n")


def proc(img: str, cli: str, parent: str) -> dict:
    return {"Channel": SYSMON, "EventID": 1, "Image": img, "CommandLine": cli, "ParentImage": parent, "User": "CORP\\it-admin"}


def linux_benign() -> list[dict]:
    cmds = [
        ["ls", "-la"], ["ps", "aux"], ["ip", "addr"], ["ip", "route"], ["ip", "link", "show"],
        ["dd", "if=/dev/sda", "of=/backup/sda.img", "bs=4M"],
        ["dd", "if=ubuntu.iso", "of=/dev/sdb", "bs=4M", "status=progress"],
        ["arp"], ["netstat", "-tulpn"], ["ss", "-tlnp"], ["grep", "-r", "TODO", "src"], ["git", "status"],
        ["systemctl", "status", "nginx"], ["journalctl", "-u", "sshd"], ["crontab", "-l"], ["df", "-h"],
        ["uname", "-a"], ["cat", "/etc/os-release"], ["tar", "-czf", "logs.tgz", "/var/log/nginx"],
        ["curl", "-s", "https://api.github.com"], ["apt", "list", "--upgradable"], ["ip", "-s", "link"],
    ]
    rows = []
    for i in range(400):
        c = random.choice(cmds)
        msg = f"audit(1700000000.{i:03d}:{5000 + i})"
        r = {"Channel": "linux/auditd", "type": "EXECVE", "msg": msg, "argc": str(len(c))}
        r.update({f"a{j}": a for j, a in enumerate(c)})
        rows.append(r)
        rows.append({"Channel": "linux/auditd", "type": "SYSCALL", "msg": msg, "syscall": "59", "success": "yes",
                     "comm": c[0], "exe": f"/usr/bin/{c[0]}", "uid": "1000"})
    return rows


def aws_benign() -> list[dict]:
    user = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev-alice", "accountId": "111122223333", "userName": "dev-alice"}
    role = {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/web-app-role/i-0a1b2c3d4e5f60718", "accountId": "111122223333"}
    ci = {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/github-deploy/GitHubActions", "accountId": "111122223333"}
    kinds = [
        ("s3.amazonaws.com", "GetObject", role, "aws-sdk-java/1.12.500 Linux/5.10.198-187.748.amzn2.x86_64 OpenJDK_64-Bit_Server_VM/17"),
        ("s3.amazonaws.com", "PutObject", role, "Boto3/1.28.0 Python/3.11.4 Linux/6.1.49-69.116.amzn2023.x86_64 Botocore/1.31.0"),
        ("s3.amazonaws.com", "ListObjects", user, "[aws-cli/2.13.0 Python/3.11.4 Darwin/22.6.0 exe/x86_64 prompt/off]"),
        ("ec2.amazonaws.com", "DescribeInstances", user, "console.ec2.amazonaws.com"),
        ("cloudtrail.amazonaws.com", "DescribeTrails", user, "console.amazonaws.com"),
        ("cloudtrail.amazonaws.com", "GetTrailStatus", ci, "aws-cli/2.13.0 Python/3.11.4 Linux/6.2.0-1012-azure"),
        ("cloudtrail.amazonaws.com", "LookupEvents", user, "console.amazonaws.com"),
        ("sts.amazonaws.com", "AssumeRoleWithWebIdentity", ci, "aws-sdk-js/2.1400.0"),
        ("iam.amazonaws.com", "ListRoles", user, "console.amazonaws.com"),
        ("s3.amazonaws.com", "HeadBucket", ci, "aws-cli/2.13.0 Python/3.11.4 Linux/6.2.0-1012-azure"),
    ]
    rows = []
    for _ in range(500):
        src, name, ident, ua = random.choice(kinds)
        rows.append({
            "Channel": "aws/cloudtrail", "eventSource": src, "eventName": name, "eventType": "AwsApiCall",
            "awsRegion": "eu-west-1", "userIdentity": ident, "userAgent": ua,
            "sourceIPAddress": f"10.0.{random.randint(0, 9)}.{random.randint(2, 250)}",
            "eventTime": f"2026-11-{random.randint(1, 24):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00Z",
        })
    return rows


def windows_hard_negatives() -> list[dict]:
    pf = "C:\\Program Files\\"
    vs = pf + "Microsoft Visual Studio\\2022\\Community\\"
    return [
        proc(SYS32 + "reg.exe", "reg save HKLM\\SOFTWARE\\Contoso software.hiv", SYS32 + "cmd.exe"),
        proc(SYS32 + "reg.exe", "reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip tcpip.reg", SYS32 + "cmd.exe"),
        proc(SYS32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", SYS32 + "explorer.exe"),
        proc(SYS32 + "mshta.exe", '"' + pf + 'Contoso\\Setup\\setup.hta"', SYS32 + "explorer.exe"),
        proc(SYS32 + "regsvr32.exe", 'regsvr32.exe /s "' + pf + 'Contoso\\addin.dll"', pf + "Contoso\\setup.exe"),
        proc(SYS32 + "net.exe", "net use Z: \\\\fileserver\\share", SYS32 + "cmd.exe"),
        proc(SYS32 + "net.exe", "net start spooler", SYS32 + "cmd.exe"),
        proc(SYS32 + "schtasks.exe", "schtasks /query /fo LIST", SYS32 + "cmd.exe"),
        proc(SYS32 + "schtasks.exe", 'schtasks /create /tn Backup /tr "' + pf + 'Veeam\\agent.exe" /sc daily', SYS32 + "cmd.exe"),
        proc(SYS32 + "sc.exe", "sc config wuauserv start= auto", SYS32 + "cmd.exe"),
        proc(SYS32 + "netsh.exe", "netsh advfirewall show allprofiles", SYS32 + "cmd.exe"),
        proc(SYS32 + "netsh.exe", "netsh interface ip show config", SYS32 + "cmd.exe"),
        proc(SYS32 + "wbem\\WMIC.exe", "wmic process list /format:csv", SYS32 + "cmd.exe"),
        proc(SYS32 + "bitsadmin.exe", "bitsadmin /list /allusers", SYS32 + "cmd.exe"),
        proc(SYS32 + "ntdsutil.exe", 'ntdsutil "metadata cleanup" q q', SYS32 + "cmd.exe"),
        proc(SYS32 + "cmstp.exe", "cmstp.exe", SYS32 + "explorer.exe"),
        proc(vs + "MSBuild\\Current\\Bin\\MSBuild.exe", "MSBuild.exe C:\\src\\app\\App.sln /p:Configuration=Release", vs + "Common7\\IDE\\devenv.exe"),
        proc(SYS32 + "cmd.exe", "C:\\Windows\\CCM\\ccmexec.exe /cmd ver", SYS32 + "wbem\\WmiPrvSE.exe"),
        {"Channel": SYSMON, "EventID": 13, "Image": pf + "Contoso\\update.exe",
         "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ContosoUpdate",
         "Details": '"' + pf + 'Contoso\\update.exe" /background'},
        {"Channel": SYSMON, "EventID": 13, "Image": "C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         "TargetObject": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
         "Details": '"C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'},
        {"Channel": SYSMON, "EventID": 13, "Image": "C:\\Windows\\regedit.exe",
         "TargetObject": "HKLM\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute",
         "Details": "{4ed3a719-cea8-4bd9-910d-e252f997afc2}"},
        {"Channel": SYSMON, "EventID": 13, "Image": SYS32 + "svchost.exe",
         "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start", "Details": "DWORD (0x00000002)"},
        {"Channel": SYSMON, "EventID": 13, "Image": SYS32 + "svchost.exe",
         "TargetObject": "HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
         "Details": "DWORD (0x00000000)"},
        {"Channel": SYSMON, "EventID": 10, "SourceImage": SYS32 + "svchost.exe",
         "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1410"},
        {"Channel": SYSMON, "EventID": 10, "SourceImage": pf + "CrowdStrike\\CSFalconService.exe",
         "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1fffff"},
        {"Channel": SYSMON, "EventID": 20, "Name": ' "SCM Event Log Consumer"', "Destination": "", "EventType": "WmiConsumerEvent"},
        {"Channel": "Security", "EventID": 4662, "SubjectUserName": "DC01$", "AccessMask": "0x100",
         "Properties": "%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"},
        {"Channel": "Security", "EventID": 4662, "SubjectUserName": "MSOL_8a7b6c5d4e3f", "AccessMask": "0x100",
         "Properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"},
        {"Channel": "Security", "EventID": 4719, "SubjectUserName": "WS01$", "SubjectLogonId": "0x3e7", "AuditPolicyChanges": "%%8448"},
        {"Channel": "System", "EventID": 7045, "ServiceName": "Contoso Agent", "ImagePath": '"' + pf + 'Contoso\\agent.exe" -service'},
    ]


def attack_net_discovery() -> list[dict]:
    return [
        proc(SYS32 + "net.exe", "net user", SYS32 + "cmd.exe"),
        proc(SYS32 + "net.exe", "net localgroup administrators", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"),
        proc(SYS32 + "net1.exe", 'C:\\Windows\\system32\\net1 group "Domain Admins" /domain', SYS32 + "net.exe"),
    ]


def attack_cloudtrail_tampering() -> list[dict]:
    who = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/ci-legacy", "accountId": "111122223333", "userName": "ci-legacy"}
    return [
        {"Channel": "aws/cloudtrail", "eventSource": "cloudtrail.amazonaws.com", "eventName": name, "eventType": "AwsApiCall",
         "awsRegion": "eu-west-1", "userIdentity": who, "sourceIPAddress": "203.0.113.50",
         "userAgent": "[aws-cli/1.18.136 Python/3.8.5 Linux/5.15.0-kali3-amd64 botocore/1.17.59]",
         "requestParameters": {"name": "org-trail"}}
        for name in ("StopLogging", "PutEventSelectors", "DeleteTrail")
    ]


if __name__ == "__main__":
    write("benign/linux_auditd.jsonl", linux_benign())
    write("benign/aws_cloudtrail.jsonl", aws_benign())
    write("benign/windows_hard_negatives.jsonl", windows_hard_negatives())
    write("attack/win_net_account_discovery.jsonl", attack_net_discovery())
    write("attack/aws_cloudtrail_tampering.jsonl", attack_cloudtrail_tampering())
