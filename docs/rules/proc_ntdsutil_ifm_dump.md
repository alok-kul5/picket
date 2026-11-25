# NTDS.dit copy via ntdsutil Install From Media

**Rule:** [`rules/windows/credential_access/proc_ntdsutil_ifm_dump.yml`](../../rules/windows/credential_access/proc_ntdsutil_ifm_dump.yml) · **ATT&CK:** T1003.003 NTDS · **Level:** high

## What it detects
`ntdsutil "ac i ntds" "ifm" "create full C:\path" q q` makes a consistent copy of the Active Directory database and the SYSTEM hive. With both files an attacker can extract every domain password hash offline. The rule needs ntdsutil plus both `ifm` and `create` on the command line.

## Data source
Sysmon event 1 on domain controllers.

## Known false positives
Staging a new domain controller from IFM media is a real admin task, but a rare and scheduled one.

## Tuning notes
- Watch for the output folder being zipped or copied off the DC within minutes; that turns a medium-confidence event into a confirmed theft.
- Shadow-copy based theft (`vssadmin create shadow` + copy) does not use ntdsutil. Cover it with a separate VSS rule.

## Test evidence
OTRF `cmd_dumping_ntds_dit_file_ntdsutil`. 0 hits on baselines and on the `metadata cleanup` hard negative.
