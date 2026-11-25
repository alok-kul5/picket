# Audit policy success or failure auditing removed

**Rule:** [`rules/windows/defense_evasion/sec_audit_policy_disabled.yml`](../../rules/windows/defense_evasion/sec_audit_policy_disabled.yml) · **ATT&CK:** T1685.001 Disable or Modify Windows Event Log · **Level:** high

## What it detects
Event 4719 records every audit policy change. `AuditPolicyChanges` holds `%%8448` (success removed) and `%%8450` (failure removed). `auditpol /set /category:"Account Logon" /success:disable` or `auditpol /clear /y` produce exactly that. The rule ignores changes made as SYSTEM (`0x3e7`) or a machine account, which is how Group Policy refresh applies policy.

## Data source
Windows Security log (event 4719).

## Known false positives
Administrators trimming noisy subcategories by hand on a single server.

## Tuning notes
- The auditpol test raises 63 events for one command because `/clear` resets every subcategory. Deduplicate per host per minute in the SIEM.
- Per-user audit policy changes (`auditpol /set /user:`) also raise event 4912; add it if you use per-user policy.

## Test evidence
OTRF `auditpol_system_user_auditpolicy_modification`. The hard negative (a GPO refresh as SYSTEM) does not fire.
