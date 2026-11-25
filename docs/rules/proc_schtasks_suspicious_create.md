# Scheduled task created to run a script host or staged payload

**Rule:** [`rules/windows/persistence/proc_schtasks_suspicious_create.yml`](../../rules/windows/persistence/proc_schtasks_suspicious_create.yml) · **ATT&CK:** T1053.005 Scheduled Task · **Level:** medium

## What it detects
`schtasks /create` whose arguments run a script interpreter or LOLBin, an encoded command, a URL, or a file in `AppData`, `Users\Public` or a temp folder.

## Data source
Sysmon event 1. Security 4698 (task created) holds the full task XML and catches tasks created through the COM API.

## Known false positives
- IT maintenance tasks created from a management tool.
- **Measured:** one baseline hit. An Inno Setup installer creates a task from an XML file it staged in `%TEMP%\is-*.tmp\`. It stays in (budget `max_fp: 1`): attackers use `/XML` from temp in exactly the same way, and the fix belongs in an allow-list for the signed installer.

## Tuning notes
- Tasks created by `Register-ScheduledTask` or the COM API never run schtasks.exe. Add a 4698 rule that inspects `TaskContent`.
- A creating parent of `powershell.exe`, `mshta.exe` or `wmiprvse.exe` should raise severity.

## Test evidence
OTRF `empire_schtasks_creation_standard_user`.
