# Suspicious LSASS process access with credential-read rights

**Rule:** [`rules/windows/credential_access/proc_access_lsass_credential_read.yml`](../../rules/windows/credential_access/proc_access_lsass_credential_read.yml) · **ATT&CK:** T1003.001 LSASS Memory · **Level:** high

## What it detects
Credential dumpers have to open a handle to `lsass.exe` with `PROCESS_VM_READ`. Mimikatz `sekurlsa::logonpasswords` asks for `0x1010`, older builds and many dumpers use `0x1410`, and tools that copy the whole process use full access. The rule flags those masks when the source is not a known Windows, security or Program Files component.

## Data source
Sysmon event 10 (ProcessAccess) with a config that logs access to `lsass.exe`.

## Known false positives
- EDR, AV and backup agents installed outside Program Files.
- Task Manager or Process Explorer used on purpose to make a dump (filtered).
- **Measured:** the Windows 10 baseline has 2 hits from `DropboxUpdate.exe` running out of `%TEMP%\GUM*.tmp\` with `0x1410`. They stay in on purpose (budget `max_fp: 2`): filtering an updater by its path in a user temp folder would let any binary dropped there do the same.

## Tuning notes
- The baselines drove three filters: `Sysmon64.exe` and `MRT.exe` (the Malicious Software Removal Tool scans LSASS), and `MsiExec.exe` with `0x1fffff`/`0x1410`. Without them the rule raised 53 alerts on clean hosts.
- The MsiExec filter is a known blind spot. If you can, replace path filters with a signer check from your EDR.
- `CallTrace` containing `dbghelp.dll` or `dbgcore.dll` is a strong extra signal for real dumps.

## Test evidence
OTRF `empire_mimikatz_logonpasswords` (PowerShell-hosted Mimikatz opening LSASS with `0x1010`) and EVTX-ATTACK-SAMPLES `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords`. It also fires on the comsvcs dump scenario, where rundll32 opens LSASS.
