# Run key persistence pointing at a script host or staging folder

**Rule:** [`rules/windows/persistence/reg_run_key_suspicious_value.yml`](../../rules/windows/persistence/reg_run_key_suspicious_value.yml) · **ATT&CK:** T1547.001 Registry Run Keys · **Level:** high

## What it detects
A value written under `...\CurrentVersion\Run` or `RunOnce` (HKLM, HKCU or WOW6432Node) whose data launches PowerShell, cmd, mshta, rundll32, regsvr32 or a WSH host, uses `-enc`, points at a URL, or starts a binary in a staging folder. It also flags a value with an empty name (`...\Run\`), a trick that hides the entry from some tools.

## Data source
Sysmon event 13.

## Known false positives
Updaters that register a script or rundll32 helper at logon. OneDrive's per-user Run value is filtered.

## Tuning notes
- Every Run key write is far too noisy (Defender, Teams and OneDrive write them all the time), so this rule only looks at suspicious data. The baselines hold 320k registry events and none match.
- Sysmon truncates long `Details` values. Encoded PowerShell is caught by the `powershell` term before the truncation point.

## Test evidence
OTRF `empire_persistence_registry_modification_run_keys_standard_user` and EVTX-ATTACK-SAMPLES `evasion_persis_hidden_run_keyvalue_sysmon_13`.
