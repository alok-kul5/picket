# Service binary path changed to a script host or staged payload

**Rule:** [`rules/windows/persistence/proc_sc_service_binpath_change.yml`](../../rules/windows/persistence/proc_sc_service_binpath_change.yml) · **ATT&CK:** T1543.003 Windows Service · **Level:** high

## What it detects
`sc config <svc> binPath= "powershell ..."` hijacks an existing service so that starting it runs the attacker's command as SYSTEM. This is quieter than installing a new service. The rule needs `sc.exe`, `config` and `binpath`, plus a shell, LOLBin or staging path in the new value.

## Data source
Sysmon event 1. A Sysmon 13 write to `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` catches the same change made without sc.exe.

## Known false positives
Installers that wrap a script as a service.

## Tuning notes
- In the test the attacker restores `fxssvc.exe` afterwards. That restore does not match, which is right, but alerting on any binPath change of a Microsoft service is a reasonable stricter variant.
- `sc config wuauserv start= auto` does not match (hard negative).

## Test evidence
OTRF `cmd_service_mod_fax`.
