# Service installed with a shell or script host image path

**Rule:** [`rules/windows/lateral_movement/sys_service_install_suspicious_path.yml`](../../rules/windows/lateral_movement/sys_service_install_suspicious_path.yml) · **ATT&CK:** T1569.002 Service Execution, T1021.002 SMB/Admin Shares · **Level:** high

## What it detects
PsExec-style tools copy nothing to disk or a tiny stub, then create a service over the `svcctl` named pipe whose image path is `%COMSPEC% /C ...` or a PowerShell one-liner. System event 7045 on the target records the service name and image path. The rule fires when that path contains a shell, script host, LOLBin, `ADMIN$` path or user-writable folder.

## Data source
Windows System log, event 7045 (Service Control Manager).

## Known false positives
Some installers briefly register a helper service that calls cmd.exe and remove it seconds later.

## Tuning notes
- **Measured:** an early version matched `\AppData\` and fired on Zoom's sharing service, which passes an AppData path as an argument. `\AppData\` was removed; the rule now keys on what runs, not on its arguments.
- Random 8-character service names (Impacket) or `PSEXESVC` are good extra signals.

## Test evidence
OTRF `empire_psexec_dcerpc_tcp_svcctl` and EVTX-ATTACK-SAMPLES `LM_Remote_Service02_7045` (services running cmd.exe and calc.exe).
