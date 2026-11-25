# CMSTP installing a connection profile silently

**Rule:** [`rules/windows/defense_evasion/proc_cmstp_inf_execution.yml`](../../rules/windows/defense_evasion/proc_cmstp_inf_execution.yml) · **ATT&CK:** T1218.003 CMSTP, T1548.002 Bypass UAC · **Level:** high

## What it detects
`cmstp.exe /s file.inf` or `/au file.ini` installs a Connection Manager profile. A crafted profile's `RunPreSetupCommands` section runs any command, and the CMSTPLUA COM object it uses auto-elevates, giving a UAC bypass. The rule matches cmstp with the silent (`/s`), all-users (`/au`) or no-icon (`/ni`) switches.

## Data source
Sysmon event 1.

## Known false positives
VPN profile rollouts built with the Connection Manager Administration Kit, pushed by a deployment tool rather than a user shell.

## Tuning notes
- The UAC-bypass variant shows `dllhost.exe` (CMSTPLUA) spawning `cmd.exe` right after cmstp. Correlating the two raises confidence a lot.
- Running bare `cmstp.exe` (user opening the GUI) does not match; the hard negatives check this.

## Test evidence
OTRF `psh_cmstp_execution_bypassuac` and EVTX-ATTACK-SAMPLES `sysmon_1_13_11_cmstp_ini_uacbypass` (WinPwnage method 17).
