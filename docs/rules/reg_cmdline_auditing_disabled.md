# Process command-line auditing disabled

**Rule:** [`rules/windows/defense_evasion/reg_cmdline_auditing_disabled.yml`](../../rules/windows/defense_evasion/reg_cmdline_auditing_disabled.yml) · **ATT&CK:** T1685.001 Disable or Modify Windows Event Log · **Level:** high

## What it detects
`ProcessCreationIncludeCmdLine_Enabled` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` controls whether event 4688 carries the command line. Setting it to 0 quietly removes the most useful field defenders have.

## Data source
Sysmon event 13.

## Known false positives
A Group Policy rollback. It should match a change ticket and arrive through the Group Policy client, not `reg.exe` from a user shell.

## Tuning notes
- The rule accepts both the Sysmon `DWORD (0x00000000)` form and a bare `0` so that older Winlogbeat captures and other agents match.
- Pair with an alert on 4719/4907 audit changes for the same host.

## Test evidence
OTRF `reg_cmd_process_commandline_logging_disabled`.
