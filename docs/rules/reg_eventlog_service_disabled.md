# Windows Event Log service or autologger disabled via registry

**Rule:** [`rules/windows/defense_evasion/reg_eventlog_service_disabled.yml`](../../rules/windows/defense_evasion/reg_eventlog_service_disabled.yml) · **ATT&CK:** T1685.001 Disable or Modify Windows Event Log · **Level:** high

## What it detects
Setting `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Start` to 4 (Disabled) stops event logging after the next reboot, and setting an `EventLog-*` autologger `Start` to 0 drops a single channel. Both are quieter than stopping the service, which itself logs an event.

## Data source
Sysmon event 13.

## Known false positives
None expected. The service normally runs as Automatic (2); the hard-negative fixture writes 2 and does not fire.

## Tuning notes
- The OTRF sample also has hundreds of benign `Autologger\EventLog-*` writes by svchost with other values, which is why the autologger branch needs both `\Start` and `0`.
- An EventLog service that stops sending events altogether is the backstop for this rule. Monitor log-source silence in your SIEM.

## Test evidence
OTRF `cmd_disable_eventlog_service_startuptype_modification_via_registry`.
