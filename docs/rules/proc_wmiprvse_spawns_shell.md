# WMI provider host spawning a shell or script host

**Rule:** [`rules/windows/lateral_movement/proc_wmiprvse_spawns_shell.yml`](../../rules/windows/lateral_movement/proc_wmiprvse_spawns_shell.yml) · **ATT&CK:** T1047 Windows Management Instrumentation · **Level:** high

## What it detects
Remote `Win32_Process.Create` (wmic `/node:`, `Invoke-WmiMethod`, Impacket `wmiexec`, Empire `invoke_wmi`) makes `WmiPrvSE.exe` on the target the parent of whatever runs. A shell or script host under WmiPrvSE is rare in normal operation.

## Data source
Sysmon event 1.

## Known false positives
SCCM and some RMM tools run scripts through WMI. Commands under `\Windows\CCM\` are filtered.

## Tuning notes
- Pair with a 4624 type 3 logon on the same host just before the process starts to separate remote use from local scripts.
- This rule also fired on the MSBuild and WMI-subscription scenarios, where the attack chain used WMI too. That is expected overlap, reported on the dashboard as other-scenario hits.

## Test evidence
OTRF `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod`.
