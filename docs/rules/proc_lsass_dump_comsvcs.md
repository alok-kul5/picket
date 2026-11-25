# LSASS memory dump via comsvcs.dll MiniDump

**Rule:** [`rules/windows/credential_access/proc_lsass_dump_comsvcs.yml`](../../rules/windows/credential_access/proc_lsass_dump_comsvcs.yml) · **ATT&CK:** T1003.001 LSASS Memory · **Level:** high

## What it detects
`rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <file> full` writes a full memory dump of any process. It needs no extra tools, so it is a common way to dump LSASS once an attacker has local admin. The rule matches rundll32 (by path or original file name) whose command line names `comsvcs` and either the `MiniDump` export or its ordinal `#24`.

## Data source
Sysmon event 1 (process creation). Security 4688 with command-line auditing works too once fields are mapped.

## Known false positives
Close to none. Some in-house crash collectors call MiniDump, but they target application processes, not LSASS.

## Tuning notes
- Attackers rename `comsvcs.dll` or call it by ordinal. The `#24` branch covers the ordinal; a renamed DLL slips past, so pair this with the LSASS access rule, which sees the handle open whatever the DLL is called.
- To raise confidence, check that the PID argument is LSASS's PID on that host.

## Test evidence
OTRF `psh_lsass_memory_dump_comsvcs` and EVTX-ATTACK-SAMPLES `sysmon_10_1_memdump_comsvcs_minidump`. 0 hits on the clean baselines.
