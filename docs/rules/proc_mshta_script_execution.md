# Mshta executing inline script or a remote HTA

**Rule:** [`rules/windows/defense_evasion/proc_mshta_script_execution.yml`](../../rules/windows/defense_evasion/proc_mshta_script_execution.yml) · **ATT&CK:** T1218.005 Mshta · **Level:** high

## What it detects
`mshta.exe` is a signed host for HTML applications. Attackers use it to run script without dropping an executable: `mshta vbscript:Execute(...)`, `mshta javascript:GetObject('script:https://...')`, or an `.hta` opened from a browser cache or temp folder. The rule matches those command lines, and separately any shell or script host whose parent is mshta.

## Data source
Sysmon event 1.

## Known false positives
Legacy internal HTA tools. These usually live under `Program Files` or a file share; the hard-negative fixture runs a setup HTA from Program Files and does not fire.

## Tuning notes
- The child-process branch catches payloads even when the parent command line is obfuscated. It is the higher-value half; keep it even if you drop the first.
- If your estate never uses HTAs, block mshta with WDAC/AppLocker and keep this rule as a tripwire.

## Test evidence
OTRF `cmd_mshta_vbscript_execute_psh`, `cmd_mshta_javascript_getobject_sct` and EVTX-ATTACK-SAMPLES `sysmon_mshta_sharpshooter_stageless_meterpreter` (HTA opened from IE's cache).
