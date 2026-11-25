# UAC bypass via per-user shell open command hijack

**Rule:** [`rules/windows/privilege_escalation/reg_uac_bypass_shell_open_hijack.yml`](../../rules/windows/privilege_escalation/reg_uac_bypass_shell_open_hijack.yml) · **ATT&CK:** T1548.002 Bypass User Account Control · **Level:** high

## What it detects
Auto-elevating binaries look up file and protocol handlers under the user's own `HKCU\Software\Classes` before the machine-wide ones. Writing a command to `ms-settings\shell\open\command` (fodhelper, computerdefaults), `mscfile\shell\open\command` (eventvwr), `exefile\shell\runas\command` (sdclt) or `Folder\shell\open\command` makes the elevated binary run it without a prompt. The rule matches those keys inside a `_Classes` hive.

## Data source
Sysmon event 13.

## Known false positives
None known. Software registers these handlers machine-wide under HKLM. The hard negative is an HKLM write and does not fire.

## Tuning notes
- The attacker usually deletes the key seconds later. Sysmon 12 `DeleteKey` on the same path is a useful follow-up signal.
- A child process of `fodhelper.exe`, `eventvwr.exe` or `sdclt.exe` that is a shell confirms the bypass worked.

## Test evidence
OTRF `empire_uac_shellapi_fodhelper` and EVTX-ATTACK-SAMPLES `Sysmon_13_1_UAC_Bypass_EventVwrBypass` and `Sysmon_13_1_UACBypass_SDCLTBypass`. Three techniques, one rule.
