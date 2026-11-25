# Firewall rule added or firewall disabled via netsh

**Rule:** [`rules/windows/defense_evasion/proc_netsh_firewall_allow.yml`](../../rules/windows/defense_evasion/proc_netsh_firewall_allow.yml) · **ATT&CK:** T1686.003 Windows Host Firewall · **Level:** medium

## What it detects
`netsh advfirewall firewall add rule ... action=allow`, legacy `netsh firewall add portopening|allowedprogram`, `... set allprofiles state off` and `opmode disable`. Attackers open a port for a backdoor listener or switch the firewall off before moving laterally.

## Data source
Sysmon event 1. Windows Firewall events 2004/2005 in *Microsoft-Windows-Windows Firewall With Advanced Security/Firewall* show the resulting rule and are a good second source.

## Known false positives
Applications that add their own exception at install or first run.

## Tuning notes
- **Measured:** the Windows 10 baseline had Dropbox adding an inbound allow rule for itself. A filter for parents under `Program Files` removed it. Attacker tooling rarely runs from there, but an installed RMM tool would be filtered too, so review that list.
- Show commands (`netsh advfirewall show allprofiles`) do not match.

## Test evidence
OTRF `cmd_netsh_fw_mod_open_ports`.
