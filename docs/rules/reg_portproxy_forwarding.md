# Netsh PortProxy port forwarding configured

**Rule:** [`rules/windows/defense_evasion/reg_portproxy_forwarding.yml`](../../rules/windows/defense_evasion/reg_portproxy_forwarding.yml) · **ATT&CK:** T1090.001 Internal Proxy · **Level:** medium

## What it detects
`netsh interface portproxy add v4tov4 listenport=8001 connectaddress=10.0.0.5 connectport=3389` turns a host into a TCP relay, often to reach RDP on a segment the attacker cannot route to. netsh stores each forward as a value under `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\`, so the rule watches that key rather than the command line.

## Data source
Sysmon event 13 (registry value set).

## Known false positives
IPv6 transition setups and lab or developer machines that forward ports on purpose.

## Tuning notes
- The test sample uses the abbreviated syntax `netsh I p a v l=8001 ...`, which most command-line rules miss. Watching the registry gets around the abbreviations.
- Alert on the listen port too: 3389, 445 and 5985 as connect ports are the interesting ones.

## Test evidence
EVTX-ATTACK-SAMPLES `de_portforward_netsh_rdp_sysmon_13_1`. 0 hits across 320k registry events on clean hosts.
