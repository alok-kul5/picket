# ARP cache or neighbour table enumeration

**Rule:** [`rules/linux/proc_arp_cache_discovery.yml`](../../rules/linux/proc_arp_cache_discovery.yml) · **ATT&CK:** T1018 Remote System Discovery · **Level:** informational

## What it detects
`arp -a` / `arp -n` and `ip neigh` print the hosts this machine has recently talked to. That lists neighbours without sending scan traffic.

## Data source
Linux auditd `EXECVE` records.

## Known false positives
Network troubleshooting by admins.

## Tuning notes
- Informational on its own. Use it as one input to a discovery-burst correlation (several of `id`, `whoami`, `ip a`, `arp -a`, `cat /etc/passwd` within minutes from one session).
- Bare `arp` without flags does not match (benign fixture).

## Test evidence
OTRF `sh_arp_cache`.
