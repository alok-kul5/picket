# Local account and group discovery

**Rule:** [`rules/windows/discovery/proc_account_group_discovery.yml`](../../rules/windows/discovery/proc_account_group_discovery.yml) · **ATT&CK:** T1087.001 Local Account, T1069.001 Local Groups · **Level:** low

## What it detects
`net user`, `net localgroup administrators`, `net group "Domain Admins" /domain` (including the `net1.exe` child that net.exe spawns), and runs of the Seatbelt host survey tool with its `-group=user|system|all` presets.

## Data source
Sysmon event 1.

## Known false positives
Helpdesk staff and admin scripts check group membership all the time, which is why the level is low. `net use` and `net start` do not match.

## Tuning notes
- On its own this is a hunting lead, not an alert. Raise it when several discovery commands run from the same parent within a few minutes, or when the parent is an Office app, mshta or WmiPrvSE.
- The OTRF Empire `net user` / `net localgroup` captures are flagged by Windows Defender on download, so local runs replay a synthetic fixture with the same command lines.

## Test evidence
OTRF `cmd_seatbelt_group_user` and the synthetic `fx_win_net_discovery` fixture.
