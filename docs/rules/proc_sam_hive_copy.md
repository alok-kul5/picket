# Registry hive copy for offline credential extraction

**Rule:** [`rules/windows/credential_access/proc_sam_hive_copy.yml`](../../rules/windows/credential_access/proc_sam_hive_copy.yml) · **ATT&CK:** T1003.002 Security Account Manager · **Level:** high

## What it detects
Two common ways to get the SAM, SYSTEM and SECURITY hives off a live host:
- `reg save HKLM\SAM sam` (or `export`), and
- `esentutl /y /vss C:\Windows\System32\config\SAM /d <dest>`, which copies the locked file through a volume shadow copy.

With SAM plus SYSTEM an attacker gets local NTLM hashes; SECURITY adds cached domain credentials and LSA secrets.

## Data source
Sysmon event 1.

## Known false positives
Backup or imaging scripts that export hives. They run on a schedule from a service account, which makes them easy to allow-list.

## Tuning notes
- `hklm\system` is matched with a trailing space so that exporting a subkey such as `HKLM\SYSTEM\CurrentControlSet\...` does not fire. The hard-negative fixtures check this.
- Add `ntds.dit` paths to the esentutl branch if your DCs are in scope (already included).

## Test evidence
OTRF `empire_shell_reg_dump_sam` and `cmd_sam_copy_esentutl`. 0 baseline hits.
