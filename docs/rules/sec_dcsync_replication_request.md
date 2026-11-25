# DCSync directory replication request by a user account

**Rule:** [`rules/windows/credential_access/sec_dcsync_replication_request.yml`](../../rules/windows/credential_access/sec_dcsync_replication_request.yml) · **ATT&CK:** T1003.006 DCSync · **Level:** high

## What it detects
DCSync tools (Mimikatz `lsadump::dcsync`, Impacket `secretsdump`, Covenant) pretend to be a domain controller and ask a real DC to replicate password data. On the DC this leaves event 4662 with access mask `0x100` (control access) and the GUID of *DS-Replication-Get-Changes* (`1131f6aa-…`), *Get-Changes-All* (`1131f6ad-…`) or *Get-Changes-In-Filtered-Set* (`89e95b76-…`). Real DCs replicate as their machine account (`DC01$`), so a user name here is suspicious.

## Data source
Windows Security log on domain controllers. Requires *Audit Directory Service Access* and an auditing SACL on the domain root object.

## Known false positives
Azure AD Connect (`MSOL_*`, `AAD_*`) and other identity sync accounts legitimately hold replication rights; they are filtered.

## Tuning notes
- List every account that holds replication rights (`Get-ADObject` on the domain root ACL) and allow-list only those, by SID not name, if you can.
- The event does not carry the source IP. Join on `SubjectLogonId` with 4624 to find where the request came from.

## Test evidence
OTRF Empire and Covenant DCSync captures and EVTX-ATTACK-SAMPLES `CA_DCSync_4662`. The hard negatives (a DC machine account and an `MSOL_` account) stay silent.
