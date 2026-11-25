# Bitsadmin download or job notification abuse

**Rule:** [`rules/windows/defense_evasion/proc_bitsadmin_transfer.yml`](../../rules/windows/defense_evasion/proc_bitsadmin_transfer.yml) · **ATT&CK:** T1197 BITS Jobs · **Level:** medium

## What it detects
`bitsadmin /transfer`, `/create`, `/addfile`, `/resume` or `/SetNotifyCmdLine`. BITS downloads files in the background through a trusted service, and a notify command line re-runs a payload whenever the job completes or errors, which gives persistence.

## Data source
Sysmon event 1. The *Microsoft-Windows-Bits-Client/Operational* log (events 3, 59, 60) gives the URL and is worth adding.

## Known false positives
Old installers that shell out to bitsadmin. Windows itself uses the BITS API, not the CLI. Read-only commands such as `bitsadmin /list` do not match.

## Tuning notes
- PowerShell's `Start-BitsTransfer` uses the same service without bitsadmin.exe. Cover it with a PowerShell script-block rule or the BITS client log.
- Raise severity when the URL points at a raw paste or file-sharing site.

## Test evidence
OTRF `cmd_bitsadmin_download_psh_script`. 0 baseline hits.
