# WDigest cleartext credential caching enabled

**Rule:** [`rules/windows/defense_evasion/reg_wdigest_logon_credential.yml`](../../rules/windows/defense_evasion/reg_wdigest_logon_credential.yml) · **ATT&CK:** T1112 Modify Registry, T1003.001 LSASS Memory · **Level:** high

## What it detects
Since Windows 8.1 / Server 2012 R2, LSASS no longer keeps WDigest cleartext passwords. Setting `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` to 1 turns that back on. Every user who logs on afterwards leaves a plaintext password for the next Mimikatz run.

## Data source
Sysmon event 13.

## Known false positives
Very old applications that need WDigest authentication.

## Tuning notes
- Writing 0 is the hardening baseline and does not match (hard negative included).
- This is an early warning. The dump that follows may come days later, so keep the alert open until the host is checked.

## Test evidence
OTRF `empire_wdigest_downgrade`. The upstream archive is truncated; `picket fetch` salvages the complete JSON lines from it.
