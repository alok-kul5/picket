# Binary padding with dd from /dev/zero or /dev/random

**Rule:** [`rules/linux/proc_dd_binary_padding.yml`](../../rules/linux/proc_dd_binary_padding.yml) · **ATT&CK:** T1027.001 Binary Padding · **Level:** low

## What it detects
`dd if=/dev/zero bs=1 count=1 >> payload` appends junk to a binary, so its hash no longer matches blocklists and its size may exceed scanner limits. The rule reads auditd `EXECVE` records: `a0=dd`, an `if=` of `/dev/zero`, `/dev/random` or `/dev/urandom`, and `bs=` / `count=` arguments.

## Data source
Linux auditd with an `execve` rule (for example `-a always,exit -F arch=b64 -S execve -k exec`).

## Known false positives
Swap file creation and disk wiping read from the same devices. The benign fixture `dd if=/dev/zero of=/swapfile bs=1M count=2048` does not match, but only because `of=` sits in `a2`, before `bs=`.

## Tuning notes
- This is the weakest rule in the set. auditd stores arguments by position (`a0`…`aN`), and Sigma has no "any argument" field, so reordering the arguments evades it. A SIEM-side rule over the joined argument string is more robust.
- auditd records do not show the shell redirection (`>>`) that makes this padding rather than a copy. Joining the `EXECVE` record with the `PATH` record for the output file, or looking for tiny `count=` values, is a better signal.

## Test evidence
OTRF `sh_binary_padding_dd`. 0 hits on 800 synthetic benign auditd records.
