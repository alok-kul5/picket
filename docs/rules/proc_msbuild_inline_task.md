# MSBuild building from a staging folder or spawning a shell

**Rule:** [`rules/windows/defense_evasion/proc_msbuild_inline_task.yml`](../../rules/windows/defense_evasion/proc_msbuild_inline_task.yml) · **ATT&CK:** T1127.001 MSBuild · **Level:** medium

## What it detects
MSBuild compiles and runs inline C# tasks from any project file, so `MSBuild.exe C:\Windows\Tasks\pshell.xml` runs attacker code through a Microsoft-signed developer tool. The rule fires on MSBuild building from writable staging folders (`\Windows\Tasks`, `\Windows\Temp`, `\Users\Public`, `\ProgramData`, user temp and Downloads) or from files with non-project extensions (`.xml`, `.txt`, `.dat`, `.log`), and on MSBuild spawning PowerShell, cmd, mshta or rundll32.

## Data source
Sysmon event 1.

## Known false positives
Build agents that keep work folders under ProgramData or temp, and build scripts that call cmd from an `Exec` task. A normal Visual Studio build of a `.sln` does not match (hard negative).

## Tuning notes
- Scope to non-developer machines with a host group if your build fleet is noisy.
- In the test capture MSBuild also spawns `csc.exe` from user temp to compile the inline task. That is normal MSBuild behaviour and is not used as a signal.

## Test evidence
OTRF `empire_msbuild_dcerpc_wmi_smb` (MSBuild launched remotely over WMI). Two hits: the build itself and the PowerShell child.
