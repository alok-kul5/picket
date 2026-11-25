# WMI permanent event subscription created

**Rule:** [`rules/windows/persistence/wmi_event_subscription.yml`](../../rules/windows/persistence/wmi_event_subscription.yml) · **ATT&CK:** T1546.003 WMI Event Subscription · **Level:** high

## What it detects
A permanent subscription has three parts: a filter (Sysmon 19), a consumer that runs a command or script (Sysmon 20), and a binding (Sysmon 21). The rule alerts on consumer and binding creation, which is the moment the persistence becomes active.

## Data source
Sysmon events 20 and 21.

## Known false positives
SCCM and some monitoring agents register consumers. The built-in `SCM Event Log Consumer` and `BVTConsumer` are filtered.

## Tuning notes
- The two clean baselines contain no WMI subscription events at all; the only benign one in the corpus is the SCM fixture. Treat every hit as worth a look.
- `CommandLineEventConsumer` and `ActiveScriptEventConsumer` are the dangerous consumer types. Alert higher when `Destination` holds an encoded command.

## Test evidence
OTRF `empire_wmi_local_event_subscriptions_elevated_user` (a CommandLineEventConsumer running encoded PowerShell) and EVTX-ATTACK-SAMPLES `wmighost_sysmon_20_21_1` (an ActiveScriptEventConsumer).
