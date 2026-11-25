# CloudTrail logging stopped, deleted or redirected

**Rule:** [`rules/cloud/aws_cloudtrail_logging_tampering.yml`](../../rules/cloud/aws_cloudtrail_logging_tampering.yml) · **ATT&CK:** T1685.002 Disable or Modify Cloud Log · **Level:** high

## What it detects
`StopLogging`, `DeleteTrail`, `UpdateTrail` and `PutEventSelectors` on `cloudtrail.amazonaws.com`. Attackers call these right after getting access so later actions leave no record.

## Data source
CloudTrail management events. The calls are logged even when they succeed in stopping the trail.

## Known false positives
Planned trail changes by the platform team, which should come from an infrastructure-as-code role.

## Tuning notes
- Allow-list the Terraform/CloudFormation role by ARN rather than by user agent.
- With an organisation trail, member accounts cannot stop it. Alert on these calls in member accounts anyway: they show intent.

## Test evidence
No public capture exists, so a synthetic fixture (`fx_aws_cloudtrail_tampering`) replays the three calls from a leaked CI key. Read-only calls (`DescribeTrails`, `GetTrailStatus`, `LookupEvents`) in the benign fixture do not match.
