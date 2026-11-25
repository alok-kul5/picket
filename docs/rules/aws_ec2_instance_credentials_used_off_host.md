# EC2 instance role credentials used from a workstation client

**Rule:** [`rules/cloud/aws_ec2_instance_credentials_used_off_host.yml`](../../rules/cloud/aws_ec2_instance_credentials_used_off_host.yml) · **ATT&CK:** T1552.005 Cloud Instance Metadata API, T1078.004 Cloud Accounts · **Level:** high

## What it detects
An instance profile session's ARN ends in the instance id (`assumed-role/<role>/i-0abc…`). When that session calls AWS with an `aws-cli` user agent that reports `Darwin/` or a Windows desktop build, the keys almost certainly left the instance (SSRF to the metadata service, a stolen `~/.aws` file) and are being replayed from a laptop.

## Data source
CloudTrail management and data events.

## Known false positives
EC2 Mac or Windows instances calling AWS with their own role.

## Tuning notes
- The stronger check is the source IP. If `sourceIPAddress` is outside your VPC/NAT ranges for an instance session, that is the GuardDuty `InstanceCredentialExfiltration` signal. Sigma has no IP-range lookup, so add it in the SIEM.
- The benign fixture includes the same role used from Amazon Linux SDKs, which does not match.

## Test evidence
OTRF `ec2_proxy_s3_exfiltration` (an SSRF through an nginx proxy, then `ListBuckets`/`GetObject` from aws-cli on macOS).
