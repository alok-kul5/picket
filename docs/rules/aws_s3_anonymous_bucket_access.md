# Anonymous principal enumerating or writing to an S3 bucket

**Rule:** [`rules/cloud/aws_s3_anonymous_bucket_access.yml`](../../rules/cloud/aws_s3_anonymous_bucket_access.yml) · **ATT&CK:** T1619 Cloud Storage Object Discovery, T1530 Data from Cloud Storage · **Level:** medium

## What it detects
S3 calls (`ListObjects`, `HeadBucket`, `GetObject`, `PutObject`, …) whose `userIdentity.accountId` is `ANONYMOUS_PRINCIPAL`. Any hit means a bucket answers unauthenticated requests and someone outside the account is touching it.

## Data source
CloudTrail S3 data events, which are off by default and must be enabled per bucket or account.

## Known false positives
Buckets that serve a public website or downloads on purpose. Exclude them by `requestParameters.bucketName`.

## Tuning notes
- In the honey-bucket capture, scanners found the bucket within hours and ran 284 anonymous calls. `PutObject` from an anonymous principal means the bucket is world-writable and needs fixing at once.
- The OTRF export is a CSV summary, not raw CloudTrail; `picket fetch` maps its columns onto CloudTrail field names.

## Test evidence
OTRF `aws_s3_honeybucketlogs`. 0 hits on 500 synthetic benign CloudTrail events.
