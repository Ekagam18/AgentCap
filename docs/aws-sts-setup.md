# AWS setup for per-lease STS credentials

When `AWS_ROLE_ARN` is set, every `POST /leases/execute` call:

1. Assumes the role with `sts:AssumeRole`.
2. Passes an inline session policy that allows only `s3:GetObject` on the leased object, e.g.
   `arn:aws:s3:::agentcap-demo/reports/q3-report.txt`.
3. Uses the temporary credentials for that one request and then discards them.

AWS grants the intersection of the role's policy and the session policy, so even though the
role can read the whole `reports/` prefix, each session can read exactly one object.
The role session name is `agentcap-<lease_id>`, so CloudTrail entries map back to the broker's audit log.

When `AWS_ROLE_ARN` is unset, the broker falls back to its own default boto3 credentials (local/dev only).

## 1. Execution role: permissions policy

The most any lease could ever be granted. Keep it to the allowed bucket and prefix.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::agentcap-demo/reports/*"
    }
  ]
}
```

## 2. Execution role: trust policy

Only the broker's own identity may assume the role. Replace the principal with the broker's IAM user or role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/agentcap-broker" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## 3. Broker identity

The broker's own credentials need nothing except permission to assume that one role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/agentcap-executor"
    }
  ]
}
```

The broker identity has no S3 access of its own, so S3 can only be reached through a scoped session.

## 4. Create it with the AWS CLI

```bash
aws iam create-role --role-name agentcap-executor \
  --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name agentcap-executor \
  --policy-name agentcap-reports-read --policy-document file://permissions.json

export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/agentcap-executor
```

## Notes

- STS sessions last at least 15 minutes (900 s), longer than the 60 s lease. The credentials never leave
  the broker process, so the agent can't reuse them; the lease itself is still single-use.
- `*` and `?` are rejected in resources, so they can never become IAM wildcards in the session policy.
- STS errors are reduced to the AWS error code (e.g. `AccessDenied`) before they reach the audit log or the agent.
