# AgentCap Authorization Broker

A minimal authorization broker built with Python 3.12 and FastAPI. It enforces strict default-deny policies, separates administrator task approval from agent execution, and issues single-use, time-bound authorization leases.

---

## 1. Installation on Windows

Ensure Python 3.12 is installed. In PowerShell:

```powershell
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## 2. Environment Variables

Configure environment variables before starting the broker or running tasks. You can copy `.env.example` as a template:

| Variable | Description | Example / Default |
|---|---|---|
| `ADMIN_API_KEY` | Secret key for trusted task registration | Required |
| `AGENT_API_KEY` | Secret key for agent lease requests and execution | Required |
| `AGENT_ID` | Identity bound to the configured agent key | `agent-default` |
| `ALLOWED_S3_BUCKET` | Only bucket the broker may access | Required (e.g. `agentcap-demo`) |
| `ALLOWED_S3_PREFIX` | Only key prefix the broker may access | Required (e.g. `reports/`) |
| `TASK_TTL_SECONDS` | How long an approved task remains valid | `900` (default) |
| `AWS_ROLE_ARN` | IAM role assumed per lease with a one-object session policy; see [AWS STS setup](docs/aws-sts-setup.md) | Unset (default; broker credentials used for local development) |
| `S3_MAX_OBJECT_BYTES` | Maximum object size returned by the execution API | `1048576` (default, 1 MiB) |
| `AGENTCAP_URL` | Broker base URL used by the Python agent CLI | `http://127.0.0.1:8000` (default) |
| `DATABASE_PATH` | SQLite database file path | `broker/agentcap.db` (default) |

Set the required values in PowerShell:

```powershell
$env:ADMIN_API_KEY = "replace-with-a-long-random-admin-secret"
$env:AGENT_API_KEY = "replace-with-a-different-long-random-agent-secret"
$env:AGENT_ID = "agent-default"
$env:ALLOWED_S3_BUCKET = "agentcap-demo"
$env:ALLOWED_S3_PREFIX = "reports/"
```

The values above are examples, not production secrets. Do not commit real API keys, AWS credentials, or populated `.env` files. For an AWS deployment, configure `AWS_ROLE_ARN` and give the broker identity only `sts:AssumeRole` permission; see the STS setup guide.

---

## 3. Starting the FastAPI Server

Run the server with Uvicorn:

```powershell
.\.venv\Scripts\uvicorn.exe broker.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/health -Method GET
```

---

## 4. Running the Tests

Execute the full test suite using the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The unit and integration tests use mocked AWS clients. They do not require live AWS credentials or make real AWS requests.

---

## 5. Usage & API Flow

### Step A: Trusted Task Registration (`POST /tasks`)

A trusted administrator approves an exact action and resource. The task is bound to the configured agent identity.

```powershell
$adminHeaders = @{ "X-Admin-Key" = $env:ADMIN_API_KEY }
$taskBody = @{
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json

$task = Invoke-RestMethod -Uri http://127.0.0.1:8000/tasks -Method POST -Headers $adminHeaders -ContentType "application/json" -Body $taskBody
Write-Host "Task approved with ID: $($task.task_id)"
```

### Alternative: Use the Python Agent CLI

Instead of manually following Steps B and C, the Python agent client can request a lease and execute the approved operation in one command.

Ensure `AGENT_API_KEY` is set in the shell running the agent. It must match the key configured in the broker. `AGENTCAP_URL` is optional and defaults to `http://127.0.0.1:8000`.

```powershell
.\.venv\Scripts\python.exe -m agent `
    --task-id $task.task_id `
    --action "s3:GetObject" `
    --resource "s3://agentcap-demo/reports/q3-report.txt" `
    --output ".\q3-report-agent-output.txt"
```

The CLI requests the lease, submits it for execution, validates the response, and saves the returned object. The output file must not already exist, and its parent directory must exist.

The CLI does not print the lease token or object contents. It reports the number of bytes saved and the output path.

**Important:** Use either the Python CLI or the manual Steps B and C for a given task, not both. Each approved task can issue only one lease.


### Step B: Agent Requests a Lease (`POST /leases`)

The authenticated agent requests a lease by providing the approved `task_id`, matching `action`, and matching `resource`.

```powershell
$agentHeaders = @{ "X-Agent-Key" = $env:AGENT_API_KEY }
$leaseBody = @{
    task_id  = $task.task_id
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json

$lease = Invoke-RestMethod -Uri http://127.0.0.1:8000/leases -Method POST -Headers $agentHeaders -ContentType "application/json" -Body $leaseBody
Write-Host "Lease issued; expires in $($lease.expires_in) seconds."
```

Keep `$lease.lease_token` in memory and do not print it or write it to logs.

### Step C: Agent Spends the Lease (`POST /leases/execute`)

The agent sends only the lease token in the request body (along with its agent authentication header). The broker consumes the lease once, performs the approved `s3:GetObject`, and returns a JSON response containing the object bytes encoded as Base64. AWS credentials remain inside the broker and are never returned to the agent.

```powershell
$execBody = @{ lease_token = $lease.lease_token } | ConvertTo-Json
$execResponse = Invoke-RestMethod -Uri http://127.0.0.1:8000/leases/execute -Method POST -Headers $agentHeaders -ContentType "application/json" -Body $execBody

# Decode the JSON Base64 field back into the original object bytes.
$fileBytes = [Convert]::FromBase64String($execResponse.content_base64)

# Check the decoded byte count before writing the file.
if ($fileBytes.Length -ne $execResponse.content_length) {
    throw "Downloaded object length did not match the broker response."
}

[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "q3-report.txt"), $fileBytes)
Write-Host "Downloaded $($fileBytes.Length) bytes to q3-report.txt"
```

The successful JSON response contains:

| Field | Meaning |
|---|---|
| `content_base64` | Object bytes encoded as Base64 |
| `content_length` | Number of decoded object bytes |
| `content_type` | Optional S3 content-type metadata |
| `etag` | Optional S3 entity tag |

The response also includes `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

| HTTP status | Meaning |
|---|---|
| `200` | Execution succeeded; response is JSON with Base64 content |
| `401` | Missing or invalid agent API key |
| `403` | Invalid, expired, replayed, or wrong-agent lease; or policy violation |
| `404` | Task not found |
| `409` | Task has already issued its one permitted lease |
| `413` | Object is larger than `S3_MAX_OBJECT_BYTES` |
| `500` | Invalid server configuration or unexpected internal error |
| `502` | S3 or STS execution failed |
| `503` | Required audit write failed; execution fails closed |

The lease is consumed before S3 is called. It remains spent even if S3 or STS fails, and it can never be replayed.

---

## 6. Policy Enforcement & Audit

The broker enforces:

- **Default deny:** Only `s3:GetObject` on the configured bucket and prefix is permitted.
- **Strict scope:** The action, bucket, prefix, and resource must match the administrator-approved task.
- **No wildcards or traversal:** Wildcards, query markers, path traversal, fragments, and malformed S3 URIs are rejected.
- **Single-use, expiring approvals:** Each approved task can issue exactly one lease, and only before the task expires.
- **Agent-bound leases:** A lease is tied to the configured agent identity and cannot be consumed by another agent.
- **Fail-closed auditing:** Required audit writes must succeed; otherwise the operation is rejected or reported as unavailable.
- **Append-only audit history:** Audit records cannot be updated or deleted through the database triggers.
- **Per-lease AWS credentials:** When `AWS_ROLE_ARN` is configured, the broker calls STS AssumeRole with an inline session policy allowing only `s3:GetObject` on the leased object. Temporary credentials stay inside the broker.
- **Credential hygiene:** Lease tokens, token hashes, AWS credentials, object contents, and raw exception messages are not written to audit events.

Audit events cover task registration, lease issuance/denial/consumption, rejected execution attempts, and S3 execution success or failure.

### Denied request examples

#### 1. Unauthorized action (`s3:DeleteObject`)

An attempt to register an unapproved action returns `403 Forbidden`:

```powershell
$badTaskBody = @{
    action   = "s3:DeleteObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:8000/tasks -Method POST -Headers $adminHeaders -ContentType "application/json" -Body $badTaskBody
```

#### 2. Scope mismatch on lease request

An attempt to request a lease for a different resource than the one approved returns `403 Forbidden`:

```powershell
$badLeaseBody = @{
    task_id  = $task.task_id
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/unapproved-payroll.txt"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:8000/leases -Method POST -Headers $agentHeaders -ContentType "application/json" -Body $badLeaseBody
```

No lease is created when the request fails validation.
