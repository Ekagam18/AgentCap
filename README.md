# AgentCap Authorization Broker

A minimal, secure authorization broker built with Python 3.12 and FastAPI. It enforces strict default-deny policies, decouples task approval by administrators from agent execution, and issues single-use, time-bound authorization leases.

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
| `ADMIN_API_KEY` | Secret key for trusted task registration | `admin-secret-key-123` (Required) |
| `AGENT_API_KEY` | Secret key for agent lease requests | `agent-secret-key-456` (Required) |
| `AGENT_ID` | Bound agent identity for the configured agent key | `agent-default` |
| `ALLOWED_S3_BUCKET` | Allowed S3 bucket | `agentcap-demo` |
| `ALLOWED_S3_PREFIX` | Allowed S3 key prefix | `reports/` |
| `DATABASE_PATH` | Path to SQLite database file | `broker/agentcap.db` (Default) |

Set them in PowerShell:

```powershell
$env:ADMIN_API_KEY="admin-secret-key-123"
$env:AGENT_API_KEY="agent-secret-key-456"
$env:AGENT_ID="agent-default"
$env:ALLOWED_S3_BUCKET="agentcap-demo"
$env:ALLOWED_S3_PREFIX="reports/"
```

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

Execute pytest using the virtual environment:

```powershell
.\.venv\Scripts\pytest.exe -v
```

---

## 5. Usage & API Flow

### Step A: Trusted Task Registration (`POST /tasks`)
A trusted administrator approves an exact action and resource. The task is bound to the configured agent identity.

```powershell
$adminHeaders = @{ "X-Admin-Key" = "admin-secret-key-123" }
$taskBody = @{
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json

$task = Invoke-RestMethod -Uri http://127.0.0.1:8000/tasks -Method POST -Headers $adminHeaders -ContentType "application/json" -Body $taskBody
Write-Host "Task approved with ID: $($task.task_id)"
```

### Step B: Agent Requests Lease (`POST /leases`)
The authenticated AI agent requests a lease by providing the approved `task_id`, matching `action`, and matching `resource`.

```powershell
$agentHeaders = @{ "X-Agent-Key" = "agent-secret-key-456" }
$leaseBody = @{
    task_id  = $task.task_id
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json

$lease = Invoke-RestMethod -Uri http://127.0.0.1:8000/leases -Method POST -Headers $agentHeaders -ContentType "application/json" -Body $leaseBody
Write-Host "Issued lease token: $($lease.lease_token)"
```

---

## 6. Policy Enforcement & Denied Requests

The broker enforces:
- **Default Deny**: Only `s3:GetObject` on the configured bucket and prefix is permitted.
- **Strict Scope**: Actions, bucket, prefix, and task parameters must match approved records exactly.
- **No Wildcards / Traversal**: Reject `*`, `?`, `..`, and malformed URIs.
- **Identity Isolation**: The agent cannot register its own tasks (`401 Unauthorized`), nor can it claim a task approved for another agent (`403 Forbidden`).

### Denied Request Examples

#### 1. Unauthorized Action (`s3:DeleteObject`)
```powershell
# Attempting to register an unapproved action returns 403 Forbidden:
Invoke-RestMethod -Uri http://127.0.0.1:8000/tasks -Method POST -Headers $adminHeaders -ContentType "application/json" -Body (@{
    action   = "s3:DeleteObject"
    resource = "s3://agentcap-demo/reports/q3-report.txt"
} | ConvertTo-Json)
# Result: 403 Forbidden: Action 's3:DeleteObject' is not permitted; only 's3:GetObject' is allowed
```

#### 2. Scope Mismatch on Lease Request
```powershell
# Attempting to request a lease for a different resource than approved returns 403 Forbidden:
Invoke-RestMethod -Uri http://127.0.0.1:8000/leases -Method POST -Headers $agentHeaders -ContentType "application/json" -Body (@{
    task_id  = $task.task_id
    action   = "s3:GetObject"
    resource = "s3://agentcap-demo/reports/unapproved-payroll.txt"
} | ConvertTo-Json)
# Result: 403 Forbidden: Requested resource does not match approved task
```
No lease is created in the database when any check fails.