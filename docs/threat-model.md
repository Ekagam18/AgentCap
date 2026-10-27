# AgentCap Security Threat Model

## 1. Purpose and Scope

### 1.1 Purpose
**AgentCap** is an authorization and runtime containment layer designed to limit the privileges of AI agents operating against cloud infrastructure. Autonomous AI agents present distinct security challenges: non-deterministic execution, susceptibility to prompt injection, vulnerability to malicious third-party dependencies, and the risk of hallucinated or unintended actions. Granting broad, static, or long-lived cloud credentials (such as AWS IAM access keys) directly to an agent creates severe exposure to data exfiltration, unauthorized modification, destructive actions (e.g., resource deletion), and denial-of-wallet attacks.

AgentCap addresses this problem by interposing a trusted broker between the AI agent and cloud resources. Instead of receiving ambient or long-term cloud credentials, the agent must obtain short-lived, single-use, scope-bound authorization leases for administrator-approved tasks.

### 1.2 Prototype Scope
This threat model assesses the **AgentCap Minimum Viable Product (MVP)** for its first evaluation milestone. The prototype focuses on:
- Decoupled task approval by a trusted administrator.
- Identity and policy verification prior to issuing authorization leases.
- Cryptographically hashed, time-bounded, single-use application leases.
- Deterministic policy enforcement against unauthorized actions and resources (targeting Amazon S3 `s3:GetObject`).
- Append-only structured audit logging for lease lifecycle events.
- An isolated S3 executor enforcing size constraints and error sanitization.

This document identifies assets, defines trust boundaries, analyzes potential threats and attacker capabilities, documents implemented and planned mitigations, and honestly details current architectural limitations and residual risks.

---

## 2. System Architecture and Trust Boundaries

### 2.1 System Components

```
+-----------------------------------------------------------------------------------+
|                                  TRUST DOMAIN                                     |
|                                                                                   |
|   +-----------------------+                    +------------------------------+   |
|   | Trusted Administrator |                    |       AI Agent Client        |   |
|   |  (Human Supervisor)   |                    |     (Semi-Trusted / LLM)     |   |
|   +-----------+-----------+                    +--------------+---------------+   |
|               |                                               |                   |
|               | POST /tasks (X-Admin-Key)                     | POST /leases      |
|               |                                               | (X-Agent-Key)     |
|               v                                               v                   |
|   +---------------------------------------------------------------------------+   |
|   |                AgentCap Authorization Broker (FastAPI)                    |   |
|   |                                                                           |   |
|   |   - Authenticates callers (HMAC constant-time key validation)             |   |
|   |   - Policy Engine (action whitelist, URI safety, bucket/prefix checks)     |   |
|   |   - Task Management (creation and lookup)                                 |   |
|   |   - Lease Management (issuance with SHA-256 token hashing)                |   |
|   +---------------------+---------------------------------+-------------------+   |
|                         |                                 |                       |
|                         | Atomic SQL                      | In-memory lease dict  |
|                         v                                 v                       |
|   +---------------------------------------+   +-------------------------------+   |
|   |           SQLite Database             |   |      Isolated S3 Executor     |   |
|   |                                       |   |    (broker/s3_executor.py)    |   |
|   |   - tasks (approved scopes)           |   |                               |   |
|   |   - leases (hashed tokens, status)    |   |   - Re-validates lease fields |   |
|   |   - audit_events (append-only events) |   |   - Re-checks policy          |   |
|   +---------------------------------------+   |   - Streams with size limits  |   |
|                                               |   - Sanitizes AWS errors      |   |
|                                               +---------------+---------------+   |
+---------------------------------------------------------------|-------------------+
                                                                |
                                             AWS Boto3 API Call | IAM Role / Credentials
                                                                v
                                                +-------------------------------+
                                                |     Amazon S3 Cloud API       |
                                                |   (s3://<bucket>/<prefix>/)   |
                                                +-------------------------------+
```

The system comprises the following primary components:
1. **Administrator Client**: A trusted actor using `ADMIN_API_KEY` to register approved tasks through `POST /tasks`.
2. **AI Agent Client**: An untrusted or semi-trusted software process executing tasks. Authenticates via `X-Agent-Key` and requests authorization leases via `POST /leases`.
3. **Authorization Broker ([`broker/main.py`](../broker/main.py))**: A FastAPI service exposing endpoints for health checks, task approval, and lease issuance.
4. **Policy Engine ([`policy/checks.py`](../policy/checks.py))**: Deterministic validation routines enforcing action whitelisting (`s3:GetObject`), S3 URI syntax rules, path traversal defenses, wildcard rejection, and exact task matching.
5. **Database & Audit Storage ([`broker/database.py`](../broker/database.py) & [`broker/tasks.py`](../broker/tasks.py))**: An embedded SQLite database maintaining tables for `tasks`, `leases`, and `audit_events`. Uses SQLite triggers to enforce append-only audit semantics.
6. **Isolated S3 Executor ([`broker/s3_executor.py`](../broker/s3_executor.py))**: A dedicated Python execution module that consumes a lease, re-verifies policy constraints, invokes `boto3` to fetch the approved S3 object, enforces streaming size caps, and sanitizes AWS errors.
7. **Cloud Target (Amazon Web Services S3)**: Remote object storage housing sensitive or operational data.

> [!IMPORTANT]
> **Component Status Note:** The isolated S3 executor exists as an independently tested Python module ([`broker/s3_executor.py`](../broker/s3_executor.py)), verified by 78 automated unit tests (expanded from an initial 67-test baseline). However, **there is currently no HTTP execution endpoint** (such as `POST /execute` or `POST /leases/execute`) exposed in [`broker/main.py`](../broker/main.py). In the current prototype state, lease consumption and execution are coordinated programmatically.

### 2.2 Trust Boundaries

1. **Trust Boundary 1: Administrator <-> Broker API**
   - *Protocol:* HTTP/HTTPS with `X-Admin-Key` header.
   - *Assumptions:* The administrator is trusted. The `ADMIN_API_KEY` is a high-entropy secret kept confidential from the agent.
2. **Trust Boundary 2: AI Agent <-> Broker API**
   - *Protocol:* HTTP/HTTPS with `X-Agent-Key` header.
   - *Assumptions:* The agent is untrusted or semi-trusted. Inputs from the agent (task IDs, requested actions, requested resources) are untrusted and must be validated against previously approved records. The agent cannot register its own approved tasks.
3. **Trust Boundary 3: Broker & Executor <-> Local SQLite Database**
   - *Protocol:* Local IPC via Python `sqlite3` driver.
   - *Assumptions:* Transactions are atomic (`BEGIN IMMEDIATE`). Raw tokens are never persisted. Database file access is protected by operating system user permissions.
4. **Trust Boundary 4: Isolated Executor <-> AWS S3 Service**
   - *Protocol:* HTTPS via `boto3`/`botocore`.
   - *Assumptions:* The executor possesses restricted AWS IAM credentials. The agent does not have access to these AWS credentials. All error responses from AWS are sanitized before reaching callers.

---

## 3. Assets to Protect

| Asset Category | Specific Asset | Security Objective | Impact of Compromise |
|---|---|---|---|
| **Cloud Data** | Amazon S3 Objects | Confidentiality, Integrity, Availability | Unauthorized data exfiltration, ransomware/deletion, tampering with business data. |
| **Cloud Credentials** | AWS IAM Credentials / STS Sessions | Confidentiality, Least Privilege | Full cloud account compromise, lateral movement across AWS infrastructure. |
| **Broker Secrets** | `ADMIN_API_KEY` | Confidentiality, Integrity | Rogue task approval, arbitrary action authorization, complete security bypass. |
| **Agent Credentials** | `AGENT_API_KEY` | Confidentiality, Integrity | Impersonation of agent to claim approved tasks; restricted to approved scopes. |
| **Authorization Tokens**| Active Lease Tokens | Confidentiality, Single-Use Integrity | Replay attacks, unauthorized resource access during token TTL window. |
| **Database Records** | `tasks` and `leases` Tables | Integrity, Availability | State corruption, phantom lease creation, authorization bypass. |
| **Audit Logs** | `audit_events` Table | Integrity, Non-repudiation | Inability to detect attacks, untraceable security breaches, forensic failure. |
| **Host Resources** | Broker Memory & CPU | Availability | Denial of Service (DoS) via memory exhaustion from oversized S3 downloads. |

---

## 4. Security Assumptions and Attacker Capabilities

### 4.1 Attacker Profiles

1. **Compromised or Malicious AI Agent**:
   - The primary adversary in AgentCap's threat model.
   - May be subverted via prompt injection (direct or indirect), unsafe tool use, model jailbreaks, or poisoned training/context.
   - Possesses valid agent credentials (`AGENT_API_KEY`) and an assigned identity (`AGENT_ID`).
   - May attempt to:
     - Request actions outside its scope (e.g., `s3:DeleteObject`, `s3:PutObject`, `iam:PassRole`).
     - Access resources outside permitted boundaries (e.g., unauthorized buckets, cross-tenant prefixes, traversal to parent paths).
     - Submit malformed, ambiguous, or wildcard URIs to trick policy parsers.
     - Replay previously issued lease tokens.
     - Forge or modify task records.
     - Trigger excessive memory consumption by reading oversized cloud files.

2. **External Network Adversary**:
   - Lacks valid API keys.
   - Attempts brute force, credential stuffing, or timing attacks on broker endpoints.
   - Attempts to access unauthenticated endpoints or inject malformed HTTP payloads.

3. **Curious or Insider Colleague (Multi-Tenant Agent)**:
   - Controls an agent identity (`agent-2`) but attempts to claim tasks approved for `agent-1`.

### 4.2 Explicit Non-Assumptions (Out of Scope for MVP)
- **Host Compromise**: If an attacker achieves arbitrary code execution as the operating system user running the broker, they can read environment variables (`ADMIN_API_KEY`, AWS credentials) and modify the SQLite database file directly. OS-level containment is planned for later milestones (containers, eBPF).
- **Physical Memory Extraction**: Cold boot attacks, memory scraping of running Python process memory, and hardware-level attacks are out of scope.
- **AWS Service-Side Zero-Days**: Vulnerabilities in AWS S3 or AWS IAM core infrastructure are out of scope.

---

## 5. Threats and Existing Mitigations

The following matrix documents threats, their implementation status in AgentCap, and the specific mechanisms enforcing mitigation:

### Status Legend
- **Implemented**: Fully operational in current codebase and verified by automated tests.
- **Partially implemented**: Operational in core logic but lacking full end-to-end integration or infrastructure backing.
- **Planned**: Designed or recommended for future milestones; not present in the current codebase.

| Threat ID | Threat Description | Status | Implemented Mitigation / Technical Control |
|---|---|---|---|
| **TH-01** | **Direct Cloud Credential Theft**<br>Agent steals static AWS access keys to perform arbitrary actions. | **Implemented** | AgentCap does not distribute AWS credentials to agents. Cloud operations are executed exclusively through the broker/executor layer. The agent receives only a short-lived, single-use application lease token. |
| **TH-02** | **Self-Approved Privilege Escalation**<br>Agent approves its own high-privilege tasks. | **Implemented** | Strict separation of duties. Task creation (`POST /tasks`) requires `ADMIN_API_KEY`. Lease requests (`POST /leases`) accept only `AGENT_API_KEY`. Agents cannot call `/tasks` (`401 Unauthorized`). |
| **TH-03** | **Cross-Agent Task Usurpation**<br>Agent attempts to use a task approved for another agent. | **Implemented** | Tasks are bound to an `agent_id` at creation. [`validate_task_match()`](../policy/checks.py#L75-L89) in [`policy/checks.py`](../policy/checks.py) verifies that the authenticated caller matches the task's assigned `agent_id`. Mismatches return `403 Forbidden`. |
| **TH-04** | **Scope and Resource Substitution**<br>Agent requests an approved task ID but substitutes a malicious resource or action at lease request time. | **Implemented** | [`validate_task_match()`](../policy/checks.py#L75-L89) verifies that `action` and `resource` match the task record exactly. Furthermore, [`execute_consumed_lease()`](../broker/s3_executor.py#L248-L358) extracts `action` and `resource` from the consumed lease record itself, preventing caller tampering. |
| **TH-05** | **Unauthorized Action Execution**<br>Agent attempts destructive actions (e.g., `s3:DeleteObject`, `s3:PutObject`). | **Implemented** | Strict default-deny policy. [`validate_action_and_resource()`](../policy/checks.py#L53-L73) enforces a strict whitelist allowing only `s3:GetObject`. All other actions are rejected with `403 Forbidden` / `PolicyViolationError`. |
| **TH-06** | **Bucket and Key Prefix Escape**<br>Agent attempts to read outside permitted bucket or prefix. | **Implemented** | [`validate_action_and_resource()`](../policy/checks.py#L53-L73) validates bucket against `ALLOWED_S3_BUCKET` and key against `ALLOWED_S3_PREFIX`. Boundary leakage (e.g. `reports_backup/` when `reports/` is allowed) is prevented via normalized trailing slash checking. |
| **TH-07** | **Path Traversal & Ambiguous URIs**<br>Agent uses `..`, `.`, double slashes, backslashes, or URI fragments to bypass path checks. | **Implemented** | [`parse_and_validate_s3_uri()`](../policy/checks.py#L12-L51) strictly checks scheme (`s3://`), forbids backslashes (`\`), forbids consecutive slashes (`//`), rejects path traversal segments (`..`, `.`), and rejects URI fragments (`#`). Directory-only URIs ending in `/` are rejected. |
| **TH-08** | **Wildcard Injection**<br>Agent attempts to gain broad access using wildcard patterns (`*`, `?`). | **Implemented** | [`parse_and_validate_s3_uri()`](../policy/checks.py#L12-L51) explicitly forbids `*` and `?` characters in resource strings. |
| **TH-09** | **Token Replay / Multi-Use**<br>Agent attempts to reuse a lease token multiple times. | **Implemented** | [`consume_lease()`](../broker/database.py#L130-L177) performs an atomic conditional update: `UPDATE leases SET status = 'consumed' WHERE token_hash = ? AND status = 'issued' AND expires_at > ? RETURNING ...`. Once consumed, any subsequent attempt returns `None`. Verified with 10 concurrent threads in [`test_concurrent_consumption_allows_only_one_winner`](../tests/test_leases.py#L117-L144). |
| **TH-10** | **Immortal / Non-Expiring Leases**<br>Agent inputs invalid, infinite (`inf`), or negative TTL to keep lease active indefinitely. | **Implemented** | [`issue_lease()`](../broker/database.py#L74-L127) validates `math.isfinite(ttl_seconds) and ttl_seconds > 0`. Inputs of `0`, negative numbers, `float("inf")`, and `float("nan")` are rejected with `ValueError`. Consumption actively verifies `expires_at > time.time()`. |
| **TH-11** | **Database Token Compromise**<br>Attacker inspecting SQLite database extracts valid lease tokens. | **Implemented** | [`issue_lease()`](../broker/database.py#L74-L127) computes SHA-256 hash of the random 32-byte URL-safe token. Only `token_hash` is stored in the database. The plaintext token is returned once to the caller and never stored. |
| **TH-12** | **Denial of Service via Giant Objects**<br>Agent targets huge S3 objects to exhaust broker memory. | **Implemented** | [`_read_body_with_limit()`](../broker/s3_executor.py#L203-L237) checks `ContentLength` header before download and streams object in 64 KiB chunks, terminating and raising `S3ObjectTooLargeError` if size exceeds `max_object_bytes` (default 1 MiB). Response stream is closed in `finally` block under all exit paths. |
| **TH-13** | **Information Leakage via Errors**<br>Error messages leak internal AWS paths, tokens, or IAM details. | **Implemented** | [`_sanitize_error_code()`](../broker/s3_executor.py#L239-L246) strips sensitive details from AWS `ClientError` and `BotoCoreError`, mapping them to sanitized alphanumeric codes (e.g., `S3ServiceError: AWS S3 error (NoSuchKey) during GetObject`). Tokens and hashes are excluded from error messages. |
| **TH-14** | **Timing Attacks on API Keys**<br>Attacker measures comparison duration to deduce admin/agent keys. | **Implemented** | API key headers are verified using `hmac.compare_digest()` in [`authenticate_admin()`](../broker/main.py#L66-L78) and [`authenticate_agent()`](../broker/main.py#L80-L93) to resist timing analysis. |
| **TH-15** | **Audit Log Tampering via SQL**<br>Attacker attempts to modify or delete historical audit entries. | **Partially implemented** | SQLite triggers `prevent_audit_update` and `prevent_audit_delete` abort any SQL `UPDATE` or `DELETE` on `audit_events`. Audit inserts occur in the same atomic transaction as lease operations. *(See Section 6 for residual risks).* |
| **TH-16** | **Execution Auditing Gaps**<br>S3 execution attempts, successes, and failures lack audit trail. | **Planned** | Audit logging covers lease issuance and consumption, but not S3 executor outcomes. Planned for next iteration. |
| **TH-17** | **Direct Cloud Access Bypass**<br>Agent bypasses broker completely using host AWS environment credentials or IMDS. | **Planned** | Broker-level controls cannot prevent direct outbound traffic. Planned for Evaluation 2 (eBPF network filtering and container workload isolation). |

---

## 6. Current Limitations and Residual Risks

### 6.1 Application Leases vs. AWS STS Credential Lifetimes
A central security distinction in AgentCap is between **application-level leases** and **cloud-level credentials**:
- An AgentCap lease is an internal database token with a short TTL (default 60 seconds) that allows a single authorized execution through the broker.
- This application lease **does not alter AWS IAM credentials**. The executor uses AWS IAM credentials (or STS assumed-role sessions). AWS STS role sessions have a minimum lifetime of 15 minutes (900 seconds) enforced by AWS.
- Therefore, lease expiration in SQLite does not automatically expire the underlying AWS credential. The security guarantee relies on the broker retaining control over the execution channel.

### 6.2 Lack of Network-Level Bypass Prevention (The Direct-Access Risk)
AgentCap currently operates as an **application-layer authorization broker**:
- It validates requests that are sent to it.
- However, if the agent runs in an environment with ambient AWS credentials (such as environment variables `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, shared `~/.aws/credentials`, or access to the EC2 Instance Metadata Service `169.254.169.254`), a malicious or compromised agent could **bypass the broker entirely** and contact the AWS API directly.
- **Residual Risk:** Full mitigation of the bypass threat requires operating-system and network-level enforcement (e.g., eBPF egress filtering, cgroup network namespaces, or Kubernetes network policies), which is scheduled for Evaluation 2.

### 6.3 Missing Execution HTTP Endpoint Integration
While [`broker/s3_executor.py`](../broker/s3_executor.py) is implemented and thoroughly tested as a Python library:
- [`broker/main.py`](../broker/main.py) only exposes `GET /health`, `POST /tasks`, and `POST /leases`.
- There is currently **no HTTP endpoint** through which an agent can submit a lease token over the network to execute the S3 operation.
- **Residual Risk:** An end-to-end HTTP demonstration requires completing the execution endpoint in the broker API.

### 6.4 Audit Logging Coverage Gaps
The audit subsystem in [`broker/database.py`](../broker/database.py):
- Successfully captures `lease_issued` and `lease_consumed` events atomically with their respective database operations.
- However, it **does not yet capture S3 execution outcomes** (`s3_execution_attempted`, `s3_execution_succeeded`, `s3_execution_failed`).
- If an S3 operation fails due to network partition or AWS access denial, the lease remains recorded as `consumed`, but no corresponding cloud failure event is logged in `audit_events`.

### 6.5 Database Integrity Limitations
Although SQLite triggers prevent SQL-level modification or deletion of rows:
- Anyone with write access to the underlying `.db` file on the filesystem can modify or delete the database file directly.
- SQLite does not provide cryptographic tamper-evidence (such as Merkle trees or external ledger anchoring).
- **Residual Risk:** The audit log cannot be claimed to be completely "tamper-proof"; it is append-only within the context of the SQL execution engine.

### 6.6 Single-Agent Authentication Model
Currently, `AGENT_API_KEY` is a single environment variable bound to a single `AGENT_ID`:
- The system does not yet support multi-agent dynamic credential provisioning or per-agent key rotation.
- If the agent key is compromised, the attacker can request leases for any task approved for that `AGENT_ID`.

---

## 7. Recommended Next Steps

The following improvements are prioritized for upcoming milestones:

### Priority 1: High (Immediate MVP Completion)
1. **Expose S3 Execution Endpoint in Broker**:
   - Add `POST /leases/execute` (or `POST /s3/execute`) to [`broker/main.py`](../broker/main.py).
   - Accept the lease token, invoke `consume_lease()`, pass the resulting record to `execute_consumed_lease()`, and return the structured object payload or download stream.
2. **Extend Audit Logging to S3 Execution**:
   - Add audit event recording for `s3_execution_attempted`, `s3_execution_succeeded`, and `s3_execution_failed`.
   - Record sanitized AWS error codes, object content length, and latency.
3. **End-to-End Workflow Integration Tests**:
   - Add integration tests verifying the full HTTP lifecycle: Admin registers task -> Agent requests lease -> Agent invokes execution endpoint -> Object received -> Audit log verified.

### Priority 2: Medium (Evaluation 1 Hardening)
4. **Least-Privilege AWS IAM Configuration**:
   - Document and template the exact IAM policy required for the broker's cloud identity, restricting AWS permissions solely to `s3:GetObject` on `arn:aws:s3:::<allowed-bucket>/<allowed-prefix>/*`.
5. **Payload Streaming in HTTP Endpoint**:
   - Ensure the new execution endpoint streams large payloads using FastAPI `StreamingResponse` rather than loading entire multi-megabyte files into memory at the HTTP layer.

### Priority 3: Architecture & Evaluation 2 (Long-term Containment)
6. **Network & eBPF-Based Enforcement**:
   - Implement eBPF socket filtering or container network policies to block outbound TCP port 443 connections from the agent container to AWS endpoints (`*.amazonaws.com`), ensuring the agent cannot bypass the broker.
7. **Workload Identity & Dynamic Tokens**:
   - Transition from static `AGENT_API_KEY` environment variables to dynamic workload identity (e.g., Kubernetes ServiceAccount tokens or SPIFFE/SPIRE).

---

## 8. Security Validation & Test Evidence

The security controls detailed in this threat model are validated through automated regression test suites.

### 8.1 Automated Test Suite Summary
Execution of the complete local test suite across the repository produces **136 passed tests** (0 failed, 1 Starlette deprecation warning), expanded from an earlier 125-test baseline:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: D:\5th Sem Cse 2026\Grp_project\AgentCap
configfile: pytest.ini
plugins: anyio-4.15.1
collected 136 items

tests/test_broker.py (15 tests) ............... PASSED
tests/test_leases.py (29 tests) ............................. PASSED
tests/test_policy.py (14 tests) .............. PASSED
tests/test_s3_executor.py (78 tests) .................................... PASSED

======================= 136 passed, 1 warning in 1.84s ========================
```

*(Historical baseline prior to S3 executor edge-case test expansion: 125 total tests, including 67 S3 executor tests).*

### 8.2 Security Properties Verified by Tests

1. **Broker Authentication & Task Isolation ([`tests/test_broker.py`](../tests/test_broker.py))**:
   - Missing or invalid admin keys rejected (`401 Unauthorized`).
   - Missing or invalid agent keys rejected (`401 Unauthorized`).
   - Agents attempting to register tasks rejected (`401 Unauthorized`).
   - Cross-agent task claiming rejected (`403 Forbidden`).
   - Unapproved actions/buckets/prefixes rejected without lease issuance (`403 Forbidden`).
   - Unexpected request fields rejected via Pydantic strict schemas (`422 Unprocessable Entity`).

2. **Lease Lifecycle & Concurrency ([`tests/test_leases.py`](../tests/test_leases.py))**:
   - Single-use consumption enforced; subsequent consumption returns `None`.
   - Expired leases rejected.
   - Unknown tokens rejected.
   - Input validation: empty task, action, or resource rejected.
   - TTL validation: `0`, negative numbers, `inf`, `-inf`, and `nan` rejected.
   - Plaintext tokens never stored in SQLite (verified against database rows).
   - Concurrency race conditions: 10 concurrent threads attempting to consume the same token simultaneously results in exactly 1 winner and 9 rejections.
   - Audit logging: Events written for issuance and consumption; append-only triggers prevent update/delete; deterministic ordering preserved.

3. **Policy Engine Defenses ([`tests/test_policy.py`](../tests/test_policy.py))**:
   - Disallowed actions (e.g., `s3:DeleteObject`, `s3:PutObject`) rejected.
   - Disallowed buckets and prefixes rejected.
   - Prefix boundary leakage (e.g. `reports-other/` vs `reports/`) rejected.
   - Directory-only resources (`/`) rejected.
   - Wildcards (`*`, `?`) rejected.
   - Path traversal (`../`, `/./`) rejected.
   - Malformed S3 URIs (backslashes, consecutive slashes, non-S3 schemes) rejected.

4. **Isolated S3 Executor Security ([`tests/test_s3_executor.py`](../tests/test_s3_executor.py))**:
   - Consumed lease structure strictly validated before AWS invocation.
   - Policy checks independently re-enforced at execution time.
   - Oversized objects rejected via `ContentLength` header before full download.
   - Oversized objects with missing or understated headers rejected during chunked stream reading.
   - Stream response body closed reliably under all circumstances (success, exception, size violation).
   - AWS errors (`ClientError`, `BotoCoreError`) sanitized to avoid credential or environment leakage.
   - No tokens, hashes, or secret keys present in execution results or error strings.
