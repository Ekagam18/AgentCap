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
|                         | Atomic SQL                      | SQLite lease state  |
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
- **Host Compromise**: If an attacker achieves arbitrary code execution as the operating system user running the broker, they may read environment variables and AWS credential sources, and modify the SQLite database file directly. Process isolation and network-level egress enforcement are outside the current MVP.
- **Physical Memory Extraction**: Cold boot attacks, memory scraping of running Python process memory, and hardware-level attacks are out of scope.
- **AWS Service-Side Zero-Days**: Vulnerabilities in AWS S3 or AWS IAM core infrastructure are out of scope.

---

## 5. Threats and Existing Mitigations

The following matrix documents threats, their implementation status in AgentCap, and the specific mechanisms enforcing mitigation:

### Status Legend
- **Implemented**: Operational in the current codebase and covered by automated tests.
- **Partially implemented**: The application-level control exists, but an important deployment or isolation limitation remains.
- **Planned**: Recommended future work that is not present in the current codebase.
- **Residual risk / out of scope**: Not mitigated by the current MVP.

| Threat ID | Threat Description | Status | Implemented Mitigation / Technical Control |
|---|---|---|---|
| **TH-01** | **Direct Cloud Credential Theft**<br>Agent steals static AWS access keys to perform arbitrary actions. | **Partially implemented** | The broker API does not return AWS credentials, and the Python client uses application leases rather than AWS credentials in its requests. This does not prevent an agent process from using ambient credentials, shared AWS profiles, credential caches, or instance metadata if its runtime can access them; see Section 6.2. |
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
| **TH-16** | **Execution Audit Coverage**<br>Rejected execution attempts and S3 execution successes or failures are recorded with sanitized audit events. | **Implemented** | The broker records rejected execution attempts and S3 execution success or failure events. Audit records use sanitized metadata and exclude lease tokens, token hashes, AWS credentials, object contents, and raw exception messages. Audit-write failures fail closed. |
| **TH-17** | **Direct Cloud Access Bypass**<br>Agent bypasses broker using ambient AWS credentials, shared profiles, credential caches, or instance metadata. | **Residual risk / out of scope** | The MVP enforces authorization at the broker API but does not isolate the agent process or prevent all direct network access. Deployment must ensure the agent cannot access broker AWS credential sources or independent cloud permissions. See Section 6.2. |

---

## 6. Current Limitations and Residual Risks

### 6.1 Application Leases vs. AWS STS Credential Lifetimes
A central security distinction in AgentCap is between **application-level leases** and **cloud-level credentials**:
- An AgentCap lease is an internal database token with a short TTL (default 60 seconds) that allows a single authorized execution through the broker.
- This application lease **does not alter AWS IAM credentials**. The executor uses AWS IAM credentials (or STS assumed-role sessions). AWS STS role sessions have a minimum lifetime of 15 minutes (900 seconds) enforced by AWS.
- Therefore, lease expiration in SQLite does not automatically expire the underlying AWS credential. The security guarantee relies on the broker retaining control over the execution channel.

### 6.2 Lack of Process and Network-Level Isolation (Residual Risk)

AgentCap operates as an application-layer authorization broker:

- The broker validates requests and does not return AWS credentials in its API responses.
- The Python agent client communicates with the broker and does not need to call AWS directly to perform the approved operation.
- However, if the agent process can access ambient AWS credentials, shared `~/.aws` configuration, AWS login or SSO credential caches, environment-based credentials, or the EC2 Instance Metadata Service (`169.254.169.254`), a compromised agent may contact AWS independently of the broker.
- **Development-demo limitation:** The live local demonstration launched the broker and Python agent from the same PowerShell session. That session contained `AWS_PROFILE=agentcap-broker`, so the agent process inherited the variable. The demonstration verifies the broker-mediated workflow, but it does not prove isolation from AWS credential sources.
- **Residual Risk:** A deployment must run the agent under a separate operating-system identity or runtime that cannot read the broker's AWS environment, profiles, or credential caches. Platform-level controls must also restrict direct cloud access where required. These isolation controls are outside the current MVP.

### 6.3 HTTP Execution Endpoint and Agent Client

The HTTP execution path is implemented:

- `POST /leases/execute` accepts a lease token and requires the agent authentication header.
- The broker consumes the lease exactly once, uses the trusted consumed-lease record, rechecks policy, and executes the approved S3 operation.
- The endpoint returns object bytes encoded as Base64 together with content metadata. The response is subject to `S3_MAX_OBJECT_BYTES` (default 1 MiB).
- [`agent/client.py`](../agent/client.py) requests the lease and submits it for execution. It validates the response, strictly decodes Base64, checks the reported content length and configured size limit, and does not expose the lease token in its result representation.
- [`agent/__main__.py`](../agent/__main__.py) provides the `python -m agent` command-line interface. Output files are created exclusively rather than overwritten.

The lease remains consumed if S3 or STS execution fails. Automated tests cover successful execution, invalid and expired leases, replay attempts, authentication failures, oversized objects, and sanitized AWS errors.

### 6.4 Audit Logging Coverage

The audit subsystem records the task and execution lifecycle, including:

- Task registration.
- Lease issuance and denied lease requests.
- Successful lease consumption.
- Rejected execution attempts.
- Successful S3 execution.
- Failed S3 execution.

Audit records contain sanitized metadata. Lease tokens, token hashes, AWS credentials, object contents, and raw exception messages are excluded. Required audit writes fail closed: an operation is not reported as successful if its required audit write fails.

The live development demonstration verified four successful events for one task: `task_registered`, `lease_issued`, `lease_consumed`, and `s3_execution_succeeded`.

SQLite triggers prevent updates and deletes through normal SQL statements, but this does not make the database cryptographically tamper-proof. See Section 6.5.

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

The current MVP implements the administrator-approved task flow, single-use leases, broker-mediated S3 execution, and structured audit events. The following are deployment-hardening recommendations rather than claims of existing MVP functionality:

1. **Separate agent and broker identities:** Run the agent under an operating-system identity or runtime that cannot read the broker's AWS environment variables, AWS configuration, credential files, or login caches.
2. **Restrict cloud access from the agent runtime:** Where required, enforce platform and network controls so the agent can reach the broker without independently reaching cloud APIs or metadata services.
3. **Protect API keys:** Use a secure secret-management process, separate administrator and agent credentials, and define a rotation procedure.
4. **Protect the broker transport:** Use HTTPS for non-local deployments and restrict access to the broker API to authorized callers.
5. **Improve audit durability:** Protect database filesystem permissions, establish backup and retention procedures, and consider exporting audit events to a separately controlled system.
6. **Review production IAM configuration:** Keep the broker's role-assumption permissions and executor role policy limited to the intended S3 resources. Revalidate the policy before deployment.

These recommendations do not change the current MVP scope. The current threat model does not claim operating-system or network-level containment of a compromised agent.

## 8. Security Validation & Test Evidence

The security controls detailed in this threat model are validated through automated regression test suites.

### 8.1 Automated Test Suite Summary

The complete local automated test suite was run on 2026-11-08 and completed with **337 passed tests, 0 failures, and 1 deprecation warning**.

Run the suite with:

`.\.venv\Scripts\python.exe -m pytest -v`

The warning is a Starlette deprecation warning indicating that using `httpx` with `starlette.testclient` is deprecated and recommending `httpx2`. It did not cause test failures.

The suite covers broker authentication and task handling, lease lifecycle and concurrency, policy validation, S3 execution and error handling, and Python agent client behavior.

Dependency validation also completed successfully with:

`.\.venv\Scripts\python.exe -m pip check`

Result: `No broken requirements found.`

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

5. **Python Agent Client (`tests/test_agent_client.py`)**:
   - Agent API key attached to broker requests.
   - Successful response Base64 decoding and content metadata validation.
   - Lease token not exposed in the result representation.
   - HTTP errors sanitized.
   - Invalid Base64, mismatched content length, and oversized responses rejected.
