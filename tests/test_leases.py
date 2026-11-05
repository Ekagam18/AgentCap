import hashlib
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from broker.database import (
    _migrate_audit_events_on_connection,
    connect,
    consume_lease,
    get_audit_events,
    issue_lease,
    migrate_audit_events_table,
    record_audit_event,
)


def test_lease_can_only_be_consumed_once(tmp_path):
    db = tmp_path / "test.db"

    token = issue_lease(
        "task-1",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        db_path=db,
    )

    first = consume_lease(token, db_path=db)
    second = consume_lease(token, db_path=db)

    assert first is not None
    assert first["task_id"] == "task-1"
    assert first["action"] == "s3:GetObject"
    assert second is None


def test_expired_lease_is_rejected(tmp_path):
    db = tmp_path / "expired.db"

    token = issue_lease(
        "task-2",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        ttl_seconds=0.01,
        db_path=db,
    )

    time.sleep(0.05)

    assert consume_lease(token, db_path=db) is None


def test_unknown_token_is_rejected(tmp_path):
    db = tmp_path / "unknown.db"

    assert consume_lease(
        "not-a-valid-token",
        db_path=db,
    ) is None


@pytest.mark.parametrize(
    "task_id,action,resource",
    [
        ("", "s3:GetObject", "s3://demo/reports/report.txt"),
        (None, "s3:GetObject", "s3://demo/reports/report.txt"),
        ("task-1", "", "s3://demo/reports/report.txt"),
        ("task-1", None, "s3://demo/reports/report.txt"),
        ("task-1", "s3:GetObject", ""),
        ("task-1", "s3:GetObject", None),
    ],
)
def test_missing_or_empty_required_fields_raise_error(tmp_path, task_id, action, resource):
    db = tmp_path / "validation.db"

    with pytest.raises(ValueError, match="task_id, action, and resource are required"):
        issue_lease(task_id, action, resource, db_path=db)


@pytest.mark.parametrize("ttl_seconds", [0, -1, -60])
def test_zero_or_negative_ttl_raises_error(tmp_path, ttl_seconds):
    db = tmp_path / "ttl.db"

    with pytest.raises(ValueError, match="ttl_seconds must be positive"):
        issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", ttl_seconds=ttl_seconds, db_path=db)


@pytest.mark.parametrize("invalid_ttl", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_ttl_raises_error(tmp_path, invalid_ttl):
    db = tmp_path / "non_finite.db"

    with pytest.raises(ValueError, match="ttl_seconds must be positive and finite"):
        issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", ttl_seconds=invalid_ttl, db_path=db)


def test_plaintext_token_is_not_stored_in_database(tmp_path):
    db = tmp_path / "hash_check.db"

    token = issue_lease(
        "task-1",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        db_path=db,
    )

    expected_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT lease_id, token_hash, task_id, action, resource, expires_at, status FROM leases")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 1
    lease_id, token_hash, task_id, action, resource, expires_at, status = rows[0]

    # Verify token_hash matches SHA-256 of the token
    assert token_hash == expected_hash
    # Verify the plaintext token itself is never stored in any column
    for col in (lease_id, token_hash, task_id, action, resource, str(expires_at), status):
        assert token not in col


def test_concurrent_consumption_allows_only_one_winner(tmp_path):
    db = tmp_path / "concurrent.db"

    token = issue_lease(
        "task-concurrent",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        ttl_seconds=60,
        db_path=db,
    )

    num_threads = 10

    def attempt_consume():
        return consume_lease(token, db_path=db)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_consume) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r is not None]
    failures = [r for r in results if r is None]

    assert len(successes) == 1
    assert len(failures) == num_threads - 1
    assert successes[0]["task_id"] == "task-concurrent"
    assert successes[0]["action"] == "s3:GetObject"


@pytest.mark.parametrize("empty_token", ["", None])
def test_empty_or_none_token_consumption_returns_none(tmp_path, empty_token):
    db = tmp_path / "empty_token.db"
    assert consume_lease(empty_token, db_path=db) is None


def test_consumed_lease_status_in_database(tmp_path):
    db = tmp_path / "status.db"

    token = issue_lease(
        "task-audit",
        "s3:GetObject",
        "s3://demo/data.csv",
        db_path=db,
    )

    lease_info = consume_lease(token, db_path=db)
    assert lease_info is not None

    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases WHERE lease_id = ?", (lease_info["lease_id"],)).fetchone()
        assert row["status"] == "consumed"


def test_audit_event_created_on_lease_issuance(tmp_path):
    db = tmp_path / "audit_issue.db"

    token = issue_lease(
        "task-10",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        db_path=db,
    )

    events = get_audit_events(db_path=db)
    assert len(events) == 1

    event = events[0]
    assert event["event_id"].startswith("evt_")
    assert isinstance(event["timestamp"], float)
    assert time.time() - 10 <= event["timestamp"] <= time.time() + 10
    assert "T" in event["timestamp_utc"]
    assert event["event_type"] == "lease_issued"
    assert event["task_id"] == "task-10"
    assert event["action"] == "s3:GetObject"
    assert event["resource"] == "s3://demo/reports/report.txt"
    assert event["outcome"] == "success"
    assert event["lease_id"] is not None

    # Never log secret token or token hash
    expected_hash = hashlib.sha256(token.encode()).hexdigest()
    for val in event.values():
        val_str = str(val)
        assert token not in val_str
        assert expected_hash not in val_str


def test_audit_event_created_on_successful_lease_consumption(tmp_path):
    db = tmp_path / "audit_consume.db"

    token = issue_lease(
        "task-20",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        db_path=db,
    )

    lease_info = consume_lease(token, db_path=db)
    assert lease_info is not None

    events = get_audit_events(db_path=db)
    assert len(events) == 2

    issue_evt = events[0]
    consume_evt = events[1]

    assert issue_evt["event_type"] == "lease_issued"
    assert consume_evt["event_type"] == "lease_consumed"
    assert consume_evt["task_id"] == "task-20"
    assert consume_evt["action"] == "s3:GetObject"
    assert consume_evt["resource"] == "s3://demo/reports/report.txt"
    assert consume_evt["outcome"] == "success"
    assert consume_evt["lease_id"] == lease_info["lease_id"]
    assert consume_evt["timestamp"] >= issue_evt["timestamp"]

    # Verify no tokens or hashes in any audit record
    expected_hash = hashlib.sha256(token.encode()).hexdigest()
    for evt in events:
        for val in evt.values():
            val_str = str(val)
            assert token not in val_str
            assert expected_hash not in val_str


def test_replayed_consumption_does_not_create_duplicate_audit_event(tmp_path):
    db = tmp_path / "audit_replay.db"

    token = issue_lease(
        "task-replay",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        db_path=db,
    )

    first = consume_lease(token, db_path=db)
    assert first is not None

    # Replay attempt
    second = consume_lease(token, db_path=db)
    assert second is None

    # Audit events must still only have 1 issue and 1 consume event
    events = get_audit_events(db_path=db)
    assert len(events) == 2
    consumed_events = [e for e in events if e["event_type"] == "lease_consumed"]
    assert len(consumed_events) == 1
    assert consumed_events[0]["outcome"] == "success"


def test_expired_lease_consumption_does_not_create_audit_event(tmp_path):
    db = tmp_path / "audit_expired.db"

    token = issue_lease(
        "task-expired",
        "s3:GetObject",
        "s3://demo/reports/report.txt",
        ttl_seconds=0.01,
        db_path=db,
    )

    time.sleep(0.05)

    result = consume_lease(token, db_path=db)
    assert result is None

    events = get_audit_events(db_path=db)
    assert len(events) == 1  # only lease_issued exists
    assert events[0]["event_type"] == "lease_issued"
    consumed_events = [e for e in events if e["event_type"] == "lease_consumed"]
    assert len(consumed_events) == 0


def test_unknown_or_empty_token_consumption_does_not_create_audit_event(tmp_path):
    db = tmp_path / "audit_unknown.db"

    assert consume_lease("non-existent-token", db_path=db) is None
    assert consume_lease("", db_path=db) is None
    assert consume_lease(None, db_path=db) is None

    events = get_audit_events(db_path=db)
    assert len(events) == 0


def test_audit_events_custom_db_path(tmp_path):
    custom_dir = tmp_path / "custom_sub_dir" / "audit_logs"
    custom_db = custom_dir / "custom_agentcap.db"

    token = issue_lease(
        "task-custom",
        "s3:GetObject",
        "s3://demo/custom.txt",
        db_path=custom_db,
    )
    assert consume_lease(token, db_path=custom_db) is not None

    assert custom_db.exists()
    events = get_audit_events(db_path=custom_db)
    assert len(events) == 2
    assert events[0]["task_id"] == "task-custom"
    assert events[1]["task_id"] == "task-custom"


def test_audit_events_table_is_append_only(tmp_path):
    db = tmp_path / "audit_append_only.db"

    issue_lease(
        "task-immutable",
        "s3:GetObject",
        "s3://demo/file.txt",
        db_path=db,
    )

    with connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="audit_events is append-only"):
            conn.execute("UPDATE audit_events SET task_id = 'tampered'")

        with pytest.raises(sqlite3.IntegrityError, match="audit_events is append-only"):
            conn.execute("DELETE FROM audit_events")

    # Verify event is intact and unmodified
    events = get_audit_events(db_path=db)
    assert len(events) == 1
    assert events[0]["task_id"] == "task-immutable"


def test_audit_events_filtered_queries(tmp_path):
    db = tmp_path / "audit_filters.db"

    tok_a = issue_lease("task-A", "s3:GetObject", "s3://demo/a.txt", db_path=db)
    tok_b = issue_lease("task-B", "s3:GetObject", "s3://demo/b.txt", db_path=db)
    consume_lease(tok_a, db_path=db)

    events_a = get_audit_events(task_id="task-A", db_path=db)
    assert len(events_a) == 2
    assert [e["event_type"] for e in events_a] == ["lease_issued", "lease_consumed"]

    events_b = get_audit_events(task_id="task-B", db_path=db)
    assert len(events_b) == 1
    assert events_b[0]["event_type"] == "lease_issued"

    consumed_only = get_audit_events(event_type="lease_consumed", db_path=db)
    assert len(consumed_only) == 1
    assert consumed_only[0]["task_id"] == "task-A"


def test_audit_events_order_by_rowid_when_timestamps_identical(tmp_path):
    db = tmp_path / "audit_identical_ts.db"

    ts = 1700000000.0
    ts_utc = "2023-11-14T22:13:20+00:00"

    with connect(db) as conn:
        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("evt_z_first_inserted", ts, ts_utc, "lease_issued", "t1", "s3:GetObject", "s3://b/k", "success", "l1"),
        )
        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("evt_a_second_inserted", ts, ts_utc, "lease_consumed", "t1", "s3:GetObject", "s3://b/k", "success", "l1"),
        )

    events = get_audit_events(db_path=db)
    assert len(events) == 2
    assert events[0]["event_id"] == "evt_z_first_inserted"
    assert events[1]["event_id"] == "evt_a_second_inserted"


def test_record_audit_event_success(tmp_path):
    db = tmp_path / "record_success.db"

    ev = record_audit_event(
        event_type="s3_execution_succeeded",
        outcome="success",
        task_id="task-success",
        action="s3:GetObject",
        resource="s3://bucket/reports/annual.csv",
        lease_id="lease-success-1",
        db_path=db,
    )

    assert ev["event_id"].startswith("evt_")
    assert ev["event_type"] == "s3_execution_succeeded"
    assert ev["outcome"] == "success"
    assert ev["task_id"] == "task-success"
    assert ev["action"] == "s3:GetObject"
    assert ev["resource"] == "s3://bucket/reports/annual.csv"
    assert ev["lease_id"] == "lease-success-1"
    assert abs(time.time() - ev["timestamp"]) < 10.0
    assert "T" in ev["timestamp_utc"]

    stored = get_audit_events(task_id="task-success", db_path=db)
    assert len(stored) == 1
    assert stored[0] == ev


def test_record_audit_event_failed_execution(tmp_path):
    db = tmp_path / "record_failed.db"

    ev = record_audit_event(
        event_type="s3_execution_failed",
        outcome="NoSuchKey",
        task_id="task-failed",
        action="s3:GetObject",
        resource="s3://bucket/missing.json",
        lease_id="lease-fail-1",
        db_path=db,
    )

    assert ev["event_type"] == "s3_execution_failed"
    assert ev["outcome"] == "NoSuchKey"

    stored = get_audit_events(event_type="s3_execution_failed", db_path=db)
    assert len(stored) == 1
    assert stored[0]["outcome"] == "NoSuchKey"


def test_record_audit_event_nullable_fields(tmp_path):
    db = tmp_path / "record_nullable.db"

    ev = record_audit_event(
        event_type="lease_execution_rejected",
        outcome="invalid_token",
        task_id=None,
        action=None,
        resource=None,
        lease_id=None,
        db_path=db,
    )

    assert ev["event_type"] == "lease_execution_rejected"
    assert ev["outcome"] == "invalid_token"
    assert ev["task_id"] is None
    assert ev["action"] is None
    assert ev["resource"] is None
    assert ev["lease_id"] is None

    stored = get_audit_events(event_type="lease_execution_rejected", db_path=db)
    assert len(stored) == 1
    assert stored[0]["task_id"] is None
    assert stored[0]["action"] is None
    assert stored[0]["resource"] is None
    assert stored[0]["lease_id"] is None


@pytest.mark.parametrize(
    "ev_type,outcome,task_id,action,resource,lease_id",
    [
        ("", "success", None, None, None, None),
        ("   ", "success", None, None, None, None),
        (123, "success", None, None, None, None),
        ("s3_execution_succeeded", "", None, None, None, None),
        ("s3_execution_succeeded", "   ", None, None, None, None),
        ("s3_execution_succeeded", None, None, None, None, None),
        ("s3_execution_succeeded", 456, None, None, None, None),
        ("s3_execution_failed", "Error\nTraceback (most recent call last):", None, None, None, None),
        ("s3_execution_failed", "Traceback (most recent call last): line 1", None, None, None, None),
        ("s3_execution_succeeded", '{"bucket": "demo", "data": "body"}', None, None, None, None),
        ("s3_execution_succeeded", "b'raw_binary_content'", None, None, None, None),
        ("s3_execution_failed", "AKIAIOSFODNN7EXAMPLE", None, None, None, None),
        ("s3_execution_failed", "a" * 64, None, None, None, None),
        ("s3_execution_succeeded", "success", "", None, None, None),
        ("s3_execution_succeeded", "success", None, "", None, None),
        ("s3_execution_succeeded", "success", None, None, "", None),
        ("s3_execution_succeeded", "success", None, None, None, ""),
        ("s3_execution_succeeded", "success", "task\nid", None, None, None),
    ],
)
def test_record_audit_event_validation_errors(tmp_path, ev_type, outcome, task_id, action, resource, lease_id):
    db = tmp_path / "record_validation.db"

    with pytest.raises(ValueError):
        record_audit_event(
            event_type=ev_type,
            outcome=outcome,
            task_id=task_id,
            action=action,
            resource=resource,
            lease_id=lease_id,
            db_path=db,
        )


def test_record_audit_event_append_only(tmp_path):
    db = tmp_path / "record_append_only.db"

    ev = record_audit_event(
        event_type="s3_execution_succeeded",
        outcome="success",
        task_id="task-immutable",
        action="s3:GetObject",
        resource="s3://bucket/data",
        lease_id="lease-imm",
        db_path=db,
    )

    with connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE audit_events SET outcome = 'tampered' WHERE event_id = ?",
                (ev["event_id"],),
            )

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "DELETE FROM audit_events WHERE event_id = ?",
                (ev["event_id"],),
            )


def test_audit_events_schema_migration_from_old_schema(tmp_path):
    db = tmp_path / "old_schema.db"

    # Manually create the old schema with NOT NULL constraints
    conn = sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            lease_id TEXT
        )
    """)
    conn.execute("CREATE INDEX idx_audit_events_task_id ON audit_events (task_id)")
    conn.execute("CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp)")
    conn.execute("""
        CREATE TRIGGER prevent_audit_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
    """)
    conn.execute("""
        CREATE TRIGGER prevent_audit_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
    """)

    # Populate historical records with identical timestamps to verify deterministic rowid ordering
    fixed_ts = 1700000000.0
    fixed_ts_utc = "2023-11-14T22:13:20+00:00"
    conn.execute(
        """INSERT INTO audit_events
        (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ("evt_hist_1", fixed_ts, fixed_ts_utc, "lease_issued", "task-hist", "s3:GetObject", "s3://b/k1", "success", "l1"),
    )
    conn.execute(
        """INSERT INTO audit_events
        (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ("evt_hist_2", fixed_ts, fixed_ts_utc, "lease_consumed", "task-hist", "s3:GetObject", "s3://b/k1", "success", "l1"),
    )
    conn.commit()

    # Pre-migration verification: NOT NULL constraints present
    columns_before = {col[1]: col[3] for col in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert columns_before["task_id"] == 1
    assert columns_before["action"] == 1
    assert columns_before["resource"] == 1

    # Attempting to insert NULL before migration must fail
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("evt_null_fail", fixed_ts, fixed_ts_utc, "lease_execution_rejected", None, None, None, "rejected", None),
        )

    conn.close()

    # Execute migration
    migrated = migrate_audit_events_table(db)
    assert migrated is True

    # Post-migration verification
    conn2 = sqlite3.connect(db)
    conn2.row_factory = sqlite3.Row

    # 1. task_id, action, resource are now nullable
    cols_info = conn2.execute("PRAGMA table_info(audit_events)").fetchall()
    columns_after = {col["name"]: col["notnull"] for col in cols_info}
    pks_after = {col["name"]: col["pk"] for col in cols_info}
    assert columns_after["task_id"] == 0
    assert columns_after["action"] == 0
    assert columns_after["resource"] == 0
    assert pks_after["event_id"] == 1
    assert columns_after["timestamp"] == 1
    assert columns_after["timestamp_utc"] == 1
    assert columns_after["event_type"] == 1
    assert columns_after["outcome"] == 1

    # 2. Historical rows and their order are strictly preserved
    historical_events = get_audit_events(task_id="task-hist", db_path=db)
    assert len(historical_events) == 2
    assert historical_events[0]["event_id"] == "evt_hist_1"
    assert historical_events[1]["event_id"] == "evt_hist_2"

    # 3. Inserting nullable fields now succeeds
    record_audit_event(
        event_type="lease_execution_rejected",
        outcome="rejected_invalid_lease",
        task_id=None,
        action=None,
        resource=None,
        lease_id=None,
        db_path=db,
    )
    rejected_events = get_audit_events(event_type="lease_execution_rejected", db_path=db)
    assert len(rejected_events) == 1
    assert rejected_events[0]["outcome"] == "rejected_invalid_lease"

    # 4. Indexes exist and are operational
    index_names = [row["name"] for row in conn2.execute("PRAGMA index_list(audit_events)").fetchall()]
    assert "idx_audit_events_task_id" in index_names
    assert "idx_audit_events_timestamp" in index_names

    # 5. Append-only triggers are active
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn2.execute("UPDATE audit_events SET outcome = 'tampered' WHERE event_id = 'evt_hist_1'")

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn2.execute("DELETE FROM audit_events WHERE event_id = 'evt_hist_1'")

    conn2.close()


def test_audit_events_migration_idempotent(tmp_path):
    db = tmp_path / "idempotent.db"
    connect(db)

    # Database is already up to date, migration should return False
    first_check = migrate_audit_events_table(db)
    assert first_check is False

    # Second check returns False
    second_check = migrate_audit_events_table(db)
    assert second_check is False


def test_connect_auto_migrates_existing_database(tmp_path):
    db = tmp_path / "auto_migrate.db"

    # Create old database
    conn = sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            lease_id TEXT
        )
    """)
    conn.execute(
        """INSERT INTO audit_events
        (event_id, timestamp, timestamp_utc, event_type, task_id, action, resource, outcome, lease_id)
        VALUES ('evt_old', 1.0, '2023-01-01T00:00:00+00:00', 'lease_issued', 't1', 's3:GetObject', 's3://b/k', 'success', 'l1')"""
    )
    conn.commit()
    conn.close()

    # Calling connect() should automatically migrate
    conn_migrated = connect(db)
    cols = {c["name"]: c["notnull"] for c in conn_migrated.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert cols["task_id"] == 0
    assert cols["action"] == 0
    assert cols["resource"] == 0

    events = get_audit_events(db_path=db)
    assert len(events) == 1
    assert events[0]["event_id"] == "evt_old"
    conn_migrated.close()


def test_record_audit_event_with_open_connection(tmp_path):
    db = tmp_path / "open_conn.db"
    conn = connect(db)

    # Explicitly start a transaction before calling record_audit_event
    conn.execute("BEGIN IMMEDIATE")
    assert conn.in_transaction is True

    record_audit_event(
        event_type="s3_execution_succeeded",
        outcome="success",
        task_id="t-conn",
        action="s3:GetObject",
        resource="s3://b/k",
        lease_id="l-conn",
        db_path=conn,
    )
    conn.commit()

    events = get_audit_events(task_id="t-conn", db_path=conn)
    assert len(events) == 1
    assert events[0]["outcome"] == "success"
    conn.close()


def test_record_audit_event_connection_without_active_transaction_checks_inside_transaction(tmp_path, monkeypatch):
    import broker.database

    db = tmp_path / "check_in_tx.db"
    conn = connect(db)
    assert conn.in_transaction is False

    in_tx_states = []
    original_checker = broker.database._check_plaintext_tokens_in_connection

    def spy_checker(c, fields):
        in_tx_states.append(c.in_transaction)
        return original_checker(c, fields)

    monkeypatch.setattr(broker.database, "_check_plaintext_tokens_in_connection", spy_checker)

    record_audit_event(
        event_type="s3_execution_succeeded",
        outcome="success",
        task_id="task-fresh-conn",
        action="s3:GetObject",
        resource="s3://bucket/reports/report.txt",
        db_path=conn,
    )

    # Verified: Token/hash checker executed while conn.in_transaction was True
    assert in_tx_states == [True]
    # And after successful completion, the transaction was committed
    assert conn.in_transaction is False

    # Verify rollback behavior when checker raises inside transaction
    def failing_checker(c, fields):
        in_tx_states.append(c.in_transaction)
        raise ValueError("simulated token rejection")

    monkeypatch.setattr(broker.database, "_check_plaintext_tokens_in_connection", failing_checker)

    with pytest.raises(ValueError, match="simulated token rejection"):
        record_audit_event(
            event_type="s3_execution_succeeded",
            outcome="success",
            task_id="task-fresh-conn-fail",
            action="s3:GetObject",
            resource="s3://bucket/reports/report.txt",
            db_path=conn,
        )

    # Checker ran inside the transaction
    assert in_tx_states[-1] is True
    # Transaction was rolled back by with conn context manager
    assert conn.in_transaction is False

    events = get_audit_events(task_id="task-fresh-conn-fail", db_path=conn)
    assert len(events) == 0

    conn.close()


def test_record_audit_event_rejects_plaintext_lease_tokens(tmp_path):
    db = tmp_path / "token_rejection.db"
    token = issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)
    assert len(token) == 43

    # In task_id
    with pytest.raises(ValueError, match="prohibited plaintext lease token"):
        record_audit_event("s3_execution_succeeded", "success", task_id=token, db_path=db)

    # In lease_id
    with pytest.raises(ValueError, match="prohibited plaintext lease token"):
        record_audit_event("s3_execution_succeeded", "success", lease_id=token, db_path=db)

    # In resource
    with pytest.raises(ValueError, match="prohibited plaintext lease token"):
        record_audit_event("s3_execution_succeeded", "success", resource=f"s3://bucket/{token}", db_path=db)

    # In outcome
    with pytest.raises(ValueError):
        record_audit_event("s3_execution_succeeded", outcome=token, db_path=db)

    # In event_type
    with pytest.raises(ValueError):
        record_audit_event(token, "success", db_path=db)


def test_record_audit_event_token_hash_validation_and_s3_key_compatibility(tmp_path):
    db = tmp_path / "hash_compat.db"
    token = issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert len(token_hash) == 64

    # 1. Actual lease token hash as a standalone resource key (lowercase & uppercase)
    with pytest.raises(ValueError, match="resource contains prohibited lease token hash"):
        record_audit_event("s3_execution_succeeded", "success", resource=f"s3://bucket/{token_hash}", db_path=db)

    with pytest.raises(ValueError, match="resource contains prohibited lease token hash"):
        record_audit_event("s3_execution_succeeded", "success", resource=f"s3://bucket/{token_hash.upper()}", db_path=db)

    # 2. Actual lease token hash embedded in a longer resource key
    with pytest.raises(ValueError, match="resource contains prohibited lease token hash"):
        record_audit_event(
            "s3_execution_succeeded",
            "success",
            resource=f"s3://bucket/reports/prefix_{token_hash}_suffix.json",
            db_path=db,
        )

    # 3. Actual lease token hash in task_id and lease_id
    with pytest.raises(ValueError, match="task_id contains prohibited lease token hash"):
        record_audit_event("s3_execution_succeeded", "success", task_id=token_hash, db_path=db)

    with pytest.raises(ValueError, match="lease_id contains prohibited lease token hash"):
        record_audit_event("s3_execution_succeeded", "success", lease_id=token_hash, db_path=db)

    # 4. An unrelated SHA-256 S3 object key being accepted
    unrelated_hash = hashlib.sha256(b"content-addressable-object").hexdigest()
    assert unrelated_hash != token_hash
    unrelated_s3_uri = f"s3://bucket/{unrelated_hash}"
    ev1 = record_audit_event("s3_execution_succeeded", "success", resource=unrelated_s3_uri, db_path=db)
    assert ev1["resource"] == unrelated_s3_uri

    # 5. An unrelated 64-character hash embedded in a longer S3 key being accepted
    unrelated_embedded_uri = f"s3://bucket/reports/data_{unrelated_hash}.json"
    ev2 = record_audit_event("s3_execution_succeeded", "success", resource=unrelated_embedded_uri, db_path=db)
    assert ev2["resource"] == unrelated_embedded_uri

    # Also verify issue_lease succeeds for such legitimate S3 resources
    issued_tok = issue_lease("task-sha", "s3:GetObject", unrelated_s3_uri, db_path=db)
    assert issued_tok is not None


def test_exact_token_hash_detection_with_connection_and_transaction_atomicity(tmp_path):
    db = tmp_path / "hash_conn_atomicity.db"
    token = issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    conn = connect(db)
    conn.execute("BEGIN IMMEDIATE")
    assert conn.in_transaction is True

    # Recording audit event with actual token hash on active connection must fail
    with pytest.raises(ValueError, match="resource contains prohibited lease token hash"):
        record_audit_event(
            "s3_execution_succeeded",
            "success",
            resource=f"s3://bucket/reports/run_{token_hash}.json",
            db_path=conn,
        )

    # Transaction is still active and can be rolled back safely
    assert conn.in_transaction is True
    conn.rollback()

    events = get_audit_events(db_path=conn)
    assert len(events) == 1
    conn.close()


def test_record_audit_event_embedded_plaintext_lease_tokens(tmp_path):
    db = tmp_path / "embedded_tokens.db"
    token = issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)
    assert len(token) == 43

    # Case A: Actual token delimited by non-URL-safe characters
    delimited_cases = [
        f"Bearer {token}",
        f"?token={token}",
        f"token:{token}",
        f"[{token}]",
    ]
    for delimited in delimited_cases:
        with pytest.raises(ValueError, match="task_id contains prohibited plaintext lease token"):
            record_audit_event("s3_execution_succeeded", "success", task_id=delimited, db_path=db)

    # Case B: Actual token embedded contiguously with URL-safe characters [A-Za-z0-9_-]
    # Exact token detection extracts all 43-character candidates, hashes them, and rejects
    # any string containing the actual issued lease token
    contiguous_cases = [
        f"prefix_{token}",
        f"{token}_suffix",
        f"prefix_{token}_suffix",
        f"task-{token}-run",
    ]
    for contiguous in contiguous_cases:
        with pytest.raises(ValueError, match="task_id contains prohibited plaintext lease token"):
            record_audit_event("s3_execution_succeeded", "success", task_id=contiguous, db_path=db)

    # Case C: Actual token embedded in S3 resource URI
    with pytest.raises(ValueError, match="resource contains prohibited plaintext lease token"):
        record_audit_event("s3_execution_succeeded", "success", resource=f"s3://bucket/{token}", db_path=db)

    with pytest.raises(ValueError, match="resource contains prohibited plaintext lease token"):
        record_audit_event(
            "s3_execution_succeeded",
            "success",
            resource=f"s3://bucket/reports/prefix_{token}_suffix.json",
            db_path=db,
        )

    # Case D: Unrelated valid 43-character identifiers and S3 object keys MUST NOT be rejected
    unrelated_43_task_id = "task-" + "x" * 38
    assert len(unrelated_43_task_id) == 43
    ev1 = record_audit_event("s3_execution_succeeded", "success", task_id=unrelated_43_task_id, db_path=db)
    assert ev1["task_id"] == unrelated_43_task_id

    unrelated_50_task_id = "task-custom-identifier-" + "a" * 27
    assert len(unrelated_50_task_id) == 50
    ev2 = record_audit_event("s3_execution_succeeded", "success", task_id=unrelated_50_task_id, db_path=db)
    assert ev2["task_id"] == unrelated_50_task_id

    unrelated_43_key = "k" * 43
    unrelated_s3_uri = f"s3://bucket/{unrelated_43_key}"
    ev3 = record_audit_event("s3_execution_succeeded", "success", resource=unrelated_s3_uri, db_path=db)
    assert ev3["resource"] == unrelated_s3_uri

    unrelated_long_uri = f"s3://bucket/reports/{'v' * 60}.json"
    ev4 = record_audit_event("s3_execution_succeeded", "success", resource=unrelated_long_uri, db_path=db)
    assert ev4["resource"] == unrelated_long_uri


def test_exact_token_detection_with_connection_and_transaction_atomicity(tmp_path):
    db = tmp_path / "conn_atomicity.db"
    token = issue_lease("task-1", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)

    conn = connect(db)
    conn.execute("BEGIN IMMEDIATE")
    assert conn.in_transaction is True

    # Recording audit event with embedded actual token on active connection must fail
    with pytest.raises(ValueError, match="task_id contains prohibited plaintext lease token"):
        record_audit_event(
            "s3_execution_succeeded",
            "success",
            task_id=f"prefix_{token}_suffix",
            db_path=conn,
        )

    # Transaction is still active and can be rolled back safely
    assert conn.in_transaction is True
    conn.rollback()

    # Verify no new audit event was committed
    events = get_audit_events(db_path=conn)
    assert len(events) == 1  # only lease_issued from issue_lease
    conn.close()


@pytest.mark.parametrize(
    "raw_exc",
    [
        "An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.",
        "ValueError: invalid token supplied",
        "AWS S3 error (NoSuchKey) during GetObject",
        "botocore.exceptions.ClientError: An error occurred",
        "Exception: unexpected system failure",
    ],
)
def test_record_audit_event_rejects_raw_exception_messages(tmp_path, raw_exc):
    db = tmp_path / "raw_exc.db"
    with pytest.raises(ValueError, match="known sanitized status code"):
        record_audit_event("s3_execution_failed", outcome=raw_exc, db_path=db)


@pytest.mark.parametrize(
    "raw_content",
    [
        "Hello world raw content from S3 object file",
        "col1,col2,col3,val1,val2,val3",
        '{"user_id": 12345, "secret": "confidential_data"}',
        "<html><body>403 Forbidden</body></html>",
        '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
        "%PDF-1.4 file binary header",
    ],
)
def test_record_audit_event_rejects_raw_object_content(tmp_path, raw_content):
    db = tmp_path / "raw_content.db"
    with pytest.raises(ValueError, match="known sanitized status code"):
        record_audit_event("s3_execution_succeeded", outcome=raw_content, db_path=db)


@pytest.mark.parametrize("invalid_ev", ["s3_execution_attempted", "custom_event", "invalid", "s3:GetObject"])
def test_record_audit_event_rejects_invalid_event_types(tmp_path, invalid_ev):
    db = tmp_path / "invalid_ev.db"
    with pytest.raises(ValueError, match="Invalid event_type"):
        record_audit_event(invalid_ev, "success", db_path=db)


@pytest.mark.parametrize("invalid_action", ["s3:PutObject", "s3:DeleteObject", "s3:*", "GetObject"])
def test_record_audit_event_rejects_invalid_actions(tmp_path, invalid_action):
    db = tmp_path / "invalid_act.db"
    with pytest.raises(ValueError, match="Supported policy action is"):
        record_audit_event("s3_execution_succeeded", "success", action=invalid_action, db_path=db)


@pytest.mark.parametrize(
    "invalid_resource",
    [
        "https://bucket.s3.amazonaws.com/file.txt",
        "s3://bucket/reports/../secret.txt",
        "s3://bucket/reports/./file.txt",
        "s3://bucket/dir/",
        "s3://bucket/*.txt",
        "s3://bucket",
    ],
)
def test_record_audit_event_rejects_invalid_s3_resources(tmp_path, invalid_resource):
    db = tmp_path / "invalid_res.db"
    with pytest.raises(ValueError):
        record_audit_event("s3_execution_succeeded", "success", resource=invalid_resource, db_path=db)


@pytest.mark.parametrize(
    "valid_task,valid_lease",
    [
        ("task-1", "l1"),
        ("task-hist", "lease-success-1"),
        ("task-success", "lease-imm"),
        ("analytics-run-42", "l-conn"),
        ("t1", secrets.token_urlsafe(12)),
    ],
)
def test_record_audit_event_preserves_valid_task_and_lease_ids(tmp_path, valid_task, valid_lease):
    db = tmp_path / "valid_ids.db"
    ev = record_audit_event(
        event_type="s3_execution_succeeded",
        outcome="success",
        task_id=valid_task,
        action="s3:GetObject",
        resource="s3://demo/reports/report.txt",
        lease_id=valid_lease,
        db_path=db,
    )
    assert ev["task_id"] == valid_task
    assert ev["lease_id"] == valid_lease


def test_audit_events_migration_savepoint_in_active_transaction(tmp_path):
    db = tmp_path / "active_txn_mig.db"
    conn = sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            lease_id TEXT
        )
    """)
    conn.execute(
        "INSERT INTO audit_events VALUES ('e1', 1.0, '2023-01-01T00:00:00Z', 'lease_issued', 't1', 's3:GetObject', 's3://b/k', 'success', 'l1')"
    )
    conn.commit()

    # Open transaction before calling migration
    conn.execute("BEGIN IMMEDIATE")
    assert conn.in_transaction is True

    migrated = migrate_audit_events_table(conn)
    assert migrated is True
    assert conn.in_transaction is True

    # Commit caller's transaction
    conn.commit()

    # Verify migrated schema and record
    cols = {c[1]: c[3] for c in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert cols["task_id"] == 0
    assert cols["action"] == 0
    assert cols["resource"] == 0
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    conn.close()


def test_issue_lease_transaction_atomicity_on_audit_failure(tmp_path, monkeypatch):
    import broker.database

    db = tmp_path / "issue_atomicity.db"

    def fail_record_audit_event(*args, **kwargs):
        raise RuntimeError("Simulated audit write failure during issue")

    monkeypatch.setattr(broker.database, "record_audit_event", fail_record_audit_event)

    with pytest.raises(RuntimeError, match="Simulated audit write failure during issue"):
        issue_lease("task-atom", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)

    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_consume_lease_transaction_atomicity_on_audit_failure(tmp_path, monkeypatch):
    import broker.database

    db = tmp_path / "consume_atomicity.db"

    token = issue_lease("task-atom-2", "s3:GetObject", "s3://demo/reports/report.txt", db_path=db)

    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM leases WHERE status = 'issued'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1

    def fail_record_audit_event(*args, **kwargs):
        raise RuntimeError("Simulated audit write failure during consume")

    monkeypatch.setattr(broker.database, "record_audit_event", fail_record_audit_event)

    with pytest.raises(RuntimeError, match="Simulated audit write failure during consume"):
        consume_lease(token, db_path=db)

    # Verification: lease is still 'issued' and not 'consumed', and no duplicate/failed audit event committed
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "issued"
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1

    # Unpatch and verify normal consumption still succeeds
    monkeypatch.undo()
    consumed = consume_lease(token, db_path=db)
    assert consumed is not None
    assert consumed["task_id"] == "task-atom-2"

    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "consumed"
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2


def test_audit_events_migration_savepoint_failure_rollback(tmp_path):
    db = tmp_path / "mig_fail.db"
    conn = sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            lease_id TEXT
        )
    """)
    conn.execute(
        "INSERT INTO audit_events VALUES ('e1', 1.0, '2026-01-01', 'lease_issued', 't1', 's3:GetObject', 's3://b/k', 'success', 'l1')"
    )
    conn.commit()

    # 1. Start an outer SQLite transaction
    conn.execute("BEGIN IMMEDIATE")
    assert conn.in_transaction is True

    # 2. Force migration to fail after its savepoint is created
    class FaultInjectingConnection:
        def __init__(self, real_conn):
            self._conn = real_conn

        @property
        def in_transaction(self):
            return self._conn.in_transaction

        def execute(self, sql, *args, **kwargs):
            if "ALTER TABLE audit_events_new RENAME" in sql:
                raise sqlite3.OperationalError("Simulated failure during table rename")
            return self._conn.execute(sql, *args, **kwargs)

    proxy = FaultInjectingConnection(conn)

    with pytest.raises(sqlite3.OperationalError, match="Simulated failure during table rename"):
        _migrate_audit_events_on_connection(proxy)

    # 3. Verify original schema and historical records remain intact
    cols = {c[1]: c[3] for c in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert cols["task_id"] == 1  # Still NOT NULL!
    assert cols["action"] == 1
    assert cols["resource"] == 1

    row = conn.execute("SELECT * FROM audit_events").fetchone()
    assert row[0] == "e1"

    # 4. Verify the outer transaction remains active
    assert conn.in_transaction is True

    # 5. Verify the connection can still execute SQL and commit or roll back
    conn.execute("CREATE TABLE outer_work (val INT)")
    conn.execute("INSERT INTO outer_work VALUES (999)")
    conn.commit()

    assert conn.execute("SELECT * FROM outer_work").fetchone()[0] == 999
    conn.close()
