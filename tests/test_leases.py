import hashlib
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from broker.database import connect, consume_lease, get_audit_events, issue_lease


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
