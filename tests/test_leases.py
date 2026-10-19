import hashlib
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from broker.database import connect, consume_lease, issue_lease


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
