
import time

from broker.database import consume_lease, issue_lease


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
