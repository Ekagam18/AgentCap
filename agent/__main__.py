"""Run an approved AgentCap task using the Python agent client."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from agent.client import (
    AgentCapClient,
    AgentClientError,
    BrokerHTTPError,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute an administrator-approved task through AgentCap."
    )
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()

    api_key = os.environ.get("AGENT_API_KEY")
    if not api_key:
        parser.error("Set the AGENT_API_KEY environment variable first.")

    base_url = os.environ.get(
        "AGENTCAP_URL",
        "http://127.0.0.1:8000",
    )

    if args.output.exists():
        parser.error("Output already exists. Choose a new output filename.")

    if not args.output.parent.is_dir():
        parser.error("The output directory does not exist.")

    try:
        with AgentCapClient(base_url, api_key) as client:
            result = client.execute_task(
                args.task_id,
                args.action,
                args.resource,
            )

        result.save(args.output)

    except BrokerHTTPError as exc:
        print(
            f"Broker rejected the request (HTTP {exc.status_code}).",
            file=sys.stderr,
        )
        return 1
    except AgentClientError as exc:
        print(f"Agent request failed: {exc}", file=sys.stderr)
        return 1
    except FileExistsError:
        print("Output file already exists; nothing was overwritten.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Agent client could not complete the operation: {exc}", file=sys.stderr)
        return 1

    print(f"Successfully retrieved {result.content_length} bytes.")
    print(f"Saved object to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
