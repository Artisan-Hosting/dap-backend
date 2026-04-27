#!/usr/bin/env python3
"""Verbose backend debug client.

This script is intentionally chatty because it is meant to help debug the local
backend service end to end.

Default flow:
1. Query `GET /v1/tests`
2. Print every supported test the server currently exposes
3. Submit a run for `artisanhosting.net` using every returned test id
4. Poll `GET /v1/runs/{run_id}` until the run reaches a terminal state
5. Fetch `results` and `report` payloads
6. Save raw JSON snapshots under `artifacts/debug-client/...`
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request


TERMINAL_RUN_STATES = {"completed", "failed", "cache_hit", "canceled"}


@dataclass
class HttpJsonResponse:
    status_code: int
    body: dict[str, Any]


class HttpJsonError(Exception):
    def __init__(self, url: str, status_code: int, body: dict[str, Any] | str) -> None:
        super().__init__(f"HTTP {status_code} for {url}")
        self.url = url
        self.status_code = status_code
        self.body = body


class RequestTransportError(Exception):
    def __init__(self, url: str, message: str) -> None:
        super().__init__(message)
        self.url = url
        self.message = message


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verbose debug client for the Artisan DAP backend server."
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:3000",
        help="Backend base URL. Default: %(default)s",
    )
    parser.add_argument(
        "--target",
        default="artisanhosting.net",
        help="Domain or hostname to audit. Default: %(default)s",
    )
    parser.add_argument(
        "--test",
        action="append",
        default=[],
        help=(
            "Specific test id to run. Repeat this flag to run a subset. "
            "If omitted, the script submits every test returned by GET /v1/tests."
        ),
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Request a fresh run instead of allowing cache reuse.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between run status polls. Default: %(default)s",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=600.0,
        help="Maximum time to wait for completion before exiting. Default: %(default)s",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/debug-client",
        help="Directory where raw JSON snapshots should be written. Default: %(default)s",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def session_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def log(message: str) -> None:
    print(f"[{utc_now()}] {message}", flush=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def save_json(directory: Path, name: str, payload: Any) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(pretty_json(payload) + "\n", encoding="utf-8")
    log(f"Saved JSON snapshot to {path}")


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> HttpJsonResponse:
    headers = {"accept": "application/json"}
    data: bytes | None = None

    if payload is not None:
        headers["content-type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    log(f"HTTP {method} {url}")
    if payload is not None:
        print(pretty_json(payload), flush=True)

    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            status_code = response.status
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        log(f"HTTP error {exc.code} while requesting {url}")
        parsed_body: dict[str, Any] | str
        try:
            parsed_body = json.loads(raw)
        except json.JSONDecodeError:
            parsed_body = raw

        if isinstance(parsed_body, dict):
            print(pretty_json(parsed_body), flush=True)
        elif str(parsed_body).strip():
            print(parsed_body, flush=True)

        raise HttpJsonError(url=url, status_code=exc.code, body=parsed_body) from exc
    except error.URLError as exc:
        message = f"Request to {url} failed: {exc}"
        log(message)
        raise RequestTransportError(url=url, message=message) from exc

    log(f"HTTP {status_code} response received from {url}")

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        log(f"Response body from {url} was not valid JSON: {exc}")
        print(raw, flush=True)
        raise

    return HttpJsonResponse(status_code=status_code, body=body)


def print_supported_tests(tests: list[dict[str, Any]]) -> None:
    log(f"Supported tests reported by the backend: {len(tests)}")
    for index, test in enumerate(tests, start=1):
        test_id = test.get("id", "<missing id>")
        name = test.get("name", "<missing name>")
        version = test.get("version", "<missing version>")
        runtime = test.get("runtime", "<missing runtime>")
        category = test.get("category", "<missing category>")
        timeout_seconds = test.get("timeout_seconds", "<missing timeout>")
        log(
            f"  {index:02d}. id={test_id} | name={name} | category={category} | "
            f"runtime={runtime} | timeout_seconds={timeout_seconds} | version={version}"
        )


def choose_tests(
    available_tests: list[dict[str, Any]],
    requested_test_ids: list[str],
) -> list[str]:
    available_ids = [str(test.get("id")) for test in available_tests if test.get("id")]
    available_set = set(available_ids)

    if requested_test_ids:
        missing = [test_id for test_id in requested_test_ids if test_id not in available_set]
        if missing:
            log("Requested test ids were not present in GET /v1/tests:")
            for test_id in missing:
                log(f"  - {test_id}")
            raise SystemExit(2)
        return requested_test_ids

    return available_ids


def print_run_submission(run_payload: dict[str, Any]) -> None:
    log("Run submission response:")
    print(pretty_json(run_payload), flush=True)


def print_status_summary(status_payload: dict[str, Any], poll_number: int, started_at: float) -> None:
    state = status_payload.get("state", "<missing>")
    elapsed = time.monotonic() - started_at
    counts = status_payload.get("counts") or {}
    planned = counts.get("planned", 0)
    completed = counts.get("completed", 0)
    failed_to_start = counts.get("failed_to_start", 0)
    rejected_not_applicable = counts.get("rejected_not_applicable", 0)

    log(
        f"Poll #{poll_number}: state={state} | elapsed={elapsed:.1f}s | "
        f"planned={planned} | completed={completed} | "
        f"failed_to_start={failed_to_start} | "
        f"rejected_not_applicable={rejected_not_applicable}"
    )

    requested_tests = status_payload.get("requested_tests") or []
    if requested_tests:
        log("Per-requested-test status snapshot:")
        for item in requested_tests:
            test_id = item.get("test_id", "<missing>")
            test_state = item.get("state", "<missing>")
            reason = item.get("reason")
            if reason:
                log(f"  - {test_id}: {test_state} | reason={reason}")
            else:
                log(f"  - {test_id}: {test_state}")


def print_results_summary(results_payload: dict[str, Any]) -> None:
    requested_outcomes = results_payload.get("requested_test_outcomes") or []
    results = results_payload.get("results") or []

    log(
        f"Final results payload contains {len(requested_outcomes)} requested outcome row(s) "
        f"and {len(results)} result row(s)."
    )

    if requested_outcomes:
        log("Requested test outcomes:")
        for outcome in requested_outcomes:
            test_id = outcome.get("test_id", "<missing>")
            state = outcome.get("state", "<missing>")
            reason = outcome.get("reason")
            if reason:
                log(f"  - {test_id}: {state} | reason={reason}")
            else:
                log(f"  - {test_id}: {state}")

    if results:
        log("Individual result rows:")
        for result in results:
            result_id = result.get("result_id", "<missing>")
            target = result.get("target", "<missing>")
            test_id = result.get("test_id", "<missing>")
            status = result.get("status", "<missing>")
            severity = result.get("severity", "<missing>")
            notes = result.get("notes")
            log(
                f"  - result_id={result_id} | target={target} | test_id={test_id} | "
                f"status={status} | severity={severity}"
            )
            if notes:
                log(f"    notes={notes}")


def print_report_summary(report_payload: dict[str, Any]) -> None:
    summary = report_payload.get("summary") or {}
    run = report_payload.get("run") or {}
    site_profiles = report_payload.get("site_profiles") or []
    dead_hosts = report_payload.get("dead_hosts") or []
    results = report_payload.get("results") or []
    artifacts = report_payload.get("artifacts") or []

    log(
        f"Report summary for run_id={run.get('run_id', '<missing>')} | "
        f"state={run.get('state', '<missing>')} | site_profiles={len(site_profiles)} | "
        f"dead_hosts={len(dead_hosts)} | results={len(results)} | artifacts={len(artifacts)}"
    )
    print(pretty_json(summary), flush=True)


def main() -> int:
    args = parse_args()
    session_dir = Path(args.output_dir) / session_stamp()
    session_dir.mkdir(parents=True, exist_ok=True)

    log(f"Debug session directory: {session_dir}")
    log(f"Backend base URL: {args.base_url}")
    log(f"Target: {args.target}")
    log(f"Force refresh: {args.force_refresh}")
    log(f"Poll interval: {args.poll_interval}s")
    log(f"Overall timeout: {args.timeout_seconds}s")

    try:
        tests_response = request_json("GET", f"{args.base_url}/v1/tests")
    except HttpJsonError as exc:
        save_json(
            session_dir,
            "error_tests_endpoint.json",
            {
                "url": exc.url,
                "status_code": exc.status_code,
                "body": exc.body,
            },
        )
        log("Failed while loading supported tests.")
        return 1
    except RequestTransportError as exc:
        save_json(
            session_dir,
            "error_tests_endpoint_transport.json",
            {
                "url": exc.url,
                "message": exc.message,
            },
        )
        log("Failed while loading supported tests due to a transport error.")
        return 1

    save_json(session_dir, "01_tests.json", tests_response.body)

    tests = tests_response.body.get("tests")
    if not isinstance(tests, list):
        log("GET /v1/tests returned an unexpected payload shape.")
        print(pretty_json(tests_response.body), flush=True)
        return 2

    print_supported_tests(tests)
    selected_tests = choose_tests(tests, args.test)
    log(f"Selected {len(selected_tests)} test id(s) for submission.")
    for test_id in selected_tests:
        log(f"  - submitting test_id={test_id}")

    submit_payload = {
        "target": args.target,
        "requested_tests": selected_tests,
        "force_refresh": args.force_refresh,
        "client_request_id": f"debug-client-{session_stamp()}",
    }
    try:
        run_response = request_json("POST", f"{args.base_url}/v1/runs", submit_payload)
    except HttpJsonError as exc:
        save_json(
            session_dir,
            "error_run_create.json",
            {
                "url": exc.url,
                "status_code": exc.status_code,
                "body": exc.body,
            },
        )
        log("Run creation failed.")
        return 1
    except RequestTransportError as exc:
        save_json(
            session_dir,
            "error_run_create_transport.json",
            {
                "url": exc.url,
                "message": exc.message,
            },
        )
        log("Run creation failed due to a transport error.")
        return 1

    save_json(session_dir, "02_run_create.json", run_response.body)
    print_run_submission(run_response.body)

    run_id = run_response.body.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        log("POST /v1/runs did not return a usable run_id.")
        return 2

    log(f"Tracking run_id={run_id}")
    status_url = f"{args.base_url}/v1/runs/{run_id}"
    results_url = f"{args.base_url}/v1/runs/{run_id}/results"
    report_url = f"{args.base_url}/v1/runs/{run_id}/report"

    started_at = time.monotonic()
    deadline = started_at + args.timeout_seconds
    poll_number = 0
    final_status: dict[str, Any] | None = None

    while time.monotonic() <= deadline:
        poll_number += 1
        try:
            status_response = request_json("GET", status_url)
        except HttpJsonError as exc:
            save_json(
                session_dir,
                f"error_status_{poll_number:03d}.json",
                {
                    "url": exc.url,
                    "status_code": exc.status_code,
                    "body": exc.body,
                    "run_id": run_id,
                    "poll_number": poll_number,
                },
            )
            log("Polling failed due to an HTTP error from the backend.")
            return 1
        except RequestTransportError as exc:
            save_json(
                session_dir,
                f"error_status_transport_{poll_number:03d}.json",
                {
                    "url": exc.url,
                    "message": exc.message,
                    "run_id": run_id,
                    "poll_number": poll_number,
                },
            )
            log("Polling failed due to a transport error.")
            return 1

        final_status = status_response.body
        save_json(session_dir, f"status_{poll_number:03d}.json", status_response.body)
        save_json(session_dir, "status_latest.json", status_response.body)
        print_status_summary(status_response.body, poll_number, started_at)

        state = status_response.body.get("state")
        if state in TERMINAL_RUN_STATES:
            log(f"Run reached terminal state: {state}")
            break

        time.sleep(args.poll_interval)
    else:
        log(f"Run did not finish within {args.timeout_seconds}s.")
        return 3

    try:
        results_response = request_json("GET", results_url)
    except HttpJsonError as exc:
        save_json(
            session_dir,
            "error_results.json",
            {
                "url": exc.url,
                "status_code": exc.status_code,
                "body": exc.body,
                "run_id": run_id,
            },
        )
        log("Fetching final results failed.")
        return 1
    except RequestTransportError as exc:
        save_json(
            session_dir,
            "error_results_transport.json",
            {
                "url": exc.url,
                "message": exc.message,
                "run_id": run_id,
            },
        )
        log("Fetching final results failed due to a transport error.")
        return 1

    save_json(session_dir, "03_results.json", results_response.body)
    print_results_summary(results_response.body)

    try:
        report_response = request_json("GET", report_url)
    except HttpJsonError as exc:
        save_json(
            session_dir,
            "error_report.json",
            {
                "url": exc.url,
                "status_code": exc.status_code,
                "body": exc.body,
                "run_id": run_id,
            },
        )
        log("Fetching final report failed.")
        return 1
    except RequestTransportError as exc:
        save_json(
            session_dir,
            "error_report_transport.json",
            {
                "url": exc.url,
                "message": exc.message,
                "run_id": run_id,
            },
        )
        log("Fetching final report failed due to a transport error.")
        return 1

    save_json(session_dir, "04_report.json", report_response.body)
    print_report_summary(report_response.body)

    final_state = None if final_status is None else final_status.get("state")
    if final_state == "failed":
        log("Run finished in failed state. Inspect the saved JSON snapshots for details.")
        return 1

    log("Debug run finished successfully.")
    log(f"All raw JSON snapshots are available under {session_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("Interrupted by user.")
        raise SystemExit(130)
