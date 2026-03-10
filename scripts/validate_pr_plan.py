#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PLAN_ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]{1,9}-\d{1,5}\b")
CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".swift", ".sql", ".sh"
}


def _read_event(path: Path) -> dict:
    return json.loads(path.read_text())


def _get_pr_text(event: dict) -> tuple[str, str]:
    pr = event.get("pull_request") or {}
    title = pr.get("title") or ""
    body = pr.get("body") or ""
    return title, body


def _extract_section(body: str, heading: str) -> str:
    pattern = re.compile(
        rf"^##\s+{re.escape(heading)}\s*$([\s\S]*?)(?=^##\s+|\Z)",
        re.MULTILINE,
    )
    match = pattern.search(body)
    if not match:
        return ""
    return match.group(1).strip()


def _is_meaningful(text: str) -> bool:
    stripped = text.strip().lower()
    if not stripped:
        return False
    placeholders = {
        "tbd",
        "n/a",
        "na",
        "none",
        "-",
        "todo",
        "same as above",
    }
    return stripped not in placeholders and "<!--" not in stripped


def _changed_files(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}..{head}"],
        check=True,
        text=True,
        capture_output=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _is_code_file(path: str) -> bool:
    p = Path(path)
    if p.suffix.lower() not in CODE_EXTENSIONS:
        return False
    if any(part in {"tests", "test", "__tests__", "spec"} for part in p.parts):
        return False
    return True


def _is_test_file(path: str) -> bool:
    p = Path(path)
    lower = path.lower()
    return (
        any(part in {"tests", "test", "__tests__", "spec"} for part in p.parts)
        or lower.endswith("_test.py")
        or lower.endswith(".spec.ts")
        or lower.endswith(".spec.tsx")
        or lower.endswith(".test.ts")
        or lower.endswith(".test.tsx")
        or lower.endswith(".test.js")
        or lower.endswith(".spec.js")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PR plan/test contract")
    parser.add_argument("--event-path", default="", help="Path to GitHub event payload")
    parser.add_argument("--base", required=True, help="Base commit sha")
    parser.add_argument("--head", required=True, help="Head commit sha")
    args = parser.parse_args()

    event_path = Path(args.event_path or os.environ.get("GITHUB_EVENT_PATH", ""))
    if not event_path.exists():
        print("ERROR: missing GitHub event payload path", file=sys.stderr)
        return 1

    event = _read_event(event_path)
    title, body = _get_pr_text(event)

    errors: list[str] = []

    plan_section = _extract_section(body, "Plan ID")
    scope_section = _extract_section(body, "Scope")
    tests_section = _extract_section(body, "Test Evidence")
    commands_section = _extract_section(body, "Validation Commands")
    risk_section = _extract_section(body, "Risk & Rollback")

    if not (
        PLAN_ID_PATTERN.search(title)
        or PLAN_ID_PATTERN.search(plan_section)
        or PLAN_ID_PATTERN.search(body)
    ):
        errors.append("Missing Plan ID (expected format like ENG-101) in title or PR body.")

    if not _is_meaningful(scope_section):
        errors.append("Scope section is required and must describe in-scope and out-of-scope work.")
    if not _is_meaningful(tests_section):
        errors.append("Test Evidence section is required and cannot be placeholder text.")
    if not _is_meaningful(commands_section):
        errors.append("Validation Commands section is required with real commands/results.")
    if not _is_meaningful(risk_section):
        errors.append("Risk & Rollback section is required.")

    try:
        files = _changed_files(args.base, args.head)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr, file=sys.stderr)
        return 1

    code_changed = any(_is_code_file(path) for path in files)
    tests_changed = any(_is_test_file(path) for path in files)

    if code_changed and not tests_changed:
        combined = f"{tests_section}\n{commands_section}".lower()
        if all(token not in combined for token in ("manual", "no test", "existing test")):
            errors.append(
                "Code changed but no test files changed. Add tests or explain why in Test Evidence."
            )

    if errors:
        print("PLAN GUARD FAILED")
        for idx, error in enumerate(errors, start=1):
            print(f"{idx}. {error}")
        return 1

    print("PLAN GUARD PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
