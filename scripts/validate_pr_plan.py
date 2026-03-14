#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ALLOWED_TYPES = {"bug", "feature", "refactor", "detection", "security", "dependency", "docs"}
TRACKER_ID_RE = re.compile(r"\b[A-Z]{2,10}-\d{1,5}\b")
DOC_REFERENCE_RE = re.compile(r"(?:^|[\s(])(?:/?[\w./-]+\.(?:md|mdx))(?:$|[\s)])", re.IGNORECASE)
PRIVATE_PROCESS_RE = re.compile(
    r"\b(?:internal|private|proprietary)\b.{0,40}\b(?:process|workflow|playbook|runbook|checklist|policy|ops?)\b",
    re.IGNORECASE,
)
PLACEHOLDERS = {"tbd", "n/a", "na", "-", "todo", "same as above"}


def _read_event(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _get_pr_text_from_event(event: dict) -> tuple[str, str]:
    pr = event.get("pull_request") or {}
    title = str(pr.get("title") or "")
    body = str(pr.get("body") or "")
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


def _has_content(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and "<!--" not in stripped


def _is_meaningful(text: str) -> bool:
    stripped = text.strip().lower()
    if not stripped or "<!--" in stripped:
        return False
    return stripped not in PLACEHOLDERS


def _normalize_type(value: str) -> str:
    token = re.split(r"[\s|,/;]+", value.strip().lower(), maxsplit=1)[0]
    return token.strip("-* ")


def _resolve_local_text(args: argparse.Namespace) -> tuple[str, str]:
    title = args.title.strip()
    body = args.body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8")
    return title, body


def _load_pr_text(args: argparse.Namespace) -> tuple[str, str]:
    if args.title.strip() or args.body or args.body_file:
        return _resolve_local_text(args)

    event_path = Path(args.event_path or os.environ.get("GITHUB_EVENT_PATH", ""))
    if not event_path.exists():
        raise FileNotFoundError("missing GitHub event payload path")
    event = _read_event(event_path)
    return _get_pr_text_from_event(event)


def _has_public_copy_smell(text: str) -> bool:
    return bool(
        TRACKER_ID_RE.search(text)
        or DOC_REFERENCE_RE.search(text)
        or PRIVATE_PROCESS_RE.search(text)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PR title/body hygiene and template contract")
    parser.add_argument("--event-path", default="", help="Path to GitHub event payload")
    parser.add_argument("--title", default="", help="PR title for local validation")
    parser.add_argument("--body", default="", help="PR body text for local validation")
    parser.add_argument("--body-file", default="", help="Path to PR body file for local validation")
    parser.add_argument("--base", default="", help="Compatibility arg for repo workflows")
    parser.add_argument("--head", default="", help="Compatibility arg for repo workflows")
    args = parser.parse_args()

    try:
        title, body = _load_pr_text(args)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []

    if not title.strip():
        errors.append("PR title is required.")

    summary_section = _extract_section(body, "Summary")
    type_section = _extract_section(body, "Type")
    security_section = _extract_section(body, "Security Impact")
    breaking_section = _extract_section(body, "Breaking Changes")

    if not _is_meaningful(summary_section):
        errors.append("Summary section is required and must describe what changed and why.")

    if not _has_content(type_section):
        errors.append("Type section is required.")
    else:
        normalized_type = _normalize_type(type_section)
        if normalized_type not in ALLOWED_TYPES:
            errors.append("Type must be one of: bug, feature, refactor, detection, security, dependency, docs.")

    if not _has_content(security_section):
        errors.append('Security Impact section is required (use "None." if no impact).')

    if not _has_content(breaking_section):
        errors.append('Breaking Changes section is required (use "None." if no changes).')

    if _has_public_copy_smell(title):
        errors.append("PR title contains public-unsafe tracker IDs, doc references, or private-process language.")

    if _has_public_copy_smell(body):
        errors.append("PR body contains public-unsafe tracker IDs, doc references, or private-process language.")

    if errors:
        print("PR HYGIENE FAILED")
        for idx, error in enumerate(errors, start=1):
            print(f"{idx}. {error}")
        return 1

    print("PR HYGIENE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
