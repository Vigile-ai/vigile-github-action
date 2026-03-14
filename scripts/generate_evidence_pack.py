#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse

PLAN_ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]{1,9}-\d{1,5}\b")
DEFAULT_TIMEOUT_SECONDS = 20


WORKFLOW_MATCHERS = {
    "plan_guard": lambda run: ("/plan-guard.yml" in _run_path(run)) or (_run_name(run) in {"plan guard", "pr hygiene"}),
    "ci": lambda run: "/ci.yml" in _run_path(run),
    "semgrep": lambda run: ("/semgrep.yml" in _run_path(run)) or ("semgrep" in _run_name(run)),
    "release": lambda run: "/release-provenance.yml" in _run_path(run),
}

WORKFLOW_FILES = {
    "plan_guard": "plan-guard.yml",
    "ci": "ci.yml",
    "semgrep": "semgrep.yml",
    "release": "release-provenance.yml",
}


API_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "vigile-evidence-pack",
}

try:
    import certifi  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    certifi = None


def _run_name(run: dict[str, Any]) -> str:
    return str(run.get("name") or "").strip().lower()


def _run_path(run: dict[str, Any]) -> str:
    return str(run.get("path") or "").strip().lower()


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def _guess_repo() -> str:
    repo = _env("GITHUB_REPOSITORY")
    if repo:
        return repo

    remote = _git(["config", "--get", "remote.origin.url"])
    remote = remote.removesuffix(".git")
    if remote.startswith("git@github.com:"):
        return remote.split("git@github.com:", 1)[1]
    if "github.com/" in remote:
        return remote.split("github.com/", 1)[1]
    raise RuntimeError("Could not infer GitHub repository (owner/repo).")


def _guess_sha() -> str:
    sha = _env("GITHUB_SHA")
    if sha:
        return sha
    return _git(["rev-parse", "HEAD"])


def _read_event_payload() -> dict[str, Any]:
    event_path = _env("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    path = Path(event_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def _api_get(url: str, token: str) -> dict[str, Any]:
    parts = parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc != "api.github.com":
        raise RuntimeError(f"Blocked non-GitHub API URL: {url}")

    request_path = parts.path
    if parts.query:
        request_path += f"?{parts.query}"

    headers = dict(API_HEADERS_BASE)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if certifi is not None:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
    else:
        ssl_context = ssl.create_default_context()

    # nosemgrep - GitHub API host is hard-pinned above to https://api.github.com.
    conn = http.client.HTTPSConnection(
        "api.github.com",
        timeout=DEFAULT_TIMEOUT_SECONDS,
        context=ssl_context,
    )
    try:
        conn.request("GET", request_path, headers=headers)
        resp = conn.getresponse()
        payload = resp.read().decode("utf-8")
    finally:
        conn.close()

    if resp.status >= 400:
        raise error.HTTPError(url, resp.status, resp.reason, hdrs=None, fp=None)

    return json.loads(payload)


def _fetch_runs(
    repo: str,
    token: str,
    *,
    head_sha: str = "",
    workflow_file: str = "",
    branch: str = "",
    event: str = "",
    per_page: int = 100,
) -> list[dict[str, Any]]:
    if workflow_file:
        endpoint = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/runs"
    else:
        endpoint = f"https://api.github.com/repos/{repo}/actions/runs"

    params: dict[str, Any] = {"per_page": per_page}
    if head_sha:
        params["head_sha"] = head_sha
    if branch:
        params["branch"] = branch
    if event:
        params["event"] = event

    query = parse.urlencode(params)
    data = _api_get(f"{endpoint}?{query}", token)
    return list(data.get("workflow_runs") or [])


def _associated_pr_for_sha(repo: str, sha: str, token: str) -> dict[str, Any] | None:
    if not token:
        return None
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/pulls?per_page=10"
    try:
        prs = _api_get(url, token)
    except error.HTTPError:
        return None
    if not isinstance(prs, list) or not prs:
        return None

    merged_prs = [pr for pr in prs if pr.get("merged_at")]
    selected = merged_prs[0] if merged_prs else prs[0]
    return selected


def _pick_run(runs: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    matcher = WORKFLOW_MATCHERS[key]
    for run in runs:
        if matcher(run):
            return run
    return None


def _resolve_run(
    repo: str,
    token: str,
    key: str,
    candidate_shas: list[str],
    branch_fallback: str,
) -> dict[str, Any] | None:
    seen: set[str] = set()
    for sha in candidate_shas:
        if not sha or sha in seen:
            continue
        seen.add(sha)
        try:
            runs = _fetch_runs(repo, token, head_sha=sha, per_page=100)
        except Exception:
            continue
        match = _pick_run(runs, key)
        if match:
            return match

    workflow_file = WORKFLOW_FILES[key]
    try:
        fallback_runs = _fetch_runs(
            repo,
            token,
            workflow_file=workflow_file,
            branch=branch_fallback,
            per_page=20,
        )
    except Exception:
        return None

    for run in fallback_runs:
        if str(run.get("status") or "").lower() == "completed":
            return run
    return fallback_runs[0] if fallback_runs else None


def _normalize_status(run: dict[str, Any] | None) -> str:
    if not run:
        return "missing"
    status = str(run.get("status") or "unknown").lower()
    conclusion = str(run.get("conclusion") or "").lower()
    if status != "completed":
        return f"{status}"
    if conclusion:
        return conclusion
    return "completed"


def _run_url(run: dict[str, Any] | None) -> str:
    if not run:
        return ""
    return str(run.get("html_url") or "").strip()


def _extract_plan_id(event: dict[str, Any]) -> str:
    pr = event.get("pull_request") or {}
    body = str(pr.get("body") or "")
    title = str(pr.get("title") or "")

    for text in (title, body):
        match = PLAN_ID_PATTERN.search(text)
        if match:
            return match.group(0)
    return ""


def _write_markdown(
    output_path: Path,
    *,
    repo: str,
    sha: str,
    event_name: str,
    ref_name: str,
    branch_name: str,
    actor: str,
    run_url: str,
    plan_id: str,
    pr_url: str,
    pr_number: str,
    chain: dict[str, dict[str, str]],
    generated_at: str,
) -> None:
    lines: list[str] = []
    lines.append("# EVIDENCE_PACK")
    lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append(f"Repository: {repo}")
    lines.append(f"Commit: `{sha}`")
    lines.append(f"Trigger: `{event_name}`")
    if ref_name:
        lines.append(f"Ref: `{ref_name}`")
    if branch_name:
        lines.append(f"Branch: `{branch_name}`")
    lines.append(f"Actor: `{actor or 'unknown'}`")
    if plan_id:
        lines.append(f"Plan ID: `{plan_id}`")
    else:
        lines.append("Plan ID: `unknown`")
    if pr_number:
        lines.append(f"PR: #{pr_number}")
    if pr_url:
        lines.append(f"PR URL: {pr_url}")
    if run_url:
        lines.append(f"Evidence Producer Run: {run_url}")

    lines.append("")
    lines.append("## Evidence Chain")
    lines.append("")
    lines.append("| Check | Status | Run URL | Notes |")
    lines.append("|---|---|---|---|")

    def row(label: str, key: str, notes: str) -> None:
        entry = chain[key]
        url = entry["url"] if entry["url"] else "(missing)"
        lines.append(f"| {label} | `{entry['status']}` | {url} | {notes} |")

    row("PR Hygiene", "plan_guard", "PR template and public-hygiene gate")
    row("CI", "ci", "Build, tests, and CI checks")
    row("Semgrep SAST", "semgrep", "Static analysis")
    row("Audit", "audit", "Audit step is executed within linked run")
    row("Release Provenance", "release", "Present for tag-based releases")

    lines.append("")
    lines.append("## Verdict")
    lines.append("")

    required = ["plan_guard", "ci", "semgrep", "audit"]
    incomplete = [k for k in required if chain[k]["status"] == "missing"]
    if incomplete:
        lines.append(
            "Status: `incomplete` - missing required evidence links for: "
            + ", ".join(incomplete)
            + "."
        )
    else:
        lines.append("Status: `linked` - required evidence links captured.")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This pack is generated automatically by `scripts/generate_evidence_pack.py`.")
    lines.append("- Store this artifact with release/merge records for auditability.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate EVIDENCE_PACK.md from GitHub run metadata")
    parser.add_argument("--output", default="EVIDENCE_PACK.md", help="Output markdown path")
    parser.add_argument("--repo", default="", help="Override owner/repo")
    parser.add_argument("--sha", default="", help="Override commit sha")
    parser.add_argument("--strict", action="store_true", help="Fail if required evidence links are missing")
    args = parser.parse_args()

    output_path = Path(args.output)

    try:
        repo = args.repo or _guess_repo()
        sha = args.sha or _guess_sha()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    token = _env("GITHUB_TOKEN")
    event = _read_event_payload()
    event_name = _env("GITHUB_EVENT_NAME", "manual")
    ref_name = _env("GITHUB_REF_NAME")
    branch_name = _env("GITHUB_HEAD_REF") or ref_name
    actor = _env("GITHUB_ACTOR")
    run_url = ""
    server_url = _env("GITHUB_SERVER_URL", "https://github.com")
    run_id = _env("GITHUB_RUN_ID")
    if run_id:
        run_url = f"{server_url}/{repo}/actions/runs/{run_id}"

    pr = event.get("pull_request") or {}
    pr_url = str(pr.get("html_url") or "").strip()
    pr_number = str(pr.get("number") or "").strip()

    associated_pr = _associated_pr_for_sha(repo, sha, token) if token else None
    if associated_pr and not pr_url:
        pr_url = str(associated_pr.get("html_url") or "").strip()
    if associated_pr and not pr_number:
        pr_number = str(associated_pr.get("number") or "").strip()

    pr_head_sha = ""
    if pr.get("head"):
        pr_head_sha = str((pr.get("head") or {}).get("sha") or "").strip()
    elif associated_pr:
        pr_head_sha = str(((associated_pr.get("head") or {}).get("sha") or "")).strip()

    candidate_shas = [sha, pr_head_sha]
    branch_fallback = branch_name or "main"

    chain_runs: dict[str, dict[str, Any] | None] = {}
    for key in ("plan_guard", "ci", "semgrep", "release"):
        chain_runs[key] = _resolve_run(repo, token, key, candidate_shas, branch_fallback) if token else None

    audit_run = chain_runs.get("ci")
    if not audit_run and (event_name == "push" and ref_name.startswith("v")):
        audit_run = chain_runs.get("release")

    chain: dict[str, dict[str, str]] = {
        "plan_guard": {
            "status": _normalize_status(chain_runs.get("plan_guard")),
            "url": _run_url(chain_runs.get("plan_guard")),
        },
        "ci": {
            "status": _normalize_status(chain_runs.get("ci")),
            "url": _run_url(chain_runs.get("ci")),
        },
        "semgrep": {
            "status": _normalize_status(chain_runs.get("semgrep")),
            "url": _run_url(chain_runs.get("semgrep")),
        },
        "audit": {
            "status": _normalize_status(audit_run),
            "url": _run_url(audit_run),
        },
        "release": {
            "status": _normalize_status(chain_runs.get("release")),
            "url": _run_url(chain_runs.get("release")),
        },
    }

    plan_id = _extract_plan_id(event)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    _write_markdown(
        output_path,
        repo=repo,
        sha=sha,
        event_name=event_name,
        ref_name=ref_name,
        branch_name=branch_name,
        actor=actor,
        run_url=run_url,
        plan_id=plan_id,
        pr_url=pr_url,
        pr_number=pr_number,
        chain=chain,
        generated_at=generated_at,
    )

    missing_required = [
        key
        for key in ("plan_guard", "ci", "semgrep", "audit")
        if chain[key]["status"] == "missing"
    ]

    print(f"Generated {output_path} for {repo}@{sha[:12]}")
    if missing_required:
        print("Missing required evidence:", ", ".join(missing_required))
        return 1 if args.strict else 0

    print("Evidence chain links captured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
