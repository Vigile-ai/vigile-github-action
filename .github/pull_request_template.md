## Plan ID

<!-- Required. Example: ENG-101 -->

## Summary

<!-- What does this PR do? -->

## Scope

<!-- Required. What is intentionally in scope and out of scope? -->

## Architecture Alignment

<!-- Required for code changes. -->
- Guardrails: AGR-001
- Contract Impact: none
- Cross-Repo Impact: none
- PHI Boundary Impact: none
- Why now: aligns with `memory/ROADMAP.md` and `memory/SOURCE_OF_TRUTH.md`

## Test Evidence

<!-- Required. What did you test and what passed? -->

## Validation Commands

```bash
# Required. Paste exact commands you ran
```

## Risk & Rollback

<!-- Required. Risk level + how to rollback if needed -->

## Pre-Merge Checklist

- [ ] Plan ID is present and maps to a roadmap/decision item
- [ ] Security/quality gates pass (lint, typecheck, tests, audit, SAST)
- [ ] New code has test coverage or explicit justification
- [ ] Architecture Alignment completed for code changes (guardrails + contract + cross-repo + PHI boundary + why now)
- [ ] Any source-of-truth edits have tagged decision entry (`[CODEX]` or `[CLAUDE]`)
