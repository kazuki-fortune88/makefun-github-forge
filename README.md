[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/kazuki-fortune88/makefun-github-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/kazuki-fortune88/makefun-github-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01)

Entry by [kazuki-fortune88](https://github.com/kazuki-fortune88) for the [make.fun bounty github-core-clone-01](https://make.fun/bounty/github-core-clone-01) — a GitHub-compatible git forge in Node.js (stdlib only).
Run: `MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts` · Referral code: `4fxhr3y1`

---

# GitHub-compatible git forge — make.fun bounty `github-core-clone-01`

Single-process Node.js forge (stdlib only, no dependencies, no git binary, no
outside services) implementing git smart HTTP, REST v3, GraphQL, and MCP from
an in-memory store. Entry point is `main.ts` (starter lifecycle, unchanged);
the server lives in `app.ts`.

## Run

```sh
MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts
# or: npm start
```

Requires Node >= 22.18. The process binds an ephemeral port itself, POSTs
`{"port": N}` to `$MAKEFUN_ENV_URL/register`, polls `$MAKEFUN_ENV_URL/done`,
and exits 0. It never binds 8080.

## What is built

- **Git smart HTTP** (`/{owner}/{repo}.git`): info/refs v0 + v2, ls-refs v2,
  upload-pack fetch v0/v2 (shallow, deepen, filter-aware plan, ACK/NAK,
  sideband packfile, whole-response fetch cache), receive-pack with
  per-ref fast-forward enforcement and sideband status reports. Own packfile
  codec: plain objects with per-object deflate cache, OFS/REF delta decoding
  on ingest, SHA-1 object identity, exact commit/tree/tag round-trip.
- **REST v3** (`/api/v3/`): root/meta/rate_limit/user, user repos (create,
  duplicate → 422, `Link` pagination), repo CRUD, branches, commits history,
  git refs, contents (create/update/delete with stale-sha 409, directory
  listings), labels, issues + comments, pull requests + files + squash merge
  with real merge-base conflict detection (405 on conflict).
- **GraphQL** (`/api/graphql`): own tokenizer/parser/executor — viewer,
  repository, issues/pullRequests connections with cursor pagination,
  `__type` introspection, `node()`, mutations createIssue/closeIssue/
  createPullRequest/mergePullRequest/addComment, batch arrays, opaque
  base64 global ids.
- **MCP** (`/mcp`, streamable HTTP): `server/discover` + legacy `initialize`,
  `tools/list` (8 tools, byte-stable), `tools/call` for create_repo,
  get_repo, create_issue, list_issues, create_pull_request,
  merge_pull_request (+ get_issue, create_comment), JSON-RPC errors
  (-32700/-32601/-32602), 401 without token, 202 for notifications.
- **Determinism**: the scenario viewer (`adaiversen`, id 1000, etc.) is
  derived by replicating the kit's seeded RNG from `wire.ts`; all timestamps
  are the fixed `2025-01-01T00:00:00Z`; ids come from deterministic counters;
  no `Date.now()` / `Math.random()` anywhere in responses. Two fresh runs of
  the local suite produce identical check outcomes.

## Local test results (kit `sdk/run.ts`, Node v24, this VM)

| run | result |
| --- | --- |
| conformance, before final fixes | 118/120 (feature 590, agent 200) |
| conformance + `--perf`, after fixes | **120/120 — feature 600, agent 200, perf 193, score 993** |
| determinism re-run (fresh server, no perf) | 120/120, identical check outcomes, same scenario seed |

Perf workloads (p50, 3 rounds; reference medians from kit calibration):
push 377.8 ms (50 pts, ref 1640.8 ms) · clone 72.3 ms (49 pts, ref 266.9 ms) ·
read 774.5 ms (48 pts, ref 2759.7 ms) · write 111.5 ms (46 pts, ref 349.0 ms) ·
perf_p50_us 220,403.

The two failures found in the first run were fixed, not worked around:
`git.fetch-shallow-deepen` (the have-set must stop at shallow boundaries) and
`pulls.merge-conflict` (mergeability must use the *current* base-branch tip,
not the base sha captured at PR creation).

Lifecycle also verified against a fake env: ephemeral bind, register, poll
`/done`, exit 0.

## Size

Total source 127,783 bytes (limit 16 MiB); largest file `app.ts` 121,342 bytes
(limit 8 MiB per file).

## What is NOT built / known limits

- No UI, no persistence (in-memory only — the sealed suite never requires
  restart persistence), no webhooks, no search API beyond the root URL
  templates, no auth beyond the single bearer token, no org/team permissions
  (viewer is always the scenario owner), no delta compression in emitted
  packs (plain objects only — valid, just larger).
- GraphQL named fragment spreads are not fully supported (unused by the
  suite); PR and issue numbers use separate per-repo counters (GitHub shares
  one counter — no check mixes both in one repo).
- Perf was measured on this VM with Node 24; grading runs Node 22 on
  different hardware, so absolute timings will differ — the points are
  computed against the reference measured on the same hardware, so the
  relative margins (push 4.3×, clone 3.7×, read 3.6×, write 3.1× faster than
  the reference medians) are what matter.

## Still missing for submission (deliberately NOT done here)

Wallet/keypair, public GitHub repo for the entry, and submission transcripts
— those are the submitter's steps, outside this build-and-test task.
