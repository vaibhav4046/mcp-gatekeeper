# Architecture

mcp-gatekeeper is one Python process: an MCP server (`server.py`, CLI in `cli.py`) in front of a
`Gatekeeper` (`proxy.py`) that owns a psycopg 3 async connection pool. Each agent session holds one
pooled connection for its lifetime, so its statements share one PostgreSQL transaction at a time.
All decisions are deterministic code over the sqlglot AST, the policy file, and rows read from the
database. Nothing calls a model.

| Module | Responsibility |
|---|---|
| `config.py` | `policies.yaml` models (roles, tables, columns, invariants, change limits, limits), runtime settings |
| `policy.py` | Fail-closed static checks on the AST for the session's role |
| `verifier.py` | `FOR UPDATE` probe: before-images, row cap, optimistic version check, version-bump rewrite |
| `breaker.py` | Per-session counters: repeated failures, policy violations, write cap |
| `rollback.py` | Session transaction, savepoints, undo log, compensation |
| `audit.py` | Hash-chained JSONL, HMAC, redaction, `verify_trace` |
| `proxy.py` | Orchestrates the above per call; never lets an exception leave a session in an aborted transaction |

## Session state machine

```
                       begin_session (role from the operator's policy)
                              │
                              v
     rollback_session   ┌──────────┐   execute_sql: OK, POLICY_BLOCKED, DB_ERROR,
   ┌──────────────────> │  ACTIVE  │   missing expected_version (savepoint undone)
   │                    └──────────┘ <───────────────────────────────┐
   │                      │   │   │                                  │
   │  stale version /     │   │   │ commit_session                   │
   │  invariant failure / │   │   ├─ no failed step ──> COMMITTED ───┘ (undo entries kept)
   │  post-step DB error  │   │   ├─ a step failed ───> COMMIT_REFUSED, full rollback
   │  (full rollback)     v   │   └─ COMMIT itself fails ─> COMMIT_REFUSED, full rollback
   │              ┌──────────┐│
   └───────────── │ ABORTED  ││   execute_sql -> TRANSACTION_ABORTED
                  └──────────┘│   commit_session -> COMMIT_REFUSED
                        │     │
          breaker trip  │     │   breaker trip: >3 identical failures in 30 s,
                        v     v   3 policy violations, or write #21
                     ┌──────────┐
                     │  HALTED  │  rollback open txn, then compensate committed writes
                     └──────────┘  (all or nothing); every later call -> SESSION_HALTED
                           │ close / idle reaper (300 s)
                           v
                        CLOSED: uncommitted work rolled back, connection reset and returned
```

Per statement inside ACTIVE: policy -> write cap -> `SAVEPOINT` -> (UPDATE/DELETE) probe with
`FOR UPDATE`, before-images, row cap and version check -> execute the rewritten statement ->
row-count recheck, change limits, invariants -> `RELEASE SAVEPOINT` -> undo entries -> trace.

## Guarantees (with the default policy and a least-privilege database role)

1. A statement that does not parse to exactly one allowlisted statement for the role never reaches
   PostgreSQL.
2. A `read_only` session cannot write, even if the AST check were wrong: its transactions are
   started `READ ONLY` by the driver.
3. No UPDATE/DELETE on a versioned table runs without the version the agent read; a stale version
   is refused before mutation, and a successful write bumps the version.
4. No single UPDATE/DELETE touches more rows than the role's cap (checked before and after).
5. A transaction in which any mutating step failed cannot commit.
6. After a write, declared invariants and change limits hold before the savepoint is released; if
   not, the step (change limit) or the whole transaction (invariant) is rolled back.
7. A tripped breaker leaves the database as if the session's writes had never happened, provided
   none of the affected rows were changed by anyone else since; otherwise it changes nothing and
   says so in the trace.
8. Every call is in an append-only trace whose tampering (edit, deletion, reordering) is detected
   by `verify-trace`; with an audit key, a rewrite also needs the key.

## Threat model (STRIDE)

**Adversary:** the agent. It may be prompt-injected, buggy, looping, or racing other agents. It can
send any SQL through `execute_sql` and pick any `expected_version`. It reaches the database only
through the gatekeeper and does not control the gatekeeper's process, configuration, policy file,
database credentials or audit key.

| STRIDE | Threat | Controls |
|---|---|---|
| **Spoofing** | Agent claims a more powerful identity | `begin_session` takes no identity; the operator fixes it with `--agent`. Session ids are random UUID4 tokens. |
| **Tampering** | Destructive DDL, mass writes, lost updates, partial units of work, broken business rules, edited traces | DDL/GRANT/REVOKE blocked; WHERE required, tautologies blocked, row caps; optimistic versions; commit refused after a failed step; invariants and change limits; compensation on trip; hash-chained + HMAC traces |
| **Repudiation** | "The agent never ran that" | Every call, verdict, latency and pre/post state hash in the trace; `verify-trace` |
| **Information disclosure** | Reading `system_secrets`, `audit_logs`, catalogs, server files; secrets echoed in errors | Restricted tables/schemas on every table node; function allowlist (blocks `pg_read_file`, `query_to_xml`, `dblink`, ...); column allowlists; least-privilege DB role; redaction in errors, traces, logs |
| **Denial of service** | Long queries, lock hogging, retry storms, write floods, abandoned sessions | `statement_timeout` 5 s, `lock_timeout` 2 s; breaker; idle reaper returns connections; pool timeout returns `POOL_EXHAUSTED` |
| **Elevation of privilege** | `read_only` agent writing; `SET`, `COPY`, `DO`, `SET TRANSACTION READ WRITE`, nested writes in CTEs, upserts, version tampering | Role checks on the AST plus `READ ONLY` transactions; statement allowlist; nested statements blocked; `ON CONFLICT DO UPDATE` blocked; version column managed by the proxy |

Out of scope: a compromised gatekeeper host, a database role that bypasses the proxy, attacks on the
MCP transport itself (authenticate it separately, e.g. behind a reverse proxy for HTTP), and denial
of service against the proxy process.

## Measured results

From `benchmarks/results.json` (2026-11-22T01:27:31Z, WSL2 + PostgreSQL 16.16 in Docker, busy laptop):
44/50 scenarios corrupted unprotected, 0/50 protected; expected protective verdict in 49/50 (the
miss was a race that did not overlap that run). Proxy overhead over 1,500 benign calls: p50
3.242 ms, p95 6.288 ms, p99 9.234 ms; 0 benign calls refused. The README has the full table and the
definition of corruption.

## Known limitations

1. **Semantic errors pass within the declared rules.** A correctly versioned single-row update that
   credits the wrong account, or moves 9,000 when the change limit is 10,000, is allowed. Change
   limits and invariants only encode what you declare; scenario I10 is caught only because the
   default policy declares a balance change limit.
2. **Compensation is not time travel.** It reverses this session's committed row changes using
   before-images, guarded by version. Anything that read the intermediate committed state in the
   meantime (other agents, reports, triggers, replicas) already saw it. If any affected row changed
   since, nothing is compensated and the trace says so. Tables without a single-column primary key
   cannot be compensated.
3. **Breaker state is per session.** An agent that opens a new session starts with fresh counters.
   Per-client limits belong in front of the gatekeeper.
4. **Conflicts count toward the breaker.** Under heavy contention, agents that keep losing races are
   halted after their fourth identical conflict (16 `SESSION_HALTED` verdicts across the 10 race
   scenarios in the run above). The data stays correct, but throughput suffers; a backoff-aware retry budget would
   be kinder.
5. **Non-transactional side effects are not covered.** Emails, HTTP calls, other databases,
   `NOTIFY` listeners and sequence values are outside the transaction and are not rolled back.
6. **sqlglot dialect gaps.** The policy is only as good as sqlglot's postgres parser. Anything it
   cannot parse, or parses as an opaque `Command`, is blocked, which can refuse valid but unusual
   SQL. A construct it misreads as harmless would slip through; the statement, table and function
   allowlists shrink but do not remove that risk.
7. **Column resolution is approximate.** An unqualified column in a join is allowed if any joined
   table allowlists that name. Qualify columns, or keep allowlists tight, if column-level secrecy
   matters.
8. **Tautology detection is syntactic.** `WHERE id > 0` is not a tautology to the parser; the row
   cap and the version check catch it on versioned tables, but on an unversioned table with fewer
   rows than the cap it runs.
9. **Locks are held across tool calls.** The `FOR UPDATE` probe holds row locks until commit or
   rollback. `lock_timeout` (2 s) bounds waits and PostgreSQL breaks deadlocks (`DB_ERROR` 40P01 in
   the transfer races), but a slow agent still slows others.
10. **Redaction is pattern-based.** It catches common credential, token and e-mail shapes plus
    secret values the gatekeeper can read at startup. With a least-privilege role it cannot read
    `system_secrets`, so unusual secret formats in error text can slip through. Redaction also
    rewrites literals in traced SQL, so traces are for audit, not exact replay of redacted values.
11. **Trace truncation at the end is not detectable from the file alone.** The chain proves nothing
    was edited, removed or reordered up to the last line; to detect a dropped tail, ship
    `entry_hash` values to a separate store.
12. **Overhead is mostly extra round trips.** A write costs up to 7 extra queries (savepoint, probe,
    change-limit check, invariant, release, two state hashes). State hashing reads whole tables:
    fine for the demo, too slow for large tables; turn it off with `hash_state=False`.
13. **The baseline is a plain autocommit executor** with the same database role and no
    transactions. A hand-written agent that used transactions and row locks correctly would do better
    than this baseline; the comparison shows what the proxy adds to agents that do not.
