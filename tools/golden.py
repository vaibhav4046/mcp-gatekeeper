"""Differential harness: Python reference (policy.check) vs the C++ port.

  make   build the corpus, run the Python reference on it, write cpp/tests/golden/{policies,cases,expected}
  diff   run the C++ CLI over a cases file and compare every field with the Python reference, live
  bench  time the Python reference on a cases file (per-call median / p99), same method as the C++ --bench

The corpus = SQL strings ported from the project's own tests and benchmark scenarios, plus a seeded
grammar-based generator and token-level mutations (to exercise parse errors).
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from ref import config
from ref import policy as P

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "cpp" / "tests" / "golden"
KNOWN = ["accounts", "orders", "audit_logs", "system_secrets"]

NARROW = config.Policy.model_validate(
    {
        "agents": {"default": "r"},
        "roles": {"r": {"kind": "scoped_write", "tables": {"accounts": {"read": ["id", "owner"], "update": ["owner"]}}}},
    }
)
POLICIES = {"default": config.DEFAULT_POLICY, "narrow": NARROW}


def ref_result(sql: str, pol: str, role: str, known: list[str] | None) -> dict:
    policy = POLICIES[pol]
    r = P.check(sql, policy, policy.roles[role], known)
    return {
        "allowed": r.allowed,
        "rule_id": r.rule_id,
        "reason": r.reason,
        "is_write": r.is_write,
        "is_ddl": r.is_ddl,
        "tables": sorted(r.tables),
    }


# --------------------------------------------------------------------------- corpus: ported SQL
def project_sql() -> list[str]:
    """Every SQL-looking string literal in the project's tests/benchmarks (f-string holes -> 1)."""
    starts = (
        "select",
        "update",
        "insert",
        "delete",
        "with",
        "drop",
        "truncate",
        "alter",
        "create",
        "grant",
        "revoke",
        "copy",
        "set",
        "vacuum",
        "begin",
        "commit",
        "explain",
        "values",
    )
    found: set[str] = set()
    for f in [*ROOT.glob("tests/*.py"), *ROOT.glob("benchmarks/*.py"), *ROOT.glob("examples/*.py")]:
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            text = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = "".join(v.value if isinstance(v, ast.Constant) else "1" for v in node.values)
            if text and text.strip().lower().startswith(starts) and len(text) < 600 and "\n\n" not in text:
                found.add(text.strip())
    return sorted(found)


# --------------------------------------------------------------------------- corpus: generator
TABLES = [
    "accounts",
    "orders",
    "accounts",
    "orders",
    "system_secrets",
    "audit_logs",
    "pg_authid",
    "other.accounts",
    '"Accounts"',
    "information_schema.tables",
    "public.accounts",
    "foo",
    "ACCOUNTS",
    "SYSTEM_SECRETS",
    "pg_catalog.pg_class",
]
COLS = ["id", "balance", "owner", "version", "status", "amount", "account_id", "value", "created_at", "Balance"]
FUNCS = [
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "coalesce",
    "nullif",
    "greatest",
    "least",
    "upper",
    "lower",
    "length",
    "substring",
    "trim",
    "round",
    "abs",
    "ceil",
    "floor",
    "now",
    "concat",
    "string_agg",
    "array_agg",
    "to_char",
    "date_trunc",
    "pg_sleep",
    "pg_read_file",
    "nextval",
    "set_config",
    "current_setting",
    "version",
    "random",
    "md5",
    "left",
    "right",
    "replace",
    "split_part",
    "json_agg",
    "age",
    "date_part",
    "mod",
    "power",
    "sqrt",
    "char_length",
    "ceiling",
    "ifnull",
    "lpad",
    "dblink",
    "lo_import",
    "pg_ls_dir",
    "generate_series",
    "unnest",
    "row_number",
    "rank",
    "string_to_array",
    "regexp_replace",
    "to_timestamp",
    "strpos",
    "initcap",
    "ltrim",
]
TAUTS = [
    "1=1",
    "TRUE",
    "'a'='a'",
    "id = id",
    "id >= id",
    "NOT FALSE",
    "2>1",
    "1<>2",
    "NULL IS NULL",
    "1 IN (1,2)",
    "5 BETWEEN 1 AND 10",
    "'x' LIKE '%'",
    "(1=1)",
    "1=1.0",
    "'a'='A'",
    "NOT (1=2)",
    "1=1 AND 2=2",
    "TRUE AND TRUE",
    "id = 3 OR 1=1",
    "id = 3 OR 'a'='a'",
    "balance IS NOT NULL OR TRUE",
    "1<2",
    "0=0",
    "ID = id",
    "owner = owner",
    "2 > 3",
    "FALSE",
    "1=2",
    "NULL",
    "NOT TRUE",
    "1 = 1 OR random() > 2",
    "random() = random()",
    "1 IS NOT NULL",
    "'a' <> 'b'",
    "3 BETWEEN 1 AND 2",
    "1+1=2",
    "id = 3",
    "id > 0 AND status = 'x'",
    "status ILIKE '%'",
    "status LIKE 'a%'",
    "NOT NOT TRUE",
    "(id = 3) OR (1 = 1)",
    "id IN (1,2)",
    "TRUE OR id = 1",
    "id = 1 AND TRUE",
]


class Gen:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)

    def pick(self, xs):
        return self.r.choice(xs)

    def lit(self) -> str:
        return self.pick(["1", "42", "0", "'x'", "'pending'", "1.5", "NULL", "TRUE", "'%'", "-1", "'a'"])

    def expr(self, d: int = 0) -> str:
        c = self.r.random()
        if d > 2 or c < 0.3:
            return self.pick(COLS) if self.r.random() < 0.6 else self.lit()
        if c < 0.5:
            f = self.pick(FUNCS)
            n = 0 if f in ("now", "random", "version") else self.r.randint(1, 3)
            if f == "count" and self.r.random() < 0.5:
                return "count(*)"
            return f"{f}({', '.join(self.expr(d + 1) for _ in range(n))})"
        if c < 0.65:
            return f"{self.expr(d + 1)} {self.pick(['+', '-', '*', '/', '||', '=', '<>', '<', '>=', 'AND', 'OR', 'LIKE', 'ILIKE'])} {self.expr(d + 1)}"
        if c < 0.72:
            return f"CASE WHEN {self.expr(d + 1)} THEN {self.expr(d + 1)} ELSE {self.expr(d + 1)} END"
        if c < 0.78:
            return f"CAST({self.expr(d + 1)} AS {self.pick(['int', 'text', 'numeric(10,2)', 'timestamp'])})"
        if c < 0.82:
            return f"{self.expr(d + 1)}::{self.pick(['int', 'text', 'date'])}"
        if c < 0.86:
            return f"({self.expr(d + 1)})"
        if c < 0.9:
            return f"{self.expr(d + 1)} IN ({self.lit()}, {self.lit()})"
        if c < 0.93:
            return f"({self.select(d + 1, tiny=True)})"
        if c < 0.96:
            return f"{self.expr(d + 1)} IS {self.pick(['NULL', 'NOT NULL'])}"
        return f"{self.pick(['a', 'o', 'accounts', 'orders'])}.{self.pick(COLS)}"

    def where(self) -> str:
        if self.r.random() < 0.5:
            return self.pick(TAUTS)
        return f"{self.expr(1)} {self.pick(['=', '>', '<>'])} {self.expr(1)}" if self.r.random() < 0.6 else self.pick(TAUTS)

    def table(self) -> str:
        return self.pick(TABLES)

    def select(self, d: int = 0, tiny: bool = False) -> str:
        items = (
            "*"
            if self.r.random() < 0.2
            else ", ".join(
                self.expr(1) + (f" AS {self.pick(['n', 'x', 'total'])}" if self.r.random() < 0.2 else "")
                for _ in range(self.r.randint(1, 3))
            )
        )
        s = f"SELECT {items} FROM {self.table()}"
        if self.r.random() < 0.3:
            s += f" a JOIN {self.table()} o ON a.id = o.account_id"
        if self.r.random() < 0.5 or tiny:
            s += f" WHERE {self.where()}"
        if not tiny and self.r.random() < 0.15:
            s += f" GROUP BY {self.pick(COLS)}"
        if not tiny and d < 2 and self.r.random() < 0.12:
            s += f" {self.pick(['UNION', 'UNION ALL', 'EXCEPT'])} {self.select(d + 1, tiny=True)}"
        if not tiny:  # ORDER BY / LIMIT / FOR UPDATE apply to the whole (set) query
            if self.r.random() < 0.2:
                s += f" ORDER BY {self.pick(COLS)} {self.pick(['', 'DESC', 'ASC'])}"
            if self.r.random() < 0.2:
                s += f" LIMIT {self.r.randint(1, 50)}"
            if self.r.random() < 0.08:
                s += " FOR UPDATE"
        if not tiny and self.r.random() < 0.12:
            s = f"WITH c AS ({self.select(d + 1, tiny=True)}) SELECT {self.pick(['*', 'count(*)', 'id'])} FROM c"
        return s

    def update(self) -> str:
        sets = ", ".join(f"{self.pick(COLS)} = {self.expr(2)}" for _ in range(self.r.randint(1, 2)))
        s = f"UPDATE {self.table()} SET {sets}"
        if self.r.random() < 0.85:
            s += f" WHERE {self.where()}"
        return s

    def delete(self) -> str:
        s = f"DELETE FROM {self.table()}"
        if self.r.random() < 0.85:
            s += f" WHERE {self.where()}"
        return s

    def insert(self) -> str:
        cols = ", ".join(self.r.sample(COLS, 2))
        s = f"INSERT INTO {self.table()} ({cols}) "
        s += f"VALUES ({self.expr(2)}, {self.lit()})" if self.r.random() < 0.7 else self.select(2, tiny=True)
        c = self.r.random()
        if c < 0.12:
            s += " ON CONFLICT DO NOTHING"
        elif c < 0.2:
            s += f" ON CONFLICT (id) DO UPDATE SET {self.pick(COLS)} = {self.lit()}"
        return s

    def other(self) -> str:
        t = self.table()
        return self.pick(
            [
                f"DROP TABLE {t}",
                f"TRUNCATE {t}",
                f"ALTER TABLE {t} ADD COLUMN z int",
                f"ALTER TABLE {t} DROP COLUMN balance",
                f"CREATE TABLE {t} (id int)",
                f"CREATE INDEX i ON {t} ({self.pick(COLS)})",
                f"CREATE INDEX i ON {t} (lower({self.pick(COLS)}))",
                f"GRANT SELECT ON {t} TO PUBLIC",
                f"REVOKE ALL ON {t} FROM PUBLIC",
                f"COMMENT ON TABLE {t} IS 'x'",
                "SET statement_timeout = 0",
                f"COPY {t} TO STDOUT",
                "VACUUM",
                "BEGIN",
                "COMMIT",
                "ROLLBACK",
                f"EXPLAIN SELECT * FROM {t}",
                f"SELECT * INTO new_t FROM {t}",
                f"CREATE VIEW v AS SELECT * FROM {t}",
                "DROP INDEX i",
                "SELECT 1; SELECT 2",
                "SELECT 1;",
                ";",
                "   ",
                f"WITH d AS (DELETE FROM {t} WHERE id = 1 RETURNING *) SELECT * FROM d",
                f"WITH u AS (UPDATE {t} SET owner = 'x' WHERE id = 1 RETURNING id) SELECT * FROM u",
                f"SELECT * FROM {t} WHERE id = 1; DROP TABLE {t}",
                f"/* c */ SELECT * FROM {t}",
                f"-- c\nSELECT * FROM {t}",
            ]
        )

    def statement(self) -> str:
        c = self.r.random()
        if c < 0.38:
            return self.select()
        if c < 0.55:
            return self.update()
        if c < 0.68:
            return self.delete()
        if c < 0.8:
            return self.insert()
        return self.other()

    def mutate(self, sql: str) -> str:
        toks = sql.split(" ")
        if len(toks) < 3:
            return sql + " )"
        i = self.r.randrange(len(toks))
        m = self.r.random()
        if m < 0.4:
            del toks[i]
        elif m < 0.6:
            toks.insert(i, toks[i])
        elif m < 0.8:
            toks[i] = self.pick(["(", ")", ",", "FROM", "WHERE", "SELECT", "AND", "'", "--", "/*", ";", "*"])
        else:
            toks[i], toks[self.r.randrange(len(toks))] = toks[self.r.randrange(len(toks))], toks[i]
        return " ".join(toks)


def build_cases(n_fuzz: int, seed: int) -> list[dict]:
    g = Gen(seed)
    sqls: list[tuple[str, str]] = [("ported", s) for s in project_sql()]
    sqls += [("ported", s) for s in TEST_COMPONENT_SQL]
    for _ in range(n_fuzz):
        s = g.statement()
        sqls.append(("gen", s))
        if g.r.random() < 0.25:
            sqls.append(("mutant", g.mutate(s)))
    cases = []
    for src, sql in sqls:
        roles = ["scoped_write"]
        if src == "ported" or g.r.random() < 0.3:
            roles += ["read_only", "admin"]
        for role in roles:
            cases.append({"src": src, "policy": "default", "role": role, "sql": sql, "known": KNOWN})
        if g.r.random() < 0.15 or src == "ported":
            cases.append({"src": src, "policy": "narrow", "role": "r", "sql": sql, "known": KNOWN})
        if g.r.random() < 0.05:
            cases.append({"src": src, "policy": "default", "role": "scoped_write", "sql": sql, "known": None})
    for i, c in enumerate(cases):
        c["id"] = i
    return cases


# SQL strings from tests/test_components.py's policy tests (also hand-ported with expectations in C++).
TEST_COMPONENT_SQL = [
    "DROP TABLE accounts",
    "/* maintenance */ DROP TABLE accounts",
    "TRUNCATE orders",
    "ALTER TABLE accounts DROP COLUMN balance",
    "CREATE TABLE x (id int)",
    "GRANT ALL ON system_secrets TO PUBLIC",
    "REVOKE ALL ON accounts FROM PUBLIC",
    "SELECT * INTO copy_of_accounts FROM accounts",
    "SELECT 1; DROP TABLE accounts",
    "SELECT 1; /* harmless */ DROP TABLE accounts",
    "DELETE FROM orders",
    "UPDATE accounts SET balance = 0",
    "DELETE FROM orders WHERE 1=1",
    "DELETE FROM orders WHERE TRUE",
    "DELETE FROM orders WHERE id = id",
    "UPDATE accounts SET balance = 0 WHERE (owner = 'x' OR 'a' = 'a')",
    "DELETE FROM orders WHERE status LIKE '%'",
    "SELECT * FROM system_secrets",
    "SELECT owner FROM accounts UNION SELECT value FROM system_secrets",
    "WITH s AS (SELECT value FROM system_secrets) SELECT * FROM s",
    "SELECT (SELECT value FROM SYSTEM_SECRETS LIMIT 1) FROM accounts",
    "DELETE FROM audit_logs WHERE id < 10",
    "SELECT rolname, rolpassword FROM pg_authid",
    "SELECT * FROM information_schema.tables",
    "SELECT * FROM other.accounts",
    'UPDATE "Accounts" SET balance = 1 WHERE id = 1',
    "SELECT pg_read_file('PG_VERSION')",
    "SELECT \"pg_read_file\"('PG_VERSION')",
    "SELECT query_to_xml_and_xmlschema('select 1', true, true, '')",
    "SELECT * FROM ts_stat('select 1')",
    "SELECT nextval('orders_id_seq')",
    "SELECT pg_sleep(10)",
    "SELECT set_config('statement_timeout', '0', false)",
    "COPY accounts TO STDOUT",
    "SET statement_timeout = 0",
    "VACUUM",
    "WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING *) SELECT * FROM d",
    "UPDATE accounts SET version = 1 WHERE id = 1",
    "INSERT INTO accounts (id, owner, balance) VALUES (1, 'a', 1) ON CONFLICT (id) DO UPDATE SET balance = 0",
    "DELETE FROM accounts WHERE id = 3",
    "SELEC * FROM accounts",
    "",
    "SELECT id, balance, version FROM accounts WHERE id = 3",
    "SELECT count(*) FROM orders WHERE status = 'pending'",
    "SELECT count(*) AS n FROM orders GROUP BY status ORDER BY n",
    "UPDATE accounts SET balance = balance - 10 WHERE id = 3",
    "DELETE FROM orders WHERE id = 17",
    "INSERT INTO orders (account_id, amount) VALUES (1, 20)",
    "INSERT INTO orders (account_id, amount) VALUES (1, 20) ON CONFLICT DO NOTHING",
    "SELECT a.owner, o.amount FROM accounts a JOIN orders o ON o.account_id = a.id WHERE a.id = 2",
    "SELECT * FROM accounts WHERE id = 1 FOR UPDATE",
    "SELECT upper(owner), coalesce(balance, 0), now() FROM accounts WHERE id = 1",
    "WITH big AS (SELECT id FROM orders WHERE amount > 20) SELECT count(*) FROM big",
    "UPDATE accounts SET balance = 1 WHERE id = 1",
    "INSERT INTO orders (account_id, amount) VALUES (1, 2)",
    "DELETE FROM orders WHERE id = 1",
    "SELECT owner FROM accounts WHERE id = 1",
    "SELECT id, owner FROM accounts WHERE id = 1",
    "SELECT balance FROM accounts",
    "SELECT * FROM accounts",
    "UPDATE accounts SET owner = 'x' WHERE id = 1",
    "UPDATE accounts SET balance = 0 WHERE id = 1",
    "CREATE INDEX idx ON orders (status)",
    "DROP TABLE orders",
    "GRANT SELECT ON accounts TO PUBLIC",
    "DELETE FROM audit_logs WHERE id = 1",
    "SELECT 1; SELECT 2",
    "SELECT pg_sleep(0.01)",
    "UPDATE accounts SET balance = 1 WHER id = 2",
]


# --------------------------------------------------------------------------- commands
def cmd_make(a: argparse.Namespace) -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "policies.json").write_text(
        json.dumps({k: v.model_dump(mode="json") for k, v in POLICIES.items()}, indent=1, sort_keys=True), encoding="utf-8"
    )
    cases = build_cases(a.n, a.seed)
    with (
        (GOLDEN / "cases.jsonl").open("w", encoding="utf-8", newline="\n") as fc,
        (GOLDEN / "expected.jsonl").open("w", encoding="utf-8", newline="\n") as fe,
    ):
        for c in cases:
            fc.write(json.dumps(c) + "\n")
            fe.write(json.dumps({"id": c["id"], **ref_result(c["sql"], c["policy"], c["role"], c["known"])}) + "\n")
    print(f"wrote {len(cases)} cases to {GOLDEN}")


def load_cases(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def cmd_diff(a: argparse.Namespace) -> None:
    cases = load_cases(Path(a.cases))
    payload = "".join(json.dumps(c) + "\n" for c in cases)
    cli = [a.cli, "--policy", str(GOLDEN / "policies.json")]
    out = subprocess.run(cli, input=payload, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    got = {r["id"]: r for r in map(json.loads, out.splitlines())}
    tally: Counter[str] = Counter()
    examples: dict[str, list] = {}
    for c in cases:
        exp_r = ref_result(c["sql"], c["policy"], c["role"], c["known"])
        g = got[c["id"]]
        keys = ("allowed", "rule_id", "is_write", "is_ddl", "tables")
        if all(g[k] == exp_r[k] for k in keys):
            tally["exact"] += 1
            if g["reason"] == exp_r["reason"]:
                tally["exact+reason"] += 1
            continue
        if g["allowed"] and not exp_r["allowed"]:
            cat = "FAIL-OPEN (cpp allows, python blocks)"
        elif exp_r["allowed"] and not g["allowed"]:
            cat = "stricter (cpp blocks, python allows)"
        elif g["rule_id"] != exp_r["rule_id"]:
            cat = "both block, different rule"
        else:
            cat = "same verdict+rule, other field differs"
        tally[cat] += 1
        tally[f"  {cat} [{c['src']}]"] += 1
        examples.setdefault(cat, []).append((c, exp_r, g))
    print(f"cases={len(cases)} " + json.dumps(dict(tally), indent=1))
    if a.write_known:
        known = {str(c["id"]): cat for cat, ex in examples.items() for c, _, _ in ex}
        Path(a.write_known).write_text(json.dumps(known, indent=0, sort_keys=True), encoding="utf-8")
        print(f"wrote {len(known)} documented divergences to {a.write_known}")
    for cat, ex in examples.items():
        print(f"\n== {cat}: {len(ex)}")
        for c, e, g in [x for x in ex if a.src in ("", x[0]["src"])][: a.show]:
            print(
                f"  [{c['policy']}/{c['role']}] {c['sql']!r}\n    py : {e['allowed']} {e['rule_id']} w={e['is_write']} t={e['tables']} | {e['reason'][:80]}"
                f"\n    cpp: {g['allowed']} {g['rule_id']} w={g['is_write']} t={g['tables']} | {g['reason'][:80]}"
            )
    if a.strict and any(k for k in tally if not k.startswith(("exact", "  "))):
        sys.exit(1)


def cmd_bench(a: argparse.Namespace) -> None:
    cases = load_cases(Path(a.cases))
    for c in cases:
        c["_p"] = POLICIES[c["policy"]]
        c["_r"] = c["_p"].roles[c["role"]]
    for c in cases:
        P.check(c["sql"], c["_p"], c["_r"], c["known"])  # warm-up
    ns: list[int] = []
    for _ in range(a.iters):
        for c in cases:
            t0 = time.perf_counter_ns()
            P.check(c["sql"], c["_p"], c["_r"], c["known"])
            ns.append(time.perf_counter_ns() - t0)
    ns.sort()
    print(
        json.dumps(
            {
                "cases": len(cases),
                "iters": a.iters,
                "n": len(ns),
                "median_ns": ns[len(ns) // 2],
                "p99_ns": ns[min(len(ns) - 1, int(0.99 * len(ns)))],
                "mean_ns": int(statistics.fmean(ns)),
                "python": sys.version.split()[0],
            }
        )
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--n", type=int, default=2500)
    m.add_argument("--seed", type=int, default=20261124)
    m.set_defaults(fn=cmd_make)
    d = sub.add_parser("diff")
    d.add_argument("--cli", required=True)
    d.add_argument("--cases", default=str(GOLDEN / "cases.jsonl"))
    d.add_argument("--show", type=int, default=6)
    d.add_argument("--write-known", default="", help="record current divergences as documented (known_divergences.json)")
    d.add_argument("--src", default="", help="only show examples from this corpus part (ported|gen|mutant)")
    d.add_argument("--strict", action="store_true")
    d.set_defaults(fn=cmd_diff)
    b = sub.add_parser("bench")
    b.add_argument("--cases", default=str(GOLDEN / "cases.jsonl"))
    b.add_argument("--iters", type=int, default=20)
    b.set_defaults(fn=cmd_bench)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
