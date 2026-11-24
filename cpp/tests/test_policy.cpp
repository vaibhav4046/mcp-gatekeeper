// Tests for the C++ policy port.
//  1. Ported unit tests: the policy cases from tests/test_components.py, same SQL, same expected rule ids.
//  2. Golden equivalence: every case in tests/golden/cases.jsonl must produce exactly what the Python
//     reference (sqlglot) produced (expected.jsonl), except cases recorded in known_divergences.json.
#include <gtest/gtest.h>

#include <fstream>
#include <set>
#include <sstream>

#include "json.hpp"
#include "policy.hpp"

namespace {

using gk::json::Value;

std::string slurp(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::vector<Value> lines(const std::string& path) {
    std::vector<Value> out;
    std::istringstream in(slurp(path));
    for (std::string l; std::getline(in, l);)
        if (!l.empty()) out.push_back(gk::json::parse(l));
    return out;
}

const std::map<std::string, gk::Policy>& policies() {
    static const auto p = [] {
        std::map<std::string, gk::Policy> m;
        const Value doc = gk::json::parse(slurp(std::string(GK_GOLDEN_DIR) + "/policies.json"));
        for (const auto& [name, v] : doc.as_object()) m.emplace(name, gk::Policy::from_json(v));
        return m;
    }();
    return p;
}

const std::set<std::string> kKnown = {"accounts", "orders", "audit_logs", "system_secrets"};

gk::PolicyResult run(const std::string& sql, const char* role, const char* pol = "default") {
    const auto& p = policies().at(pol);
    return gk::check(sql, p, p.roles.at(role), kKnown);
}

struct BlockCase { const char* sql; const char* rule; };

}  // namespace

// ---------------------------------------------------------------- ported: test_policy_blocks_for_scoped_write
TEST(PortedPolicy, BlocksForScopedWrite) {
    const BlockCase cases[] = {
        {"DROP TABLE accounts", "DDL_BLOCKED"},
        {"/* maintenance */ DROP TABLE accounts", "DDL_BLOCKED"},
        {"TRUNCATE orders", "DDL_BLOCKED"},
        {"ALTER TABLE accounts DROP COLUMN balance", "DDL_BLOCKED"},
        {"CREATE TABLE x (id int)", "DDL_BLOCKED"},
        {"GRANT ALL ON system_secrets TO PUBLIC", "DDL_BLOCKED"},
        {"REVOKE ALL ON accounts FROM PUBLIC", "DDL_BLOCKED"},
        {"SELECT * INTO copy_of_accounts FROM accounts", "STATEMENT_NOT_ALLOWED"},
        {"SELECT 1; DROP TABLE accounts", "MULTI_STATEMENT"},
        {"SELECT 1; /* harmless */ DROP TABLE accounts", "MULTI_STATEMENT"},
        {"DELETE FROM orders", "NO_WHERE"},
        {"UPDATE accounts SET balance = 0", "NO_WHERE"},
        {"DELETE FROM orders WHERE 1=1", "TAUTOLOGICAL_WHERE"},
        {"DELETE FROM orders WHERE TRUE", "TAUTOLOGICAL_WHERE"},
        {"DELETE FROM orders WHERE id = id", "TAUTOLOGICAL_WHERE"},
        {"UPDATE accounts SET balance = 0 WHERE (owner = 'x' OR 'a' = 'a')", "TAUTOLOGICAL_WHERE"},
        {"DELETE FROM orders WHERE status LIKE '%'", "TAUTOLOGICAL_WHERE"},
        {"SELECT * FROM system_secrets", "RESTRICTED_TABLE"},
        {"SELECT owner FROM accounts UNION SELECT value FROM system_secrets", "RESTRICTED_TABLE"},
        {"WITH s AS (SELECT value FROM system_secrets) SELECT * FROM s", "RESTRICTED_TABLE"},
        {"SELECT (SELECT value FROM SYSTEM_SECRETS LIMIT 1) FROM accounts", "RESTRICTED_TABLE"},
        {"DELETE FROM audit_logs WHERE id < 10", "RESTRICTED_TABLE"},
        {"SELECT rolname, rolpassword FROM pg_authid", "RESTRICTED_TABLE"},
        {"SELECT * FROM information_schema.tables", "RESTRICTED_TABLE"},
        {"SELECT * FROM other.accounts", "TABLE_NOT_ALLOWED"},
        {"UPDATE \"Accounts\" SET balance = 1 WHERE id = 1", "UNKNOWN_TABLE"},
        {"SELECT pg_read_file('PG_VERSION')", "FUNCTION_NOT_ALLOWED"},
        {"SELECT \"pg_read_file\"('PG_VERSION')", "FUNCTION_NOT_ALLOWED"},
        {"SELECT query_to_xml_and_xmlschema('select 1', true, true, '')", "FUNCTION_NOT_ALLOWED"},
        {"SELECT * FROM ts_stat('select 1')", "FUNCTION_NOT_ALLOWED"},
        {"SELECT nextval('orders_id_seq')", "FUNCTION_NOT_ALLOWED"},
        {"SELECT pg_sleep(10)", "FUNCTION_NOT_ALLOWED"},
        {"SELECT set_config('statement_timeout', '0', false)", "FUNCTION_NOT_ALLOWED"},
        {"COPY accounts TO STDOUT", "STATEMENT_NOT_ALLOWED"},
        {"SET statement_timeout = 0", "STATEMENT_NOT_ALLOWED"},
        {"VACUUM", "STATEMENT_NOT_ALLOWED"},
        {"WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING *) SELECT * FROM d", "NESTED_WRITE"},
        {"UPDATE accounts SET version = 1 WHERE id = 1", "VERSION_TAMPER"},
        {"INSERT INTO accounts (id, owner, balance) VALUES (1, 'a', 1) ON CONFLICT (id) DO UPDATE SET balance = 0",
         "UPSERT_UPDATE"},
        {"DELETE FROM accounts WHERE id = 3", "WRITE_NOT_ALLOWED"},
        {"SELEC * FROM accounts", "PARSE_ERROR"},
        {"", "EMPTY"},
    };
    for (const auto& c : cases) {
        auto r = run(c.sql, "scoped_write");
        EXPECT_FALSE(r.allowed) << c.sql;
        EXPECT_EQ(r.rule_id.value_or("<allowed>"), c.rule) << c.sql;
    }
}

// ---------------------------------------------------------------- ported: test_policy_allows_for_scoped_write
TEST(PortedPolicy, AllowsForScopedWrite) {
    const char* cases[] = {
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
    };
    for (const char* sql : cases) {
        auto r = run(sql, "scoped_write");
        EXPECT_TRUE(r.allowed) << sql << " -> " << r.rule_id.value_or("") << ": " << r.reason;
    }
}

TEST(PortedPolicy, ReadOnlyRoleBlocksEveryWrite) {
    for (const char* sql : {"UPDATE accounts SET balance = 1 WHERE id = 1", "INSERT INTO orders (account_id, amount) VALUES (1, 2)",
                            "DELETE FROM orders WHERE id = 1"}) {
        auto r = run(sql, "read_only");
        EXPECT_FALSE(r.allowed) << sql;
        EXPECT_EQ(r.rule_id.value_or(""), "ROLE_READ_ONLY") << sql;
    }
    EXPECT_TRUE(run("SELECT owner FROM accounts WHERE id = 1", "read_only").allowed);
}

TEST(PortedPolicy, ColumnAllowlist) {
    auto n = [](const char* sql) { return run(sql, "r", "narrow"); };
    EXPECT_TRUE(n("SELECT id, owner FROM accounts WHERE id = 1").allowed);
    EXPECT_EQ(n("SELECT balance FROM accounts").rule_id.value_or(""), "COLUMN_NOT_ALLOWED");
    EXPECT_EQ(n("SELECT * FROM accounts").rule_id.value_or(""), "COLUMN_NOT_ALLOWED");
    EXPECT_TRUE(n("UPDATE accounts SET owner = 'x' WHERE id = 1").allowed);
    const auto rule = n("UPDATE accounts SET balance = 0 WHERE id = 1").rule_id.value_or("");
    EXPECT_TRUE(rule == "COLUMN_NOT_ALLOWED" || rule == "WRITE_NOT_ALLOWED") << rule;
}

TEST(PortedPolicy, AdminStillBlocksDestructiveDdlAndRestrictedTables) {
    EXPECT_TRUE(run("CREATE INDEX idx ON orders (status)", "admin").allowed);
    const BlockCase cases[] = {
        {"DROP TABLE orders", "DDL_BLOCKED"},
        {"TRUNCATE orders", "DDL_BLOCKED"},
        {"GRANT SELECT ON accounts TO PUBLIC", "DDL_BLOCKED"},
        {"SELECT * FROM system_secrets", "RESTRICTED_TABLE"},
        {"DELETE FROM audit_logs WHERE id = 1", "RESTRICTED_TABLE"},
        {"SELECT 1; SELECT 2", "MULTI_STATEMENT"},
    };
    for (const auto& c : cases) EXPECT_EQ(run(c.sql, "admin").rule_id.value_or(""), c.rule) << c.sql;
    EXPECT_TRUE(run("SELECT pg_sleep(0.01)", "admin").allowed);  // opted in via allow_functions
}

TEST(PortedPolicy, BlockedUnparseableStatementCountsAsPossibleWrite) {
    EXPECT_TRUE(run("UPDATE accounts SET balance = 1 WHER id = 2", "scoped_write").is_write);
    EXPECT_FALSE(run("SELECT * FROM system_secrets", "scoped_write").is_write);
}

// ---------------------------------------------------------------- C++-specific robustness
TEST(Robustness, HostileInputsNeverThrowOrHang) {
    const std::string deep(2000, '(');
    for (const std::string& sql : {deep, deep + "1" + std::string(2000, ')'), std::string("SELECT '") + std::string(10000, 'a'),
                                   std::string("/*") + std::string(5000, '*'), std::string("SELECT \"") + "x", std::string("SELECT $$abc"),
                                   std::string("\xff\xfe SELECT 1"), std::string("\0SELECT", 7)}) {
        auto r = run(sql, "scoped_write");
        EXPECT_FALSE(r.allowed);
    }
}

// ---------------------------------------------------------------- golden equivalence against Python
TEST(Golden, MatchesPythonReference) {
    const std::string dir = GK_GOLDEN_DIR;
    const auto cases = lines(dir + "/cases.jsonl");
    const auto expected = lines(dir + "/expected.jsonl");
    const auto known = gk::json::parse(slurp(dir + "/known_divergences.json"));
    ASSERT_EQ(cases.size(), expected.size());
    size_t exact = 0, listed = 0;
    for (size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        const auto& e = expected[i];
        const auto& p = policies().at(c.find("policy")->as_string());
        std::optional<std::set<std::string>> k;
        if (const auto* kv = c.find("known"); kv && kv->is_array()) {
            std::set<std::string> s;
            for (const auto& t : kv->as_array()) s.insert(t.as_string());
            k = s;
        }
        auto r = gk::check(c.find("sql")->as_string(), p, p.roles.at(c.find("role")->as_string()), k);
        std::vector<std::string> et;
        for (const auto& t : e.find("tables")->as_array()) et.push_back(t.as_string());
        const auto* rid = e.find("rule_id");
        const bool same = r.allowed == e.find("allowed")->as_bool() &&
                          r.rule_id == (rid->is_null() ? std::optional<std::string>{} : std::optional<std::string>{rid->as_string()}) &&
                          r.is_write == e.find("is_write")->as_bool() && r.is_ddl == e.find("is_ddl")->as_bool() && r.tables == et;
        if (same) { ++exact; continue; }
        const std::string id = std::to_string(static_cast<long long>(c.find("id")->as_number()));
        if (known.find(id)) { ++listed; continue; }
        ADD_FAILURE() << "unlisted divergence from Python reference, case " << id << ": " << c.find("sql")->as_string();
    }
    RecordProperty("exact", static_cast<int>(exact));
    RecordProperty("documented_divergences", static_cast<int>(listed));
    std::printf("golden: %zu cases, %zu exact, %zu documented divergences\n", cases.size(), exact, listed);
}

TEST(Golden, PortedCasesHaveNoDivergence) {
    const std::string dir = GK_GOLDEN_DIR;
    const auto cases = lines(dir + "/cases.jsonl");
    const auto known = gk::json::parse(slurp(dir + "/known_divergences.json"));
    for (const auto& c : cases) {
        if (c.find("src")->as_string() != "ported") continue;
        const std::string id = std::to_string(static_cast<long long>(c.find("id")->as_number()));
        EXPECT_EQ(known.find(id), nullptr) << "ported case diverges: " << c.find("sql")->as_string();
    }
}
