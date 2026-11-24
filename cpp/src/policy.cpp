#include "policy.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <deque>
#include <functional>

#include "sql.hpp"

namespace gk {
namespace {

using sql::K;
using sql::Node;

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ------------------------------------------------------------------------------------ traversal
struct Ref {
    const Node* node;
    const Node* parent;
};

// Breadth-first, like sqlglot's walk()/find_all().
std::vector<Ref> bfs(const Node& root) {
    std::vector<Ref> out;
    out.push_back({&root, nullptr});
    for (size_t i = 0; i < out.size(); ++i) {
        const Node* n = out[i].node;
        for (const auto& k : n->kids) out.push_back({&k, n});
    }
    return out;
}

std::string table_name(const Node& t) { return t.quoted ? t.text : lower(t.text); }

std::set<std::string> cte_names(const std::vector<Ref>& nodes) {
    std::set<std::string> out;
    for (const auto& r : nodes)
        if (r.node->kind == K::Cte) out.insert(lower(r.node->text));
    return out;
}

// alias-or-name (lower) -> table name, for tables that are not CTE references.
std::map<std::string, std::string> real_tables(const std::vector<Ref>& nodes, const std::set<std::string>& ctes) {
    std::map<std::string, std::string> out;
    for (const auto& r : nodes) {
        const Node& t = *r.node;
        if (t.kind != K::Table || t.text.empty()) continue;
        if (t.schema.empty() && ctes.count(lower(t.text))) continue;
        out[lower(t.alias.empty() ? t.text : t.alias)] = table_name(t);
    }
    return out;
}

std::vector<std::string> values_of(const std::map<std::string, std::string>& m) {
    std::set<std::string> s;
    for (const auto& [k, v] : m) s.insert(v);
    return {s.begin(), s.end()};
}

// ------------------------------------------------------------------------------------ tautology
struct Val {
    enum class T { Bool, Num, Str, Null, Opaque } t = T::Opaque;
    bool b = false;
    double num = 0;
    std::string str;
};

Val mk_bool(bool b) { Val v; v.t = Val::T::Bool; v.b = b; return v; }
Val mk_null() { Val v; v.t = Val::T::Null; return v; }
Val mk_num(double d) { Val v; v.t = Val::T::Num; v.num = d; return v; }

Val eval(const Node& n) {
    switch (n.kind) {
        case K::Literal: {
            if (n.quoted) { Val v; v.t = Val::T::Str; v.str = n.text; return v; }
            try { return mk_num(std::stod(n.text)); } catch (...) { return {}; }
        }
        case K::Boolean: return mk_bool(n.text == "true");
        case K::Null: return mk_null();
        case K::Paren: return eval(n.kids[0]);
        case K::Neg: { Val v = eval(n.kids[0]); return v.t == Val::T::Num ? mk_num(-v.num) : Val{}; }
        case K::Not: {
            Val v = eval(n.kids[0]);
            if (v.t == Val::T::Bool) return mk_bool(!v.b);
            if (v.t == Val::T::Null) return mk_null();
            return {};
        }
        case K::And:
        case K::Or: {
            const bool is_and = n.kind == K::And;
            Val a = eval(n.kids[0]), b = eval(n.kids[1]);
            auto is = [](const Val& v, bool x) { return v.t == Val::T::Bool && v.b == x; };
            if (is(a, !is_and) || is(b, !is_and)) return mk_bool(!is_and);  // FALSE AND x, TRUE OR x
            if (is(a, is_and) && is(b, is_and)) return mk_bool(is_and);
            if (a.t == Val::T::Opaque || b.t == Val::T::Opaque) return {};
            if (is(a, is_and) || is(b, is_and)) return mk_null();
            return mk_null();
        }
        case K::Is: {
            Val a = eval(n.kids[0]);
            const Node& r = n.kids[1];
            if (a.t == Val::T::Opaque) return {};
            if (r.kind == K::Null) return mk_bool(a.t == Val::T::Null);
            return {};  // IS TRUE / IS FALSE are not folded by sqlglot.simplify
        }
        case K::Binary: {
            const std::string& o = n.text;
            const bool cmp = o == "=" || o == "<>" || o == "<" || o == ">" || o == "<=" || o == ">=";
            const bool arith = o == "+" || o == "-" || o == "*";
            if (o == "||") {
                Val a = eval(n.kids[0]), b = eval(n.kids[1]);
                if (a.t != Val::T::Str || b.t != Val::T::Str) return {};
                Val v; v.t = Val::T::Str; v.str = a.str + b.str;
                return v;
            }
            if (!cmp && !arith) return {};
            Val a = eval(n.kids[0]), b = eval(n.kids[1]);
            if (a.t == Val::T::Opaque || b.t == Val::T::Opaque) return {};
            if (a.t == Val::T::Null || b.t == Val::T::Null) return mk_null();
            if (arith) {
                if (a.t != Val::T::Num || b.t != Val::T::Num) return {};
                return mk_num(o == "+" ? a.num + b.num : o == "-" ? a.num - b.num : a.num * b.num);
            }
            int c = 0;
            if (a.t == Val::T::Num && b.t == Val::T::Num) c = a.num < b.num ? -1 : a.num > b.num ? 1 : 0;
            else if (a.t == Val::T::Str && b.t == Val::T::Str) c = a.str < b.str ? -1 : a.str > b.str ? 1 : 0;
            else if (a.t == Val::T::Bool && b.t == Val::T::Bool && (o == "=" || o == "<>")) c = a.b == b.b ? 0 : 1;
            else return {};
            bool r = o == "=" ? c == 0 : o == "<>" ? c != 0 : o == "<" ? c < 0 : o == ">" ? c > 0 : o == "<=" ? c <= 0 : c >= 0;
            return mk_bool(r);
        }
        case K::Between: {
            Val x = eval(n.kids[0]), lo = eval(n.kids[1]), hi = eval(n.kids[2]);
            if (x.t == Val::T::Num && lo.t == Val::T::Num && hi.t == Val::T::Num) return mk_bool(x.num >= lo.num && x.num <= hi.num);
            return {};
        }
        default: return {};
    }
}

bool contains(const Node& n, const std::function<bool(const Node&)>& pred) {
    if (pred(n)) return true;
    return std::any_of(n.kids.begin(), n.kids.end(), [&](const Node& k) { return contains(k, pred); });
}

bool is_tautology(const Node& c) {
    if (c.kind == K::Paren) return is_tautology(c.kids[0]);
    if (c.kind == K::Or) return is_tautology(c.kids[0]) || is_tautology(c.kids[1]);
    if (c.kind == K::And) return is_tautology(c.kids[0]) && is_tautology(c.kids[1]);
    if (c.kind == K::Binary && (c.text == "=" || c.text == ">=" || c.text == "<=" || c.text == "IS NOT DISTINCT FROM") &&
        sql::signature(c.kids[0]) == sql::signature(c.kids[1]))
        return true;  // id = id, x >= x
    if (c.kind == K::Like && c.text == "LIKE" && c.kids[1].kind == K::Literal && c.kids[1].quoted && c.kids[1].text == "%")
        return true;  // col LIKE '%'
    auto is_col = [](const Node& n) { return n.kind == K::Column; };
    auto is_query = [](const Node& n) { return n.kind == K::Select || n.kind == K::SetOp || n.kind == K::Subquery; };
    if (!contains(c, is_col) && !contains(c, is_query)) {
        Val v = eval(c);
        return v.t == Val::T::Bool && v.b;
    }
    return false;
}

// ------------------------------------------------------------------------------------ results
PolicyResult block(std::string rule, std::string reason, bool is_write = true, std::vector<std::string> tables = {}) {
    PolicyResult r;
    r.allowed = false;
    r.rule_id = std::move(rule);
    r.reason = std::move(reason);
    r.is_write = is_write;
    r.tables = std::move(tables);
    return r;
}

std::string py_list(const std::vector<std::string>& v) {
    std::string s = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s += ", ";
        s += "'" + v[i] + "'";
    }
    return s + "]";
}

const char* type_name_upper(K k) {
    switch (k) {
        case K::Drop: return "DROP";
        case K::Truncate: return "TRUNCATETABLE";
        case K::Grant: return "GRANT";
        case K::Revoke: return "REVOKE";
        case K::Create: return "CREATE";
        case K::Alter: return "ALTER";
        case K::CommentStmt: return "COMMENT";
        default: return "?";
    }
}

// ------------------------------------------------------------------------------------ checks
std::optional<PolicyResult> check_tables(const std::vector<Ref>& nodes, const std::set<std::string>& ctes,
                                         const Policy& policy, const Role& role,
                                         const std::optional<std::set<std::string>>& known) {
    for (const auto& r : nodes) {
        const Node& t = *r.node;
        if (t.kind != K::Table || t.text.empty()) continue;
        const std::string name = table_name(t), schema = lower(t.schema);
        if (schema.empty() && ctes.count(lower(name))) continue;
        const std::string lname = lower(name);
        const std::string shown = (schema.empty() ? "" : schema + ".") + name;
        if (policy.restricted_tables.count(lname) || policy.restricted_schemas.count(schema) || lname.rfind("pg_", 0) == 0)
            return block("RESTRICTED_TABLE", "access to " + shown + " is not allowed");
        if (!schema.empty() && schema != "public")
            return block("TABLE_NOT_ALLOWED", "schema-qualified table " + schema + "." + name + " is outside the allowed schema");
        if (known && !known->count(name))
            return block("UNKNOWN_TABLE", "table " + name + " is not in the gatekeeper's schema snapshot");
        if (role.tables && !role.tables->count(name))
            return block("TABLE_NOT_ALLOWED", "role " + role.kind + " may not use table " + name);
    }
    return std::nullopt;
}

std::optional<PolicyResult> check_columns(const std::vector<Ref>& nodes, const std::set<std::string>& ctes, const Role& role,
                                          const std::map<std::string, std::string>& tables) {
    if (!role.tables) return std::nullopt;
    const auto name_list = values_of(tables);
    std::set<std::string> aliases = ctes;
    for (const auto& r : nodes)
        if (r.node->kind == K::Alias && !r.node->alias.empty()) aliases.insert(lower(r.node->alias));
    for (const auto& r : nodes) {
        if (r.node->kind != K::Star) continue;
        std::string qualifier;
        if (r.parent && r.parent->kind == K::Column) qualifier = lower(r.parent->schema);
        std::vector<std::string> targets;
        if (auto it = tables.find(qualifier); !qualifier.empty() && it != tables.end()) targets = {it->second};
        else if (qualifier.empty()) targets = name_list;
        for (const auto& tname : targets) {
            auto acc = role.tables->find(tname);
            if (acc != role.tables->end() && !acc->second.read_all)
                return block("COLUMN_NOT_ALLOWED", "SELECT * on " + tname + " would expose columns outside the allowlist", false);
        }
    }
    for (const auto& r : nodes) {
        const Node& col = *r.node;
        if (col.kind != K::Column) continue;
        if (!col.kids.empty() && col.kids[0].kind == K::Star) continue;
        const std::string cname = lower(col.text), qualifier = lower(col.schema);
        if (!qualifier.empty()) {
            auto it = tables.find(qualifier);
            if (it == tables.end()) continue;
            auto acc = role.tables->find(it->second);
            if (acc != role.tables->end() && !acc->second.can_read(cname))
                return block("COLUMN_NOT_ALLOWED", "column " + it->second + "." + cname + " is not allowlisted", false);
        } else {
            if (aliases.count(cname)) continue;
            bool any = false;
            for (const auto& t : name_list) {
                auto acc = role.tables->find(t);
                if (acc != role.tables->end() && acc->second.can_read(cname)) { any = true; break; }
            }
            if (!name_list.empty() && !any)
                return block("COLUMN_NOT_ALLOWED", "column " + cname + " is not allowlisted on " + py_list(name_list), false);
        }
    }
    return std::nullopt;
}

std::optional<PolicyResult> check_write(const Node& node, const Node& stmt, const Policy& policy, const Role& role,
                                        const std::vector<std::string>& tables) {
    if (&node != &stmt)
        return block("NESTED_WRITE", "data-modifying statements inside CTEs/subqueries are not allowed", true, tables);
    if (role.kind == "read_only") return block("ROLE_READ_ONLY", "this agent's role is read_only", true, tables);
    const std::string tname = node.target >= 0 ? table_name(node.kids[static_cast<size_t>(node.target)]) : "";
    const TableAccess* access = nullptr;
    if (role.tables) {
        auto it = role.tables->find(tname);
        if (it != role.tables->end()) access = &it->second;
    }
    if (node.kind == K::Insert) {
        if (node.flag) return block("UPSERT_UPDATE", "INSERT ... ON CONFLICT DO UPDATE bypasses version checks", true, tables);
        if (role.tables && (!access || !access->insert))
            return block("WRITE_NOT_ALLOWED", "role " + role.kind + " may not INSERT into " + tname, true, tables);
        return std::nullopt;
    }
    const std::string verb = node.kind == K::Update ? "UPDATE" : "DELETE";
    if (node.kind == K::Delete && role.tables && (!access || !access->del))
        return block("WRITE_NOT_ALLOWED", "role " + role.kind + " may not DELETE from " + tname, true, tables);
    if (node.where < 0) return block("NO_WHERE", verb + " without WHERE touches every row", true, tables);
    const Node& where = node.kids[static_cast<size_t>(node.where)];
    if (is_tautology(where))
        return block("TAUTOLOGICAL_WHERE", verb + " WHERE clause is always true: " + where.source, true, tables);
    if (node.kind == K::Update) {
        for (int idx : node.assigns) {
            const Node& col = node.kids[static_cast<size_t>(idx)].kids[0];
            const std::string cname = lower(col.text);
            if (cname == policy.version_column)
                return block("VERSION_TAMPER", "the " + policy.version_column + " column is managed by the gatekeeper", true, tables);
            if (role.tables && (!access || !access->can_update(cname)))
                return block("WRITE_NOT_ALLOWED",
                             "role " + role.kind + " may not UPDATE " + tname + "." + (cname.empty() ? "?" : cname), true, tables);
        }
    }
    return std::nullopt;
}

}  // namespace

const std::set<std::string>& default_allowed_functions() {
    static const std::set<std::string> kAllowed = {
        "count", "sum", "avg", "min", "max", "coalesce", "nullif", "greatest", "least", "upper", "lower", "length",
        "substring", "trim", "round", "abs", "ceil", "floor", "current_timestamp", "current_date", "timestamp_trunc",
        "date_trunc", "extract", "concat", "group_concat", "array_agg", "cast", "try_cast", "case", "if", "exists",
        "time_to_str", "row_number", "rank", "dense_rank"};
    return kAllowed;
}

PolicyResult check(const std::string& sql_text, const Policy& policy, const Role& role,
                   const std::optional<std::set<std::string>>& known) {
    std::vector<Node> statements;
    try {
        statements = sql::parse(sql_text);
    } catch (const sql::ParseError& e) {
        return block("PARSE_ERROR", std::string("SQL could not be parsed; refusing to guess: ") + e.what());
    }
    if (statements.empty()) return block("EMPTY", "no SQL statement found", false);
    if (statements.size() > 1)
        return block("MULTI_STATEMENT", std::to_string(statements.size()) + " statements in one call; send exactly one");

    const Node& stmt = statements[0];
    const auto nodes = bfs(stmt);
    const auto ctes = cte_names(nodes);
    const auto tmap = real_tables(nodes, ctes);
    const auto tables = values_of(tmap);

    std::vector<const Node*> writes;
    for (const auto& r : nodes)
        if (r.node->kind == K::Insert || r.node->kind == K::Update || r.node->kind == K::Delete) writes.push_back(r.node);
    const bool is_query = stmt.kind == K::Select || stmt.kind == K::SetOp || stmt.kind == K::Subquery;
    const bool is_read = is_query && writes.empty();

    for (const auto& r : nodes) {
        K k = r.node->kind;
        if (k == K::Drop || k == K::Truncate || k == K::Grant || k == K::Revoke)
            return block("DDL_BLOCKED", std::string(type_name_upper(k)) + " is never allowed", true, tables);
    }
    const bool is_ddl = stmt.kind == K::Create || stmt.kind == K::Alter || stmt.kind == K::CommentStmt;
    if (is_ddl && role.kind != "admin")
        return block("DDL_BLOCKED", std::string(type_name_upper(stmt.kind)) + " needs the admin role", true, tables);
    if (!is_ddl && !is_query && stmt.kind != K::Insert && stmt.kind != K::Update && stmt.kind != K::Delete) {
        const std::string cls = stmt.kind == K::Foreign ? stmt.text : "Statement";
        return block("STATEMENT_NOT_ALLOWED", cls + " statements are not allowed", true, tables);
    }
    for (const auto& r : nodes)
        if (r.node->kind == K::Into)
            return block("STATEMENT_NOT_ALLOWED", "Into is not allowed inside a statement", true, tables);

    auto finish = [&](PolicyResult r) {
        r.is_write = !is_read;
        r.tables = tables;
        return r;
    };

    if (auto b = check_tables(nodes, ctes, policy, role, is_ddl ? std::nullopt : known)) return finish(std::move(*b));

    std::set<std::string> allowed = default_allowed_functions();
    allowed.insert(role.allow_functions.begin(), role.allow_functions.end());
    for (const auto& r : nodes) {
        if (r.node->kind != K::Func) continue;
        std::string names = r.node->text;
        size_t pos = 0;
        while (pos <= names.size()) {
            size_t sp = names.find(' ', pos);
            std::string fname = names.substr(pos, sp == std::string::npos ? std::string::npos : sp - pos);
            pos = sp == std::string::npos ? names.size() + 1 : sp + 1;
            if (role.allow_functions.count(fname)) continue;
            if (!allowed.count(fname) || policy.denied_functions.count(fname))
                return block("FUNCTION_NOT_ALLOWED", "function " + fname + "() is not on the allowlist", !is_read, tables);
        }
    }

    if (!is_ddl)
        if (auto b = check_columns(nodes, ctes, role, tmap)) return finish(std::move(*b));
    for (const Node* w : writes)
        if (auto b = check_write(*w, stmt, policy, role, tables)) return std::move(*b);

    PolicyResult ok;
    ok.allowed = true;
    ok.reason = "allowed";
    ok.is_write = !is_read;
    ok.is_ddl = is_ddl;
    ok.tables = tables;
    return ok;
}

// ------------------------------------------------------------------------------------ config
namespace {
std::set<std::string> str_set(const json::Value* v) {
    std::set<std::string> s;
    if (v && v->is_array())
        for (const auto& e : v->as_array()) s.insert(e.as_string());
    return s;
}
void columns(const json::Value* v, bool& all, std::set<std::string>& cols, bool default_all) {
    if (!v) { all = default_all; return; }
    if (v->is_string()) { all = true; return; }  // "*"
    all = false;
    cols = str_set(v);
}
}  // namespace

Policy Policy::from_json(const json::Value& v) {
    Policy p;
    p.restricted_tables = str_set(v.find("restricted_tables"));
    p.restricted_schemas = str_set(v.find("restricted_schemas"));
    p.denied_functions = str_set(v.find("denied_functions"));
    if (const auto* vc = v.find("version_column")) p.version_column = vc->as_string();
    const auto* roles = v.find("roles");
    if (!roles || !roles->is_object()) throw json::ParseError("policy: missing roles");
    for (const auto& [name, rv] : roles->as_object()) {
        Role r;
        r.kind = rv.find("kind")->as_string();
        r.allow_functions = str_set(rv.find("allow_functions"));
        const auto* tv = rv.find("tables");
        if (tv && tv->is_object()) {
            std::map<std::string, TableAccess> tables;
            for (const auto& [tn, av] : tv->as_object()) {
                TableAccess a;
                columns(av.find("read"), a.read_all, a.read, true);
                columns(av.find("update"), a.update_all, a.update, false);
                if (const auto* i = av.find("insert")) a.insert = i->as_bool();
                if (const auto* d = av.find("delete")) a.del = d->as_bool();
                tables.emplace(tn, std::move(a));
            }
            r.tables = std::move(tables);
        }
        p.roles.emplace(name, std::move(r));
    }
    return p;
}

}  // namespace gk
