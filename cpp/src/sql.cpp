#include "sql.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string_view>

namespace gk::sql {
namespace {

struct FunctionArity { const char* name; unsigned mask; };
struct FunctionCanon { const char* name; int arity; const char* canonical; };
struct NiladicFunc { const char* name; const char* canonical; };
struct StatementWord { const char* word; const char* class_name; };
#include "sqlglot_tables.inc"

std::string lower(std::string_view s) {
    std::string r(s);
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}
std::string upper(std::string_view s) {
    std::string r(s);
    for (auto& c : r) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return r;
}

// ------------------------------------------------------------------------------------ lexer
enum class T { Word, QIdent, Number, String, Param, Op, End };
struct Token {
    T type = T::End;
    std::string text;  // Word: as written; QIdent/String: unescaped content; Op: operator text
    std::string up;    // upper-case copy for Word
    size_t begin = 0, end = 0;
};

bool is_ident_start(unsigned char c) { return std::isalpha(c) || c == '_' || c >= 0x80; }
bool is_ident_part(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$' || c >= 0x80; }

std::vector<Token> lex(const std::string& s) {
    static constexpr const char* kOps[] = {
        "!~*", "->>", "#>>", "<=>", "::", "<>", "!=", "<=", ">=", "||", "->", "#>", "@>", "<@", "&&", "~*", "!~", "<<", ">>",
        "@@", "?|", "?&", ":=", "=>", "+", "-", "*", "/", "%", "^", "<", ">", "=", "~", "&", "|", "#", "@", "?", "(", ")",
        "[", "]", ",", ".", ";", ":"};
    std::vector<Token> out;
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (std::isspace(c)) { ++i; continue; }
        if (c == '-' && i + 1 < n && s[i + 1] == '-') {
            while (i < n && s[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < n && s[i + 1] == '*') {
            int depth = 1;
            i += 2;
            while (i < n && depth > 0) {
                if (s[i] == '/' && i + 1 < n && s[i + 1] == '*') { ++depth; i += 2; }
                else if (s[i] == '*' && i + 1 < n && s[i + 1] == '/') { --depth; i += 2; }
                else ++i;
            }
            if (depth > 0) throw ParseError("unterminated comment");
            continue;
        }
        Token t;
        t.begin = i;
        auto quoted_run = [&](char q, bool backslash) {
            std::string v;
            ++i;
            while (true) {
                if (i >= n) throw ParseError("unterminated quoted token");
                char d = s[i];
                if (backslash && d == '\\' && i + 1 < n) { v += s[i + 1]; i += 2; continue; }
                if (d == q) {
                    if (i + 1 < n && s[i + 1] == q) { v += q; i += 2; continue; }
                    ++i;
                    return v;
                }
                v += d;
                ++i;
            }
        };
        if (is_ident_start(c)) {
            size_t j = i;
            while (j < n && is_ident_part(static_cast<unsigned char>(s[j]))) ++j;
            std::string w = s.substr(i, j - i);
            if (j < n && s[j] == '\'' && w.size() == 1 && std::strchr("eEbBxXnN", w[0])) {
                i = j;
                t.type = T::String;
                t.text = quoted_run('\'', w[0] == 'e' || w[0] == 'E');
            } else {
                t.type = T::Word;
                t.text = w;
                t.up = upper(w);
                i = j;
            }
        } else if (c == '"') {
            t.type = T::QIdent;
            t.text = quoted_run('"', false);
        } else if (c == '\'') {
            t.type = T::String;
            t.text = quoted_run('\'', false);
        } else if (c == '$') {
            size_t j = i + 1;
            if (j < n && std::isdigit(static_cast<unsigned char>(s[j]))) {
                while (j < n && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
                t.type = T::Param;
                t.text = s.substr(i, j - i);
                i = j;
            } else {
                while (j < n && is_ident_part(static_cast<unsigned char>(s[j])) && s[j] != '$') ++j;
                if (j >= n || s[j] != '$') throw ParseError("bad dollar quote");
                std::string tag = s.substr(i, j - i + 1);
                size_t close = s.find(tag, j + 1);
                if (close == std::string::npos) throw ParseError("unterminated dollar quote");
                t.type = T::String;
                t.text = s.substr(j + 1, close - j - 1);
                i = close + tag.size();
            }
        } else if (std::isdigit(c) || (c == '.' && i + 1 < n && std::isdigit(static_cast<unsigned char>(s[i + 1])))) {
            size_t j = i;
            while (j < n && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
            if (j < n && s[j] == '.' && !(j + 1 < n && s[j + 1] == '.')) {
                ++j;
                while (j < n && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
            }
            if (j < n && (s[j] == 'e' || s[j] == 'E')) {
                size_t k = j + 1;
                if (k < n && (s[k] == '+' || s[k] == '-')) ++k;
                if (k < n && std::isdigit(static_cast<unsigned char>(s[k]))) {
                    while (k < n && std::isdigit(static_cast<unsigned char>(s[k]))) ++k;
                    j = k;
                }
            }
            t.type = T::Number;
            t.text = s.substr(i, j - i);
            i = j;
        } else if (c == '%' && i + 1 < n && s[i + 1] == 's') {
            t.type = T::Param;
            t.text = "%s";
            i += 2;
        } else {
            bool hit = false;
            for (const char* op : kOps) {
                size_t len = std::strlen(op);
                if (s.compare(i, len, op) == 0) {
                    t.type = T::Op;
                    t.text = op;
                    i += len;
                    hit = true;
                    break;
                }
            }
            if (!hit) throw ParseError(std::string("unexpected character '") + s[i] + "'");
        }
        t.end = i;
        out.push_back(std::move(t));
    }
    Token e;
    e.begin = e.end = n;
    out.push_back(std::move(e));
    return out;
}

// ------------------------------------------------------------------------------------ parser
const char* const kReserved[] = {
    "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "FOR", "UNION", "INTERSECT", "EXCEPT",
    "WINDOW", "ON", "USING", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL", "OUTER", "RETURNING", "SET",
    "VALUES", "INTO", "AND", "OR", "NOT", "AS", "WHEN", "THEN", "ELSE", "END", "CASE", "IS", "IN", "LIKE", "ILIKE",
    "BETWEEN", "SIMILAR", "ASC", "DESC", "NULLS", "DISTINCT", "ALL", "SELECT", "WITH", "CONFLICT", "DO", "LATERAL",
    "ESCAPE", "TO", "OVER", "FILTER", "WITHIN", "ISNULL", "NOTNULL", "COLLATE", "AT", "ONLY", "TABLESAMPLE", "DEFAULT",
    "OVERRIDING", "SYMMETRIC", "ASYMMETRIC", "UNKNOWN", "BOTH", "LEADING", "TRAILING", "PRIMARY", "REFERENCES",
    "CHECK", "UNIQUE", "CURRENT"};

bool reserved(const std::string& up) {
    return std::any_of(std::begin(kReserved), std::end(kReserved), [&](const char* r) { return up == r; });
}

class Parser {
public:
    explicit Parser(const std::string& sql) : src_(sql), toks_(lex(sql)) {}

    std::vector<Node> script() {
        std::vector<Node> out;
        while (true) {
            while (op(";")) next();
            if (cur().type == T::End) break;
            out.push_back(statement());
            if (cur().type != T::End && !op(";")) fail("unexpected token '" + cur().text + "'");
        }
        return out;
    }

private:
    const std::string& src_;
    std::vector<Token> toks_;
    size_t i_ = 0;
    int depth_ = 0;
    static constexpr int kMaxDepth = 120;  // bounds recursion on hostile input (parse error instead of stack overflow)

    struct DepthGuard {
        Parser& p;
        explicit DepthGuard(Parser& parser) : p(parser) {
            if (++p.depth_ > kMaxDepth) p.fail("nesting too deep");
        }
        ~DepthGuard() { --p.depth_; }
    };

    [[noreturn]] void fail(const std::string& m) const { throw ParseError(m); }
    const Token& cur() const { return toks_[i_]; }
    const Token& at(size_t k) const { return toks_[std::min(i_ + k, toks_.size() - 1)]; }
    const Token& next() {
        const Token& t = toks_[i_];
        if (i_ + 1 < toks_.size()) ++i_;
        return t;
    }
    bool op(const char* o, size_t k = 0) const { return at(k).type == T::Op && at(k).text == o; }
    bool word(const char* w, size_t k = 0) const { return at(k).type == T::Word && at(k).up == w; }
    bool accept_op(const char* o) { if (op(o)) { next(); return true; } return false; }
    bool accept_word(const char* w) { if (word(w)) { next(); return true; } return false; }
    void expect_op(const char* o) { if (!accept_op(o)) fail(std::string("expected '") + o + "'"); }
    void expect_word(const char* w) { if (!accept_word(w)) fail(std::string("expected ") + w); }
    bool at_end_of_stmt() const { return cur().type == T::End || op(";"); }
    bool starts_query(size_t k = 0) const { return word("SELECT", k) || word("WITH", k) || word("VALUES", k); }

    static Node make(K kind, std::string text = {}) {
        Node n;
        n.kind = kind;
        n.text = std::move(text);
        return n;
    }
    void skip_to_end() { while (!at_end_of_stmt()) next(); }

    // ---------------------------------------------------------------------------- statements
    Node statement() {
        if (word("VALUES")) {  // a bare VALUES list is sqlglot's Values node, not a Query
            Node v = values_clause();
            query_tail(v);
            return make(K::Foreign, "Values");
        }
        if (op("(") || word("SELECT") || word("TABLE") || word("WITH") || word("INSERT") || word("UPDATE") ||
            word("DELETE"))
            return query_or_dml();
        if (cur().type != T::Word) fail("unexpected statement start");
        const std::string w = cur().up;
        if (w == "DROP") return ddl_drop();
        if (w == "TRUNCATE") return ddl_truncate();
        if (w == "GRANT" || w == "REVOKE") return ddl_grant(w == "GRANT");
        if (w == "CREATE") return ddl_create();
        if (w == "ALTER") return ddl_alter();
        if (w == "COMMENT") return ddl_comment();
        for (const auto& sw : kStatementWords) {
            if (w == sw.word) {
                Node n = make(K::Foreign, sw.class_name);
                next();
                if (w == "COPY" && (cur().type == T::Word || cur().type == T::QIdent) && !word("TO")) n.kids.push_back(table_name());
                skip_to_end();
                return n;
            }
        }
        // sqlglot parses an unknown leading word as a bare expression (Column / Alias ...), which the policy
        // rejects as a non-query statement. Mirror that, but only when the whole statement is such an expression.
        Node e = expression();
        std::string cls = e.kind == K::Column ? "Column" : "Other";
        if (cur().type == T::Word && !reserved(cur().up)) { next(); cls = "Alias"; }
        if (!at_end_of_stmt()) fail("unrecognised statement");
        return make(K::Foreign, cls);
    }

    Node query_or_dml() {
        DepthGuard guard(*this);
        Node with;
        bool has_with = false;
        if (word("WITH")) {
            with = with_clause();
            has_with = true;
        }
        Node n;
        if (word("INSERT")) n = insert_stmt();
        else if (word("UPDATE")) n = update_stmt();
        else if (word("DELETE")) n = delete_stmt();
        else if (word("SELECT") || word("VALUES") || word("TABLE") || op("(")) n = query();
        else fail("expected statement after WITH");
        if (has_with) n.kids.push_back(std::move(with));
        return n;
    }

    Node with_clause() {
        expect_word("WITH");
        accept_word("RECURSIVE");
        Node w = make(K::With);
        do {
            if (cur().type != T::Word && cur().type != T::QIdent) fail("expected CTE name");
            Node cte = make(K::Cte, next().text);
            if (op("(")) {
                next();
                while (!op(")")) {
                    if (cur().type == T::End) fail("unterminated CTE column list");
                    next();
                }
                next();
            }
            expect_word("AS");
            if (accept_word("NOT")) expect_word("MATERIALIZED");
            else accept_word("MATERIALIZED");
            expect_op("(");
            cte.kids.push_back(query_or_dml());
            expect_op(")");
            w.kids.push_back(std::move(cte));
        } while (accept_op(","));
        return w;
    }

    // ---------------------------------------------------------------------------- queries
    Node query() {
        Node left = query_primary();
        int chain = 0;
        while (word("UNION") || word("INTERSECT") || word("EXCEPT")) {
            if (++chain > kMaxTreeDepth) fail("too many set operations");
            Node s = make(K::SetOp, next().up);
            if (!accept_word("ALL")) accept_word("DISTINCT");
            s.kids.push_back(std::move(left));
            s.kids.push_back(query_primary());
            left = std::move(s);
        }
        query_tail(left);
        return left;
    }

    Node query_primary() {
        if (op("(")) {
            next();
            Node inner = query_or_dml();
            expect_op(")");
            Node sq = make(K::Subquery);
            sq.kids.push_back(std::move(inner));
            return sq;
        }
        if (word("VALUES")) return values_clause();
        if (word("TABLE")) {  // TABLE name == SELECT * FROM name
            next();
            Node s = make(K::Select);
            s.kids.push_back(make(K::Star));
            s.kids.push_back(table_name());
            return s;
        }
        return select_core();
    }

    Node values_clause() {
        expect_word("VALUES");
        Node v = make(K::Select, "VALUES");
        do {
            expect_op("(");
            do v.kids.push_back(expr_or_default()); while (accept_op(","));
            expect_op(")");
        } while (accept_op(","));
        return v;
    }

    Node expr_or_default() {
        if (word("DEFAULT")) { next(); return make(K::Other, "DEFAULT"); }
        return expression();
    }

    void query_tail(Node& n) {
        if (word("ORDER")) order_by(n.kids);
        // LIMIT / OFFSET / FETCH may come in either order
        while (true) {
            if (accept_word("LIMIT")) {
                if (!accept_word("ALL")) n.kids.push_back(expression());
            } else if (accept_word("OFFSET")) {
                n.kids.push_back(expression());
                if (!accept_word("ROW")) accept_word("ROWS");
            } else if (word("FETCH")) {
                next();
                if (!accept_word("FIRST")) expect_word("NEXT");
                if (!(word("ROW") || word("ROWS"))) n.kids.push_back(expression());
                if (!accept_word("ROW")) expect_word("ROWS");
                if (accept_word("ONLY")) {} else { expect_word("WITH"); expect_word("TIES"); }
            } else {
                break;
            }
        }
        while (word("FOR")) {
            next();
            if (accept_word("NO")) expect_word("KEY");
            else accept_word("KEY");
            if (!accept_word("UPDATE")) expect_word("SHARE");
            if (accept_word("OF")) {
                do table_name(); while (accept_op(","));
            }
            if (!accept_word("NOWAIT") && accept_word("SKIP")) expect_word("LOCKED");
        }
    }

    void order_by(std::vector<Node>& out) {
        expect_word("ORDER");
        expect_word("BY");
        do {
            out.push_back(expression());
            if (accept_word("USING")) next();
            else if (!accept_word("ASC")) accept_word("DESC");
            if (accept_word("NULLS")) { if (!accept_word("FIRST")) expect_word("LAST"); }
        } while (accept_op(","));
    }

    Node select_core() {
        expect_word("SELECT");
        Node s = make(K::Select);
        if (accept_word("DISTINCT")) {
            if (accept_word("ON")) {
                expect_op("(");
                do s.kids.push_back(expression()); while (accept_op(","));
                expect_op(")");
            }
        } else {
            accept_word("ALL");
        }
        select_items(s.kids);
        if (word("INTO")) {
            next();
            Node into = make(K::Into);
            if (!(accept_word("TEMPORARY") || accept_word("TEMP"))) accept_word("UNLOGGED");
            accept_word("TABLE");
            into.kids.push_back(table_name());
            s.kids.push_back(std::move(into));
        }
        if (accept_word("FROM")) from_items(s.kids);
        if (word("WHERE")) set_where(s);
        if (word("GROUP")) {
            next();
            expect_word("BY");
            do s.kids.push_back(expression()); while (accept_op(","));
        }
        if (accept_word("HAVING")) s.kids.push_back(expression());
        if (accept_word("WINDOW")) {
            do {
                next();
                expect_word("AS");
                window_spec(s.kids);
            } while (accept_op(","));
        }
        return s;
    }

    void set_where(Node& owner) {
        expect_word("WHERE");
        if (word("CURRENT")) fail("WHERE CURRENT OF is not supported");
        size_t begin = cur().begin;
        Node e = expression();
        e.source = src_.substr(begin, toks_[i_ - 1].end - begin);
        owner.where = static_cast<int>(owner.kids.size());
        owner.kids.push_back(std::move(e));
    }

    void select_items(std::vector<Node>& out) {
        do {
            if (op("*")) {
                next();
                out.push_back(make(K::Star));
                continue;
            }
            Node e = expression();
            std::string a;
            if (accept_word("AS")) {
                if (cur().type != T::Word && cur().type != T::QIdent) fail("expected alias");
                a = next().text;
            } else if (cur().type == T::QIdent || (cur().type == T::Word && !reserved(cur().up))) {
                a = next().text;
            }
            if (!a.empty()) {
                Node al = make(K::Alias);
                al.alias = a;
                al.kids.push_back(std::move(e));
                out.push_back(std::move(al));
            } else {
                out.push_back(std::move(e));
            }
        } while (accept_op(","));
    }

    // ---------------------------------------------------------------------------- FROM clause
    struct NamePart { std::string text; bool quoted; };

    std::vector<NamePart> name_parts(bool allow_star = false) {
        std::vector<NamePart> parts;
        while (true) {
            if (cur().type == T::Word) parts.push_back({cur().text, false});
            else if (cur().type == T::QIdent) parts.push_back({cur().text, true});
            else fail("expected identifier");
            next();
            if (op(".") && (at(1).type == T::Word || at(1).type == T::QIdent)) { next(); continue; }
            if (allow_star && op(".") && op("*", 1)) break;
            break;
        }
        return parts;
    }

    Node table_from_parts(const std::vector<NamePart>& p) {
        if (p.size() > 3) fail("too many name parts");
        Node t = make(K::Table, p.back().text);
        t.quoted = p.back().quoted;
        if (p.size() >= 2) t.schema = p[p.size() - 2].text;
        return t;
    }

    Node table_name() { return table_from_parts(name_parts()); }

    std::string opt_alias() {
        std::string a;
        if (accept_word("AS")) {
            if (cur().type != T::Word && cur().type != T::QIdent) fail("expected alias");
            a = next().text;
        } else if (cur().type == T::QIdent || (cur().type == T::Word && !reserved(cur().up))) {
            a = next().text;
        }
        if (!a.empty() && op("(")) {
            next();
            while (!op(")")) {
                if (cur().type == T::End) fail("unterminated alias column list");
                next();
            }
            next();
        }
        return a;
    }

    void from_items(std::vector<Node>& out) {
        from_factor(out);
        while (true) {
            if (accept_op(",")) { from_factor(out); continue; }
            if (word("JOIN") || word("INNER") || word("LEFT") || word("RIGHT") || word("FULL") || word("CROSS") ||
                word("NATURAL")) {
                accept_word("NATURAL");
                if (accept_word("INNER") || accept_word("CROSS")) {}
                else if (accept_word("LEFT") || accept_word("RIGHT") || accept_word("FULL")) accept_word("OUTER");
                expect_word("JOIN");
                from_factor(out);
                if (accept_word("ON")) out.push_back(expression());
                else if (accept_word("USING")) {
                    expect_op("(");
                    while (!op(")")) { if (cur().type == T::End) fail("unterminated USING"); next(); }
                    next();
                }
                continue;
            }
            break;
        }
    }

    void from_factor(std::vector<Node>& out) {
        if (accept_word("LATERAL")) {
            from_factor(out);
            return;
        }
        if (op("(")) {
            if (starts_query(1) || op("(", 1)) {
                next();
                Node sq = make(K::Subquery);
                sq.kids.push_back(query_or_dml());
                expect_op(")");
                sq.alias = opt_alias();
                out.push_back(std::move(sq));
            } else {
                next();
                from_items(out);
                expect_op(")");
                opt_alias();
            }
            return;
        }
        accept_word("ONLY");
        if (cur().type != T::Word && cur().type != T::QIdent) fail("expected table");
        auto parts = name_parts();
        if (op("(")) {  // function in FROM
            Node f = function_call(parts);
            if (accept_word("WITH")) expect_word("ORDINALITY");
            f.alias = opt_alias();
            out.push_back(std::move(f));
            return;
        }
        Node t = table_from_parts(parts);
        if (accept_word("TABLESAMPLE")) {
            next();
            expect_op("(");
            do out.push_back(expression()); while (accept_op(","));
            expect_op(")");
            if (accept_word("REPEATABLE")) { expect_op("("); expression(); expect_op(")"); }
        }
        t.alias = opt_alias();
        out.push_back(std::move(t));
    }

    // ---------------------------------------------------------------------------- DML
    Node assign() {
        auto parts = name_parts();
        Node col = make(K::Column, parts.back().text);
        col.quoted = parts.back().quoted;
        if (parts.size() >= 2) col.schema = parts[parts.size() - 2].text;
        if (!op("=")) fail("expected '=' in SET");
        next();
        Node a = make(K::Assign);
        a.kids.push_back(std::move(col));
        a.kids.push_back(expr_or_default());
        return a;
    }

    void assignments(Node& owner) {
        do {
            owner.assigns.push_back(static_cast<int>(owner.kids.size()));
            owner.kids.push_back(assign());
        } while (accept_op(","));
    }

    void returning(Node& n) {
        if (accept_word("RETURNING")) select_items(n.kids);
    }

    Node dml_target(Node& owner) {
        accept_word("ONLY");
        Node t = table_name();
        if (accept_word("AS")) {
            if (cur().type != T::Word && cur().type != T::QIdent) fail("expected alias");
            t.alias = next().text;
        } else if (cur().type == T::QIdent || (cur().type == T::Word && !reserved(cur().up) && !word("SELECT"))) {
            t.alias = next().text;
        }
        owner.target = static_cast<int>(owner.kids.size());
        return t;
    }

    Node insert_stmt() {
        expect_word("INSERT");
        expect_word("INTO");
        Node n = make(K::Insert);
        Node t = dml_target(n);
        n.kids.push_back(std::move(t));
        if (op("(") && !(starts_query(1) || op("(", 1))) {
            next();
            while (!op(")")) {
                if (cur().type != T::Word && cur().type != T::QIdent) fail("expected column name");
                next();
                if (!accept_op(",") && !op(")")) fail("expected ',' or ')'");
            }
            next();
        }
        if (accept_word("OVERRIDING")) { next(); expect_word("VALUE"); }
        if (accept_word("DEFAULT")) expect_word("VALUES");
        else if (word("VALUES")) n.kids.push_back(values_clause());
        else if (starts_query() || op("(")) {
            Node q = query_or_dml();
            n.kids.push_back(std::move(q));
        } else fail("expected VALUES or query");
        if (word("ON") && word("CONFLICT", 1)) {
            next(); next();
            Node c = make(K::Conflict);
            if (op("(")) {
                next();
                do {
                    Node e = expression();
                    (void)e;  // index inference elements are identifiers, not column references
                } while (accept_op(","));
                expect_op(")");
                if (word("WHERE")) { next(); expression(); }
            } else if (accept_word("ON")) {
                expect_word("CONSTRAINT");
                next();
            }
            expect_word("DO");
            if (accept_word("NOTHING")) {
            } else {
                expect_word("UPDATE");
                expect_word("SET");
                assignments(c);
                c.flag = true;
                if (word("WHERE")) { next(); c.kids.push_back(expression()); }
            }
            n.flag = c.flag;
            n.kids.push_back(std::move(c));
        }
        returning(n);
        return n;
    }

    Node update_stmt() {
        expect_word("UPDATE");
        Node n = make(K::Update);
        Node t = dml_target(n);
        n.kids.push_back(std::move(t));
        expect_word("SET");
        assignments(n);
        if (accept_word("FROM")) from_items(n.kids);
        if (word("WHERE")) set_where(n);
        returning(n);
        return n;
    }

    Node delete_stmt() {
        expect_word("DELETE");
        expect_word("FROM");
        Node n = make(K::Delete);
        Node t = dml_target(n);
        n.kids.push_back(std::move(t));
        if (accept_word("USING")) from_items(n.kids);
        if (word("WHERE")) set_where(n);
        returning(n);
        return n;
    }

    // ---------------------------------------------------------------------------- DDL (shallow)
    void skip_balanced() {
        int depth = 0;
        do {
            if (cur().type == T::End) fail("unbalanced parentheses");
            if (op("(")) ++depth;
            else if (op(")")) --depth;
            next();
        } while (depth > 0);
    }

    Node ddl_drop() {
        Node n = make(K::Drop);
        next();
        std::string kind = cur().up;
        if (word("MATERIALIZED")) { next(); kind = cur().up; }
        next();
        accept_word("CONCURRENTLY");
        if (accept_word("IF")) expect_word("EXISTS");
        if (kind == "TABLE" || kind == "VIEW" || kind == "INDEX" || kind == "SEQUENCE") {
            do n.kids.push_back(table_name()); while (accept_op(","));
        }
        skip_to_end();
        return n;
    }

    Node ddl_truncate() {
        Node n = make(K::Truncate);
        next();
        accept_word("TABLE");
        do {
            accept_word("ONLY");
            n.kids.push_back(table_name());
            accept_op("*");
        } while (accept_op(","));
        skip_to_end();
        return n;
    }

    Node ddl_grant(bool grant) {
        Node n = make(grant ? K::Grant : K::Revoke);
        next();
        while (!at_end_of_stmt() && !word("ON")) next();
        if (accept_word("ON")) {
            accept_word("TABLE");
            if (cur().type == T::Word || cur().type == T::QIdent) n.kids.push_back(table_name());
        }
        skip_to_end();
        return n;
    }

    Node ddl_comment() {
        Node n = make(K::CommentStmt);
        next();
        expect_word("ON");
        const bool is_table = word("TABLE");
        if (cur().type != T::Word) fail("expected object kind");
        next();
        Node target = table_from_parts(name_parts());
        if (is_table) n.kids.push_back(std::move(target));
        expect_word("IS");
        if (cur().type != T::String && !word("NULL")) fail("expected comment text");
        next();
        if (!at_end_of_stmt()) fail("unexpected token after COMMENT");
        return n;
    }

    Node ddl_alter() {
        Node n = make(K::Alter);
        next();
        if (!accept_word("TABLE")) {  // sqlglot turns other ALTER kinds into a generic Command
            skip_to_end();
            return make(K::Foreign, "Command");
        }
        if (accept_word("IF")) expect_word("EXISTS");
        accept_word("ONLY");
        for (const char* kw : {"ADD", "DROP", "ALTER", "RENAME", "SET", "OWNER", "ENABLE", "DISABLE"})
            if (word(kw)) fail("expected table name");
        n.kids.push_back(table_name());
        while (!at_end_of_stmt()) {
            if (word("DROP")) n.kids.push_back(make(K::Drop));
            next();
        }
        return n;
    }

    Node ddl_create() {
        Node n = make(K::Create);
        next();
        while (word("OR") || word("REPLACE") || word("UNIQUE") || word("TEMP") || word("TEMPORARY") ||
               word("UNLOGGED") || word("GLOBAL") || word("LOCAL") || word("MATERIALIZED") || word("RECURSIVE"))
            next();
        std::string kind = cur().up;
        next();
        accept_word("CONCURRENTLY");
        if (accept_word("IF")) { expect_word("NOT"); expect_word("EXISTS"); }
        if (kind != "TABLE" && kind != "INDEX" && kind != "VIEW" && kind != "SEQUENCE" && kind != "SCHEMA") {
            skip_to_end();  // sqlglot: unknown CREATE kinds become a generic Command
            return make(K::Foreign, "Command");
        }
        if (kind == "TABLE") {
            n.kids.push_back(table_name());
            if (op("(")) skip_balanced();
            if (accept_word("AS")) n.kids.push_back(query_or_dml());
        } else if (kind == "INDEX") {
            if (!word("ON")) next();
            expect_word("ON");
            accept_word("ONLY");
            n.kids.push_back(table_name());
            if (accept_word("USING")) next();
            expect_op("(");
            do {
                n.kids.push_back(expression());
                if (cur().type == T::Word && !reserved(cur().up)) next();  // operator class
                if (!accept_word("ASC")) accept_word("DESC");
                if (accept_word("NULLS")) { if (!accept_word("FIRST")) expect_word("LAST"); }
            } while (accept_op(","));
            expect_op(")");
            if (accept_word("WHERE")) n.kids.push_back(expression());
        } else if (kind == "VIEW") {
            n.kids.push_back(table_name());
            if (op("(")) skip_balanced();
            expect_word("AS");
            n.kids.push_back(query_or_dml());
        }
        skip_to_end();
        return n;
    }

    // ---------------------------------------------------------------------------- expressions
    Node expression() { return parse_or(); }

    // Left-associative chains (a+a+a+...) build deep trees without recursing in the parser; cap them so the
    // recursive analyses (signature, constant folding) cannot overflow the stack.
    static constexpr int kMaxTreeDepth = 400;
    Node binary(K kind, std::string text, Node l, Node r) {
        Node n = make(kind, std::move(text));
        n.depth = std::max(l.depth, r.depth) + 1;
        if (n.depth > kMaxTreeDepth) fail("expression too deeply nested");
        n.kids.push_back(std::move(l));
        n.kids.push_back(std::move(r));
        return n;
    }
    Node wrap(K kind, Node inner, std::string text = {}) {
        Node n = make(kind, std::move(text));
        n.depth = inner.depth + 1;
        if (n.depth > kMaxTreeDepth) fail("expression too deeply nested");
        n.kids.push_back(std::move(inner));
        return n;
    }

    Node parse_or() {
        DepthGuard guard(*this);
        Node l = parse_and();
        while (accept_word("OR")) l = binary(K::Or, "OR", std::move(l), parse_and());
        return l;
    }
    Node parse_and() {
        Node l = parse_not();
        while (accept_word("AND")) l = binary(K::And, "AND", std::move(l), parse_not());
        return l;
    }
    Node parse_not() {
        DepthGuard guard(*this);
        if (accept_word("NOT")) return wrap(K::Not, parse_not(), "NOT");
        return parse_is();
    }
    // IS / comparison / BETWEEN / IN / LIKE share one left-associative level. PostgreSQL itself is stricter
    // (non-associative), sqlglot accepts chains, so the port does too.
    Node parse_is() {
        Node l = parse_other();
        while (true) {
            if (word("IS")) {
                next();
                bool neg = accept_word("NOT");
                Node r;
                if (accept_word("NULL")) r = make(K::Null);
                else if (accept_word("TRUE")) r = make(K::Boolean, "true");
                else if (accept_word("FALSE")) r = make(K::Boolean, "false");
                else if (accept_word("UNKNOWN")) r = make(K::Null);
                else if (accept_word("DISTINCT")) {
                    expect_word("FROM");
                    l = binary(K::Binary, neg ? "IS NOT DISTINCT FROM" : "IS DISTINCT FROM", std::move(l), parse_other());
                    continue;
                } else fail("unsupported IS predicate");
                Node is = binary(K::Is, "IS", std::move(l), std::move(r));
                l = neg ? wrap(K::Not, std::move(is), "NOT") : std::move(is);
            } else if (word("ISNULL") || word("NOTNULL")) {
                bool neg = word("NOTNULL");
                next();
                Node is = binary(K::Is, "IS", std::move(l), make(K::Null));
                l = neg ? wrap(K::Not, std::move(is), "NOT") : std::move(is);
            } else if (op("=") || op("<>") || op("!=") || op("<") || op(">") || op("<=") || op(">=") || op("<=>")) {
                std::string o = next().text;
                if (o == "!=") o = "<>";
                if (o == "<=>") o = "IS NOT DISTINCT FROM";
                l = binary(K::Binary, o, std::move(l), parse_other());
            } else if (word("BETWEEN") || word("IN") || word("LIKE") || word("ILIKE") || word("SIMILAR") ||
                       (word("NOT") && (word("BETWEEN", 1) || word("IN", 1) || word("LIKE", 1) || word("ILIKE", 1) ||
                                        word("SIMILAR", 1)))) {
                l = range_predicate(std::move(l));
            } else break;
        }
        return l;
    }
    Node range_predicate(Node l) {
        bool neg = accept_word("NOT");
        Node r;
        if (accept_word("BETWEEN")) {
            if (!accept_word("SYMMETRIC")) accept_word("ASYMMETRIC");
            Node lo = parse_other();
            expect_word("AND");
            Node hi = parse_other();
            r = make(K::Between);
            r.kids.push_back(std::move(l));
            r.kids.push_back(std::move(lo));
            r.kids.push_back(std::move(hi));
        } else if (accept_word("IN")) {
            expect_op("(");
            r = make(K::In);
            r.kids.push_back(std::move(l));
            if (starts_query()) {
                Node sq = make(K::Subquery);
                sq.kids.push_back(query_or_dml());
                r.kids.push_back(std::move(sq));
            } else {
                do r.kids.push_back(expression()); while (accept_op(","));
            }
            expect_op(")");
        } else {
            std::string kw = next().up;
            if (kw == "SIMILAR") expect_word("TO");
            Node pat = parse_other();
            if (accept_word("ESCAPE")) parse_other();
            r = binary(K::Like, kw, std::move(l), std::move(pat));
        }
        return neg ? wrap(K::Not, std::move(r), "NOT") : r;
    }
    Node parse_other() {
        Node l = parse_add();
        while (true) {
            if (op("||") || op("->") || op("->>") || op("#>") || op("#>>") || op("@>") || op("<@") || op("&&") ||
                op("~") || op("~*") || op("!~") || op("!~*") || op("<<") || op(">>") || op("&") || op("|") ||
                op("#") || op("@@") || op("?") || op("?|") || op("?&") || op("@")) {
                std::string o = next().text;
                l = binary(K::Binary, o, std::move(l), parse_add());
            } else if (word("AT") && word("TIME", 1) && word("ZONE", 2)) {
                next(); next(); next();
                l = binary(K::Binary, "AT TIME ZONE", std::move(l), parse_add());
            } else break;
        }
        return l;
    }
    Node parse_add() {
        Node l = parse_mul();
        while (op("+") || op("-")) {
            std::string o = next().text;
            l = binary(K::Binary, o, std::move(l), parse_mul());
        }
        return l;
    }
    Node parse_mul() {
        Node l = parse_pow();
        while (op("*") || op("/") || op("%")) {
            std::string o = next().text;
            l = binary(K::Binary, o, std::move(l), parse_pow());
        }
        return l;
    }
    Node parse_pow() {
        Node l = parse_unary();
        while (op("^")) {
            next();
            l = binary(K::Binary, "^", std::move(l), parse_unary());
        }
        return l;
    }
    Node parse_unary() {
        DepthGuard guard(*this);
        if (op("-")) { next(); return wrap(K::Neg, parse_unary(), "-"); }
        if (op("+")) { next(); return parse_unary(); }
        return parse_postfix();
    }
    Node parse_postfix() {
        Node e = primary();
        int chain = 0;
        while (true) {
            if (++chain > kMaxTreeDepth) fail("postfix chain too long");
            if (op("::")) {
                next();
                skip_type();
                Node c = make(K::Func, "cast");
                c.kids.push_back(std::move(e));
                e = std::move(c);
            } else if (op("[")) {
                next();
                Node s = make(K::Subscript);
                s.kids.push_back(std::move(e));
                if (!op(":")) s.kids.push_back(expression());
                if (accept_op(":")) { if (!op("]")) s.kids.push_back(expression()); }
                expect_op("]");
                e = std::move(s);
            } else if (word("COLLATE")) {
                next();
                name_parts();
            } else break;
        }
        return e;
    }

    void skip_type() {
        auto parts = name_parts();
        const std::string base = upper(parts.back().text);
        if (parts.size() == 1 && !parts[0].quoted) {
            if (base == "DOUBLE") expect_word("PRECISION");
            else if (base == "CHARACTER" || base == "CHAR" || base == "BIT" || base == "NATIONAL") accept_word("VARYING");
        }
        if (op("(")) {
            next();
            while (!op(")")) {
                if (cur().type != T::Number && !op(",")) fail("bad type modifier");
                next();
            }
            next();
        }
        if ((word("WITH") || word("WITHOUT")) && word("TIME", 1) && word("ZONE", 2)) { next(); next(); next(); }
        while (op("[")) { next(); if (cur().type == T::Number) next(); expect_op("]"); }
    }

    static const char* niladic(const std::string& lowered) {
        for (const auto& nf : kNiladic)
            if (lowered == nf.name) return nf.canonical;
        return nullptr;
    }

    Node primary() {
        const Token& t = cur();
        switch (t.type) {
            case T::Number: { Node n = make(K::Literal, t.text); next(); return n; }
            case T::String: { Node n = make(K::Literal, t.text); n.quoted = true; next(); return n; }
            case T::Param: { Node n = make(K::Param, t.text); next(); return n; }
            case T::Op:
                if (t.text == "(") return paren();
                fail("unexpected '" + t.text + "'");
            case T::End: fail("unexpected end of SQL");
            case T::QIdent: return name_or_call();
            case T::Word: break;
        }
        const std::string& w = t.up;
        if (w == "NULL") { next(); return make(K::Null); }
        if (w == "TRUE" || w == "FALSE") { next(); return make(K::Boolean, lower(w)); }
        if (w == "CASE") return case_expr();
        if ((w == "CAST" || w == "TRY_CAST") && op("(", 1)) {
            std::string fname = lower(w);
            next(); next();
            Node e = expression();
            expect_word("AS");
            skip_type();
            expect_op(")");
            Node c = make(K::Func, fname);
            c.kids.push_back(std::move(e));
            return c;
        }
        if (w == "EXISTS" && op("(", 1)) {
            next(); next();
            Node sq = make(K::Subquery);
            sq.kids.push_back(query_or_dml());
            expect_op(")");
            return wrap(K::Exists, std::move(sq), "EXISTS");
        }
        if ((w == "ANY" || w == "ALL" || w == "SOME") && op("(", 1)) {
            next(); next();
            Node a = make(K::AnyAll, w);
            if (starts_query()) {
                Node sq = make(K::Subquery);
                sq.kids.push_back(query_or_dml());
                a.kids.push_back(std::move(sq));
            } else a.kids.push_back(expression());
            expect_op(")");
            return a;
        }
        if (w == "ARRAY" && (op("[", 1) || op("(", 1))) {
            next();
            Node a = make(K::Func, "array");
            if (accept_op("[")) {
                if (!op("]")) do a.kids.push_back(expression()); while (accept_op(","));
                expect_op("]");
            } else {
                next();
                Node sq = make(K::Subquery);
                sq.kids.push_back(query_or_dml());
                a.kids.push_back(std::move(sq));
                expect_op(")");
            }
            return a;
        }
        if (w == "EXTRACT" && op("(", 1)) {
            next(); next();
            next();  // field
            expect_word("FROM");
            Node e = expression();
            expect_op(")");
            Node f = make(K::Func, "extract");
            f.kids.push_back(std::move(e));
            return f;
        }
        if (w == "INTERVAL" && at(1).type == T::String) {
            next(); next();
            if (cur().type == T::Word && !reserved(cur().up) &&
                (word("YEAR") || word("MONTH") || word("DAY") || word("HOUR") || word("MINUTE") || word("SECOND")))
                next();
            return make(K::Interval);
        }
        if ((w == "DATE" || w == "TIME" || w == "TIMESTAMP" || w == "TIMESTAMPTZ" || w == "TIMETZ") &&
            at(1).type == T::String) {
            next();
            Node lit = make(K::Literal, cur().text);
            lit.quoted = true;
            next();
            Node c = make(K::Func, "cast");
            c.kids.push_back(std::move(lit));
            return c;
        }
        if (w == "POSITION" && op("(", 1)) {
            next(); next();
            Node a = parse_other();
            expect_word("IN");
            Node b = parse_other();
            expect_op(")");
            Node f = make(K::Func, "str_position");
            f.kids.push_back(std::move(a));
            f.kids.push_back(std::move(b));
            return f;
        }
        if (const char* canon = niladic(lower(w)); canon != nullptr && !op("(", 1)) {
            next();
            return make(K::Func, canon);
        }
        if (reserved(w) && !op("(", 1)) fail("unexpected keyword " + w);
        return name_or_call();
    }

    Node paren() {
        expect_op("(");
        if (starts_query()) {
            Node sq = make(K::Subquery);
            sq.kids.push_back(query_or_dml());
            expect_op(")");
            return sq;
        }
        Node first = expression();
        if (op(",")) {
            Node row = make(K::Other, "ROW");
            row.kids.push_back(std::move(first));
            while (accept_op(",")) row.kids.push_back(expression());
            expect_op(")");
            return row;
        }
        expect_op(")");
        return wrap(K::Paren, std::move(first), "(");
    }

    Node case_expr() {
        expect_word("CASE");
        Node c = make(K::Func, "case");
        if (!word("WHEN")) c.kids.push_back(expression());
        if (!word("WHEN")) fail("CASE needs WHEN");
        while (accept_word("WHEN")) {
            Node cond = expression();
            expect_word("THEN");
            Node res = expression();
            Node f = make(K::Func, "if");
            f.kids.push_back(std::move(cond));
            f.kids.push_back(std::move(res));
            c.kids.push_back(std::move(f));
        }
        if (accept_word("ELSE")) c.kids.push_back(expression());
        expect_word("END");
        return c;
    }

    Node name_or_call() {
        auto parts = name_parts(true);
        if (op("(")) return function_call(parts);
        if (op(".") && op("*", 1)) {
            next(); next();
            Node col = make(K::Column);
            col.schema = parts.back().text;
            col.kids.push_back(make(K::Star));
            return col;
        }
        Node col = make(K::Column, parts.back().text);
        col.quoted = parts.back().quoted;
        if (parts.size() >= 2) col.schema = parts[parts.size() - 2].text;
        return col;
    }

    void window_spec(std::vector<Node>& out) {
        expect_op("(");
        if (cur().type == T::Word && !word("PARTITION") && !word("ORDER") && !word("ROWS") && !word("RANGE") && !word("GROUPS"))
            next();  // base window name
        if (accept_word("PARTITION")) {
            expect_word("BY");
            do out.push_back(expression()); while (accept_op(","));
        }
        if (word("ORDER")) order_by(out);
        if (word("ROWS") || word("RANGE") || word("GROUPS")) {
            int depth = 0;
            while (!(depth == 0 && op(")"))) {
                if (cur().type == T::End) fail("unterminated window frame");
                if (op("(")) ++depth;
                if (op(")")) --depth;
                if (cur().type == T::Number || cur().type == T::Word || op(",") || op("(") || op(")")) next();
                else fail("unsupported window frame");
            }
        }
        expect_op(")");
    }

    Node function_call(const std::vector<NamePart>& parts) {
        const bool plain = parts.size() == 1 && !parts[0].quoted;
        const std::string name = lower(parts.back().text);
        expect_op("(");
        std::vector<Node> args;
        const bool infix = name == "substring" || name == "trim" || name == "overlay";
        if (infix && (word("BOTH") || word("LEADING") || word("TRAILING"))) next();
        if (!op(")")) {
            if (!accept_word("DISTINCT")) accept_word("ALL");
            if (op("*") && op(")", 1)) {
                next();
                args.push_back(make(K::Star));
            } else {
                do {
                    accept_word("VARIADIC");
                    if (infix && (word("FROM") || word("FOR"))) next();
                    args.push_back(name == "trim" ? parse_other() : expression());  // sqlglot rejects predicates in TRIM()
                    if (op("=>") || op(":=")) { next(); args.back() = expression(); }
                } while (accept_op(",") || (infix && (word("FROM") || word("FOR"))));
            }
            if (word("ORDER")) order_by(args);
        }
        expect_op(")");
        std::string canon = name;
        bool operator_node = false;
        if (plain) {
            const int n = static_cast<int>(args.size());
            for (const auto& fa : kFunctionArity)
                if (name == fa.name && !((fa.mask >> std::min(n, 6)) & 1U)) fail("wrong number of arguments for " + name + "()");
            for (const auto& fc : kFunctionCanon) {
                if (name == fc.name && (fc.arity == -1 || fc.arity == n)) {
                    canon = fc.canonical;
                    operator_node = canon.empty();
                    break;
                }
            }
        }
        Node f = make(operator_node ? K::Binary : K::Func, operator_node ? name : canon);
        for (auto& a : args) f.kids.push_back(std::move(a));
        if (word("WITHIN")) {
            next();
            expect_word("GROUP");
            expect_op("(");
            order_by(f.kids);
            expect_op(")");
        }
        if (accept_word("FILTER")) {
            expect_op("(");
            expect_word("WHERE");
            f.kids.push_back(expression());
            expect_op(")");
        }
        if (accept_word("OVER")) {
            if (op("(")) window_spec(f.kids);
            else next();
        }
        return f;
    }
};

void sig_into(const Node& n, std::string& out) {
    out += std::to_string(static_cast<int>(n.kind));
    out += n.quoted ? "q" : "u";
    out += '[';
    out += n.text;
    out += '|';
    out += n.schema;
    out += '|';
    out += n.alias;
    out += ']';
    out += '(';
    for (const auto& k : n.kids) {
        sig_into(k, out);
        out += ',';
    }
    out += ')';
}

}  // namespace

std::vector<Node> parse(const std::string& sql) { return Parser(sql).script(); }

std::string signature(const Node& n) {
    std::string s;
    sig_into(n, s);
    return s;
}

}  // namespace gk::sql
