// Lexer + recursive-descent parser for the PostgreSQL subset the gatekeeper policy inspects.
// Produces a small generic AST (Node). Anything outside the subset throws ParseError, which the
// policy layer turns into a PARSE_ERROR block (fail closed).
#pragma once
#include <stdexcept>
#include <string>
#include <vector>

namespace gk::sql {

class ParseError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

enum class K {
    // roots
    Select, SetOp, Subquery, Insert, Update, Delete, Drop, Truncate, Grant, Revoke, Create, Alter,
    CommentStmt, Foreign,
    // structure
    With, Cte, Table, Column, Star, Func, Alias, Assign, Conflict, Into, Ident,
    // expressions
    Literal, Boolean, Null, Param, Binary, And, Or, Not, Neg, Paren, Between, In, Like, Is, Exists, AnyAll,
    Subscript, Interval, Other,
};

struct Node {
    K kind = K::Other;
    std::string text;    // operator / function canonical names (space separated) / class name / literal value
    std::string schema;  // Table: schema part as written; Column: table qualifier as written
    std::string alias;   // Table / Alias
    bool quoted = false; // Table / Column / Literal(is_string)
    bool flag = false;   // Insert: conflict DO UPDATE; Is/Like/In/Between: NOT; Conflict: has assignments
    int where = -1;      // index into kids of the WHERE expression
    int depth = 0;       // expression-tree depth for binary/wrap chains (parser bookkeeping)
    int target = -1;     // index into kids of the DML target Table
    std::vector<int> assigns;  // indices into kids of Assign nodes
    std::vector<Node> kids;
    std::string source;  // Select/DML WHERE text for messages (filled for where expressions)
};

// Parses a script into statements. Empty statements are dropped. Throws ParseError.
std::vector<Node> parse(const std::string& sql);

// Canonical signature used for structural equality (case-insensitive, like sqlglot's hash).
std::string signature(const Node& n);

}  // namespace gk::sql
