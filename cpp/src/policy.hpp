// C++20 port of mcp_gatekeeper.policy.check: the static, model-free SQL policy decision.
#pragma once
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "json.hpp"

namespace gk {

struct TableAccess {
    bool read_all = true;
    std::set<std::string> read;
    bool update_all = false;
    std::set<std::string> update;
    bool insert = false;
    bool del = false;

    bool can_read(const std::string& c) const { return read_all || read.count(c) > 0; }
    bool can_update(const std::string& c) const { return update_all || update.count(c) > 0; }
};

struct Role {
    std::string kind;  // read_only | scoped_write | admin
    std::optional<std::map<std::string, TableAccess>> tables;
    std::set<std::string> allow_functions;
};

struct Policy {
    std::map<std::string, Role> roles;
    std::set<std::string> restricted_tables;
    std::set<std::string> restricted_schemas;
    std::set<std::string> denied_functions;
    std::string version_column = "version";

    // Accepts the JSON produced by pydantic's Policy.model_dump(mode="json").
    static Policy from_json(const json::Value& v);
};

struct PolicyResult {
    bool allowed = false;
    std::optional<std::string> rule_id;
    std::string reason;
    bool is_write = true;
    bool is_ddl = false;
    std::vector<std::string> tables;  // sorted, unique
};

const std::set<std::string>& default_allowed_functions();

PolicyResult check(const std::string& sql, const Policy& policy, const Role& role,
                   const std::optional<std::set<std::string>>& known_tables);

}  // namespace gk
