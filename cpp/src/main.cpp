// gatekeeper-cpp: JSON-lines front end for the C++ policy check.
//   gatekeeper-cpp --policy policy.json            read requests on stdin, one JSON object per line
//   gatekeeper-cpp --policy policies.json --bench cases.jsonl [--iters N]
// Request:  {"id":1,"sql":"...","role":"scoped_write","known":["accounts"]|null,"policy":"default"}
// Response: {"id":1,"allowed":false,"rule_id":"NO_WHERE","reason":"...","is_write":true,"is_ddl":false,"tables":[...]}
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#include "json.hpp"
#include "policy.hpp"

namespace {

using gk::json::Value;

std::map<std::string, gk::Policy> load_policies(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open policy file " + path);
    std::stringstream ss;
    ss << in.rdbuf();
    Value v = gk::json::parse(ss.str());
    std::map<std::string, gk::Policy> out;
    if (v.find("roles")) {
        out.emplace("default", gk::Policy::from_json(v));
    } else {
        for (const auto& [name, pv] : v.as_object()) out.emplace(name, gk::Policy::from_json(pv));
    }
    return out;
}

struct Request {
    Value id;
    std::string sql;
    std::string role;
    std::string policy = "default";
    std::optional<std::set<std::string>> known;
};

Request parse_request(const std::string& line) {
    Value v = gk::json::parse(line);
    Request r;
    if (const auto* id = v.find("id")) r.id = *id;
    r.sql = v.find("sql")->as_string();
    r.role = v.find("role")->as_string();
    if (const auto* p = v.find("policy"); p && p->is_string()) r.policy = p->as_string();
    if (const auto* k = v.find("known"); k && k->is_array()) {
        std::set<std::string> s;
        for (const auto& e : k->as_array()) s.insert(e.as_string());
        r.known = std::move(s);
    }
    return r;
}

gk::PolicyResult run(const Request& r, const std::map<std::string, gk::Policy>& policies) {
    const gk::Policy& p = policies.at(r.policy);
    return gk::check(r.sql, p, p.roles.at(r.role), r.known);
}

std::string render(const Request& r, const gk::PolicyResult& res) {
    gk::json::Object o;
    o["id"] = r.id;
    o["allowed"] = res.allowed;
    o["rule_id"] = res.rule_id ? Value(*res.rule_id) : Value(nullptr);
    o["reason"] = res.reason;
    o["is_write"] = res.is_write;
    o["is_ddl"] = res.is_ddl;
    gk::json::Array t;
    for (const auto& s : res.tables) t.emplace_back(s);
    o["tables"] = std::move(t);
    return gk::json::dump(Value(std::move(o)));
}

int bench(const std::map<std::string, gk::Policy>& policies, const std::string& path, int iters) {
    std::ifstream in(path);
    std::vector<Request> cases;
    for (std::string line; std::getline(in, line);)
        if (!line.empty()) cases.push_back(parse_request(line));
    if (cases.empty()) return 2;
    volatile size_t sink = 0;
    for (const auto& c : cases) sink += run(c, policies).tables.size();  // warm-up
    std::vector<double> ns;
    ns.reserve(cases.size() * static_cast<size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        for (const auto& c : cases) {
            auto t0 = std::chrono::steady_clock::now();
            auto res = run(c, policies);
            auto t1 = std::chrono::steady_clock::now();
            sink += res.tables.size();
            ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
        }
    }
    std::sort(ns.begin(), ns.end());
    double sum = 0;
    for (double x : ns) sum += x;
    auto q = [&](double p) { return ns[std::min(ns.size() - 1, static_cast<size_t>(p * static_cast<double>(ns.size())))]; };
    std::printf("{\"cases\":%zu,\"iters\":%d,\"n\":%zu,\"median_ns\":%.0f,\"p99_ns\":%.0f,\"mean_ns\":%.0f}\n", cases.size(), iters,
                ns.size(), q(0.5), q(0.99), sum / static_cast<double>(ns.size()));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::string policy_path, bench_path;
    int iters = 200;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--policy" && i + 1 < argc) policy_path = argv[++i];
        else if (a == "--bench" && i + 1 < argc) bench_path = argv[++i];
        else if (a == "--iters" && i + 1 < argc) iters = std::stoi(argv[++i]);
        else {
            std::fprintf(stderr, "usage: gatekeeper-cpp --policy FILE [--bench CASES.jsonl [--iters N]]\n");
            return 2;
        }
    }
    if (policy_path.empty()) {
        std::fprintf(stderr, "--policy is required\n");
        return 2;
    }
    try {
        const auto policies = load_policies(policy_path);
        if (!bench_path.empty()) return bench(policies, bench_path, iters);
        std::ios::sync_with_stdio(false);
        for (std::string line; std::getline(std::cin, line);) {
            if (line.empty()) continue;
            Request r = parse_request(line);
            std::cout << render(r, run(r, policies)) << '\n' << std::flush;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}
