// Minimal JSON value, parser and writer (RFC 8259 subset: no comments, UTF-8 pass-through).
#pragma once
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace gk::json {

struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

struct Value {
    std::variant<std::nullptr_t, bool, double, std::string, Array, Object> v{nullptr};
    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool b) : v(b) {}
    Value(double d) : v(d) {}
    Value(int i) : v(static_cast<double>(i)) {}
    Value(std::string s) : v(std::move(s)) {}
    Value(const char* s) : v(std::string(s)) {}
    Value(Array a) : v(std::move(a)) {}
    Value(Object o) : v(std::move(o)) {}

    bool is_null() const { return std::holds_alternative<std::nullptr_t>(v); }
    bool is_string() const { return std::holds_alternative<std::string>(v); }
    bool is_array() const { return std::holds_alternative<Array>(v); }
    bool is_object() const { return std::holds_alternative<Object>(v); }
    bool as_bool() const { return std::get<bool>(v); }
    double as_number() const { return std::get<double>(v); }
    const std::string& as_string() const { return std::get<std::string>(v); }
    const Array& as_array() const { return std::get<Array>(v); }
    const Object& as_object() const { return std::get<Object>(v); }
    const Value* find(const std::string& k) const {
        if (!is_object()) return nullptr;
        const auto& o = as_object();
        auto it = o.find(k);
        return it == o.end() ? nullptr : &it->second;
    }
};

class ParseError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

namespace detail {
struct Parser {
    const std::string& s;
    size_t i = 0;
    explicit Parser(const std::string& text) : s(text) {}
    [[noreturn]] void fail(const char* m) const {
        throw ParseError(std::string("json: ") + m + " at " + std::to_string(i));
    }
    char peek() const {
        if (i >= s.size()) fail("unexpected end");
        return s[i];
    }
    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
    }
    static void put_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    uint32_t hex4() {
        if (i + 4 > s.size()) fail("short \\u escape");
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else fail("bad hex digit");
        }
        return v;
    }
    std::string str() {
        if (peek() != '"') fail("expected string");
        ++i;
        std::string out;
        while (true) {
            if (i >= s.size()) fail("unterminated string");
            char c = s[i++];
            if (c == '"') return out;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i >= s.size()) fail("bad escape");
            char e = s[i++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                        i += 2;
                        uint32_t lo = hex4();
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    put_utf8(out, cp);
                    break;
                }
                default: fail("bad escape");
            }
        }
    }
    Value value() {
        ws();
        char c = peek();
        if (c == '{') {
            ++i;
            Object o;
            ws();
            if (peek() == '}') {
                ++i;
                return Value(std::move(o));
            }
            while (true) {
                ws();
                std::string k = str();
                ws();
                if (peek() != ':') fail("expected ':'");
                ++i;
                o.emplace(std::move(k), value());
                ws();
                char d = peek();
                ++i;
                if (d == '}') return Value(std::move(o));
                if (d != ',') fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++i;
            Array a;
            ws();
            if (peek() == ']') {
                ++i;
                return Value(std::move(a));
            }
            while (true) {
                a.push_back(value());
                ws();
                char d = peek();
                ++i;
                if (d == ']') return Value(std::move(a));
                if (d != ',') fail("expected ',' or ']'");
            }
        }
        if (c == '"') return Value(str());
        if (s.compare(i, 4, "true") == 0) { i += 4; return Value(true); }
        if (s.compare(i, 5, "false") == 0) { i += 5; return Value(false); }
        if (s.compare(i, 4, "null") == 0) { i += 4; return Value(nullptr); }
        size_t start = i;
        while (i < s.size() && std::string_view("+-0123456789.eE").find(s[i]) != std::string_view::npos) ++i;
        if (start == i) fail("unexpected character");
        return Value(std::stod(s.substr(start, i - start)));
    }
};
}  // namespace detail

inline Value parse(const std::string& text) {
    detail::Parser p(text);
    Value v = p.value();
    p.ws();
    if (p.i != text.size()) p.fail("trailing data");
    return v;
}

inline void write_string(std::string& out, const std::string& s) {
    static const char* hex = "0123456789abcdef";
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

inline void write(std::string& out, const Value& v) {
    if (v.is_null()) {
        out += "null";
    } else if (std::holds_alternative<bool>(v.v)) {
        out += v.as_bool() ? "true" : "false";
    } else if (std::holds_alternative<double>(v.v)) {
        out += std::to_string(static_cast<long long>(v.as_number()));
    } else if (v.is_string()) {
        write_string(out, v.as_string());
    } else if (v.is_array()) {
        out += '[';
        bool first = true;
        for (const auto& e : v.as_array()) {
            if (!first) out += ',';
            first = false;
            write(out, e);
        }
        out += ']';
    } else {
        out += '{';
        bool first = true;
        for (const auto& [k, e] : v.as_object()) {
            if (!first) out += ',';
            first = false;
            write_string(out, k);
            out += ':';
            write(out, e);
        }
        out += '}';
    }
}

inline std::string dump(const Value& v) {
    std::string s;
    write(s, v);
    return s;
}

}  // namespace gk::json
