// SPDX-License-Identifier: MIT

#pragma once

#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace finalis::minijson {

struct Value {
  enum class Type {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
  };

  using Array = std::vector<Value>;
  using Object = std::map<std::string, Value>;

  Type type{Type::Null};
  bool bool_value{false};
  std::string string_value;
  Array array_value;
  Object object_value;

  bool is_null() const { return type == Type::Null; }
  bool is_bool() const { return type == Type::Bool; }
  bool is_number() const { return type == Type::Number; }
  bool is_string() const { return type == Type::String; }
  bool is_array() const { return type == Type::Array; }
  bool is_object() const { return type == Type::Object; }

  const Value* get(std::string_view key) const {
    if (!is_object()) return nullptr;
    auto it = object_value.find(std::string(key));
    return it == object_value.end() ? nullptr : &it->second;
  }

  std::optional<std::string> as_string() const {
    if (!is_string()) return std::nullopt;
    return string_value;
  }

  std::optional<bool> as_bool() const {
    if (!is_bool()) return std::nullopt;
    return bool_value;
  }

  std::optional<std::uint64_t> as_u64() const {
    if (!is_number() || string_value.empty()) return std::nullopt;
    std::uint64_t out = 0;
    for (char ch : string_value) {
      if (ch < '0' || ch > '9') return std::nullopt;
      const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
      if (out > (UINT64_MAX - digit) / 10) return std::nullopt;
      out = out * 10 + digit;
    }
    return out;
  }
};

namespace detail {

inline void append_utf8(std::string& out, std::uint32_t cp) {
  if (cp <= 0x7F) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

class Parser {
 public:
  explicit Parser(std::string_view input) : input_(input) {}

  std::optional<Value> parse() {
    skip_ws();
    auto value = parse_value();
    if (!value.has_value()) return std::nullopt;
    skip_ws();
    if (pos_ != input_.size()) return std::nullopt;
    return value;
  }

 private:
  std::string_view input_;
  std::size_t pos_{0};

  void skip_ws() {
    while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_]))) ++pos_;
  }

  bool consume(char ch) {
    if (pos_ >= input_.size() || input_[pos_] != ch) return false;
    ++pos_;
    return true;
  }

  std::optional<Value> parse_value() {
    skip_ws();
    if (pos_ >= input_.size()) return std::nullopt;
    switch (input_[pos_]) {
      case 'n':
        return parse_null();
      case 't':
      case 'f':
        return parse_bool();
      case '"':
        return parse_string_value();
      case '[':
        return parse_array();
      case '{':
        return parse_object();
      default:
        if (input_[pos_] == '-' || std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
          return parse_number();
        }
        return std::nullopt;
    }
  }

  std::optional<Value> parse_null() {
    if (input_.substr(pos_, 4) != "null") return std::nullopt;
    pos_ += 4;
    return Value{};
  }

  std::optional<Value> parse_bool() {
    Value out;
    out.type = Value::Type::Bool;
    if (input_.substr(pos_, 4) == "true") {
      out.bool_value = true;
      pos_ += 4;
      return out;
    }
    if (input_.substr(pos_, 5) == "false") {
      out.bool_value = false;
      pos_ += 5;
      return out;
    }
    return std::nullopt;
  }

  std::optional<std::string> parse_string() {
    if (!consume('"')) return std::nullopt;
    std::string out;
    while (pos_ < input_.size()) {
      const char ch = input_[pos_++];
      if (ch == '"') return out;
      if (ch == '\\') {
        if (pos_ >= input_.size()) return std::nullopt;
        const char esc = input_[pos_++];
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out.push_back(esc);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            if (pos_ + 4 > input_.size()) return std::nullopt;
            std::uint32_t cp = 0;
            for (int i = 0; i < 4; ++i) {
              const char hex = input_[pos_++];
              cp <<= 4;
              if (hex >= '0' && hex <= '9') cp |= static_cast<std::uint32_t>(hex - '0');
              else if (hex >= 'a' && hex <= 'f') cp |= static_cast<std::uint32_t>(10 + hex - 'a');
              else if (hex >= 'A' && hex <= 'F') cp |= static_cast<std::uint32_t>(10 + hex - 'A');
              else return std::nullopt;
            }
            append_utf8(out, cp);
            break;
          }
          default:
            return std::nullopt;
        }
        continue;
      }
      if (static_cast<unsigned char>(ch) < 0x20) return std::nullopt;
      out.push_back(ch);
    }
    return std::nullopt;
  }

  std::optional<Value> parse_string_value() {
    auto s = parse_string();
    if (!s.has_value()) return std::nullopt;
    Value out;
    out.type = Value::Type::String;
    out.string_value = std::move(*s);
    return out;
  }

  std::optional<Value> parse_number() {
    const std::size_t start = pos_;
    if (input_[pos_] == '-') ++pos_;
    if (pos_ >= input_.size()) return std::nullopt;
    if (input_[pos_] == '0') {
      ++pos_;
    } else {
      if (!std::isdigit(static_cast<unsigned char>(input_[pos_]))) return std::nullopt;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }
    if (pos_ < input_.size() && input_[pos_] == '.') {
      ++pos_;
      if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) return std::nullopt;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }
    if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
      if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) return std::nullopt;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }
    Value out;
    out.type = Value::Type::Number;
    out.string_value = std::string(input_.substr(start, pos_ - start));
    return out;
  }

  std::optional<Value> parse_array() {
    if (!consume('[')) return std::nullopt;
    Value out;
    out.type = Value::Type::Array;
    skip_ws();
    if (consume(']')) return out;
    while (true) {
      auto item = parse_value();
      if (!item.has_value()) return std::nullopt;
      out.array_value.push_back(std::move(*item));
      skip_ws();
      if (consume(']')) return out;
      if (!consume(',')) return std::nullopt;
    }
  }

  std::optional<Value> parse_object() {
    if (!consume('{')) return std::nullopt;
    Value out;
    out.type = Value::Type::Object;
    skip_ws();
    if (consume('}')) return out;
    while (true) {
      auto key = parse_string();
      if (!key.has_value()) return std::nullopt;
      skip_ws();
      if (!consume(':')) return std::nullopt;
      auto value = parse_value();
      if (!value.has_value()) return std::nullopt;
      out.object_value.emplace(std::move(*key), std::move(*value));
      skip_ws();
      if (consume('}')) return out;
      if (!consume(',')) return std::nullopt;
      skip_ws();
    }
  }
};

inline std::string escape(const std::string& input) {
  std::string out;
  out.reserve(input.size() + 8);
  for (char ch : input) {
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

}  // namespace detail

inline std::optional<Value> parse(std::string_view input) {
  return detail::Parser(input).parse();
}

inline std::string stringify(const Value& value) {
  switch (value.type) {
    case Value::Type::Null:
      return "null";
    case Value::Type::Bool:
      return value.bool_value ? "true" : "false";
    case Value::Type::Number:
      return value.string_value;
    case Value::Type::String:
      return "\"" + detail::escape(value.string_value) + "\"";
    case Value::Type::Array: {
      std::string out = "[";
      for (std::size_t i = 0; i < value.array_value.size(); ++i) {
        if (i) out += ",";
        out += stringify(value.array_value[i]);
      }
      out += "]";
      return out;
    }
    case Value::Type::Object: {
      std::string out = "{";
      bool first = true;
      for (const auto& [key, item] : value.object_value) {
        if (!first) out += ",";
        first = false;
        out += "\"" + detail::escape(key) + "\":" + stringify(item);
      }
      out += "}";
      return out;
    }
  }
  return "null";
}

}  // namespace finalis::minijson
