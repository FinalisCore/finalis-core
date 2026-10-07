// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <map>

using TestFn = std::function<void()>;
std::vector<std::pair<std::string, TestFn>>& tests();
// Test name -> comma-separated labels (e.g. "soak,asan-slow"); see TEST_TAGS.
std::map<std::string, std::string>& test_tags();

struct Reg {
  Reg(const std::string& n, TestFn fn);
};

struct RegTags {
  RegTags(const std::string& n, const std::string& tags);
};

#define TEST(name) \
  void name(); \
  static Reg reg_##name(#name, name); \
  void name()

// Labels a test for ctest discovery (`--list-tags`). Place at file scope, before or after the TEST.
#define TEST_TAGS(name, tags) static RegTags regtags_##name(#name, tags)

#define ASSERT_TRUE(x) \
  do { if (!(x)) throw std::runtime_error(std::string("assert failed: ") + #x); } while (0)

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))
