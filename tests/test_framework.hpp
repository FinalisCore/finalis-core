#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using TestFn = std::function<void()>;
std::vector<std::pair<std::string, TestFn>>& tests();

struct Reg {
  Reg(const std::string& n, TestFn fn);
};

#define TEST(name) \
  void name(); \
  static Reg reg_##name(#name, name); \
  void name()

#define ASSERT_TRUE(x) \
  do { if (!(x)) throw std::runtime_error(std::string("assert failed: ") + #x); } while (0)

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
