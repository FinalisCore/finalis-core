// SPDX-License-Identifier: MIT

#pragma once

// Qt 5.15.2 headers call stdext::make_(un)checked_array_iterator on MSVC; the MSVC STL removed
// them in VS 18 (_MSC_VER 1950). Force-included into Qt consumers; plain pointers are equivalent.
#if defined(_MSC_VER) && !defined(__clang__) && _MSC_VER >= 1950
#include <cstddef>

namespace stdext {
template <class T>
constexpr T* make_checked_array_iterator(T* p, std::size_t) noexcept {
  return p;
}
template <class T>
constexpr T* make_unchecked_array_iterator(T* p) noexcept {
  return p;
}
}  // namespace stdext
#endif
