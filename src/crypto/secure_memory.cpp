// SPDX-License-Identifier: MIT

#include "crypto/secure_memory.hpp"

#include <climits>

#include <openssl/rand.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace finalis::crypto {

bool secure_random_bytes(void* p, std::size_t n) {
  if (n == 0) return true;
  if (p == nullptr || n > static_cast<std::size_t>(INT_MAX)) return false;
  return RAND_bytes(static_cast<unsigned char*>(p), static_cast<int>(n)) == 1;
}

bool lock_memory(const void* p, std::size_t n) {
  if (p == nullptr || n == 0) return false;
#ifdef _WIN32
  return VirtualLock(const_cast<void*>(p), n) != 0;
#else
  return ::mlock(p, n) == 0;
#endif
}

void unlock_memory(const void* p, std::size_t n) {
  if (p == nullptr || n == 0) return;
#ifdef _WIN32
  (void)VirtualUnlock(const_cast<void*>(p), n);
#else
  (void)::munlock(p, n);
#endif
}

}  // namespace finalis::crypto
