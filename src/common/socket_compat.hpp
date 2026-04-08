#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
using ssize_t = SSIZE_T;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace finalis::net {

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

inline bool ensure_sockets() {
#ifdef _WIN32
  static const bool initialized = []() {
    WSADATA wsa{};
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  }();
  return initialized;
#else
  return true;
#endif
}

inline bool valid_socket(SocketHandle fd) { return fd != kInvalidSocket; }

inline int socket_last_error() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

inline std::string socket_error_string(int err) {
#ifdef _WIN32
  char* message = nullptr;
  const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  const DWORD len = FormatMessageA(flags, nullptr, static_cast<DWORD>(err), 0, reinterpret_cast<LPSTR>(&message), 0, nullptr);
  std::string out = len != 0 && message != nullptr ? std::string(message, len) : ("winsock-error-" + std::to_string(err));
  if (message) LocalFree(message);
  while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' ')) out.pop_back();
  return out;
#else
  return std::strerror(err);
#endif
}

inline bool close_socket(SocketHandle fd) {
#ifdef _WIN32
  return !valid_socket(fd) || ::closesocket(fd) == 0;
#else
  return !valid_socket(fd) || ::close(fd) == 0;
#endif
}

inline bool shutdown_socket(SocketHandle fd) {
#ifdef _WIN32
  return !valid_socket(fd) || ::shutdown(fd, SD_BOTH) == 0;
#else
  return !valid_socket(fd) || ::shutdown(fd, SHUT_RDWR) == 0;
#endif
}

inline void set_close_on_exec(SocketHandle fd) {
#ifdef _WIN32
  (void)fd;
#else
  if (!valid_socket(fd)) return;
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0) return;
  (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
#endif
}

inline bool set_nonblocking(SocketHandle fd, bool enabled) {
#ifdef _WIN32
  u_long mode = enabled ? 1UL : 0UL;
  return ::ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  const int desired = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  return ::fcntl(fd, F_SETFL, desired) == 0;
#endif
}

inline bool set_reuseaddr(SocketHandle fd) {
  int one = 1;
#ifdef _WIN32
  return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one)) == 0;
#else
  return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0;
#endif
}

inline bool set_socket_timeouts(SocketHandle fd, std::uint32_t timeout_ms) {
#ifdef _WIN32
  const DWORD tv = timeout_ms;
  const bool recv_ok = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
  const bool send_ok = ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
  return recv_ok && send_ok;
#else
  timeval tv{};
  tv.tv_sec = static_cast<time_t>(timeout_ms / 1000U);
  tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000U) * 1000U);
  const bool recv_ok = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
  const bool send_ok = ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
  return recv_ok && send_ok;
#endif
}

inline bool wait_readable(SocketHandle fd, std::uint32_t timeout_ms) {
#ifdef _WIN32
  WSAPOLLFD pfd{};
  pfd.fd = fd;
  pfd.events = POLLRDNORM;
  const int rc = ::WSAPoll(&pfd, 1, static_cast<INT>(timeout_ms));
  if (rc <= 0) return false;
  return (pfd.revents & (POLLRDNORM | POLLERR | POLLHUP | POLLNVAL)) != 0;
#else
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  const int rc = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (rc <= 0) return false;
  return (pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
#endif
}

inline bool wait_writable(SocketHandle fd, std::uint32_t timeout_ms) {
#ifdef _WIN32
  WSAPOLLFD pfd{};
  pfd.fd = fd;
  pfd.events = POLLWRNORM;
  const int rc = ::WSAPoll(&pfd, 1, static_cast<INT>(timeout_ms));
  if (rc <= 0) return false;
  return (pfd.revents & (POLLWRNORM | POLLERR | POLLHUP | POLLNVAL)) != 0;
#else
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLOUT;
  const int rc = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (rc <= 0) return false;
  return (pfd.revents & (POLLOUT | POLLHUP | POLLERR | POLLNVAL)) != 0;
#endif
}

inline ssize_t recv_nonblocking(SocketHandle fd, void* buf, std::size_t len) {
#ifdef _WIN32
  if (!set_nonblocking(fd, true)) return -1;
  const int rc = ::recv(fd, static_cast<char*>(buf), static_cast<int>(len), 0);
  (void)set_nonblocking(fd, false);
  return static_cast<ssize_t>(rc);
#else
  return ::recv(fd, buf, len, MSG_DONTWAIT);
#endif
}

}  // namespace finalis::net
