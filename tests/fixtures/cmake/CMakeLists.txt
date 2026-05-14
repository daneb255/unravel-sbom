cmake_minimum_required(VERSION 3.16)
project(my_cpp_project VERSION 1.5.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

# Version pins set via variables (find_package fallback)
set(OPENSSL_VERSION 3.1.2)
set(Boost_VERSION 1.83.0)

# ── find_package ──────────────────────────────────────────────────────────────
find_package(OpenSSL ${OPENSSL_VERSION} REQUIRED)
find_package(Boost 1.83.0 COMPONENTS system filesystem REQUIRED)
find_package(Threads REQUIRED)   # built-in, must be skipped
find_package(Git QUIET)          # built-in, must be skipped
find_package(GTest REQUIRED)

# ── FetchContent with GIT_TAG ─────────────────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        12.1.0
)

FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio
  GIT_TAG        asio-1-30-2
)

FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11
  GIT_TAG        v3.0.1
)

FetchContent_Declare(
  CLI11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG        v2.4.1
)

FetchContent_Declare(
  websocketpp
  GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
  GIT_TAG        0.8.2
)

FetchContent_Declare(
  tinyxml2
  GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
  GIT_TAG        v10.0.0
)

FetchContent_Declare(
  cpp-httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.18.0
)

# ── FetchContent with VERSION keyword ────────────────────────────────────────
FetchContent_Declare(
  nlohmann_json
  URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  VERSION  3.11.3
)

# ── ExternalProject_Add ───────────────────────────────────────────────────────
include(ExternalProject)

ExternalProject_Add(
  libsodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG        1.0.20
)

# ── CPM_AddPackage ────────────────────────────────────────────────────────────
CPM_AddPackage(
  NAME spdlog
  VERSION 1.13.0
  GITHUB_REPOSITORY gabime/spdlog
)

CPM_AddPackage(
  NAME zlib
  GIT_TAG v1.3.1
  GITHUB_REPOSITORY madler/zlib
)

add_subdirectory(third-party)
add_subdirectory(modules)
