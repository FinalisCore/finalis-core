cmake_minimum_required(VERSION 3.20)
project(finalis_core LANGUAGES CXX)

include(GNUInstallDirs)
if(WIN32)
  set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION ${CMAKE_INSTALL_BINDIR})
  set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
  include(InstallRequiredSystemLibraries)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
option(FINALIS_SANITIZE "Enable ASan/UBSan instrumentation" OFF)
option(FINALIS_BUILD_FUZZ "Build fuzz harness executables" ON)
option(FINALIS_STRICT_WARNINGS "Enable strict warning flags" OFF)
option(FINALIS_USE_VENDORED_SECP256K1_ZKP "Prefer vendored secp256k1-zkp when available." ON)

find_package(OpenSSL REQUIRED)
find_package(Qt5 COMPONENTS Widgets QUIET)
find_package(ZLIB QUIET)

# Optional libs: RocksDB and libsodium. Build falls back gracefully if unavailable.
find_library(SODIUM_LIB sodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)
if(SODIUM_LIB AND SODIUM_INCLUDE_DIR)
  message(STATUS "Using libsodium")
  add_compile_definitions(SC_HAS_LIBSODIUM=1)
endif()

set(FINALIS_SECP256K1_TARGET "")
set(FINALIS_SECP256K1_INCLUDE_DIR "")
set(FINALIS_USE_SECP256K1_ZKP_BACKEND OFF)

if(FINALIS_USE_VENDORED_SECP256K1_ZKP AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1-zkp/CMakeLists.txt")
  message(STATUS "Using vendored secp256k1-zkp")
  set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_GENERATOR ON CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_RANGEPROOF ON CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_SURJECTIONPROOF OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_WHITELIST OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_ECDSA_ADAPTOR OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_ECDSA_S2C OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_BPPP OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_SCHNORRSIG_HALFAGG OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/secp256k1-zkp EXCLUDE_FROM_ALL)
  set(FINALIS_SECP256K1_TARGET secp256k1)
  set(FINALIS_SECP256K1_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1-zkp/include")
  set(FINALIS_USE_SECP256K1_ZKP_BACKEND ON)
  add_compile_definitions(SC_HAS_SECP256K1=1 SC_HAS_SECP256K1_ZKP=1)
else()
  find_library(SECP256K1_LIB secp256k1)
  find_path(SECP256K1_INCLUDE_DIR secp256k1.h)
  if(SECP256K1_LIB AND SECP256K1_INCLUDE_DIR)
    message(STATUS "Using libsecp256k1")
    add_compile_definitions(SC_HAS_SECP256K1=1)
    set(FINALIS_SECP256K1_INCLUDE_DIR "${SECP256K1_INCLUDE_DIR}")
  endif()
  find_path(SECP256K1_ZKP_INCLUDE_DIR
    NAMES
      secp256k1_rangeproof.h
    PATHS
      ${SECP256K1_INCLUDE_DIR}
      /usr/local/include
      /usr/include
  )
  if(SECP256K1_LIB AND SECP256K1_ZKP_INCLUDE_DIR
     AND EXISTS "${SECP256K1_ZKP_INCLUDE_DIR}/secp256k1_generator.h"
     AND EXISTS "${SECP256K1_ZKP_INCLUDE_DIR}/secp256k1_extrakeys.h"
     AND EXISTS "${SECP256K1_ZKP_INCLUDE_DIR}/secp256k1_schnorrsig.h")
    message(STATUS "Using system secp256k1-zkp headers")
    add_compile_definitions(SC_HAS_SECP256K1_ZKP=1)
    set(FINALIS_USE_SECP256K1_ZKP_BACKEND ON)
  endif()
endif()

find_library(ROCKSDB_LIB rocksdb)
find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)
if(ROCKSDB_LIB AND ROCKSDB_INCLUDE_DIR)
  message(STATUS "Using RocksDB")
  add_compile_definitions(SC_HAS_ROCKSDB=1)
endif()

add_library(finalis_core
  src/common/types.cpp
  src/common/network.cpp
  src/common/chain_id.cpp
  src/common/paths.cpp
  src/codec/bytes.cpp
  src/codec/varint.cpp
  src/crypto/hash.cpp
  src/crypto/ed25519.cpp
  src/crypto/smt.cpp
  src/crypto/confidential.cpp
  src/crypto/stealth_address.cpp
  src/keystore/validator_keystore.cpp
  src/onboarding/validator_onboarding.cpp
  src/genesis/genesis.cpp
  src/genesis/embedded_mainnet.cpp
  src/merkle/merkle.cpp
  src/address/address.cpp
  src/availability/retention.cpp
  src/privacy/mint_client.cpp
  src/privacy/mint_scripts.cpp
  src/wallet/utxo_selection.cpp
  src/wallet/confidential_builder.cpp
  src/utxo/tx.cpp
  src/utxo/confidential_tx.cpp
  src/utxo/validate.cpp
  src/utxo/signing.cpp
  src/policy/hashcash.cpp
  src/mempool/mempool.cpp
  src/consensus/monetary.cpp
  src/consensus/committee_schedule.cpp
  src/consensus/canonical_derivation.cpp
  src/consensus/frontier_execution.cpp
  src/consensus/ingress.cpp
  src/consensus/epoch_tickets.cpp
  src/consensus/epoch_committee.cpp
  src/consensus/randomness.cpp
  src/consensus/state_commitment.cpp
  src/consensus/validator_registry.cpp
  src/consensus/finalized_committee.cpp
  src/consensus/votes.cpp
  src/storage/db.cpp
  src/storage/snapshot.cpp
  src/p2p/framing.cpp
  src/p2p/addrman.cpp
  src/p2p/hardening.cpp
  src/p2p/messages.cpp
  src/p2p/peer_manager.cpp
  src/node/node.cpp
  src/lightserver/client.cpp
  src/lightserver/server.cpp
)

target_include_directories(finalis_core PUBLIC src)
target_link_libraries(finalis_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if(SODIUM_LIB AND SODIUM_INCLUDE_DIR)
  target_include_directories(finalis_core PUBLIC ${SODIUM_INCLUDE_DIR})
  target_link_libraries(finalis_core PUBLIC ${SODIUM_LIB})
endif()
if(FINALIS_SECP256K1_INCLUDE_DIR)
  target_include_directories(finalis_core PUBLIC ${FINALIS_SECP256K1_INCLUDE_DIR})
endif()
if(FINALIS_SECP256K1_TARGET)
  target_link_libraries(finalis_core PUBLIC ${FINALIS_SECP256K1_TARGET})
elseif(SECP256K1_LIB AND SECP256K1_INCLUDE_DIR)
  target_link_libraries(finalis_core PUBLIC ${SECP256K1_LIB})
endif()
if(ROCKSDB_LIB AND ROCKSDB_INCLUDE_DIR)
  target_include_directories(finalis_core PUBLIC ${ROCKSDB_INCLUDE_DIR})
  target_link_libraries(finalis_core PUBLIC ${ROCKSDB_LIB})
endif()
if(ZLIB_FOUND)
  target_link_libraries(finalis_core PUBLIC ZLIB::ZLIB)
endif()
if(WIN32)
  target_link_libraries(finalis_core PUBLIC ws2_32 rpcrt4 shlwapi)
endif()

if(FINALIS_STRICT_WARNINGS)
  target_compile_options(finalis_core PRIVATE -Wall -Wextra -Wpedantic)
endif()
set(SC_SAN_FLAGS "")
if(FINALIS_SANITIZE)
  set(SC_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_compile_options(finalis_core PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis_core PRIVATE -fsanitize=address,undefined)
endif()

add_executable(finalis-node apps/finalis-node/main.cpp)
target_link_libraries(finalis-node PRIVATE finalis_core)
if(FINALIS_SANITIZE)
  target_compile_options(finalis-node PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis-node PRIVATE -fsanitize=address,undefined)
endif()
install(TARGETS finalis-node
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(finalis-cli apps/finalis-cli/main.cpp)
target_link_libraries(finalis-cli PRIVATE finalis_core)
if(FINALIS_SANITIZE)
  target_compile_options(finalis-cli PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis-cli PRIVATE -fsanitize=address,undefined)
endif()
install(TARGETS finalis-cli
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(finalis-lightserver apps/finalis-lightserver/main.cpp)
target_link_libraries(finalis-lightserver PRIVATE finalis_core)
if(FINALIS_SANITIZE)
  target_compile_options(finalis-lightserver PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis-lightserver PRIVATE -fsanitize=address,undefined)
endif()
install(TARGETS finalis-lightserver
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(checkpoint-fixture-export tools/checkpoint_fixture_export.cpp)
target_link_libraries(checkpoint-fixture-export PRIVATE finalis_core)
if(FINALIS_SANITIZE)
  target_compile_options(checkpoint-fixture-export PRIVATE ${SC_SAN_FLAGS})
  target_link_options(checkpoint-fixture-export PRIVATE -fsanitize=address,undefined)
endif()

add_executable(finalis-explorer apps/finalis-explorer/main.cpp)
target_link_libraries(finalis-explorer PRIVATE finalis_core)
if(FINALIS_SANITIZE)
  target_compile_options(finalis-explorer PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis-explorer PRIVATE -fsanitize=address,undefined)
endif()
install(TARGETS finalis-explorer
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(Qt5Widgets_FOUND)
  add_executable(finalis-wallet
    apps/finalis-wallet/main.cpp
    apps/finalis-wallet/history_merge.cpp
    apps/finalis-wallet/refresh_gate.cpp
    apps/finalis-wallet/wallet_window.cpp
    apps/finalis-wallet/wallet_store.cpp
    apps/finalis-wallet/widgets/activity_page.cpp
    apps/finalis-wallet/widgets/advanced_page.cpp
    apps/finalis-wallet/widgets/overview_page.cpp
    apps/finalis-wallet/widgets/receive_page.cpp
    apps/finalis-wallet/widgets/send_page.cpp
    apps/finalis-wallet/widgets/settings_page.cpp
    apps/finalis-wallet/resources.qrc
  )
  target_link_libraries(finalis-wallet PRIVATE finalis_core Qt5::Widgets)
  if(FINALIS_SANITIZE)
    target_compile_options(finalis-wallet PRIVATE ${SC_SAN_FLAGS})
    target_link_options(finalis-wallet PRIVATE -fsanitize=address,undefined)
  endif()

  set(FINALIS_WALLET_DESKTOP_DIR "${CMAKE_INSTALL_DATAROOTDIR}/applications")
  set(FINALIS_WALLET_DOC_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/finalis-wallet")
  set(FINALIS_WALLET_ICON_DIR "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/finalis-wallet.desktop.in
    ${CMAKE_CURRENT_BINARY_DIR}/finalis-wallet.desktop
    @ONLY
  )

  install(TARGETS finalis-wallet
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/finalis-wallet.desktop
    DESTINATION ${FINALIS_WALLET_DESKTOP_DIR}
  )
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/finalis-wallet.svg
    DESTINATION ${FINALIS_WALLET_ICON_DIR}
    RENAME finalis-wallet.svg
  )
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/apps/finalis-wallet/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/LIVE_PROTOCOL.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/ADDRESSES.md
    DESTINATION ${FINALIS_WALLET_DOC_DIR}
  )

  add_executable(finalis-wallet-widget-tests
    tests/test_wallet_widgets.cpp
    apps/finalis-wallet/history_merge.cpp
    apps/finalis-wallet/refresh_gate.cpp
    apps/finalis-wallet/wallet_window.cpp
    apps/finalis-wallet/wallet_store.cpp
    apps/finalis-wallet/widgets/activity_page.cpp
    apps/finalis-wallet/widgets/advanced_page.cpp
    apps/finalis-wallet/widgets/overview_page.cpp
    apps/finalis-wallet/widgets/receive_page.cpp
    apps/finalis-wallet/widgets/send_page.cpp
    apps/finalis-wallet/widgets/settings_page.cpp
    apps/finalis-wallet/resources.qrc
  )
  target_link_libraries(finalis-wallet-widget-tests PRIVATE finalis_core Qt5::Widgets)
  target_include_directories(finalis-wallet-widget-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  if(FINALIS_SANITIZE)
    target_compile_options(finalis-wallet-widget-tests PRIVATE ${SC_SAN_FLAGS})
    target_link_options(finalis-wallet-widget-tests PRIVATE -fsanitize=address,undefined)
  endif()
else()
  message(STATUS "Qt5 Widgets not found; skipping finalis-wallet target")
endif()

set(FINALIS_INSTALL_DOC_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/finalis-core")
install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/README.md
  ${CMAKE_CURRENT_SOURCE_DIR}/apps/finalis-explorer/README.md
  ${CMAKE_CURRENT_SOURCE_DIR}/apps/finalis-wallet/README.md
  ${CMAKE_CURRENT_SOURCE_DIR}/docs/LIVE_PROTOCOL.md
  ${CMAKE_CURRENT_SOURCE_DIR}/docs/ADDRESSES.md
  DESTINATION ${FINALIS_INSTALL_DOC_DIR}
)
install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/branding/finalis-app-icon.png
  ${CMAKE_CURRENT_SOURCE_DIR}/branding/finalis-logo-horizontal.png
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/finalis-core/branding
)
if(WIN32 AND CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
  install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
endif()

add_executable(finalis-tests
  apps/finalis-wallet/history_merge.cpp
  apps/finalis-wallet/refresh_gate.cpp
  apps/finalis-wallet/wallet_store.cpp
  tests/test_main.cpp
  tests/test_codec.cpp
  tests/test_chain_id.cpp
  tests/test_crypto.cpp
  tests/test_confidential_tx.cpp
  tests/test_address.cpp
  tests/test_p2p.cpp
  tests/test_addrman.cpp
  tests/test_monetary.cpp
  tests/test_committee_schedule.cpp
  tests/test_state_commitment.cpp
  tests/test_smt.cpp
  tests/test_bonding.cpp
  tests/test_finality_certificate.cpp
  tests/test_availability.cpp
  tests/test_snapshot.cpp
  tests/test_validator_lifecycle.cpp
  tests/test_mempool.cpp
  tests/test_frontier_execution.cpp
  tests/test_frontier_replay.cpp
  tests/test_ingress.cpp
  tests/test_hardening.cpp
  tests/test_protocol_scope.cpp
  tests/test_privacy.cpp
  tests/test_genesis.cpp
  tests/test_paths.cpp
  tests/test_keystore.cpp
  tests/test_wallet_send_policy.cpp
  tests/test_validator_onboarding.cpp
  tests/test_wallet_store.cpp
  tests/test_mainnet_characterization.cpp
  tests/test_integration.cpp
  tests/test_lightserver.cpp
  tests/test_explorer.cpp
)
target_link_libraries(finalis-tests PRIVATE finalis_core)
target_include_directories(finalis-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(FINALIS_SANITIZE)
  target_compile_options(finalis-tests PRIVATE ${SC_SAN_FLAGS})
  target_link_options(finalis-tests PRIVATE -fsanitize=address,undefined)
endif()

if(FINALIS_BUILD_FUZZ)
  add_executable(fuzz_p2p_frame fuzz/fuzz_p2p_frame.cpp)
  target_link_libraries(fuzz_p2p_frame PRIVATE finalis_core)
  if(FINALIS_SANITIZE)
    target_compile_options(fuzz_p2p_frame PRIVATE ${SC_SAN_FLAGS})
    target_link_options(fuzz_p2p_frame PRIVATE -fsanitize=address,undefined)
  endif()
  add_executable(fuzz_tx_parse fuzz/fuzz_tx_parse.cpp)
  target_link_libraries(fuzz_tx_parse PRIVATE finalis_core)
  if(FINALIS_SANITIZE)
    target_compile_options(fuzz_tx_parse PRIVATE ${SC_SAN_FLAGS})
    target_link_options(fuzz_tx_parse PRIVATE -fsanitize=address,undefined)
  endif()
endif()

enable_testing()
add_test(NAME finalis-tests COMMAND finalis-tests)
set_tests_properties(finalis-tests PROPERTIES RESOURCE_LOCK ports)
if(TARGET finalis-wallet-widget-tests)
  add_test(NAME finalis-wallet-widget-tests COMMAND finalis-wallet-widget-tests)
  set_tests_properties(finalis-wallet-widget-tests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

set(CPACK_PACKAGE_NAME "finalis-wallet")
set(CPACK_PACKAGE_VENDOR "reikagitakashi-bot")
set(CPACK_PACKAGE_CONTACT "reikagitakashi-bot")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Finalis reference desktop wallet")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_GENERATOR "TGZ;ZIP")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}")
include(CPack)
