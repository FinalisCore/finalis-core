# SPDX-License-Identifier: MIT
# ctest configure-rejects-file-backend: configuring without RocksDB must fail with the file-backend
# message unless FINALIS_ALLOW_FILE_BACKEND=ON (the file backend is not crash-durable).
# Usage: cmake -DSRC=<source dir> -DBIN=<scratch build dir> -P check_file_backend_rejected.cmake
file(REMOVE_RECURSE "${BIN}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${SRC}" -B "${BIN}" -DROCKSDB_LIB=OFF -DROCKSDB_INCLUDE_DIR=OFF
  RESULT_VARIABLE rc
  OUTPUT_VARIABLE out
  ERROR_VARIABLE err)
file(REMOVE_RECURSE "${BIN}")
if(rc EQUAL 0)
  message(FATAL_ERROR "configure without RocksDB succeeded; it must be rejected")
endif()
if(NOT "${out}${err}" MATCHES "-DFINALIS_ALLOW_FILE_BACKEND=ON")
  message(FATAL_ERROR "configure failed for another reason:\n${err}")
endif()
message(STATUS "configure without RocksDB rejected as expected")
