# Build and Run Instructions for NanoWS Unit Test

> **Note:** Run all commands from the root of the repository.

## Prerequisites

Linux, CMake, and a C compiler are required. Install the test dependencies:

```bash
sudo apt update
sudo apt install -y libcmocka-dev pkg-config
```

## Build

```bash
cmake -DENABLE_WEBSOCKET_SUPPORT=ON -DENABLE_WEBSOCKET_UNITTEST=ON -B build -S .
cmake --build build
```

## Run

```bash
./projects/websocket_testunit/run.sh
```

Run selected suites:

```bash
./projects/websocket_testunit/run.sh test_websocket_frame
./projects/websocket_testunit/run.sh test_websocket_handshake test_websocket_websocket
```

The runner returns a nonzero exit status for failed tests, unknown suite names,
or missing binaries.

## Test Scope

The three suites test frame encoding/decoding, handshake validation, and transport
callbacks. The standard build covers both plain TCP and TLS handshake paths.
TCP/TLS I/O and randomness are mocked; NanoWS library code runs without opening
sockets or waiting for real timeouts.

The mock source requires `NANOWS_UNIT_TEST_MOCKS`, defined only for the mock
target, to prevent accidental compilation in other targets.

## Coverage

Install `lcov` (`sudo apt install -y lcov`). Run from the repository root.

1. Configure and build with gcov instrumentation. The variable is read at
   configure time, so use a fresh build directory (or delete `build/CMakeCache.txt`):

   ```bash
   export CM_ENV_CODE_COVERAGE=1
   cmake -DENABLE_WEBSOCKET_SUPPORT=ON -DENABLE_WEBSOCKET_UNITTEST=ON -B build -S .
   cmake --build build
   ```

2. Capture a zero-count baseline so files that never run still appear:

   ```bash
   lcov --no-external --capture --initial --directory . --output-file /tmp/nanows_base.info
   ```

3. Run the tests:

   ```bash
   ./projects/websocket_testunit/run.sh
   ```

4. Capture the results, merge with the baseline, and keep only the NanoWS sources:

   ```bash
   lcov --no-external --capture --directory . --output-file /tmp/nanows_test.info
   lcov --add-tracefile /tmp/nanows_base.info --add-tracefile /tmp/nanows_test.info \
        --output-file /tmp/nanows_combined.info
   lcov --extract /tmp/nanows_combined.info \
        '*/src/websocket/websocket.c' \
        '*/src/websocket/websocket_frame.c' \
        '*/src/websocket/websocket_handshake.c' \
        --output-file /tmp/nanows_filtered.info
   lcov --list /tmp/nanows_filtered.info
   ```

5. Optional HTML report:

   ```bash
   genhtml /tmp/nanows_filtered.info --output-directory /tmp/nanows_coverage_html
   ```

   Open `/tmp/nanows_coverage_html/index.html`.

Re-running the tests accumulates counts in the `.gcda` files. Delete them first
(`find build -name '*.gcda' -delete`) for a clean measurement.
