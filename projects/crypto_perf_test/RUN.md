To run the full test

./run.sh

To run a single test (or cipher) at a time

./run.sh <prefix> where prefix is beggining of any non-static method found in a .c file in the
src/crypto/perf_test/ folder. For example...

./run.sh aes_

will run the aes tests only.

