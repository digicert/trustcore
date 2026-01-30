To run the full test

./run.sh

To run a single test (or cipher) at a time

./run.sh <prefix> where prefix is beggining of any non-static method found in a .c file in the
src/crypto/test/ folder. For example...

./run.sh aes_

will run the aes tests only. If you wish to run the executable directly, say with valgrind or gdb, you
should first change directory to the src/crypto/test folder, then run...

../../../bin/crypto_test <prefix>

This way the test will be able to find the correct keys and certs needed for some of the tests.
