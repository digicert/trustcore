To run the full test

./run.sh

To run a single test (or cipher) at a time

./run.sh <prefix> where prefix is beggining of any non-static method found in a .c file in the
src/crypto_interface/test/ folder. For example...

./run.sh crypto_interface_aes_

will run the aes tests only. If you wish to run the executable directly, say with valgrind or gdb, you
should first change directory to the src/crypto/test folder (yes, src/crypto/test and not src/crypto_interface/test), then run...

../../../bin/crypto_interface_test <prefix>

This way the test will be able to find the correct keys and certs needed for some of the tests.
