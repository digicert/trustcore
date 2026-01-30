---------- Unit Test CMake Rules ---------------

The CMake rules in this directory create the unit test executables and place them in the 'bin'
directory. They are named '<lib>_test' (e.g. 'common_test') to distinguish the various test
executables for the different libraries that are being tested.

To run a test, you must use the 'src/<lib>/test' area as the working directory, so that any
needed test file can be located.

NOTE: The 'main.c' file to run tests are generated ONLY on platforms that support the Ruby
tool. In order to run the tests on a platform that does not have Ruby installed, the source
file 'main.c' MUST be checked in and kept up-to-date.
