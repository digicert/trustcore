export GCOV=gcov

unset CC
./clean.sh
rm -rf CMakeFiles/
mkdir CMakeFiles/

# GPROF is on
cmake -DMOCANA_ENABLE_GPROF=ON -DCMAKE_BUILD_TYPE=Debug -DCM_ENABLE_QUICKTEST=ON -DCM_DISABLE_CI=ON CMakeLists.txt

make clean all

# Always declare success
rm -rf Testing
ctest --timeout 5000 -V --no-compress-output -T Test || echo "Test Finished"
cp Testing/`head -n 1 Testing/TAG`/Test.xml ./CTestResults.xml

# Make XML
rm -rf xml
mkdir xml
gcovr -x -r ../.. -o xml/coverage.xml
# Make HTML
rm -rf html
mkdir html
lcov -c -d . -o test_coverage.info
genhtml test_coverage.info --output-directory html

./clean.sh
rm -rf CMakeFiles/ 2>/dev/null
rm CMakeCache.txt 2>/dev/null
rm CTestResults.xml 2>/dev/null
rm CTestTestfile.cmake 2>/dev/null
rm DartConfiguration.tcl 2>/dev/null
rm Makefile 2>/dev/null
rm -rf Testing/ 2>/dev/null
rm cmake_install.cmake 2>/dev/null
rm test_coverage.info 2>/dev/null
rm -rf xml/ 2>/dev/null
rm ../../src/crypto_interface/test/default.profraw 2>/dev/null

