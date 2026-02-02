#!/bin/bash

echo "Get size of binary per algorithm"

# make a backup directory to store files temporarily.
# ignore output, directory might already exist
mkdir ../../src/crypto_interface/test1 2>/dev/null

# copy all files to a backup directory called test1
for i in ../../src/crypto_interface/test/*.c; do
    BASE=`basename $i`

    # if not copied successfully. exit
    if ! cp $i ../../src/crypto_interface/test1/$BASE >/dev/null; then
        echo 'failed to copy ' $i;
        exit 1;
    fi
done

# check that all files were copied successfully. 
for i in ../../src/crypto_interface/test/*.c; do
    BASE=`basename $i`

    if diff $i ../../src/crypto_interface/test1/$BASE >/dev/null; then
        echo $i;
    else
        echo $i ' does not match expected file';
        exit 1; # exit with an error status, if a single file doesn't match
    fi
done

# remove all entries in crypto_interface/test
rm ../../src/crypto_interface/test/crypto_interface_*.c

# make a back up of the test_sources.txt
cp ../../projects/cryptointerface_unittest/test_sources.txt ../../projects/cryptointerface_unittest/backup.txt

# remove any previously generated sizes.txt
rm sizes.txt >/dev/null

# init file that will have size information
echo 'File with the sizes of the executable' > sizes.txt

# for each test file, build with mbed, without mbed, and without CI
while IFS='' read -r line || [[ -n "$line" ]]; do

    # copy current test file into test_sources.txt
    echo $line > test_sources.txt 

    # get base name of file to copy back into test directory
    BASE=`basename $line`

    # copy file into test directory
    cp ../../src/crypto_interface/test1/$BASE ../../src/crypto_interface/test/$BASE

    echo '-----------------------------------------------------------------------' >> sizes.txt
    echo '                  ' $BASE >> sizes.txt
    echo '-----------------------------------------------------------------------' >> sizes.txt

    # build with mbed
    echo 'with mbed' >> sizes.txt
    ./build.sh --mbedtls --mbed-path ~/mbedtls-2.13.0 --quick
    size ../../bin/crypto_interface_test >> sizes.txt
    ./clean.sh

    # build without mbed
    echo 'without mbed' >> sizes.txt
    ./build.sh --quick
    size ../../bin/crypto_interface_test >> sizes.txt
    ./clean.sh

    # build without CI
    echo 'without CI' >> sizes.txt
    ./build.sh --quick --no-ci
    size ../../bin/crypto_interface_test >> sizes.txt
    ./clean.sh

    # removed current file in test in preparation of next
    rm ../../src/crypto_interface/test/$BASE

done < ../../projects/cryptointerface_unittest/backup.txt

# add new line to end of file
echo '' >> sizes.txt

# restore original test_sources directory
cp ../../projects/cryptointerface_unittest/backup.txt ../../projects/cryptointerface_unittest/test_sources.txt

# delete backup file
rm ../../projects/cryptointerface_unittest/backup.txt

# return all test files back to original directory
cp ../../src/crypto_interface/test1/crypto_interface_*.c ../../src/crypto_interface/test/

# delete temporary test directory
rm -r ../../src/crypto_interface/test1/
