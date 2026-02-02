#!/usr/bin/env bash

str=rsa_perf_test_primes_"$@"

~/bin/crypto_perf_test $str > digi_test_"$@"_0.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_1.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_2.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_3.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_4.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_5.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_6.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_7.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_8.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_9.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_10.txt &
~/bin/crypto_perf_test $str > digi_test_"$@"_11.txt &
