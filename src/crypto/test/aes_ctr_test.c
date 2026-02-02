/*
 *  aes_ctr_test.c
 *
 *   unit test for aes_ctr.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "../aes_ctr.c"

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#endif

#include "../../../unit_tests/unittest.h"

static ubyte* counter = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

static ubyte* pt =      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
                        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
                        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
                        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";

static ubyte* k128 =    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
static ubyte* ct128 =   "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce"
                        "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff"
                        "\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab"
                        "\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee";
/*
F.5.1 CTR-AES128.Encrypt
Key 2b7e151628aed2a6abf7158809cf4f3c
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block ec8cdf7398607cb0f2d21675ea9ea1e4
Plaintext 6bc1bee22e409f96e93d7e117393172a
Ciphertext 874d6191b620e3261bef6864990db6ce
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block 362b7c3c6773516318a077d7fc5073ae
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext 9806f66b7970fdff8617187bb9fffdff
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 6a2cc3787889374fbeb4c81b17ba6c44
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 5ae4df3edbd5d35e5b4f09020db03eab
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block e89c399ff0f198c6d40a31db156cabfe
Plaintext f69f2445df4f9b17ad2b417be66c3710
Ciphertext 1e031dda2fbe03d1792170a0f3009cee

F.5.2 CTR-AES128.Decrypt
Key 2b7e151628aed2a6abf7158809cf4f3c
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block ec8cdf7398607cb0f2d21675ea9ea1e4
Ciphertext 874d6191b620e3261bef6864990db6ce
Plaintext 6bc1bee22e409f96e93d7e117393172a
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block 362b7c3c6773516318a077d7fc5073ae
Ciphertext 9806f66b7970fdff8617187bb9fffdff
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 6a2cc3787889374fbeb4c81b17ba6c44
Ciphertext 5ae4df3edbd5d35e5b4f09020db03eab
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block e89c399ff0f198c6d40a31db156cabfe
Ciphertext 1e031dda2fbe03d1792170a0f3009cee
Plaintext f69f2445df4f9b17ad2b417be66c3710
*/

static ubyte* k192 =    "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
static ubyte* ct192 =   "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b"
                        "\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94"
                        "\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7"
                        "\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50";
/*
F.5.3 CTR-AES192.Encrypt
Key 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block 717d2dc639128334a6167a488ded7921
Plaintext 6bc1bee22e409f96e93d7e117393172a
Ciphertext 1abc932417521ca24f2b0459fe7e6e0b
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block a72eb3bb14a556734b7bad6ab16100c5
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext 090339ec0aa6faefd5ccc2c6f4ce8e94
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 2efeae2d72b722613446dc7f4c2af918
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 1e36b26bd1ebc670d1bd1d665620abf7
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block b9e783b30dd7924ff7bc9b97beaa8740
Plaintext f69f2445df4f9b17ad2b417be66c3710
Ciphertext 4f78a7f6d29809585a97daec58c6b050

F.5.4 CTR-AES192.Decrypt
Key 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block 717d2dc639128334a6167a488ded7921
Ciphertext 1abc932417521ca24f2b0459fe7e6e0b
Plaintext 6bc1bee22e409f96e93d7e117393172a
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block a72eb3bb14a556734b7bad6ab16100c5
Ciphertext 090339ec0aa6faefd5ccc2c6f4ce8e94
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 2efeae2d72b722613446dc7f4c2af918
Ciphertext 1e36b26bd1ebc670d1bd1d665620abf7
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block b9e783b30dd7924ff7bc9b97beaa8740
Ciphertext 4f78a7f6d29809585a97daec58c6b050
Plaintext f69f2445df4f9b17ad2b417be66c3710
*/

static ubyte* k256=     "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
static ubyte* ct256 =   "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28"
                        "\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5"
                        "\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d"
                        "\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6";

/*
F.5.5 CTR-AES256.Encrypt
Key 603deb1015ca71be2b73aef0857d7781
1f352c073b6108d72d9810a30914dff4
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block 0bdf7df1591716335e9a8b15c860c502
Plaintext 6bc1bee22e409f96e93d7e117393172a
Ciphertext 601ec313775789a5b7a7f504bbf3d228
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block 5a6e699d536119065433863c8f657b94
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext f443e3ca4d62b59aca84e990cacaf5c5
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 1bc12c9c01610d5d0d8bd6a3378eca62
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 2b0930daa23de94ce87017ba2d84988d
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block 2956e1c8693536b1bee99c73a31576b6
Plaintext f69f2445df4f9b17ad2b417be66c3710
Ciphertext dfc9c58db67aada613c2dd08457941a6

F.5.6 CTR-AES256.Decrypt
Key 603deb1015ca71be2b73aef0857d7781
1f352c073b6108d72d9810a30914dff4
Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Block #1
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Output Block 0bdf7df1591716335e9a8b15c860c502
Ciphertext 601ec313775789a5b7a7f504bbf3d228
Plaintext 6bc1bee22e409f96e93d7e117393172a
Block #2
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
Output Block 5a6e699d536119065433863c8f657b94
Ciphertext f443e3ca4d62b59aca84e990cacaf5c5
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
Output Block 1bc12c9c01610d5d0d8bd6a3378eca62
Ciphertext 2b0930daa23de94ce87017ba2d84988d
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
Output Block 2956e1c8693536b1bee99c73a31576b6
Ciphertext dfc9c58db67aada613c2dd08457941a6
Plaintext f69f2445df4f9b17ad2b417be66c3710
*/



/*------------------------------------------------------------------*/

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__)

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (3)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
                             mContinueTest = 1;          \
                             alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}


/*------------------------------------------------------------------*/

static void
aes_ctr_speed_test(MOC_SYM(hwAccelDescr hwAccelCtx) int dummy)
{
    ubyte* buffer = 0;
    int i;
    ubyte4 sizes[] = { 16, 64, 256, 1024, 8192 };
    ubyte zeroes[32] = { 0};

    buffer = (ubyte*) MALLOC(8192);

    if ( buffer)
    {
        for (i = 0; i < 8192; ++i)
        {
            buffer[i] = (ubyte) i;
        }

        for ( i = 0; i < COUNTOF(sizes); ++i)
        {
            struct tms tstart, tend;
            double diffTime, kbytes;
            ubyte4 counter;
            BulkCtx aesCtx;

            START_ALARM(TEST_SECONDS);
            times(&tstart);
            counter = 0;
            aesCtx = CreateAESCTRCtx(MOC_SYM(hwAccelCtx) zeroes, 32, 1);
            while( ALARM_OFF)
            {
                DoAESCTR(MOC_SYM(hwAccelCtx) aesCtx, buffer, sizes[i], 1, NULL);
                counter++;
            }
            DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) &aesCtx);
            times(&tend);
            diffTime = tend.tms_utime-tstart.tms_utime;
            diffTime /= sysconf(_SC_CLK_TCK);
            kbytes = sizes[i] * (counter / 1024.0);
            printf("\tAES CTR: %d blocks of %d bytes in %g seconds of CPU time\n", 
                   counter, sizes[i], diffTime);
            printf("AES CTR: %g kbytes/second (CPU time)(%d bytes block) (1 kbyte = 1024 bytes)\n",
                   kbytes/diffTime, sizes[i]);
            
        }
        FREE(buffer);
    }    
}

#endif

/*---------------------------------------------------------------------*/

static int
test_vector_aux( MOC_SYM( hwAccelDescr hwAccelCtx) const ubyte* key, ubyte4 keyLen, 
                ubyte encrypt, const ubyte* input, const ubyte* expOutput)
{
    sbyte4 i;
    int errors;
    ubyte output[64];
    
    errors = 0;
    for ( i = 64; i >= 1; --i)
    {
        BulkCtx aesCtx;
        sbyte4 sent = 0;
        sbyte4 cmpRes;
        MSTATUS status;

        DIGI_MEMCPY( output, input, 64);
        aesCtx = CreateAESCTRCtx(MOC_SYM(hwAccelCtx) key, keyLen, encrypt);
        errors += UNITTEST_TRUE( i, (0 != aesCtx));
        while ( sent < 64)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > 64 - sent)
            {
                toSend = 64 - sent;
            }
            status = DoAESCTR(MOC_SYM(hwAccelCtx) aesCtx, output+sent, toSend, encrypt, NULL);
            errors += UNITTEST_STATUS( i, status);
            sent += toSend;
        }
        DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) &aesCtx);
        DIGI_MEMCMP( output, expOutput, 64, &cmpRes);
        errors += UNITTEST_INT(i, cmpRes, 0);
    }

    /* to display the test values if there are errors  */
    errors += UNITTEST_INT( keyLen + encrypt, errors, 0);

    return errors;
}


/*---------------------------------------------------------------------*/

int aes_ctr_test_vectors()
{
    int retVal = 0;

    ubyte key128[16+16];
    ubyte key192[24+16];
    ubyte key256[32+16];
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    /* build the "keys", actually key + counter */
    DIGI_MEMCPY( key128, k128, 16);
    DIGI_MEMCPY( key128 + 16, counter, 16);

    DIGI_MEMCPY( key192, k192, 24);
    DIGI_MEMCPY( key192 + 24, counter, 16);

    DIGI_MEMCPY( key256, k256, 32);
    DIGI_MEMCPY( key256 + 32, counter, 16);

    /* key128 encryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key128, 32, 1, pt, ct128);
    /* key128 decryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key128, 32, 0, ct128, pt);
    /* key192 encryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key192, 40, 1, pt, ct192);
    /* key192 decryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key192, 40, 0, ct192, pt);
    /* key128 encryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key256, 48, 1, pt, ct256);
    /* key128 decryption test */
    retVal += test_vector_aux( MOC_SYM(hwAccelCtx) key256, 48, 0, ct256, pt);

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
    if ( 0 == retVal)
    {
        aes_ctr_speed_test(MOC_SYM(hwAccelCtx) 0);
    }
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------*/

int aes_ctr_test_vectors_rfc3711()
{
    /* test vectors from RFC 3711 */
    int retVal = 0;
    ubyte key128[16+16];
    hwAccelDescr hwAccelCtx;
    const ubyte* rfc3711_counter = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\x00\x00";
    ubyte inout[64] = { 0 };
    const ubyte* firstCt =  "\xe0\x3e\xad\x09\x35\xc9\x5e\x80\xe1\x66\xb1\x6d\xd9\x2b\x4e\xb4"
                            "\xd2\x35\x13\x16\x2b\x02\xd0\xf7\x2a\x43\xa2\xfe\x4a\x5f\x97\xab"
                            "\x41\xe9\x5b\x3b\xb0\xa2\xe8\xdd\x47\x79\x01\xe4\xfc\xa8\x94\xc0";
    const ubyte* lastCt =   "\xec\x8c\xdf\x73\x98\x60\x7c\xb0\xf2\xd2\x16\x75\xea\x9e\xa1\xe4"
                            "\x36\x2b\x7c\x3c\x67\x73\x51\x63\x18\xa0\x77\xd7\xfc\x50\x73\xae"
                            "\x6a\x2c\xc3\x78\x78\x89\x37\x4f\xbe\xb4\xc8\x1b\x17\xba\x6c\x44"
                            "\xe8\x9c\x39\x9f\xf0\xf1\x98\xc6\xd4\x0a\x31\xdb\x15\x6c\xab\xfe";
    BulkCtx aesCtx;
    sbyte4 i;
    sbyte4 cmpRes;
    MSTATUS status;
   
    if (OK > (status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return 1;

    /* build the "keys", actually key + counter */
    DIGI_MEMCPY( key128, k128, 16);
    DIGI_MEMCPY( key128 + 16, rfc3711_counter, 16);

    aesCtx = CreateAESCTRCtx(MOC_SYM(hwAccelCtx) key128, 32, 1);
    status = DoAESCTR(MOC_SYM(hwAccelCtx) aesCtx, inout, 48, 1, NULL);
    retVal += UNITTEST_STATUS(0, status); 

    DIGI_MEMCMP(inout, firstCt, 48, &cmpRes);
    retVal += UNITTEST_INT(0, 0, cmpRes);

    /* do 65282 - 6 blocks more -- we don't check the results */
    for (i = 0; i < (65282-6); ++i)
    {
        status = DoAESCTR(MOC_SYM(hwAccelCtx) aesCtx, inout, 16, 1, NULL);
        retVal += UNITTEST_STATUS(0, status); 
    }

    /* test the last 4 blocks which corresponds to CTR F.5.1 */
    DIGI_MEMSET(inout, 0, 64);
    status = DoAESCTR(MOC_SYM(hwAccelCtx) aesCtx, inout, 64, 1, NULL);
    retVal += UNITTEST_STATUS(0, status); 
    DIGI_MEMCMP(inout, lastCt, 64, &cmpRes);
    retVal += UNITTEST_INT(0, 0, cmpRes);

    DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) &aesCtx);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;

}


/*---------------------------------------------------------------------*/

int aes_ctr_test_increment_block()
{
/* this is a long test, not very useful -- run it only on main */
#ifdef CUSTOM_RSA_BLIND_FUNC
    return 0;
#else
    ubyte ptBlock[AES_BLOCK_SIZE] = { 0 };
    ubyte4 i,j;
    int retVal = 0;

    for (j=0; j < 0xFFFFFFFF; ++j)
    {
        /* increment the block */
        ubyte addend = 1;
        for ( i = AES_BLOCK_SIZE - 1; i > 0; --i)
        {
            addend =  (ptBlock[i] += addend) ? 0 : addend;
        }
    }

    for (i = 0; i < AES_BLOCK_SIZE-4; ++i)
    {
        retVal += UNITTEST_TRUE(i, ( ptBlock[i] == 0x00));
    }
    for (; i < AES_BLOCK_SIZE; ++i)
    {
        retVal += UNITTEST_TRUE(i, ( ptBlock[i] == 0xFF));
    }
    return retVal;
#endif
}
