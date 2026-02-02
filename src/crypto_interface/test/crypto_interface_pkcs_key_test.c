/*
 * crypto_interface_pkcs_key_test.c
 *
 * PKCS1/PKCS8  Test
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/sec_key.h"

#include "../../crypto_interface/crypto_interface_ecc.h"

/* We want to use arrays within FILE_PATH, so undefine it
   and we'll manually get the .der files from the 
   crypto/test dir */
#ifdef FILE_PATH
#undef FILE_PATH
#define FILE_PATH( x) x
#endif

static MocCtx gpMocCtx = NULL;

static const char* rsafiles[] = 
{ 
    "../../crypto/test/noenckey1024.der",            /* no encryption */
    "../../crypto/test/enckey1024v1_sha1_des.der",   /* all pkcs5 */
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey1024v1_sha1_rc2.der",
#endif
#ifdef __ENABLE_DIGICERT_MD2__
    "../../crypto/test/enckey1024v1_md2_des.der",
#endif
#if defined(__ENABLE_DIGICERT_MD2__) && defined(__ENABLE_ARC2_CIPHERS__)
    "../../crypto/test/enckey1024v1_md2_rc2.der",   
#endif
    "../../crypto/test/enckey1024v1_md5_des.der",
#ifdef __ENABLE_ARC2_CIPHERS__      
    "../../crypto/test/enckey1024v1_md5_rc2.der",
#endif
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    "../../crypto/test/enckey1024_12_sha_2des.der",
#endif
    "../../crypto/test/enckey1024_12_sha_3des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey1024_12_sha_rc2_40.der",
    "../../crypto/test/enckey1024_12_sha_rc2_128.der",
#endif
    "../../crypto/test/enckey1024_12_sha_rc4_40.der",
    "../../crypto/test/enckey1024_12_sha_rc4_128.der",
    "../../crypto/test/enckey1024v2_3des.der",
    "../../crypto/test/enckey1024v2_des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey1024v2_rc2.der"
#endif
};

static const char* pkcs12_rsafiles[] =
{
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    "../../crypto/test/enckey1024_12_sha_2des.der",
#endif
    "../../crypto/test/enckey1024_12_sha_3des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey1024_12_sha_rc2_40.der",
    "../../crypto/test/enckey1024_12_sha_rc2_128.der",
#endif
    "../../crypto/test/enckey1024_12_sha_rc4_40.der",
    "../../crypto/test/enckey1024_12_sha_rc4_128.der",
};

static const char* eccfiles[] = 
{ 
    "../../crypto/test/noenckey521.der",            /* no encryption */
    "../../crypto/test/enckey521v1_sha1_des.der",   /* all pkcs5 */
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey521v1_sha1_rc2.der",   
#endif
#ifdef __ENABLE_DIGICERT_MD2__
    "../../crypto/test/enckey521v1_md2_des.der",
#endif
#if defined(__ENABLE_DIGICERT_MD2__) && defined(__ENABLE_ARC2_CIPHERS__)
    "../../crypto/test/enckey521v1_md2_rc2.der",   
#endif
    "../../crypto/test/enckey521v1_md5_des.der", 
#ifdef __ENABLE_ARC2_CIPHERS__  
    "../../crypto/test/enckey521v1_md5_rc2.der",
#endif
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    "../../crypto/test/enckey521_12_sha_2des.der",
#endif
    "../../crypto/test/enckey521_12_sha_3des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey521_12_sha_rc2_40.der",
    "../../crypto/test/enckey521_12_sha_rc2_128.der",
#endif
    "../../crypto/test/enckey521_12_sha_rc4_40.der",
    "../../crypto/test/enckey521_12_sha_rc4_128.der",
    "../../crypto/test/enckey521v2_3des.der",
    "../../crypto/test/enckey521v2_des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey521v2_rc2.der"
#endif
};

static const char* pkcs12_eccfiles[] =
{
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    "../../crypto/test/enckey521_12_sha_2des.der",
#endif
    "../../crypto/test/enckey521_12_sha_3des.der",
#ifdef __ENABLE_ARC2_CIPHERS__
    "../../crypto/test/enckey521_12_sha_rc2_40.der",
    "../../crypto/test/enckey521_12_sha_rc2_128.der",
#endif
    "../../crypto/test/enckey521_12_sha_rc4_40.der",
    "../../crypto/test/enckey521_12_sha_rc4_128.der",
};

static const char* dsafiles[] =
{
    "../../crypto/test/noenckeydsa.der",
    "../../crypto/test/enckeydsav1_md5_des.der",
};

static const char* pkcs12_dsafiles[] =
{
    "../../crypto/test/enckeydsa_12_sha_3des.der",
    "../../crypto/test/enckeydsa_12_sha_rc4_40.der",
    "../../crypto/test/enckeydsa_12_sha_rc4_128.der",
};

/*----------------------------------------------------------------*/

int crypto_interface_pkcs_key_test_rsa()
{
    int i, retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    MSTATUS status = OK;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("key1024.der"), &newBuffer,
                                                        &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(0, PKCS_getPKCS1Key(MOC_RSA(hwAccelCtx) newBuffer, newBufferLen,
                                                         &compareKey)))
    {
        goto exit;
    }

    FREE(newBuffer);
    newBuffer = 0;

    /* see if we can read this same key in PKCS8 format */
    for (i = 0; i < COUNTOF(rsafiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH((rsafiles[i])), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "mocana", 6, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));

        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;

    }

    /* pkcs12 uses a Unicode, null terminated password! */
    for (i = 0; i < COUNTOF(pkcs12_rsafiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH((pkcs12_rsafiles[i])), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "\x00\x6d\x00\x6f\x00\x63\x00\x61\x00\x6e\x00\x61\x00\x00", 14, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));

        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;
    }

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);

    return retVal;
}


/*----------------------------------------------------------------*/

int crypto_interface_pkcs_key_test_ecc()
{
    int i, retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    byteBoolean res = FALSE;
    MSTATUS status = OK;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("seckey521_1.der"), &newBuffer,
                                                        &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(0, SEC_getKey(MOC_ECC(hwAccelCtx) newBuffer, newBufferLen,
                                                       &compareKey)))
    {
        goto exit;
    }

    FREE(newBuffer);
    newBuffer = 0;

    /* see if we can read this same key in PKCS8 format */
    for (i = 0; i < COUNTOF(eccfiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH((eccfiles[i])), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "mocana", 6, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));
        /* also the private part */
        retVal += UNITTEST_STATUS(i, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) key.key.pECC, compareKey.key.pECC, &res));
        retVal += UNITTEST_TRUE(i, res);
       
        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;

    }

    /* pkcs12 uses a Unicode, null terminated password! */
    for (i = 0; i < COUNTOF(pkcs12_eccfiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH((pkcs12_eccfiles[i])), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "\x00\x6d\x00\x6f\x00\x63\x00\x61\x00\x6e\x00\x61\x00\x00", 14, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));
        /* also the private part */
        retVal += UNITTEST_STATUS(i, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) key.key.pECC, compareKey.key.pECC, &res));
        retVal += UNITTEST_TRUE(i, res);
       
        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;
    }

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);

    return retVal;
}



/*----------------------------------------------------------------*/

int crypto_interface_pkcs_key_test_dsa()
{
    int retVal = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    int i = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    MSTATUS status = OK;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("dsakey.der"), &newBuffer,
                                                        &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(0, PKCS_getDSAKey(MOC_DSA(hwAccelCtx)
                                                   newBuffer, newBufferLen,
                                                   &compareKey)))
    {
        goto exit;
    }

    FREE(newBuffer);
    newBuffer = 0;

    /* see if we can read this same key in PKCS8 format */
    for (i = 0; i < COUNTOF(dsafiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH(dsafiles[i]), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "mocana", 6, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));
         /* also the private part */
        retVal += UNITTEST_TRUE(i, 0 == VLONG_compareSignedVlongs( DSA_X(key.key.pDSA),
                                                                    DSA_X(compareKey.key.pDSA)));
              
        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;

    }

    /* pkcs12 uses a Unicode, null terminated password! */
    for (i = 0; i < COUNTOF(pkcs12_dsafiles); ++i)
    {
        status = DIGICERT_readFile( FILE_PATH(pkcs12_dsafiles[i]), &newBuffer, &newBufferLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, 
                   newBufferLen, "\x00\x6d\x00\x6f\x00\x63\x00\x61\x00\x6e\x00\x61\x00\x00", 14, &key);
        
        retVal += UNITTEST_STATUS(i, status);
        if (OK > status) continue;

        retVal += UNITTEST_STATUS(i, CRYPTO_matchPublicKey( &key, &compareKey));
        /* also the private part */
        retVal += UNITTEST_TRUE(i, 0 == VLONG_compareSignedVlongs( DSA_X(key.key.pDSA),
                                                                    DSA_X(compareKey.key.pDSA)));
        CRYPTO_uninitAsymmetricKey( &key, 0);
        FREE(newBuffer);
        newBuffer = 0;
    }

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);
#endif
    return retVal;
}

/*----------------------------------------------------------------*/

static int test_pkcs1(const char* inFile, const char* outFile, int hint)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS1Key(MOC_RSA(hwAccelCtx) buffer, bufferLen,
                                                         &compareKey)))
    {
        goto exit;
    }

    /* save it again */

    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS1Key( MOC_RSA(hwAccelCtx) &compareKey, &newBuffer,
                                                        &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS1Key(MOC_HASH(hwAccelCtx) newBuffer, newBufferLen,
                                                         &key)))
    {
        goto exit;
    }

    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    
#if 0
    /* compare the buffers */
    retVal += UNITTEST_INT(hint, newBufferLen, bufferLen);
    DIGI_MEMCMP(buffer, newBuffer, bufferLen, &memCmpRes);
    retVal += UNITTEST_TRUE(hint, 0 == memCmpRes);

    if (retVal)
    {
        /* write it so that we can look at it  */
        DIGICERT_writeFile(outFile, newBuffer, newBufferLen);
    }
#endif

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    if (buffer)
    {
        FREE( buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*-------------------------------------------------------------------*/

int crypto_interface_pkcs_key_test_2()
{
    int retVal = 0;
    MSTATUS status = OK;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

/* export does not allow keys < 2048 bytes */
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    retVal += test_pkcs1( FILE_PATH("key512.der"), FILE_PATH("pkcs1_512.der"), 512);
    retVal += test_pkcs1( FILE_PATH("key1023.der"), FILE_PATH("pkcs1_1023.der"), 1023);
    retVal += test_pkcs1( FILE_PATH("key1024.der"), FILE_PATH("pkcs1_1024.der"), 1024);
    retVal += test_pkcs1( FILE_PATH("key1025.der"), FILE_PATH("pkcs1_1025.der"), 1025);
    retVal += test_pkcs1( FILE_PATH("key1026.der"), FILE_PATH("pkcs1_1026.der"), 1026);
    retVal += test_pkcs1( FILE_PATH("key1027.der"), FILE_PATH("pkcs1_1027.der"), 1027);
    retVal += test_pkcs1( FILE_PATH("key1028.der"), FILE_PATH("pkcs1_1028.der"), 1028);
    retVal += test_pkcs1( FILE_PATH("key1029.der"), FILE_PATH("pkcs1_1029.der"), 1029);
    retVal += test_pkcs1( FILE_PATH("key1030.der"), FILE_PATH("pkcs1_1030.der"), 1030);
    retVal += test_pkcs1( FILE_PATH("key1031.der"), FILE_PATH("pkcs1_1031.der"), 1031);
    retVal += test_pkcs1( FILE_PATH("key1032.der"), FILE_PATH("pkcs1_1032.der"), 1032);
    retVal += test_pkcs1( FILE_PATH("key1033.der"), FILE_PATH("pkcs1_1033.der"), 1033);
    retVal += test_pkcs1( FILE_PATH("key1055.der"), FILE_PATH("pkcs1_1030.der"), 1055);
#endif
    retVal += test_pkcs1( FILE_PATH("key2048.der"), FILE_PATH("pkcs1_2048.der"), 2048);
    retVal += test_pkcs1( FILE_PATH("key4096.der"), FILE_PATH("pkcs1_4096.der"), 4096);

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);
    return retVal;
}


/*----------------------------------------------------------------*/

static int test_unencrypted_pkcs8_rsa(const char* inFile, const char* outFile, int hint)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS1Key(MOC_RSA(hwAccelCtx) buffer, bufferLen,
                                                         &compareKey)))
    {
        goto exit;
    }

    /* save it again as PKCS8 -- unencrypted*/
    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS8Key(MOC_RSA(hwAccelCtx) 
                                    &compareKey, NULL, 0, 0, NULL, 0, &newBuffer, &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS8Key(MOC_RSA(hwAccelCtx) newBuffer, newBufferLen,
                                                         &key)))
    {
        goto exit;
    }

    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    
#if 0
    /* compare the buffers */
    retVal += UNITTEST_INT(hint, newBufferLen, bufferLen);
    DIGI_MEMCMP(buffer, newBuffer, bufferLen, &memCmpRes);
    retVal += UNITTEST_TRUE(hint, 0 == memCmpRes);
#endif

    DIGICERT_writeFile(outFile, newBuffer, newBufferLen);

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    if (buffer)
    {
        FREE( buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*----------------------------------------------------------------*/

static int test_encrypted_pkcs8_rsa(randomContext* pRandomContext,
                         const char* inFile, const char* outFile, 
                         enum PKCS8EncryptionType encType)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    int hint = encType;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS1Key(MOC_RSA(hwAccelCtx) buffer, bufferLen,
                                                         &compareKey)))
    {
        goto exit;
    }

    /* save it again as PKCS8 -- encrypted*/
    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS8Key(MOC_RSA(hwAccelCtx) 
                                    &compareKey, pRandomContext, encType, 0, "mocana", 6,
                                    &newBuffer, &newBufferLen)))
    {
        goto exit;
    }
    DIGICERT_writeFile(outFile, newBuffer, newBufferLen);

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, newBufferLen,
                                                         "mocana", 6, &key)))
    {
        goto exit;
    }

    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    
exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }
    if (buffer)
    {
        FREE( buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}




/*----------------------------------------------------------------*/

static int test_unencrypted_pkcs8_ecc(const char* inFile, const char* outFile, int hint)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    byteBoolean res = FALSE;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, SEC_getKey(MOC_ECC(hwAccelCtx) buffer, bufferLen, &compareKey)))
    {
        goto exit;
    }

    /* save it again as PKCS8 -- unencrypted*/
    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS8Key(MOC_RSA(hwAccelCtx) 
                                    &compareKey, NULL, 0, 0, NULL, 0, &newBuffer, &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS8Key(MOC_RSA(hwAccelCtx) newBuffer, newBufferLen,
                                                         &key)))
    {
        goto exit;
    }

    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    /* also the private part */
    retVal += UNITTEST_STATUS(hint, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) key.key.pECC, compareKey.key.pECC, &res));
    retVal += UNITTEST_TRUE(hint, res);

    DIGICERT_writeFile(outFile, newBuffer, newBufferLen);

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    if (buffer)
    {
        FREE( buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*----------------------------------------------------------------*/

static int test_encrypted_pkcs8_ecc(randomContext* pRandomContext,
                         const char* inFile, const char* outFile, 
                         enum PKCS8EncryptionType encType)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    byteBoolean res = FALSE;
    int hint = encType;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);

    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, SEC_getKey(MOC_ECC(hwAccelCtx) buffer, bufferLen, &compareKey)))
    {
        goto exit;
    }

    /* save it again as PKCS8 -- encrypted*/
    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS8Key(MOC_RSA(hwAccelCtx) 
                                    &compareKey, pRandomContext, encType, 0, "mocana", 6,
                                    &newBuffer, &newBufferLen)))
    {
        goto exit;
    }
    DIGICERT_writeFile(outFile, newBuffer, newBufferLen);

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, newBufferLen,
                                                         "mocana", 6, &key)))
    {
        goto exit;
    }

    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    /* also the private part */
    retVal += UNITTEST_STATUS(hint, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) key.key.pECC, compareKey.key.pECC, &res));
    retVal += UNITTEST_TRUE(hint, res);

exit:

    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);

    if (newBuffer)
    {
        FREE( newBuffer);
    }

    if (buffer)
    {
        FREE( buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*----------------------------------------------------------------*/

static int test_encrypted_pkcs8_ecc_prf(randomContext* pRandomContext,
                                 const char* inFile, const char* outFile,
                                 enum PKCS8EncryptionType encType,
                                 enum PKCS8PrfType prfType)
{
    int retVal = 0;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key;
    AsymmetricKey compareKey;
    byteBoolean res = FALSE;
    int hint = encType;
    
    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;
    
    CRYPTO_initAsymmetricKey(&compareKey);
    CRYPTO_initAsymmetricKey(&key);
    
    /* read the original key */
    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inFile, &buffer,
                                                       &bufferLen)))
    {
        goto exit;
    }
    
    if (retVal = UNITTEST_STATUS(hint, SEC_getKey(MOC_ECC(hwAccelCtx) buffer, bufferLen, &compareKey)))
    {
        goto exit;
    }
       
    /* save it again as PKCS8 -- encrypted*/
    if ( retVal = UNITTEST_STATUS( hint, PKCS_setPKCS8Key(MOC_RSA(hwAccelCtx)
                                                          &compareKey, pRandomContext,
                                                          encType, prfType, "mocana", 6,
                                                          &newBuffer, &newBufferLen)))
    {
        goto exit;
    }
    DIGICERT_writeFile(outFile, newBuffer, newBufferLen);
    
    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) newBuffer, newBufferLen,
                                                          "mocana", 6, &key)))
    {
        goto exit;
    }
    
    /* compare the keys */
    retVal += UNITTEST_STATUS(hint, CRYPTO_matchPublicKey( &key, &compareKey));
    /* also the private part */
    retVal += UNITTEST_STATUS(hint, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) key.key.pECC, compareKey.key.pECC, &res));
    retVal += UNITTEST_TRUE(hint, res);

exit:
    
    CRYPTO_uninitAsymmetricKey( &key, 0);
    CRYPTO_uninitAsymmetricKey( &compareKey, 0);
    
    if (newBuffer)
    {
        FREE( newBuffer);
    }
    
    if (buffer)
    {
        FREE( buffer);
    }
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return retVal;
}


/*-------------------------------------------------------------------*/

int crypto_interface_pkcs_key_test_3()
{
    int retVal = 0;
    randomContext* pRandomContext = NULL;
    MSTATUS status = OK;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    retVal += UNITTEST_STATUS( 0, RANDOM_acquireContext(&pRandomContext));
    if (retVal) return retVal;

    /* RSA */

    retVal += test_unencrypted_pkcs8_rsa( FILE_PATH("key1024.der"), FILE_PATH("pkcs8_no_encrypt_1024.der"), 1024);

    /* pkcs5 v1 */
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_sha1_des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_sha1_des);
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_sha1_rc2_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_sha1_rc2);
#endif
#ifdef __ENABLE_DIGICERT_MD2__
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_md2_des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md2_des);
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_md2_rc2_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md2_rc2);
#endif 
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_md5_des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md5_des);
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v1_md5_rc2_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md5_rc2);
#endif
    /* pkcs12 */
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_2des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_2des);
#endif
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_3des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_3des);
#ifdef __ENABLE_ARC2_CIPHERS__ 
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc2_40_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc2_40);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc2_128_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc2_128);
#endif 
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc4_40_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc4_40);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc4_128_1024.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc4_128);

    /* pkcs5 v2 */
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v2_rc2_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_rc2);
#endif
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v2_des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_des);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext, 
                                    FILE_PATH("key1024.der"), 
                                    FILE_PATH("pkcs8_v2_3des_1024.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_3des);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext,
                                   FILE_PATH("key1024.der"),
                                   FILE_PATH("pkcs8_v2_aes128_1024.der"),
                                   PCKS8_EncryptionType_pkcs5_v2_aes128);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext,
                                   FILE_PATH("key1024.der"),
                                   FILE_PATH("pkcs8_v2_aes192_1024.der"),
                                   PCKS8_EncryptionType_pkcs5_v2_aes192);
    retVal += test_encrypted_pkcs8_rsa( pRandomContext,
                                   FILE_PATH("key1024.der"),
                                   FILE_PATH("pkcs8_v2_aes256_1024.der"),
                                   PCKS8_EncryptionType_pkcs5_v2_aes256);

    /* ECC */

    retVal += test_unencrypted_pkcs8_ecc( FILE_PATH("seckey521_2.der"), FILE_PATH("pkcs8_no_encrypt_521.der"), 1024);

    /* pkcs5 v1 */
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_sha1_des_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_sha1_des);
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_sha1_rc2_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_sha1_rc2);
#endif
#ifdef __ENABLE_DIGICERT_MD2__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_md2_des_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md2_des);
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_md2_rc2_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md2_rc2);
#endif
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_md5_des_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md5_des);
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v1_md5_rc2_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v1_md5_rc2);
#endif
    /* pkcs12 */
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_2des_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_2des);
#endif
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_3des_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_3des);
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc2_40_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc2_40);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc2_128_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc2_128);
#endif
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc4_40_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc4_40);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v12_sha_rc4_128_521.der"), 
                                    PCKS8_EncryptionType_pkcs12_sha_rc4_128);

    /* pkcs5 v2 */
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v2_rc2_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_rc2);
#endif
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v2_des_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_des);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext, 
                                    FILE_PATH("seckey521_2.der"), 
                                    FILE_PATH("pkcs8_v2_3des_521.der"), 
                                    PCKS8_EncryptionType_pkcs5_v2_3des);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext,
                                    FILE_PATH("seckey521_2.der"),
                                    FILE_PATH("pkcs8_v2_aes128_521.der"),
                                    PCKS8_EncryptionType_pkcs5_v2_aes128);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext,
                                    FILE_PATH("seckey521_2.der"),
                                    FILE_PATH("pkcs8_v2_aes192_521.der"),
                                    PCKS8_EncryptionType_pkcs5_v2_aes192);
    retVal += test_encrypted_pkcs8_ecc( pRandomContext,
                                    FILE_PATH("seckey521_2.der"),
                                    FILE_PATH("pkcs8_v2_aes256_521.der"),
                                    PCKS8_EncryptionType_pkcs5_v2_aes256);
    
    /* pkcs5 v2 prf */
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += test_encrypted_pkcs8_ecc_prf( pRandomContext,
                                       FILE_PATH("seckey521_2.der"),
                                       FILE_PATH("pkcs8_v2_rc2_sha224_521.der"),
                                       PCKS8_EncryptionType_pkcs5_v2_rc2,
                                       PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest);
#endif
    retVal += test_encrypted_pkcs8_ecc_prf( pRandomContext,
                                       FILE_PATH("seckey521_2.der"),
                                       FILE_PATH("pkcs8_v2_des_sha256_521.der"),
                                       PCKS8_EncryptionType_pkcs5_v2_des,
                                       PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
    retVal += test_encrypted_pkcs8_ecc_prf( pRandomContext,
                                       FILE_PATH("seckey521_2.der"),
                                       FILE_PATH("pkcs8_v2_3des_sha384_521.der"),
                                       PCKS8_EncryptionType_pkcs5_v2_3des,
                                       PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest);
    retVal += test_encrypted_pkcs8_ecc_prf( pRandomContext,
                                       FILE_PATH("seckey521_2.der"),
                                       FILE_PATH("pkcs8_v2_aes128_sha512_521.der"),
                                       PCKS8_EncryptionType_pkcs5_v2_aes128,
                                       PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest);
    retVal += test_encrypted_pkcs8_ecc_prf( pRandomContext,
                                       FILE_PATH("seckey521_2.der"),
                                       FILE_PATH("pkcs8_v2_aes192_sha1_521.der"),
                                       PCKS8_EncryptionType_pkcs5_v2_aes192,
                                       PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest);

exit:

    RANDOM_releaseContext( &pRandomContext);
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);
    return retVal;
}
