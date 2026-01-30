/*
 * crypto_interface_example.c
 *
 * Crypto Interface Example Code
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/initmocana.h"
#include "../../crypto/hw_accel.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#endif

#include <stdio.h>

MOC_EXTERN MSTATUS crypto_interface_sha2_example();
MOC_EXTERN MSTATUS crypto_interface_sha3_example();
MOC_EXTERN MSTATUS crypto_interface_random_example();
MOC_EXTERN MSTATUS crypto_interface_hmac_example();
MOC_EXTERN MSTATUS crypto_interface_aes_example();
MOC_EXTERN MSTATUS crypto_interface_aes_gcm_example();
MOC_EXTERN MSTATUS crypto_interface_tdes_example();
MOC_EXTERN MSTATUS crypto_interface_rsa_example();
MOC_EXTERN MSTATUS crypto_interface_rsa_pss_example();
MOC_EXTERN MSTATUS crypto_interface_ecc_example();
MOC_EXTERN MSTATUS crypto_interface_ecc_eg_example();
MOC_EXTERN MSTATUS crypto_interface_ecdh_example();
MOC_EXTERN MSTATUS crypto_interface_dh_example();
MOC_EXTERN MSTATUS crypto_interface_composite_example();
MOC_EXTERN MSTATUS crypto_interface_keygen_example();
MOC_EXTERN MSTATUS crypto_interface_cms_example();
MOC_EXTERN MSTATUS crypto_interface_moccms_streaming_example();

MSTATUS crypto_interface_example_main(sbyte4 argc, char *argv[])
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_TAP__ 
    ubyte4 modNum = 1;
#endif
    
    /* To initialize with all default settings, simply use DIGICERT_initDigicert */
    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    /* To initialize with non defaults declare a InitMocanaSetupInfo object
       and call DIGICERT_initialize instead. For example, if wanting to use
       dev/urandom for RNG seeding, and wishing to use a static memmory buffer
       for allocations, one would have...
    
       ubyte pBuffer[65536];
       InitMocanaSetupInfo setupInfo = {0};
       setupInfo.flags = MOC_INIT_FLAG_SEED_FROM_DEV_URANDOM;
       setupInfo.pStaticMem = pBuffer;
       setupInfo.staticMemSize = 65536;

       status = DIGICERT_initialize(&setupInfo, NULL);
       if (OK != status)
           goto exit;
    */
#ifdef __ENABLE_DIGICERT_TAP__ 
    status = TAP_EXAMPLE_init(&modNum,1);
    if (OK != status)
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256__
    status = crypto_interface_sha2_example();
    if(OK != status)
    {
        printf("SHA2 example failed\n");
        goto exit;
    }
    printf("SHA2 example passed\n");
#endif

#if defined( __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    status = crypto_interface_sha3_example();
    if(OK != status)
    {
        printf("SHA3 example failed\n");
        goto exit;
    }
    printf("SHA3 example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_RANDOM__
    status = crypto_interface_random_example();
    if(OK != status)
    {
        printf("RANDOM example failed\n");
        goto exit;
    }
    printf("RANDOM example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__
    status = crypto_interface_hmac_example();
    if(OK != status)
    {
        printf("HMAC example failed\n");
        goto exit;
    }
    printf("HMAC example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__
    status = crypto_interface_aes_example();
    if(OK != status)
    {
        printf("AES example failed\n");
        goto exit;
    }
    printf("AES example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__
    status = crypto_interface_aes_gcm_example();
    if(OK != status)
    {
        printf("AES-GCM example failed\n");
        goto exit;
    }
    printf("AES-GCM example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__
    status = crypto_interface_tdes_example();
    if(OK != status)
    {
        printf("TDES example failed\n");
        goto exit;
    }
    printf("TDES example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__

    status = crypto_interface_rsa_example();
    if(OK != status)
    {
        printf("RSA example failed. (You may need to re-run the example from the directory with the sample keys and certs)\n");
        goto exit;
    }
    printf("RSA example passed\n");

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1__
    status = crypto_interface_rsa_pss_example();
    if(OK != status)
    {
        printf("RSA-PSS example failed\n");
        goto exit;
    }
    printf("RSA-PSS example passed\n");
#endif

#endif /* ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__ */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
    status = crypto_interface_ecc_example();
    if(OK != status)
    {
        printf("ECC example failed\n");
        goto exit;
    }
    printf("ECC example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
    status = crypto_interface_ecdh_example();
    if(OK != status)
    {
        printf("ECDH example failed\n");
        goto exit;
    }
    printf("ECDH example passed\n");
#endif

/* EC ElGamal is via nanocrypto only, pkcs11 and export are not supported */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL__) && \
    !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && \
    !defined(__ENABLE_DIGICERT_SMP_PKCS11__) && \
    !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    status = crypto_interface_ecc_eg_example();
    if(OK != status)
    {
        printf("ECC ElGamal example failed\n");
        goto exit;
    }
    printf("ECC ElGamal example passed\n");
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) && defined(__ENABLE_DIGICERT_PQC__)
    status = crypto_interface_composite_example();
    if(OK != status)
    {
        printf("ECC/QS COMPOSITE example failed\n");
        goto exit;
    }
    printf("ECC/QS COMPOSITE example passed\n");
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    status = crypto_interface_dh_example();
    if(OK != status)
    {
        printf("DH example failed\n");
        goto exit;
    }
    printf("DH example passed\n");
#endif

    status = crypto_interface_keygen_example();
    if(OK != status)
    {
        printf("Keygen example failed\n");
        goto exit;
    }
    printf("Keygen example passed\n");

    /* CMS Example is primarily an ECC based one */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
    status = crypto_interface_cms_example();
    if(OK != status)
    {
        printf("CMS example failed\n");
        goto exit;
    }
    printf("CMS example passed\n");
#endif

    status = crypto_interface_moccms_streaming_example();
    if(OK != status)
    {
        printf("MOCCMS streaming example failed\n");
        goto exit;
    }
    printf("MOCCMS streaming example passed\n");

exit:

#ifdef __ENABLE_DIGICERT_TAP__
    TAP_EXAMPLE_clean();
#endif

    /* cleanup for DIGICERT_initDigicert(); */
    DIGICERT_freeDigicert();

    if (OK == status)
    {
        printf("All examples run successfully\n");
    }

    return status;
}

sbyte4 main(sbyte4 argc, char *argv[])
{
    return crypto_interface_example_main(argc, argv);
}
