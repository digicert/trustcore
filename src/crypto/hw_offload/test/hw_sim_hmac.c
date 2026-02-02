/**
 * @file hw_sim_hmac.c
 *
 * @brief HMAC - Secure Hash Algorithm Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_HMAC__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define HMAC_MD5        HW_HMAC_MD5
#define HMAC_MD5_quick  HW_HMAC_MD5_quick
#define HMAC_SHA1       HW_HMAC_SHA1
#define HMAC_SHA1_quick HW_HMAC_SHA1_quick
#define HMAC_SHA1Ex     HW_HMAC_SHA1Ex

#include "../../hmac.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef HMAC_MD5
#undef HMAC_MD5_quick
#undef HMAC_SHA1
#undef HMAC_SHA1_quick
#undef HMAC_SHA1Ex

extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, const ubyte* key, sbyte4 keyLen,
         const ubyte* text, sbyte4 textLen,
         const ubyte* textOpt, sbyte4 textOptLen,
         ubyte result[MD5_DIGESTSIZE])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "HMAC_MD5");
    if (OK != status)
        return status;
    
    return HW_HMAC_MD5(hwAccelCtx, key, keyLen, text, textLen, textOpt, textOptLen, result);
}

extern MSTATUS
HMAC_MD5_quick(hwAccelDescr hwAccelCtx, const ubyte* pKey, sbyte4 keyLen,
               const ubyte* pText, sbyte4 textLen,
               ubyte* pResult /* MD5_DIGESTSIZE */)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "HMAC_MD5_quick");
    if (OK != status)
        return status;
    
    return HW_HMAC_MD5_quick(hwAccelCtx, pKey, keyLen, pText, textLen, pResult);
}

extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen,
          ubyte result[SHA_HASH_RESULT_SIZE])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "HMAC_SHA1");
    if (OK != status)
        return status;
    
    return HW_HMAC_SHA1(hwAccelCtx, key, keyLen, text, textLen, textOpt, textOptLen, result);
}

extern MSTATUS
HMAC_SHA1_quick(hwAccelDescr hwAccelCtx, const ubyte* pKey, sbyte4 keyLen,
                const ubyte* pText, sbyte4 textLen,
                ubyte* pResult /* SHA_HASH_RESULT_SIZE */)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "HMAC_SHA1_quick");
    if (OK != status)
        return status;
    
    return HW_HMAC_SHA1_quick(hwAccelCtx, pKey, keyLen, pText, textLen, pResult);
}

extern MSTATUS
HMAC_SHA1Ex(hwAccelDescr hwAccelCtx, const ubyte* key, sbyte4 keyLen,
                        const ubyte* texts[], sbyte4 textLens[],
                        sbyte4 numTexts, ubyte result[SHA_HASH_RESULT_SIZE])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "HMAC_SHA1Ex");
    if (OK != status)
        return status;
    
    return HW_HMAC_SHA1Ex(hwAccelCtx, key, keyLen, texts, textLens, numTexts, result);
}

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_HMAC__) */
