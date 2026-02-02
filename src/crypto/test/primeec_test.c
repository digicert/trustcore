/*
 * primeec_test.c
 *
 * unit test for primeec.c
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
#define __ENABLE_DIGICERT_SOFT_DIVIDE__

#include "../primeec.c"

#include "../../../unit_tests/unittest.h"

#include "../../common/vlong.h"
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif

static MocCtx gpMocCtx = NULL;

static ubyte4 gVals[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 123, 345, 3456, 0xFFFF, 0xFFFFEEE, 0x80000000,
                          0xEFFFFFFF, 0xFFFFFFFF };

/*---------------------------------------------------------------------*/

int primeec_test_divide()
{
    ubyte4 res;
    int i, j, retval = 0;

    for (i = 0; i < COUNTOF(gVals); ++i)
    {
        for (j = 0; j < COUNTOF(gVals); ++j)
        {
            res = EC_unsignedDivide( gVals[i], gVals[j]);
            retval += UNITTEST_INT((i << 16| j), res, gVals[i]/gVals[j]);
        }
    }

    return retval;
}


ubyte gTestModulus[][sizeof(Pmu_521)] = {
{ 
    0x0a, 0xfc, 0x6f, 0x01, 0x4a, 0xa5, 0xcd, 0x42, 0x96, 0xae, 0x53, 0xfe, 0xea, 0x74, 0xd5, 0x9e,
    0x7a, 0xb9, 0x00, 0x14, 0x25, 0x7f, 0x03, 0xaa, 0xcf, 0xaa, 0xe5, 0x8d, 0xcd, 0xc8, 0x8a, 0x5d,
    0x7b, 0xa6, 0x83, 0x76, 0x88, 0x7b, 0x5c, 0x82, 0x0a, 0x51, 0x63, 0x6b, 0x85, 0x39, 0x76, 0x9d,
    0x0d, 0x2d, 0x16, 0x7b, 0x5d, 0x82, 0xd9, 0xa4, 0xdb, 0xd2, 0x6f, 0x40, 0x08, 0xab, 0xc5, 0xd7,
    0xba, 0x4a, 0xce, 0xb9 
},
{
    0x13, 0xa7, 0x1f, 0x74, 0xa9, 0x75, 0xeb, 0x7b, 0xbd, 0x9e, 0xd7, 0x84, 0x71, 0x5e, 0x4b, 0x84, 
    0xa2, 0x30, 0x0b, 0x8a, 0x38, 0xdf, 0x37, 0x70, 0xef, 0x1b, 0x73, 0x45, 0xb9, 0x4b, 0xc3, 0x1e, 
    0x9c, 0xd0, 0xe3, 0xc6, 0x91, 0x86, 0xfd, 0xf8, 0x5b, 0x65, 0x20, 0xde, 0x22, 0x20, 0x73, 0x05, 
    0x3a, 0x1f, 0x80, 0x19, 0x12, 0xf2, 0x6c, 0x1c, 0x52, 0x70, 0x48, 0xd4, 0x89, 0x57, 0x22, 0x2a, 
    0xbc, 0x02, 0xd0, 0xc0
},
{ 
    0x33, 0x21, 0xdf, 0x66, 0x32, 0x0c, 0x37, 0xa2, 0x9d, 0xcb, 0x67, 0x26, 0xc4, 0x5c, 0x2a, 0x7e, 
    0x22, 0xaa, 0x4d, 0x84, 0x5d, 0x0f, 0xd7, 0x06, 0xe9, 0x99, 0x3c, 0x74, 0x7a, 0xeb, 0xac, 0xa2, 
    0xc6, 0x1c, 0xe1, 0x13, 0x19, 0x30, 0x1f, 0x9d, 0xca, 0xaa, 0x25, 0x9a, 0x8f, 0x10, 0xac, 0x93, 
    0x7a, 0x4f, 0x8a, 0x42, 0x6b, 0x01, 0x70, 0x1a, 0x2b, 0x1b, 0xd9, 0x9a, 0x3b, 0xa2, 0x26, 0xaa, 
    0xd8, 0xe1, 0x7b, 0xd7
},
{ 
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x9d, 0xcb, 0x67, 0x26, 0xc4, 0x5c, 0x2a, 0x7e, 
    0x22, 0xaa, 0x4d, 0x84, 0x5d, 0x0f, 0xd7, 0x06, 0xe9, 0x99, 0x3c, 0x74, 0x7a, 0xeb, 0xac, 0xa2, 
    0xc6, 0x1c, 0xe1, 0x13, 0x19, 0x30, 0x1f, 0x9d, 0xca, 0xaa, 0x25, 0x9a, 0x8f, 0x10, 0xac, 0x93, 
    0x7a, 0x4f, 0x8a, 0x42, 0x6b, 0x01, 0x70, 0x1a, 0x2b, 0x1b, 0xd9, 0x9a, 0x3b, 0xa2, 0x26, 0xaa, 
    0xd8, 0xe1, 0x7b, 0xd7
}
};

/*---------------------------------------------------------------------*/
int primeec_test_barrett_mu()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_RSA_SIMPLE__ )
    int i;

    sbyte4 resCmp;
    pf_unit* test_mu = 0;
    pf_unit* test_modulus = 0;
    vlong* vModulus = 0;
    vlong* vMu = 0;
    vlong* pQueue = 0;
    ubyte buffer[sizeof(Pmu_521)]; 

    /* Init digicert for the rng */
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    if (OK > (MSTATUS)(retVal = DIGICERT_initialize(&setupInfo, NULL)))
        return retVal;

    test_mu = (pf_unit*) MALLOC( sizeof( Pmu_521));
    test_modulus = (pf_unit*) MALLOC( sizeof(Pmu_521));

    if ( !test_mu)
    {
        retVal += UNITTEST_TRUE(0, test_mu != 0);
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC_P192__
    DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
    retVal += UNITTEST_STATUS(0, 
                BI_barrettMu( COUNTOF(Pmu_192) - 1, test_mu, Pn_192));    
    DIGI_MEMCMP( (ubyte*) Pmu_192, (ubyte*) test_mu, sizeof(Pmu_192), &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);
#endif

    DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
    retVal += UNITTEST_STATUS(0, 
                BI_barrettMu( COUNTOF(Pmu_224) - 1, test_mu, Pn_224));    
    DIGI_MEMCMP( (ubyte*) Pmu_224, (ubyte*) test_mu, sizeof(Pmu_224), &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);

    DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
    retVal += UNITTEST_STATUS(0, 
                BI_barrettMu( COUNTOF(Pmu_256) - 1, test_mu, Pn_256));
    DIGI_MEMCMP( (ubyte*) Pmu_256, (ubyte*) test_mu, sizeof(Pmu_256), &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);

    DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
    retVal += UNITTEST_STATUS(0, 
                BI_barrettMu( COUNTOF(Pmu_384) - 1, test_mu, Pn_384));
    DIGI_MEMCMP( (ubyte*) Pmu_384, (ubyte*) test_mu, sizeof(Pmu_384), &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);

    DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
    retVal += UNITTEST_STATUS(0, 
                BI_barrettMu( COUNTOF(Pmu_521) - 1, test_mu, Pn_521));
    DIGI_MEMCMP( (ubyte*) Pmu_521, (ubyte*) test_mu, sizeof(Pmu_521), &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);


    if ( sizeof(pf_unit) == sizeof(vlong_unit))
    {

        for (i = 0; i < COUNTOF(gTestModulus); ++i)
        {
            VLONG_vlongFromByteString(gTestModulus[i], sizeof(Pmu_521)-sizeof(vlong_unit), &vModulus, &pQueue);
            VLONG_newBarrettMu(&vMu, vModulus, &pQueue);

            DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
            DIGI_MEMSET( (ubyte*) test_modulus, 0, sizeof(Pmu_521));

            DIGI_MEMCPY( test_modulus, vModulus->pUnits, sizeof(vlong_unit) * vModulus->numUnitsUsed);
            BI_barrettMu( vModulus->numUnitsUsed, test_mu, test_modulus);

            DIGI_MEMCMP( (ubyte*) vMu->pUnits, (ubyte*) test_mu, sizeof(vlong_unit) * vMu->numUnitsUsed, &resCmp); 
            retVal += UNITTEST_TRUE(i, 0 == resCmp);
           
            VLONG_freeVlong(&vModulus, &pQueue);
            VLONG_freeVlong(&vMu, &pQueue);
        }

#if !defined(__ENABLE_DIGICERT_RNG_DRBG_ECC__)     /* too slow for this test */

        /* random tests -- compare with vlong */
        for (i = 0; i < 100000; ++i)
        {
            RANDOM_numberGenerator(g_pRandomContext, buffer, sizeof(Pmu_521)-sizeof(vlong_unit));
            VLONG_vlongFromByteString(buffer, sizeof(Pmu_521)-sizeof(vlong_unit), &vModulus, &pQueue);
            VLONG_newBarrettMu(&vMu, vModulus, &pQueue);

            DIGI_MEMSET( (ubyte*) test_mu, 0, sizeof(Pmu_521));
            DIGI_MEMSET( (ubyte*) test_modulus, 0, sizeof(Pmu_521));

            DIGI_MEMCPY( test_modulus, vModulus->pUnits, sizeof(vlong_unit) * vModulus->numUnitsUsed);
            BI_barrettMu( vModulus->numUnitsUsed, test_mu, test_modulus);

            DIGI_MEMCMP( (ubyte*) vMu->pUnits, (ubyte*) test_mu, sizeof(vlong_unit) * vMu->numUnitsUsed, &resCmp); 
            retVal += UNITTEST_TRUE(0, 0 == resCmp);
           
            VLONG_freeVlong(&vModulus, &pQueue);
            VLONG_freeVlong(&vMu, &pQueue);

        }

#endif

    }

exit:

    if (test_modulus)
    {
        FREE(test_modulus);
    }

    if ( test_mu)
    {
        FREE(test_mu);
    }

    VLONG_freeVlongQueue( &pQueue);
    DIGICERT_freeDigicert();

#endif

    return retVal;    
}

/*----------------------------------------------------------------------------*/

int mod_invert_group_order_test( int hint, PEllipticCurvePtr pEC,
                                randomContext* pRandomContext)
{
    int retVal = 0;
    sbyte4 resCmp;
    ECCKey* pKey1 = 0;
    PrimeFieldPtr pPF = EC_getUnderlyingField(pEC);
    PFEPtr pInverse = 0, pResX = 0, pResY = 0;
    
    UNITTEST_STATUS_GOTO( hint, EC_newKey( pEC, &pKey1), retVal, exit);
    UNITTEST_STATUS_GOTO( hint, EC_generateKeyPair( pEC, RANDOM_rngFun,
                                                   pRandomContext, pKey1->k,
                                                   pKey1->Qx, pKey1->Qy),
                         retVal, exit);

    /* compute the inverse of pKey1->k modulo group order */
    UNITTEST_STATUS_GOTO( hint, PRIMEFIELD_newElement(pPF, &pInverse),
                         retVal, exit);
    UNITTEST_STATUS_GOTO( hint,
                         PRIMEFIELD_inverseAux(pPF->n, pInverse, pKey1->k, pEC->n),
                         retVal, exit);

    /* multipy key point by inverse */
    UNITTEST_STATUS_GOTO( hint, PRIMEFIELD_newElement(pPF, &pResX),
                         retVal, exit);
    UNITTEST_STATUS_GOTO( hint, PRIMEFIELD_newElement(pPF, &pResY),
                         retVal, exit);

    UNITTEST_STATUS_GOTO( hint,
                         EC_multiplyPoint(pPF, pResX, pResY, pInverse, pKey1->Qx, pKey1->Qy),
                         retVal, exit);


    retVal += UNITTEST_TRUE(hint, 0 == PRIMEFIELD_cmp(pPF, pResX, pEC->pPx));
    retVal += UNITTEST_TRUE(hint, 0 == PRIMEFIELD_cmp(pPF, pResY, pEC->pPy));

    /* test the EC_verifyPoint static routine */
    UNITTEST_STATUS_GOTO(hint, EC_verifyPoint(pEC, pKey1->Qx, pKey1->Qy),
                         retVal, exit);

#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
    /* test the routine that computes Y from X */
    EC_computeYFromX(pEC, pKey1->Qx, pResY);

    retVal += UNITTEST_STATUS(hint, EC_verifyPoint(pEC, pKey1->Qx, pResY));

    resCmp = PRIMEFIELD_cmp(pEC->pPF, pKey1->Qy, pResY);
    if ( 0 != resCmp)
    {
        /* if this is not the Y, then it's the other Y, the negative of it, 
         i.e. p-Y */
        PRIMEFIELD_copyElement(pEC->pPF, pResX, (ConstPFEPtr) pEC->pPF->units);
        PRIMEFIELD_subtract(pEC->pPF, pResX, pResY);

        resCmp = PRIMEFIELD_cmp( pEC->pPF, pKey1->Qy, pResX);
    }

    /* negative test: change a single bit */
    pKey1->Qy->units[0] ^= 0x08;

    retVal += UNITTEST_TRUE(hint, ERR_FALSE == EC_verifyPoint(pEC, pKey1->Qx, pKey1->Qy));
#endif
    
exit:

    PRIMEFIELD_deleteElement(pPF, &pInverse);
    PRIMEFIELD_deleteElement(pPF, &pResX);
    PRIMEFIELD_deleteElement(pPF, &pResY);

    EC_deleteKey(&pKey1);
    
    return retVal;
}


/*---------------------------------------------------------------------------*/

int primeec_test_mod_invert_group_order()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    MSTATUS status = OK;
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal += mod_invert_group_order_test(256, EC_P256, g_pRandomContext);
    retVal += mod_invert_group_order_test(384, EC_P384, g_pRandomContext);
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += mod_invert_group_order_test(521, EC_P521, g_pRandomContext);
#endif

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}


/*----------------------------------------------------------------------------*/

static void print_element(PEllipticCurvePtr pEC, ConstPFEPtr pElem)
{
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    int j;
    ubyte* buffer = 0;
    sbyte4 bufferLen;

    PRIMEFIELD_getAsByteString(pEC->pPF, pElem, &buffer, &bufferLen);

    for (j = 0; j < bufferLen; ++j)
    {
        printf("%02x ", buffer[j]);
    }
    
    printf("\n");
    
    FREE(buffer);
#endif
}


#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)

/*----------------------------------------------------------------------------*/

sbyte4
FastRandom(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    int i, val;

    for (i = 0; i < length / sizeof(int); ++i)
    {
        val = rand();
        memcpy( buffer, &val, sizeof(int));
        buffer += sizeof(int);
    }

    val = rand();
    memcpy(buffer, &val, length % sizeof(int));

    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

int multiplications_test(int hint, PEllipticCurvePtr pEC)
{
    int i, retVal = 0;
    PFEPtr randomK = 0;
    ComputeHelper* pBlock1 = 0;
    ComputeHelper* pBlock2 = 0;
    int cmpRes;
    MSTATUS status, fstatus;

    hint <<= 16;

    UNITTEST_STATUS_GOTO(hint, PRIMEFIELD_newElement(pEC->pPF, &randomK),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, EC_newComputeHelper(pEC->pPF->n, &pBlock1),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, EC_newComputeHelper(pEC->pPF->n, &pBlock2),
                         retVal, exit);


    for (i = 0; i < 1000; ++i)
    {
        UNITTEST_STATUS_GOTO(hint + i, PRIMEFIELD_setToUnsigned(pEC->pPF, randomK, i),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint + i, EC_multiplyPointJacobiLRBSimple(pEC->pPF,
                                                                       randomK,
                                                                       pEC->pPx,
                                                                       pEC->pPy,
                                                                       pBlock1),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint + i, EC_multiplyPointJacobi(pEC->pPF,
                                                              randomK,
                                                              pEC->pPx,
                                                              pEC->pPy,
                                                              pBlock2),
                             retVal, exit);

        status = EC_convertToAffine(pEC->pPF, pBlock1);
        fstatus = EC_convertToAffine(pEC->pPF, pBlock2);
        retVal += UNITTEST_TRUE(hint + i, status == fstatus);
        if (OK == status)
        {
            cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->X1, pBlock2->X1);
            retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);
        
            cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->Y1, pBlock2->Y1);
            retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);
            
            if (retVal)
            {
                print_element(pEC, pBlock1->X1);
                print_element(pEC, pBlock2->X1);
                print_element(pEC, pBlock1->Y1);
                print_element(pEC, pBlock2->Y1);
                print_element(pEC, randomK);
            }
        }
    }

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)

    for (i = 0; i < 100; ++i)
    {
        UNITTEST_STATUS_GOTO(hint + i, EC_generateRandomNumber(pEC, randomK,
                                                               FastRandom, NULL),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint + i, EC_multiplyPointJacobiLRBSimple(pEC->pPF,
                                                                       randomK,
                                                                       pEC->pPx,
                                                                       pEC->pPy,
                                                                       pBlock1),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint + i, EC_multiplyPointJacobi(pEC->pPF,
                                                              randomK,
                                                              pEC->pPx,
                                                              pEC->pPy,
                                                              pBlock2),
                             retVal, exit);

        status = EC_convertToAffine(pEC->pPF, pBlock1);
        fstatus = EC_convertToAffine(pEC->pPF, pBlock2);
        retVal += UNITTEST_TRUE(hint + i, status == fstatus);
        if (OK == status)
        {
            cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->X1, pBlock2->X1);
            retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);
            
            cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->Y1, pBlock2->Y1);
            retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);
            
            if (retVal)
            {
                print_element(pEC, pBlock1->X1);
                print_element(pEC, pBlock2->X1);
                print_element(pEC, pBlock1->Y1);
                print_element(pEC, pBlock2->Y1);
                print_element(pEC, randomK);
            }
        }
    }
#endif

exit:

    PRIMEFIELD_deleteElement(pEC->pPF, &randomK);

    EC_deleteComputeHelper(pEC->pPF, &pBlock1);
    EC_deleteComputeHelper(pEC->pPF, &pBlock2);


    return retVal;
}


/*----------------------------------------------------------------------------*/

int primeec_test_multiplications()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;


    retVal += multiplications_test(256, EC_P256);
    retVal += multiplications_test(384, EC_P384);
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += multiplications_test(521, EC_P521);
#endif
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return retVal;
}


/*----------------------------------------------------------------------------*/

int jacobiadditions_test(int hint, PEllipticCurvePtr pEC)
{
    int i, j, retVal = 0;
    PFEPtr mult = 0;
    ComputeHelper* pBlock1 = 0;
    ComputeHelper* pBlock2 = 0;
    ComputeHelper* pBlock3 = 0;
    int cmpRes;

    hint <<= 16;


    UNITTEST_STATUS_GOTO(hint, PRIMEFIELD_newElement(pEC->pPF, &mult),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, EC_newComputeHelper(pEC->pPF->n, &pBlock1),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, EC_newComputeHelper(pEC->pPF->n, &pBlock2),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, EC_newComputeHelper(pEC->pPF->n, &pBlock3),
                         retVal, exit);



    for (i = 3; i < 203; i += 2)
    {

        UNITTEST_STATUS_GOTO(hint + i, PRIMEFIELD_setToUnsigned(pEC->pPF, mult, i),
                             retVal, exit);

        /* compute the triple using the affine-jacobi method */
        UNITTEST_STATUS_GOTO(hint + i, EC_multiplyPointJacobi(pEC->pPF,
                                                          mult,
                                                          pEC->pPx,
                                                          pEC->pPy,
                                                          pBlock3),
                             retVal, exit);


        /* set up pBlock1 and pBlock2 */
        UNITTEST_STATUS_GOTO(hint + i, EC_setJacobiPt( pEC->pPF,
                                                  pBlock1->X1,
                                                  pBlock1->Y1,
                                                  pBlock1->Z1,
                                                  pEC->pPx,
                                                  pEC->pPy),
                             retVal, exit);


        UNITTEST_STATUS_GOTO(hint + i, EC_setJacobiPt( pEC->pPF,
                                                  pBlock2->X1,
                                                  pBlock2->Y1,
                                                  pBlock2->Z1,
                                                  pEC->pPx,
                                                  pEC->pPy),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint + i, EC_doubleJacobiPoint( pEC->pPF, pBlock2),
                         retVal, exit);

        /* repeatedly add the two jacobi points  */
        for (j = 3; j <= i; j+=2)
        {
            UNITTEST_STATUS_GOTO(hint + i, EC_addJacobiPoint( pEC->pPF, pBlock1, pBlock2),
                             retVal, exit);
        }

        UNITTEST_STATUS_GOTO(hint + i, EC_convertToAffine(pEC->pPF, pBlock3), retVal, exit);
        UNITTEST_STATUS_GOTO(hint + i, EC_convertToAffine(pEC->pPF, pBlock1), retVal, exit);

        cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->X1, pBlock3->X1);
        retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);

        cmpRes = PRIMEFIELD_cmp( pEC->pPF, pBlock1->Y1, pBlock3->Y1);
        retVal += UNITTEST_TRUE(hint + i, 0 == cmpRes);
        
        if (retVal)
        {
            print_element(pEC, pBlock1->X1);
            print_element(pEC, pBlock3->X1);
            print_element(pEC, pBlock1->Y1);
            print_element(pEC, pBlock3->Y1);
        }
    }


exit:

    PRIMEFIELD_deleteElement(pEC->pPF, &mult);
    
    EC_deleteComputeHelper(pEC->pPF, &pBlock1);
    EC_deleteComputeHelper(pEC->pPF, &pBlock2);
    EC_deleteComputeHelper(pEC->pPF, &pBlock3);

    
    return retVal;
}


/*----------------------------------------------------------------------------*/

int primeec_test_jacobiaddition()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;


    retVal += jacobiadditions_test(256, EC_P256);
    retVal += jacobiadditions_test(384, EC_P384);
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += jacobiadditions_test(521, EC_P521);
#endif
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return retVal;
}


