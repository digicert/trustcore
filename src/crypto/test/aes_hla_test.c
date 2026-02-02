/*
 * aes_hla_test.c
 *
 * Unit Test for aes.c
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
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/aesalgo.h"
#include "../../crypto/aes.h"

#include "../../../unit_tests/unittest.h"

#include <stdio.h>
#include <string.h>

/* test vectors */

/*Test vector 0*/
static ubyte Key0[]    = { 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 };
static ubyte IV0[]     = { 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 };
static ubyte Input0[]  = { "Single block msg" };
static ubyte Output0[] = { 0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8, 0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a };

static ubyte Key1[]    = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };
static ubyte IV1[]     = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 };
static ubyte Input1[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
static ubyte Output1[] = { 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a, 0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 };

static void
printBlock(ubyte *pBlock, sbyte blockSize)
{
   int i;
   for (i=0; i<blockSize; i++)
       printf("%02x",pBlock[i]);
   printf("\n");
}

static int
doTest (MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *keyMaterial, sbyte4 keySize, ubyte *iv, ubyte *input, sbyte4 inputLength, ubyte *output, int hint)
{
    ubyte *pTemp = NULL;
    ubyte encryptIV[16];
    ubyte decryptIV[16];
    int errors = 0;
    aesCipherContext* pAesCtxEncrypt = CreateAESCtx(MOC_SYM(hwAccelCtx) keyMaterial, keySize, 1);
    aesCipherContext* pAesCtxDecrypt = CreateAESCtx(MOC_SYM(hwAccelCtx) keyMaterial, keySize, 0);

    pTemp = MALLOC(inputLength);

    memcpy(pTemp, input, inputLength);
    memcpy(encryptIV, iv, 16);
    memcpy(decryptIV, iv, 16);

    printf("Input length = %d\n", inputLength);

    printf("Encrypt input:");
    printBlock(input, inputLength);

    DoAES(MOC_SYM(hwAccelCtx) (BulkCtx)pAesCtxEncrypt, pTemp, inputLength, 1, encryptIV);

    errors += UNITTEST_INT( 1, memcmp(pTemp, output, inputLength), 0 );

    printf("Encrypt output:");
    printBlock(pTemp, inputLength);

    memcpy (pTemp, output, inputLength);

    printf ("\nDecrypt input:");
    printBlock(pTemp, inputLength);

    DoAES(MOC_SYM(hwAccelCtx) (BulkCtx)pAesCtxDecrypt, pTemp, inputLength, 0, decryptIV);

    printf ("Decrypt output:");
    printBlock(pTemp, inputLength);

    errors += UNITTEST_INT(2, memcmp(pTemp, input, inputLength),0 );

    errors += UNITTEST_VALIDPTR(3, pAesCtxEncrypt);
    errors += UNITTEST_VALIDPTR(4, pAesCtxDecrypt);

    DeleteAESCtx(MOC_SYM(hwAccelCtx) &pAesCtxEncrypt);
    DeleteAESCtx(MOC_SYM(hwAccelCtx) &pAesCtxDecrypt);

    free(pTemp);
    return errors;

}

int aes_hla_test_simple()
{

    int retVal = 0;

    sbyte4 hwAccelCtx;


    retVal += doTest(MOC_SYM(hwAccelCtx) Key0, 16, IV0, Input0, sizeof(Input0)-1, Output0, 0);
    retVal += doTest(MOC_SYM(hwAccelCtx) Key1, 16, IV1, Input1, 32, Output1, 1);

    return retVal;
}
