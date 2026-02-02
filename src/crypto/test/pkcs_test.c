/*
 * pkcs_test.c
 *
 * unit test for pkcs.c
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

#include "../../crypto/pkcs.c"
#include "../../common/initmocana.h"
#include "../../asn1/parsecert.h"

#include "../../../unit_tests/unittest.h"


const char* kPayload = "A doctor, a civil engineer and a programmer are discussing whose profession is the oldest.\n"
"\"Surely medicine is the oldest profession,\" says the doctor.\n"
"\"God took a rib from Adam and created Eve and if this isn’t medicine I’ll be...\""
"The civil engineer breaks in:\n"
"\"But before that He created the heavens and the earth from chaos. Now that’s civil engineering to me.\"\n"
"The programmer thinks a bit and then says:\n"
"\"And who do you think created chaos?\"\n";


/*----------------------------------------------------------------------------*/

static const char* gCurrCertFileName;
static const char* gCurrKeyFileName;

/*----------------------------------------------------------------------------*/

static MSTATUS myGetPrivateKeyFun(const void* arg, CStream cs,
                                  ASN1_ITEM* pSerialNumber,
                                  ASN1_ITEM* pIssuerName,
                                  AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte* pKeyBlob = 0;
    ubyte4 keyBlobLen;
    ubyte* buff = 0;
    ubyte4 buffLen;
    hwAccelDescr hwAccelCtx;
    MemFile memFile;
    CStream certCS;
    ASN1_ITEM* pCertRoot = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    /* verify that the pSerialNumber and pIssuer match our own */
    if (OK > ( status = DIGICERT_readFile( gCurrCertFileName, &buff, &buffLen)))
        goto exit;

    MF_attach(&memFile, buffLen, buff);
    CS_AttachMemFile(&certCS, &memFile);

    if (OK > ( status = ASN1_Parse(certCS, &pCertRoot)))
        goto exit;

    if (OK > ( status = X509_checkCertificateIssuerSerialNumber( pIssuerName, pSerialNumber,
                                                                cs, ASN1_FIRST_CHILD(pCertRoot), certCS)))
    {
        goto exit;
    }

    if (OK > (status = DIGICERT_readFile( gCurrKeyFileName, &pKeyBlob, &keyBlobLen)))
        goto exit;

    /* load the key */
    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLen, pKey)))
        goto exit;

exit:

    if (pKeyBlob)
    {
        FREE(pKeyBlob);
    }
    if (buff)
    {
        FREE(buff);
    }

    if (pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRoot);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return status;
}

/*----------------------------------------------------------------------------*/

static int
TestDecryptEnvelopedPKCS7Data( MOC_RSA(hwAccelDescr hwAccelCtx) int hint,
                              CStream cs,
                              ASN1_ITEMPTR pEnvelopedData,
                              const char* certFileName,
                              const char* keyBlobFileName)
{
    int retVal = 0;
    ubyte* decryptedInfo = 0;
    sbyte4 decryptedInfoLen, cmpResult;

    /* set up the globals used by myGetPrivateKeyFun */
    gCurrCertFileName = certFileName;
    gCurrKeyFileName = keyBlobFileName;

    retVal += UNITTEST_STATUS(hint, PKCS7_DecryptEnvelopedData(MOC_HW(hwAccelCtx)
                                                               pEnvelopedData,
                                                               cs,
                                                               NULL,
                                                               myGetPrivateKeyFun,
                                                               &decryptedInfo,
                                                               &decryptedInfoLen));
    if (retVal) goto exit;

    retVal += UNITTEST_INT(hint, decryptedInfoLen, (sbyte4) DIGI_STRLEN(kPayload));
    if (retVal) goto exit;

    DIGI_MEMCMP((const ubyte*) kPayload, decryptedInfo, decryptedInfoLen, &cmpResult);
    retVal += UNITTEST_TRUE( hint, 0 == cmpResult);


exit:

    FREE( decryptedInfo);

    return retVal;
    
}


/*----------------------------------------------------------------------------*/

int pkcs_test_PKCS7_envelopWithCertificates()
{
    int retVal = 0;
    ubyte* certs[2] = { 0};
    ubyte4 certlens[2];
    ubyte* enveloped = 0;
    ubyte4 envelopedLen;
    hwAccelDescr hwAccelCtx;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pEnvelopedRoot = 0, pEnvelopedData;

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
    
    retVal += UNITTEST_STATUS( 0,DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) return retVal;

    UNITTEST_STATUS_GOTO( 0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    /* use the same files as the PKCS7 tests */
    UNITTEST_STATUS_GOTO( 0, DIGICERT_readFile("selfcert.der", certs, certlens),
                         retVal, exit);

    UNITTEST_STATUS_GOTO( 0, DIGICERT_readFile("ecc_selfcert.der", certs+1, certlens+1),
                         retVal, exit);


    UNITTEST_STATUS_GOTO( 0, PKCS7_EnvelopWithCertificates(2, certs, certlens, aes256CBC_OID,
                                  kPayload, DIGI_STRLEN(kPayload),
                                  &enveloped, &envelopedLen),
                         retVal, exit);

    DIGICERT_writeFile("pkcs_test_output.der", enveloped, envelopedLen);

    /* decrypt the message now -- most of this code comes frpm pkcs7_test.c */
    MF_attach(&mf, envelopedLen, enveloped);
    CS_AttachMemFile(&cs, &mf);

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pEnvelopedRoot), retVal, exit);

    pEnvelopedData = ASN1_FIRST_CHILD(pEnvelopedRoot);
    
    /* This generate a content info unlinked to anything -> the SEQUENCE
     expected by the PKCS7 routine is the first child of Root then */
    retVal += TestDecryptEnvelopedPKCS7Data(MOC_RSA(hwAccelCtx) 0, cs,
                                            pEnvelopedData,
                                            "selfcert.der",
                                            "keyblobFile.dat");

    retVal += TestDecryptEnvelopedPKCS7Data(MOC_RSA(hwAccelCtx) 1, cs,
                                            pEnvelopedData,
                                            "ecc_selfcert.der",
                                            "ecc_keyblobFile.dat");

exit:

    FREE(certs[0]);
    FREE(certs[1]);

    if (pEnvelopedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pEnvelopedRoot);
    }

    FREE(enveloped);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();
    
    return 0;
}
