/*
 * pkcs12_test.c
 *
 * unit test for pkcs12.c
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
#include "../../common/debug_console.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../crypto/crypto.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/md5.h"
#include "../../common/initmocana.h"
#include "../../common/vlong.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../asn1/derencoder.h"
#include "../../common/random.h"
#include "../../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/hmac.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/arc4.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/arc2.h"
#include "../../crypto/rc2algo.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs12.h"
#include "../../crypto/pkcs8.h"
#include "../../crypto/ca_mgmt.h"



#if _DEBUG
#include <stdio.h>
#endif

#include "../../../unit_tests/unittest.h"

#ifdef _DEBUG
#define __P12_DEBUG__
#define __TEST_WITH_OPENSSL__
#include <string.h>
#endif

/* key is DER encoded PrivateKeyInfo defined in PKCS#8 */
MSTATUS PKCS12_Encrypt_testContentHandler(const void* pContext, contentTypes type,
                                          ubyte4 extraInfo, const ubyte* content,
                                          ubyte4 contentLen)
{
    MSTATUS status = OK;

    ubyte* keyBlob = NULL;
    ubyte4 keyBlobLen;

    switch (type)
    {
    case KEYINFO:
        if (OK > (status = PKCS8_decodePrivateKeyDER((ubyte*)content, contentLen, &keyBlob, &keyBlobLen)))
            goto exit;
#ifdef __P12_DEBUG__
        if (OK > (status = DIGICERT_writeFile(FILE_PATH("pkcs12keyBlob.dat"), keyBlob, keyBlobLen)))
            goto exit;
#endif

#ifdef __P12_DEBUG__
        printf("KEYINFO obtained for testcase = %d \n", *(int *)(pContext));
#endif
        break;
    case CERT:
#ifdef __P12_DEBUG__
        if (OK > (status = DIGICERT_writeFile((FILE_PATH("pkcs12cert.der")), (ubyte*)content, contentLen)))
            goto exit;
        printf("CERT obtained for testcase = %d \n", *(int *)(pContext));
#endif
        break;
    default:
        break;
    }

exit:

    if (keyBlob)
    {
        FREE(keyBlob);
    }
    return status;
}

static MSTATUS myValCertFun(const void* arg, CStream cs, ASN1_ITEM* pLeafCertificate, int chainLength)
{
#ifdef __P12_DEBUG__
    printf("I AM IN mpValCertFun \n");
#endif
    return OK;
}

static MSTATUS myGetPrivateKeyFun(const void* arg,
                                  CStream cs,
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
    if (OK > ( status = DIGICERT_readFile(FILE_PATH("../test/selfcert.der"), &buff, &buffLen)))
        goto exit;

    MF_attach(&memFile, buffLen, buff);
    CS_AttachMemFile(&certCS, &memFile);

    if (OK > ( status = ASN1_Parse(certCS, &pCertRoot)))
        goto exit;

    if (OK > ( status = X509_checkCertificateIssuerSerialNumber( pIssuerName,
                                                                pSerialNumber,
                                                                cs,
                                                                ASN1_FIRST_CHILD(pCertRoot),
                                                                certCS)))
    {
        goto exit;
    }
    
    if (OK > (status = DIGICERT_readFile(FILE_PATH("../test/keyblobFile.dat"),
                                       &pKeyBlob, &keyBlobLen)))
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

typedef struct PKCS12PrivacyDataMap
{
    ubyte4                    startDataIndex;
    ubyte4                    numDataContents;
    PKCS12PrivacyModeConfig   pkcs12PrivacyModeConfig;
} PKCS12PrivacyDataMap;

typedef struct PKCS12InputParams
{
    byteBoolean                isRandomContextPresent;
    ubyte4                     integrityMode;
    ubyte*                     password;
    ubyte4                     passwordLen;
    ubyte*                     pKeyFilePath;
    ubyte*                     pDigestAlgo;
    ubyte*                     pSignerCertPath;
    PKCS12PrivacyDataMap**     ppPrivacyDataMap;
    ubyte4                     numPrivacyData;
} PKCS12TestInputParams;

MSTATUS TestPKCS12Encryption(MOC_SYM(hwAccelDescr hwAccelCtx)
                             randomContext* pRandomContext,
                             ubyte4 integrityMode,
                             ubyte* password,
                             ubyte4 passwordLen,
                             ubyte* pKeyFilePath,
                             ubyte* pDigestAlgo,
                             ubyte* pSignerCertPath,
                             PKCS12PrivacyDataMap* pPrivacyDataMap,
                             PKCS12DataObject pkcs12DataObject[],
                             ubyte4 testcase)
{
    MSTATUS        status = OK;
    AsymmetricKey  key;
    ubyte*         pKeyBlob = NULL;
    ubyte4         keyBlobLen;
    ubyte*         pCertBlob = NULL;
    ubyte4         certBlobLen;
    CStream        cs;
    CStream        csArg[1];
    MemFile        memFile;
    ubyte*         pPKCS12CertFile = NULL;
    ubyte4         pkcs12CertFileNum = 0;
    ASN1_ITEMPTR   pPKCS12ItemPtr = NULL;
    PKCS7_Callbacks  cbk = {0};

    cbk.valCertFun = &myValCertFun;
    cbk.getPrivKeyFun = &myGetPrivateKeyFun;

    if (pKeyFilePath)
    {
        if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
            goto exit;

        if (OK > (status = DIGICERT_readFile(pKeyFilePath, &pKeyBlob, &keyBlobLen)))
            goto exit;

        if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLen, &key)))
            goto exit;
    }

    if (pSignerCertPath)
    {
        if (OK > (status = DIGICERT_readFile(pSignerCertPath, &pCertBlob, &certBlobLen)))
            goto exit;
        MF_attach(&memFile, certBlobLen, pCertBlob);
        CS_AttachMemFile(&cs, &memFile);
        csArg[0] = cs;
    }

    if (OK > (status = PKCS12_EncryptPFXPdu(MOC_RSA(hwAccelCtx)
                                            pRandomContext,
                                            integrityMode,
                                            password,
                                            passwordLen,
                                            ((pKeyFilePath) ? &key : NULL),
                                            pDigestAlgo,
                                            ((pSignerCertPath) ? csArg : NULL),
                                            (pSignerCertPath) ? 1 : 0,
                                            (pPrivacyDataMap ? &pPrivacyDataMap->pkcs12PrivacyModeConfig : NULL),
                                            ((NULL == pPrivacyDataMap) ? NULL : pkcs12DataObject + pPrivacyDataMap->startDataIndex),
                                            (NULL == pPrivacyDataMap ? 0 : pPrivacyDataMap->numDataContents),
                                            &pPKCS12CertFile,
                                            &pkcs12CertFileNum)))
        goto exit;

#ifdef __TEST_WITH_OPENSSL__
    {
      sbyte    buffer[40];

      sprintf(buffer, "test_%d.p12", testcase);
      if (OK > (status = DIGICERT_writeFile((const sbyte *)FILE_PATH(buffer), pPKCS12CertFile, pkcs12CertFileNum)))
        goto exit;
    }
#endif

    MF_attach(&memFile, pkcs12CertFileNum, pPKCS12CertFile);
    CS_AttachMemFile(&cs, &memFile);

    if (OK > (status = ASN1_Parse(cs, &pPKCS12ItemPtr)))
        goto exit;

    if (OK > (status = PKCS12_ExtractInfo(MOC_RSA(hwAccelCtx)
                                           pPKCS12ItemPtr,
                                          cs,
                                          (const ubyte *)"\x00\x73\x00\x65\x00\x63\x00\x72\x00\x65\x00\x74\x00\x00",
                                          14/*passwordLen*/,
                                          0,
                                          &cbk,
                                          &testcase,
                                          &PKCS12_Encrypt_testContentHandler)))
    {
        goto exit;
    }

exit:
    if (pKeyBlob)
      FREE(pKeyBlob);
    if (pCertBlob)
      FREE(pCertBlob);
    if (pKeyFilePath)
      CRYPTO_uninitAsymmetricKey(&key, NULL);
    if (pPKCS12CertFile)
      FREE(pPKCS12CertFile);
    if (pPKCS12ItemPtr)
      TREE_DeleteTreeItem((TreeItem *)pPKCS12ItemPtr);

    return status;
}

int TestIntegrityModeWithVariousPrivacyModes(MOC_SYM(hwAccelDescr hwAccelCtx)
                                             randomContext* pRandomContext,
                                             PKCS12TestInputParams integrityParams[],
                                             ubyte4 integrityParamsCount,
                                             PKCS12DataObject pkcs12DataObject[],
                                             byteBoolean pass,
                                             ubyte4 hint)
{
    MSTATUS      status = OK;
    ubyte4       iter, iterPrivacyMode, num;
    int          retVal = 0;

    for (iter = 0, num = 0; iter < integrityParamsCount; iter++)
    {
        for (iterPrivacyMode = 0; iterPrivacyMode < integrityParams[iter].numPrivacyData; iterPrivacyMode++)
        {
            status = TestPKCS12Encryption(MOC_SYM(hwAccelCtx)
                                          integrityParams[iter].isRandomContextPresent ? pRandomContext: NULL,
                                          integrityParams[iter].integrityMode,
                                          integrityParams[iter].password,
                                          integrityParams[iter].passwordLen,
                                          integrityParams[iter].pKeyFilePath,
                                          integrityParams[iter].pDigestAlgo,
                                          integrityParams[iter].pSignerCertPath,
                                          integrityParams[iter].ppPrivacyDataMap ? integrityParams[iter].ppPrivacyDataMap[iterPrivacyMode] : NULL,
                                          pkcs12DataObject,
                                          hint + num + iterPrivacyMode);
#ifdef __P12_DEBUG__
            printf("TestPasswordIntegrityModeWithVariousParameters, testcase = %d, status = %d \n", (hint + num + iterPrivacyMode), status);
#endif
            if (pass)
              retVal += UNITTEST_TRUE(hint + num + iterPrivacyMode, (OK == status));
            else
              retVal += UNITTEST_TRUE(hint + num + iterPrivacyMode, (OK > status));
        }
        num += iterPrivacyMode;
    }

    return retVal;
}

int pkcs12_encrypt_test_all()
{
    int                        retVal = 0;
    MSTATUS                    status = OK;
    hwAccelDescr               hwAccelCtx;
    AsymmetricKey              privateDataKey;
    ubyte*                     pPrivateKeyBlob;
    ubyte4                     privateKeyBlobLen = 0;
    ubyte*                     pDataCert = NULL;
    ubyte4                     dataCertLen = 0;
    CStream*                   csPubKey[1];
    CStream                    csPubKey0;
    MemFile                    memFilePubKey0;//, memFilePubKey1;
    ubyte*                     pCSPubKey0Cert = NULL;
    //ubyte*                     pCSPubKey1Cert = NULL;
    ubyte4                     csPubKeyLen = 0;
    const ubyte                dummy_OID[] = {8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x03, 0x02};

    PKCS12AttributeUserValue   attrVal[] = 
    {
        {PKCS12_AttributeType_friendlyName, (ubyte *)"this is friendly name ", 22}, /* this has to be in BMP string format, this is just an example*/
        {PKCS12_AttributeType_localKeyId, (ubyte *)"this is local key id", 20}
    };
    PKCS12AttributeUserValue*  pAttrValArr [] =
    {
        &attrVal[0], &attrVal[1]
    };

    PKCS12DataObject           dataObject [] = {
      /*privacy mode, encKeyType, key password, password len, private key, cert type, certificate, certificate len, crl, crl len, attr, attr len*/
      /* Certificates and CRLs are assigned below. The assignment is done obly for specific instances of dataObject*/
      /*Password privacy*/
      /*PKCS#8 Shrouded Keys - 0*/
      {PKCS12Mode_Privacy_none, PCKS8_EncryptionType_pkcs5_v2_3des, (ubyte *)"secret", 6, &privateDataKey, 0, NULL, 0, NULL, 0, NULL, 0},
      /*PKCS8 Private Keys - 1*/
      {PKCS12Mode_Privacy_password, 0, NULL, 0, &privateDataKey, 0, NULL, 0, NULL, 0, pAttrValArr, 2},
      /*Certificate data - 2*/
      {PKCS12Mode_Privacy_password, 0, NULL, 0, NULL, X509, NULL, 0, NULL, 0, NULL, 0},
      /*CRL data - 3*/
      {PKCS12Mode_Privacy_password, 0, NULL, 0, NULL, 0, NULL, 0, /*crl*/NULL, 0, NULL, 0},
      /*All Data - 4*/
      {PKCS12Mode_Privacy_password, 0, NULL, 0, &privateDataKey, X509, NULL, 0, NULL, 0, NULL, 0},

      /* No encryption - all data - 5*/
      {PKCS12Mode_Privacy_data, 0, NULL, 0, &privateDataKey, X509, NULL, 0, NULL, 0, NULL, 0},
      /* No encryption - all data - 6*/
      {PKCS12Mode_Privacy_data, 0, NULL, 0, &privateDataKey, X509, NULL, 0, NULL, 0, NULL, 0},

      /*Public Key privacy*/
      /*PKCS#8 Shrouded Keys - 7*/
      {PKCS12Mode_Privacy_pubKey, PCKS8_EncryptionType_pkcs5_v2_3des, (ubyte *)"secret", 6, &privateDataKey, 0, NULL, 0, NULL, 0, NULL, 0},
      /*PKCS8 Private Keys - 8*/
      {PKCS12Mode_Privacy_pubKey, 0, NULL, 0, &privateDataKey, 0, NULL, 0, NULL, 0, NULL, 0},
      /*Certificate data - 9*/
      {PKCS12Mode_Privacy_pubKey, 0, NULL, 0, NULL, X509, NULL, 0, NULL, 0, NULL, 0},
      /*CRL data - 10*/
      {PKCS12Mode_Privacy_pubKey, 0, NULL, 0, NULL, 0, NULL, 0, /*crl*/NULL, 0, NULL, 0},
      /*All Data - 11*/
      {PKCS12Mode_Privacy_pubKey, 0, NULL, 0, &privateDataKey, X509, NULL, 0, NULL, 0, NULL, 0},

      /* Any new test case to be added over here */
      /* test case for putting shrouded key in data mode and certificate password mode - for EJBCA */
      {PKCS12Mode_Privacy_data, PCKS8_EncryptionType_pkcs12_sha_3des, (ubyte *)"secret", 6, &privateDataKey, 0, NULL, 0, NULL, 0, NULL, 0},
      {PKCS12Mode_Privacy_password, 0, NULL, 0, NULL, X509, NULL, 0, NULL, 0, NULL, 0},

      /*Error, wrong password -14*/
      {PKCS12Mode_Privacy_password, 0, (ubyte *)"\x1e\x1f\x00", 3, &privateDataKey, 0, NULL, 0, NULL, 0, NULL, 0}
    };

    PKCS12PrivacyDataMap    privacyDataMap[] = 
    {
        /* all valid parameters */
        {0, 1, {(const ubyte *)"secret", 6, 0/*default enc type*/, NULL, NULL, 0}},
        /* privacy password for private key */
        {1, 1, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_3des, NULL, NULL, 0}},
        /* privacy pssword for Certificate*/
        {2, 1, {(const ubyte *)"\x73\x65\x63\x72\x65\x74", 6, PCKS8_EncryptionType_pkcs12_sha_2des, NULL, NULL, 0}},
        /* privacy password for CRL */
        {3, 1, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_rc2_128, NULL, NULL, 0}},
        /* single safe content having multiple safe bags */
        {4, 1, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_rc4_128, NULL, NULL, 0}},
        /*multiple safe contents with password privacy mode */
        {0, 5, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_rc4_40, NULL, NULL, 0}},

        /*single safe content with un-encrypted data */
        {5, 1, {NULL, 0, 0, NULL, NULL, 0}},
        /* multiple safe content with un-encrypted data */
        {5, 2, {NULL, 0, 0, NULL, NULL, 0}},

        /* privacy pub key: only 1 certificate is supported with pkcs7 for creating enveloped data. */
        /* for PKCS#8 shrouded key */
        {7, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},
        /* for private key */
        {8, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},
        /* for certificate */
        {9, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},
        /* for CRL */
        {10, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},
        /* single safe content with multiple safe bags */
        {11, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},
        /* multiple safe content */
        {7, 5, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 1}},

        /* all with password private mode & public key privacy mode */
        {0, 11, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_rc4_40, desEDE3CBC_OID, csPubKey, 1}},

        /* to add any more positive combinations put it out here*/
        {12, 2, {(const ubyte *)"secret", 6, PCKS8_EncryptionType_pkcs12_sha_rc2_40, NULL, NULL, 0}},
        /* end of new test case combination */

        /* to show case default values taken for password privacy mode if password integrity mode is used */
        {0, 5, {NULL, 0, 0, NULL, NULL, 0}}
    };

    PKCS12PrivacyDataMap*   pPrivacyDataMapArr[] = 
      {
        &privacyDataMap[0], &privacyDataMap[1], &privacyDataMap[2], &privacyDataMap[3],
        &privacyDataMap[4], &privacyDataMap[5], &privacyDataMap[6], &privacyDataMap[7],
        &privacyDataMap[8], &privacyDataMap[9], &privacyDataMap[10], &privacyDataMap[11],
        &privacyDataMap[12], &privacyDataMap[13], &privacyDataMap[14], &privacyDataMap[15], &privacyDataMap[16]
      };

    PKCS12PrivacyDataMap   privacyErrDataMap[] = 
    {
        /* public privacy mode, with alogrithm not set */
        {7, 1, {NULL, 0, 0, NULL, csPubKey, 1}},
        /* public privacy mode, with cstream not set */
        {7, 1, {NULL, 0, 0, desEDE3CBC_OID, NULL, 1}},
        /* public privacy mode, with numOfCStream not set properly */
        {7, 1, {NULL, 0, 0, desEDE3CBC_OID, csPubKey, 0}},
        /* password privacy mode, with password containing unprintable characters */
        {0, 1, {(const ubyte*)"\x1e\x1f\x00", 3, 0, NULL, NULL, 0}},
        /* password privacy mode, with Encrypted key for safe bag having unprintable characters */
        {COUNTOF(dataObject) - 1/*12*/, 1, {(const ubyte*)"password", 8, 0, NULL, NULL, 0}},
        /* public privacy mode, with unsupported encryption algo oid */
        {7, 1, {NULL, 0, 0, dummy_OID, csPubKey, 1}}
    };

    PKCS12PrivacyDataMap*  pPrivacyErrDataMapArr[] = {
      &privacyErrDataMap[0], &privacyErrDataMap[1], &privacyErrDataMap[2], &privacyErrDataMap[3],
      &privacyErrDataMap[4], &privacyErrDataMap[5]
    };

    PKCS12TestInputParams      pkcs12TestIntegrityInputParams[] =
    {
        /* error : random context not set */
        {FALSE, PKCS12Mode_Integrity_password, NULL, 0, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error: Privacy mode not configured*/
        {TRUE, PKCS12Mode_Integrity_password, NULL, 0, NULL, NULL, NULL, NULL, 1},
        /* error : password integrity mode but no password */
        {TRUE, PKCS12Mode_Integrity_password, NULL, 0, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error: password integrity mode - password but password len set to 0 */
        {TRUE, PKCS12Mode_Integrity_password, (ubyte *)"secret", 0, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error: incorrect integrity mode */
        {TRUE, PKCS12Mode_Privacy_data, NULL, 0, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error : incorrect integrity mode */
        {TRUE, 14/*arbitrary value*/, NULL, 0, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error: pub key integrity mode : no private key */
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, NULL, (ubyte *)sha1_OID, (ubyte *)FILE_PATH("../test/selfcert.der"), pPrivacyDataMapArr, 1},
        /* error: pub key integrity mode : no digest algorithm */
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte *)FILE_PATH("../test/keyblobFile.dat"), NULL, (ubyte *)FILE_PATH("../test/selfcert.der"), pPrivacyDataMapArr, 1},
        /* error: pub key integrity mode : no signer certificate */
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte *)FILE_PATH("../test/keyblobFile.dat"), (ubyte *)sha1_OID, NULL, pPrivacyDataMapArr, 1},
        /* error : public integrity mode but invalid public key privacy parameters */
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte *)FILE_PATH("../test/keyblobFile.dat"), (ubyte *)sha1_OID, (ubyte *)FILE_PATH("../test/selfcert.der"), pPrivacyErrDataMapArr, 3},
        /* error : password integrity mode but password is set to non printable character */
        {TRUE, PKCS12Mode_Integrity_password, (ubyte *)"\x1e\x1f\x00", 3, NULL, NULL, NULL, pPrivacyDataMapArr, 1},
        /* error: password integrity mode, but privacy password set to non printable characters */
        {TRUE, PKCS12Mode_Integrity_password, (ubyte *)"password", 8, NULL, NULL, NULL, &pPrivacyErrDataMapArr[3], 1},
        /* error: password integrity mode, but safe bags containing password set to non printable characters */
        {TRUE, PKCS12Mode_Integrity_password, (ubyte *)"password", 8, NULL, NULL, NULL, &pPrivacyErrDataMapArr[4], 1},
        /* error: public key integrity mode, but with unsupported digest algo OID*/
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte*)FILE_PATH("../test/keyblobFile.dat"), (ubyte*)dummy_OID, (ubyte *)FILE_PATH("../test/selfcert.der"), &pPrivacyDataMapArr[8], 1},
        /* error : public integrity mode but invalid public key privacy parameters */
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte *)FILE_PATH("../test/keyblobFile.dat"), (ubyte *)sha1_OID, (ubyte *)FILE_PATH("../test/selfcert.der"), &pPrivacyErrDataMapArr[5], 1},
    };

    PKCS12TestInputParams   pkcs12IntegrityParam[] =
    {
        {TRUE, PKCS12Mode_Integrity_password, (ubyte*)"secret", 6, NULL, NULL, NULL, pPrivacyDataMapArr, COUNTOF(pPrivacyDataMapArr)},
        {TRUE, PKCS12Mode_Integrity_pubKey, NULL, 0, (ubyte *)FILE_PATH("../test/keyblobFile.dat"), (ubyte *)sha1_OID, (ubyte *)FILE_PATH("../test/selfcert.der"), pPrivacyDataMapArr, COUNTOF(pPrivacyDataMapArr) - 1},
    };

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
    
    if (OK > (status = DIGICERT_initialize(&setupInfo, NULL)))
        goto exit;

    if (OK > (status = DIGICERT_readFile(FILE_PATH("../test/keyblobFile.dat"), &pPrivateKeyBlob, &privateKeyBlobLen)))
        goto exit;

    /* this certificate is a dummy certificate, which is acting as a payload within PKCS#12 cert safe bag*/
    if (OK > (status = DIGICERT_readFile(FILE_PATH("CA5.cacert.der"), &pDataCert, &dataCertLen)))
        goto exit;

    /* set this certificate to specific dataObject[] */
    dataObject[2].pCertificate = dataObject[4].pCertificate = dataObject[5].pCertificate = dataObject[6].pCertificate = dataObject[9].pCertificate = dataObject[11].pCertificate = pDataCert;
    dataObject[2].certificateLen = dataObject[4].certificateLen = dataObject[5].certificateLen = dataObject[6].certificateLen = dataObject[9].certificateLen = dataObject[11].certificateLen = dataCertLen;

    if (OK > (status = DIGICERT_readFile(FILE_PATH("../test/selfcert.der"/*"new5.der"*/), &pCSPubKey0Cert, &csPubKeyLen)))
        goto exit;

    /* EJBCA is able to load self signed certificates properly */
    dataObject[13].pCertificate = pCSPubKey0Cert;
    dataObject[13].certificateLen = csPubKeyLen;

    /* Assign CA5 certificate as one of the public key certificate, since it is the parent of new5 */
    //pCSPubKey1Cert = pDataCert;

    /* create cs streams for */
    /* new 5 : PKCS7 envelop data only supports 1 certificate */
    MF_attach(&memFilePubKey0, csPubKeyLen, pCSPubKey0Cert);
    CS_AttachMemFile(&csPubKey0, &memFilePubKey0);
    /* CA 5 */
    //MF_attach(&memFilePubKey1, dataCertLen, pCSPubKey1Cert);
    //CS_AttachMemFile(&csPubKey1, &memFilePubKey1);

    /* Assign pub keys for pubKey privacy mode */
    csPubKey[0] = &csPubKey0;
    //csPubKey[1] = &csPubKey1;

    if (OK > (status = CRYPTO_initAsymmetricKey(&privateDataKey)))
        goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pPrivateKeyBlob, privateKeyBlobLen, &privateDataKey)))
        goto exit;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal = 0;

    /* Password Integrity : various privacy modes */
    retVal += TestIntegrityModeWithVariousPrivacyModes(MOC_SYM(hwAccelCtx)
                                                       g_pRandomContext,
                                                       pkcs12IntegrityParam,
                                                       1,
                                                       dataObject,
                                                       TRUE,
                                                       100);


    /* PubKey Integrity : various privacy modes */
    retVal += TestIntegrityModeWithVariousPrivacyModes(MOC_SYM(hwAccelCtx)
                                                       g_pRandomContext,
                                                       pkcs12IntegrityParam + 1,
                                                       1,
                                                       dataObject,
                                                       TRUE,
                                                       200);

    /* basic error tests */
    retVal += TestIntegrityModeWithVariousPrivacyModes(MOC_SYM(hwAccelCtx)
                                                       g_pRandomContext,
                                                       pkcs12TestIntegrityInputParams,
                                                       COUNTOF(pkcs12TestIntegrityInputParams),
                                                       dataObject,
                                                       FALSE,
                                                       300);


    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

exit:
    if (pPrivateKeyBlob)
    {
        CRYPTO_uninitAsymmetricKey(&privateDataKey, NULL);
        FREE(pPrivateKeyBlob);
    }
    if (pCSPubKey0Cert)
      FREE(pCSPubKey0Cert);
    if (pDataCert)
      FREE(pDataCert);
    
#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif

    DIGICERT_freeDigicert();
    return retVal;
}
