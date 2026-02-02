/*
 * pkcs7_cert_store_test.c
 *
 * unit test for pkcs7.c using cert_store provided callbacks
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
#include "../../crypto/secmod.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/initmocana.h"
#include "../../crypto/crypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/arc4.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/arc2.h"
#include "../../crypto/rc2algo.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../crypto/pkcs_common.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/derencoder.h"
#define __IN_DIGICERT_C__     /* FOR TESTING PURPOSES --- ENABLES BASE64 init/free */
#include "../../common/base64.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/pkcs7_cert_store.h"

#include "../../../unit_tests/unittest.h"
//#define UNITTEST_STATUS(a, b) b

static WalkerStep contentInfoRootToContent[] =
{
    { GoFirstChild, 0, 0},
    { VerifyType, SEQUENCE, 0},
    { GoChildWithTag, 0, 0},
    { Complete, 0, 0}
};	

static WalkerStep SignerInfosToAuthenticateAttributes[] =
{
    { GoFirstChild, 0, 0}, /* first signerInfo */
    { VerifyType, SEQUENCE, 0},
    { GoChildWithTag, 0, 0},
    { Complete, 0, 0}
};	


static int load_trust_point(int hint,
                            certStorePtr pCertStore,
                            const char* certFileName)
{
    int retVal = 0;
    ubyte* cert = 0;
    ubyte4 certLen;

    /* read in certificate */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( certFileName, &cert, &certLen),
                         retVal, exit);

    /* load as trust point */
    UNITTEST_STATUS_GOTO(hint, CERT_STORE_addTrustPoint(pCertStore, cert, certLen),
                         retVal, exit);
exit:
    FREE(cert);

    return retVal;
}

static int load_identity(int hint, certStorePtr pCertStore,
                         const char* certFileName, const char* keyFileName)
{
    int retVal = 0;
    ubyte* cert = 0;
    ubyte4 certLen;
    ubyte* key = 0;
    ubyte4 keyLen;
    

    /* read in certificate */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( certFileName, &cert, &certLen),
                         retVal, exit);
    /* read in key */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyFileName, &key, &keyLen),
                         retVal, exit);

    /* load as trust point */
    UNITTEST_STATUS_GOTO(hint, CERT_STORE_addIdentity(pCertStore,
                                                      cert, certLen,
                                                      key, keyLen),
                         retVal, exit);

exit:
    FREE(cert);
    FREE(key);

    return retVal;
}


/* sign some data and then verify */
static int SignAndVerifyData(int hint, const char* selfCertFile,
                             const char* keyblobFile)
{
    MSTATUS status;
    ubyte* payLoad = (ubyte*) "This is signed data content.";
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo mySignerInfo;
    ubyte* pSigned = NULL;
    ubyte4 signedLen;
    ubyte *certData=NULL, *pKeyblob=NULL;
    ubyte4 certDataLen, keyblobLen;
    CStream cs, certStream;
    CStream certStreams[1];
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    ASN1_ITEMPTR pCertificates[1];
    AsymmetricKey key;
    Attribute *pAuthAttributes = NULL;
    ubyte4 authAttributeLen = 1;
    sbyte4 numKnownSigners;
    hwAccelDescr hwAccelCtx;
    certStorePtr pCertStore = 0;
    int retVal = 0;

    UNITTEST_STATUS_GOTO(hint, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    /* read in signer certificate */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( selfCertFile, &certData, &certDataLen),
                         retVal, exit);

    MF_attach(&memFile, certDataLen, certData);
    CS_AttachMemFile(&certStream, &memFile );

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(certStream, &pSelfCertificate),
                         retVal, exit);
    /* read in signer private key */

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyblobFile, &pKeyblob, &keyblobLen),
                        retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CRYPTO_initAsymmetricKey( &key),
                        retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key),
                         retVal, exit);

    /* create signer infos */
    /* get issuer and serial number of certificate */
    UNITTEST_STATUS_GOTO(hint, X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber),
                         retVal, exit);
    mySignerInfo.pIssuer = pIssuer;
    mySignerInfo.pSerialNumber = pSerialNumber;
    mySignerInfo.cs = certStream;
    mySignerInfo.digestAlgoOID = sha1_OID;
    mySignerInfo.pKey = &key;
    mySignerInfo.pUnauthAttrs = NULL;
    mySignerInfo.unauthAttrsLen = 0;
    /* gather together authenticated Attributes, including transaction attributes */
    pAuthAttributes = (Attribute *)MALLOC(sizeof(Attribute)*authAttributeLen);

    if (!pAuthAttributes)
    {
        UNITTEST_STATUS_GOTO(hint, ERR_MEM_ALLOC_FAIL, retVal, exit);
    }

    /* manditory attributes like contentType and messageDigest are
       added automatically in pkcs7 signedData */

    pAuthAttributes->typeOID = pkcs9_emailAddress_OID;
    pAuthAttributes->type = PRINTABLESTRING;
    pAuthAttributes->value = (ubyte*) "nobody@mocana.com";
    pAuthAttributes->valueLen = 17;

    mySignerInfo.pAuthAttrs = pAuthAttributes;
    mySignerInfo.authAttrsLen = authAttributeLen;
    mySignerInfoPtr[0] = &mySignerInfo;

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    pCertificates[0] = pSelfCertificate;
    certStreams[0] =  certStream;
    UNITTEST_STATUS_GOTO(hint, PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0,
                                                      pContentInfo, pSignedData,
                                                      pCertificates, certStreams, 1,
                                                      NULL, NULL, 0, /* no crls */
                                                      mySignerInfoPtr,
                                                      1,
                                                      pkcs7_data_OID,
                                                      payLoad,
                                                      DIGI_STRLEN((const sbyte*) payLoad),
                                                      RANDOM_rngFun, g_pRandomContext,
                                                      &pSigned,
                                              &signedLen),
                         retVal, exit);

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedLen, (ubyte*)pSigned );
    CS_AttachMemFile(&cs, &memFile );
    ASN1_Parse(cs, &pSignedDataRoot);	

    /* walk tree to verify signed data type */
    /* or use openssl to verify it but that introduce a dependency on a third party app */
    UNITTEST_STATUS_GOTO(hint, PKCS7_GetCertificates(pSignedDataRoot, cs, &pTemp),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, ASN1_WalkTree( pSignedDataRoot, cs,
                                             contentInfoRootToContent, &pTemp),
                         retVal, exit);

    /* try to verify the signature with an empty cert store: should fail */
    UNITTEST_STATUS_GOTO(hint, CERT_STORE_createStore(&pCertStore), retVal, exit);

    status = PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                    pTemp, cs, pCertStore,
                                    NULL,
                                    CERT_STORE_PKCS7_ValidateRootCertificate,
                                    NULL, 0,
                                    &numKnownSigners);
    retVal += UNITTEST_TRUE(hint, OK != status);

    /* verify the signature with the correct trust point in the cert store now */
    UNITTEST_STATUS_GOTO(hint,
                         CERT_STORE_addTrustPoint(pCertStore, certData, certDataLen),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint,
                         PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                                pTemp, cs, pCertStore,
                                                NULL,
                                                CERT_STORE_PKCS7_ValidateRootCertificate,
                                                NULL, 0,
                                                &numKnownSigners),
                         retVal, exit);

    retVal += UNITTEST_INT(hint, numKnownSigners, 1);
    
exit:
    FREE(pAuthAttributes);

    if (pSelfCertificate)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }

    FREE(pSigned);

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    FREE(certData);
    FREE(pKeyblob);

    CERT_STORE_releaseStore(&pCertStore);

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

int pkcs7_cert_store_test_SignAndVerifyData()
{
    int retVal = 0;

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) return retVal;

    retVal += SignAndVerifyData(1, FILE_PATH("selfcert.der"), FILE_PATH("keyblobFile.dat"));
    retVal += SignAndVerifyData(2, FILE_PATH("ecc_selfcert.der"), FILE_PATH("ecc_keyblobFile.dat"));

    DIGICERT_freeDigicert();

    return retVal;
}

static int signAndVerify(int hint, const ubyte* contentType)
{
    MSTATUS status = OK;
    ubyte* payLoad = (ubyte*) "This is signed data content.";
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo mySignerInfo;
    ubyte* pSigned = NULL;
    ubyte4 signedLen;
    const char* selfCertFile = FILE_PATH("selfcert.der");
    const char* keyblobFile = FILE_PATH("keyblobFile.dat");
    ubyte *certData=NULL, *pKeyblob=NULL;
    ubyte4 certDataLen, keyblobLen;
    CStream cs, certStream;
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    AsymmetricKey key;
    sbyte4 numKnownSigners;
    certStorePtr pCertStore = 0;
    hwAccelDescr hwAccelCtx;
    int retVal = 0;

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(hint, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    /* read in signer certificate */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( selfCertFile, &certData, &certDataLen),
                         retVal, exit);


    MF_attach(&memFile, certDataLen, (ubyte*) certData);
    CS_AttachMemFile(&certStream, &memFile );

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(certStream, &pSelfCertificate),
                         retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyblobFile, &pKeyblob, &keyblobLen),
                        retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CRYPTO_initAsymmetricKey( &key),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key),
                         retVal, exit);

    /* create signer infos */
    /* get issuer and serial number of certificate */
    UNITTEST_STATUS_GOTO(hint, X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber),
                         retVal, exit);

    mySignerInfo.pIssuer = pIssuer;
    mySignerInfo.pSerialNumber = pSerialNumber;
    mySignerInfo.cs = certStream;
    mySignerInfo.digestAlgoOID = md5_OID;
    mySignerInfo.pKey = &key;
    mySignerInfo.pAuthAttrs = NULL;
    mySignerInfo.authAttrsLen = 0;
    mySignerInfo.pUnauthAttrs = NULL;
    mySignerInfo.unauthAttrsLen = 0;
    mySignerInfoPtr[0] = &mySignerInfo;

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    status = PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0, pContentInfo, pSignedData,
                            &pSelfCertificate, &certStream, 1,
                            NULL, NULL, 0, /* no crls */
                            mySignerInfoPtr, 1,
                            contentType, payLoad,
                            DIGI_STRLEN((const sbyte*) payLoad),
                            RANDOM_rngFun, g_pRandomContext,
                            &pSigned, &signedLen);

    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedLen, (ubyte*)pSigned );
    CS_AttachMemFile(&cs, &memFile );
    ASN1_Parse(cs, &pSignedDataRoot);	

    /* walk tree to verify signed data type */
    /* or use openssl to verify it but that introduce a dependency on a third party app */
    UNITTEST_STATUS_GOTO(hint, PKCS7_GetCertificates(pSignedDataRoot, cs, &pTemp),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(hint, ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp),
                         retVal, exit);

    /* try to verify the signature with an empty cert store: should fail */
    UNITTEST_STATUS_GOTO(hint, CERT_STORE_createStore(&pCertStore), retVal, exit);

    status = PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                    pTemp, cs, pCertStore,
                                    NULL,
                                    CERT_STORE_PKCS7_ValidateRootCertificate,
                                    NULL, 0,
                                    &numKnownSigners);

    retVal += UNITTEST_TRUE(hint, OK != status);

    /* verify the signature with the correct trust point in the cert store now */
    UNITTEST_STATUS_GOTO(hint,
                         CERT_STORE_addTrustPoint(pCertStore, certData, certDataLen),
                         retVal, exit);
    

    /* verify the signature */
    UNITTEST_STATUS_GOTO(hint,
                         PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pTemp, cs,
                                              pCertStore,
                                              NULL,
                                              CERT_STORE_PKCS7_ValidateRootCertificate,
                                              NULL, 0,
                                              &numKnownSigners),
              retVal, exit);

    retVal += UNITTEST_INT(hint, numKnownSigners, 1);

    /* verify absence of authenticated attributes */
    {
        ASN1_ITEMPTR pNextSibling;
        /* certificate has tag 0 or 2 */
        pTemp = ASN1_FIRST_CHILD(pTemp);
        /* now go to the signer Info: this is the last child of the sequence */
        pTemp = ASN1_NEXT_SIBLING( pTemp);
        retVal += UNITTEST_TRUE(hint, 0 != pTemp);

        pNextSibling = ASN1_NEXT_SIBLING( pTemp);
        /* if the last child is EOC, it is the second to last child */
        while ( pNextSibling &&
            !(pNextSibling->tag == 0 && pNextSibling->id == 0 && pNextSibling->length==0))
        {
            pTemp = pNextSibling;
            pNextSibling = ASN1_NEXT_SIBLING( pTemp);
        }
        status = ASN1_WalkTree( pTemp, cs, SignerInfosToAuthenticateAttributes, &pTemp);
        if (pkcs7_data_OID[pkcs7_data_OID[0]] == contentType[contentType[0]])
        {
            if ( ERR_WALKER_OUT_OF_TREE == status )
            {
                status = OK;
            }
        } /* else status has to be OK(authenticatedAttributes present), otherwise it's a failure */
    }
exit:

    if (pSelfCertificate)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }

    FREE(pSigned);

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    FREE(certData);
    FREE(pKeyblob);

    CERT_STORE_releaseStore(&pCertStore);

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}

int pkcs7_cert_store_test_SignAndVerifyData2()
{
    int retVal = 0;
    retVal += signAndVerify(1, pkcs7_data_OID);
    retVal += signAndVerify(2, pkcs7_signedData_OID);

    return retVal;
}

/* sign some data and then verify */
int pkcs7_cert_store_test_SignAndVerifyDetachedSignature()
{
    const ubyte* payLoad = (const ubyte*) "Hello World";
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo mySignerInfo;
    ubyte* pSigned = NULL;
    ubyte4 signedLen;
    const char* selfCertFile = FILE_PATH("cert.der");
    const char* pemKeyFile = FILE_PATH("key.pem");
    ubyte *certData=NULL, *pPemKey=NULL, *pKeyblob=NULL;
    ubyte4 certDataLen, pemKeyLen, keyblobLen;
    CStream cs, certStream;
    CStream certStreams[1];
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    ASN1_ITEMPTR pCertificates[1];
    AsymmetricKey key = {0};
    Attribute *pAuthAttributes = NULL;
    ubyte4 authAttributeLen = 1;
    sbyte4 numKnownSigners;
    certStorePtr pCertStore = 0;
    hwAccelDescr hwAccelCtx;
    int retVal = 0;

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    /* read in signer certificate */
    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( selfCertFile, &certData, &certDataLen),
                         retVal, exit);


    MF_attach(&memFile, certDataLen, (ubyte*) certData);
    CS_AttachMemFile(&certStream, &memFile );

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(certStream, &pSelfCertificate),
                         retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( pemKeyFile, &pPemKey, &pemKeyLen),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, BASE64_initializeContext(),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, CA_MGMT_convertKeyPEM(pPemKey, pemKeyLen, &pKeyblob, &keyblobLen),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, BASE64_freeContext(),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key),
                         retVal,exit);

    /* create signer infos */
    /* get issuer and serial number of certificate */
   UNITTEST_STATUS_GOTO(0, X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber),
                        retVal,exit);

    mySignerInfo.pIssuer = pIssuer;
    mySignerInfo.pSerialNumber = pSerialNumber;
    mySignerInfo.cs = certStream;
    mySignerInfo.digestAlgoOID = md5_OID;
    mySignerInfo.pKey = &key;
    mySignerInfo.pUnauthAttrs = NULL;
    mySignerInfo.unauthAttrsLen = 0;
    /* gather together authenticated Attributes, including transaction attributes */
    pAuthAttributes = (Attribute *)MALLOC(sizeof(Attribute)*authAttributeLen);

    if (!pAuthAttributes)
    {
        UNITTEST_STATUS_GOTO(0, ERR_MEM_ALLOC_FAIL, retVal, exit);
    }

    /* manditory attributes like contentType and messageDigest are
       added automatically in pkcs7 signedData */

    pAuthAttributes->typeOID = pkcs9_emailAddress_OID;
    pAuthAttributes->type = PRINTABLESTRING;
    pAuthAttributes->value = (ubyte*) "nobody@mocana.com";
    pAuthAttributes->valueLen = 17;

    mySignerInfo.pAuthAttrs = pAuthAttributes;
    mySignerInfo.authAttrsLen = authAttributeLen;
    mySignerInfoPtr[0] = &mySignerInfo;

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    pCertificates[0] = pSelfCertificate;
    certStreams[0] =  certStream;
    UNITTEST_STATUS_GOTO(0,
                         PKCS7_SignData(MOC_ASYM(hwAccelCtx)
                                        PKCS7_EXTERNAL_SIGNATURES, pContentInfo, pSignedData,
                                        pCertificates, certStreams, 1,
                                        NULL, NULL, 0, /* no crls */
                                        mySignerInfoPtr,
                                        1,
                                        pkcs7_data_OID,
                                        payLoad,
                                        DIGI_STRLEN((const sbyte*) payLoad),
                                        RANDOM_rngFun, g_pRandomContext,
                                        &pSigned,
                                        &signedLen),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_writeFile(FILE_PATH("detachedSignature2.der"), pSigned, signedLen),
                         retVal, exit);

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedLen, (ubyte*)pSigned );
    CS_AttachMemFile(&cs, &memFile );
    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pSignedDataRoot), retVal, exit);

    /* walk tree to verify signed data type */
    /* or use openssl to verify it but that introduce a dependency on a third party app */
    UNITTEST_STATUS_GOTO(0, PKCS7_GetCertificates(pSignedDataRoot, cs, &pTemp),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp),
                         retVal, exit);

    /* try to verify the signature with an empty cert store: should fail */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore), retVal, exit);

    UNITTEST_TRUE(0, OK > PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                                 pTemp, cs, pCertStore,
                                                 NULL,
                                                 CERT_STORE_PKCS7_ValidateRootCertificate,
                                                 NULL, 0,
                                                 &numKnownSigners));
    retVal += UNITTEST_INT(0, numKnownSigners, 0);

    /* verify the signature with the correct trust point in the cert store now */
    UNITTEST_STATUS_GOTO(0,
                         CERT_STORE_addTrustPoint(pCertStore, certData, certDataLen),
                         retVal, exit);


    /* verify the signature */
    UNITTEST_STATUS_GOTO(0, PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pTemp, cs,
                                              pCertStore, NULL,
                                              CERT_STORE_PKCS7_ValidateRootCertificate,
                                              payLoad,
                                              DIGI_STRLEN((const sbyte*) payLoad),
                                              &numKnownSigners),
                         retVal, exit);

    retVal += UNITTEST_INT(0 , numKnownSigners, 1);
    
exit:
    FREE(pAuthAttributes);

    if (pSelfCertificate)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }

    FREE(pSigned);

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }


    FREE(certData);
    FREE(pKeyblob);
    FREE(pPemKey);

    CERT_STORE_releaseStore(&pCertStore);

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}


/* degenerate SignedData is used to distribute certificates and crls
 * 1. create a degenerate SignedData to distribute two certificates read from files;
 * 2. parse the generated SignedData and walk the tree to verify the structure and return the certificates;
 * 3. compare the certificates with those read from files.
 */
#define num 2
int pkcs7_cert_store_test_SignDataDegenerate()
{
    const char* files[]= {FILE_PATH("Cert1.cer"), FILE_PATH("2000Remote.cer")};
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    ASN1_ITEMPTR pCertificates[num]={NULL, NULL}, pCertRoot=NULL, pFirstCert;
    ubyte *pSignedDegenerated=NULL;
    ubyte *pCertFile[num] = {NULL, NULL};
    ubyte4 signedDegeneratedLen;
    ubyte4 certFileLen[num];
    CStream pStreams[num], cs;
    MemFile certMemFile[num], memFile;
    ubyte4 i = 0;
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    /* load and parse certificates */
    for (i = 0; i < num; i++)
    {
        UNITTEST_STATUS_GOTO(i, DIGICERT_readFile( files[i], &(pCertFile[i]), &certFileLen[i]),
                             retVal, exit);

        MF_attach(&certMemFile[i], certFileLen[i], (ubyte*) pCertFile[i]);
        CS_AttachMemFile(&pStreams[i], &certMemFile[i] );

        UNITTEST_STATUS_GOTO(i, ASN1_Parse(pStreams[i], &pCertificates[i]),
                             retVal, exit);
    }

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    /* create a degenerate SignedData type with the two certificates */
    UNITTEST_STATUS_GOTO(0, PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0,
                                           pContentInfo, pSignedData,
                                           pCertificates, pStreams, 2,
                                           NULL, NULL, 0,
                                           NULL,
                                           0,
                                           NULL, NULL, 0,
                                           RANDOM_rngFun, g_pRandomContext,
                                           &pSignedDegenerated,
                                           &signedDegeneratedLen),
                         retVal, exit);

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedDegeneratedLen, (ubyte*)pSignedDegenerated );
    CS_AttachMemFile(&cs, &memFile );

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pCertRoot), retVal, exit);

    /* walk the tree to verify and retrieve the two certificates */
    UNITTEST_STATUS_GOTO(0, PKCS7_GetCertificates(pCertRoot, cs, &pFirstCert),
                         retVal, exit);


    /* compare to make sure we get back the same two certificates */
    for (i = 0; i < num; i++)
    {
        retVal += UNITTEST_STATUS(i, ASN1_CompareItems(ASN1_FIRST_CHILD(pCertificates[i]), pStreams[i], pFirstCert, cs));

        /* make sure the certs are what we expected */
        pFirstCert = ASN1_NEXT_SIBLING(pFirstCert);
    }

exit:

    for (i = 0; i < num; i++)
    {
        if (pCertFile[i])
            FREE(pCertFile[i]);
        if (pCertificates[i])
            TREE_DeleteTreeItem((TreeItem*)pCertificates[i]);
    }

    if (pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRoot);
    }
    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }
    if (pSignedDegenerated)
    {
        FREE(pSignedDegenerated);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}

/* verify a third party signedData. the signer certificate is provided in a callback */
int pkcs7_cert_store_test_VerifySignedData()
{
    MSTATUS status;
    const char* signedFile= FILE_PATH("signedData.der");
    const char* certFile = FILE_PATH("signerCert.der");
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *data = NULL;
    ubyte4 dataLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;
    hwAccelDescr hwAccelCtx;
    certStorePtr pCertStore = 0;
    int retVal = 0;

    UNITTEST_STATUS_GOTO(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( signedFile, &data, &dataLen),
                          retVal, exit);

    MF_attach(&memFile, dataLen, data);
    CS_AttachMemFile(&cs, &memFile );

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pRoot), retVal, exit);
    UNITTEST_STATUS_GOTO(0, ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore), retVal, exit);

    /* try with no cert */
    status = PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pSignedData, cs,
                                    pCertStore,
                                    CERT_STORE_PKCS7_GetCertificate,
                                    CERT_STORE_PKCS7_ValidateRootCertificate,
                                    NULL, 0, &numKnownSigners);

    retVal += UNITTEST_TRUE(0, OK != status);

    retVal += load_trust_point(__LINE__, pCertStore, certFile);
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(0, PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pSignedData, cs,
                                                   pCertStore,
                                                   CERT_STORE_PKCS7_GetCertificate,
                                                   CERT_STORE_PKCS7_ValidateRootCertificate,
                                                   NULL, 0, &numKnownSigners),
                         retVal, exit);

    retVal += UNITTEST_INT(0, numKnownSigners, 1);
exit:

    FREE(data);

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }

    CERT_STORE_releaseStore(&pCertStore);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/* verify openssl generated detached signature. Signer's certificate is included in signature. So no need
* to pass in the certificate retrieval callback function. (passing NULL)
* the detachedSignature.der file can be generated by the following command: (keypassword: passwd)
* $ openssl smime -sign -in content.txt -outform DER -out detachedSignature.der -signer cert.pem -inkey key.pem
* the detached signature can be verified using openssl with the following command:
$ openssl smime -verify -inform DER -in detachedSignature.der -noverify -content content.txt
*/
int pkcs7_cert_store_test_VerifyDetachedSignature()
{
    int retVal = 0;
    const char* signedFile= FILE_PATH("detachedSignature.der");
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *pFile=NULL;
    ubyte4 fileLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;
    hwAccelDescr hwAccelCtx;
    certStorePtr pCertStore = 0;
    MSTATUS status;

    UNITTEST_STATUS_GOTO(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( signedFile, &pFile, &fileLen), retVal, exit);


    MF_attach(&memFile, fileLen, (ubyte*) pFile);
    CS_AttachMemFile(&cs, &memFile );

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pRoot), retVal, exit);

    UNITTEST_STATUS_GOTO(0, ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore), retVal, exit);

    /* load a couple of the wrong certificates*/
    retVal += load_trust_point(__LINE__, pCertStore, FILE_PATH("selfcert.der"));
    retVal += load_trust_point(__LINE__, pCertStore, FILE_PATH("signerCert.der"));
    if (retVal) goto exit;

    status = PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                    pSignedData, cs,
                                    pCertStore, NULL,
                                    CERT_STORE_PKCS7_ValidateRootCertificate,
                                    (ubyte*) "Hello World", 11,
                                    &numKnownSigners);

    retVal += UNITTEST_TRUE(0, OK != status);


    /* load the right certificate */
    retVal += load_trust_point(__LINE__, pCertStore, FILE_PATH("cert.der"));
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(0, PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx)
                                                   pSignedData, cs,
                                                   pCertStore, NULL,
                                                   CERT_STORE_PKCS7_ValidateRootCertificate,
                                                   (ubyte*) "Hello World", 11,
                                                   &numKnownSigners),
                         retVal, exit);

    retVal += UNITTEST_INT( 0, numKnownSigners, 1);
    

    /* also make sure that we would correctly fail to verify the wrong content */
    status = PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pSignedData, cs,
                                    pCertStore, NULL,
                                    CERT_STORE_PKCS7_ValidateRootCertificate,
                                    (ubyte*) "Hello Worle", 11,
                                    &numKnownSigners);

    retVal += UNITTEST_TRUE(0, status == ERR_PKCS7_INVALID_SIGNATURE);

exit:
    CERT_STORE_releaseStore(&pCertStore);

    FREE(pFile);

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/* read in a third party degenerate signed data file.
 * verify the structure and make sure there are two certs contained within
 */
int pkcs7_cert_store_test_VerifyDegenerateSignedData()
{
    const char* file= {FILE_PATH("degenerateSignedData.der")};
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *pDataFile=NULL;
    ubyte4 dataFileLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;
    hwAccelDescr hwAccelCtx;
    int retVal = 0;

    UNITTEST_STATUS_GOTO(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( file, &pDataFile, &dataFileLen),
                         retVal, exit);

    MF_attach(&memFile, dataFileLen, (ubyte*) pDataFile);
    CS_AttachMemFile(&cs, &memFile );

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pRoot), retVal, exit);

    UNITTEST_STATUS_GOTO(0, ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pSignedData, cs,
                                                   NULL, NULL, NULL, NULL, 0,
                                                   &numKnownSigners),
                         retVal, exit);

exit:

    FREE(pDataFile);

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/* decrypt a third party envelopedData; the private key is available in
keyblobFile.dat. the decrypted content should be the fixed string as shown.
*/
static int Decrypt_pkcs7_envelopedData( int hint, const char* file,
                                       const char* certFile,
                                       const char* keyFile)
{
    int retVal = 0;
    ubyte* pExpVal = (ubyte*) "This is a pkcs7 envelopedData test.";
    ubyte *pDataFile = NULL, *decryptedInfo=NULL;
    ubyte4 dataFileLen;
    sbyte4 decryptedInfoLen;
    ASN1_ITEMPTR pEnvelopedRoot=NULL, pEnvelopedData, pSignedRoot=NULL;
    MemFile memFile1;
    CStream cs1;
    hwAccelDescr hwAccelCtx;
    sbyte4 resCmp;
    certStorePtr pCertStore = 0;

    UNITTEST_STATUS_GOTO(hint, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( file, &pDataFile, &dataFileLen), 
                         retVal, exit);

    MF_attach(&memFile1, dataFileLen, (ubyte*) pDataFile);
    CS_AttachMemFile(&cs1, &memFile1 );

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(cs1, &pEnvelopedRoot), retVal, exit);

    UNITTEST_STATUS_GOTO(hint, ASN1_WalkTree( pEnvelopedRoot, cs1, contentInfoRootToContent, 
                                            &pEnvelopedData), 
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CERT_STORE_createStore(&pCertStore),retVal, exit);


    /* set up the globals used by myGetPrivateKeyFun */
    retVal += load_identity(((hint << 16) | __LINE__), pCertStore, certFile, keyFile);
    if (retVal) goto exit;

    UNITTEST_STATUS_GOTO(hint, PKCS7_DecryptEnvelopedData(MOC_HW(hwAccelCtx)
                                                          pEnvelopedData, cs1,
                                                          pCertStore,
                                                          CERT_STORE_PKCS7_GetPrivateKey,
                                                          &decryptedInfo,
                                                          &decryptedInfoLen),
                           retVal, exit);


    /* verify that the decryptedInfo match the content of outFile */
    retVal += UNITTEST_INT(hint, decryptedInfoLen, DIGI_STRLEN(pExpVal));  
    
    DIGI_MEMCMP( decryptedInfo, pExpVal, DIGI_STRLEN(pExpVal), &resCmp);
    retVal += UNITTEST_TRUE(hint, resCmp ==0);

exit:
    CERT_STORE_releaseStore(&pCertStore);

    FREE(pDataFile);

    if (pEnvelopedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pEnvelopedRoot);
    }
    if (decryptedInfo)
    {
        FREE(decryptedInfo);
    }
    if (pSignedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedRoot);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

int pkcs7_cert_store_test_DecryptEnvelopedData()
{
    int retVal = 0;

    retVal += Decrypt_pkcs7_envelopedData(1, FILE_PATH("envelopedData2.der"),
                                          FILE_PATH("selfcert2.der"),
                                          FILE_PATH("keyblobFile2.dat"));
    return retVal;
}

static int EnvelopeAndDecryptData(MOC_RSA( hwAccelDescr hwAccelCtx) int hint,
                           const char* certFileName, const char* keyFileName)
{
    ubyte* payLoad = (ubyte*) "This is a pkcs7 envelopedData test.";
    ubyte *pCertFile=NULL, *pEnveloped=NULL, *decryptedInfo=NULL;
    ubyte4 certFileLen, envelopedLen;
    sbyte4 decryptedInfoLen;
    ASN1_ITEMPTR pCertRoot=NULL, pEnvelopedRoot=NULL, pEnvelopedData2;
    DER_ITEMPTR pContentInfo=NULL, pEnvelopedData;
    MemFile memFile1, memFile2;
    CStream cs1, cs2;
    sbyte4 cmpResult;
    int retVal = 0;
    certStorePtr pCertStore = 0;

    retVal += UNITTEST_STATUS(hint, DIGICERT_readFile( certFileName, &pCertFile, &certFileLen));
    if (retVal) goto exit;

    MF_attach(&memFile1, certFileLen, (ubyte*) pCertFile);
    CS_AttachMemFile(&cs1, &memFile1);

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(cs1, &pCertRoot), retVal, exit);

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_envelopedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pEnvelopedData);

    retVal += UNITTEST_STATUS(hint, PKCS7_EnvelopData(MOC_SYM(hwAccelCtx) MOC_ASYM (hwAccelCtx) pContentInfo, pEnvelopedData,
                                                      &pCertRoot, &cs1, 1,
                                                      aes128CBC_OID,
                                                      RANDOM_rngFun,
                                                      g_pRandomContext,
                                                      payLoad,
                                                      DIGI_STRLEN((const sbyte*) payLoad),
                                                      &pEnveloped, &envelopedLen));
    if (retVal) goto exit;

    MF_attach(&memFile2, envelopedLen, (ubyte*) pEnveloped);
    CS_AttachMemFile(&cs2, &memFile2);

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(cs2, &pEnvelopedRoot), retVal, exit);

    UNITTEST_STATUS_GOTO(hint,
                         ASN1_WalkTree( pEnvelopedRoot, cs2, contentInfoRootToContent, &pEnvelopedData2),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CERT_STORE_createStore(&pCertStore), retVal, exit);
    /* set up the globals used by myGetPrivateKeyFun */
    retVal += load_identity(((hint<<6)| __LINE__), pCertStore, certFileName, keyFileName);
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, PKCS7_DecryptEnvelopedData(MOC_HW(hwAccelCtx)
                                                               pEnvelopedData2,
                                                               cs2,
                                                               pCertStore,
                                                               CERT_STORE_PKCS7_GetPrivateKey,
                                                               &decryptedInfo,
                                                               &decryptedInfoLen));
    if (retVal) goto exit;
      
    DIGI_MEMCMP(payLoad, decryptedInfo, DIGI_STRLEN((const sbyte*) payLoad), &cmpResult);
    retVal += UNITTEST_TRUE( hint, 0 == cmpResult);

exit:

    FREE(pCertFile);
    FREE(pEnveloped);
    FREE(decryptedInfo);

    CERT_STORE_releaseStore(&pCertStore);

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }

    if (pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRoot);
    }
    if (pEnvelopedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pEnvelopedRoot);
    }

    return retVal;
}


/*---------------------------------------------------------------------------------*/

int pkcs7_cert_store_test_EnvelopeAndDecryptData()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( 0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    /* RSA test */
    retVal += EnvelopeAndDecryptData( MOC_RSA( hwAccelCtx) 1,
                                            FILE_PATH("selfcert2.der"), 
                                            FILE_PATH("keyblobFile2.dat")); 

    /* ECDH test */
    retVal += EnvelopeAndDecryptData( MOC_RSA( hwAccelCtx) 2,
                                            FILE_PATH("ecc_selfcert2.der"),
                                            FILE_PATH("ecc_keyblobFile2.dat")); 

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}


/*---------------------------------------------------------------------------------*/

static int VerifyOpenSSLSign( int hint, const char* signedFile,
                             const char* certFile)
{
    int retVal = 0;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    ASN1_ITEMPTR pSignedDataRoot = 0, pTemp;
    MemFile memFile;
    CStream cs;
    sbyte4 numKnownSigners;
    hwAccelDescr hwAccelCtx;
    certStorePtr pCertStore = 0;

    retVal += UNITTEST_STATUS( 0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, DIGICERT_readFile( signedFile, &buffer, &bufferLen));
    if (retVal) goto exit;

    MF_attach(&memFile, bufferLen, buffer);
    CS_AttachMemFile(&cs, &memFile );
    retVal += UNITTEST_STATUS(hint, ASN1_Parse(cs, &pSignedDataRoot));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp));
    if (retVal) goto exit;

    /* verify the signature */
    UNITTEST_STATUS_GOTO(hint, CERT_STORE_createStore(&pCertStore), retVal, exit);

    retVal += load_trust_point(hint, pCertStore, certFile);
    if ( retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, PKCS7_VerifySignedData(MOC_RSA(hwAccelCtx) pTemp, cs,
                                                           pCertStore, NULL,
                                                           CERT_STORE_PKCS7_ValidateRootCertificate,
                                                           NULL, 0, &numKnownSigners));
    if (retVal) goto exit;

    retVal += UNITTEST_INT(hint, 1, numKnownSigners);
    
exit:

    if ( pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    if (buffer)
    {
        FREE(buffer);
    }

    CERT_STORE_releaseStore(&pCertStore);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------------------*/

int pkcs7_cert_store_test_VerifyOpenSSLSign()
{
    int retVal = 0;

    retVal += VerifyOpenSSLSign( 1, FILE_PATH("openssl_ec521_sign.der"),
                                FILE_PATH("openssl_ec521_cert.der"));

    return retVal;
}

