/*
 *  crypto_interface_pkcs7_test.c
 *
 *   unit test for pkcs7.c
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

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

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


static const char* gCurrCertFileName;
static const char* gCurrKeyFileName;

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
    MemFile memFile;
    CStream certCS;
    ASN1_ITEM* pCertRoot = 0;

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

    return status;
}

static MSTATUS myValCertFun(const void* arg, CStream cs,
                            ASN1_ITEM* pCertificate, sbyte4 certChain)
{
    return OK;
}


/* these functions should return the certificate */
static MSTATUS myGetCertFun(const void* arg, CStream cs,
                            ASN1_ITEM* pSerialNumber, ASN1_ITEM* pIssuerName,
                            ubyte** ppCertificate, ubyte4* certificateLen)
{
    return DIGICERT_readFile( FILE_PATH("signerCert.der"),
                            ppCertificate,
                            certificateLen);
}

/* Version 3, in practice search for the certificate with
   the matching pSubjectKeyId but for testing we can
   get the one we know matches */
static MSTATUS myGetCertFunV3(const void* arg, CStream cs,
    ASN1_ITEM* pSubjectKeyId,
    ubyte** ppCertificate, ubyte4* certificateLen)
{
    return DIGICERT_readFile( FILE_PATH("rsa_cert_ski.der"),
                            ppCertificate,
                            certificateLen);
}

/* sign some data and then verify */
static int SignAndVerifyData(int hint, const char* selfCertFile, const char* keyblobFile, byteBoolean isDer)
{
    MSTATUS status = OK;
    ubyte* payLoad = (ubyte*) "This is signed data content.";
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo mySignerInfo;
    ubyte* pSigned = NULL;
    ubyte4 signedLen;
    ubyte *pSelfCertFile=NULL, *pKeyblob=NULL;
    ubyte4 selfCertFileLen, keyblobLen;
    CStream cs, certStream;
    CStream certStreams[1];
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    ASN1_ITEMPTR pCertificates[1];
    AsymmetricKey key;
    Attribute *pAuthAttributes = NULL;
    ubyte4 authAttributeLen = 1;
    sbyte4 numKnownSigners;
    int retVal = 0;

    /* read in signer certificate */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( selfCertFile, &pSelfCertFile, &selfCertFileLen),
                         retVal, exit);

    MF_attach(&memFile, selfCertFileLen, (ubyte*) pSelfCertFile);
    CS_AttachMemFile(&certStream, &memFile );

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(certStream, &pSelfCertificate),
                         retVal, exit);
    /* read in signer private key */

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyblobFile, &pKeyblob, &keyblobLen),
                        retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CRYPTO_initAsymmetricKey( &key),
                        retVal, exit);

    if(isDer)
    {
        UNITTEST_STATUS_GOTO(hint, CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKeyblob, keyblobLen, NULL, &key),
                            retVal, exit);
    }
    else
    {
        UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key),
                            retVal, exit);
    }

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
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
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
    UNITTEST_STATUS_GOTO(hint, PKCS7_SignData(MOC_ASYM(gpHwAccelCtx) 0,
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

    /* verify the signature */
    UNITTEST_STATUS_GOTO(hint, PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pTemp, cs, NULL,
                                                      NULL, myValCertFun, NULL, 0,
                                                      &numKnownSigners),
                         retVal, exit);

    retVal += UNITTEST_INT(hint, 1, numKnownSigners);

exit:

    if (pAuthAttributes)
    {
        FREE(pAuthAttributes);
    }

    if (pSelfCertificate)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }
    if (pSigned)
    {
        FREE(pSigned);
    }

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    if (pSelfCertFile)
    {
        FREE(pSelfCertFile);
    }
    if (pKeyblob)
    {
        FREE(pKeyblob);
    }

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return retVal;
}

static int signAndVerify(ubyte* contentType)
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
    ubyte *pSelfCertFile=NULL, *pKeyblob=NULL;
    ubyte4 selfCertFileLen, keyblobLen;
    CStream cs, certStream;
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    AsymmetricKey key;
    sbyte4 numKnownSigners;

    /* read in signer certificate */
    if (OK > (status = DIGICERT_readFile( selfCertFile, &pSelfCertFile, &selfCertFileLen)))
        goto exit;

    MF_attach(&memFile, selfCertFileLen, (ubyte*) pSelfCertFile);
    CS_AttachMemFile(&certStream, &memFile );

    if (OK > (status = ASN1_Parse(certStream, &pSelfCertificate)))
        goto exit;

    /* read in signer private key */
    if (OK > (status = DIGICERT_readFile( keyblobFile, &pKeyblob, &keyblobLen)))
        goto exit;
    if (OK > (status = CRYPTO_initAsymmetricKey( &key)))
        goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key)))
        goto exit;

    /* create signer infos */
    /* get issuer and serial number of certificate */
    if ( OK > ( status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber)))
        goto exit;
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

    PKCS7_SignData(MOC_ASYM(gpHwAccelCtx) 0, pContentInfo, pSignedData,
                   &pSelfCertificate, &certStream, 1,
                   NULL, NULL, 0, /* no crls */
                   mySignerInfoPtr, 1,
                   contentType, payLoad, DIGI_STRLEN((const sbyte*) payLoad),
                   RANDOM_rngFun, g_pRandomContext,
                   &pSigned, &signedLen);

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedLen, (ubyte*)pSigned );
    CS_AttachMemFile(&cs, &memFile );
    ASN1_Parse(cs, &pSignedDataRoot);

    /* walk tree to verify signed data type */
    /* or use openssl to verify it but that introduce a dependency on a third party app */
    if (OK > (status = PKCS7_GetCertificates(pSignedDataRoot, cs, &pTemp)))
        goto exit;

    if (OK > (status = ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp)))
        goto exit;

    /* verify the signature */
    if (OK > (status = PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pTemp, cs, NULL,
                                              NULL, myValCertFun, NULL, 0,
                                              &numKnownSigners)))
    {
        goto exit;
    }

    if (numKnownSigners != 1)
    {
        status = ERR_PKCS7;
        goto exit;
    }
    /* verify absence of authenticated attributes */
    {
        ASN1_ITEMPTR pNextSibling;
        /* certificate has tag 0 or 2 */
        pTemp = ASN1_FIRST_CHILD(pTemp);
        /* now go to the signer Info: this is the last child of the sequence */
        pTemp = ASN1_NEXT_SIBLING( pTemp);
        if ( 0 == pTemp)
        {
            /* must be at least one */
            return ERR_PKCS7_INVALID_STRUCT;
        }

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
    if (pSigned)
    {
        FREE(pSigned);
    }

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    if (pSelfCertFile)
    {
        FREE(pSelfCertFile);
    }
    if (pKeyblob)
    {
        FREE(pKeyblob);
    }

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return UNITTEST_STATUS(1, status);
}

/* sign some data and then verify */
static int pkcs7_test_SignAndVerifyDetachedSignature()
{
    MSTATUS status = OK;
    const ubyte* payLoad = (const ubyte*) "Hello World";
    DER_ITEMPTR pContentInfo=NULL, pSignedData;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo mySignerInfo;
    ubyte* pSigned = NULL;
    ubyte4 signedLen;
    const char* selfCertFile = FILE_PATH("cert.der");
    const char* pemKeyFile = FILE_PATH("key.pem");
    ubyte *pSelfCertFile=NULL, *pPemKey=NULL, *pKeyblob=NULL;
    ubyte4 selfCertFileLen, pemKeyLen, keyblobLen;
    CStream cs, certStream;
    CStream certStreams[1];
    MemFile memFile;
    ASN1_ITEMPTR pSelfCertificate=NULL, pIssuer, pSerialNumber, pSignedDataRoot=NULL, pTemp;
    ASN1_ITEMPTR pCertificates[1];
    AsymmetricKey key;
    Attribute *pAuthAttributes = NULL;
    ubyte4 authAttributeLen = 1;
    sbyte4 numKnownSigners;

    /* read in signer certificate */
    if (OK > (status = DIGICERT_readFile( selfCertFile, &pSelfCertFile, &selfCertFileLen)))
        goto exit;

    MF_attach(&memFile, selfCertFileLen, (ubyte*) pSelfCertFile);
    CS_AttachMemFile(&certStream, &memFile );

    if (OK > (status = ASN1_Parse(certStream, &pSelfCertificate)))
        goto exit;

    /* read in signer private key */
    if (OK > (status = DIGICERT_readFile( pemKeyFile, &pPemKey, &pemKeyLen)))
        goto exit;

    if (OK > (status = BASE64_initializeContext()))
        goto exit;

    if (OK > (status = CA_MGMT_convertKeyPEM(pPemKey, pemKeyLen, &pKeyblob, &keyblobLen)))
        goto exit;

    if (OK > (status = BASE64_freeContext()))
        goto exit;

    if (OK > (status = CRYPTO_initAsymmetricKey( &key)))
        goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key)))
        goto exit;

    /* create signer infos */
    /* get issuer and serial number of certificate */
    if ( OK > ( status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber)))
        goto exit;
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
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
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
    PKCS7_SignData(MOC_ASYM(gpHwAccelCtx)
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
                   &signedLen);

    if (OK > (status = DIGICERT_writeFile(FILE_PATH("detachedSignature2.der"), pSigned, signedLen)))
        goto exit;

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedLen, (ubyte*)pSigned );
    CS_AttachMemFile(&cs, &memFile );
    ASN1_Parse(cs, &pSignedDataRoot);

    /* walk tree to verify signed data type */
    /* or use openssl to verify it but that introduce a dependency on a third party app */
    if (OK > (status = PKCS7_GetCertificates(pSignedDataRoot, cs, &pTemp)))
        goto exit;

    if (OK > (status = ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp)))
        goto exit;


    /* verify the signature */
    if (OK > (status = PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pTemp, cs,
                                              NULL, NULL, myValCertFun,
                                              payLoad,
                                              DIGI_STRLEN((const sbyte*) payLoad),
                                              &numKnownSigners)))
    {
        goto exit;
    }

    if (numKnownSigners != 1)
    {
        status = ERR_PKCS7;
        goto exit;
    }
exit:

    if (pAuthAttributes)
    {
        FREE(pAuthAttributes);
    }

    if (pSelfCertificate)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }

    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }
    if (pSigned)
    {
        FREE(pSigned);
    }

    if (pSignedDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedDataRoot);
    }

    if (pSelfCertFile)
    {
        FREE(pSelfCertFile);
    }
    if (pKeyblob)
    {
        FREE(pKeyblob);
    }

    if (pPemKey)
    {
        FREE(pPemKey);
    }

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return UNITTEST_STATUS(1, status);
}


/* degenerate SignedData is used to distribute certificates and crls
 * 1. create a degenerate SignedData to distribute two certificates read from files;
 * 2. parse the generated SignedData and walk the tree to verify the structure and return the certificates;
 * 3. compare the certificates with those read from files.
 */
#define num 2
static int pkcs7_test_SignDataDegenerate()
{
    MSTATUS status = OK;
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

    /* load and parse certificates */
    for (i = 0; i < num; i++)
    {
        if (OK > (status = DIGICERT_readFile( files[i], &(pCertFile[i]), &certFileLen[i])))
        goto exit;

        MF_attach(&certMemFile[i], certFileLen[i], (ubyte*) pCertFile[i]);
        CS_AttachMemFile(&pStreams[i], &certMemFile[i] );

        ASN1_Parse(pStreams[i], &pCertificates[i]);
    }

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    /* create a degenerate SignedData type with the two certificates */
    if (OK > (status = PKCS7_SignData(MOC_ASYM(gpHwAccelCtx) 0,
                                      pContentInfo, pSignedData,
                                      pCertificates, pStreams, 2,
                                      NULL, NULL, 0,
                                      NULL,
                                      0,
                                      NULL, NULL, 0,
                                      RANDOM_rngFun, g_pRandomContext,
                                      &pSignedDegenerated,
                                      &signedDegeneratedLen)))
    {
        goto exit;
    }

    /* parse the resulting SignedData */
    MF_attach(&memFile, signedDegeneratedLen, (ubyte*)pSignedDegenerated );
    CS_AttachMemFile(&cs, &memFile );
    ASN1_Parse(cs, &pCertRoot);

    /* walk the tree to verify and retrieve the two certificates */
    if (OK > (status = PKCS7_GetCertificates(pCertRoot, cs, &pFirstCert)))
        goto exit;

    /* compare to make sure we get back the same two certificates */
    for (i = 0; i < num; i++)
    {
        if (OK != (status = ASN1_CompareItems(ASN1_FIRST_CHILD(pCertificates[i]), pStreams[i], pFirstCert, cs)))
            goto exit;

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

    return UNITTEST_STATUS(2, status);
}

/* verify a third party signedData. the signer certificate is provided in a callback */
static int verifySignedData(const char *signedFile)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *pFile=NULL;
    ubyte4 fileLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;

    if (OK > (status = DIGICERT_readFile( signedFile, &pFile, &fileLen)))
        goto exit;

    MF_attach(&memFile, fileLen, (ubyte*) pFile);
    CS_AttachMemFile(&cs, &memFile );

    ASN1_Parse(cs, &pRoot);

    if (OK > (status = ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData)))
        goto exit;

    if (OK > (status = PKCS7_VerifySignedDataV3(MOC_ASYM(gpHwAccelCtx) pSignedData, cs,
                                                NULL, myGetCertFun, myGetCertFunV3, myValCertFun,
                                                NULL, 0, &numKnownSigners)))
    {
        goto exit;
    }

exit:
    if (pFile)
    {
        FREE(pFile);
    }
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }

    return UNITTEST_STATUS(3, status);
}

/* verify openssl generated detached signature. Signer's certificate is included in signature. So no need
* to pass in the certificate retrieval callback function. (passing NULL)
* the detachedSignature.der file can be generated by the following command: (keypassword: passwd)
* $ openssl smime -sign -in content.txt -outform DER -out detachedSignature.der -signer cert.pem -inkey key.pem
* the detached signature can be verified using openssl with the following command:
$ openssl smime -verify -inform DER -in detachedSignature.der -noverify -content content.txt
*/
static int pkcs7_test_VerifyDetachedSignature()
{
    MSTATUS status = OK;
    const char* signedFile= FILE_PATH("detachedSignature.der");
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *pFile=NULL;
    ubyte4 fileLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;

    if (OK > (status = DIGICERT_readFile( signedFile, &pFile, &fileLen)))
        goto exit;

    MF_attach(&memFile, fileLen, (ubyte*) pFile);
    CS_AttachMemFile(&cs, &memFile );

    ASN1_Parse(cs, &pRoot);

    if (OK > (status = ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData)))
        goto exit;

    if (OK > (status = PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pSignedData, cs,
                                              NULL, NULL, myValCertFun,
                                              (ubyte*) "Hello World", 11,
                                              &numKnownSigners)))
    {
        goto exit;
    }

    /* also make sure that we would correctly fail to verify the wrong content */
    status = PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pSignedData, cs,
                                    NULL, NULL, myValCertFun,
                                    (ubyte*) "Hello There", 11,
                                    &numKnownSigners);
    if (status == ERR_PKCS7_INVALID_SIGNATURE)
        status = OK;


exit:
    if (pFile)
    {
        FREE(pFile);
    }
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }

    return UNITTEST_STATUS(3, status);
}

/* read in a third party degenerate signed data file.
 * verify the structure and make sure there are two certs contained within
 */
static int pkcs7_test_VerifyDegenerateSignedData()
{
    MSTATUS status = OK;
    const char* file= {FILE_PATH("degenerateSignedData.der")};
    ASN1_ITEMPTR pRoot=NULL, pSignedData;
    ubyte *pDataFile=NULL;
    ubyte4 dataFileLen;
    CStream cs;
    MemFile memFile;
    sbyte4 numKnownSigners;

    if (OK > (status = DIGICERT_readFile( file, &pDataFile, &dataFileLen)))
        goto exit;

    MF_attach(&memFile, dataFileLen, (ubyte*) pDataFile);
    CS_AttachMemFile(&cs, &memFile );

    ASN1_Parse(cs, &pRoot);

    if (OK > (status = ASN1_WalkTree( pRoot, cs, contentInfoRootToContent, &pSignedData)))
        goto exit;

    if (OK > (status = PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pSignedData, cs,
                                              NULL, NULL, NULL, NULL, 0,
                                              &numKnownSigners)))
    {
        goto exit;
    }
exit:
    if (pDataFile)
    {
        FREE(pDataFile);
    }
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }

    return UNITTEST_STATUS(4, status);
}

/* decrypt a third party envelopedData; the private key is available in
keyblobFile.dat. the decrypted content should be a degenerate signed data
*/
static int Decrypt_pkcs7_envelopedData( int hint, const char* file,
                                       const char* outFile,
                                       const char* certFile,
                                       const char* keyFile)
{
     MSTATUS status = OK;
    int retVal = 0;
    ubyte *pDataFile=NULL, *pOutDataFile = NULL, *decryptedInfo=NULL;
    ubyte4 dataFileLen, outDataFileLen;
    sbyte4 decryptedInfoLen;
    ASN1_ITEMPTR pEnvelopedRoot=NULL, pEnvelopedData, pSignedRoot=NULL;
    MemFile memFile1;
    CStream cs1;
    sbyte4 resCmp;

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( file, &pDataFile, &dataFileLen),
                            retVal, exit);

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( outFile, &pOutDataFile, &outDataFileLen),
                            retVal, exit);

    MF_attach(&memFile1, dataFileLen, (ubyte*) pDataFile);
    CS_AttachMemFile(&cs1, &memFile1 );

    ASN1_Parse(cs1, &pEnvelopedRoot);

    UNITTEST_STATUS_GOTO(hint, ASN1_WalkTree( pEnvelopedRoot, cs1, contentInfoRootToContent,
                                            &pEnvelopedData),
                         retVal, exit);

    /* set up the globals used by myGetPrivateKeyFun */
    gCurrCertFileName = certFile;
    gCurrKeyFileName = keyFile;
    UNITTEST_STATUS_GOTO(hint, PKCS7_DecryptEnvelopedData(MOC_HW(gpHwAccelCtx)
                                                          pEnvelopedData, cs1,
                                                          NULL, myGetPrivateKeyFun,
                                                          &decryptedInfo,
                                                          &decryptedInfoLen),
                           retVal, exit);


    /* verify that the decryptedInfo match the content of outFile */
    retVal += UNITTEST_INT(hint, decryptedInfoLen, outDataFileLen);

    DIGI_MEMCMP( decryptedInfo, pOutDataFile, outDataFileLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, resCmp ==0);

exit:

    if (pDataFile)
    {
        FREE(pDataFile);
    }
    if (pOutDataFile)
    {
        FREE(pOutDataFile);
    }

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

    return retVal;
}

static int EnvelopeAndDecryptData(int hint, const char* certFileName, const char* keyFileName)
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

    retVal += UNITTEST_STATUS(hint, DIGICERT_readFile( certFileName, &pCertFile, &certFileLen));
    if (retVal) goto exit;

    MF_attach(&memFile1, certFileLen, (ubyte*) pCertFile);
    CS_AttachMemFile(&cs1, &memFile1);

    ASN1_Parse(cs1, &pCertRoot);

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_envelopedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pEnvelopedData);

    retVal += UNITTEST_STATUS(hint, PKCS7_EnvelopData(MOC_HW(gpHwAccelCtx) pContentInfo, pEnvelopedData,
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

    ASN1_Parse(cs2, &pEnvelopedRoot);

    retVal += UNITTEST_STATUS(hint,
        ASN1_WalkTree( pEnvelopedRoot, cs2, contentInfoRootToContent, &pEnvelopedData2));
    if (retVal) goto exit;

    /* set up the globals used by myGetPrivateKeyFun */
    gCurrCertFileName = certFileName;
    gCurrKeyFileName = keyFileName;
    retVal += UNITTEST_STATUS(hint, PKCS7_DecryptEnvelopedData(MOC_HW(gpHwAccelCtx)
                                                               pEnvelopedData2,
                                                               cs2,
                                                               NULL,
                                                               myGetPrivateKeyFun,
                                                               &decryptedInfo,
                                                               &decryptedInfoLen));
    if (retVal) goto exit;

    retVal += UNITTEST_INT(0, decryptedInfoLen, DIGI_STRLEN((const sbyte*) payLoad));
    if (retVal) goto exit;
    
    DIGI_MEMCMP(payLoad, decryptedInfo, decryptedInfoLen, &cmpResult);
    retVal += UNITTEST_TRUE( hint, 0 == cmpResult);

exit:
    if (pCertFile)
    {
        FREE(pCertFile);
    }
    if (pEnveloped)
    {
        FREE(pEnveloped);
    }
    if (decryptedInfo)
    {
        FREE(decryptedInfo);
    }

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

static MSTATUS getFixedKeyFun(const void* arg, CStream cs,
                              ASN1_ITEM* pSerialNumber,
                              ASN1_ITEM* pIssuerName,
                              AsymmetricKey* pAsymKey)
{
    MSTATUS status = OK;
    ubyte* pKeyBlob = 0;
    ubyte4 keyBlobLen;
    ubyte* buff = 0;
    ubyte4 buffLen;
    MemFile memFile;
    CStream certCS;
    ASN1_ITEM* pCertRoot = 0;

    char *pKey = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100de49561c2f9baf684d"
                 "34f48dae911d66383a3a6ea40ebd89808716111503eddad1e858e19c29f2e82e3e1873c2da9b7ffee24f40abd475b2"
                 "afd8fe622844937c4678818f8644aeaed3bc34fb1ee7ea79a9adc7bc92583ad08e0affe53f37f7c57875c2166e755f"
                 "599b40b51d554051a3b78c08133c3364c610e408fda6216b512a0732853ead15aae0bb85df043e73f0eb244193cd5a"
                 "33657312ecccac980d03a24c785a63e7083b0a0c3a8e31e16d7526edd6b44aa0d69cfc0ea2cc8093d42ff8c96a12d0"
                 "db6c31df989cf2dd94c483d3a92da6d3daa16def6fd95697fcda3f3ab5ef1477a2b263c444173ae2f28f3e7a3e992c"
                 "d3c44e73661fbc16518923470203010001028201007f292ee492eb9a0dadd5346d74c6b92dc7ceafaca99771201ef1"
                 "a852ff55af14f5edd822c046531a3591fa4506dc2e06abd5e5069705c48b0303bc8a8484ae66729def681ea45dd5cf"
                 "74a44e6020c5c6f1a56354e1d72d562f5be585cc8384ef6778de1e1cf472267da527b6ef150b5effda50a84851123e"
                 "285d7b33377d78b8f542cc02a95f73b98569b4b67255f309528a52b55183998b45b1b18dc0d5a570c31c4183831bbe"
                 "0e0a49693e4ed6d727745d06147fcc442da71f4e1b89cc60ab45f587018d42dc9e335f876da7a8ada75c5c110ca4b8"
                 "d8df158bf89b19f6446766639d065ec07c460928e3f597e6a4a39f368ecbdd100499ab8867e1416a0fc902818100fd"
                 "a7f9b5a0693b2a29a9d5b5b7ca950dd8f9fc63a1700c44e3d6986bfc29b6e43cc06a5e021ad937d7a48be09ae13366"
                 "aa72dbb5d0cfbf61533cb91090af7416ae0941e3c48853fb52538338d39f53c836a0a4e7cf7a5b742eab845f55b42c"
                 "35cc4d497f48b54afdddd63352d7a8f7d58a442a40125030d0e2f013e27ac4584d02818100e05727e4e800ce444360"
                 "24fe1a3a4c757e427614cf1ada175375fe31d129c5828f7587d6abffc1b8597936bbe6c2e51e062101f6511d65b0da"
                 "02e94fd4fd386c017bf8415f9d0a04412d589ef88d168b59d1c4b35e9bd8a42846de1924d835540d6b6013d9931432"
                 "cb4b4899a2b7993cf352a969c86d13fd118acaa752f5b3e302818100b003f0e6951290a8b8528ee6d34bb354f19cbf"
                 "03cfd1b5e1d40c64a6824bdc0ad3115e7e2f8dbbefe126e09d923bf57427911e5f333006089e3f03d8b7ddd87ba876"
                 "ea0f08a0e54dff99cdf40ffd7ea0ef2f585f377d1b9b2a8b8086bb2d14849c698137df17569b85658f25cc5b06e75a"
                 "53e4d1a3239c4c473dfb3e6c9c74fd0281804c053cbf94deb106f0cde3bb37a809c0c6c83ebb4e730af45c93df4f82"
                 "51655c98c07b0783c16723d12e021e2a5460cf8bc423a61456a1df0c01708e5cde720027809adf8c46eade0638178f"
                 "c72a0839b07624f1a35dac4bf45a0f68f5d34e3eed4d35818479129f23c49f1570ce465f211521d376d77fae820346"
                 "28ed33d581028181009271ded96dd63ea86a5b5eefe88513ba92e74f96882884a8e2593e2795c0b992178f03725dfc"
                 "95a3682d034a4fa51f06cd176a6347480b4441c4c5083ed9c0c978942d1933ad1a8d10a51a71529a6e36bfdbab5778"
                 "abf9979f5db339b7e2961f38cb6ab2f5a46f9d6b08de00b807ec2dc458a146f7fe0df039175c44cfc14e93";

    ubyte *pKeyBin = NULL;
    ubyte4 keyLen = 0;

    keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pKey, &pKeyBin);

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKeyBin, keyLen, NULL, pAsymKey);

exit:

    if (pKeyBin)
    {
        FREE(pKeyBin);
    }

    return status;
}

static int pkcs7_test_decrypt(char *pEnv)
{
    ubyte* payLoad = (ubyte*) "test cms rsa oaep\r\n";
    ASN1_ITEMPTR pEnvelopedRoot=NULL, pEnvelopedData = NULL;

    MemFile memFile;
    CStream cs;
    sbyte4 cmpResult;
    int retVal = 0;

    ubyte *pEnvBin = NULL;
    ubyte4 envLen = 0;

    ubyte *decryptedInfo = NULL;
    ubyte4 decryptedInfoLen = 0;

    envLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pEnv, &pEnvBin);

    MF_attach(&memFile, envLen, pEnvBin);
    CS_AttachMemFile(&cs, &memFile);

    ASN1_Parse(cs, &pEnvelopedRoot);

    retVal += UNITTEST_STATUS(__MOC_LINE__, ASN1_WalkTree( pEnvelopedRoot, cs, contentInfoRootToContent, &pEnvelopedData));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, PKCS7_DecryptEnvelopedData(MOC_HW(gpHwAccelCtx)
                                                                       pEnvelopedData,
                                                                       cs,
                                                                       NULL,
                                                                       getFixedKeyFun,
                                                                       &decryptedInfo,
                                                                       &decryptedInfoLen));
    if (retVal) goto exit;

    retVal += UNITTEST_INT(0, decryptedInfoLen, DIGI_STRLEN((const sbyte*) payLoad));
    if (retVal) goto exit;
    
    DIGI_MEMCMP(decryptedInfo, payLoad, decryptedInfoLen - 2, &cmpResult);
    retVal += UNITTEST_TRUE( __MOC_LINE__, 0 == cmpResult);

exit:

    if (NULL != pEnvBin)
    {
        (void) DIGI_FREE((void **) &pEnvBin);
    }

    if (NULL != decryptedInfo)
    {
        (void) DIGI_FREE((void **) &decryptedInfo);
    }

    if (NULL != pEnvelopedRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem*)pEnvelopedRoot);
    }

    return retVal;
}

static int pkcs7_test_decrypt_all()
{
    int retVal = 0;

    /* Sha512 with label.

       openssl cms -encrypt -in plain.txt -out cipher.txt -recip rsa2048.pem -keyopt rsa_padding_mode:oaep 
                   -keyopt rsa_oaep_md:sha512 -keyopt rsa_mgf1_md:sha512 -keyopt rsa_oaep_label:637573746f6d5f6c6162656c

       where plain.txt is a text file containing "test cms rsa oaep\r\n" and rsa2048.pem is the cert for the key hardcoded
       in getFixedKeyFun. The following envelope is the data inside cipher.txt
    */
    char *pEnv = "3082025e06092a864886f70d010703a082024f3082024b02010031820207"
                 "308202030201003081a2308189310b3009060355040613025553310b3009"
                 "06035504080c0243413112301006035504070c0953756e6e7976616c6531"
                 "0f300d060355040a0c064d6f63616e6131143012060355040b0c0b437279"
                 "70746f205465616d310e300c06035504030c054a61696d65312230200609"
                 "2a864886f70d01090116136a68616c65746b79406d6f63616e612e636f6d"
                 "02141c4df3f52ac8f635733b565293947f3d33d116ce305506092a864886"
                 "f70d0101073048a00d300b0609608648016503040203a11a301806092a86"
                 "4886f70d010108300b0609608648016503040203a21b301906092a864886"
                 "f70d010109040c637573746f6d5f6c6162656c04820100240217cfc5d9a4"
                 "bca0440c4a183b439b49197c8850812ec263a3a2152326d063c51494c253"
                 "841642e79e37ebf287620571065a101620637f8ab8ba51fb6984b25bd498"
                 "af10bff9495284817ae698e0ff25b50a7be54aacbfae84d485ec9ccb91f3"
                 "ad12100516f260b1836755a58143ee5da910db96ca0d49dcfb83b46dcb41"
                 "d419407dc615dbd9bd3ceb19d5d033b692195a9776f041575602e861accc"
                 "cdaf18233ab310826eaa62ccbeb5d8d1e7c8a83683bab00621115d4ae9de"
                 "9f2e6c1a9dbdd6bbd7b2e1966fe5efe181deb69f61e71befcd6539e4fe0a"
                 "bbbcb776e369ed858636842f94dbee5b82b6d3db3ae088c6c2d5ae51ad2d"
                 "9df6592c7372c064fa303b06092a864886f70d010701301406082a864886"
                 "f70d0307040805669d8494c42d2f80182efd188ef52ff4a72c9d3b7857e6"
                 "a7c41b8dd894770d8192";

    /* sha384 with no label
    
        openssl cms -encrypt -in plain.txt -out cipher.txt -recip rsa2048.pem -keyopt rsa_padding_mode:oaep \
                    -keyopt rsa_oaep_md:sha384 -keyopt rsa_mgf1_md:sha384
     */
    char *pEnv2 = "3082024106092a864886f70d010703a08202323082022e020100318201ea308201e60201003081a2308189310b3009060355040613025553310"
                  "b300906035504080c0243413112301006035504070c0953756e6e7976616c65310f300d060355040a0c064d6f63616e6131143012060355040b"
                  "0c0b43727970746f205465616d310e300c06035504030c054a61696d653122302006092a864886f70d01090116136a68616c65746b79406d6f6"
                  "3616e612e636f6d02141c4df3f52ac8f635733b565293947f3d33d116ce303806092a864886f70d010107302ba00d300b060960864801650304"
                  "0202a11a301806092a864886f70d010108300b0609608648016503040202048201007f47f6a3d938ca2f7e4b7bcecce771177916bf2aeb05270"
                  "8ce2bf99c1e3440a142331b253ee926ad94ed685c1a5255922354a84f68e61cfdaa915d7ee2b3683088df9a5b7b001322c91113080b1a2284dd"
                  "6b0c8c8eddbee5b571ccf1f5b4630d6aa9948fae83609f61dbaf2553d512235c017aa95b7f69c137ae4d3380aa6cc9909292bc795b556380dd4"
                  "70793e49c0b41ea0978bd468186600a7b2eacb5e49f922d2a3d3d60c6238eedf055cc02b8899ea6799f6912bcd4161d678d1b13b3910f48de4a"
                  "23545719922c7148bea4961c2b2882020271d3ec9f041e74f38a2b6cdbca9938bd93cb47595474270be75aa6010ad07e8eb717c19b5b7c902a1"
                  "e66ed303b06092a864886f70d010701301406082a864886f70d03070408c80ce2c72b7413148018c0388839c67d8bd42552a5711c69b57f858e"
                  "47e8924cfed3";

    /* sha1 with no label 

    openssl cms -encrypt -in plain.txt -out cipher.txt -recip rsa2048.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha1 \
                -keyopt rsa_mgf1_md:sha1
     
     */
    char *pEnv3 = "3082021606092a864886f70d010703a082020730820203020100318201bf308201bb0201003081a2308189310b3009060355040613025553310"
                  "b300906035504080c0243413112301006035504070c0953756e6e7976616c65310f300d060355040a0c064d6f63616e6131143012060355040b"
                  "0c0b43727970746f205465616d310e300c06035504030c054a61696d653122302006092a864886f70d01090116136a68616c65746b79406d6f6"
                  "3616e612e636f6d02141c4df3f52ac8f635733b565293947f3d33d116ce300d06092a864886f70d01010730000482010040ad0c85a7152d4b23"
                  "eb97d8b38966f29102126187faecb363ba6f322a778006550c3793f008352ba2a1ded6a5117098175aa7e81e5c02770e1406a0fd1db7e52f7c3"
                  "3af1af52319d3e1bcb639932d3e3e8568e2dd4aa86c1a76b06e7c34894694f20c08fc86cf69505d34c78ff726d8f6f74d652e87774e2087e6d7"
                  "597d63c75b9a14c3a0bea935bd23ddd72720e8b9d5398dc2e4c21c262b458a140cfacfa6308aa9e8dbd93049408ab4de4be35cd2721fd6c7b94"
                  "e3065f0ff043d96cb0de0c03d2bc74b0959b4a16d187fc9a9a6056512ef4ed272b92bb9da25fe7418f3e7183cd49384d32c69377256567cbd7f"
                  "36da9835041727c350315ab376a4b13390303b06092a864886f70d010701301406082a864886f70d03070408ed3681cc38e50e4b8018bbb26f6"
                  "41d15cac807dd3de4773d840d1d5ee33833bf41dd";

    retVal += pkcs7_test_decrypt(pEnv);
    retVal += pkcs7_test_decrypt(pEnv2);
    retVal += pkcs7_test_decrypt(pEnv3);

    return retVal;
}

/*---------------------------------------------------------------------------------*/

static int VerifyOpenSSLSign( int hint, const char* signedFile)
{
    int retVal = 0;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    ASN1_ITEMPTR pSignedDataRoot = 0, pTemp;
    MemFile memFile;
    CStream cs;
    sbyte4 numKnownSigners;

    retVal += UNITTEST_STATUS(hint, DIGICERT_readFile( signedFile, &buffer, &bufferLen));
    if (retVal) goto exit;

    MF_attach(&memFile, bufferLen, buffer);
    CS_AttachMemFile(&cs, &memFile );
    retVal += UNITTEST_STATUS(hint, ASN1_Parse(cs, &pSignedDataRoot));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pSignedDataRoot, cs, contentInfoRootToContent, &pTemp));
    if (retVal) goto exit;

    /* verify the signature */
    retVal += UNITTEST_STATUS(hint, PKCS7_VerifySignedData(MOC_ASYM(gpHwAccelCtx) pTemp, cs,
                                                           NULL, NULL, myValCertFun,
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

    return retVal;
}


/*---------------------------------------------------------------------------------*/

int crypto_interface_pkcs7_test_all()
{
    MSTATUS status;
    int retVal = 0;

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

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

/* RSA tests that use a 1024 bit key are not supported by mbedtls */
#ifndef __ENABLE_DIGICERT_RSA_MBED__
    retVal += SignAndVerifyData(1, FILE_PATH("selfcert.der"), FILE_PATH("keyblobFile.dat"), FALSE);
#endif
    retVal += SignAndVerifyData(2, FILE_PATH("ecc_selfcert.der"), FILE_PATH("ecc_keyblobFile.dat"), FALSE);
#ifdef __ENABLE_DIGICERT_PQC__
    retVal += SignAndVerifyData(3, FILE_PATH("mldsa44_cert.der"), FILE_PATH("mldsa44_key.der"), TRUE);
#endif

#ifndef __ENABLE_DIGICERT_RSA_MBED__
    retVal += signAndVerify((ubyte *)pkcs7_data_OID);
    retVal += signAndVerify((ubyte *)pkcs7_signedData_OID);
#endif

    retVal += pkcs7_test_SignAndVerifyDetachedSignature();
    retVal += pkcs7_test_SignDataDegenerate();

    retVal += verifySignedData("signedData.der");
    retVal += verifySignedData("cms_signed_rsa_ski.der");

    retVal += pkcs7_test_VerifyDetachedSignature();
    retVal += pkcs7_test_VerifyDegenerateSignedData();

#ifndef __ENABLE_DIGICERT_RSA_MBED__
    retVal += Decrypt_pkcs7_envelopedData(1, FILE_PATH("envelopedData.der"),
                                          FILE_PATH("degenerateSignedData.der"),
                                          FILE_PATH("selfcert.der"),
                                          FILE_PATH("keyblobFile.dat"));

    /* RSA test */
    retVal += EnvelopeAndDecryptData(1, FILE_PATH("selfcert.der"),
                                        FILE_PATH("keyblobFile.dat"));

#endif
    /* ECDH test */
    retVal += EnvelopeAndDecryptData(2, FILE_PATH("ecc_selfcert.der"),
                                        FILE_PATH("ecc_keyblobFile.dat"));
    retVal += pkcs7_test_decrypt_all();
    retVal += VerifyOpenSSLSign( 1, FILE_PATH("openssl_ec521_sign.der"));

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    DIGICERT_free(&gpMocCtx);

    return retVal;
}
