/*
 *  cms_test.c
 *
 *   unit test for cms.inc
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
#include "../../crypto/pkcs_key.h"
#include "../../crypto/cms.h"
#include "../../crypto/cms_aux.h"

#include "../../crypto/test/cms_test.h" /* shared routines */

#include "../../../unit_tests/unittest.h"

#define _CSB (const sbyte*)
#define _CUB (const ubyte*)

static const char* gCurrCertFileName;
static const char* gCurrKeyFileName;

const char* kCMSSampleData =
"Gallia est omnis divisa in partes tres, quarum unam incolunt Belgae, "
"aliam Aquitani, tertiam qui ipsorum lingua Celtae, nostra Galli appellantur."
"Hi omnes lingua, institutis, legibus inter se differunt. Gallos ab Aquitanis "
"Garumna flumen, a Belgis Matrona et Sequana dividit. Horum omnium "
"fortissimi sunt Belgae, propterea quod a cultu atque humanitate provinciae "
"longissime absunt, minimeque ad eos mercatores saepe commeant atque ea quae "
"ad effeminandos animos pertinent important, proximique sunt Germanis, "
"qui trans Rhenum incolunt, quibuscum continenter bellum gerunt. Qua de causa "
"Helvetii quoque reliquos Gallos virtute praecedunt, quod fere cotidianis "
"proeliis cum Germanis contendunt, cum aut suis finibus eos prohibent aut "
"ipsi in eorum finibus bellum gerunt. Eorum una, pars, quam Gallos obtinere "
"dictum est, initium capit a flumine Rhodano, continetur Garumna flumine, "
"Oceano, finibus Belgarum, attingit etiam ab Sequanis et Helvetiis flumen "
"Rhenum, vergit ad septentriones. Belgae ab extremis Galliae finibus "
"oriuntur, pertinent ad inferiorem partem fluminis Rheni, spectant in "
"septentrionem et orientem solem. Aquitania a Garumna flumine ad Pyrenaeos "
"montes et eam partem Oceani quae est ad Hispaniam pertinet; spectat inter "
"occasum solis et septentriones."; /* saved in DeBelloGallico.txt */

/* getPrivateKey function -- just tries to match the content of the globals
 gCurrCertFileName and gCurrKeyFileName */

/*------------------------------------------------------------------------------------*/

static MSTATUS myGetPrivateKeyFun(const void* arg, CStream cs,
                                  const CMSRecipientId* pId,
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
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    ubyte4 keyFileNameLen;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    switch (pId->type)
    {
    case NO_TAG:
        if (NO_TAG == pId->ri.ktrid.type)
        {
            pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
            pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
        }
        else
        {
            status = ERR_FALSE;
            goto exit;
        }
        break;

    case 1:
        if (NO_TAG == pId->ri.karid.type)
        {
            pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
            pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
        }
        else
        {
            status = ERR_FALSE;
            goto exit;
        }
        break;

    default:
        status = ERR_FALSE;
        goto exit;
    }

    /* verify that the pSerialNumber and pIssuer match our own */
    if (OK > ( status = DIGICERT_readFile( gCurrCertFileName, &buff, &buffLen)))
        goto exit;

    MF_attach(&memFile, buffLen, buff);
    CS_AttachMemFile(&certCS, &memFile);

    if (OK > ( status = ASN1_Parse(certCS, &pCertRoot)))
        goto exit;

    if (OK > ( status = X509_checkCertificateIssuerSerialNumber( pIssuer, pSerialNumber,
                                cs, ASN1_FIRST_CHILD(pCertRoot), certCS)))
    {
        goto exit;
    }

    if (OK > (status = DIGICERT_readFile( gCurrKeyFileName, &pKeyBlob, &keyBlobLen)))
        goto exit;

    keyFileNameLen = DIGI_STRLEN( _CSB gCurrKeyFileName);
    if (keyFileNameLen > 4 &&
        0 == DIGI_STRNICMP( _CSB gCurrKeyFileName + keyFileNameLen - 4, _CSB ".der", 4))
    {
        /* read a PKCS#1 file */
        if (OK > ( status = PKCS_getPKCS1Key( MOC_HASH(hwAccelCtx) pKeyBlob, keyBlobLen, pKey)))
            goto exit;
    }
    else /* read a key blob */
    {
        /* load the key */
        if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLen, pKey)))
            goto exit;
    }

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


/* valCertFun: always says it's OK */
/*------------------------------------------------------------------------------------*/

static MSTATUS myValCertFun(const void* arg, CStream cs,
                            ASN1_ITEM* pCertificate)
{
    return OK;
}


static MSTATUS myGetCertFun(const void* arg,
                            CStream cs,
                            ASN1_ITEM* pSerialNumber,
                            ASN1_ITEM* pIssuerName,
                            ubyte** ppCertificate,
                            ubyte4* certLen)
{
    return DIGICERT_readFile((const char*) arg, ppCertificate, certLen);
}



#ifdef __ENABLE_DIGICERT_CMS__

/*---------------------------------------------------------------------------------*/

int CMSEnvTest( int hint, const char* pkcs7FileName,
                const char* certFileName,
                const char* keyBlobFileName,
                const char* dataFileName,
                int expectedNumRecipients,
                int expectedRecipient,
                const ubyte* expEncryptionAlgoOID,
                const ubyte* eContentType)
{
    int retVal = 0;
    CMS_context myCtx = 0;
    CMS_Callbacks myCb = {0};
    ubyte* pkcs7 = 0;
    ubyte* data = 0;
    ubyte4 pkcs7Len, outputLen, dataLen;
    ubyte* output = 0;
    intBoolean done;
    MSTATUS status;
    ubyte* outBuffer = 0;
    sbyte4 i, v;
    sbyte4 resCmp;
    CStream cs;
    ASN1_ITEMPTR pRecipientInfo;
    ubyte* encryptionAlgoOID = 0;
    const char* encryptionAlgoName;
    ubyte* ecType = 0;

    myCb.getCertFun = 0;
    myCb.valCertFun = 0; /* not needed for decrypt envelopped */
    myCb.getPrivKeyFun = myGetPrivateKeyFun;

    /* set up the globals used by myGetPrivateKeyFun */
    gCurrCertFileName = certFileName;
    gCurrKeyFileName = keyBlobFileName;
    /* read the file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( pkcs7FileName, &pkcs7, &pkcs7Len),
                         retVal, exit);

    if (dataFileName)
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( dataFileName, &data, &dataLen),
                            retVal, exit);
    }

    /* allocate a buffer to collect the result */
    outBuffer = MALLOC( pkcs7Len);
    retVal += UNITTEST_VALIDPTR( hint, outBuffer);
    if (retVal) goto exit;

    /* get a CMS context */
    UNITTEST_STATUS_GOTO( hint, CMS_newContext( &myCtx, 0, &myCb),
                          retVal, exit);
    retVal += UNITTEST_VALIDPTR( hint, myCtx);

    /* note that we can send more data (and garbage too) without the
       code being affected: it will detect the logical end of the data */
    status = CMS_updateContext( myCtx, pkcs7, pkcs7Len,
                                &output, &outputLen, &done);

    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    retVal += UNITTEST_VALIDPTR(hint, output);

    retVal += UNITTEST_TRUE(hint, done);

    retVal += UNITTEST_STATUS( hint, CMS_getEncapContentType(myCtx, &ecType));

    retVal += UNITTEST_TRUE(hint, EqualOID( ecType, eContentType));

    retVal += UNITTEST_STATUS( hint, CMS_getNumRecipients(myCtx, &v));

    retVal += UNITTEST_INT( hint, v, expectedNumRecipients);

    for (i = 0; i < v; ++i)
    {
        retVal += UNITTEST_STATUS( hint, CMS_getRecipientInfo( myCtx, i,
                                                               &pRecipientInfo,
                                                               &cs));

        retVal += UNITTEST_VALIDPTR( hint, pRecipientInfo);
    }

    status = CMS_getRecipientInfo( myCtx, v, &pRecipientInfo, &cs);
    retVal += UNITTEST_TRUE( hint, (ERR_INDEX_OOB == status));

    status = CMS_getRecipientInfo( myCtx, -1, &pRecipientInfo, &cs);
    retVal += UNITTEST_TRUE( hint, (ERR_INDEX_OOB == status));

    retVal += UNITTEST_STATUS( hint, CMS_getDecryptingRecipient(myCtx, &v));

    retVal += UNITTEST_INT( hint, v, expectedRecipient);

    retVal += UNITTEST_STATUS( hint, CMS_getEncryptionAlgo( myCtx, &encryptionAlgoOID));

    retVal += UNITTEST_TRUE(hint, EqualOID( encryptionAlgoOID, expEncryptionAlgoOID));

    retVal += UNITTEST_STATUS(hint, CMS_AUX_getAlgoName( encryptionAlgoOID,
                                                         &encryptionAlgoName));

    retVal += UNITTEST_STATUS(hint, CMS_deleteContext(&myCtx));

    if (data)
    {
        retVal += UNITTEST_INT(hint, outputLen, dataLen);
        DIGI_MEMCMP( output, data, dataLen, &resCmp);
        retVal += UNITTEST_TRUE(hint, resCmp == 0);
    }
    else
    {
        DIGICERT_writeFile("CMSEnvTest.out", output, outputLen);
    }


exit:

    if (encryptionAlgoOID)
    {
        FREE(encryptionAlgoOID);
    }

    if (ecType)
    {
        free(ecType);
    }

    if (output)
    {
        FREE(output);
    }

    CMS_deleteContext(&myCtx);

    if (outBuffer)
    {
        FREE(outBuffer);
    }

    if (data)
    {
        FREE(data);
    }
    if (pkcs7)
    {
        FREE(pkcs7);
    }

    return retVal;
}

/*---------------------------------------------------------------------------------*/

int CMSEnvStreamTest( int hint, const char* pkcs7FileName,
                     const char* certFileName,
                     const char* keyBlobFileName,
                     const char* dataFileName,
                     int expectedNumRecipients,
                     int expectedRecipient,
                     const ubyte* expEncryptionAlgoOID,
                     const ubyte* eContentType)
{
    int retVal = 0;
    CMS_context myCtx = 0;
    CMS_Callbacks myCb = {0};
    ubyte* pkcs7 = 0;
    ubyte* data = 0;
    ubyte4 pkcs7Len, dataLen, outputLen;
    ubyte* output = 0;
    int inputSize, offset;
    intBoolean done;
    MSTATUS status = OK;
    ubyte* outBuffer = 0;
    int outOffset;
    sbyte4 i,v;
    sbyte4 resCmp;
    CStream cs;
    ASN1_ITEMPTR pRecipientInfo;
    ubyte* encryptionAlgoOID = 0;
    const char* encryptionAlgoName;
    ubyte* ecType = 0;
    ubyte4 bytesLeft = 0;

    hint <<= 24;

    myCb.getCertFun = 0;
    myCb.valCertFun = 0; /* not needed for decrypt envelopped */
    myCb.getPrivKeyFun = myGetPrivateKeyFun;

    /* set up the globals used by myGetPrivateKeyFun */
    gCurrCertFileName = certFileName;
    gCurrKeyFileName = keyBlobFileName;
    /* read the file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( pkcs7FileName, &pkcs7, &pkcs7Len),
                            retVal, exit);

    if (dataFileName)
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( dataFileName, &data, &dataLen),
                            retVal, exit);
    }

    /* allocate a buffer to collect the result */
    outBuffer = MALLOC( pkcs7Len);
    retVal += UNITTEST_VALIDPTR( hint, outBuffer);
    if (retVal) goto exit;

    /* first test is to send everything in 1 to 19 bytes part */
    for (inputSize = 1; inputSize < 20; ++inputSize)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_newContext( &myCtx, 0, &myCb),
                            retVal, exit);
        retVal += UNITTEST_VALIDPTR( hint, myCtx);

        /* send the pkcs7 */
        offset = 0;
        outOffset = 0;
        bytesLeft = pkcs7Len;

        do
        {
            /* note that we can send more data (and garbage too) without the
            code being affected: it will detect the logical end of the data */
            status = CMS_updateContext( myCtx, pkcs7 + offset, bytesLeft > inputSize ? inputSize : bytesLeft,
                                            &output, &outputLen, &done);
            if (output)
            {
                if (UNITTEST_TRUE(hint, outOffset + outputLen <= pkcs7Len))
                {
                    ++retVal; goto exit;
                }

                DIGI_MEMCPY( outBuffer + outOffset, output, outputLen);
                outOffset += outputLen;

                FREE(output);
                output = 0;

                retVal += UNITTEST_STATUS( hint, CMS_getEncapContentType(myCtx, &ecType));

                retVal += UNITTEST_TRUE(hint, EqualOID( ecType, eContentType));
                FREE(ecType); ecType = 0;
            }
            offset += inputSize;
            bytesLeft -= inputSize;

        } while (!done && OK <= status);


        retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                                    status);

        retVal += UNITTEST_STATUS( (hint | (inputSize << 16)),
                                    CMS_getNumRecipients(myCtx, &v));

        retVal += UNITTEST_INT( (hint | (inputSize << 16)),
                                v, expectedNumRecipients);

        for (i = 0; i < v; ++i)
        {
            retVal += UNITTEST_STATUS( (hint | (inputSize << 16)),
                                    CMS_getRecipientInfo( myCtx, i,
                                                    &pRecipientInfo,
                                                    &cs));

            retVal += UNITTEST_VALIDPTR( (hint | (inputSize << 16)),
                                        pRecipientInfo);
        }

        status = CMS_getRecipientInfo( myCtx, v, &pRecipientInfo, &cs);
        retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), (ERR_INDEX_OOB == status));

        status = CMS_getRecipientInfo( myCtx, -1, &pRecipientInfo, &cs);
        retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), (ERR_INDEX_OOB == status));

        retVal += UNITTEST_STATUS( (hint | (inputSize << 16)),
                                    CMS_getDecryptingRecipient(myCtx, &v));

        retVal += UNITTEST_INT( (hint | (inputSize << 16)),
                                v, expectedRecipient);

        retVal += UNITTEST_STATUS( (hint | (inputSize << 16)),
                                    CMS_getEncryptionAlgo( myCtx, &encryptionAlgoOID));

        retVal += UNITTEST_TRUE((hint | (inputSize << 16)),
                        EqualOID( encryptionAlgoOID, expEncryptionAlgoOID));

        retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                        CMS_AUX_getAlgoName( encryptionAlgoOID,
                                            &encryptionAlgoName));

        FREE( encryptionAlgoOID); encryptionAlgoOID = 0;

        retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                                    CMS_deleteContext(&myCtx));


        if (data)
        {
            retVal += UNITTEST_INT((hint | (inputSize << 16)), outOffset, dataLen);
            DIGI_MEMCMP( outBuffer, data, dataLen, &resCmp);
            retVal += UNITTEST_TRUE((hint | (inputSize << 16)), resCmp == 0);
        }
        else
        {
            DIGICERT_writeFile("CMSEnvStreamTest.out", outBuffer, outOffset);
        }
    }

exit:

    if (ecType)
    {
        free(ecType);
    }

    if (output)
    {
        FREE(output);
    }

    CMS_deleteContext(&myCtx);

    if (outBuffer)
    {
        FREE(outBuffer);
    }

    if (data)
    {
        FREE(data);
    }
    if (pkcs7)
    {
        FREE(pkcs7);
    }

    return retVal;
}

#endif

/*---------------------------------------------------------------------------------*/

int cms_test_enveloped()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_CMS__
    retVal += CMSEnvTest(1, FILE_PATH("pb_cms_enveloped_rsa.der"),
                         FILE_PATH("selfcert.der"),
                         FILE_PATH("keyblobFile.dat"),
                         FILE_PATH("DeBelloGallico.txt"),
                         1, 0, aes128CBC_OID, pkcs7_data_OID);

    retVal += CMSEnvTest(2, FILE_PATH("envelopedData.der"),
                         FILE_PATH("selfcert.der"),
                         FILE_PATH("keyblobFile.dat"),
                         FILE_PATH("degenerateSignedData.der"),
                         1, 0, desCBC_OID, pkcs7_data_OID);

    retVal += CMSEnvTest(3, FILE_PATH("ecc_enveloped.der"),
                         FILE_PATH("ecc_selfcert.der"),
                         FILE_PATH("ecc_keyblobFile.dat"),
                         FILE_PATH("ecc_enveloped_payload.dat"),
                         1, 0, aes128CBC_OID, pkcs7_data_OID);

    retVal += CMSEnvTest(4, FILE_PATH("outlook_2010.der"),
                         FILE_PATH("outlook_2010_cert.der"),
                         FILE_PATH("outlook_2010_key.der"),
                         FILE_PATH("outlook_2010_payload.dat"),
                         1, 0, desEDE3CBC_OID, pkcs7_data_OID);


    retVal += CMSEnvStreamTest(1, FILE_PATH("pb_cms_enveloped_rsa.der"),
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    FILE_PATH("DeBelloGallico.txt"),
                                    1, 0, aes128CBC_OID, pkcs7_data_OID);

    retVal += CMSEnvStreamTest(2, FILE_PATH("envelopedData.der"),
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    FILE_PATH("degenerateSignedData.der"),
                                    1, 0, desCBC_OID, pkcs7_data_OID);

    retVal += CMSEnvStreamTest(3, FILE_PATH("ecc_enveloped.der"),
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    FILE_PATH("ecc_enveloped_payload.dat"),
                                    1, 0, aes128CBC_OID, pkcs7_data_OID);
    retVal += CMSEnvStreamTest(4, FILE_PATH("outlook_2010.der"),
                                    FILE_PATH("outlook_2010_cert.der"),
                                    FILE_PATH("outlook_2010_key.der"),
                                    FILE_PATH("outlook_2010_payload.dat"),
                                    1, 0, desEDE3CBC_OID, pkcs7_data_OID);

#endif

    return retVal;
}


#ifdef __ENABLE_DIGICERT_CMS__


/*---------------------------------------------------------------------------------*/

static int
CMSTestVerifyNames( int hint, sbyte4 numNames, const ubyte* names[],
                   const ubyte* nullSeparatedNames)
{
    int retVal = 0;
    const ubyte* currName;
    sbyte4 i;
    int found;

    currName = nullSeparatedNames;

    while (*currName)
    {
        found = 0;
        for (i = 0; i < numNames; ++i)
        {
            if ( 0 == DIGI_STRCMP( _CSB currName, _CSB names[i]))
            {
                found = 1;
                break;
            }
        }
        retVal += UNITTEST_TRUE( hint, found);
        if (!found) { unittest_write( (const char*) currName); unittest_write( "\n"); }

        while (*currName) { ++currName; }
        ++currName;
    }

    return retVal;
}

/*---------------------------------------------------------------------------------*/

static int
CMSRequestInfoTest( int hint, const CMS_TEST_RR_Info* pRRInfo,
                   ASN1_ITEMPTR pReceiptRequest, CStream cs)
{
    int retVal = 0;
    ubyte** res = 0;
    sbyte4 num;

    /* from */
    UNITTEST_STATUS_GOTO( hint,
            CMS_AUX_getReceiptRequestFrom( pReceiptRequest, cs, &res, &num),
            retVal, exit);

    retVal += UNITTEST_INT( hint, num, pRRInfo->numFrom);
    if (retVal) goto exit;

    if (num > 0)
    {
        retVal += UNITTEST_TRUE( hint, 0 != res);
        /* verify value in the buffer */
        if (res)
        {
            retVal += CMSTestVerifyNames( hint, num, res, pRRInfo->from);
        }
        FREE(res); res = 0;
    }
    else
    {   /* verify no buffer was allocated */
        retVal += UNITTEST_TRUE( hint, 0 == res);
    }


    /* to */
    UNITTEST_STATUS_GOTO( hint,
            CMS_AUX_getReceiptRequestTo( pReceiptRequest, cs, &res, &num),
            retVal, exit);

    retVal += UNITTEST_INT( hint, num, pRRInfo->numTo);
    if (retVal) goto exit;

    /* verify value in the buffer */
    retVal += UNITTEST_TRUE( hint, 0 != res);
    /* verify value in the buffer */
    if (res)
    {
        retVal += CMSTestVerifyNames( hint, num, res, pRRInfo->to);
    }

exit:

    if ( res)
    {
        FREE(res);
    }

    return retVal;
}


/*---------------------------------------------------------------------------------*/

int CMSSignedGenerateReceiptFileName( int hint, const char* receiptRequestFileName,
                                     char** pReceiptFileName)
{
    int retVal = 0;
    ubyte4 fileNameLen;
    char* receiptFileName = 0;

    fileNameLen = DIGI_STRLEN(_CSB receiptRequestFileName);
    receiptFileName = MALLOC(fileNameLen + 9);
    retVal += UNITTEST_VALIDPTR( hint, receiptFileName);
    if (retVal) goto exit;

    DIGI_MEMCPY( receiptFileName, receiptRequestFileName, fileNameLen - 4);
    DIGI_MEMCPY( receiptFileName + fileNameLen - 4, "_receipt.der", 13);

    *pReceiptFileName = receiptFileName;

exit:

    return retVal;
}


/*---------------------------------------------------------------------------*/

int CMSSignedTestReceipt( int hint, CMS_signedDataContext myCtx,
                          const char* receiptFileName,
                          const CMS_TEST_RC_Info* pRCInfo)
{
    int retVal = 0;
    CMS_context receiptCtx = 0;
    ubyte* receipt = 0;
    ubyte4 receiptLen;
    ubyte* receiptContent = 0;
    ubyte4 receiptContentLen;
    CMS_Callbacks myCb = {0};
    intBoolean finished;
    sbyte4 numSigners;
    const ubyte* messageId;
    ubyte4 messageIdLen;
    const ubyte* signature;
    ubyte4 signatureLen;
    const ubyte* digest;
    ubyte4 digestLen;
    sbyte4 resCmp;
    ASN1_ITEMPTR pSignerInfo;
    CStream cs;
    ubyte* attrContent = 0;
    ubyte4 attrContentLen;
    ubyte* ecType = 0;

    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile( receiptFileName, &receipt, &receiptLen),
                            retVal, exit);

    myCb.getCertFun = NULL; /* not needed since cert is in the receipt */
    myCb.valCertFun = myValCertFun; /* not needed for decrypt envelopped */
    myCb.getPrivKeyFun = NULL; /* not needed for signed */

    UNITTEST_STATUS_GOTO( hint, CMS_newContext( &receiptCtx, 0, &myCb),
                            retVal, exit);
    UNITTEST_STATUS_GOTO( hint, CMS_updateContext( receiptCtx, receipt, receiptLen,
                                                    &receiptContent, &receiptContentLen,
                                                    &finished),
                            retVal, exit);

    retVal += UNITTEST_TRUE( hint, finished);
    if ( retVal) goto exit;

    UNITTEST_STATUS_GOTO( hint, CMS_getEncapContentType( receiptCtx, &ecType),
                            retVal, exit);

    retVal += UNITTEST_TRUE( hint, EqualOID( ecType, smime_receipt_OID));

    UNITTEST_STATUS_GOTO( hint, CMS_getNumSigners( receiptCtx, &numSigners),
                        retVal, exit);

    retVal += UNITTEST_TRUE( hint, 1 == numSigners);
    if ( retVal) goto exit;

    /* compare receipt info with request info  */
    UNITTEST_STATUS_GOTO( hint,
                        CMS_getReceiptInfo( receiptContent, receiptContentLen,
                                            &messageId, &messageIdLen,
                                            &signature, &signatureLen),
                            retVal, exit);

    retVal += UNITTEST_INT( hint, messageIdLen, pRCInfo->messageIdLen);
    DIGI_MEMCMP( messageId, pRCInfo->messageId, messageIdLen, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);

    retVal += UNITTEST_INT( hint, signatureLen, pRCInfo->signatureLen);
    DIGI_MEMCMP( signature, pRCInfo->signature, signatureLen, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);

    UNITTEST_STATUS_GOTO(hint, CMS_getReceiptMsgDigest( receiptCtx,
                         &digest, &digestLen),
                         retVal, exit);

    retVal += UNITTEST_INT( hint, digestLen, pRCInfo->digestLen);
    DIGI_MEMCMP( digest, pRCInfo->digest, digestLen, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);

    UNITTEST_STATUS_GOTO( hint, CMS_getSignerInfo( receiptCtx, 0,
                                            &pSignerInfo, &cs),
                           retVal, exit);

    /* look at the message digest --
        this is basically what CMS_getReceiptMsgDigest does */
    UNITTEST_STATUS_GOTO( hint, CMS_AUX_getAttributeValue( pSignerInfo, cs,
                                              smime_msgSigDigest_OID, 1,
                                              &attrContent, &attrContentLen),
                           retVal, exit);

    retVal += UNITTEST_INT( hint, attrContentLen, pRCInfo->digestLen);
    DIGI_MEMCMP( attrContent, pRCInfo->digest, attrContentLen, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);

    /* this needs to be freed */
    FREE(attrContent); attrContent = 0;

    /* look at the content type -- verify it's smime_receipt_OID */
    UNITTEST_STATUS_GOTO( hint, CMS_AUX_getAttributeValue( pSignerInfo, cs,
                                              pkcs9_contentType_OID, 1,
                                              &attrContent, &attrContentLen),
                           retVal, exit);
    retVal += UNITTEST_INT( hint, attrContentLen, smime_receipt_OID[0]);
    DIGI_MEMCMP( attrContent, smime_receipt_OID + 1, attrContentLen, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);


    FREE(attrContent); attrContent = 0;

exit:

    FREE(ecType);
    FREE(attrContent);
    FREE( receiptContent);
    FREE( receipt);
    CMS_deleteContext( &receiptCtx);

    return retVal;
}


/*---------------------------------------------------------------------------------*/

static int
CMSCreateRequestTest( int hint, const char* fileName,
                     CMS_context myCtx, sbyte4 signerIndex,
                     const CMS_TEST_RC_Info* pRCInfo)
{
    int retVal = 0;
    ubyte* receipt = 0;
    ubyte4 receiptLen;
    char* receiptFileName = 0;
    const ubyte* hashAlgoOID = 0;

    switch( pRCInfo->key.type)
    {
    case akt_dsa:
        hashAlgoOID = sha256_OID;
        break;

    case akt_rsa:
        hashAlgoOID = md5_OID;
        break;

    case akt_ecc:
        hashAlgoOID = sha384_OID;
        break;
    }

    UNITTEST_STATUS_GOTO( hint,
                         CMS_createSignedReceipt( myCtx, signerIndex,
                                        pRCInfo->rngFun, pRCInfo->rngFunArg,
                                        pRCInfo->signerCert, pRCInfo->signerCertLen,
                                        &pRCInfo->key,
                                        hashAlgoOID,
                                        &receipt, &receiptLen),
                        retVal, exit);

    retVal += CMSSignedGenerateReceiptFileName( hint, fileName,
                                                &receiptFileName);
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( hint,
                        DIGICERT_writeFile( receiptFileName, receipt, receiptLen));

    if (pRCInfo->messageIdLen)
    {
        retVal += CMSSignedTestReceipt( hint, myCtx, receiptFileName, pRCInfo);
        if ( retVal) goto exit;
    }

exit:

    FREE( receiptFileName);

    if (receipt)
    {
        FREE( receipt);
    }
    return retVal;
}


/*---------------------------------------------------------------------------------*/

int CMSSignedStreamTest( int hint, const char* pkcs7FileName,
                        const char* certFileName,
                        const char* dataFileName, sbyte4 expectedNumSigners,
                        sbyte4 expectedNumCerts, sbyte4 lengthCerts[/* expectedNumCerts*/],
                        ubyte hashType, ubyte pubKeyType, ubyte expectedDetached,
                        const CMS_TEST_RR_Info* receiptRequestInfo,
                        const CMS_TEST_RC_Info* receiptCreateInfo,
                        const ubyte* eContentTypeOID)
{
    int retVal = 0;
    CMS_context myCtx = 0;
    CMS_Callbacks myCb = {0};
    ubyte* pkcs7 = 0;
    ubyte* data = 0;
    ubyte4 pkcs7Len, dataLen, outputLen;
    ubyte* output = 0;
    int inputSize, offset, receiptCreated = FALSE;
    intBoolean done = FALSE;
    MSTATUS status = OK;
    ubyte* outBuffer = 0;
    int outOffset;
    sbyte4 i, numSigners, numCerts;
    sbyte4 resCmp;
    CStream cs;
    ASN1_ITEMPTR pSignerInfo, pCertificate;
    ubyte * ecType = 0;
    ubyte4 bytesLeft = 0;

    hint <<= 24;

    myCb.getCertFun = myGetCertFun;
    myCb.valCertFun = myValCertFun; /* not needed for decrypt envelopped */
    myCb.getPrivKeyFun = NULL; /* not needed for signed */

    /* read the file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( pkcs7FileName, &pkcs7, &pkcs7Len),
                            retVal, exit);

    if ( dataFileName)
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( dataFileName, &data, &dataLen),
                            retVal, exit);
        /* allocate a buffer to collect the result */
        outBuffer = MALLOC( dataLen);
        retVal += UNITTEST_VALIDPTR( hint, outBuffer);
        if (retVal) goto exit;
    }
    else
    {
        dataLen = 0;
    }

    /* first test is to send everything in 1 to 19 bytes part */
    for (inputSize = 1; inputSize < 20; ++inputSize)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_newContext( &myCtx, certFileName, &myCb),
                            retVal, exit);
        retVal += UNITTEST_VALIDPTR( hint, myCtx);

        /* send the pkcs7 */
        offset = 0;
        outOffset = 0;
        bytesLeft = pkcs7Len;

        do
        {
            /* note that we can send more data (and garbage too) without the
            code being affected: it will detect the logical end of the data */
            status = CMS_updateContext( myCtx, pkcs7 + offset, bytesLeft > inputSize ? inputSize : bytesLeft,
                                            &output, &outputLen, &done);
            if (output)
            {
                if (UNITTEST_TRUE(hint, outOffset + outputLen <= dataLen))
                {
                    ++retVal; goto exit;
                }

                DIGI_MEMCPY( outBuffer + outOffset, output, outputLen);
                outOffset += outputLen;

                FREE(output);
                output = 0;

                retVal += UNITTEST_STATUS( hint, CMS_getEncapContentType(myCtx, &ecType));

                retVal += UNITTEST_TRUE(hint, EqualOID( ecType, eContentTypeOID));
                FREE(ecType); ecType = 0;
            }
            offset += (bytesLeft > inputSize ? inputSize : bytesLeft);
            bytesLeft -= (bytesLeft > inputSize ? inputSize : bytesLeft);

        } while (!done && OK <= status);


        retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                                    status);

        /* if detached signature, we got nothing back */
        if ( 0 == outOffset)
        {
            intBoolean detached;

            retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                                    CMS_detachedSignature(myCtx, &detached));

            retVal += UNITTEST_TRUE( (hint | (inputSize << 16) | offset), detached);
            retVal += UNITTEST_TRUE( (hint | (inputSize << 16) | offset), detached == expectedDetached);

            /* set the data then if we have it */
            if ( data && dataLen)
            {
                retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                            CMS_setDetachedSignatureData( myCtx, data, dataLen, TRUE));
            }
            else
            {
                retVal += UNITTEST_TRUE( (hint | (inputSize << 16) | offset),
                                    ERR_PKCS7_DETACHED_DATA == CMS_getNumSigners(myCtx, &numSigners));
            }
        }

        if ( expectedNumSigners >= 0)
        {
            retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                                    CMS_getNumSigners(myCtx, &numSigners));

            retVal += UNITTEST_INT((hint | (inputSize << 16)), numSigners, expectedNumSigners);
        }
        else
        {
            numSigners = 0;
        }

        for ( i = 0; i < numSigners; ++i)
        {
            ubyte signerHashType, signerPubKeyType;

            retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                          CMS_getSignerInfo( myCtx, i, &pSignerInfo, &cs));

            retVal += UNITTEST_VALIDPTR((hint | (inputSize << 16)),
                                            pSignerInfo);

            retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                          ASN1_VerifyType(pSignerInfo, SEQUENCE ));

            if ( 0 == i)
            {
                MSTATUS status = OK;
                ASN1_ITEMPTR pReceiptRequest;

                retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                              PKCS7_GetSignerDigestAlgo( pSignerInfo, cs, &signerHashType));

                retVal += UNITTEST_INT((hint | (inputSize << 16)), signerHashType, hashType);

                retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                              PKCS7_GetSignerSignatureAlgo( pSignerInfo, cs, &signerPubKeyType));

                retVal += UNITTEST_INT((hint | (inputSize << 16)), signerPubKeyType, pubKeyType);

                status = CMS_AUX_getReceiptRequest( pSignerInfo, cs, &pReceiptRequest);

                if (receiptRequestInfo)
                {
                    retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), status >= OK );
                    retVal += CMSRequestInfoTest( (hint | (inputSize << 16)),
                                                receiptRequestInfo, pReceiptRequest, cs);

                    /* generate a receipt */
                    if ( receiptCreateInfo && ! receiptCreated)
                    {
                        receiptCreated = TRUE;
                        retVal += CMSCreateRequestTest( (hint | (inputSize << 16)),
                                                    pkcs7FileName, myCtx, i,
                                                    receiptCreateInfo);
                    }

                }
                else
                {
                    retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), status < OK );
                }
            }


            status = CMS_getSignerInfo( myCtx, numSigners, &pSignerInfo, &cs);
            retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), (ERR_INDEX_OOB == status));

            status = CMS_getSignerInfo( myCtx, -1, &pSignerInfo, &cs);
            retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), (ERR_INDEX_OOB == status));
        }

        retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                                      CMS_getFirstCertificate(myCtx, &pCertificate, &cs));

        numCerts = 0;
        while (pCertificate)
        {
            retVal += UNITTEST_TRUE( (hint | (inputSize << 16)),
                               pCertificate->length + pCertificate->headerSize ==
                               lengthCerts[numCerts++]);

            pCertificate = ASN1_NEXT_SIBLING(pCertificate);
        }

        retVal += UNITTEST_TRUE( (hint | (inputSize << 16)), numCerts == expectedNumCerts);

        retVal += UNITTEST_STATUS((hint | (inputSize << 16)),
                                    CMS_deleteContext(&myCtx));

        /* non detached signature -> verify the output */
        if (outOffset)
        {
            retVal += UNITTEST_INT((hint | (inputSize << 16)), outOffset, dataLen);

            DIGI_MEMCMP( outBuffer, data, dataLen, &resCmp);

            retVal += UNITTEST_TRUE((hint | (inputSize << 16)), resCmp == 0);
        }
    }

exit:

    if (ecType)
    {
        FREE(ecType);
    }

    if (output)
    {
        FREE(output);
    }

    CMS_deleteContext(&myCtx);

    if (outBuffer)
    {
        FREE(outBuffer);
    }

    if (data)
    {
        FREE(data);
    }

    if (pkcs7)
    {
        FREE(pkcs7);
    }

    return retVal;
}
#endif


/*---------------------------------------------------------------------------------*/

int cms_test_signed_normal()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_CMS__
    sbyte4 lengthCerts[20];
    CMS_TEST_RR_Info rrInfo;
    CMS_TEST_RC_Info rcInfo = { 0 };
    ubyte* keyBlob = 0;
    ubyte4 keyBlobLen;

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

    rcInfo.rngFun = RANDOM_rngFun;
    rcInfo.rngFunArg = g_pRandomContext;

    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile(FILE_PATH("selfcert.der"),
                                        &rcInfo.signerCert,
                                        &rcInfo.signerCertLen),
                        retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile( FILE_PATH("keyblobFile.dat"),
                                        &keyBlob, &keyBlobLen),
                        retVal, exit);


    UNITTEST_STATUS_GOTO(0,
                        CA_MGMT_extractKeyBlobEx(keyBlob, keyBlobLen,
                                                    &rcInfo.key),
                        retVal, exit);

    lengthCerts[0] = 766;
    retVal += CMSSignedStreamTest(1, FILE_PATH("signedRSA.der"),
                                    NULL, FILE_PATH("signedData.dat"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 0, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 787;
    retVal += CMSSignedStreamTest(2, FILE_PATH("signedECC.der"),
                                    NULL, FILE_PATH("signedData.dat"), 1, 1, lengthCerts,
                                    ht_sha1, akt_ecc, 0, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 0;
    retVal += CMSSignedStreamTest(3, FILE_PATH("signedData.der"),
                                    FILE_PATH("signerCert.der"),
                                    FILE_PATH("octetstring_ber.dat"), 1, 0, 0,
                                    ht_md5, akt_rsa, 0, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 761;
    retVal += CMSSignedStreamTest(4, FILE_PATH("detachedSignature.der"),
                                    FILE_PATH("cert.der"),
                                    FILE_PATH("hello_world.dat"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 1221;
    lengthCerts[1] = 1466;
    lengthCerts[2] = 1536;
    retVal += CMSSignedStreamTest(5, FILE_PATH("good_signedData.der"),
                                    NULL, NULL, -1, 3, lengthCerts,
                                    ht_sha1, akt_rsa, 1, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 1512;
    retVal += CMSSignedStreamTest(6, FILE_PATH("good_signed_data_certicom.der"),
                                    NULL,
                                    FILE_PATH("good_signed_data_certicom_content.dat"), -1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, 0, 0, pkcs7_data_OID);

    lengthCerts[0] = 1184;
    lengthCerts[1] = 1676;
    retVal += CMSSignedStreamTest(7, FILE_PATH("good_signed_data_dsa_certicom.der"),
                                    NULL, FILE_PATH("good_signed_data_dsa_certicom_content.dat"),
                                    -1, 2, lengthCerts,
                                    ht_sha1, akt_dsa, 1, 0, 0, pkcs7_data_OID);

    rrInfo.numFrom = -1;
    rrInfo.from = 0;
    rrInfo.numTo = 1;
    rrInfo.to = (const ubyte*) "fferino@mocana.com\0";
    lengthCerts[0] = 1061;
    retVal += CMSSignedStreamTest(10, FILE_PATH("receipt_request_signed_all.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

    rrInfo.numFrom = -1;
    rrInfo.from = 0;
    rrInfo.numTo = 1;
    rrInfo.to = (const ubyte*) "fferino@mocana.com\0";
    lengthCerts[0] = 1250;
    retVal += CMSSignedStreamTest(11, FILE_PATH("receipt_request_signed_all_dsa.der"),
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_dsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

    rrInfo.numFrom = 0;
    rrInfo.from = 0;
    rrInfo.numTo = 1;
    rrInfo.to = _CUB "fferino@mocana.com\0";
    lengthCerts[0] = 1061;
    retVal += CMSSignedStreamTest(12, FILE_PATH("receipt_request_signed_first.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

    rrInfo.numFrom = 1;
    rrInfo.from = _CUB "fabrice@mocana.com\0";
    rrInfo.numTo = 1;
    rrInfo.to = _CUB "fferino@mocana.com\0";
    lengthCerts[0] = 1061;
    retVal += CMSSignedStreamTest(13, FILE_PATH("receipt_request_signed_fabrice.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);


    rrInfo.numFrom = 1;
    rrInfo.from = _CUB "fabrice@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = _CUB "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    lengthCerts[0] = 1061;
    retVal += CMSSignedStreamTest(14, FILE_PATH("receipt_request_signed_multiple_to.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

    rrInfo.numFrom = 2;
    rrInfo.from = _CUB "fabrice@mocana.com\0sales@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = _CUB "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    lengthCerts[0] = 1061;
    retVal += CMSSignedStreamTest(15, FILE_PATH("receipt_request_signed_multiple_from_to.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);


    rrInfo.numFrom = 2;
    rrInfo.from = _CUB "fabrice@mocana.com\0sales@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = _CUB "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    lengthCerts[0] = 1061;
    lengthCerts[1] = 1061;
    retVal += CMSSignedStreamTest(16, FILE_PATH("receipt_request_signed_multiple_signer_from_to.der"),
                                    FILE_PATH("openssl_cert2.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 2, 2, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

    rrInfo.numFrom = 2;
    rrInfo.from = _CUB "fabrice@mocana.com\0sales@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = _CUB "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    lengthCerts[0] = 1061;
    lengthCerts[1] = 1061;
    retVal += CMSSignedStreamTest(17, FILE_PATH("receipt_request_signed_multiple_signer_from_to.der"),
                                    FILE_PATH("openssl_cert1.der"),
                                    FILE_PATH("DeBelloGallico.txt"), 2, 2, lengthCerts,
                                    ht_sha1, akt_rsa, 1, &rrInfo, &rcInfo, pkcs7_data_OID);

exit:

    FREE(keyBlob);
    FREE( rcInfo.signerCert);
    CRYPTO_uninitAsymmetricKey( &rcInfo.key, NULL);

    DIGICERT_freeDigicert();

#endif

    return retVal;
}

#ifdef __ENABLE_DIGICERT_CMS__

/*---------------------------------------------------------------------------------*/

int CMSSignedOtherTests(int hint, const char* pkcs7FileName,
                        const char* certFileName,
                        const char* dataFileName,
                        MSTATUS expStatus)
{
    int retVal = 0;
    CMS_context myCtx = 0;
    CMS_Callbacks myCb = {0};
    ubyte* pkcs7 = 0;
    ubyte* data = 0;
    ubyte4 pkcs7Len, dataLen, outputLen;
    ubyte* output = 0;
    intBoolean done;
    MSTATUS status = OK;

    myCb.getCertFun = myGetCertFun;
    myCb.valCertFun = myValCertFun; /* not needed for decrypt envelopped */
    myCb.getPrivKeyFun = NULL; /* not needed for signed */

    /* read the file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( pkcs7FileName, &pkcs7, &pkcs7Len),
                            retVal, exit);

    if ( dataFileName)
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( dataFileName, &data, &dataLen),
            retVal, exit);
    }
    else
    {
        dataLen = 0;
    }

    UNITTEST_STATUS_GOTO( hint, CMS_newContext( &myCtx, certFileName, &myCb),
                            retVal, exit);

    retVal += UNITTEST_VALIDPTR( hint, myCtx);

    status = CMS_updateContext( myCtx, pkcs7, pkcs7Len,
                               &output, &outputLen, &done);

    retVal += UNITTEST_INT( hint, status, expStatus);

    if (OK <= status)
    {
        sbyte4 resCmp;

        retVal += UNITTEST_INT(hint, outputLen, dataLen);

        DIGI_MEMCMP(output, data, outputLen, &resCmp);
        retVal += UNITTEST_INT(hint, resCmp, 0);
    }

exit:

    if (output)
    {
        FREE(output);
    }

    CMS_deleteContext(&myCtx);

    if (data)
    {
        FREE(data);
    }

    if (pkcs7)
    {
        FREE(pkcs7);
    }

    return retVal;
}


#endif

/*---------------------------------------------------------------------------------*/

int cms_test_signed_others()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_CMS__
    /* content type in auth attributes does not match content type */
    retVal += CMSSignedOtherTests(1, FILE_PATH("mismatch_attr_receipt.der"),
                                    FILE_PATH("selfcert.der"),
                                    NULL, ERR_PKCS7_INVALID_SIGNATURE);
    /* error in data */
    retVal += CMSSignedOtherTests(2, FILE_PATH("err_cms_signed_rsa.der"),
                                    FILE_PATH("selfcert.der"),
                                    NULL, ERR_PKCS7_INVALID_SIGNATURE);
    /* error in data */
    retVal += CMSSignedOtherTests(3, FILE_PATH("err_cms_signed_ecc.der"),
                                    FILE_PATH("ecc_selfcert.der"),
                                    NULL, ERR_PKCS7_INVALID_SIGNATURE);

#endif

    return retVal;
}


#ifdef __ENABLE_DIGICERT_CMS__
/*---------------------------------------------------------------------------------*/

int CMSDigestedStreamTest(int hint, const char* pkcs7FileName, const ubyte* data,
                            ubyte4 dataLen, const ubyte* eContentTypeOID)
{
    int retVal = 0;
    CMS_context myCtx = 0;
    CMS_Callbacks myCb = {0};
    ubyte* pkcs7 = 0;
    ubyte4 pkcs7Len, outputLen;
    ubyte* output = 0;
    int inputSize, offset;
    intBoolean done;
    MSTATUS status = OK;
    ubyte* outBuffer = 0;
    int outOffset;
    sbyte4 numSigners;
    sbyte4 resCmp;
    ubyte* ecType = 0;
    ubyte4 bytesLeft = 0;

    hint <<= 24;


    myCb.getCertFun = NULL;
    myCb.valCertFun = NULL; /* not needed for digested */
    myCb.getPrivKeyFun = NULL; /* not needed for digested */

    /* read the file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( pkcs7FileName, &pkcs7, &pkcs7Len),
                            retVal, exit);

    /* allocate a buffer to collect the result */
    outBuffer = MALLOC( dataLen);
    retVal += UNITTEST_VALIDPTR( hint, outBuffer);
    if (retVal) goto exit;

    /* first test is to send everything in 1 to 19 bytes part */
    for (inputSize = 1; inputSize < 20; ++inputSize)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_newContext( &myCtx, 0, &myCb),
                            retVal, exit);
        retVal += UNITTEST_VALIDPTR( hint, myCtx);

        retVal += UNITTEST_INT(hint, CMS_getEncapContentType( myCtx, &ecType), ERR_EOF);

        /* send the pkcs7 */
        offset = 0;
        outOffset = 0;
        bytesLeft = pkcs7Len;

        do
        {
            /* note that we can send more data (and garbage too) without the
            code being affected: it will detect the logical end of the data */
            status = CMS_updateContext( myCtx, pkcs7 + offset, bytesLeft > inputSize ? inputSize : bytesLeft,
                                            &output, &outputLen, &done);
            if (output)
            {
                if (UNITTEST_TRUE(hint, outOffset + outputLen <= dataLen))
                {
                    ++retVal; goto exit;
                }

                DIGI_MEMCPY( outBuffer + outOffset, output, outputLen);
                outOffset += outputLen;

                FREE(output);
                output = 0;

                retVal += UNITTEST_STATUS( hint, CMS_getEncapContentType(myCtx, &ecType));

                retVal += UNITTEST_TRUE(hint, EqualOID( ecType, eContentTypeOID));
                FREE(ecType); ecType = 0;
            }
            offset += inputSize;
            bytesLeft -= inputSize;

        } while (!done && OK <= status);


        retVal += UNITTEST_STATUS( (hint | (inputSize << 16) | offset),
                                    status);

        retVal += UNITTEST_TRUE( (hint | (inputSize << 16) | offset),
                           ERR_PKCS7_INVALID_TYPE_FOR_OP == CMS_getNumSigners(myCtx, &numSigners));

        retVal += UNITTEST_INT((hint | (inputSize << 16)), numSigners, -1);

        retVal += UNITTEST_STATUS((hint | (inputSize << 16) | offset),
                                    CMS_deleteContext(&myCtx));

        retVal += UNITTEST_INT((hint | (inputSize << 16)), outOffset, dataLen);

        DIGI_MEMCMP( outBuffer, data, dataLen, &resCmp);

        retVal += UNITTEST_TRUE((hint | (inputSize << 16)), resCmp == 0);

    }

exit:
    if (ecType)
    {
        FREE(ecType);
    }

    if (output)
    {
        FREE(output);
    }

    CMS_deleteContext(&myCtx);

    if (outBuffer)
    {
        FREE(outBuffer);
    }

    if (pkcs7)
    {
        FREE(pkcs7);
    }

    return retVal;
}
#endif


#ifdef __ENABLE_DIGICERT_CMS__
/*---------------------------------------------------------------------------------*/

int CMSDigestedStreamTestEx( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                            ubyte algoId, const char* digestedFile,
                            const ubyte* eContentTypeOID)
{
    int retVal = 0;
    ubyte* output = 0;
    ubyte4 outputLen;
    ubyte4 len;

    len = DIGI_STRLEN(_CSB kCMSSampleData);

    UNITTEST_STATUS_GOTO( hint, PKCS7_DigestData(MOC_SYM(hwAccelCtx) NULL, NULL, NULL,
                                                    algoId, _CUB kCMSSampleData, len,
                                                    &output, &outputLen),
                                                    retVal, exit);

    UNITTEST_STATUS_GOTO( hint, DIGICERT_writeFile(digestedFile, output, outputLen),
                            retVal, exit);

    /* CMS stream test */
    retVal += CMSDigestedStreamTest(hint, digestedFile, _CUB kCMSSampleData, len, eContentTypeOID);

exit:

    if (output)
    {
        FREE(output);
    }

    return retVal;
}
#endif

/*---------------------------------------------------------------------------------*/

int cms_test_digested()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HARNESS__
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;
#endif

#ifdef __ENABLE_DIGICERT_CMS__
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 1, ht_md5, FILE_PATH("digested_md5.der"), pkcs7_data_OID );
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 2, ht_sha1, FILE_PATH("digested_sha1.der"), pkcs7_data_OID );
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 3, ht_sha224, FILE_PATH("digested_sha224.der"), pkcs7_data_OID );
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 4, ht_sha256, FILE_PATH("digested_sha256.der"), pkcs7_data_OID );
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 5, ht_sha384, FILE_PATH("digested_sha384.der"), pkcs7_data_OID );
    retVal += CMSDigestedStreamTestEx(MOC_SYM(hwAccelCtx) 6, ht_sha512, FILE_PATH("digested_sha512.der"), pkcs7_data_OID );
#endif

#ifdef __ENABLE_DIGICERT_HARNESS__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
#endif

    return retVal;

}


/*---------------------------------------------------------------------------------*/

int cms_test_get_algo_names()
{
    int retVal = 0;
    const char* name;

#ifdef __ENABLE_DIGICERT_CMS__

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( aes128CBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB"AES 128 CBC"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( aes192CBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB "AES 192 CBC"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( aes256CBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB "AES 256 CBC"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( desEDE3CBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB "3DES CBC"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( rc4_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB "RC4"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( desCBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name,  _CSB "DES CBC"));

    retVal += UNITTEST_STATUS( 1, CMS_AUX_getAlgoName( rc2CBC_OID, &name));
    retVal += UNITTEST_TRUE( 1, 0  == DIGI_STRCMP( _CSB name, _CSB"RC2 CBC"));

#endif

    return retVal;
}
