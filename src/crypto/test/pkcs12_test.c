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
#include "../../common/vlong.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
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
#include "../../crypto/pkcs12.h"
#include "../../crypto/pkcs8.h"

#if _DEBUG
#include <stdio.h>
#endif

#include "../../../unit_tests/unittest.h"


typedef struct PKVCS12Test
{
    const char* fileName;
    const char* uniPass;
    sbyte4 uniPassLen;
} PKCS12Test;

/* key is DER encoded PrivateKeyInfo defined in PKCS#8 */
MSTATUS testContentHandler(const void* context, contentTypes type,
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
        if (OK > (status = DIGICERT_writeFile(FILE_PATH("pkcs12keyBlob.dat"), keyBlob, keyBlobLen)))
            goto exit;
        break;
    case CERT:
        if (OK > (status = DIGICERT_writeFile(FILE_PATH("pkcs12cert.der"), (ubyte*)content, contentLen)))
            goto exit;
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

int TestSampleFile(MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                   const char* fileName, ubyte* uniPass, sbyte4 passLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    ASN1_ITEMPTR pRootItem = NULL;
    CStream cs;
    ubyte* pFile=NULL;
    ubyte4 fileLen;
    MemFile memFile;

#ifdef DEBUG_PKCS12
    /* DEBFILENAME_MAX_LEN matches that in pkcs12.c */
#define DEBFILENAME_MAX_LEN 128
    extern char gDebFileName[];
    printf("Processing file=%s\n", fileName);
    strncpy(gDebFileName, fileName, DEBFILENAME_MAX_LEN);
    gDebFileName[strlen(gDebFileName)-4] = 0x00;
#endif

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(fileName, &pFile, &fileLen),
                          retVal, exit);
    MF_attach(&memFile, fileLen, pFile);
    CS_AttachMemFile(&cs, &memFile );

    UNITTEST_STATUS_GOTO( hint, ASN1_Parse( cs, &pRootItem ),
                         retVal, exit);

        /* pkcs 12 */
    UNITTEST_STATUS_GOTO(hint,PKCS12_ExtractInfo(MOC_RSA(hwAccelCtx)
                                        pRootItem,
                                        cs,
                                        uniPass, passLen,
                                        NULL, NULL, NULL, &testContentHandler),
                         retVal, exit);

exit:
    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }
    if (pFile)
    {
        FREE(pFile);
    }
    return retVal;
}

int pkcs12_test_all()
{
    int retVal = 0;
    PKCS12Test pkcs12Test[] =
    {
        {
            FILE_PATH("certra.pfx"),
            "\0h\0e\0l\0l\0o\0\0",
            12
        },

        {
            FILE_PATH("certsj.pfx"),
            "\0h\0e\0l\0l\0o\0\0",
            12
        },
        {
            FILE_PATH("mycert.p12"),
            "\0p\0a\0s\0s" /* password  */
            "\0w\0o\0r\0d\0\0",
            18
        },
        {
            FILE_PATH("h1.mocana.sipit.net.p12"),
            "\0p\0a\0s\0s" /* password  */
            "\0w\0o\0r\0d\0\0",
            18
        },
        {
            FILE_PATH("h2.mocana.sipit.net.p12"),
            "\0p\0a\0s\0s" /* password  */
            "\0w\0o\0r\0d\0\0",
            18
        },
        {
            FILE_PATH("hornet.p12"),
            "\x00\x73\x00\x65\x00\x63"
            "\x00\x72\x00\x65\x00\x74"
            "\x00\x00", /* secret */
            14
        },
        {
            FILE_PATH("jack.p12"),
            "\x00\x31\x00\x32\x00\x33" /* password = 1234 */
            "\x00\x34\x00\x00",
            10
        },
        {
            FILE_PATH("myfile.p12"),
            "\x00\x31\x00\x32\x00\x33" /* password = 1234 */
            "\x00\x34\x00\x00",
            10
        },
        /* BER PasswordIntegrityMode */
        {
            FILE_PATH("test_pkcs12_001.p12"),
            "\x00\x61\x00\x6E\x00\x79" /* password = anything  */
            "\x00\x74\x00\x68\x00\x69\x00\x6E\x00\x67\x00\x00",
            18
        },
    };
    hwAccelDescr hwAccelCtx;
    int i;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal = 0;
    for (i =0; i < COUNTOF(pkcs12Test); ++i)
    {
        retVal += TestSampleFile(MOC_SYM(hwAccelCtx)i,
                                 (const char*)pkcs12Test[i].fileName,
                                 (ubyte*) pkcs12Test[i].uniPass,
                                 pkcs12Test[i].uniPassLen);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}
