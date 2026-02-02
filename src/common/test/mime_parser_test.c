/*
 * mime_parser_test.c
 *
 * unit test for mime_parser.c APIs
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
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mocana.h"

#include "../mime_parser.c"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static int test_mime_file(sbyte *pFile, int h)
{
    int retVal = 0;
    ubyte *pData = NULL, *pIter = NULL, *pLine = NULL;
    ubyte4 dataLen = 0, iterLen = 0, lineLen = 0;
    ubyte pTmp[4096] = { 0 };
    ubyte4 tmpLen = 0;
    sbyte4 cmp = -1;

    retVal += UNITTEST_STATUS(h, DIGICERT_readFile(pFile, &pData, &dataLen));
    pIter = pData;
    iterLen = dataLen;

    while (iterLen > 0)
    {
        retVal += UNITTEST_STATUS(h, MIME_getLine(&pIter, &iterLen, &pLine, &lineLen));

        DIGI_MEMCPY(pTmp + tmpLen, pLine, lineLen);
        tmpLen += lineLen;
        if ('\n' == *(pIter - 1))
        {
            *(pTmp + tmpLen) = '\n';
            tmpLen++;
        }
    }

    retVal += UNITTEST_INT(h, tmpLen, dataLen);
    if (0 == retVal)
    {
        retVal += UNITTEST_STATUS(h, DIGI_MEMCMP(pTmp, pData, tmpLen, &cmp));
        retVal += UNITTEST_INT(h, 0, cmp);
    }

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    return retVal;
}

int mime_unittest_get_line()
{
    int retVal = 0;
    unsigned int i;
    sbyte *ppMimeFiles[] = {
        "basic.mime",
        "basic_newline.mime"
    };

    for (i = 0; i < COUNTOF(ppMimeFiles); i++)
    {
        retVal += test_mime_file(ppMimeFiles[i], i);
    }

    return retVal;
}

int test_mime_get_boundary(char *pInput, char *pExpected)
{
    int retVal = 0;
    sbyte *pBoundary = NULL;

    retVal += UNITTEST_STATUS(__MOC_LINE__, MIME_getBoundary((ubyte *)pInput, DIGI_STRLEN(pInput), &pBoundary));

    retVal += UNITTEST_INT(__MOC_LINE__, 0, DIGI_STRCMP(pBoundary, pExpected));

    DIGI_FREE((void **) &pBoundary);

    return retVal;
}

int mime_unittest_get_boundary()
{
    int retVal = 0;

    retVal += test_mime_get_boundary(
        "Content-Type: multipart/mixed; boundary=\"DeviceTM_Certificate_Response_Boundary\"",
        "--DeviceTM_Certificate_Response_Boundary");

    return retVal;
}

int mime_parser_test_main()
{
    int retVal = 0;

    retVal += mime_unittest_get_line();
    retVal += mime_unittest_get_boundary();

    return retVal;
}