/*
 *  parsecert_test.c
 *
 *  unit test for parsecert.c
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

#include "../parsecert.c"

#include "../../crypto/cert_store.h"

#include "../../../unit_tests/unittest.h"

#define _CSB (const sbyte*)

typedef struct ExpectedResult
{
    MSTATUS     res;
    const char* fileName;
    ubyte4      extra;
} ExpectedResult;


typedef struct ExpectedResult2
{
    MSTATUS     res;
    const char* fileName;
    const char* match;
    ubyte4      extra;
} ExpectedResult2;



typedef struct ExpectedValue
{
    ubyte4      type;
    const char* value;
} ExpectedValue;


const ExpectedValue kExpectedCRLValuesCert1[] =
{
    { 6, "http://crl.microsoft.com/pki/mscorp/crl/mswww(2).crl" },
    { 6, "http://corppki/crl/mswww(2).crl" }
};

const ExpectedValue kExpectedCRLValues2000Remote[] =
{
    { 6, "ldap:///CN=Server2000CA.me06cas.intel.com,CN=win2000CA,CN=CDP,CN=Public%20Key%20Services,"
    "CN=Services,CN=Configuration,DC=me06cas,DC=intel,DC=com?certificateRevocationList?base?"
    "objectclass=cRLDistributionPoint" },
    { 6,  "http://win2000ca.me06cas.intel.com/CertEnroll/Server2000CA.me06cas.intel.com.crl" }
};

const ExpectedValue kExpectedCRLValuesNyTimes[] =
{
    {6, "http://crl.verisign.com/Class3InternationalServer.crl"}
};

const ExpectedValue kExpectedAltNameValuesSCard[] =
{
    /* subjectAltName - GeneralName - otherName - Microsoft User Principal Name */
    /* Must be ASN1-encoded UTF8 string */
    {UTF8STRING, "Scard@blazerdev.com"}
};

const ExpectedValue kExpectedAltNameValuesKeyWe[] =
{
    /* subjectAltName - GeneralName */
    /* 6 is the tag */
    {6, "kiwi:a2V5dG9uZS50ZXN0LjY1MEBnbWFpbC5jb20=@keytone.net"}
};


typedef struct MyEnumCbArg
{
    ubyte4 numCalls;
    ubyte4 hint;
    ubyte4 failures;
    ubyte4 numValues;
    const ExpectedValue* pExpectedValues;
} MyEnumCbArg;


/* test call back function for matching names */
typedef int (*MatchTestCb)(ASN1_ITEM* pRoot, CStream cs);

/*--------------------------------------------------------------------------*/

MSTATUS MyEnumCallback( ASN1_ITEM* pItem, CStream cs, void* userArg)
{
    MyEnumCbArg* pTestInfo = (MyEnumCbArg*) userArg;
    const ExpectedValue* pEV;
    const ubyte* value;
    ubyte4 errors = 0;
    sbyte4 cmpRes;

    if ( pTestInfo->numCalls < pTestInfo->numValues)
    {
        pEV = pTestInfo->pExpectedValues + pTestInfo->numCalls;
        errors += UNITTEST_INT(pTestInfo->hint, pItem->tag, pEV->type);
        errors += UNITTEST_INT(pTestInfo->hint, pItem->length,
                            DIGI_STRLEN( _CSB pEV->value));

        value = CS_memaccess( cs, pItem->dataOffset, pItem->length);
        if ( !value)
        {
            return ERR_MEM_ALLOC_FAIL;
        }
        DIGI_MEMCMP( value, (const ubyte*) pEV->value, pItem->length, &cmpRes);
        errors += UNITTEST_INT(pTestInfo->hint, cmpRes, 0);
        CS_stopaccess( cs, value);
    }

    ++(pTestInfo->numCalls);
    ++(pTestInfo->hint);

    pTestInfo->failures += errors;
    return OK;
}


/*------------------------------------------------------------------------*/

int enumCRL_test( const char* fileName, ubyte2 numCRLs,
                 const ExpectedValue* expectedValues, ubyte4 hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    MyEnumCbArg testInfo;
    int retVal = 0;

    testInfo.failures = 0;
    testInfo.hint = hint;
    testInfo.numCalls = 0;
    testInfo.numValues = numCRLs;
    testInfo.pExpectedValues = expectedValues;

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);

    status = X509_enumerateCRL( ASN1_FIRST_CHILD(pRootItem), cs,
                               MyEnumCallback, &testInfo);

    retVal += UNITTEST_STATUS(hint, status);
    retVal += testInfo.failures;
    retVal += UNITTEST_INT(hint, testInfo.numValues, testInfo.numCalls);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int enumAltName_test( const char* fileName, sbyte4 isSubject, ubyte2 numAltNames,
                     const ExpectedValue* expectedValues, ubyte4 hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    MyEnumCbArg testInfo;
    int retVal = 0;

    testInfo.failures = 0;
    testInfo.hint = hint;
    testInfo.numCalls = 0;
    testInfo.numValues = numAltNames;
    testInfo.pExpectedValues = expectedValues;

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);

    status = X509_enumerateAltName( ASN1_FIRST_CHILD(pRootItem), cs, isSubject,
                                   MyEnumCallback, &testInfo);

    retVal += UNITTEST_STATUS(hint, status);
    retVal += testInfo.failures;
    retVal += UNITTEST_INT(hint, testInfo.numValues, testInfo.numCalls);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int MatchTestCbTest1(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 1: certificate CN = homedelivery.nytimes.com */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB "nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB ".nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 1, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 2, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 3, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch7[] = {
        { 3, _CSB ".nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch8[] = {
        { 4, _CSB"nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch9[] = {
        { 5, _CSB "nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch10[] = {
        { 7, _CSB "nytimes.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch11[] = {
        { 0, _CSB "homedelvery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch12[] = {
        { 1, _CSB "nytimes.comX" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch13[] = {
        { 1, _CSB "x.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch14[] = {
        { 1, _CSB "xhomedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch15[] = {
        { 2, _CSB "xhomedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch16[] = {
        { 3, _CSB "xhomedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch17[] = {
        { 5, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch18[] = {
        { 5, _CSB ".nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch19[] = {
        { 5, _CSB "ytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch20[] = {
        { 7, _CSB "ytimes.com" },
        { 0, NULL }
    };

    /* positive tests */
    CNMatchInfo namesToMatch21[] = {
        { 0, _CSB "homedelvery.nytimes.com" },
        { 0, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch22[] = {
        { 1, _CSB "nytimes.comX" },
        { 1, _CSB "nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch23[] = {
        { 1, _CSB "x.nytimes.com" },
        { 1, _CSB ".nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch24[] = {
        { 1, _CSB "xhomedelivery.nytimes.com" },
        { 1, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch25[] = {
        { 2, _CSB "xhomedelivery.nytimes.com" },
        { 2, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch26[] = {
        { 3, _CSB "xhomedelivery.nytimes.com" },
        { 3, _CSB "homedelivery.nytimes.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch27[] = {
        { 3, _CSB ".nytimes.com" },
        { 3, _CSB "xhomedelivery.nytimes.com" },
        { 0, NULL }
    };

    int retVal = 0;

    status = X509_compSubjectCommonName( pCert, cs, _CSB "homedelivery.nytimes.com");
    retVal += UNITTEST_STATUS(0, status);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"omedelivery.nytimes.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"homedelivery.nytimes.co");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"homedelivery.nytimes.comX");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"Xhomedelivery.nytimes.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"homedelvery.nytimes.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch1);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch2);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch3);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch4);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch5);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch6);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch7);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch11);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch12);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch13);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch14);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch15);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch16);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch21);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch22);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch23);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch24);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch25);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch26);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch27);
    retVal += UNITTEST_INT(0, status, OK);

    return retVal;

}


/*------------------------------------------------------------------------*/

int MatchTestCbTest2(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 2: certificate CN = *.mocana.com */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB"sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB"*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 1, _CSB"sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 0, _CSB"*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 3, _CSB"*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch7[] = {
        { 3, _CSB".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch8[] = {
        { 1, _CSB"ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch9[] = {
        { 3, _CSB"ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch10[] = {
        { 5, _CSB"mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch11[] = {
        { 7, _CSB"mocana.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch111[] = {
        { 2, _CSB"sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch112[] = {
        { 3, _CSB"sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch113[] = {
        { 0, _CSB"mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch114[] = {
        { 2, _CSB"mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch115[] = {
        { 1, _CSB"*.mocana.comX" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch116[] = {
        { 3, _CSB"*.mocana.comX" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch117[] = {
        { 2, _CSB".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch118[] = {
        { 1, _CSB"acana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch119[] = {
        { 3, _CSB"acana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch120[] = {
        { 0, _CSB"fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch121[] = {
        { 1, _CSB"fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch122[] = {
        { 2, _CSB"fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch123[] = {
        { 3, _CSB"fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch124[] = {
        { 5, _CSB"fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch125[] = {
        { 5, _CSB"ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch126[] = {
        { 5, _CSB".mocana.com" },
        { 0, NULL }
    };

    int retVal = 0;

    status = X509_compSubjectCommonName( pCert, cs, _CSB"sslexample.mocana.com");
    retVal += UNITTEST_STATUS(0, status);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"sslexamplemocana.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"sslexample.mocana.co");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"ssl.mocana.comX");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB"ssl.mocaa.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch1);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch2);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch3);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch4);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch5);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch6);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch7);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch8);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch9);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch10);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch11);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch111);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch112);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch113);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch114);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch115);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch116);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch117);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch118);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch119);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch120);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch121);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch122);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch123);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch124);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch125);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch126);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    return retVal;
}


/*------------------------------------------------------------------------*/

int MatchTestCbTest3(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 3: certificate CN = sslexample.fakemocana.com */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "sslexample.fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB ".fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 5, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 1, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 1, _CSB "sslexample.fakemocana.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch11[] = {
        { 0, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch12[] = {
        { 1, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch13[] = {
        { 5, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch14[] = {
        { 1, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch15[] = {
        { 5, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch16[] = {
        { 5, _CSB "sslexample.fakemocana.com" },
        { 0, NULL }
    };

    int retVal = 0;

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexample.fakemocana.com");
    retVal += UNITTEST_STATUS(0, status);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexamplefakemocana.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexample.fakemocana.co");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "ssl.fakemocana.comX");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "ssl.fakemocaa.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch1);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch2);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch3);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch4);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch5);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch6);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch11);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch12);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch13);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch14);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch15);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch16);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    return retVal;
}


/*------------------------------------------------------------------------*/

int MatchTestCbTest4(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 4: certificate CN = *.cana.com */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "sslexample.cana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB ".cana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB "cana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 5, _CSB "cana.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch11[] = {
        { 0, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch12[] = {
        { 1, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch13[] = {
        { 5, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch14[] = {
        { 1, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch15[] = {
        { 5, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch16[] = {
        { 5, _CSB "sslexample.fakemocana.com" },
        { 0, NULL }
    };

    int retVal = 0;

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexample.cana.com");
    retVal += UNITTEST_STATUS(0, status);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexamplecana.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "sslexample.cana.co");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "ssl.cana.comX");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonName( pCert, cs, _CSB "ssl.caa.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch1);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch2);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch3);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch4);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch11);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch12);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch13);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch14);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch15);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch16);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    return retVal;
}


/*------------------------------------------------------------------------*/

int MatchTestCbTest5(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 5: certificate Alt Subject Name = rossi2970.viper.com */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "rossi2970.viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB ".viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB "viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 5, _CSB "viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 1, _CSB "per.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 1, _CSB "rossi2970.viper.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch11[] = {
        { 0, _CSB "rossi.viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch12[] = {
        { 1, _CSB "rossi.viper.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch13[] = {
        { 5, _CSB "per.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch14[] = {
        { 1, _CSB ".per.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch15[] = {
        { 5, _CSB ".per.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch16[] = {
        { 5, _CSB "rossi2970.viper.com" },
        { 0, NULL }
    };

    int retVal = 0;
    int flags = (1 << 2); /* DNS names */

    status = X509_compSubjectAltNames( pCert, cs, _CSB "rossi2970.viper.com", flags);
    retVal += UNITTEST_STATUS(0, status);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "rossi2970viper.com", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "rossi2970.viper.co", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "rossi2970.viper.comX", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "rossi2970.vipr.com", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch1, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch2, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch3, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch4, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch5, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch6, flags);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch11, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch12, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch13, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch14, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch15, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch16, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    return retVal;
}


/*------------------------------------------------------------------------*/

int MatchTestCbTest6(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 6 certificate Moxies (i.e. embedded 0x00 in name) */
    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* negative tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 2, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 3, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 4, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 5, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch7[] = {
        { 6, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch8[] = {
        { 7, _CSB "ssltest.mocana.com" },
        { 0, NULL }
    };

    int retVal = 0;

    status = X509_compSubjectCommonName( pCert, cs, _CSB "ssltest.mocana.com");
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);


    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch1);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch2);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch3);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch4);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch5);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch6);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch7);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);
    status = X509_compSubjectCommonNameEx( pCert, cs, namesToMatch8);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_COMMON_NAME);

    return retVal;
}



/*------------------------------------------------------------------------*/

int MatchTestCbTest7(ASN1_ITEM* pRoot, CStream cs)
{
    /* test 7: certificate altname DNS = *.mocana.com */
    /* This test is almost an exact copy of MatchTestCbTest4 where
       the common name is *.mocana.com except for
       the return value if the name doesn't match is
       ERR_CERT_BAD_SUBJECT_NAME instead of ERR_CERT_BAD_COMMON_NAME
    */

    MSTATUS status;
    ASN1_ITEMPTR pCert = ASN1_FIRST_CHILD(pRoot);

    /* positive tests */
    CNMatchInfo namesToMatch1[] = {
        { 0, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch2[] = {
        { 1, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch3[] = {
        { 1, _CSB "*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch4[] = {
        { 1, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch5[] = {
        { 0, _CSB "*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch6[] = {
        { 3, _CSB "*.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch7[] = {
        { 3, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch8[] = {
        { 1, _CSB "ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch9[] = {
        { 3, _CSB "ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch10[] = {
        { 5, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch11[] = {
        { 7, _CSB "mocana.com" },
        { 0, NULL }
    };

    /* negative tests */
    CNMatchInfo namesToMatch111[] = {
        { 2, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch112[] = {
        { 3, _CSB "sslexample.mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch113[] = {
        { 0, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch114[] = {
        { 2, _CSB "mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch115[] = {
        { 1, _CSB "*.mocana.comX" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch116[] = {
        { 3, _CSB "*.mocana.comX" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch117[] = {
        { 2, _CSB ".mocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch118[] = {
        { 1, _CSB "acana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch119[] = {
        { 3, _CSB "acana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch120[] = {
        { 0, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch121[] = {
        { 1, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch122[] = {
        { 2, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch123[] = {
        { 3, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch124[] = {
        { 5, _CSB "fakemocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch125[] = {
        { 5, _CSB "ocana.com" },
        { 0, NULL }
    };
    CNMatchInfo namesToMatch126[] = {
        { 5, _CSB ".mocana.com" },
        { 0, NULL }
    };

    int retVal = 0;
    ubyte4 flags = (1 << 2); /* DNS names */

    status = X509_compSubjectAltNames( pCert, cs, _CSB "sslexample.mocana.com", flags);
    retVal += UNITTEST_INT(0, status, OK); /* X509_compSubjectAltNames now does wildchar comparisons by default */

    status = X509_compSubjectAltNames( pCert, cs, _CSB "sslexamplemocana.com", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "sslexample.mocana.co", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "ssl.mocana.comX", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNames( pCert, cs, _CSB "ssl.mocaa.com", flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch1, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch2, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch3, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch4, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch5, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch6, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch7, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch8, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch9, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch10, flags);
    retVal += UNITTEST_INT(0, status, OK);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch11, flags);
    retVal += UNITTEST_INT(0, status, OK);

    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch111, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch112, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch113, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch114, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch115, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch116, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch117, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch118, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch119, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch120, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch121, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch122, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch123, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch124, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch125, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);
    status = X509_compSubjectAltNamesEx( pCert, cs, namesToMatch126, flags);
    retVal += UNITTEST_INT(0, status, ERR_CERT_BAD_SUBJECT_NAME);

    return retVal;
}


/*------------------------------------------------------------------------*/

int matchName_test( const char* fileName, MatchTestCb matchTestCb, int hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    int retVal = 0;


    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);

    retVal += matchTestCb( pRootItem, cs);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int partialRead_test( int hint, const char* fileName)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 i, certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    int retVal = 0;
    MSTATUS rets[10];

    for (i=0; i < 10; ++i)
    {
        rets[i] = -1;
    }

    hint <<= 16;
    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    /* try to parse partial -- it should return only one of those errors:
        ERR_ASN_*/
    for (i = 0; i < certLen-1; ++i)
    {

        MF_attach(&mf, (sbyte4)i, pCert);
        CS_AttachMemFile(&cs, &mf);
        status = ASN1_Parse( cs, &pRootItem);

        {
            int j;
            for (j = 0; j < 10; ++j)
            {
                if ( status == rets[j])
                {
                    break;
                }
                else if ( -1 == rets[j])
                {
                    rets[j] = status;
                    break;
                }
            }
        }

        retVal += UNITTEST_TRUE( hint + i, (ERR_EOF == status));

        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
        pRootItem = 0;
    }



exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int signAlgo_test( const char* fileName, int signAlgo)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ubyte   rsaSignAlgo;
    int retVal = 0;

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(signAlgo, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(signAlgo, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(signAlgo,  pRootItem);

    status = X509_getRSASignatureAlgo(ASN1_FIRST_CHILD(pRootItem),
                                      cs, &rsaSignAlgo);
    retVal += UNITTEST_STATUS(signAlgo, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_INT( signAlgo, signAlgo, rsaSignAlgo);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int extractDN_test( const char* fileName, int hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    certDistinguishedName retDN;
    int retVal = 0;


    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);

    retVal += X509_extractDistinguishedNames( ASN1_FIRST_CHILD(pRootItem),
                                             cs, 1, &retDN);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}

/*------------------------------------------------------------------------*/
int extractDate_test(const char* fileName,
                     const char* expectedStartDate,
                     const char* expectedEndDate,
                     int hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    int retVal = 0;

    ASN1_ITEM*  pStart;
    ASN1_ITEM*  pEnd;
    sbyte*      pAsciiTime = NULL;
    TimeDate    certTime;
    sbyte4      cmpRes = 0;

    pAsciiTime = MALLOC(16);

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);

    status = X509_getValidityTime(ASN1_FIRST_CHILD(pRootItem), &pStart, &pEnd);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    status = X509_getCertTime( pStart, cs, &certTime);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    X509_convertTime(&certTime, (ubyte *)pAsciiTime);
    DIGI_MEMCMP((const ubyte *)pAsciiTime,
               (const ubyte *)expectedStartDate,
               16,
               &cmpRes);
    if (0 != cmpRes)
    {
        retVal += UNITTEST_STATUS(hint, ERR_FALSE);
    }

    status = X509_getCertTime( pEnd, cs, &certTime);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    X509_convertTime(&certTime, (ubyte *)pAsciiTime);
    DIGI_MEMCMP((const ubyte *)pAsciiTime,
               (const ubyte *)expectedEndDate,
               16,
               &cmpRes);
    if (0 != cmpRes)
    {
        retVal += UNITTEST_STATUS(hint, ERR_FALSE);
    }


    exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    if (NULL != pAsciiTime)
    {
        FREE(pAsciiTime);
    }

    return retVal;
}

/*------------------------------------------------------------------------*/

int parsecert_test_extractDistinguishedName()
{
    int retVal = 0;

    retVal += extractDN_test( "motorola_2.der", 1); /* empty OU field */
    return retVal;
}

/*------------------------------------------------------------------------*/
int parsecert_test_extractDates()
{
    int retVal = 0;

    /* testing against UTCTime (start) and GeneralizedTime (end) */
    retVal += extractDate_test("enddate_5_24_2051.der",
                               "20030526000126Z",
                               "20510524230126Z",
                               0);
    return retVal;
}

/*------------------------------------------------------------------------*/

int parsecert_test_enumCRL()
{
    int retVal = 0;
    retVal += enumCRL_test("2000Remote.cer",
                           COUNTOF(kExpectedCRLValues2000Remote),
                            kExpectedCRLValues2000Remote, 0);

    retVal += enumCRL_test("Cert1.cer", COUNTOF(kExpectedCRLValuesCert1),
                            kExpectedCRLValuesCert1,
                           COUNTOF(kExpectedCRLValues2000Remote));

    retVal += enumCRL_test("nytimes.cer", COUNTOF(kExpectedCRLValuesNyTimes),
                           kExpectedCRLValuesNyTimes,
                           COUNTOF(kExpectedCRLValues2000Remote) +
                           COUNTOF(kExpectedCRLValuesCert1));

    retVal += enumCRL_test("wildcncert.cer", 0, NULL,
                           COUNTOF(kExpectedCRLValues2000Remote) +
                           COUNTOF(kExpectedCRLValuesCert1) +
                           COUNTOF(kExpectedCRLValuesNyTimes));

    retVal += enumCRL_test("version1crt.der", 0, NULL, 0);

    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_enumAltName()
{
    int retVal = 0;
    retVal += enumAltName_test("SCard.cer", 1,
                           COUNTOF(kExpectedAltNameValuesSCard),
                            kExpectedAltNameValuesSCard, 0);
    retVal += enumAltName_test("keywe.der", 1,
                               COUNTOF(kExpectedAltNameValuesKeyWe),
                            kExpectedAltNameValuesKeyWe, 0);

    return retVal;
}


/*-------------------------------------------------------------------------*/

int parsecert_test_matchCommonName()
{
    int retVal = 0;

    retVal += matchName_test( "nytimes.cer", MatchTestCbTest1, 1);
    retVal += matchName_test( "wildcncert.cer", MatchTestCbTest2, 2);
    retVal += matchName_test( "fakemocana.cer", MatchTestCbTest3, 3);
    retVal += matchName_test( "wildcanacert.cer", MatchTestCbTest4, 4);
    retVal += matchName_test( "domainctrl.der", MatchTestCbTest5, 5);
    retVal += matchName_test( "moxie1.der", MatchTestCbTest6, 6);
    retVal += matchName_test( "moxie2.der", MatchTestCbTest6, 7);
    retVal += matchName_test( "moxie3.der", MatchTestCbTest6, 8);
    retVal += matchName_test( "moxie4.der", MatchTestCbTest6, 9);
    retVal += matchName_test( "mpontillo.der", MatchTestCbTest7, 10);
    return retVal;
}


/*-------------------------------------------------------------------------*/

int parsecert_test_rsaSignAlgoExtraction()
{
    int retVal = 0;

    retVal += signAlgo_test("RSACert4.der", 4);
    retVal += signAlgo_test("RSACert5.der", 5);
    retVal += signAlgo_test("RSACert11.der", 11);
    retVal += signAlgo_test("RSACert12.der", 12);
    retVal += signAlgo_test("RSACert13.der", 13);
    retVal += signAlgo_test("RSACert14.der", 14);
    retVal += signAlgo_test("vmserv.cer", 5);

    return retVal;
}


/*-------------------------------------------------------------------------*/

int verifyTimesTest( int hint, MSTATUS expectedStatus,
                     const char* certFileName)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    int retVal = 0;
    TimeDate gmtTime;

    status = DIGICERT_readFile( certFileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);
    RTOS_timeGMT(&gmtTime);
    retVal += UNITTEST_INT(hint,
                           X509_verifyValidityTime( ASN1_FIRST_CHILD(pRootItem),
                                                   cs, &gmtTime),
                           expectedStatus);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}

/*-------------------------------------------------------------------------*/

int parsecert_test_verifyTimes()
{
    int retVal = 0;

    retVal += verifyTimesTest( 1, ERR_CERT_EXPIRED, "nytimes.cer");
    retVal += verifyTimesTest( 2, OK, "RSACert4.der");
    retVal += verifyTimesTest( 3, ERR_CERT_START_TIME_VALID_IN_FUTURE, "future.cer");

    return retVal;
}



/*-------------------------------------------------------------------------*/

int verifyCertsTest( int hint, MSTATUS expectedStatus,
                     ubyte expectedKeyType,
                     const char* certFileName,
                     const char* parentCertFileName)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ubyte* pParentCert = 0;
    ubyte4 parentCertLen;
    MemFile parentMf;
    CStream parentCs;
    ASN1_ITEMPTR pParentRootItem = 0;  /* can be pRootItem if
                                          parentCertFileName = 0 */
    int retVal = 0;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key = { 0, 0};

    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    status = DIGICERT_readFile( certFileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);
    if (!pRootItem) goto exit;

    if (parentCertFileName)
    {
        status = DIGICERT_readFile( parentCertFileName, &pParentCert,
                                  &parentCertLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (status < OK) goto exit;

        MF_attach( &parentMf, (sbyte4)parentCertLen, pParentCert);
        CS_AttachMemFile(&parentCs, &parentMf);

        status = ASN1_Parse( parentCs, &pParentRootItem);
        retVal += UNITTEST_STATUS(hint, status);
        if (status < OK) goto exit;
        retVal += UNITTEST_VALIDPTR(hint,  pParentRootItem);
        if (!pParentRootItem) goto exit;
    }
    else
    {
        pParentRootItem = pRootItem;
        parentCs = cs;
    }

    status = X509_validateLink(MOC_RSA(hwAccelCtx)
                               ASN1_FIRST_CHILD(pRootItem), cs,
                               ASN1_FIRST_CHILD(pParentRootItem), parentCs,
                               0); /* chain length */

    if (OK <= status)
    {
        TimeDate td;
        td.m_year = 45; /* 1970 + 45 = 2015 */
        td.m_month = 11; /* December */
        td.m_day = 27;
        td.m_hour = td.m_minute = td.m_second = 0;


        status = X509_verifyValidityTime(ASN1_FIRST_CHILD(pRootItem), cs, &td);
    }

    retVal += UNITTEST_INT(hint, status, expectedStatus);

    if ( OK <= status) /* key extraction test */
    {
        status = X509_setKeyFromSubjectPublicKeyInfo(ASN1_FIRST_CHILD(pRootItem),
                                                     cs, &key);
        UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

        retVal += UNITTEST_TRUE( hint, key.type == expectedKeyType);
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    if (parentCertFileName && pParentRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pParentRootItem);
    }

    if (pParentCert)
    {
        FREE(pParentCert);
    }

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    return retVal;
}


/*-------------------------------------------------------------------------*/

int rootCertTest( int hint, MSTATUS expectedStatus,
                     const char* certFileName)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    int retVal = 0;

    status = DIGICERT_readFile( certFileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach( &mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;
    retVal += UNITTEST_VALIDPTR(hint,  pRootItem);
    if (!pRootItem) goto exit;


    status = X509_isRootCertificate( ASN1_FIRST_CHILD(pRootItem), cs);

    retVal += UNITTEST_INT(hint, status, expectedStatus);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_verifyCerts()
{
    int retVal = 0;

    retVal += verifyCertsTest( 1, ERR_CERT_EXPIRED, akt_rsa, "radiometer.der", "rsaca.der");
    retVal += verifyCertsTest( 2, ERR_CERT_EXPIRED, akt_rsa, "motorola_1.der", "motorola_ca.der");
    retVal += verifyCertsTest( 3, ERR_CERT_INVALID_CERT_POLICY, akt_rsa, "sonus.der", NULL); /* basic constraints: not a CA */
    retVal += verifyCertsTest( 4, OK, akt_rsa, "sonus2.der", NULL);
    retVal += verifyCertsTest( 5, OK, akt_ecc, "MS-EccRoot.der", NULL);
    retVal += verifyCertsTest( 6, ERR_CERT_EXPIRED, akt_ecc, "MS_ECDSACert256.der", "MS-EccRoot.der");
    retVal += verifyCertsTest( 7, ERR_CERT_EXPIRED, akt_ecc, "MS_ECDSACert384.der", "MS-EccRoot.der");
    retVal += verifyCertsTest( 8, ERR_CERT_EXPIRED, akt_ecc, "MS_ECDSACert521.der", "MS-EccRoot.der");
    retVal += verifyCertsTest( 9, OK, akt_rsa, "Cert-171-61.der", NULL);
    retVal += verifyCertsTest( 10, OK, akt_dsa, "dsacert.der", NULL);
    retVal += verifyCertsTest( 11, ERR_CERT_INVALID_CERT_POLICY, akt_rsa, "hpcert.der", NULL); /* version 3, basic constraints not there */
    retVal += verifyCertsTest( 12, OK, akt_ecc, "ecdsacertca.der", NULL);
    retVal += verifyCertsTest( 13, OK, akt_ecc, "server1cert.der", "ecdsacertca.der");
    retVal += verifyCertsTest( 14, OK, akt_ecc, "server2cert.der", "ecdsacertca.der");
    retVal += verifyCertsTest( 15, ERR_CERT_EXPIRED, akt_rsa, "newcert.der", "cacert.der");
    retVal += verifyCertsTest( 16, ERR_CERT_EXPIRED, akt_rsa, "entrustcert1.der", "entrust_root.cer");
    retVal += verifyCertsTest( 17, ERR_CERT_EXPIRED, akt_rsa, "QFW-VPN01A_IDCert.der", "entrust_root.cer");
    retVal += verifyCertsTest( 18, ERR_CERT_INVALID_CERT_POLICY, akt_rsa, "vmserv.cer", NULL); /* version 3, basic constraints not there */
    retVal += verifyCertsTest( 19, OK, akt_dsa, "dsacert2.der", NULL);

    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_stream()
{
    int retVal = 0;

    retVal += partialRead_test( 1, "radiometer.der");
    retVal += partialRead_test( 2, "motorola_1.der");
    retVal += partialRead_test( 3, "sonus.der");
    retVal += partialRead_test( 4, "sonus2.der");
    retVal += partialRead_test( 5, "MS-EccRoot.der");
    retVal += partialRead_test( 6, "MS_ECDSACert256.der");
    retVal += partialRead_test( 7, "MS_ECDSACert384.der");
    retVal += partialRead_test( 8, "MS_ECDSACert521.der");
    retVal += partialRead_test( 9, "Cert-171-61.der");
    retVal += partialRead_test( 10, "ber_encoded.der");
    retVal += partialRead_test( 11, "dsacert.der");
    return retVal;
}



/*------------------------------------------------------------------------*/

int parsecert_test_rootCerts()
{
    static ExpectedResult res[] =
    {
        { OK, "rsaca.der", 0},
        { ERR_FALSE, "radiometer.der", 0 },
        { OK, "motorola_ca.der", 0 },
        { ERR_FALSE, "motorola_1.der", 0 },
        { OK, "sonus2.der", 0 }, /* this one has special extensions */
        { ERR_FALSE, "sonus.der", 0 },   /* this one too */
        { OK, "MS-EccRoot.der", 0},
        { OK, "dsacert.der", 0},
    };

    int i, retVal = 0;

    for( i = 0; i < COUNTOF(res); ++i)
    {
        retVal += rootCertTest( i, res[i].res, res[i].fileName);
    }
    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_altSubjectNames()
{
    static ExpectedResult2 res[] =
    {
        { ERR_CERT_BAD_SUBJECT_NAME, "2000Remote.cer", "nomatch.com", 0xFFFF},
        { ERR_CERT_BAD_SUBJECT_NAME, "Cert1.cer", "nomatch.com", 0xFFFF},
        { ERR_CERT_BAD_SUBJECT_NAME, "radiometer.der", "nomatch.com", 0xFFFF},
        { ERR_CERT_BAD_SUBJECT_NAME, "domainctrl.der", "nomatch.com", 0xFFFF},
        { ERR_CERT_BAD_SUBJECT_NAME, "domainctrl.der", "rossi2970.viper.com",  1 << 0},
        { ERR_CERT_BAD_SUBJECT_NAME, "domainctrl.der", "rossi2970.viper.com",  1 << 1},
        { ERR_CERT_BAD_SUBJECT_NAME, "domainctrl.der", "rossi2970.viper.com",  1 << 3},
        { OK, "domainctrl.der", "rossi2970.viper.com",  0xFFFF},
        { OK, "domainctrl.der", "rossi2970.viper.com",  1 << 2}, /* only DNS */
        /* THOU SHALL NOT USE BINARY DATA AS THE COMPARISON ARG
           SINCE IT CAN CONTAIN NULL CHARACTER(S)
           USE CERT_EnumerateAltNames to implement binary comp properly
           API updated to handle IP address strings and binary data. Specifying
           IP address directly as hex values with
           non-zero values works or specifying IP address as string works */
        { OK, "subjaltname_ip.der", "\xc0\xa8\x01\xfe",  1 << 7}, /* only iPAddress */
        { OK, "subjaltname_ip.der", "192.168.1.254",  1 << 7}, /* only iPAddress */
        /* add more here */
    };

    int i, retVal = 0;
    const char* prev = NULL;
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;

    for (i = 0; i < COUNTOF(res); ++i)
    {
        /* if a new file, load it */
        if ( prev != res[i].fileName)
        {
            /* release memory if necessary */
            if (pRootItem)
            {
                TREE_DeleteTreeItem( (TreeItem*) pRootItem);
            }

            if ( pCert)
            {
                FREE(pCert);
            }

            status = DIGICERT_readFile( res[i].fileName, &pCert, &certLen);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;

            MF_attach( &mf, (sbyte4)certLen, pCert);
            CS_AttachMemFile(&cs, &mf);

            status = ASN1_Parse( cs, &pRootItem);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;
            retVal += UNITTEST_VALIDPTR(i,  pRootItem);
            if (!pRootItem) goto exit;

            prev = res[i].fileName;
        }

        status = X509_compSubjectAltNames(ASN1_FIRST_CHILD(pRootItem), cs,
                                          _CSB res[i].match,
                                          res[i].extra);
        retVal += UNITTEST_INT( i, status, res[i].res);
    }

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_keyUsageCerts()
{
    static ExpectedResult res[] =
    {
        { OK, "2000Remote.cer",
          (1 << keyEncipherment | 1 << dataEncipherment | 1 << digitalSignature | 1 << nonRepudiation) },
        { OK, "Cert1.cer",
          (1 << digitalSignature | 1 << keyCertSign | 1 << cRLSign) },
        { OK, "radiometer.der",
          (1 << digitalSignature | 1 << keyEncipherment) },
        { OK, "vmserv.cer",
            (1 << digitalSignature | 1 << keyEncipherment | 1 << dataEncipherment ) },
        { OK, "Cert-171-61.der",
            (1 << keyCertSign | 1 << cRLSign) },
        { OK, "keywe.der",
            (1 << digitalSignature | 1 << keyAgreement | 1 << nonRepudiation) },
        { OK, "MS_ECDSACert521.der",
            (1 << digitalSignature | 1 << keyAgreement) },
       /* add more here */
    };

    int i, j, retVal = 0;
    const char* prev = NULL;
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    byteBoolean b;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ITEMPTR pKeyUsage;
    
    for (i = 0; i < COUNTOF(res); ++i)
    {
        /* if a new file, load it */
        if ( prev != res[i].fileName)
        {
            /* release memory if necessary */
            if (pRootItem)
            {
                TREE_DeleteTreeItem( (TreeItem*) pRootItem);
            }

            if ( pCert)
            {
                FREE(pCert);
            }

            status = DIGICERT_readFile( res[i].fileName, &pCert, &certLen);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;

            MF_attach( &mf, (sbyte4)certLen, pCert);
            CS_AttachMemFile(&cs, &mf);

            status = ASN1_Parse( cs, &pRootItem);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;
            retVal += UNITTEST_VALIDPTR(i,  pRootItem);
            if (!pRootItem) goto exit;

            prev = res[i].fileName;
        }

        status = X509_getCertificateKeyUsage( ASN1_FIRST_CHILD(pRootItem),
                                             cs, &pKeyUsage);
        retVal += UNITTEST_STATUS(i, status);

        for (j = 0; j < 32; ++j)
        {
            status = ASN1_getBitStringBit( pKeyUsage, cs, j, &b);
            if (OK > status)
            {
                retVal += UNITTEST_STATUS((i << 16)|j, status);
            }
            else
            {
                retVal += UNITTEST_TRUE ( (i << 16)|j, ((res[i].extra >> j) & 1) == b);
            }
        }

        retVal += UNITTEST_INT( i, status, res[i].res);

    }

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_keyUsageValueCerts()
{
    static ExpectedResult res[] =
    {
        { OK, "2000Remote.cer",
            (1 << keyEncipherment | 1 << dataEncipherment | 1 << digitalSignature | 1 << nonRepudiation) },
        { OK, "Cert1.cer",
            (1 << digitalSignature | 1 << keyCertSign | 1 << cRLSign) },
        { OK, "radiometer.der",
            (1 << digitalSignature | 1 << keyEncipherment) },
        { OK, "vmserv.cer",
            (1 << digitalSignature | 1 << keyEncipherment | 1 << dataEncipherment ) },
        { OK, "Cert-171-61.der",
            (1 << keyCertSign | 1 << cRLSign) },
        { OK, "keywe.der",
            (1 << digitalSignature | 1 << keyAgreement | 1 << nonRepudiation) },
        { OK, "MS_ECDSACert521.der",
            (1 << digitalSignature | 1 << keyAgreement) },
        { OK, "motorola_2.der",
            0xFFFF }
        /* add more here */
    };

    int i, retVal = 0;
    const char* prev = NULL;
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ubyte2 keyUsageVal;

    for (i = 0; i < COUNTOF(res); ++i)
    {
        /* if a new file, load it */
        if ( prev != res[i].fileName)
        {
            /* release memory if necessary */
            if (pRootItem)
            {
                TREE_DeleteTreeItem( (TreeItem*) pRootItem);
            }

            if ( pCert)
            {
                FREE(pCert);
            }

            status = DIGICERT_readFile( res[i].fileName, &pCert, &certLen);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;

            MF_attach( &mf, (sbyte4)certLen, pCert);
            CS_AttachMemFile(&cs, &mf);

            status = ASN1_Parse( cs, &pRootItem);
            retVal += UNITTEST_STATUS(i, status);
            if (status < OK) goto exit;
            retVal += UNITTEST_VALIDPTR(i,  pRootItem);
            if (!pRootItem) goto exit;

            prev = res[i].fileName;
        }

        status = X509_getCertificateKeyUsageValue(ASN1_FIRST_CHILD(pRootItem), cs,
                                                  &keyUsageVal);
        retVal += UNITTEST_STATUS(i, status);

        retVal += UNITTEST_INT( i, keyUsageVal, res[i].extra);

    }

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }
    
    if ( pCert)
    {
        FREE(pCert);
    }
    
    return retVal;
}


/*------------------------------------------------------------------------*/

int parsecert_test_CSR()
{
    static ExpectedResult res[] =
    {
#ifdef __DISABLE_DIGICERT_ASN1_ZERO_LENGTH_ALLOWED__
        { ERR_ASN_ZERO_LENGTH, "hpcsr.der", 0},
#else
        { OK, "hpcsr.der", 0},
#endif
    };

    int i, retVal = 0;
    MSTATUS status = OK;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;

    for (i = 0; i < COUNTOF(res); ++i)
    {
        DIGI_FREE((void **) &pCert);
        status = DIGICERT_readFile( res[i].fileName, &pCert, &certLen);
        retVal += UNITTEST_STATUS(i, status);
        if(OK > status)
        {
            goto exit;
        }

        MF_attach( &mf, (sbyte4)certLen, pCert);
        CS_AttachMemFile(&cs, &mf);

        if (NULL != pRootItem)
        {
            TREE_DeleteTreeItem((TreeItem *) pRootItem);
            pRootItem = NULL;
        }

        status = ASN1_Parse( cs, &pRootItem);
        retVal += UNITTEST_INT(i, status, res[i].res);
    }


exit:
    if (NULL != pRootItem)
        TREE_DeleteTreeItem((TreeItem *) pRootItem);

    DIGI_FREE((void **) &pCert);
    return retVal;
}

/*------------------------------------------------------------------------*/

int parsecert_test_san_ipv4()
{
    MSTATUS status;
    int retVal = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = NULL;
    ubyte4 flags = 1 << 7; /* iPAddress */

    status = DIGICERT_readFile("cert_ipv4.der", &pCert, &certLen);
    retVal += UNITTEST_STATUS(0, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRootItem);
    retVal += UNITTEST_STATUS(0, status);
    if (OK != status)
        goto exit;

    /* Error case */
    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "127.0.0.0", flags);
    retVal += UNITTEST_TRUE(0, OK != status);

    /* Error case */
    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "0.0.0.0", flags);
    retVal += UNITTEST_TRUE(0, OK != status);

    /* Error case */
    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "255.255.255.255", flags);
    retVal += UNITTEST_TRUE(0, OK != status);

    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "127.0.0.1", flags);
    retVal += UNITTEST_STATUS(0, status);

    /* Error case */
    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "127.0.0.0");
    retVal += UNITTEST_TRUE(0, OK != status);

    /* Error case */
    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "0.0.0.0");
    retVal += UNITTEST_TRUE(0, OK != status);

    /* Error case */
    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "255.255.255.255");
    retVal += UNITTEST_TRUE(0, OK != status);

    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "127.0.0.1");
    retVal += UNITTEST_STATUS(0, status);

exit:

    if (NULL != pRootItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pRootItem);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    return retVal;
}

/*------------------------------------------------------------------------*/

int parsecert_test_san_ipv6()
{
    MSTATUS status;
    int retVal = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = NULL;
    ubyte4 flags = 1 << 7; /* iPAddress */

    status = DIGICERT_readFile("cert_ipv6.der", &pCert, &certLen);
    retVal += UNITTEST_STATUS(0, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRootItem);
    retVal += UNITTEST_STATUS(0, status);
    if (OK != status)
        goto exit;

    /* Error case */
    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9abc:def0:fedc:ba98:7654:9999", flags);
    retVal += UNITTEST_TRUE(0, OK != status);

    status = X509_compSubjectAltNames(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9abc:def0:fedc:ba98:7654:3210", flags);
    retVal += UNITTEST_STATUS(0, status);

    /* Error case */
    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9abc:def0:fedc:ba98:7654:9999");
    retVal += UNITTEST_TRUE(0, OK != status);

    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9abc:def0:fedc:ba98:7654:3210");
    retVal += UNITTEST_STATUS(0, status);        

    /* TEST with capital letters */

    /* Error case */
    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9ABC:deF0:fEdc:ba98:7654:9999");
    retVal += UNITTEST_TRUE(0, OK != status);

    status = X509_matchName(
        ASN1_FIRST_CHILD(pRootItem), cs, (const sbyte *) "1234:5678:9ABC:deF0:fEdc:ba98:7654:3210");
    retVal += UNITTEST_STATUS(0, status);     

exit:

    if (NULL != pRootItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pRootItem);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    return retVal;
}

/*------------------------------------------------------------------------*/

#if 0 /* Temporary to fix problems */
MSTATUS negative_parse_printCert(ubyte* pCert, ubyte4 certLen, ubyte* pTestLengthVectorPoints)
{
    ubyte4 i        = 0;
    ubyte4 j        = 0;
    ubyte  prefix   = ' ';
    ubyte  postfix  = ' ';

    if (NULL == pCert)
        return ERR_NULL_POINTER;

    if (NULL != pTestLengthVectorPoints)
    {
        printf("Legend: (XX) indicates a TestLengthVectorPoint at location\n");
    }
    for (i = 0; certLen > i; i++)
    {
        if (0 == (i % 16))
        {
            printf("\n%3.3x0    ", (i / 16));
        }
        j = 0;
        if (NULL != pTestLengthVectorPoints)
        {
            while ((0x00 != pTestLengthVectorPoints[j]) && (i > pTestLengthVectorPoints[j]))
                j++;
            if ((i != 0) && (i == pTestLengthVectorPoints[j]))
            {
                prefix = '(';
                postfix = ')';
            }
            else
            {
                prefix = ' ';
                postfix = ' ';
            }
        }
        printf("%c%2.2x%c", prefix, pCert[i], postfix);
    }
    printf("\n");

    return OK;
}

/*------------------------------------------------------------------------*/

ubyte4 negative_parse_readLength(ubyte* pToLength, ubyte4* pLengthLenRet)
{
    ubyte4 i          = 0;
    ubyte4 objLen     = 0;
    ubyte4 objLenLen  = 0;

    if (NULL == pToLength)
        return 0;

    if (0x00 != (pToLength[0] & 0x80))
    {
        /* Multi byte length */
        objLenLen = (pToLength[0] & 0x7f) + 1;
        for(i = 1; objLenLen > i; i++)
        {
            objLen = objLen * 0x0100;
            objLen = objLen + pToLength[0 + i];
        }
    }
    else
    {
        /* Single byte length */
        objLenLen = 1;
        objLen = (pToLength[0] & 0x7f);
    }

    if (NULL != pLengthLenRet)
        (*pLengthLenRet) = objLenLen;

    return objLen;
}

/*------------------------------------------------------------------------*/

MSTATUS negative_parse_writeLength(ubyte4 length, ubyte* pWriteTo, ubyte4 lengthLen)
{
    MSTATUS  status     = OK;
    ubyte4   tmpLength  = 0;
    ubyte4   index      = 0;
    ubyte4   divValue   = 1;

    if (NULL == pWriteTo)
        return ERR_NULL_POINTER;

    if (1 != lengthLen)
    {
        /* Multi byte length */
        tmpLength = length;
        pWriteTo[index] = 0x80 | ((ubyte)(lengthLen - 1));
        index++;

        /* The length is passed in as a ubyte4, this will pad the extra */
        while (4 < (lengthLen - index))
        {
            pWriteTo[index] = 0x00;
            index++;
        }

        while (lengthLen > index)
        {
            divValue = 0x01 << 8 * (lengthLen - index - 1);
            if (0 == divValue)
            {
                status = -1;
                goto exit;
            }
            pWriteTo[index] = tmpLength / divValue;
            tmpLength = tmpLength % divValue;
            index++;
        }
    }
    else
    {
        /* Single byte length */
        pWriteTo[0] = 0x7F & (ubyte)length;
    }
exit:
    return status;
}

/*------------------------------------------------------------------------*/

MSTATUS negative_parse_findVectorTestPoints(ubyte* pCert, ubyte4 certLen, ubyte4* pCertIndex, ubyte* pTestLengthVectorPoints, const ubyte4 maxVectors)
{
    MSTATUS status        = OK;
    ubyte   tagClass      = 0;
    ubyte   tagValue      = 0;
    ubyte4  objLenLoc     = 0;
    ubyte4  lastOfObjLoc  = 0;
    ubyte4  objLenLen     = 0;
    ubyte4  objLen        = 0;
    ubyte4  i             = 0;
    ubyte   constructed   = FALSE;

    if (certLen <= (*pCertIndex))
    {
        status = -1;
        goto exit;
    }

    tagClass = pCert[*pCertIndex] >> 6;
    tagClass = tagClass & 0x30;

    if (0x00 != (pCert[*pCertIndex] & 0x20))
        constructed = TRUE;
    else
        constructed = FALSE;

    /* Checking for multi byte tag */
    tagValue = pCert[*pCertIndex] & 0x1f;
    if (0x1f != tagValue)
    {
        objLenLoc = (*pCertIndex) + 1;
    }
    else
    {
        objLenLoc = (*pCertIndex) + 1;
        while (0x00 != (pCert[objLenLoc] & 0x80))
            objLenLoc++;
        /* Increment one last time to position on the length */
        objLenLoc++;
    }

    objLen = negative_parse_readLength(&(pCert[objLenLoc]), &objLenLen);

    lastOfObjLoc = (*pCertIndex) + objLenLen + objLen;

    i = 0;
    /* Walk to a free location, choosing to use prcessor over memory */
    while ((maxVectors > i) && (0x00 != pTestLengthVectorPoints[i]))
        i++;
    pTestLengthVectorPoints[i] = objLenLoc;

    /* Continue Parse */
    if (TRUE == constructed)
    {
        (*pCertIndex) = (*pCertIndex) + objLenLen + 1;
        while ((*pCertIndex) < lastOfObjLoc)
        {
            if (OK > (status = negative_parse_findVectorTestPoints(pCert, certLen, pCertIndex, pTestLengthVectorPoints, maxVectors)))
                goto exit;
        }
    }
    else
    {
        (*pCertIndex) = lastOfObjLoc + 1;
    }

exit:
    return status;
}

/*------------------------------------------------------------------------*/

MSTATUS negative_parse_corruptCert(ubyte4 testCase, ubyte4 testCaseIndex, ubyte* pTestLengthVectorPoints, ubyte* pCert, ubyte4 certLen,ubyte** ppTestCertRet, ubyte4* pTestCertLenRet)
{
    MSTATUS  status        = OK;
    ubyte*   pTestCert     = NULL;
    ubyte4   testCertLen   = 0;
    ubyte4   allocCertLen  = 0;
    ubyte4   tmpA          = 0;
    ubyte4   tmpB          = 0;

    if ((NULL == pCert) || (NULL == ppTestCertRet) || (NULL == pTestCertLenRet) || (NULL == pTestLengthVectorPoints))
        return ERR_NULL_POINTER;

    if ((NULL != (*ppTestCertRet)) || (0 > certLen))
        return -1;

    /*
     * Do work for test type before copy
     *  "badCertLen" is used to make the test cert but can be changed later
     */
    switch (testCase)
    {
        case 0:
            /* NULL TEST (Copy Cert Only) */
            testCertLen = certLen;
            break;
        default:
            /* Copy Cert */
            testCertLen = certLen;
            break;
    }

    /* Create Test Certificate */
    if ((0 < testCertLen) && (0 < certLen))
    {
        if (testCertLen >= certLen)
            tmpA = testCertLen;
        else
            tmpA = certLen;

        if (NULL == (pTestCert = MALLOC(tmpA)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET(pTestCert, 0x00, tmpA);
        DIGI_MEMCPY(pTestCert, pCert, (sbyte4)tmpA);
    }

    /* Do work for test type after copy */
    switch (testCase)
    {
        case 0:
            /* NULL TEST (Copy Cert Only) */
            break;
        case 1:
            /* Simple test that adds 1 to the first lenth */
            tmpB = negative_parse_readLength(pTestCert + pTestLengthVectorPoints[0], &tmpA);
            tmpB = tmpB + 1;
            negative_parse_writeLength(tmpB, pTestCert + pTestLengthVectorPoints[0], tmpA);
            break;
        case 2:
            /* Test using a multi byte lenth of 1 padded with 0s to be over the size of ubyte4 */
            negative_parse_writeLength(0x01, pTestCert + pTestLengthVectorPoints[0], 6);
            break;
        case 3:
            /* Cert length of 0, with a valid cert in memory */
            testCertLen = 0;
            break;
        case 4:
            /* Givess the wrong length (shorter), with a valid cert in memory */
            if (0 < testCertLen)
            {
                status = testCertLen = testCertLen - testCaseIndex;
                if (1 == testCertLen)
                    status = OK;
            }
            break;
        default:
            printf("Test Case %i is currently not a valid test case!\n", testCase);
            status = -1;
            goto exit;
            break;
    }

    (*ppTestCertRet) = pTestCert;
    (*pTestCertLenRet) = testCertLen;

exit:
    if (OK > status)
    {
        FREE(pTestCert);
        pTestCert = NULL;
    }

    return status;
}

/*------------------------------------------------------------------------*/

MSTATUS parsecert_test_negative_parse_doTest(ubyte* pCert, ubyte4 certLen)
{
    MSTATUS       status     = OK;
    MemFile       mf;
    CStream       cs;
    ASN1_ITEMPTR  pRootItem  = NULL;

    MF_attach(&mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);
    status = ASN1_Parse(cs, &pRootItem);

    if (NULL == pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return status;
}


/*------------------------------------------------------------------------*/

int parsecert_test_negative_parse()
{
    const sbyte*    fileName                 = "rsaca.der";
    const ubyte4    MAX_TEST_VECTORS         = 01024;
    ubyte4          retVal                   = 0;
    MSTATUS         status                   = OK;
    MSTATUS         negTest_status           = OK;
    ubyte*          pCert                    = NULL;
    ubyte*          pTestCert                = NULL;
    ubyte4          certLen                  = 0;
    ubyte4          testCertLen              = 0;
    ubyte4          testCase                 = 0;
    ubyte4          testCaseIndex            = 0;
    ubyte4          certIndex                = 0;
    ubyte*          pTestLengthVectorPoints  = NULL;

    if (NULL == (pTestLengthVectorPoints = MALLOC(MAX_TEST_VECTORS + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pTestLengthVectorPoints, 0x00, MAX_TEST_VECTORS + 1)))
        goto exit;

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    if (status < OK)
        goto exit;

    printf("\n============== GOOD CERT ============\n");
    negative_parse_printCert(pCert, certLen, NULL);
    printf("============== GOOD CERT END ============\n");

    if (OK > (status = negative_parse_findVectorTestPoints(pCert, certLen, &certIndex, pTestLengthVectorPoints, MAX_TEST_VECTORS)))
        goto exit;
    if (0 == pTestLengthVectorPoints[0])
    {
        printf("Did not find any lengths to test!\n");
        status = -1;
        goto exit;
    }

    /* Sanity check on the source cert */
    if (OK > (status = parsecert_test_negative_parse_doTest(pCert, certLen)))
        goto exit;

    for (testCase = 1; 10 >= testCase; testCase++)
    {
        testCaseIndex = 100;        // whatever you want here
        status = 1;
        while (OK < status)
        {
            if (OK > (status = negative_parse_corruptCert(testCase, testCaseIndex, pTestLengthVectorPoints, pCert, certLen, &pTestCert, &testCertLen)))
                goto exit;

            negTest_status = parsecert_test_negative_parse_doTest(pTestCert, testCertLen);
            retVal += UNITTEST_TRUE(testCase, negTest_status);

            if (OK == negTest_status)
            {
                /* Negative test FAILED */
                printf("--------------------------------------------------------------------------\n");
                printf("FAILED Negative Test Case: %i.%i\n", testCase, testCaseIndex);
                printf("Certificate Used:\n");
                negative_parse_printCert(pTestCert, testCertLen, NULL);

// uncomment during debug sessions
//                negTest_status = parsecert_test_negative_parse_doTest(pTestCert, testCertLen);
            }
            else
            {
                /* Negative test PASSED */
                printf("--------------------------------------------------------------------------\n");
                printf("PASSED Negative Test Case: %i.%i status = %i\n", testCase, testCaseIndex, negTest_status);
            }

            testCaseIndex++;
            negTest_status = OK;
            FREE(pTestCert);
            pTestCert = NULL;
        }
    }
    printf("--------------------------------------------------------------------------\n");

exit:
//    retVal += UNITTEST_STATUS(testCase, status);
    FREE(pTestLengthVectorPoints);
    FREE(pTestCert);
    DIGICERT_freeReadFile(&pCert);

    return retVal;
}
#endif
