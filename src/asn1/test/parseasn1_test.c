/*
 *  parseasn1_test.c
 *
 *  unit test for parseasn1.c
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

#include "../parseasn1.c"

#include "../../../unit_tests/unittest.h"


int compare_asn1_parses( int hint, int level, const ASN1_ITEM* pParse1, const ASN1_ITEM* pParse2)
{
    int retVal = 0;
    const ASN1_ITEM* pChild1, *pChild2;

    retVal += UNITTEST_TRUE( hint, pParse1->tag == pParse2->tag);
    retVal += UNITTEST_TRUE( hint, pParse1->length == pParse2->length);
    retVal += UNITTEST_TRUE( hint, pParse1->dataOffset == pParse2->dataOffset);

    pChild1 = ASN1_FIRST_CHILD( pParse1);
    pChild2 = ASN1_FIRST_CHILD( pParse2);

    while (0 == retVal && pChild1 && pChild2)
    {
        retVal += compare_asn1_parses( hint, ++level, pChild1, pChild2); 

        pChild1 = ASN1_NEXT_SIBLING( pChild1);
        pChild2 = ASN1_NEXT_SIBLING( pChild2);
    }

    if ( 0 == retVal)
    {
        retVal += UNITTEST_TRUE( hint, 0 == pChild1);
        retVal += UNITTEST_TRUE( hint, 0 == pChild2);
    }
    return retVal;
}


/*------------------------------------------------------------------------*/

int resume_parseasn1( int hint, const sbyte* fileName)
{
    MSTATUS status;

    ubyte* pCert = 0;
    ubyte4 i, certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ParseState parseState;
    int retVal = 0;

    hint <<= 16;
    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach(&mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);
    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    retVal += UNITTEST_VALIDPTR(hint, ASN1_FIRST_CHILD(pRootItem));

    /* try to parse partial -- it should return only one of those errors:
        ERR_ASN_*/
    for (i = 0; i < certLen-1; ++i)
    {
        int localRet = 0;

        MF_attach(&mf, (sbyte4)i, pCert);
        CS_AttachMemFile(&cs, &mf);

        status = ASN1_InitParseState( &parseState);
        localRet += UNITTEST_STATUS(hint, status);
        if (status < OK) goto exit;
        
        status = ASN1_ParseASN1State( cs, &parseState, NULL, NULL);
        localRet += UNITTEST_TRUE( hint + i, (ERR_EOF == status));

        /* complete the parse now */
        MF_attach(&mf, certLen, pCert);
        status = ASN1_ParseASN1State( cs, &parseState, NULL, NULL);
        localRet += UNITTEST_STATUS(hint + i, status);

        localRet += UNITTEST_VALIDPTR(hint + i, ASN1_FIRST_CHILD(parseState.rootNode));

        if (0 == localRet && 0 == retVal)
        {           
            localRet += compare_asn1_parses(hint +i, 0, 
                ASN1_FIRST_CHILD(parseState.rootNode), 
                ASN1_FIRST_CHILD(pRootItem));
        }
        
        TREE_DeleteTreeItem( (TreeItem*) parseState.rootNode);
        parseState.rootNode = 0;

        retVal += localRet;
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


/*---------------------------------------------------------------------*/

int parseasn1_test_resume()
{
    int retVal = 0;

    retVal += resume_parseasn1( 1, "radiometer.der");
    retVal += resume_parseasn1( 2, "motorola_1.der");
    retVal += resume_parseasn1( 3, "sonus.der");
    retVal += resume_parseasn1( 4, "sonus2.der");
    retVal += resume_parseasn1( 5, "MS-EccRoot.der");
    retVal += resume_parseasn1( 6, "MS_ECDSACert256.der");
    retVal += resume_parseasn1( 7, "MS_ECDSACert384.der");
    retVal += resume_parseasn1( 8, "MS_ECDSACert521.der");
    retVal += resume_parseasn1( 9, "Cert-171-61.der");
    retVal += resume_parseasn1(10, "problem.dat");

    return retVal;
}



/*------------------------------------------------------------------------*/

int bit_by_bit_parseasn1( int hint, const sbyte* fileName)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 i, certLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ParseState parseState;
    int retVal = 0;

    hint <<= 16;
    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    MF_attach(&mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);
    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    retVal += UNITTEST_VALIDPTR(hint, ASN1_FIRST_CHILD(pRootItem));

    CS_AttachMemFile(&cs, &mf);
    MF_attach(&mf, (sbyte4)1, pCert);

    ASN1_InitParseState( &parseState);
    for (i = 2; i < certLen-1; ++i)
    {
        int localRet = 0;

        MF_attach(&mf, (sbyte4)i, pCert);
       
        status = ASN1_ParseASN1State( cs, &parseState, NULL, NULL);
        localRet += UNITTEST_INT( hint + i, status, ERR_EOF);

        retVal += localRet;
    }  

    TREE_DeleteTreeItem( (TreeItem*) parseState.rootNode);
    parseState.rootNode = 0;

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


/*---------------------------------------------------------------------*/

int parseasn1_test_bit_by_bit()
{
    int retVal = 0;

    retVal += bit_by_bit_parseasn1(10, "problem.dat");

    return retVal;
}


/*------------------------------------------------------------------------*/

int simple_parseasn1( int hint, const sbyte* fileName, MSTATUS expected)
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

    MF_attach(&mf, (sbyte4)certLen, pCert);
    CS_AttachMemFile(&cs, &mf);
    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_TRUE(hint, status == expected);
    if (status < OK) goto exit;

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


/*---------------------------------------------------------------------*/

int parseasn1_test_simple()
{
    int retVal = 0;

    retVal += simple_parseasn1( 1, "signature_eof_pb.der",      OK);
    retVal += simple_parseasn1( 1, "ecdhcert_badlength.der",    ERR_EOF);

    return retVal;
}


/*---------------------------------------------------------------------*/

int getdata_test(int hint, const char* asn1File, const char* dataFile)
{
    MSTATUS status;
    int i, retVal = 0;
    ubyte* data = 0;
    ubyte* asn1 = 0;
    ubyte* res = 0;
    ubyte4 retSize, gotSize, dataLen, asn1Len, offset;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ParseState parseState;
    sbyte4 cmpRes;

    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile( dataFile, &data, &dataLen), retVal, exit);
    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile( asn1File, &asn1, &asn1Len), retVal, exit);

    res = MALLOC( dataLen);
    retVal += UNITTEST_VALIDPTR(hint, res);
    if (retVal) goto exit;
       

    for (i = 0; i < asn1Len-1; ++i)
    {
        int localRet = 0;
        
        DIGI_MEMSET( res, 0, dataLen);

        /* partial parse */
        MF_attach(&mf, (sbyte4)i, asn1);
        CS_AttachMemFile(&cs, &mf);

        status = ASN1_InitParseState( &parseState);
        localRet += UNITTEST_STATUS(hint, status);
        if (status < OK) goto exit;
        
        status = ASN1_ParseASN1State( cs, &parseState, NULL, NULL);
        localRet += UNITTEST_TRUE( hint + i, (ERR_EOF == status));

        offset = 0;
        if (0 == localRet  && ASN1_FIRST_CHILD(parseState.rootNode))
        {
            /* first pass -- get the length */
            retSize = ASN1_GetData( &parseState, cs, i, 
                                    ASN1_FIRST_CHILD(parseState.rootNode), 
                                    &offset, 0, 0);
            retVal += UNITTEST_TRUE( hint, retSize <= dataLen);
            retVal += UNITTEST_TRUE( hint, offset <= i);

            /* second pass -- retrieve the data */
            offset = 0;
            gotSize = ASN1_GetData( &parseState, cs, i, 
                                    ASN1_FIRST_CHILD(parseState.rootNode), 
                                    &offset, asn1, res);
            retVal += UNITTEST_TRUE( hint, gotSize == retSize);

            if ( gotSize <= dataLen)
            {
                DIGI_MEMCMP( data, res, gotSize, &cmpRes);
                retVal += UNITTEST_TRUE(hint, 0 == cmpRes);
            }
        }
        else
        {
            gotSize = 0;
            retVal += localRet;
            localRet = 0;
        }

        /* complete the parse now */
        MF_attach(&mf, asn1Len, asn1);
        status = ASN1_ParseASN1State( cs, &parseState, NULL, NULL);
        localRet += UNITTEST_STATUS(hint, status);

        if (0 == localRet)
        {
            /* first pass -- get the length */
            ubyte4 oldOffset = offset;
            retSize = ASN1_GetData( &parseState, cs, asn1Len, 
                                    ASN1_FIRST_CHILD(parseState.rootNode), 
                                    &offset, 0, 0);
            retVal += UNITTEST_INT( hint, retSize + gotSize, dataLen);
            retVal += UNITTEST_TRUE( hint, offset <= asn1Len);

            /* second pass -- retrieve the data */
            offset = oldOffset;
            retSize = ASN1_GetData( &parseState, cs, asn1Len, 
                                    ASN1_FIRST_CHILD(parseState.rootNode), 
                                    &offset, asn1, res + gotSize);
            retVal += UNITTEST_INT( hint, retSize + gotSize, dataLen);

            if ( retSize + gotSize == dataLen)
            {
                DIGI_MEMCMP( data, res, dataLen, &cmpRes);
                retVal += UNITTEST_TRUE(hint, 0 == cmpRes);
            }
        }
        else
        {
            retVal += localRet;
            localRet = 0;
        }

        TREE_DeleteTreeItem( (TreeItem*) parseState.rootNode);
        parseState.rootNode = 0;
    }    

exit:

    if ( data) FREE(data);
    if ( asn1) FREE(asn1);
    if ( res) FREE(res);

    if ( parseState.rootNode)
    {
        TREE_DeleteTreeItem( (TreeItem*) parseState.rootNode);
    }

    return retVal;
}


/*---------------------------------------------------------------------*/

int parseasn1_test_getdata()
{
    int retVal = 0;

    retVal += getdata_test( 1, FILE_PATH("octetstring_constructed.der"),
                            FILE_PATH("octetstring_constructed.dat"));
    retVal += getdata_test( 1, FILE_PATH("octetstring_ber.der"),
                            FILE_PATH("octetstring_ber.dat"));
    
    return retVal;
}


/*---------------------------------------------------------------------*/

int parseasn1_test_getnth_child()
{
    int retVal = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ubyte* asn1 = 0;
    ubyte4 i, asn1Len;
    ASN1_ITEMPTR pStart, pOctetStr;
    MSTATUS status;
    ubyte4 dataOffset = 0;

    UNITTEST_STATUS_GOTO( 0, DIGICERT_readFile( FILE_PATH("octetstring_ber.der"), &asn1, &asn1Len), retVal, exit);

    MF_attach(&mf, (sbyte4)asn1Len, asn1);
    CS_AttachMemFile(&cs, &mf);

    UNITTEST_STATUS_GOTO(0, ASN1_Parse(cs, &pRootItem), retVal, exit);
    retVal += UNITTEST_TRUE(0, 0 != pRootItem);
    if (retVal) goto exit;

    pStart = ASN1_FIRST_CHILD( pRootItem);
    retVal += UNITTEST_TRUE(0, 0 != pStart);
    if (retVal) goto exit;

    pStart = ASN1_FIRST_CHILD( pStart);
    retVal += UNITTEST_TRUE(0, 0 != pStart);
    if (retVal) goto exit;

    /* index 0 -> invalid */
    status = ASN1_GetNthChild( pStart, 0, &pOctetStr);
    retVal += UNITTEST_TRUE(0, ERR_INDEX_OOB == status);
    
    /* index 1 - 11 ->  valid */
    status = ASN1_GetNthChild( pStart, 1, &pOctetStr);
    retVal += UNITTEST_STATUS(1, status);
    retVal += UNITTEST_STATUS(1, ASN1_VerifyType( pOctetStr, OCTETSTRING));
    retVal += UNITTEST_TRUE(1, 2078 == pOctetStr->length); 
    retVal += UNITTEST_TRUE(1, pOctetStr->dataOffset > dataOffset);
    dataOffset = pOctetStr->dataOffset;

    for (i = 2; i <= 10; ++i)
    {
        status = ASN1_GetNthChild( pStart, i, &pOctetStr);
        retVal += UNITTEST_STATUS(i, status);
        retVal += UNITTEST_STATUS(i, ASN1_VerifyType( pOctetStr, OCTETSTRING));
        retVal += UNITTEST_TRUE(i, 1 == pOctetStr->length); 
        retVal += UNITTEST_TRUE(i, pOctetStr->dataOffset > dataOffset);
        dataOffset = pOctetStr->dataOffset;
    }

    status = ASN1_GetNthChild( pStart, 11, &pOctetStr);
    retVal += UNITTEST_STATUS(11, status);
    retVal += UNITTEST_STATUS(11, ASN1_VerifyType( pOctetStr, EOC));

    /* index 12 -> invalid */
    status = ASN1_GetNthChild( pStart, 12, &pOctetStr);
    retVal += UNITTEST_TRUE(12, ERR_INDEX_OOB == status);
   

exit:

    if ( asn1)
    {
        FREE( asn1);
    }
    if ( pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return retVal;
}
