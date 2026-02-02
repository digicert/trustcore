/*
 * derencoder_test.c
 *
 * unit test for derencoder.c
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

#include "../derencoder.c"

#include "../../../unit_tests/unittest.h"

#include "../../common/utils.h"
#include "../../common/memfile.h"
#include "../../common/absstream.h"
#include "../../common/mrtos.h"
#include "../parseasn1.h"
#include "../oiddefs.h"

typedef struct DER_AddTime_Test_Data
{
    TimeDate td;
    const ubyte* expected;
    ubyte asn1Type;
} DER_AddTime_Test_Data;


DER_AddTime_Test_Data mTimeTestData[] = {
    {   { 2010 - 1970, 07, 29, 15, 20, 00 },
        "100729152000Z", UTCTIME },
    {   { 1970 - 1970, 11, 12, 00, 00, 00 },
        "701112000000Z", UTCTIME },  
    {   { 2049 - 1970, 12, 31, 00, 01, 02 },
        "491231000102Z", UTCTIME },  
    {   { 2050 - 1970, 11, 12, 00, 00, 00 },
        "20501112000000Z", GENERALIZEDTIME },  
    {   { 2200 - 1970, 12, 31, 00, 01, 02 },
        "22001231000102Z", GENERALIZEDTIME },  
};

int derencoderTimeTest( int hint, const DER_AddTime_Test_Data* pTestData)
{
    int retVal = 0;
    DER_ITEMPTR pTimeItem = 0;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pTime, pASN1 = 0;
    sbyte4 resCmp;

    UNITTEST_STATUS_GOTO( hint, DER_AddTime(NULL, &pTestData->td, &pTimeItem),
                        retVal, exit);

    UNITTEST_STATUS_GOTO( hint, DER_Serialize( pTimeItem, 
                                                &buffer, 
                                                &bufferLen),
                          retVal, exit);
    
    /* verify it can be parsed */
    MF_attach( &mf, bufferLen, buffer);
    CS_AttachMemFile( &cs, &mf);

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse( cs, &pASN1), retVal, exit);
    
    pTime = ASN1_FIRST_CHILD( pASN1);
    UNITTEST_GOTO( UNITTEST_VALIDPTR( hint, pTime), retVal, exit);
    
    retVal += UNITTEST_STATUS( hint, ASN1_VerifyType( pTime, pTestData->asn1Type));
    retVal += UNITTEST_STATUS( hint, pTime->length == DIGI_STRLEN(pTestData->expected));

    DIGI_MEMCMP( buffer + pTime->dataOffset, pTestData->expected, pTime->length,
                &resCmp);

    retVal += UNITTEST_INT( hint, resCmp, 0);


exit:

    TREE_DeleteTreeItem( (TreeItem*) pTimeItem);
    TREE_DeleteTreeItem( (TreeItem*) pASN1);
    FREE(buffer);

    return retVal;
}

/*----------------------------------------------------------------------*/

int derencoder_test_time()
{
    int i, retVal = 0;

    for (i = 0; i < COUNTOF(mTimeTestData); ++i)
    {
        retVal += derencoderTimeTest( i, mTimeTestData + i);
    }

    return retVal;
}

/*----------------------------------------------------------------------*/

static int AddCertToSequence(int hint, const char* fileName, 
                                 DER_ITEMPTR pRoot)
{
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    MSTATUS status;
    int retVal = 0;

    if (OK > ( status = UTILS_readFile( fileName, &buffer, &bufferLen)))
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    if (OK > ( status = DER_AddDERBufferOwn( pRoot, bufferLen, &buffer, NULL)))
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    retVal += UNITTEST_TRUE( hint, buffer == 0);
        
exit:

    if ( buffer)
    {
        FREE(buffer);
    }

    return retVal;
}


/*----------------------------------------------------------------------*/

static int VerifyCertInSequence(int hint, const char* fileName, 
                                 ASN1_ITEMPTR pRoot, CStream cs)
{
    const ubyte* asn1Buff = 0;
    ubyte* buffer = 0;
    ubyte4 bufferLen;
    sbyte4 resCmp;
    MSTATUS status;
    int retVal = 0;
    ASN1_ITEMPTR pChild;

    if (OK > ( status = UTILS_readFile( fileName, &buffer, &bufferLen)))
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    if (OK > ( status = ASN1_GetNthChild( pRoot, hint+1, &pChild)))
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    retVal += UNITTEST_INT( hint, pChild->length + pChild->headerSize, bufferLen);
    if (retVal) goto exit;

    asn1Buff = CS_memaccess( cs, pChild->dataOffset - pChild->headerSize, 
                                pChild->length + pChild->headerSize);
    retVal += UNITTEST_TRUE( hint, asn1Buff !=0 );
    if (retVal) goto exit;

    DIGI_MEMCMP( asn1Buff, buffer, bufferLen, &resCmp);
    retVal += UNITTEST_TRUE( hint, resCmp ==0 );
    if (retVal) goto exit;
        
exit:

    if ( buffer)
    {
        FREE(buffer);
    }

    if (asn1Buff)
    {
        CS_stopaccess( cs, asn1Buff);
    }

    return retVal;
}


/*----------------------------------------------------------------------*/

int derencoder_test_opaque_test1()
{
    MSTATUS status;
    int i, retVal = 0;
    DER_ITEMPTR pRoot = 0;
    ASN1_ITEMPTR pASN1 = 0;
    MemFile mf;
    CStream cs;
    const char* fileNames[] = { "RSACert4.der",
                                "RSACert5.der",
                                "RSACert11.der",
                                "RSACert12.der",
                                "RSACert13.der",
                                "RSACert14.der"};
    ubyte* buffer = 0;
    ubyte4 bufferLen;
   
    /* add all buffer to a sequence */
    status = DER_AddSequence( NULL, &pRoot);
    retVal += UNITTEST_STATUS(0, status);
    if ( retVal) goto exit;
    
    for (i = 0; i < 6; ++i)
    {
        retVal += AddCertToSequence(i, fileNames[i], pRoot);
    }
     
    if ( retVal) goto exit;

    /* serialize */
    status = DER_Serialize( pRoot, &buffer, &bufferLen);

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    pRoot = 0;

    /* verify it can be parsed */
    MF_attach( &mf, bufferLen, buffer);
    CS_AttachMemFile( &cs, &mf);

    status = ASN1_Parse( cs, &pASN1);  
    retVal += UNITTEST_STATUS(0, status);
    if ( retVal) goto exit;
    
    /* make sure they are all certificates */
    for (i = 0; i < 6; ++i)
    {
        retVal += VerifyCertInSequence(i, fileNames[i], 
                ASN1_FIRST_CHILD(pASN1), cs);
    }

exit:

    FREE(buffer);
    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    TREE_DeleteTreeItem( (TreeItem*) pASN1);
    return retVal;

}


/*----------------------------------------------------------------------*/

int derencoder_test_GetIntegerEncodingOffset()
{
    int retVal = 0;
    ubyte leadZero[5];
    ubyte4 i, offset, numTests;
    /* this array is a list of value, offset */
    ubyte4 results[] = { 0, 4, 1, 4, 2, 4, 3, 4, 
                         0x7F, 4, 0x80, 3, 0x81, 3, 
                         0x17F, 3, 0x180, 3, 0x7FFF, 3,
                         0x8000, 2, 0x7FFFFF, 2, 0x800000, 1,
                         0x7FFFFFFF, 1, 0x80000000, 0, 0xFFFFFFFF, 0 };

    numTests = COUNTOF( results)/2;

    for (i = 0; i < numTests; ++i)
    {
        ubyte4 value = results[i*2];

        leadZero[0] = 0;
        leadZero[1] = (ubyte)((value) >> 24);     
        leadZero[2] = (ubyte)((value) >> 16);  
        leadZero[3] = (ubyte)((value)>>  8);   
        leadZero[4] = (ubyte)(value);

        retVal += UNITTEST_STATUS( value, 
                        DER_GetIntegerEncodingOffset( 5, leadZero, &offset));
        retVal += UNITTEST_INT(value, offset, results[i*2+1]);
                            
    }

    return retVal;
}


/*----------------------------------------------------------------------*/

int derencoder_test_BER1()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2;
    ubyte* osData = 0;
    ubyte4 osDataLen;
    ubyte* setData = 0;
    ubyte4 setDataLen;
    ubyte* signedData = 0;
    ubyte4 signedDataLen;
    ubyte* asn1Data1 = 0;
    ubyte4 asn1DataLen1;
    ubyte* asn1Data2 = 0;
    ubyte4 asn1DataLen2;
    sbyte4 resCmp, i;
    ubyte zero = 0;


    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1)); 
    
    /* try to serialize here */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data1, &asn1DataLen1));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data1 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen1, 36);
    /* verify MD5 + NULL is at the end of the returned data */
    retVal += UNITTEST_INT(0, asn1Data1[asn1DataLen1-1], 0);
    DIGI_MEMCMP( asn1Data1 + asn1DataLen1 - 2 - (md5_OID[0]+1), md5_OID, md5_OID[0]+1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* more ASN.1 */
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent2)); 
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pParent2, pkcs7_data_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pParent2, 0, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, OCTETSTRING, &pParent2));
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("octetstring.dat"),
                                                    &osData, &osDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddItem( pParent2, OCTETSTRING, osDataLen, osData, 
                                                NULL));

    /* try to serialize here */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, 2135);
    /* verify that the last added data is at the end */
    DIGI_MEMCMP( asn1Data2 + asn1DataLen2 - osDataLen, osData, osDataLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* verify that the beginning of the previous serialization matches
    the beginning of the current serialization */
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data1); asn1Data1 = asn1Data2; asn1DataLen1 = asn1DataLen2; asn1Data2 = 0;
    
    /* reserialize -- we should get the same results */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data2); asn1Data2 = 0;

    /* add the whole ASN.1 for signer info */
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("signedDataSet.der"),
                                                   &setData, &setDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddDERBuffer( pParent, setDataLen, setData, NULL));

    /* try to serialize here  -- it should be the same as before -- because the previous child
    has not been terminated by EOC yet */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data2); asn1Data2 = 0;
 
    /* add more OCTETSTRING */
    for (i = 0; i < 9; ++i)
    {
        retVal += UNITTEST_STATUS(0, DER_AddItem( pParent2, OCTETSTRING, 1, &zero, NULL));
    }

    /* try to serialize here  -- it should be the same as before + the 9 NULL octetstring
    each of which is 3 bytes long */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1 + 9 * 3);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    FREE(asn1Data1); asn1Data1 = asn1Data2; asn1DataLen1 = asn1DataLen2; asn1Data2 = 0;
            
    /* finalize now and serialize -- should be valid ASN.1 */
    retVal += UNITTEST_STATUS(0, DER_FinalizeBERItems( pRoot));

    retVal += UNITTEST_STATUS(0, DER_GetLength(pRoot, &asn1DataLen2));
    asn1Data2 = MALLOC( asn1DataLen2 + 10);
    if ( !asn1Data2)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }
    DIGI_MEMSET(asn1Data2 + asn1DataLen2, 0xAF, 10); 

    retVal += UNITTEST_STATUS( 0, DER_SerializeInto( pRoot, asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    /* should begin the same as before */
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    
    /* should not overwrite end chars */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE( i, 0xAF == asn1Data2[asn1DataLen2+i]);
    }
    /* should be identical to the signedData.der */
    retVal += UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("signedData.der"),
                                                &signedData, &signedDataLen));
    retVal += UNITTEST_INT(0, asn1DataLen2, signedDataLen);
    DIGI_MEMCMP( signedData, asn1Data2, asn1DataLen2, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

exit:
    /* free data */
    FREE(signedData); signedData = 0;
    FREE(setData); setData = 0;
    FREE(osData); osData = 0;
    FREE(asn1Data1); asn1Data1 = 0;
    FREE(asn1Data2); asn1Data2 = 0;

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    return retVal;
}


/*----------------------------------------------------------------------*/

int derencoder_test_BER2()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2;
    ubyte* asn1Data1 = 0;
    ubyte4 asn1DataLen1;

    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1)); 

    retVal += UNITTEST_STATUS( 0, DER_FinalizeBERItems(pRoot));
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data1, &asn1DataLen1));

    retVal += UNITTEST_STATUS( 0, DIGICERT_writeFile("simpleBER.der", asn1Data1, asn1DataLen1));

    FREE(asn1Data1);
    TREE_DeleteTreeItem( (TreeItem*) pRoot);

    return retVal;
}


/*----------------------------------------------------------------------*/

int derencoder_test_BER3()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2;
    ubyte* osData = 0;
    ubyte4 osDataLen;
    ubyte* setData = 0;
    ubyte4 setDataLen;
    ubyte* signedData = 0;
    ubyte4 signedDataLen;
    ubyte* asn1Data = 0;
    ubyte4 asn1DataLen;
    sbyte4 resCmp, i;
    ubyte zero = 0;
    sbyte4 offset = 0;

    retVal += UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("signedData.der"),
                                                &signedData, &signedDataLen));

    asn1DataLen = signedDataLen;
    asn1Data = MALLOC( signedDataLen + 10);
    if (!asn1Data)
    {
        UNITTEST_STATUS_GOTO(0, ERR_MEM_ALLOC_FAIL, retVal, exit);
    }
    DIGI_MEMSET( asn1Data, 0xAC, signedDataLen + 10);

    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1)); 
    
    /* try to serialize here */
    offset = 0;
    asn1DataLen = signedDataLen;
    retVal += UNITTEST_STATUS( 0, DER_SerializeIntoOffset( pRoot, offset, asn1Data, &asn1DataLen));
    offset += asn1DataLen;
    asn1DataLen = signedDataLen - offset;

    /* test results */
    retVal += UNITTEST_INT(0, offset, 36);
    /* verify MD5 + NULL is at the end of the returned data */
    retVal += UNITTEST_INT(0, asn1Data[offset-1], 0);
    DIGI_MEMCMP( asn1Data + offset - 2 - (md5_OID[0]+1), md5_OID, md5_OID[0]+1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* more ASN.1 */
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent2)); 
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pParent2, pkcs7_data_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pParent2, 0, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, OCTETSTRING, &pParent2));
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("octetstring.dat"),
                                                    &osData, &osDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddItem( pParent2, OCTETSTRING, osDataLen, osData, 
                                                NULL));

    /* try to serialize here */
    retVal += UNITTEST_STATUS( 0, DER_SerializeIntoOffset( pRoot, offset, asn1Data + offset, &asn1DataLen));
    offset += asn1DataLen;
    asn1DataLen = signedDataLen - offset;
    /* test results */
    retVal += UNITTEST_INT(0, offset, 2135);
    /* verify that the last added data is at the end */
    DIGI_MEMCMP( asn1Data + offset - osDataLen, osData, osDataLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* currently written should match signedData */
    DIGI_MEMCMP( signedData, asn1Data, offset, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);


    /* add the whole ASN.1 for signer info */
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("signedDataSet.der"),
                                                   &setData, &setDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddDERBuffer( pParent, setDataLen, setData, NULL));

    /* try to serialize here  -- it should do nothing extra */
    retVal += UNITTEST_STATUS( 0, DER_SerializeIntoOffset( pRoot, offset, asn1Data + offset, &asn1DataLen));
    /* test results */
    retVal += UNITTEST_INT(0, asn1DataLen, 0);

    offset += asn1DataLen;
    asn1DataLen = signedDataLen - offset;

    /* currently written should match signedData */
    DIGI_MEMCMP( signedData, asn1Data, offset, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* add more OCTETSTRING */
    for (i = 0; i < 9; ++i)
    {
        retVal += UNITTEST_STATUS(0, DER_AddItem( pParent2, OCTETSTRING, 1, &zero, NULL));
    }

    /* try to serialize here  -- it should be the same as before + the 9 NULL octetstring
    each of which is 3 bytes long */
    retVal += UNITTEST_STATUS( 0, DER_SerializeIntoOffset( pRoot, offset, asn1Data + offset, &asn1DataLen));
    /* test results */
    retVal += UNITTEST_INT(0, asn1DataLen, 9 * 3);
    offset += asn1DataLen;
    asn1DataLen = signedDataLen - offset;
    /* currently written should match signedData */
    DIGI_MEMCMP( signedData, asn1Data, offset, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    
    /* finalize now and serialize -- should be valid ASN.1 */
    retVal += UNITTEST_STATUS(0, DER_FinalizeBERItems( pRoot));
    retVal += UNITTEST_STATUS(0, DER_SerializeIntoOffset( pRoot, offset, asn1Data + offset, &asn1DataLen));
    offset += asn1DataLen;
    asn1DataLen = signedDataLen - offset;

    /* should not overwrite end chars */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE( i, 0xAC == asn1Data[signedDataLen+i]);
    }
    retVal += UNITTEST_INT(0, offset, signedDataLen);
    DIGI_MEMCMP( signedData, asn1Data, offset, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

exit:
    /* free data */
    FREE(signedData); signedData = 0;
    FREE(setData); setData = 0;
    FREE(osData); osData = 0;
    FREE(asn1Data); asn1Data = 0;

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    return retVal;
}

/*----------------------------------------------------------------------*/

int derencoder_test_AddIntegerCopyData()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2, pParent3;
    ubyte* osData = 0;
    ubyte4 osDataLen;
    ubyte* setData = 0;
    ubyte4 setDataLen;
    ubyte* signedData = 0;
    ubyte4 signedDataLen;
    ubyte* asn1Data1 = 0;
    ubyte4 asn1DataLen1;
    ubyte* asn1Data2 = 0;
    ubyte4 asn1DataLen2;
    sbyte4 resCmp, i;
    ubyte zero = 0;
    ubyte integerData[] = { 0, 167, 62, 167, 182, 88, 190, 156, 36, 75, 199 };


    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent3));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerCopyData( pParent3, 3, integerData, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerCopyData( pParent3, 10, integerData, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1));

    /* try to serialize here */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data1, &asn1DataLen1));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data1 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen1, 55);
    /* verify MD5 + NULL is at the end of the returned data */
    retVal += UNITTEST_INT(0, asn1Data1[asn1DataLen1-1], 0);
    DIGI_MEMCMP( asn1Data1 + asn1DataLen1 - 2 - (md5_OID[0]+1), md5_OID, md5_OID[0]+1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* more ASN.1 */
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pParent2, pkcs7_data_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pParent2, 0, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, OCTETSTRING, &pParent2));
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("octetstring.dat"),
                                                    &osData, &osDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddItem( pParent2, OCTETSTRING, osDataLen, osData,
                                                NULL));

    /* try to serialize here */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, 2154);
    /* verify that the last added data is at the end */
    DIGI_MEMCMP( asn1Data2 + asn1DataLen2 - osDataLen, osData, osDataLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* verify that the beginning of the previous serialization matches
    the beginning of the current serialization */
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data1); asn1Data1 = asn1Data2; asn1DataLen1 = asn1DataLen2; asn1Data2 = 0;

    /* reserialize -- we should get the same results */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data2); asn1Data2 = 0;

    /* add the whole ASN.1 for signer info */
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("signedDataSet.der"),
                                                   &setData, &setDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddDERBuffer( pParent, setDataLen, setData, NULL));

    /* try to serialize here  -- it should be the same as before -- because the previous child
    has not been terminated by EOC yet */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    FREE(asn1Data2); asn1Data2 = 0;

    /* add more OCTETSTRING */
    for (i = 0; i < 9; ++i)
    {
        retVal += UNITTEST_STATUS(0, DER_AddItem( pParent2, OCTETSTRING, 1, &zero, NULL));
    }

    /* try to serialize here  -- it should be the same as before + the 9 NULL octetstring
    each of which is 3 bytes long */
    retVal += UNITTEST_STATUS( 0, DER_Serialize( pRoot, &asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1 + 9 * 3);
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    FREE(asn1Data1); asn1Data1 = asn1Data2; asn1DataLen1 = asn1DataLen2; asn1Data2 = 0;

    /* finalize now and serialize -- should be valid ASN.1 */
    retVal += UNITTEST_STATUS(0, DER_FinalizeBERItems( pRoot));

    retVal += UNITTEST_STATUS(0, DER_GetLength(pRoot, &asn1DataLen2));
    asn1Data2 = MALLOC( asn1DataLen2 + 10);
    if ( !asn1Data2)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }
    DIGI_MEMSET(asn1Data2 + asn1DataLen2, 0xAF, 10);

    retVal += UNITTEST_STATUS( 0, DER_SerializeInto( pRoot, asn1Data2, &asn1DataLen2));
    /* test results */
    retVal += UNITTEST_TRUE(0, asn1Data2 != 0);
    /* should begin the same as before */
    DIGI_MEMCMP( asn1Data1, asn1Data2, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* should not overwrite end chars */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE( i, 0xAF == asn1Data2[asn1DataLen2+i]);
    }

exit:
    /* free data */
    FREE(signedData); signedData = 0;
    FREE(setData); setData = 0;
    FREE(osData); osData = 0;
    FREE(asn1Data1); asn1Data1 = 0;
    FREE(asn1Data2); asn1Data2 = 0;

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    return retVal;
}

/*----------------------------------------------------------------------*/

int BERCollectData( DER_ITEMPTR pRoot, sbyte4 offset, ubyte* data,
                   ubyte4* dataLen)
{
    int retVal = 0;
    ubyte* asn1Data = 0;
    ubyte4 asn1DataLen;

    retVal += UNITTEST_STATUS( offset, DER_SerializeOffset( pRoot, offset, &asn1Data,
                                                            &asn1DataLen));

    DIGI_MEMCPY( data + offset, asn1Data, asn1DataLen);
    *dataLen += asn1DataLen;

    FREE(asn1Data);

    return retVal;
}


/*----------------------------------------------------------------------*/

int derencoder_test_BER4()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2;
    ubyte* osData = 0;
    ubyte4 osDataLen;
    ubyte* setData = 0;
    ubyte4 setDataLen;
    ubyte* signedData = 0;
    ubyte4 signedDataLen;
    ubyte* asn1Data = 0;
    ubyte4 asn1DataLen;
    sbyte4 resCmp, i;
    ubyte zero = 0;
    sbyte4 offset = 0, newOffset = 0;

    retVal += UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("signedData.der"),
                                                &signedData, &signedDataLen));

    asn1DataLen = signedDataLen;
    asn1Data = MALLOC( signedDataLen + 10);
    if (!asn1Data)
    {
        UNITTEST_STATUS_GOTO(0, ERR_MEM_ALLOC_FAIL, retVal, exit);
    }
    DIGI_MEMSET( asn1Data, 0xAC, signedDataLen + 10);

    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);
    
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    /* do not call BERCollectData( pRoot, offset, asn1Data, &offset) 
    because the Set is not complete */
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1)); 
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent2)); 
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddOID( pParent2, pkcs7_data_OID, NULL));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pParent2, 0, &pParent2));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

#if 0
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, OCTETSTRING, &pParent2));
    /* do not collect here either or */
#else
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, (CONSTRUCTED| OCTETSTRING), &pParent2));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);
#endif 

    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("octetstring.dat"),
                                                    &osData, &osDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddItem( pParent2, OCTETSTRING, osDataLen, osData, 
                                                NULL));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);


    /* add the whole ASN.1 for signer info */
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("signedDataSet.der"),
                                                   &setData, &setDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddDERBuffer( pParent, setDataLen, setData, NULL));
    /* collect the data but there should not be anything new since the pParent2 is still not done */
    newOffset = offset;
    retVal += BERCollectData( pRoot, offset, asn1Data, &newOffset);
    retVal += UNITTEST_TRUE( 0, offset == newOffset);

    /* add more OCTETSTRING */
    for (i = 0; i < 9; ++i)
    {
        retVal += UNITTEST_STATUS(0, DER_AddItem( pParent2, OCTETSTRING, 1, &zero, NULL));
        retVal += BERCollectData( pRoot, offset, asn1Data, &offset);
    }

    /* finalize now and serialize -- should be valid ASN.1 */
    retVal += UNITTEST_STATUS(0, DER_FinalizeBERItems( pRoot));
    retVal += BERCollectData( pRoot, offset, asn1Data, &offset);

    /* should not overwrite end chars */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE( i, 0xAC == asn1Data[signedDataLen+i]);
    }

    retVal += UNITTEST_INT(0, offset, signedDataLen);
    DIGI_MEMCMP( signedData, asn1Data, offset, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    DIGICERT_writeFile("BER4.dat", asn1Data, offset);

exit:
    /* free data */
    FREE(signedData); signedData = 0;
    FREE(setData); setData = 0;
    FREE(osData); osData = 0;
    FREE(asn1Data); asn1Data = 0;

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    return retVal;
}


/*----------------------------------------------------------------------*/

/* IOT-79 and IOT-155: make sure there are no buffer overflows if
 the BER sequence is not terminated */

int derencoder_test_BER5()
{
    int retVal = 0;
    DER_ITEMPTR pRoot, pParent, pParent2;
    ubyte* osData = 0;
    ubyte4 osDataLen;
    ubyte* setData = 0;
    ubyte4 setDataLen;
    ubyte* signedData = 0;
    ubyte4 signedDataLen;
    ubyte* asn1Data1 = 0;
    ubyte4 asn1DataLen1;
    ubyte4 asn1DataLen2;
    sbyte4 resCmp, i;
    ubyte zero = 0;
    MSTATUS status;

    /* basically we reconstruct something that looks like signedData.der */

    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( NULL, &pRoot));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pRoot, pkcs7_signedData_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pRoot, 0, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent));
    retVal += UNITTEST_STATUS( 0, DER_AddIntegerEx( pParent, 1, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddSet( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_StoreAlgoOID( pParent2, md5_OID, 1));

    /* get the length */
    status = DER_GetLength(pRoot, &asn1DataLen1);
    retVal += UNITTEST_TRUE( 0, status == ERR_DER_BER_NOT_TERMINATED);

    retVal += UNITTEST_INT(0, asn1DataLen1, 36);

    /* allocate buffer manually with ten extra bytes */
    asn1Data1 = (ubyte*) MALLOC(asn1DataLen1+10);
    if ( !asn1Data1)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }

    /* last 20 bytes set to 0xCA to detect overflow */
    DIGI_MEMSET(asn1Data1 + asn1DataLen1 - 10, 0xCA, 20);

    asn1DataLen2 = asn1DataLen1 - 10;
    /* try to serialize here with a truncated length */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    /* verify there's an error then */
    retVal += UNITTEST_TRUE(0, ERR_BUFFER_OVERFLOW == status);
    /* verify that there was no overwriting */
    for (i = 0; i < 20; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 - 10 +i] == 0xCA);
    }
    /* verify the proper length was returned */
    retVal += UNITTEST_INT(0, asn1DataLen1, asn1DataLen2);

    /* try to serialize here with the proper length this time */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    retVal += UNITTEST_STATUS(0, status);
    /* test results */
    /* verify MD5 + NULL is at the end of the returned data */
    retVal += UNITTEST_INT(0, asn1Data1[asn1DataLen1-1], 0);
    DIGI_MEMCMP( asn1Data1 + asn1DataLen1 - 2 - (md5_OID[0]+1), md5_OID, md5_OID[0]+1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    /* verify that there was no overwriting */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 +i] == 0xCA);
    }

    FREE( asn1Data1);
    asn1Data1 = 0;


    /* more ASN.1 */
    retVal += UNITTEST_STATUS( 0, DER_AddBERSequence( pParent, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddOID( pParent2, pkcs7_data_OID, NULL));
    retVal += UNITTEST_STATUS( 0, DER_AddBERTag( pParent2, 0, &pParent2));
    retVal += UNITTEST_STATUS( 0, DER_AddBERItem( pParent2, OCTETSTRING, &pParent2));
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("octetstring.dat"),
                                                  &osData, &osDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddItem( pParent2, OCTETSTRING, osDataLen, osData,
                                              NULL));

    /* same test as before to verify there's no overflow */
    /* get the length */
    status = DER_GetLength(pRoot, &asn1DataLen1);
    retVal += UNITTEST_TRUE( 0, status == ERR_DER_BER_NOT_TERMINATED);

    /* allocate buffer manually with ten extra bytes */
    asn1Data1 = (ubyte*) MALLOC(asn1DataLen1+10);
    if ( !asn1Data1)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }

    /* last 20 bytes set to 0xCA to detect overflow */
    DIGI_MEMSET(asn1Data1 + asn1DataLen1 - 10, 0xCA, 20);

    asn1DataLen2 = asn1DataLen1 - 10;
    /* try to serialize here with a truncated length */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    /* verify there's an error then */
    retVal += UNITTEST_TRUE(0, ERR_BUFFER_OVERFLOW == status);
    /* verify that there was no overwriting */
    for (i = 0; i < 20; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 - 10 +i] == 0xCA);
    }
    /* verify the proper length was returned */
    retVal += UNITTEST_INT(0, asn1DataLen1, asn1DataLen2);

    /* try to serialize here with the proper length this time */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    retVal += UNITTEST_STATUS(0, status);
    /* verify that there was no overwriting */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 +i] == 0xCA);
    }

    FREE( asn1Data1);
    asn1Data1 = 0;


    /* add the whole ASN.1 for signer info */
    retVal += UNITTEST_STATUS( 0, DIGICERT_readFile( FILE_PATH("signedDataSet.der"),
                                                  &setData, &setDataLen));
    retVal += UNITTEST_STATUS( 0, DER_AddDERBuffer( pParent, setDataLen, setData, NULL));

    /* try to serialize here  -- it should be the same as before -- because the previous child
     has not been terminated by EOC yet */
    status = DER_GetLength(pRoot, &asn1DataLen2);
    retVal += UNITTEST_TRUE( 0, status == ERR_DER_BER_NOT_TERMINATED);
    retVal += UNITTEST_INT(0, asn1DataLen2, asn1DataLen1);

    /* add more OCTETSTRING */
    for (i = 0; i < 9; ++i)
    {
        retVal += UNITTEST_STATUS(0, DER_AddItem( pParent2, OCTETSTRING, 1, &zero, NULL));
    }

    /* length should be the same as before + the 9 NULL octetstring
     each of which is 3 bytes long */
    status = DER_GetLength(pRoot, &asn1DataLen1);
    retVal += UNITTEST_TRUE( 0, status == ERR_DER_BER_NOT_TERMINATED);
    retVal += UNITTEST_INT(0, asn1DataLen1, asn1DataLen2 + 9 * 3);

    /* allocate buffer manually with ten extra bytes */
    asn1Data1 = (ubyte*) MALLOC(asn1DataLen1+10);
    if ( !asn1Data1)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }

    /* last 20 bytes set to 0xCA to detect overflow */
    DIGI_MEMSET(asn1Data1 + asn1DataLen1 - 10, 0xCA, 20);

    asn1DataLen2 = asn1DataLen1 - 10;
    /* try to serialize here with a truncated length */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    /* verify there's an error then */
    retVal += UNITTEST_TRUE(0, ERR_BUFFER_OVERFLOW == status);
    /* verify that there was no overwriting */
    for (i = 0; i < 20; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 - 10 +i] == 0xCA);
    }
    /* verify the proper length was returned */
    retVal += UNITTEST_INT(0, asn1DataLen1, asn1DataLen2);

    /* try to serialize here with the proper length this time */
    status = DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen2);
    retVal += UNITTEST_STATUS(0, status);
    /* verify that there was no overwriting */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE(i, asn1Data1[asn1DataLen1 +i] == 0xCA);
    }

    FREE( asn1Data1);
    asn1Data1 = 0;


    /* finalize now and serialize -- should be valid ASN.1 */
    retVal += UNITTEST_STATUS(0, DER_FinalizeBERItems( pRoot));
    retVal += UNITTEST_STATUS(0, DER_GetLength(pRoot, &asn1DataLen1));
    asn1Data1 = MALLOC( asn1DataLen1 + 10);
    if ( !asn1Data1)
    {
        retVal += UNITTEST_STATUS(0, ERR_MEM_ALLOC_FAIL);
        goto exit;
    }
    DIGI_MEMSET(asn1Data1 + asn1DataLen1, 0xAC, 10);

    retVal += UNITTEST_STATUS( 0, DER_SerializeInto( pRoot, asn1Data1, &asn1DataLen1));
    /* should not overwrite end chars */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_TRUE( i, 0xAC == asn1Data1[asn1DataLen1+i]);
    }
    /* should be identical to the signedData.der */
    retVal += UNITTEST_STATUS(0, DIGICERT_readFile( FILE_PATH("signedData.der"),
                                                 &signedData, &signedDataLen));
    retVal += UNITTEST_INT(0, asn1DataLen1, signedDataLen);
    DIGI_MEMCMP( signedData, asn1Data1, asn1DataLen1, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

exit:
    /* free data */
    FREE(signedData); signedData = 0;
    FREE(setData); setData = 0;
    FREE(osData); osData = 0;
    FREE(asn1Data1); asn1Data1 = 0;

    TREE_DeleteTreeItem( (TreeItem*) pRoot);
    return retVal;
}



