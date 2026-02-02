/**
 * @file  est_cert_utils.c
 * @brief EST certificate utility functions.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#if !defined(__RTOS_FREERTOS__) && !defined(__IAR_SYSTEMS_ICC__)
#if defined _MSC_VER
#include <direct.h>
#endif /* _MSC_VER */
#endif /* ! __RTOS_FREERTOS__ && ! __IAR_SYSTEMS_ICC__ */

#include "../est/est_cert_utils.h"
#include "../common/base64.h"
#include "../common/mfmgmt.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../asn1/oidutils.h"
#include "../asn1/derencoder.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../est/est_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DIRECTORY_NAME                         (256)
#define MAX_ASN1_BMPSTRING                         (2*MAX_ASN1_STRING)
#define MAX_ASN1_LINES                             (10)
#define PAIR_NAME                                  (0)
#define PAIR_VALUE                                 (1)

#define ASN1_OID_STRING                            "oid"
#define ASN1_TLVS_STRING                           "tlvs"
#define ASN1_TLV_STRING	                           "tlv"
#define ASN1_SEQUENCE_STRING                       "SEQUENCE"
#define ASN1_INTEGER_STRING                        "INTEGER"
#define ASN1_IA5STRING_STRING                      "IA5STRING"
#define ASN1_UTF8STRING_STRING                     "UTF8STRING"
#define ASN1_BMPSTRING_STRING                      "BMPSTRING"
#define ASN1_BITSTRING_STRING                      "BITSTRING"

#define VERBOSE_DEBUG_CREATE_EXTENSION             0
#define VERBOSE_DEBUG_CREATE_EXTENSION_OID         0


/*------------------------------------------------------------------*/
static char* gEstPKIComponents[] =
{
    CA_PKI_COMPONENT,
    CERTS_PKI_COMPONENT,
    CRLS_PKI_COMPONENT,
    KEYS_PKI_COMPONENT,
    REQ_PKI_COMPONENT,
    CONF_PKI_COMPONENT
};

/*------------------------------------------------------------------*/

static sbyte* pUtilPkiDatabase = NULL;

static byteBoolean gIswriteExensions = TRUE;

/*------------------------------------------------------------------*/

MOC_EXTERN void EST_CERT_UTIL_setIsWriteExtensions(byteBoolean value)
{
    gIswriteExensions = value;
    return;
}

/*------------------------------------------------------------------*/

static byteBoolean EST_CERT_UTIL_isSafeFileName(const char *name)
{
    size_t len;

    if (NULL == name)
    {
        return FALSE;
    }

    len = strnlen(name, MAX_DIRECTORY_NAME);
    if (0 == len || len >= MAX_DIRECTORY_NAME)
    {
        return FALSE;
    }

    if (NULL != DIGI_STRCHR((sbyte *)name, (sbyte)'/', (ubyte4)len) ||
        NULL != DIGI_STRCHR((sbyte *)name, (sbyte)'\\', (ubyte4)len))
    {
        return FALSE;
    }

#ifdef __ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
    if (NULL != strstr(name, ".."))
    {
        return FALSE;
    }
#else
    {
        const char *p = name;
        while (*p && *(p + 1))
        {
            if (p[0] == '.' && p[1] == '.')
            {
                return FALSE;
            }
            ++p;
        }
    }
#endif

    return TRUE;
}

/*------------------------------------------------------------------*/

MOC_EXTERN char* EST_CERT_UTIL_getFullPath(const char* directory, const char* name, char **ppFull)
{
    int len = 0;

#if (!defined (__RTOS_OSE__) && !defined(__RTOS_WIN32__))
    if (FALSE == EST_CERT_UTIL_isSafeFileName(name))
        goto exit;

    /* What size? */
    len = DIGI_STRLEN ((sbyte *)directory);
    len += 1;
    len += DIGI_STRLEN ((sbyte *) name);
    len += 1;

    /* Create concatenated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    DIGI_MEMSET((ubyte *)*ppFull, 0, len);

    DIGI_STRCBCPY((sbyte *) *ppFull, len, (sbyte *) directory);
    DIGI_STRCAT((sbyte *) *ppFull, (sbyte *) "/");
    DIGI_STRCAT((sbyte *) *ppFull, (sbyte *) name);
#elif (defined(__RTOS_WIN32__))
    if (FALSE == EST_CERT_UTIL_isSafeFileName(name))
        goto exit;

    len = (int)DIGI_STRLEN ((sbyte *) directory);
    len += 1;
    len += (int)DIGI_STRLEN ((sbyte *) name);
    len += 1;

    /* Create concatenated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    DIGI_MEMSET((ubyte *)*ppFull, 0, len);

    DIGI_STRCBCPY((sbyte *) *ppFull, len, (sbyte *) directory);
    DIGI_STRCAT((sbyte *) *ppFull, (sbyte *) "\\");
    DIGI_STRCAT((sbyte *) *ppFull, (sbyte *) name);
#else
    /* Do not change! */
    if (FALSE == EST_CERT_UTIL_isSafeFileName(name))
    {
        goto exit;
    }
    len += strnlen(name, MAX_DIRECTORY_NAME);
    len += 1;

    /* Create duplicated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    strncpy(*ppFull, name, len - 1);
    (*ppFull)[len - 1] = '\0';
#endif

    DIGI_removeDuplicateSlashes (*ppFull);
exit:
    return *ppFull;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_createDirectory(char *directory)
{
	return FMGMT_mkdir ((sbyte *)directory, 0700);
}

/*------------------------------------------------------------------*/

MOC_EXTERN sbyte*
EST_CERT_UTIL_getPkiDBPtr()
{
    return pUtilPkiDatabase;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_createPkiDB(sbyte* pki_database)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    char* pki_component_path = NULL;
    pUtilPkiDatabase = MALLOC(MAX_DIRECTORY_NAME);
    if (NULL == pUtilPkiDatabase)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pUtilPkiDatabase, 0x00, MAX_DIRECTORY_NAME);
    DIGI_STRCBCPY((sbyte *)pUtilPkiDatabase, MAX_DIRECTORY_NAME, (sbyte *)pki_database);

    EST_CERT_UTIL_createDirectory((char *)pUtilPkiDatabase);
    for ( i = 0; i < COUNTOF(gEstPKIComponents); ++i)
    {
        pki_component_path = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pUtilPkiDatabase, gEstPKIComponents[i]);
        EST_CERT_UTIL_createDirectory(pki_component_path);
        if (pki_component_path)
            FREE(pki_component_path);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
MOC_EXTERN char*
EST_CERT_UTIL_buildKeyStoreFullPath(char* keystore, char* subdir)
{
    char* fullPath;
    ubyte4 keystoreLen, subdirLen;

    /* Validate inputs */
    if (NULL == keystore || NULL == subdir)
    {
        return NULL;
    }

    keystoreLen = DIGI_STRLEN((sbyte *)keystore);
    subdirLen = DIGI_STRLEN((sbyte *)subdir);

    if (keystoreLen + 1 + subdirLen + 1 > MAX_DIRECTORY_NAME)
    {
        return NULL;
    }

    /* Create concatenated string */
    fullPath = MALLOC(MAX_DIRECTORY_NAME);
    if (NULL == fullPath)
    {
        return NULL;
    }
    DIGI_MEMSET((ubyte*)fullPath, 0x00, MAX_DIRECTORY_NAME);

    DIGI_STRCBCPY((sbyte *)fullPath, MAX_DIRECTORY_NAME, (sbyte *)keystore);
    DIGI_STRCAT((sbyte *)fullPath, (sbyte *)"/");
    DIGI_STRCAT((sbyte *)fullPath, (sbyte *)subdir);
    DIGI_removeDuplicateSlashes (fullPath);
    return fullPath;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_generateOIDFromString(const sbyte* oidStr, ubyte** oid, ubyte4* oid_len)
{
    MSTATUS status = OK;
    byteBoolean w;

    if (OK > (status = BEREncodeOID(oidStr, &w, oid)))
    {
        myPrintError("EST_CERT_UTIL_generateOIDFromString::DER_AddItem::status: ", status);
        goto exit;
    }

    *oid = *oid + 1;				/* Do not include the type field of the oid encoded array.*/
    *oid_len = *((*oid) + 1);		/* Length includes the length field plus the actual der encoded oid . */

exit:
    return status;

}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_writeExtensionToFile(char* filename, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;
    sbyte *pCertPath = NULL;
    sbyte *pFileName = NULL;
    ubyte4 fileNameLen = 0;
    sbyte *pFullPath = NULL;

    /* SANITIZER: Validate filename to prevent path traversal attacks.
     * This check ensures no path separators or ".." sequences are present.
     */
    if (FALSE == EST_CERT_UTIL_isSafeFileName(filename))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    pCertPath = (sbyte*)EST_CERT_UTIL_buildKeyStoreFullPath((char *)pUtilPkiDatabase, (char *)CONF_PKI_COMPONENT);
    fileNameLen = DIGI_STRLEN((const sbyte *)filename);

    pFileName = MALLOC(fileNameLen + 1);
    if (NULL == pFileName)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pFileName, 0x00, fileNameLen + 1);
    DIGI_STRCAT(pFileName, (const sbyte *)filename);
    (pFileName)[fileNameLen] = '\0';

    if (OK > ( status = DIGICERT_writeFile((const char*)EST_CERT_UTIL_getFullPath((const char*)pCertPath,
                        (const char*)pFileName, (char **)&pFullPath), pData, dataLen)))
    {
        myPrintStringError("EST_CERT_UTIL_writeToFileMsExtension::DIGICERT_writeFile()::file ", pFullPath);
        myPrintError("EST_CERT_UTIL_writeToFileMsExtension::DIGICERT_writeFile::status: ", status);
        goto exit;
    }

exit:
    if (pFullPath)
        FREE(pFullPath);
    if (pFileName)
        FREE(pFileName);
    if (pCertPath)
        FREE(pCertPath);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_convertStringToByteArray(char *in, ubyte *results, ubyte4* count)
{
    MSTATUS status = OK;
    ubyte4 i=0;
    ubyte4 len= DIGI_STRLEN((const sbyte *)in);

    for(i = 0; i < len; i++) {
        if(0 == *in)
            break;
        sscanf(in, "%02X", (unsigned int *)&results[i]);
        in += 3;
    }
    *count = i;

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_convertStringToBmpByteArray(char *in, ubyte *results)
{
    MSTATUS status = OK;
    ubyte4 i=0, j=0;
    ubyte4 len= 2 * DIGI_STRLEN((const sbyte *)in);
    if (len == 0)
    {
        results[0] = 0;
        goto exit;
    }
    if(len > MAX_ASN1_BMPSTRING)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }
    for(i = 0; i < len-1; i++)
    {
        results[i] = 0;
        results[i+1] = in[j];
        i++;
        j++;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_populateExtensionWithASN1Object(int item_count,
        char asn1object[][NAME_VALUE_PAIR_SIZE][MAX_ASN1_STRING],
        intBoolean isCritical, extensions* pExtension)
{
    MSTATUS status = OK;
    int i=0;
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
    int j=0;
#endif
    ubyte* oid = NULL;
    ubyte4 oid_len = 0;
#if !defined (__RTOS_VXWORKS__) && !defined(__FREERTOS_RTOS__)
   char fileName[MAX_ASN1_STRING] = {0};
#endif
    DER_ITEMPTR pParent = NULL;
    ubyte *pValue[MAX_ASN1_OBJECTS] = {0};
    ubyte4 index = 0;
    ubyte4 count = 0;
	MOC_UNUSED(isCritical);

#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
    {
        myPrintNL("============================ A S N 1   O B J E C T ==============================");
        for(i = 0; i < item_count; i++)
        {
            for(j = 0; j < 2; j++)
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "asn1object[%d][%d][0]: %s\n", i, j, &asn1object[i][j][0]);
            }
        }
        myPrintNL("=================================================================================\n");
    }
#endif

    if ( OK > (status = EST_CERT_UTIL_generateOIDFromString((const sbyte*)&asn1object[0][PAIR_VALUE][0], &oid, &oid_len)))
        goto exit;

    pExtension->oid = (ubyte*) oid; oid = NULL;
    pExtension->isCritical = 0;
#if (VERBOSE_DEBUG_CREATE_EXTENSION_OID == 1)
    {
        myPrintNL("================================ A S N 1   O I D ================================");
        DEBUG_HEXDUMP(DEBUG_EST_EXAMPLE, (ubyte*)pExtension->oid, *((ubyte*)(pExtension->oid)) + 1);
        myPrintNL("=================================================================================\n");
    }
    myPrintNL("===================== P R O C E S S  A S N 1   O  B J E C T =====================");
#endif
    for(i = 0; i < item_count; i++)
    {
        if(0 == DIGI_STRCMP((const sbyte *)&asn1object[i][PAIR_NAME][0], (const sbyte *)ASN1_OID_STRING))
        {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
            myPrintNL("--------------------> case: OID");
#endif
            /* No processing needed...*/
        }
        else if(0 == DIGI_STRCMP((const sbyte *)&asn1object[i][PAIR_NAME][0], (const sbyte *)ASN1_TLVS_STRING))
        {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
            myPrintNL("--------------------> case: TLVS");
#endif
            /* No processing needed... */
        }
        else if(0 == DIGI_STRCMP((const sbyte *)&asn1object[i][PAIR_NAME][0], (const sbyte *)ASN1_TLV_STRING))
        {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "--------------------> case: TLV");
#endif
            if(0 == DIGI_STRCMP((const sbyte *)&asn1object[i][PAIR_VALUE][0], (const sbyte *)ASN1_SEQUENCE_STRING))
            {

#if  (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::SEQUENCE");
#endif
                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddSequence(NULL, &pParent)))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddSequence(pParent, NULL)))
                    {
                        goto exit;
                    }
                }
            }
            else if(strstr(&asn1object[i][PAIR_VALUE][0], ASN1_INTEGER_STRING))
            {
                ubyte value[160] = {0};
                count = 0;
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::INTEGER");
#endif
                EST_CERT_UTIL_convertStringToByteArray(&asn1object[i][PAIR_VALUE][8], &value[0], &count);
                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddItem(NULL, INTEGER, count, value, &pParent)))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddItem(pParent, INTEGER, count, value, NULL)))
                    {
                        goto exit;
                    }
                }
            }
            else if(strstr(&asn1object[i][PAIR_VALUE][0], ASN1_IA5STRING_STRING))
            {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::IA5STRING");
#endif
                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddItem(NULL, IA5STRING, DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]),
                                    (const ubyte*)&asn1object[i][PAIR_VALUE][10], &pParent)))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddItem(pParent, IA5STRING, DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]),
                                    (const ubyte*)&asn1object[i][PAIR_VALUE][10], NULL)))
                    {
                        goto exit;
                    }
                }
            }
            else if(strstr(&asn1object[i][PAIR_VALUE][0], ASN1_UTF8STRING_STRING))
            {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::UTF8STRING");
#endif
                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddItem(NULL, UTF8STRING,
                                    DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]), (const ubyte*)&asn1object[i][PAIR_VALUE][10], &pParent)))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddItem(pParent, UTF8STRING,
                                    DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]), (const ubyte*)&asn1object[i][PAIR_VALUE][10], NULL)))
                    {
                        goto exit;
                    }
                }
            }
            else if(strstr(&asn1object[i][PAIR_VALUE][0], ASN1_BMPSTRING_STRING))
            {
                status = DIGI_CALLOC((void **) &pValue[index], 1, MAX_ASN1_BMPSTRING);
                if (OK != status)
                    goto exit;

#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::BMPSTRING");
#endif
                EST_CERT_UTIL_convertStringToBmpByteArray(&asn1object[i][PAIR_VALUE][10], pValue[index]);
                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddItemCopyData(NULL, BMPSTRING,
                                    2*DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]), pValue[index], &pParent)))
                    {
                        index++;
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddItemCopyData(pParent, BMPSTRING,
                                    2*DIGI_STRLEN((const sbyte *)&asn1object[i][PAIR_VALUE][10]), pValue[index], NULL)))
                    {
                        index++;
                        goto exit;
                    }
                }
                index++;
            }
            else if(strstr(&asn1object[i][PAIR_VALUE][0], ASN1_BITSTRING_STRING))
            {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::BITSTRING");
#endif
                count = 0;

                status = DIGI_CALLOC((void **) &pValue[index], 1, MAX_ASN1_BMPSTRING);
                if (OK != status)
                    goto exit;

                EST_CERT_UTIL_convertStringToByteArray(&asn1object[i][PAIR_VALUE][10], pValue[index], &count);

                if(NULL == pParent)
                {
                    if (OK > (status = DER_AddBitString(NULL, count, pValue[index], &pParent)))
                    {
                        index++;
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = DER_AddBitString(pParent, count, pValue[index], NULL)))
                    {
                        index++;
                        goto exit;
                    }
                }
                index++;
            }
            else
            {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
                myPrintNL("::default");
#endif
            }
        }
        else
        {
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
            myPrintNL("--------------------> case: default");
#endif
        }
    }
#if (VERBOSE_DEBUG_CREATE_EXTENSION_OID == 1)
    {
        myPrintNL("=================================================================================\n");
    }
#endif
    if (OK > ( status = DER_Serialize(pParent, &pExtension->value, &pExtension->valueLen)))
    {
        myPrintError("EST_CERT_UTIL_makeMsCertificateTemplateExtension::DER_Serialize::status: ", status);
        goto exit;
    }

#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "======================= C R E A T E D   E X T E N S I O N =======================");
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "OID:");
        DEBUG_HEXDUMP(DEBUG_EST_EXAMPLE, (ubyte*)pExtension->oid, *((ubyte*)(pExtension->oid)));
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "OID's ASN1 OBJECT:");
        DEBUG_HEXDUMP(DEBUG_EST_EXAMPLE, (ubyte*)pExtension->value, pExtension->valueLen);
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n\n", "=================================================================================");
    }
#endif
#if !defined (__RTOS_VXWORKS__) && !defined(__FREERTOS_RTOS__)

    if (gIswriteExensions)
    {
        const char *oidInput = (const char*)&asn1object[0][PAIR_VALUE][0];
        char sanitizedOid[MAX_ASN1_STRING] = {0};
        ubyte4 oidLen = 0;

        if (NULL == oidInput || '\0' == *oidInput)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        while (*oidInput != '\0' && oidLen < MAX_ASN1_STRING - 5)
        {
            if ((*oidInput >= '0' && *oidInput <= '9') || *oidInput == '.')
            {
                sanitizedOid[oidLen++] = *oidInput;
            }
            else
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            oidInput++;
        }

        if (oidLen == 0)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        sanitizedOid[oidLen] = '\0';

        DIGI_STRCAT((sbyte*)fileName, (sbyte*)sanitizedOid);
        DIGI_STRCAT((sbyte*)fileName, (sbyte*)".der");
        if (pUtilPkiDatabase != NULL)
        {
            /* pUtilPkiDatabase will not be null incase of EST C Client application since it initializes
            * the Keystore by calling EST_CERT_UTIL_createPkiDB.
            */
            EST_CERT_UTIL_writeExtensionToFile(fileName, (ubyte*)pExtension->value, pExtension->valueLen);
        }
    }
#endif

exit:
    for(i = 0; i < (int)(index); i++)
    {
        if(pValue[i])
        {
            FREE(pValue[i]);
        }
    }
    if (oid)
    {
        DIGI_FREE((void **) &oid);
    }
    if (pParent)
    {
        TREE_DeleteTreeItem( (TreeItem*) pParent);
    }
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
EST_CERT_UTIL_makeExtensionsFromBuffer(char *pData, ubyte4 dataLen, certExtensions **ppExtension)
{
    MSTATUS status = OK;
    char myLineArray[MAX_ASN1_LINES][MAX_ASN1_STRING] = {{0}};
    char myLine[MAX_ASN1_STRING] = {0};
    char *ntoken = NULL;
    char *vtoken = NULL;
    char *search = "=";
    char asn1Objects[MAX_ASN1_LINES][NAME_VALUE_PAIR_SIZE][MAX_ASN1_STRING] = {{{0}}};
    ubyte4 k = 0, i = 0, num_asn1_objects = 0;
    ubyte4 max_lines = 0;
    int item_count = 0, item_index = 0, ext_count = 0;

    /* exit if dataLen is zero */
    if ( 0 == dataLen)
    {
        status = -1;
        return status;
    }
    /* 1. Separate Est Configuration file into lines.*/
    for(k = 0; k < MAX_ASN1_LINES; k++)
    {
        if (0 == dataLen)
            break;
        for(i = 0; i < MAX_ASN1_STRING; i++)
        {
            if (i >= MAX_ASN1_STRING - 1)
            {
                myLineArray[k][MAX_ASN1_STRING - 1] = '\0';
                while (dataLen > 0 && *pData != '\n' && *pData != '\r')
                {
                    pData++;
                    dataLen--;
                }
                break;
            }

            if (('\n' == *pData) || ('\r' == *pData) )
            { /* terminate line and purge any extra eol characters */
                myLineArray[k][i] = '\0';
                while (('\n' == *pData) || ('\r' == *pData))
                { /* purge any extra eol characters */
                    pData++; /* throw eol char away */
                    dataLen--;
                    if (0 == dataLen)
                        break;
                } /* end purge eol chars */
                break; /* process next line */
            }
            else
            {
                myLineArray[k][i] = *pData++;
                dataLen--;
                if (0 == dataLen)
                { /* unexpected end of buffer, add null to string array */
                    if (i < MAX_ASN1_STRING - 1)
                    {
                        myLineArray[k][i+1] = '\0';
                    }
                    break;
                }
                else
                    continue;
            }
        } /* end for MAX_ASN1_STRING */
    } /* end for MAX_ASN1_LINES */

    /* 2. Convert each line into name/value pairs, and place them into array of ASN1 objects. */
    max_lines = k;
    for(k = 0; k < max_lines; k++)
    {
        char *savePtr;
        if(0 == myLineArray[k][0])
        {
            break;
        }
        DIGI_STRCBCPY((sbyte *) myLine, MAX_ASN1_STRING, (sbyte *) &myLineArray[k][0]);
        ntoken = strtok_r(myLine, search, &savePtr);
        if (0 == (k % 3))
        {
            if(0 == DIGI_STRCMP((const sbyte *)ntoken, (const sbyte *)"oid"))
            {
                num_asn1_objects++;
            }
            else
            {
                status = ERR_EST_MISSING_OID;
                goto exit;
            }
        }
        if (ntoken != NULL)
        {
            ubyte4 ntokenLen = DIGI_STRLEN((sbyte*)ntoken);
            if (ntokenLen < MAX_ASN1_STRING)
            {
                DIGI_STRCAT((sbyte*)&asn1Objects[k][PAIR_NAME][0], (sbyte*)ntoken);
            }
        }
        vtoken = strtok_r(NULL, search, &savePtr);
        if (vtoken != NULL)
        {
            ubyte4 vtokenLen = DIGI_STRLEN((sbyte*)vtoken);
            if (vtokenLen < MAX_ASN1_STRING)
            {
                DIGI_STRCAT((sbyte*)&asn1Objects[k][PAIR_VALUE][0], (sbyte*)vtoken);
            }
        }
    }

    if (0 == num_asn1_objects)
    {
        /* No extensions to add, exit */
        status = OK;
        goto exit;
    }

    if (NULL == *ppExtension)
    {
        status = DIGI_CALLOC((void **) ppExtension, sizeof(certExtensions), 1);
        if (OK != status)
            goto exit;
    }

    if (NULL == (*ppExtension)->otherExts)
    {

        (*ppExtension)->otherExtCount = num_asn1_objects;
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtension)->otherExts), num_asn1_objects*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtension)->otherExts, 0x00, num_asn1_objects*sizeof(extensions))))
        {
            goto exit;
        }
    }
    else
    {
        /* If (*ppExtension)->otherExts is not null then it is allocated
         * at the time of creating subjectAltNames. So do a +1 in the
         * count and copy the subjectAltNames at first postion and then copy
         * other extensions from next positions
         */
        int oldCount = (*ppExtension)->otherExtCount;
        extensions *pTemp = (*ppExtension)->otherExts;
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtension)->otherExts), (oldCount + num_asn1_objects)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtension)->otherExts, 0x00, (oldCount + num_asn1_objects)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY((*ppExtension)->otherExts, pTemp, (oldCount) * sizeof(extensions))))
        {
            goto exit;
        }
        (*ppExtension)->otherExtCount = oldCount + num_asn1_objects;
        FREE(pTemp);
        pTemp = NULL;
        ext_count = oldCount;
    }


    /* 4a. Populate each extension with the der encoded oid and tlv. */
    k = 0;
    for(k = 0; k < MAX_ASN1_LINES; k++)
    {
        if(0 == asn1Objects[item_index][PAIR_NAME][0])
            break;
        item_count = DIGI_ATOL((sbyte *) &asn1Objects[item_index+1][PAIR_VALUE][0], NULL) + 2;
#if (VERBOSE_DEBUG_CREATE_EXTENSION == 1)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "item_index: %d, ", item_index);
            MSG_LOG_print(MSG_LOG_VERBOSE, "item_count: %d, ", item_count);
            MSG_LOG_print(MSG_LOG_VERBOSE, "ext_count: %d\n", ext_count);
        }
#endif
        /* Populate Extension with ASN1 Object */
        EST_CERT_UTIL_populateExtensionWithASN1Object(item_count,
                (char (*)[NAME_VALUE_PAIR_SIZE][MAX_ASN1_STRING])&asn1Objects[item_index][0][0],
                FALSE, &(*ppExtension)->otherExts[ext_count]);
        item_index = item_index + item_count;
        ext_count = ext_count + 1;
    }

exit:
    return status;
}

MOC_EXTERN MSTATUS
EST_CERT_UTIL_makeExtensionsFromConfigFile(char *pFileName, certExtensions **ppExtension)
{
    MSTATUS status = OK;
    sbyte *pCertPath = NULL;
    sbyte *pAbsFileName = NULL;
    ubyte4 fileNameLen = 0;
    sbyte *pFullPath = NULL;
    char *pData = NULL;
    ubyte4 dataLen = 0;

    /* 1. Read Est Configuration file from keystore database in etc directory. */
    pCertPath = (sbyte*)EST_CERT_UTIL_buildKeyStoreFullPath((char *)pUtilPkiDatabase, (char *)CONF_PKI_COMPONENT);
    if (NULL == pCertPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pFileName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    fileNameLen = DIGI_STRLEN((sbyte *)pFileName);
    if (fileNameLen == 0 || fileNameLen >= MAX_DIRECTORY_NAME)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pAbsFileName = MALLOC(fileNameLen + 1);
    if (NULL == pAbsFileName)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pAbsFileName, 0x00, fileNameLen + 1);
    DIGI_STRCAT((sbyte*)pAbsFileName, (sbyte*)pFileName);
    (pAbsFileName)[fileNameLen] = '\0';

    if (OK > ( status = DIGICERT_readFile(
                    (const char*)EST_CERT_UTIL_getFullPath((const char*)pCertPath, (const char*)pAbsFileName, (char **)&pFullPath),
                    (ubyte **)&pData, &dataLen)))
    {
        myPrintStringError("EST_CERT_UTIL_makeExtensionsFromConfigFileNew::DIGICERT_readFile()::file=", pFullPath);
        myPrintError("EST_CERT_UTIL_makeExtensionsFromConfigFileNew::DIGICERT_readFile::status: ", status);
        goto exit;
    }
    if (OK > (status = EST_CERT_UTIL_makeExtensionsFromBuffer(pData, dataLen, ppExtension)))
    {
        myPrintError("EST_CERT_UTIL_makeExtensionsFromConfigFileNew::DIGICERT_readFile::status: ", status);
        goto exit;
    }
exit:
    if (pAbsFileName)
        FREE(pAbsFileName);
    if (pCertPath)
        FREE(pCertPath);
    if (pFullPath)
        FREE(pFullPath);
    if (pData)
        FREE(pData);
    return status;
}
