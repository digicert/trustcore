/*
 * mocsmp_credwrite.c
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
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../../common/moptions.h"
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/mfmgmt.h"
#include "../fapi2/fapi2.h"
#include "../../../../tap/tap_smp.h"
#include "../../../../tap/tools/moctap_credparser.h"
#include "../../../../smp/smp_tpm2/smp_tpm2.h"
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#define BUFFSIZE    16

#define TPM2_DEBUG_PRINT_NO_ARGS(fmt) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

#define PRINT_TO_FILE(pFile, fmt, ...)\
    do {\
        if (OK != FMGMT_fprintf (pFile, fmt, ##__VA_ARGS__))\
        {\
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to write to text file");\
            goto exit;\
        }\
    }while (0)

typedef struct Token
{
    const sbyte* m_str;
    sbyte4 m_len;
    sbyte4 m_extra;
} Token;

/* symbolic constants for the pattern/properties/command tokens  */
enum {
    UserEntity = 1,
    parentType,
    parentId,
    entityType,
    entityId,
    entCredential,
    CredType,
    CredFormat,
    CredContext,
    CredAuth
} ;

static char *gEntityNameComment[] = 
{
    "# entity-desc TPM 2.0 Lockout hierarchy, Id – 0x4000000A",
    "# entity-desc TPM 2.0 Endorsement hierarchy, Id - 0x4000000B",
    "# entity-desc TPM 2.0 Storage hierarchy, Id - 0x40000001",
    "# entity-desc TPM 2.0 Endorsement Key, Id – 0x40000006",
    "# entity-desc TPM 2.0 Storage Root Key, Id – 0x40000000"
};

static Token gEntityTokens[] =
{
    {(const sbyte*)"entity :", 8, UserEntity },
    {(const sbyte*)"parent-type", 11, parentType },
    {(const sbyte*)"parent-id", 9, parentId },
    {(const sbyte*)"entity-type", 11, entityType },
    {(const sbyte*)"entity-id", 9, entityId },
    {(const sbyte*)"credential {", 12, entCredential }
} ;

static Token gCredTokens[] =
{
    {(const sbyte*)"type", 4, CredType },
    {(const sbyte*)"format", 6, CredFormat },
    {(const sbyte*)"context", 7, CredContext },
    {(const sbyte*)"auth [", 6, CredAuth }
} ;

static Token gParentTypeTokens[] =
{
    {(const sbyte*)"undefined", 9, 0 },
    {(const sbyte*)"module", 6, 1 },
    {(const sbyte*)"token", 5, 2 },
    {(const sbyte*)"object", 6, 3 }
} ;

static Token gEntityTypeTokens[] =
{
    {(const sbyte*)"undefined", 9, 0 },
    {(const sbyte*)"module", 6, 1 },
    {(const sbyte*)"token", 5, 2 },
    {(const sbyte*)"object", 6, 3 }
} ;

static Token gCredTypeTokens[] =
{
    {(const sbyte*)"undefined", 9, 0 },
    {(const sbyte*)"passwd", 6, 1 },
    {(const sbyte*)"cert", 4, 2 },
    {(const sbyte*)"key", 3, 3 },
    {(const sbyte*)"object", 6, 4 }
} ;

static Token gCredFormatTokens[] =
{
    {(const sbyte*)"undefined", 9, 0 },
    {(const sbyte*)"plaintext", 9, 1 },
    {(const sbyte*)"sha1", 4, 2 },
    {(const sbyte*)"sha256", 6, 3 },
    {(const sbyte*)"der", 3, 4 },
    {(const sbyte*)"pem", 3, 5 },
    {(const sbyte*)"rawbyte", 7, 6 }
} ;

static Token gCredContextTokens[] =
{
    {(const sbyte*)"undefined", 9, 0 },
    {(const sbyte*)"owner", 5, 1 },
    {(const sbyte*)"user", 4, 2 },
    {(const sbyte*)"entity", 6, 3 },
    {(const sbyte*)"dynamic", 7, 4 }
} ;


MSTATUS getLineWithValue(sbyte *pType,ubyte4 typeLen,ubyte4 value,sbyte **pLine)
{
    MSTATUS status = OK;
    ubyte *tempVal= NULL,*strVal;

    /* Allocate BUFFSIZE for Entity-d as it could be huge number */
    status = DIGI_MALLOC((void **) &tempVal,BUFFSIZE);
    if(OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    DIGI_MEMSET(tempVal,'\0',BUFFSIZE);

    status = DIGI_MALLOC((void **) (pLine),(typeLen+BUFFSIZE));
    if(OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    DIGI_MEMSET((ubyte*)*pLine,'\0',((typeLen+BUFFSIZE)));

    DIGI_MEMCPY(*pLine, pType,typeLen);

    DIGI_STRCAT(*pLine,(sbyte *) " ");

    strVal = (ubyte *)DIGI_LTOA(value, (sbyte *)tempVal, BUFFSIZE);
    DIGI_STRCAT(*pLine, (sbyte *)tempVal);

exit:
    DIGI_FREE((void**)&tempVal);
    return status;
}


MSTATUS getLine(sbyte *pType,ubyte4 typeLen,sbyte *pValue,sbyte **pLine)
{
    MSTATUS status = OK;

    status = DIGI_CALLOC((void **) (pLine), 1,(typeLen+DIGI_STRLEN(pValue)+2));
    if(OK != status)
    {
         LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }
    DIGI_MEMSET((ubyte*)*pLine,'\0',(typeLen+DIGI_STRLEN(pValue)+2));
    DIGI_MEMCPY(*pLine, pType,typeLen);

    DIGI_STRCAT(*pLine,(sbyte *) " ");

    DIGI_STRCAT(*pLine, pValue);

exit:
    return status;
}

MSTATUS getTokenString(ubyte4 parentType,Token* tokenTable,
                sbyte4 tokenTableLen,sbyte **pToken)
{
    MSTATUS status= OK;
    int i;
    /* try to match one of the token */
    for ( i = 0; i < tokenTableLen; ++i)
    {
        if(parentType == tokenTable[i].m_extra)
        {
            status = DIGI_CALLOC((void **) (pToken), 1, (tokenTable[i].m_len)+1);
            if(OK != status)
            {
                LOG_ERROR("Failed to allocate memory, status = %d", status);
                goto exit;
            }
            DIGI_MEMSET((ubyte*)*pToken,'\0',(tokenTable[i].m_len)+1);
            DIGI_MEMCPY(*pToken,tokenTable[i].m_str,tokenTable[i].m_len);

            break;
        }
    }
exit:
    return status;
}


MSTATUS MocSMP_PushCredentials(FileDescriptor pFile,TAP_EntityCredentialList* pEntityCredentials,
                        int numCredentials, byteBoolean provision)
{
    MSTATUS status= OK;
    int i=0,entityToken,credToken;
    sbyte *pToken =NULL,*pLine=NULL;
    ubyte *pEncodedAuth = NULL;

    while(numCredentials > 0)
    {
        entityToken = 0;
        credToken   = 0;

        switch (pEntityCredentials->pEntityCredentials[i].entityId)
        {
            case TPM2_RH_OWNER_ID:
                PRINT_TO_FILE(pFile,"%s\n", (const ubyte *)gEntityNameComment[2]);
                break;

            case TPM2_RH_ENDORSEMENT_ID:
                PRINT_TO_FILE(pFile,"%s\n", (const ubyte *)gEntityNameComment[1]);
                break;

            case TPM2_RH_LOCKOUT_ID:
                PRINT_TO_FILE(pFile,"%s\n", (const ubyte *)gEntityNameComment[0]);
                break;

            case TPM2_RH_EK_ID:
                PRINT_TO_FILE(pFile,"%s\n", (const ubyte *)gEntityNameComment[3]);
                break;

            case TPM2_RH_SRK_ID:
                PRINT_TO_FILE(pFile,"%s\n", (const ubyte *)gEntityNameComment[4]);
                break;

        }

        if((i > 0) || (provision == TRUE))
        {
            PRINT_TO_FILE(pFile,"%s", (const ubyte *)gEntityTokens[entityToken].m_str);
            if (OK != status)
            {
                 LOG_ERROR("Failed to write user credential file, status = %d", status);
                goto exit;
            }
        }
        else
        {
            /* Writing Conf File for the first time. This happens in takeownership*/
            PRINT_TO_FILE(pFile, "%s",(const ubyte *)gEntityTokens[entityToken].m_str);
            if (OK != status)
            {
                 LOG_ERROR("Failed to write user credential file, status = %d", status);
                goto exit;
            }
        }
        entityToken++;

        /* Write ParentType*/
        status = getTokenString(pEntityCredentials->pEntityCredentials[i].parentType,gParentTypeTokens,COUNTOF( gParentTypeTokens),&pToken);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token, status = %d", status);
            goto exit;
        }

        PRINT_TO_FILE(pFile,"\n \t");
        status = getLine((sbyte *)gEntityTokens[entityToken].m_str, gEntityTokens[entityToken].m_len ,(sbyte *)pToken, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token line, status = %d", status);
            goto exit;
        }

        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        entityToken++;

        /* Write Parent-Id */
        PRINT_TO_FILE(pFile,"\n \t");

        status = getLineWithValue((sbyte *)gEntityTokens[entityToken].m_str, gEntityTokens[entityToken].m_len ,
                        pEntityCredentials->pEntityCredentials[i].parentId, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token line with value, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        entityToken++;

        /* Write Entity Type */
        status = getTokenString(pEntityCredentials->pEntityCredentials[i].entityType,gEntityTypeTokens,COUNTOF( gEntityTypeTokens),&pToken);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token, status = %d", status);
            goto exit;
        }

        PRINT_TO_FILE(pFile,"\n \t");

        status = getLine((sbyte *)gEntityTokens[entityToken].m_str, gEntityTokens[entityToken].m_len ,(sbyte *)pToken, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token line, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        entityToken++;

        PRINT_TO_FILE(pFile,"\n \t");

        /* Write Entity Id */
        status = getLineWithValue((sbyte *)gEntityTokens[entityToken].m_str, gEntityTokens[entityToken].m_len ,
                        pEntityCredentials->pEntityCredentials[i].entityId, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token line with value, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        entityToken++;

        PRINT_TO_FILE(pFile,"\n \n \t \t");

        /* Write Credential { */
        PRINT_TO_FILE(pFile,"%s",(const ubyte *)gEntityTokens[entityToken].m_str);
        if (OK != status)
        {
            LOG_ERROR("Failed to write user credential file, status = %d", status);
            goto exit;
        }

        /* Write Credential Type */
        status = getTokenString(pEntityCredentials->pEntityCredentials[i].credentialList.pCredentialList[0].credentialType,
                    gCredTypeTokens,COUNTOF( gCredTypeTokens),&pToken);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token, status = %d", status);
            goto exit;
        }
        status = getLine((sbyte *)gCredTokens[credToken].m_str, gCredTokens[credToken].m_len ,(sbyte *)pToken, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read credential token line, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);

        credToken++;
        PRINT_TO_FILE(pFile,"\n \t \t");

        /* Write Credential Format */
        status = getTokenString(pEntityCredentials->pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat,
                    gCredFormatTokens,COUNTOF( gCredFormatTokens),&pToken);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token, status = %d", status);
            goto exit;
        }
        status = getLine((sbyte *)gCredTokens[credToken].m_str, gCredTokens[credToken].m_len ,(sbyte *)pToken, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read credential token, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        credToken++;

        PRINT_TO_FILE(pFile,"\n \t \t");

        /* Write Credential Context */
        status = getTokenString(pEntityCredentials->pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext,
                    gCredContextTokens,COUNTOF( gCredContextTokens),&pToken);
        if (OK != status)
        {
            LOG_ERROR("Failed to read entity token, status = %d", status);
            goto exit;
        }
        status = getLine((sbyte *)gCredTokens[credToken].m_str, gCredTokens[credToken].m_len ,(sbyte *)pToken, &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read credential token, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        credToken++;

        PRINT_TO_FILE(pFile,"\n \t \t");

        status = MocTap_EncodeAuthData(
            pEntityCredentials->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer,
            &pEncodedAuth);
        if (OK != status)
        {
            LOG_ERROR("Failed to encode credential auth, status = %d", status);
            goto exit;
        }
        /* Write Credential Auth */
        status = getLine((sbyte *)gCredTokens[credToken].m_str, gCredTokens[credToken].m_len,
                        (sbyte *)pEncodedAuth,
                        &pLine);
        if (OK != status)
        {
            LOG_ERROR("Failed to read credential auth, status = %d", status);
            goto exit;
        }
        PRINT_TO_FILE(pFile,"%s",(const ubyte*) pLine);
        PRINT_TO_FILE(pFile," ] \n");
        PRINT_TO_FILE(pFile,"\t \t");
        PRINT_TO_FILE(pFile,"}");

        PRINT_TO_FILE(pFile,"\n");

        DIGI_FREE((void **)&pToken);
        DIGI_FREE((void**)&pLine);
        DIGI_FREE((void**)&pEncodedAuth);
        i = i + 1;
        numCredentials = numCredentials -1;
    }
exit:
    /* Free pToken and pLine if exited in error without freeing */
    if (NULL != pToken)
    {
        DIGI_FREE((void **)&pToken);
    }
    if (NULL != pLine)
    {
        DIGI_FREE((void**)&pLine);
    }
    if (NULL != pEncodedAuth)
    {
        DIGI_FREE((void**)&pEncodedAuth);
    }

    return status;
}




