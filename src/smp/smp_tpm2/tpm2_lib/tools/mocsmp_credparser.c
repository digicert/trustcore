/*
 * moctap_credparser.c
 *
 * User credential Parser
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
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mudp.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/dynarray.h"
#include "../../../../tap/tap_smp.h"
#include "../../../../tap/tools/moctap_credparser.h"
//#include "../tap_api.h"
//#include "../tap_smp.h"
//#include "../tap_utils.h"



typedef struct Token
{
    const sbyte* m_str;
    sbyte4 m_len;
    sbyte4 m_extra;
} Token;

sbyte4 nMocSmpEntities = 0 ;


typedef struct MocTapScript_Credential_s {
    TAP_CREDENTIAL_TYPE     credentialType;
    /*! The format of the authorization information.  This must be a valid #TAP_CREDENTIAL_FORMAT value. */
    TAP_CREDENTIAL_FORMAT   credentialFormat;
    /*! Used to indicate the context associated with the credential. This must be a valid #TAP_CREDENTIAL_CONTEXT value. */
    TAP_CREDENTIAL_CONTEXT  credentialContext;
    TAP_AuthData            credentialData;
    struct MocTapScript_Credential_s *pNext ;


} MocTapScript_Credential_t ;


typedef struct MocTapScript_Entity_s {
    TAP_ENTITY_TYPE  parentType;
    /*! ModuleId, TokenId or ObjectId */
    TAP_EntityId     parentId;
    /*! The number of credentials contained in the list */
    TAP_ENTITY_TYPE  entityType;
    /*! ModuleId, TokenId or ObjectId */
    TAP_EntityId     entityId;
    sbyte4 nCredential ;
    MocTapScript_Credential_t *pHeadCred ;
    MocTapScript_Credential_t *pTailCred ;
    struct MocTapScript_Entity_s *pNextEntity ;
} MocTapScript_Entity_t ;

MocTapScript_Entity_t *pSmpEntityHead = NULL;
MocTapScript_Entity_t *pSmpCurEntity = NULL ;



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


/* possible pattern names */
static Token gEntityTokens[] =
{
    {(const sbyte*)"entity", 6, UserEntity },
    {(const sbyte*)"parent-type", 11, parentType },
    {(const sbyte*)"parent-id", 9, parentId },
    {(const sbyte*)"entity-type", 11, entityType },
    {(const sbyte*)"entity-id", 9, entityId },
    {(const sbyte*)"credential", 10, entCredential }
} ;

static Token gCredTokens[] =
{
    {(const sbyte*)"type", 4, CredType },
    {(const sbyte*)"format", 6, CredFormat },
    {(const sbyte*)"context", 7, CredContext },
    {(const sbyte*)"auth", 4, CredAuth }
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

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)



static intBoolean
IsWhiteSpace( sbyte c)
{
    return ' ' == c || '\t' == c || '\n' == c || '\r' == c;
}


static intBoolean
IsTokenDelimiter( sbyte c)
{
    return 0 == c || IsWhiteSpace(c) ||
        '{' == c || '}' == c ||
        '[' == c || ']' == c ;
}

static const sbyte*
SkipComment( const sbyte* s)
{
    /* advance until the next end of line */
    while (*s && '\n' != *s)
    {
        ++s;
    }
    return s;
}

static const sbyte*
GetNextToken( const sbyte* s)
{
    while (*s)
    {
        sbyte c = *s;
        if (IsWhiteSpace(c))
        {
            ++s;
        }
        else if ( '#' == c)
        {
            s = SkipComment( ++s);
        }
        else
        {
            break;
        }
    }
    return s;
}

static MSTATUS
ReadID( const sbyte** pNextToken, TAP_ID* number)
{
    int numDigitsRead = 0;
    const sbyte* s = *pNextToken;

    *number = 0;

    /* check hexadecimal number, e.g. 0x... */
    if ( 0 == DIGI_STRNICMP(s, (sbyte *)"0x", 2))
    {
        s += 2;
        for (;; s++)
        {
            sbyte c = *s;
            if ( c >= '0' && c <= '9') c -= '0';
            else if ( c >= 'a' && c <= 'f') c -= 'a' - 10;
            else if ( c >= 'A' && c <= 'F') c -= 'A' - 10;
            else break;

            ++numDigitsRead;
            *number *= 16;
            *number += c;
        }

        if ( 16 < numDigitsRead) return ERR_FALSE;
    }
    else

    while ( *s >= '0' && *s <= '9')
    {
        ++numDigitsRead;
        *number *= 10;
        *number += (*s++) - '0';
    }

    *pNextToken = s;
    return ( numDigitsRead) ? OK : ERR_FALSE;
}

#if 0
static MSTATUS
ReadNumber( const sbyte** pNextToken, sbyte4* number)
{
    int numDigitsRead = 0;
    const sbyte* s = *pNextToken;

    *number = 0;

    /* check hexadecimal number, e.g. 0x... */
    if ( 0 == DIGI_STRNICMP(s, (sbyte *)"0x", 2))
    {
        s += 2;
        for (;; s++)
        {
            sbyte c = *s;
            if ( c >= '0' && c <= '9') c -= '0';
            else if ( c >= 'a' && c <= 'f') c -= 'a' - 10;
            else if ( c >= 'A' && c <= 'F') c -= 'A' - 10;
            else break;

            ++numDigitsRead;
            *number *= 16;
            *number += c;
        }

        if ( 8 < numDigitsRead) return ERR_FALSE;
    }
    else

    while ( *s >= '0' && *s <= '9')
    {
        ++numDigitsRead;
        *number *= 10;
        *number += (*s++) - '0';
    }

    *pNextToken = s;
    return ( numDigitsRead) ? OK : ERR_FALSE;
}
#endif

static sbyte4
GetAuthLength( const sbyte* s)
{
    sbyte4 retVal = 0;
    while (*s && !(( *s == ']') && IsWhiteSpace(*(s+1)) ))
    {
      retVal++ ;
      s++ ;
    }
    return retVal ;
}

static MSTATUS
ReadAuth( const sbyte** pNextToken, TAP_AuthData* pAuth)
{
    int numRead = 0;
    int nws =0;
    const sbyte  *pWs ;
    MSTATUS status = ERR_NOT_FOUND;
    const sbyte* s = *pNextToken;
    if (*s != '[')
    {
        status = ERR_TAP_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the [ */
    s = GetNextToken( s);
    if (0 == *s)
    {
        status = ERR_TAP_SCRIPT_UNEXPECTED_EOF;
        goto exit;
    }
    numRead = GetAuthLength( s);
    if(!numRead)
    {
        status = ERR_TAP_SCRIPT_PARSE_ERROR;
        if(( *s == ']'))
            numRead = 2;
        else
            goto exit;
    }
    pWs = s+numRead-1 ;
    while(IsWhiteSpace(*pWs))
    {
        nws++ ;
        pWs-- ;
    }
    if(( *s == ']'))
    {
        status = DIGI_CALLOC((void **) &(pAuth->pBuffer), 1, (numRead-nws)+1);
        DIGI_MEMSET(pAuth->pBuffer,'\0',(numRead-nws)+1);
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory, status = %d", status);
            goto exit;
        }
        //status = DIGI_MEMCPY((void *)pAuth->pBuffer, (void *)" ", numRead-nws) ;
        pAuth->bufferLen =0;
    }
    else
    {
        status = MocTap_DecodeAuthData(
            (ubyte *) s, numRead-nws, &(pAuth->pBuffer), &(pAuth->bufferLen),
            TRUE);
        if (OK != status)
        {
            LOG_ERROR("failed to decode auth attribute, status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    *pNextToken = s ;
    *pNextToken += numRead+1;
    return status;

exit:
    if(pAuth->pBuffer)
    {
        DIGI_FREE((void **)&pAuth->pBuffer) ;
        pAuth->bufferLen = 0 ;
    }
    return status;
}


static intBoolean
IsToken( const sbyte* s, Token* pToken)
{
    sbyte4 cmpRes;

    DIGI_MEMCMP( (const ubyte*) pToken->m_str,
                (const ubyte*) s,
                pToken->m_len,
                &cmpRes);
    return ( 0 == cmpRes && IsTokenDelimiter( s[pToken->m_len]));
}

static MSTATUS
MatchToken( const sbyte** pNextToken, Token* tokenTable,
           sbyte4 tokenTableLen, sbyte4 *extra)
{
    MSTATUS status = ERR_NOT_FOUND;
    const sbyte* s = *pNextToken;
    sbyte4 i;

    /* try to match one of the token */
    for ( i = 0; i < tokenTableLen; ++i)
    {
        if (IsToken( s, tokenTable + i))
        {
            *extra = tokenTable[i].m_extra;
            s += tokenTable[i].m_len;
            status = OK;
            break;
        }
    }

    *pNextToken = s;
    return status;
}


static MSTATUS
ParseEntityNameValuePair( const sbyte** pNextToken, MocTapScript_Entity_t *pEntity)
{
    MSTATUS status = OK;
    sbyte4 token;

    status = MatchToken( pNextToken, gEntityTokens,
                            COUNTOF( gEntityTokens), &token);

    if ( OK > status)
    {
        return ERR_TAP_SCRIPT_UNKNOWN_PATTERN;
    }

    *pNextToken = GetNextToken(*pNextToken);
    switch (token)
    {
    case parentType:
        status = MatchToken( pNextToken, gParentTypeTokens,
                                COUNTOF( gParentTypeTokens), &token);
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_UNKNOWN_PARENT_TYPE;
        }
        else
        {
            pEntity->parentType = token ;
        }
        break;
    case parentId:
        status = ReadID(pNextToken, &(pEntity->parentId));
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_INVALID_PARENT_ID;
        }
        break;
    case entityType:
        status = MatchToken( pNextToken, gEntityTypeTokens,
                                COUNTOF( gEntityTypeTokens), &token);
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_UNKNOWN_ENTITY_TYPE;
        }
        else
        {
            pEntity->entityType = token ;
        }
        break;
    case entityId:
        status = ReadID(pNextToken, &(pEntity->entityId));
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_INVALID_ENTITY_ID;
        }
        break;
    }
        return status;

}

static MSTATUS
ParseCredentialNameValuePair( const sbyte** pNextToken, MocTapScript_Credential_t *pCred)
{
    MSTATUS status = OK;
    sbyte4 token;

    status = MatchToken( pNextToken, gCredTokens,
                            COUNTOF( gCredTokens), &token);

    if ( OK > status)
    {
        return ERR_TAP_SCRIPT_UNKNOWN_PATTERN;
    }

    *pNextToken = GetNextToken(*pNextToken);
    switch (token)
    {
    case CredType:
        status = MatchToken( pNextToken, gCredTypeTokens,
                                COUNTOF( gCredTypeTokens), &token);
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_UNKNOWN_CRED_TYPE;
        }
        pCred->credentialType = (ubyte)token ;
        break;
    case CredFormat:
        status = MatchToken( pNextToken, gCredFormatTokens,
                                COUNTOF( gCredFormatTokens), &token);
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_UNKNOWN_CRED_FORMAT;
        }
        pCred->credentialFormat = (ubyte)token ;
        break;
    case CredContext:
        status = MatchToken( pNextToken, gCredContextTokens,
                                COUNTOF( gCredContextTokens), &token);
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_UNKNOWN_CRED_CONTEXT;
        }
        pCred->credentialContext= (ubyte)token ;
        break;
    case CredAuth:
        status = ReadAuth(pNextToken, &(pCred->credentialData));
        if (OK > status)
        {
            status = ERR_TAP_SCRIPT_INVALID_AUTH_VALUE;
            LOG_ERROR("Invalid Auth value, status = %d", status);
        }
        break;
    }
        return status;

}

static MSTATUS
GetMatchingToken( const sbyte* pNextToken, Token* tokenTable,
           sbyte4 tokenTableLen, sbyte4 *extra)
{
    MSTATUS status = ERR_NOT_FOUND;
    const sbyte* s = pNextToken;
    sbyte4 i;

    /* try to match one of the token */
    for ( i = 0; i < tokenTableLen; ++i)
    {
        if (IsToken( s, tokenTable + i))
        {
            *extra = tokenTable[i].m_extra;
            status = OK;
            break;
        }
    }

    return status;
}

void MocSmp_AddEntitytoList(MocTapScript_Entity_t *pEntity)
{
  if(!pSmpEntityHead)
    pSmpEntityHead = pEntity ;
  else {
      pEntity->pNextEntity = pSmpEntityHead ;
      pSmpEntityHead = pEntity ;
  }
  nMocSmpEntities++;
}

void MocSmp_AddCredtoList(MocTapScript_Entity_t *pEntity, MocTapScript_Credential_t *pCred)
{
   pCred->pNext = NULL ;
   if(!pEntity->pHeadCred)
   {
      pEntity->pHeadCred = pCred ;
      pEntity->pTailCred = pCred ;
   }
   else
   {
      pEntity->pTailCred->pNext = pCred ;
      pEntity->pTailCred = pCred ;
   }
   pEntity->nCredential++ ;
   return ;
}


static MSTATUS
ParseEntity( const sbyte** pNextToken)
{
    MSTATUS status;
    const sbyte* s;
    sbyte4 token;
    MocTapScript_Entity_t *pEntity ;


    s = GetNextToken( *pNextToken);

    if (*s != ':')
    {
        status = ERR_TAP_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the { */

    status = DIGI_CALLOC((void **) &pEntity, 1, sizeof(MocTapScript_Entity_t));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }
    while ( OK == status)
    {
        s = GetNextToken( s);
        if (0 == *s)
        {
            status = ERR_TAP_SCRIPT_UNEXPECTED_EOF;
            break;
        }
        status = GetMatchingToken( s, gEntityTokens,
                                COUNTOF( gEntityTokens), &token);

        if ( OK > status)
        {
            return ERR_TAP_SCRIPT_UNKNOWN_PATTERN;
        }
        if ((token == entCredential) || (token == UserEntity))
        {
            break;
        }
        status = ParseEntityNameValuePair( &s, pEntity);

    }
    if(status == OK)
    {
        MocSmp_AddEntitytoList(pEntity) ;
        pSmpCurEntity = pEntity ;
    } else {
        DIGI_FREE((void **)&pEntity) ;
        pSmpCurEntity = NULL ;
    }
    exit:
        *pNextToken = s;
        return status;
}


static MSTATUS
ParseCredential( const sbyte** pNextToken)
{
    MSTATUS status;
    const sbyte* s;
    MocTapScript_Credential_t *pCred ;

    s = GetNextToken( *pNextToken);

    if (*s != '{')
    {
        status = ERR_TAP_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the { */

    if(!pSmpCurEntity) {
        status = ERR_TAP_SCRIPT_KEYWORD_ERROR;
        LOG_ERROR("no entity in scope, status = %d", status);
        goto exit;

    }
    status = DIGI_CALLOC((void **) &pCred, 1, sizeof(MocTapScript_Credential_t));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }
    while ( OK == status)
    {
        s = GetNextToken( s);
        if (0 == *s)
        {
            status = ERR_TAP_SCRIPT_UNEXPECTED_EOF;
            break;
        }
        if ('}' == *s)
        {
            ++s; /* jump over it */
            break;
        }
        status = ParseCredentialNameValuePair( &s,  pCred);
    }
    if(status == OK)
    {
        MocSmp_AddCredtoList(pSmpCurEntity, pCred) ;
    } else {
        LOG_ERROR("parse error, status = %d", status);
        DIGI_FREE((void **)&(pCred->credentialData.pBuffer)) ;
        DIGI_FREE((void **)&pCred) ;
    }

exit:
    *pNextToken = s;
    return status;

}

MSTATUS MocTap_ClearCredential(TAP_Credential *pCredential)
{
    MSTATUS status = OK;

    if (NULL == pCredential)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 != pCredential->credentialData.bufferLen) && (NULL != pCredential->credentialData.pBuffer))
    {
        status = shredMemory(&(pCredential->credentialData.pBuffer), pCredential->credentialData.bufferLen, TRUE);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for credential. status %d = %s\n", __FUNCTION__,
                   __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = DIGI_FREE((void **)&(pCredential));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for TAP_ClearCredentials. status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}


MSTATUS MocTap_ClearCredentialList(TAP_CredentialList *pCredentials)
{
    MSTATUS status = OK;
    MSTATUS errStatus = OK;
    int i = 0;

    if (NULL == pCredentials)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pCredentials->pCredentialList)
    {
        /* Empty list - not really an error */
        goto exit;
    }

    for (i = 0; i < pCredentials->numCredentials; i++)
    {
        status = MocTap_ClearCredential(&(pCredentials->pCredentialList[i]));
        if (OK != status)
        {
            errStatus = status;
            DB_PRINT("%s.%d Failed to free memory for credential %d. status %d = %s\n", __FUNCTION__,
                   __LINE__, i, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = DIGI_MEMSET((ubyte *)pCredentials, 0, sizeof(TAP_CredentialList));

exit:
    if ((OK == status) && (OK != errStatus))
        status = errStatus;

    return status;
}


MSTATUS MocTap_FreeUsageCredentials(TAP_EntityCredentialList **pUsageCred)
{
    sbyte4 i;
    TAP_EntityCredential *pEntityCred ;


    for(i=0 ; i < (*pUsageCred)->numCredentials; i++)
    {
        pEntityCred = &((*pUsageCred)->pEntityCredentials[i]) ;
        MocTap_ClearCredentialList(&(pEntityCred->credentialList));
        DIGI_FREE((void **) &(pEntityCred->credentialList.pCredentialList)) ;
    }
    DIGI_FREE((void **)&((*pUsageCred)->pEntityCredentials)) ;
    DIGI_FREE((void **)pUsageCred) ;
    *pUsageCred = NULL ;
    return OK ;
}


static MSTATUS MocTap_FreeCredential(MocTapScript_Entity_t *pEntity)
{
    MocTapScript_Credential_t *pCred ;

    pCred = pEntity->pHeadCred ;
    for( pCred = pEntity->pHeadCred ; pCred ; pCred = pEntity->pHeadCred)
    {
        pEntity->pHeadCred = pCred->pNext ;
        if(pCred->credentialData.pBuffer)
        {
            DIGI_FREE((void **)&(pCred->credentialData.pBuffer)) ;
        }
        DIGI_FREE((void **)&pCred) ;
    }
    return OK ;
}


static MSTATUS MocTap_FreeEntities(void)
{
    MocTapScript_Entity_t *pEntity ;


    pEntity = pSmpEntityHead ;
    for(; pEntity;  pEntity = pSmpEntityHead)
    {
        pSmpEntityHead = pEntity->pNextEntity ;
        MocTap_FreeCredential(pEntity) ;
        DIGI_FREE((void **)&pEntity) ;
    }
    pSmpEntityHead = NULL ;
    pSmpCurEntity = NULL ;
    nMocSmpEntities = 0;
    return OK ;
}


static MSTATUS MocTap_PrepareCredential(TAP_EntityCredentialList **pUsageCred)
{
    MocTapScript_Entity_t *pEntity ;
    TAP_EntityCredential *pEntityCred ;
    MocTapScript_Credential_t *pCred ;
    MSTATUS status = OK;
    sbyte4 i, j ;

    status = DIGI_CALLOC((void **)pUsageCred, 1, sizeof(TAP_EntityCredentialList)) ;
    if(!(*pUsageCred))
    {
        LOG_ERROR("no memory for UsageCredentials, status = %d", status);
        goto exit;

    }
    status = DIGI_CALLOC((void **)&((*pUsageCred)->pEntityCredentials), nMocSmpEntities,sizeof(TAP_EntityCredential)) ;
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory for entity credentials, status = %d", status);
        goto exit;
    }
    (*pUsageCred)->numCredentials = nMocSmpEntities ;
    pEntity = pSmpEntityHead ;
    for(i=0 ; (i< nMocSmpEntities && pEntity); i++, pEntity = pEntity->pNextEntity)
    {
        pEntityCred = &((*pUsageCred)->pEntityCredentials[i]) ;
        status = DIGI_CALLOC((void **) &(pEntityCred->credentialList.pCredentialList), pEntity->nCredential,
                        sizeof(TAP_Credential));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }
        pEntityCred->entityId = pEntity->entityId ;
        pEntityCred->entityType= pEntity->entityType;
        pEntityCred->parentId= pEntity->parentId;
        pEntityCred->parentType = pEntity->parentType;
        pEntityCred->credentialList.numCredentials = pEntity->nCredential ;
        pCred = pEntity->pHeadCred ;
        for(j = 0; (j < pEntity->nCredential && pCred); j++, pCred = pCred->pNext)
        {
            pEntityCred->credentialList.pCredentialList[j].credentialContext = pCred->credentialContext ;
            pEntityCred->credentialList.pCredentialList[j].credentialType= pCred->credentialType ;
            pEntityCred->credentialList.pCredentialList[j].credentialFormat= pCred->credentialFormat ;
            if (pCred->credentialData.bufferLen)
            {
                status = DIGI_CALLOC((void **)&pEntityCred->credentialList.pCredentialList[j].credentialData.pBuffer,
                        1, pCred->credentialData.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Failed to allocate credential data buffer, status %d", status);
                    goto exit;
                }

                pEntityCred->credentialList.pCredentialList[j].credentialData.bufferLen = pCred->credentialData.bufferLen;
                status = DIGI_MEMCPY(pEntityCred->credentialList.pCredentialList[j].credentialData.pBuffer,
                        pCred->credentialData.pBuffer, pCred->credentialData.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Failed to copy credential data buffer, status %d", status);
                    goto exit;
                }
            }
        }
    }

    exit:
        if(status != OK)
        {
            MocTap_FreeUsageCredentials(pUsageCred) ;
        }
    return status ;

}

static MSTATUS
StrGetSafeCpy(  sbyte** ppSafeStr,
                sbyte *pSrcStr,
                sbyte4 srcLen)
{
    MSTATUS status;
    if((srcLen > 0) && ('\0' == pSrcStr[srcLen-1]))
    {
        *ppSafeStr = pSrcStr;
        status = OK;
    }
    else
    {
        ubyte4 safeStrLen;
        if(srcLen > 0)
        {
            safeStrLen = srcLen+1;
            status = DIGI_MALLOC_MEMCPY( (void**)ppSafeStr, safeStrLen,
                                        (void*)pSrcStr, (safeStrLen-1));
        }
        else
        {
            safeStrLen = 1;
            status = DIGI_CALLOC((void**)ppSafeStr, 1, safeStrLen);
        }
        if(OK == status)
        {
            (*ppSafeStr)[safeStrLen-1] = '\0';
        }
    }
    return status;
}

static MSTATUS
StrFreeSafeCpy( sbyte** ppSafeStr,
                const sbyte *pSrcStr)
{
    MSTATUS status;

    if(*ppSafeStr == pSrcStr)
    {
        *ppSafeStr = NULL;
        status = OK;
    }
    else
    {
        status = DIGI_FREE((void**)ppSafeStr);
    }

    return status;
}

extern MSTATUS
MocSmp_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen,
      TAP_EntityCredentialList **pUsageCredentials)
{
    MSTATUS status = OK;
    sbyte* scriptContent_safe = NULL;
    const sbyte *pNextToken ;
    sbyte4 token;

    status = StrGetSafeCpy( &scriptContent_safe, scriptContent, scriptLen);
    if(status == OK){
        pNextToken = GetNextToken(scriptContent_safe);
        while (OK == status && *pNextToken)
        {
            status = MatchToken( &pNextToken, gEntityTokens,
                                COUNTOF( gEntityTokens), &token);
            if (token == UserEntity)
            {
                pSmpCurEntity = NULL ;
                status = ParseEntity(&pNextToken);
            }
            else if (token == entCredential)
            {
                status = ParseCredential(&pNextToken);
            }
            pNextToken = GetNextToken(pNextToken);
        }
    }

    /* go through the entity list */
    if(status == OK)
    {
        status = MocTap_PrepareCredential(pUsageCredentials) ;
    }
    else
    {
        *pUsageCredentials = NULL ;
    }
    MocTap_FreeEntities() ;
    StrFreeSafeCpy( &scriptContent_safe, scriptContent);
    return status;
}



#ifdef MOCTAP_CREDPARSER_MAIN
int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    const char *pUserCredFile = (const char *)"moc_usercredential.conf";
    TAP_Buffer userCredBuf = {0} ;
    TAP_EntityCredentialList *pUsageCredentials=NULL ;
    TAP_EntityCredential  *pCred ;
    TAP_Credential *pTapCred ;
    sbyte4 i, j ;

    DIGICERT_initDigicert();

    status = DIGICERT_readFile(pUserCredFile, &(userCredBuf.pBuffer),
                         &(userCredBuf.bufferLen));
    if (OK != status)
    {
        LOG_ERROR("Failed to read user credential file, status = %d", status);
        goto exit;
    }
    status = MocSmp_GetCredentialData(( sbyte *)userCredBuf.pBuffer, userCredBuf.bufferLen,
                &pUsageCredentials) ;
    if (OK != status)
    {
        LOG_ERROR("Failed to get user credential data from file, status = %d", status);
        goto exit;
    }

     printf("===============User credentail details==========\n") ;
     printf("no. of entity credentials %d\n", pUsageCredentials->numCredentials) ;
     for(i = 0; i < pUsageCredentials->numCredentials; i++)
    {
        pCred = &pUsageCredentials->pEntityCredentials[i] ;
        printf("parent type: %d parent id %llu\n", pCred->parentType, pCred->parentId) ;
        printf("entity type: %d entity id %llu\n", pCred->entityType, pCred->entityId) ;
        printf("no. of credentials %d\n", pCred->credentialList.numCredentials) ;
        for(j = 0; j < pCred->credentialList.numCredentials; j++)
        {
            pTapCred = &pCred->credentialList.pCredentialList[j] ;
            printf("\tcred type: %d  cred format %d\n", pTapCred->credentialType,
                      pTapCred->credentialFormat) ;
            printf("\tcred context: %d auth data len %d\n\n", pTapCred->credentialContext,
                    pTapCred->credentialData.bufferLen) ;
        }
        printf("\n---------------------------------------\n\n") ;
    }
exit:
        if (NULL != userCredBuf.pBuffer)
            DIGICERT_freeReadFile(&userCredBuf.pBuffer);
    MocTap_FreeUsageCredentials(&pUsageCredentials) ;

    DIGICERT_freeDigicert();
    return 0 ;
}
#endif /* MOCTAP_CREDPARSER_MAIN  */
