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
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mudp.h"
#include "../../common/dynarray.h"
#include "../../common/base64.h"
#include "../tap_api.h"
#include "../tap_utils.h"
#include "moctap_credparser.h"
#include "moctap_tools_utils.h"


typedef struct Token
{
    const sbyte* m_str;
    sbyte4 m_len;
    sbyte4 m_extra;
} Token;

sbyte4 nMocTapEntities = 0 ;


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

MocTapScript_Entity_t *pEntityHead = NULL;
MocTapScript_Entity_t *pCurEntity = NULL ;



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

#ifndef LOG_ERROR
#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)
#endif

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
    MSTATUS status = OK;
    const sbyte* s = *pNextToken;

    if (pAuth == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pAuth->pBuffer = NULL;
    pAuth->bufferLen = 0 ;

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
    if(!numRead && ( *s != ']'))
    {
        status = ERR_TAP_SCRIPT_PARSE_ERROR;
        goto exit;
    }
    if(numRead)
    {
        pWs = s+numRead-1 ;
        while(IsWhiteSpace(*pWs))
        {
            nws++ ;
            pWs-- ;
        }
        status = MocTap_DecodeAuthData(
            (ubyte *) s, numRead-nws, &(pAuth->pBuffer), &(pAuth->bufferLen),
            FALSE);
        if (OK != status)
        {
            LOG_ERROR("Failed to decode auth attribute, status = %d", status);
            goto exit;
        }
    }

    if(( *s == ']'))
    {
        if (pAuth->pBuffer)
        {
            DIGI_FREE((void **)&pAuth->pBuffer);
        }
        pAuth->pBuffer = NULL;
        pAuth->bufferLen = 0 ;

    }

    *pNextToken = s ;
    *pNextToken += numRead+1;
    return status ;

exit:
    if ((NULL != pAuth) && (NULL != pAuth->pBuffer))
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

void MocTap_AddEntitytoList(MocTapScript_Entity_t *pEntity)
{
  if(!pEntityHead)
    pEntityHead = pEntity ;
  else
  {
      pEntity->pNextEntity = pEntityHead ;
      pEntityHead = pEntity ;
  }
  nMocTapEntities++ ;
}

void MocTap_AddCredtoList(MocTapScript_Entity_t *pEntity, MocTapScript_Credential_t *pCred)
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
    MSTATUS status = OK;
    const sbyte* s;
    sbyte4 token;
    MocTapScript_Entity_t *pEntity = NULL;


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
            status = ERR_TAP_SCRIPT_UNKNOWN_PATTERN;
            break;
        }
        if ((token == entCredential) || (token == UserEntity))
        {
            break;
        }
        status = ParseEntityNameValuePair( &s, pEntity);

    }
    if(status == OK)
    {
        MocTap_AddEntitytoList(pEntity) ;
        pCurEntity = pEntity ;
    }

exit:
    *pNextToken = s;

    if ((OK > status) && (pEntity))
    {
        DIGI_FREE((void **)&pEntity);
        pCurEntity = NULL ;
    }

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

    if(!pCurEntity) {
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
        MocTap_AddCredtoList(pCurEntity, pCred) ;
    }
    else
    {
        LOG_ERROR("parse error, status = %d", status);
        if (pCred)
        {
            if (pCred->credentialData.pBuffer)
                DIGI_FREE((void **)&(pCred->credentialData.pBuffer)) ;
            DIGI_FREE((void **)&pCred) ;
        }
    }

exit:
    *pNextToken = s;
    return status;

}

static MSTATUS MocTap_FreeUsageCredentials(TAP_EntityCredentialList **pUsageCred)
{
    ubyte4 i, j;
    TAP_EntityCredential *pEntityCred ;

    for(i=0 ; i < (*pUsageCred)->numCredentials; i++)
    {
        pEntityCred = &((*pUsageCred)->pEntityCredentials[i]) ;
        for(j = 0; (j < pEntityCred->credentialList.numCredentials); j++)
        {
            if(pEntityCred->credentialList.pCredentialList[j].credentialData.pBuffer)
                DIGI_FREE((void **)&(pEntityCred->credentialList.pCredentialList[j].credentialData.pBuffer)) ;
        }
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


    pEntity = pEntityHead ;
    for(; pEntity;  pEntity = pEntityHead)
    {
        pEntityHead = pEntity->pNextEntity ;
        MocTap_FreeCredential(pEntity) ;
        DIGI_FREE((void **)&pEntity) ;
    }
    pEntityHead = NULL ;
    pCurEntity = NULL ;
    nMocTapEntities = 0;
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
    status = DIGI_CALLOC((void **)&((*pUsageCred)->pEntityCredentials), nMocTapEntities,sizeof(TAP_EntityCredential)) ;
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory for entity credentials, status = %d", status);
        goto exit;
    }
    (*pUsageCred)->numCredentials = nMocTapEntities ;
    pEntity = pEntityHead ;
    for(i=0 ; (i< nMocTapEntities && pEntity); i++, pEntity = pEntity->pNextEntity)
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
            pEntityCred->credentialList.pCredentialList[j].credentialData.pBuffer = pCred->credentialData.pBuffer;
            pEntityCred->credentialList.pCredentialList[j].credentialData.bufferLen = pCred->credentialData.bufferLen;
            pCred->credentialData.pBuffer = NULL ;
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

MOC_EXTERN MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen,
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
                pCurEntity = NULL ;
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

#define MOCTAP_CREDPARSER_AUTH_PREFIX "-encoded-"

MOC_EXTERN MSTATUS
MocTap_EncodeAuthData(
    ubyte *pData, ubyte **ppAuth)
{
    MSTATUS status;
    ubyte *pTemp = NULL, *pEncoded = NULL;
    ubyte4 dataLen = 0, tempLen = 0, encodedLen = 0, prefixLen;

    if ((NULL == pData) || (NULL == ppAuth))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    dataLen = DIGI_STRLEN((const sbyte *) pData);

    if (0 != dataLen)
    {
        prefixLen = DIGI_STRLEN((const sbyte *) MOCTAP_CREDPARSER_AUTH_PREFIX);

        /* Encoding will be of the encoded prefix and the auth data */
        tempLen = dataLen + prefixLen;
        status = DIGI_MALLOC((void **) &pTemp, tempLen);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_MEMCPY(pTemp, (ubyte *) MOCTAP_CREDPARSER_AUTH_PREFIX, prefixLen);
        DIGI_MEMCPY(pTemp + prefixLen, pData, dataLen);

        status = BASE64_encodeMessage(pTemp, tempLen, &pEncoded, &encodedLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        /* Caller provided 0 length auth data. In this case do not add any
         * encoding prefix */
        pEncoded = (ubyte *) "";
        encodedLen = 0;
    }

    /* Allocate new buffer to fit NULL terminating character */
    status = DIGI_MALLOC_MEMCPY(
        (void **) ppAuth, encodedLen + 1, pEncoded, encodedLen);
    if (OK != status)
    {
        goto exit;
    }
    (*ppAuth)[encodedLen] = '\0';

exit:

    if ((NULL != pEncoded) && (0 != dataLen))
    {
        DIGI_MEMSET_FREE(&pEncoded, encodedLen);
    }

    if (NULL != pTemp)
    {
        DIGI_MEMSET_FREE(&pTemp, tempLen);
    }

    return status;
}

MOC_EXTERN MSTATUS
MocTap_DecodeAuthData(
    ubyte *pData, ubyte4 dataLen, ubyte **ppAuth, ubyte4 *pAuthLen,
    intBoolean nullTerminate)
{
    MSTATUS status;
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0, prefixLen, authLen, nullLen = 0;
    sbyte4 cmpRes = -1;

    if ( (NULL == pData) || (NULL == ppAuth) ||
         ((NULL == pAuthLen) && (FALSE == nullTerminate)) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    prefixLen = DIGI_STRLEN((const sbyte *) MOCTAP_CREDPARSER_AUTH_PREFIX);

    status = BASE64_decodeMessage(pData, dataLen, &pTemp, &tempLen);
    if ((OK == status) && (tempLen >= prefixLen))
    {
        /* Check for encoding prefix. If there is a prefix then use the base 64
         * decoded message, otherwise if the prefix is not present then the
         * auth data just happened to be using only base 64 characters
         */
        status = DIGI_MEMCMP(
            pTemp, (ubyte *) MOCTAP_CREDPARSER_AUTH_PREFIX, prefixLen, &cmpRes);
        if (OK != status)
        {
            goto exit;
        }
    }

    if (FALSE != nullTerminate)
    {
        nullLen = 1;
    }

    /* If cmpRes is 0 then there was a match for the encoding prefix. Return
     * the data after the encoding prefix.
     *
     * If cmpRes is not 0 then either the auth data wasn't able to be decoded
     * successfully or the auth data was decoded successfully but the encoding
     * prefix did not match. In either case copy the data as is.
     */
    if (cmpRes == 0)
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) ppAuth, tempLen - prefixLen + nullLen,
            pTemp + prefixLen, tempLen - prefixLen);
        if (OK != status)
        {
            goto exit;
        }
        authLen = tempLen - prefixLen;
    }
    else
    {
        /* Non base64, use value as is */
        status = DIGI_MALLOC_MEMCPY(
            (void **) ppAuth, dataLen + nullLen, pData, dataLen);
        if (OK != status)
        {
            goto exit;
        }
        authLen = dataLen;
    }
    if (FALSE != nullTerminate)
    {
        (*ppAuth)[authLen] = '\0';
    }
    if (NULL != pAuthLen)
    {
        *pAuthLen = authLen;
    }

exit:

    if (NULL != pTemp)
    {
        DIGI_MEMSET_FREE(&pTemp, tempLen);
    }

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
    status = MocTap_GetCredentialData(( sbyte *)userCredBuf.pBuffer, userCredBuf.bufferLen,
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





