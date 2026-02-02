/*
 * property.c
 *
 * Property Management
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


#include "../common/moptions.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/hash_value.h"
#include "../common/hash_table.h"
#include "../common/memory_debug.h"
#include "../common/redblack.h"
#include "../common/property.h"


/*------------------------------------------------------------------*/

typedef struct propertyDescr
{
    ubyte*      pName;
    ubyte4      nameLen;

    ubyte*      pValue;
    ubyte4      valueLen;

    ubyte4      priority;

} propertyDescr;


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_freePropertyDescr(propertyDescr **ppFreeProperty)
{
    if ((NULL != ppFreeProperty) && (NULL != *ppFreeProperty))
    {
        DIGI_FREE((void**) &(*ppFreeProperty)->pValue);
        DIGI_FREE((void**) &(*ppFreeProperty)->pName);
        DIGI_FREE((void**) ppFreeProperty);
    }

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_allocPropertyDescr(const sbyte *pPropertyName, const sbyte *pPropertyValue,
                            ubyte4 propertyPriority, propertyDescr **ppNewProperty)
{
    propertyDescr*  pProperty = NULL;
    ubyte4          propertyNameLength;
    ubyte4          propertyValueLength;
    MSTATUS         status;

    /* allocate a property, if none exists */
    if (OK != (status = DIGI_MALLOC((void **)&pProperty, sizeof(propertyDescr))))
        goto exit;

    DEBUG_RELABEL_MEMORY(pProperty);

    /* clear structure */
    if (OK > (status = DIGI_MEMSET((ubyte *)pProperty, 0x00, sizeof(propertyDescr))))
        goto exit;

    /* set length fields (include null string terminator in length) */
    pProperty->nameLen  = propertyNameLength  = 1 + DIGI_STRLEN(pPropertyName);
    pProperty->valueLen = propertyValueLength = 1 + DIGI_STRLEN(pPropertyValue);

    /* set priority */
    pProperty->priority = propertyPriority;

    /* allocate memory property fields */
    if (OK != (status = DIGI_MALLOC((void **)&(pProperty->pName), propertyNameLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pProperty->pName);

    if (OK != (status = DIGI_MALLOC((void **)&(pProperty->pValue), propertyValueLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pProperty->pValue);

    /* include null string terminator */
    if (OK > (status = DIGI_MEMCPY(pProperty->pName, pPropertyName, propertyNameLength)))
        goto exit;

    if (OK > (status = DIGI_MEMCPY(pProperty->pValue, pPropertyValue, propertyValueLength)))
        goto exit;

    *ppNewProperty = pProperty;
    pProperty = NULL;

exit:
    PROPERTY_freePropertyDescr(&pProperty);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_funcPtrAllocHashPtrElement(void *pHashCookie, hashTablePtrElement **ppNewElement)
{
    MSTATUS status;
    MOC_UNUSED(pHashCookie);

    status = DIGI_MALLOC((void **)ppNewElement, sizeof(hashTablePtrElement));

    DEBUG_RELABEL_MEMORY(*ppNewElement);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_funcPtrFreeHashPtrElement(void *pHashCookie, hashTablePtrElement *pDeleteElement)
{
    propertyDescr*  pProperty = (propertyDescr*) pDeleteElement->pAppData;
    MOC_UNUSED(pHashCookie);

    PROPERTY_freePropertyDescr(&pProperty);

    return DIGI_FREE((void **)(&pDeleteElement));
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_newInstance(propertyTable **ppRetPropertyTable)
{
    propertyTable*  pPropertyTable = NULL;
    MSTATUS         status;

    if (OK != (status = DIGI_MALLOC((void **)&pPropertyTable, sizeof(propertyTable))))
        goto exit;

    DEBUG_RELABEL_MEMORY(pPropertyTable);

    DIGI_MEMSET((ubyte *)pPropertyTable, 0x00, sizeof(propertyTable));

    if (OK > (status = HASH_TABLE_createPtrsTable(&pPropertyTable->pHashTable, PROPERTY_HASH_TABLE_SIZE, NULL,
                                                  PROPERTY_funcPtrAllocHashPtrElement, PROPERTY_funcPtrFreeHashPtrElement)))
    {
        goto exit;
    }

    *ppRetPropertyTable = pPropertyTable;
    pPropertyTable = NULL;

exit:
    PROPERTY_deleteInstance(&pPropertyTable);

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_deleteInstance(propertyTable **ppDeletePropertyTable)
{
    void*   pHashCookie;
    MSTATUS status = OK;

    if ((NULL == ppDeletePropertyTable) || (NULL == *ppDeletePropertyTable))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* release internal structures */
    HASH_TABLE_removePtrsTable(((*ppDeletePropertyTable)->pHashTable), &pHashCookie);

    /* release outer layer */
    DIGI_FREE((void **)(ppDeletePropertyTable));

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_matchTest(void *pTmpProperty, void *pPropertyName, intBoolean *pRetIsMatch)
{
    propertyDescr*  pProperty = (propertyDescr *)pTmpProperty;
    ubyte4          propertyNameLength = 1 + DIGI_STRLEN((sbyte *)pPropertyName);    /* include string terminator */
    MSTATUS         status = OK;

    *pRetIsMatch = FALSE;

    if (pProperty->nameLen == propertyNameLength)
    {
        sbyte4 result;

        if (OK > (status = DIGI_MEMCMP((const ubyte*) pProperty->pName,
                                      (const ubyte*) pPropertyName,
                                      propertyNameLength, &result)))
        {
            goto exit;
        }

        if (0 == result)
            *pRetIsMatch = TRUE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_ptrMatchTest(void *pProperty, void *pPropertToDelete, intBoolean *pRetIsMatch)
{
    /* simple test */
    *pRetIsMatch = (pProperty == pPropertToDelete) ? TRUE : FALSE;

    return OK;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_addProperty(propertyTable *pPropertyTable, const sbyte *pPropertyName, const sbyte *pPropertyValue, ubyte4 propertyPriority, enum propertyPolicies propertyAddPolicy)
{
    propertyDescr*  pPropertyToDelete = NULL;
    propertyDescr*  pProperty = NULL;
    propertyDescr*  pFoundProperty = NULL;
    intBoolean      doesPropertyAlreadyExist;
    ubyte4          propertyNameLength;
    ubyte4          hashValue;
    MSTATUS         status;

    if ((NULL == pPropertyTable) || (NULL == pPropertyName) || (NULL == pPropertyValue))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* include null string terminator for length */
    propertyNameLength = 1 + DIGI_STRLEN(pPropertyName);

    /* calc hash value */
    HASH_VALUE_hashGen(pPropertyName, propertyNameLength, PROPERTY_HASH_VALUE_BASE, &hashValue);

    /* see if the property already exists */
    if (OK > (status = HASH_TABLE_findPtr(pPropertyTable->pHashTable, hashValue,
                                          (void *)pPropertyName, PROPERTY_matchTest,
                                          (void**) &pFoundProperty, &doesPropertyAlreadyExist)))
    {
        goto exit;
    }

    if (OK > (status = PROPERTY_allocPropertyDescr(pPropertyName, pPropertyValue, propertyPriority, &pProperty)))
        goto exit;

    if (FALSE == doesPropertyAlreadyExist)
    {
        if ((policyOverwriteAlways == propertyAddPolicy) || (policyOverwriteGreaterPriority == propertyAddPolicy))
        {
            /* add to hash table */
            if (OK > (status = HASH_TABLE_addPtr(pPropertyTable->pHashTable, hashValue, pProperty)))
                goto exit;

            /* to prevent bad free */
            pProperty = NULL;
        }
    }
    else
    {
        /* the property exists! */
        intBoolean addPolicy = TRUE;

        if ((policyOverwriteGreaterPriority == propertyAddPolicy) && (!(pFoundProperty->priority < propertyPriority)))
            addPolicy = FALSE;
        else if ((policyOverwriteGreaterPriorityAndExists == propertyAddPolicy) && (!(pFoundProperty->priority < propertyPriority)))
            addPolicy = FALSE;
        else if ((policyOverwriteGreaterEqualPriorityAndExists == propertyAddPolicy) && (!(pFoundProperty->priority <= propertyPriority)))
            addPolicy = FALSE;

        if (TRUE == addPolicy)
        {
            intBoolean  hashValueFound;

            if (OK > (status = HASH_TABLE_deletePtr(pPropertyTable->pHashTable,
                                                    hashValue,
                                                    pFoundProperty,
                                                    PROPERTY_ptrMatchTest,
                                                    (void**) &pPropertyToDelete,
                                                    &hashValueFound)))
            {
                goto exit;
            }
            /* add new property descriptor to hash table */
            if (OK > (status = HASH_TABLE_addPtr(pPropertyTable->pHashTable, hashValue, pProperty)))
                goto exit;

            /* to prevent bad free */
            pProperty = NULL;
        }
    }

exit:
    if (NULL != pProperty)
    {
        PROPERTY_freePropertyDescr(&pProperty);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_parseMergeLine(propertyTable *pPropertyTable, const sbyte *pLine, ubyte4 propertyPriority, enum propertyPolicies propertyAddPolicy, sbyte4 *pIsLineMalformed)
{
    const sbyte*    pTmpPropertyName  = NULL;
    const sbyte*    pTmpPropertyValue = NULL;
    sbyte*          pPropertyName     = NULL;
    sbyte*          pPropertyValue    = NULL;
    ubyte4          propertyNameLen   = 0;
    ubyte4          propertyValueLen  = 0;
    MSTATUS         status = OK;

    /* in this instance, we will assume the input is good */
    *pIsLineMalformed = FALSE;

    /* skip white space at the start of the line */
    while ((' ' == *pLine) || ('\t' == *pLine))
        pLine++;

    /* nothing to do --- comment line */
    if ('#' == *pLine)
        goto exit;

    pTmpPropertyName = pLine;

    while (('\0' != *pLine) && (' ' != *pLine) && ('\t' != *pLine) && ('=' != *pLine))
    {
        propertyNameLen++;
        pLine++;
    }

    /* skip white space before the equal sign */
    while ((' ' == *pLine) || ('\t' == *pLine))
        pLine++;

    /* nothing to do empty line */
    if ('\0' == *pLine)
        goto exit;

    if ('=' != *pLine)
    {
        /* malformed line */
        *pIsLineMalformed = TRUE;
        goto exit;
    }

    /* skip past the equal sign */
    pLine++;

    /* skip white space after the equal sign */
    while ((' ' == *pLine) || ('\t' == *pLine))
        pLine++;

    pTmpPropertyValue = pLine;

    /* grab all text after the equal sign */
    while (0 != *pLine)
    {
        propertyValueLen++;
        pLine++;
    }

    /* allocate/copy C-string property name length */
    if (OK != (status = DIGI_MALLOC((void **)&pPropertyName, 1 + propertyNameLen)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pPropertyName);

    DIGI_MEMCPY(pPropertyName, pTmpPropertyName, propertyNameLen);
    pPropertyName[propertyNameLen] = 0;

    /* allocate/copy C-string property value length */
    if (OK != (status = DIGI_MALLOC((void **)&pPropertyValue, 1 + propertyValueLen)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pPropertyValue);

    DIGI_MEMCPY(pPropertyValue, pTmpPropertyValue, propertyValueLen);
    pPropertyValue[propertyValueLen] = 0;

    if (OK > (status = PROPERTY_addProperty(pPropertyTable, pPropertyName, pPropertyValue, propertyPriority, propertyAddPolicy)))
        goto exit;

exit:
    DIGI_FREE((void**) &pPropertyValue);
    DIGI_FREE((void**) &pPropertyName);

    return status;

} /* PROPERTY_parseMergeLine */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_parseLines(propertyTable *pPropertyTable,
                    const ubyte *pLines, ubyte4 lineBytes,
                    ubyte4 propertyPriority, enum propertyPolicies propertyAddPolicy,
                    void* pCookie,
                    MSTATUS(*funcCallbackMalformedLine)(void *pCookie, const sbyte *pMalformedLine, ubyte4 lineNum))
{
    intBoolean      isLineMalformed;
    const ubyte*    pTmpLine = NULL;
    sbyte*          pLine = NULL;
    ubyte4          lineNum = 1;
    ubyte4          lineLength;
    ubyte4          allocLineLength = 0;
    MSTATUS         status = ERR_INVALID_ARG;

    while (0 < lineBytes)
    {
        while ((0 < lineBytes) && (('\x0a' == *pLines) || ('\x0d' == *pLines)))
        {
            if ('\x0a' == *pLines)
                lineNum++;

            /* skip end of lines */
            pLines++;
            lineBytes--;
        }

        if (0 == lineBytes)
            break;

        pTmpLine = pLines;
        lineLength = 0;

        while ((0 < lineBytes) && ('\x0a' != *pLines) && ('\x0d' != *pLines))
        {
            /* read until end of line or buffer */
            pLines++;
            lineLength++;
            lineBytes--;
        }

        while ((0 < lineLength) && ((' ' == pTmpLine[lineLength - 1]) || ('\t' == pTmpLine[lineLength - 1])))
        {
            /* strip off trailing spaces or tabs */
            lineLength--;
        }

        /* move to next line, if line is blank */
        if (0 == lineLength)
            continue;

        if ((1 + lineLength) > allocLineLength)
        {
            /* free previous temp buffer */
            DIGI_FREE((void**) &pLine);

            /* alloc new temp buffer */
            allocLineLength = 16 + lineLength;

            if (OK != (status = DIGI_MALLOC((void **)&pLine, allocLineLength)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pLine);
        }

        /* clone property rule */
        DIGI_MEMCPY(pLine, pTmpLine, lineLength);
        pLine[lineLength] = 0;

        if (OK > (status = PROPERTY_parseMergeLine(pPropertyTable, pLine, propertyPriority, propertyAddPolicy, &isLineMalformed)))
            goto exit;

        if ((TRUE == isLineMalformed) && (NULL != funcCallbackMalformedLine))
        {
            if (OK > (status = funcCallbackMalformedLine(pCookie, pLine, lineNum)))
                goto exit;
        }
    }

exit:
    DIGI_FREE((void**) &pLine);

    return status;

} /* PROPERTY_parseLines */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_findPropertyValue(propertyTable *pPropertyTable,
                           const sbyte *pPropertyName, sbyte **ppRetPropertyValue,
                           intBoolean *pRetFoundProperty)
{
    propertyDescr*  pFoundProperty = NULL;
    intBoolean      foundHashValue;
    ubyte4          hashValue;
    ubyte4          propertyNameLength;
    MSTATUS         status;

    if ((NULL == pPropertyTable) || (NULL == pPropertyTable) || (NULL == pPropertyTable))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* setup */
    *ppRetPropertyValue = NULL;
    propertyNameLength = 1 + DIGI_STRLEN(pPropertyName);

    if (pRetFoundProperty)
        *pRetFoundProperty = FALSE;

    /* calc hash value */
    HASH_VALUE_hashGen(pPropertyName, propertyNameLength, PROPERTY_HASH_VALUE_BASE, &hashValue);

    /* lookup the property by name */
    if (OK > (status = HASH_TABLE_findPtr(pPropertyTable->pHashTable, hashValue,
                                          (void *)pPropertyName,
                                          PROPERTY_matchTest,
                                          (void**) &pFoundProperty,
                                          &foundHashValue)))
    {
        goto exit;
    }
    if (NULL != pFoundProperty)
    {
        if (pRetFoundProperty)
            *pRetFoundProperty = TRUE;

        if (0 < pFoundProperty->valueLen)
        {
            /* we found a property, clone the value */
            if (OK > (status = DIGI_MALLOC((void **)ppRetPropertyValue, pFoundProperty->valueLen)))
            {
                goto exit;
            }
            DEBUG_RELABEL_MEMORY(*ppRetPropertyValue);

            DIGI_MEMCPY(*ppRetPropertyValue, pFoundProperty->pValue,
                       pFoundProperty->valueLen);
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_releaseClonedPropertyValue(sbyte **ppRetPropertyValue)
{
    return DIGI_FREE((void**) ppRetPropertyValue);
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_outputPropertyList(propertyTable *pPropertyTable, void *pCookie,
                            OutputPropertyFunc funcOutputProperty)
{
    propertyDescr*  pProperty;
    void*           pBucketCookie = NULL;
    ubyte4          index = 0;
    MSTATUS         status = OK;

    while (NULL != (pProperty = (propertyDescr*) HASH_TABLE_iteratePtrTable(pPropertyTable->pHashTable,
                                                           &pBucketCookie, &index)))
    {
        if (OK > (status = funcOutputProperty(pCookie, pProperty->pName,
                                              pProperty->pValue)))
        {
            goto exit;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_redBlackCompare(const void *pRedBlackCookie, const void *pTmpProperty1, const void *pTmpProperty2, sbyte4 *pResult)
{
    const propertyDescr*    pProperty1 = (const propertyDescr*) pTmpProperty1;
    const propertyDescr*    pProperty2 = (const propertyDescr*) pTmpProperty2;
    MOC_UNUSED(pRedBlackCookie);

    return DIGI_MEMCMP(pProperty1->pName, pProperty2->pName, 1 + pProperty1->nameLen, pResult);
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PROPERTY_outputSortedPropertyList(propertyTable *pPropertyTable, void *pCookie,
                                  OutputPropertyFunc funcOutputProperty)
{
    redBlackTreeDescr*      pTree = NULL;
    redBlackListDescr*      pListTracker = NULL;
    void*                   pRedBlackCookie = NULL;
    void*                   pAllocCookie = NULL;
    propertyDescr*          pProperty;
    const propertyDescr*    pFoundProperty = NULL;
    void*                   pBucketCookie = NULL;
    ubyte4                  index = 0;
    MSTATUS                 status;

    if (OK > (status = REDBLACK_allocTree(&pTree, NULL, NULL, PROPERTY_redBlackCompare, pRedBlackCookie, pAllocCookie)))
        goto exit;

    while (NULL != (pProperty = (propertyDescr*) HASH_TABLE_iteratePtrTable(pPropertyTable->pHashTable, &pBucketCookie, &index)))
    {
        if (OK > (status = REDBLACK_findOrInsert(pTree, pProperty,
                                                 (const void**) &pFoundProperty)))
        {
            goto exit;
        }
    }

    if (OK > (status = REDBLACK_traverseListInit(pTree, &pListTracker)))
        goto exit;

    while ((OK <= (status = REDBLACK_traverseListGetNext(pListTracker,
                                                         (const void**) &pFoundProperty))) &&
           (NULL != pFoundProperty))
    {
        if (OK > (status = funcOutputProperty(pCookie, pFoundProperty->pName,
                                              pFoundProperty->pValue)))
        {
            goto exit;
        }
    }

exit:
	if (NULL != pListTracker)
		REDBLACK_traverseListFree(&pListTracker);

    REDBLACK_freeTree(&pTree, NULL, &pRedBlackCookie, &pAllocCookie);

    return status;

} /* PROPERTY_outputSortedPropertyList */


/*------------------------------------------------------------------*/
