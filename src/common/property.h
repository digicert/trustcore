/*
 * property.h
 *
 * Property Management Header
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


/*------------------------------------------------------------------*/

#ifndef __PROPERTY_HEADER__
#define __PROPERTY_HEADER__


/*------------------------------------------------------------------*/

#ifndef PROPERTY_HASH_TABLE_SIZE
#define PROPERTY_HASH_TABLE_SIZE        (127)
#endif

#ifndef PROPERTY_HASH_VALUE_BASE
#define PROPERTY_HASH_VALUE_BASE        (0x07090a0b)
#endif


/*------------------------------------------------------------------*/

enum propertyPolicies
{
    policyOverwriteAlways,
    policyOverwriteIfExists,
    policyOverwriteGreaterPriority,                     /* (property doesn't exist create it) or (property exists priority must be higher ) */
    policyOverwriteGreaterPriorityAndExists,            /* (priority must be greater) and (property must exist) */
    policyOverwriteGreaterEqualPriorityAndExists        /* (priority must be greater/equal) and (property must exist) */
};


/*------------------------------------------------------------------*/

typedef struct propertyTable
{
    hashTableOfPtrs*    pHashTable;

} propertyTable;


typedef MSTATUS (*OutputPropertyFunc)(void *pCookie, const ubyte *pPropertyName, const ubyte *pPropertyValue);

/*------------------------------------------------------------------*/

/* initialization/release */
MOC_EXTERN MSTATUS PROPERTY_newInstance(propertyTable **ppRetPropertyTable);
MOC_EXTERN MSTATUS PROPERTY_deleteInstance(propertyTable **ppDeletePropertyTable);

/* to serialize in */
MOC_EXTERN MSTATUS PROPERTY_addProperty(propertyTable *pPropertyTable, const sbyte *pPropertyName, const sbyte *pPropertyValue, ubyte4 propertyPriority, enum propertyPolicies propertyAddPolicy);
MOC_EXTERN MSTATUS PROPERTY_parseLines(propertyTable *pPropertyTable, const ubyte *pLines, ubyte4 lineBytes, ubyte4 propertyPriority, enum propertyPolicies propertyAddPolicy, void* pCookie, MSTATUS(*funcCallbackMalformedLine)(void *pCookie, const sbyte *pMalformedLine, ubyte4 lineNum));

/* to serialize out */
MOC_EXTERN MSTATUS PROPERTY_outputPropertyList(propertyTable *pPropertyTable, void *pCookie, OutputPropertyFunc funcOutputProperty);
MOC_EXTERN MSTATUS PROPERTY_outputSortedPropertyList(propertyTable *pPropertyTable, void *pCookie, OutputPropertyFunc funcOutputProperty);

/* for lookups */
MOC_EXTERN MSTATUS PROPERTY_findPropertyValue(propertyTable *pPropertyTable, const sbyte *pPropertyName, sbyte **ppRetPropertyValue, intBoolean *pRetFoundProperty);
MOC_EXTERN MSTATUS PROPERTY_releaseClonedPropertyValue(sbyte **ppRetPropertyValue);

#endif /* __PROPERTY_HEADER__ */
