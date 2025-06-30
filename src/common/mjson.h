/**
 * @file   mjson.h
 * @brief  Mocana JSON Parse utility functions.
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
 * @details  This header file provides declarations, definitions, enumerations,
 *           and structure definitions for parsing JSON strings.
 *
 * @flags    There are no flag dependencies to use this header file.
 *
 * @filedoc  mjson.h
 */

#ifndef __MJSON_HEADER__
#define __MJSON_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_Undefined          (0)
#define JSON_Object             (1)
#define JSON_String             (2)
#define JSON_Array              (3)
#define JSON_Integer            (4)
#define JSON_Float              (5)
#define JSON_True               (6)
#define JSON_False              (7)
#define JSON_Null               (8)

/** Structure to describe a JSON token.
 *  <p>The 'type' is set to one of the 'JSON_xxx' values, listed above.
 *  <p>The 'pStart' and 'len' parameters describe the 'string' section this token
 *     is occupying in the parsed JSON data. That means, for the 'JSON_String' type
 *     this is the 'value' of the token (excluding the " quotes), but for other types
 *     this may contain characters like '{' or '"'.
 *  <p>If the token represents an 'array' or 'object', the 'elemCnt' is set.
 *  <p>For any token that represents a 'number', the 'num' union is used the hold
 *     its value as an 'sbyte8' (JSON_Integer) or 'double' (JSON_Float).
 *  <p>All other non-numerical values are coded as part of the type, e.g.
 *  <ul>
 *  <li>'JSON_Null': Null
 *  <li>'JSON_False': Boolean 'false'
 *  <li>'JSON_True': Boolean 'true'
 *  </ul>
 */
typedef struct JSON_TokenType_S
{
    ubyte              type;
    const sbyte*       pStart;
    ubyte4             len;
    ubyte4             elemCnt;
    union
    {
#ifdef __ENABLE_MOCANA_64_BIT__
        sbyte8         intVal;
#else
        sbyte4         intVal;
#endif
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
        double         floatVal;
#endif
    } num;
} JSON_TokenType;

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* JSON_ContextType;  /* opaque structure */

/**
 * @brief   Create a context to parse JSON data.
 * @details Allocate a new instance.
 *
 * @param ppCtx The pointer to a variable where the pointer to the new context should be
 *              stored.
 * @return      \c OK (0) if successful; otherwise a negative number
 *              error code definition from merrors.h. To retrieve a
 *              string containing an English text error identifier
 *              corresponding to the function's returned error status,
 *              use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_acquireContext(JSON_ContextType **ppCtx);

/**
 * @brief   Release a context used for parsing JSON data.
 * @details Free any memory held by the context, and then release the context.
 *
 * @param ppCtx The pointer to a variable where the pointer to the context that will
 *              be released. The variable's content will be set to NULL.
 * @return      \c OK (0) if successful; otherwise a negative number
 *              error code definition from merrors.h. To retrieve a
 *              string containing an English text error identifier
 *              corresponding to the function's returned error status,
 *              use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_releaseContext(JSON_ContextType **ppCtx);

/**
 * @brief   Parse the JSON text and store its structure inside the context.
 * @details The JSON string has to be 'complete,' you can not 'update' the parser with another
 *           string, later.
 *          <p>If you parsed a string before with the same context, the context will be cleared
 *           before the (new) string is parsed.
 *          <p>In case the JSON string is invalid, an error code will be returned.
 *          <p>The JSON structure and values are accessed with 'JSON_getToken()' after this
 *           function returns 'OK'.
 *
 * @param pCtx            The pointer to the context that will be used.
 * @param parseString     The JSON string as a 'sbyte' array.
 * @param parseStringLen  The length of the JSON string.
 * @param pNumTokensFound Pointer to a variable where the number of found token in the JSON
 *                        string should be stored.
 * @return                \c OK (0) if successful; otherwise a negative number
 *                        error code definition from merrors.h. To retrieve a
 *                        string containing an English text error identifier
 *                        corresponding to the function's returned error status,
 *                        use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_parse(JSON_ContextType *pCtx,
                              const sbyte *parseString,
                              ubyte4 parseStringLen, ubyte4 *pNumTokensFound);

/**
 * @brief   Locate a JSON 'object' (name-value pair), by locating the name.
 * @details The location of a token is expressed as an index into a token 'array'. It
 *           can be passed to 'JSON_getToken()' to access its value.
 *          <p>The search of a 'name' can be started from a different point than the
 *           beginning of the token array. This is needed when the same 'name' occurs
 *           multiple times.
 *
 * @param pCtx        The pointer to the context.
 * @param name        The C-string containing the name string.
 * @param startingndx The index value where the search should start.
 * @param ndx         Pointer to a variable where the index value of the found name should
 *                    be stored.
 * @param boundedSearch Search only with the boundary of the JSON object.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_getObjectIndex(JSON_ContextType *pCtx,
                                       const sbyte* name,
                                       ubyte4 startingndx,  ubyte4 *ndx,
                                       intBoolean boundedSearch);

/**
 * @brief   Locate the last index of the  JSON 'object'.
 * @details Using the starting index, find the ending index of the object.
 *
 * @param pCtx          The pointer to the context.
 * @param startingndx   The index value where the search should start.
 * @param ndx           Pointer to a variable where the last index of the object.
 * @return              \c OK (0) if successful; otherwise a negative number
 *                      error code definition from merrors.h. To retrieve a
 *                      string containing an English text error identifier
 *                      corresponding to the function's returned error status,
 *                      use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_getLastIndexInObject(JSON_ContextType *pCtx,
                                       ubyte4 startingndx,
                                       ubyte4 *ndx);

/**
 * @brief   Obtain a copy of a 'JSON_TokeType' instance at a specified index.
 * @details To access the content of a JSON token, you use this function. You must use the
 *          index into the token 'array' to locate any instance stored in the context.
 *         <p>The data of the token in the 'array' is copied to the instance referenced by the
 *          caller.
 *         <p>Any memory referenced by the returned instance (e.g. pStart) is owned by the
 *          context.
 *
 * @param pCtx        The pointer to the context.
 * @param ndx         The index value, selecting an entry in the token array.
 * @param outputToken Pointer to the variable where the token type should be stored.
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_getToken(JSON_ContextType *pCtx,
                                 ubyte4 ndx, JSON_TokenType *outputToken);


/**
 * @brief   Function to obtain the number of tokens stored in the context.
 * @details This is the 'size' of the token array inside the context.
 *
 * @param pCtx            The pointer to the context.
 * @param pNumTokensFound Pointer to the variable, where the number of tokens
 *                        should be stored.
 * @return                \c OK (0) if successful; otherwise a negative number
 *                        error code definition from merrors.h. To retrieve a
 *                        string containing an English text error identifier
 *                        corresponding to the function's returned error status,
 *                        use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS JSON_getNumTokens(JSON_ContextType *pCtx,
                                     ubyte4 *pNumTokensFound);

/**
 * @brief   Utility function to obtain a printable string for a given 'type' value.
 * @details The valid type values are defined as 'JSON_XXX' at the beginning of this
 *          file
 *
 * @param type       The 'type' value of a JSON token.
 * @param stringType Pointer to the variable where the string pointer should be stored.
 * @return           \c OK (0) if successful; otherwise a negative number
 *                   error code definition from merrors.h. To retrieve a
 *                   string containing an English text error identifier
 *                   corresponding to the function's returned error status,
 *                   use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  JSON_stringifyType(ubyte type, sbyte **stringType);

/* Utility Functions */
MOC_EXTERN MSTATUS JSON_utilReadJsonBoolean(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex, sbyte* parentKeyName,
    sbyte* keyName, intBoolean *pvalueName, intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_utilReadJsonInt(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex,sbyte* parentKeyName,
    sbyte* keyName, sbyte4 *pvalueName, intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_utilReadJsonString(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex,sbyte* parentKeyName,
    sbyte* keyName, sbyte** ppvalueName, intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonString(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte **ppValue);

MOC_EXTERN MSTATUS JSON_getJsonTokenValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    JSON_TokenType *pToken,
    intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonBooleanValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    intBoolean *pValue,
    intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonIntegerValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    sbyte4 *pInteger,
    intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonStringValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    sbyte **ppValue,
    intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonObjectIndex(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    intBoolean boundedSearch);

MOC_EXTERN MSTATUS JSON_getJsonArrayValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    JSON_TokenType *pToken,
    intBoolean boundedSearch);

/* Debug Utility Functions */
MOC_EXTERN MSTATUS  JSON_DBG_dumpContextInfo(JSON_ContextType *pCtx);
MOC_EXTERN MSTATUS  JSON_DBG_dumpToken(JSON_ContextType *pCtx, ubyte4 ndx, intBoolean printFullObject);
MOC_EXTERN MSTATUS  JSON_DBG_dumpAllTokens(JSON_ContextType *pCtx, intBoolean printFullObject);

#ifdef __cplusplus
}
#endif

#endif /* __MJSON_HEADER__ */
