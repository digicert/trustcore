/*
 * mjson.c
 *
 * Simple JSON parser
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

#ifdef __ENABLE_MOCANA_JSON_PARSER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mjson.h"

#include "../common/debug_console.h"

#if (defined(__KERNEL__))
#include <linux/kernel.h>       /* for printk */
#define DBG_PRINT              printk
#else
#include <stdio.h>              /* for printf */
/* For 'isdigit()' prototype */
#include <ctype.h>
#define DBG_PRINT              printf
#endif

#define MAX_NUMBER_STRING   (20)
#define MAX_CHAR_STRING     (256)

/** Internal structure describing the JSON context.
 *
 */
typedef struct MJSON_Ctx
{
    const sbyte*      parserBuf;
    ubyte4            parserBufLen;
    ubyte4            parserPos;
    ubyte4            tokenNext;
    sbyte4            tokenParent;
    JSON_TokenType*   tokens;
    ubyte4            tokenCount;
} MJSON_Ctx;

/** A type to map a 'JSON_XXX' type to a printable string
 *
 */
typedef struct typeTable
{
    ubyte    type;
    sbyte*   typeString;
} typeTable;

/** The table to map a all 'types' to a printable string.
 *
 */
static typeTable typeLookupTable[] =
{
        { JSON_Undefined, (sbyte*)"JSON_Undefined", },
        { JSON_Object, (sbyte*)"JSON_Object", },
        { JSON_String, (sbyte*)"JSON_String", },
        { JSON_Array, (sbyte*)"JSON_Array", },
        { JSON_Integer, (sbyte*)"JSON_Integer" },
        { JSON_Float, (sbyte*)"JSON_Float" },
        { JSON_True, (sbyte*)"JSON_True", },
        { JSON_False, (sbyte*)"JSON_False", },
        { JSON_Null, (sbyte*)"JSON_Null" }
};

/*---------------------------------------------------------------------------*/
/* Forward Declarations                                                      */
/*---------------------------------------------------------------------------*/

/** Initialize the context internals.
 *  <p>Sets all internal variables to initial values (= empty context).
 *
 *  @param jsonctx Pointer to the context instance.
 *
 */
static void JSON_initContextParser(MJSON_Ctx *jsonctx);

/** Free all memory held by context internal variables.
 *  <p>Release the buffer holding the JSON data
 *
 *  @param jsonctx Pointer to the context instance.
 *
 */
static void JSON_releaseInternalParserMemory(MJSON_Ctx *jsonctx);

/** Helper function to allocate a new 'token' entry while parsing the JSON string.
 *  <p>The internal 'token' array is expanded and the new entry is created.
 *
 *  @param jsonctx Pointer to the context instance.
 *  @param token   The pointer to a variable where the pointer to the newly created
 *                 'token' entry should be stored.
 */
static MSTATUS allocateToken(MJSON_Ctx *jsonctx,
                             JSON_TokenType **token);

/** Parse JSON data that represents a 'primitive' token value (e.g. a number) and
 *  fill the 'JSON_TokenType' instance.
 *  <p>The parsed value is stored in the referenced 'token' instance.
 *  <p>The JSON string section to be parsed is delimited by a 'start' and 'end' index.
 *     If the 'primitive' occupies 'zero' character entries, then these two indexes have
 *     the same value. That is, the value 'end - start' represents the true length of the
 *     string.
 *
 *  @param token
 *  @param parseString The JSON data string to parse.
 *  @param start       The index into the JSON string, where the primitive starts.
 *  @param end         The index into the JSON string, where the primitive end.
 *
 */
static MSTATUS fillPrimitiveToken(JSON_TokenType *token,
                                  const sbyte *parseString,
                                  ubyte4 start, ubyte4 end);

/** Fully parse JSON string that represents a non-string value.
 *  <p>This function applies JSON rules on 'special character' entries.
 *  <p>It will allocate a new 'JSON_TokenType' in the used context, and then
 *     call 'fillPrimitiveToken()' to fill the data fields of that new instance.
 *
 *  @param jsonctx       Pointer to the context instance.
 *  @param parseString   The JSON data string to parse.
 *  @param len           The length of the string section to be parsed.
 *  @param just_counting If true, this is the 'first pass' of the parser and we only
 *                       are counting the number tokens in the JSON data. Do not actually
 *                       fill and token data.
 *
 */
static MSTATUS parseJsonPrimitive(MJSON_Ctx *jsonctx,
                                  const sbyte *parseString, ubyte4 len,
                                  intBoolean just_counting);

/** Parse JSON string values.
 *  <p>This function applies JSON rules on the content of a string and the correct use
 *     of " (quote) symbol.
 *  <p>The parser expects the string to be delimited by quotes (start and end).
 *  <p>It will allocate a new 'JSON_TokenType' in the used context.
 *
 *  @param jsonctx       Pointer to the context instance.
 *  @param parseString   The JSON data string to parse.
 *  @param len           The length of the string section to be parsed.
 *  @param just_counting If true, this is the 'first pass' of the parser and we only
 *                       are counting the number tokens in the JSON data. Do not actually
 *                       fill and token data.
 */
static MSTATUS parseJsonString(MJSON_Ctx *jsonctx,
                               const sbyte *parseString, ubyte4 len,
                               intBoolean just_counting);


/*---------------------------------------------------------------------------*/

static void
JSON_initContextParser(MJSON_Ctx *jsonctx)
{
    if (NULL != jsonctx)
    {
        jsonctx->parserBuf = NULL;
        jsonctx->parserBufLen = 0;
        jsonctx->parserPos = 0;
        jsonctx->tokenNext = 0;
        jsonctx->tokenParent = -1;
        jsonctx->tokens = NULL;
        jsonctx->tokenCount = 0;
    }
}


/*---------------------------------------------------------------------------*/

static void
JSON_releaseInternalParserMemory(MJSON_Ctx *jsonctx)
{
    if (NULL != jsonctx)
    {
        if (NULL != jsonctx->tokens)
        {
            MOC_FREE((void **)&jsonctx->tokens);
        }
    }
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_acquireContext(JSON_ContextType **ppCxt)
{
    MSTATUS status = OK;
    MJSON_Ctx* jsonCxt = NULL;

    if (NULL == ppCxt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MOC_MALLOC((void**)&jsonCxt, sizeof(MJSON_Ctx));
    if (OK != status)
        goto exit;

    JSON_initContextParser(jsonCxt);

    *ppCxt = (JSON_ContextType *)jsonCxt;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_releaseContext(JSON_ContextType **ppCtx)
{
    MSTATUS status = OK;
    MJSON_Ctx *jsonctx = NULL;

    if ((NULL == ppCtx) ||
        (NULL == *ppCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    jsonctx = (MJSON_Ctx *)*ppCtx;

    if (NULL != jsonctx)
    {
    	JSON_releaseInternalParserMemory(jsonctx);
        MOC_FREE((void**)&jsonctx);
        *ppCtx = NULL;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
allocateToken(MJSON_Ctx* jsonctx, JSON_TokenType **token)
{
    MSTATUS status = OK;

    if (NULL == token)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (jsonctx->tokenNext >= jsonctx->tokenCount) {
    	*token = NULL;
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *token = &(jsonctx->tokens[jsonctx->tokenNext++]);
    status = MOC_MEMSET((ubyte *)*token, 0x0, sizeof(JSON_TokenType));

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
fillPrimitiveToken(JSON_TokenType *token, const sbyte *parseString,
                   ubyte4 start, ubyte4 end)
{
    MSTATUS status = OK;
    sbyte4 i  = 0;
    sbyte4 len  = end - start;
    sbyte  number[MAX_NUMBER_STRING + 1] = {0};
    sbyte4 dots = 0;
    sbyte4 preDigits = 0, postDigits = 0;
    intBoolean isNum = TRUE;

    if (MAX_NUMBER_STRING < len)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    snprintf((char*)number, sizeof(number), "%.*s", len, parseString + start);

    token->type = JSON_Undefined; /* In case it won't parse into a real primitive. */
    token->pStart = parseString + start;
    token->len = len;
    token->elemCnt = 0;

    /* Look for exact match of 'primitive type' names (ignoring case),
     * or try to read it as a valid number. */
    if ((4 == len) &&
        (0 == MOC_STRNICMP((const sbyte *)"true",
                           (const sbyte *)parseString + start, 4)) )
    {
    	token->type = JSON_True;
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
        token->num.floatVal = 0.0f;
#endif
        goto exit;
    }
    else if ((5 == len) &&
             (0 == MOC_STRNICMP((const sbyte *)"false",
                                (const sbyte *)parseString + start, 5)) )
    {
        token->type = JSON_False;
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
        token->num.floatVal = 0;
#endif
        goto exit;
    }
    else if ((4 == len) &&
             (0 == MOC_STRNICMP((const sbyte *)"null",
                                (const sbyte *)parseString + start, 4)) )
    {
        token->type = JSON_Null;
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
        token->num.floatVal = 0;
#endif
        goto exit;
    }
    else if (0 < len)
    { 	/* It should be a number... Make sure. */

        /* Determine if number is a integer or a double? */
    	/* Not supporting e format for exponents yet...  */
        for (i = 0; i < len; i++)
        {
            if ((i == 0) && ('-' == parseString[start + i]))
            {
                continue;
            }
            else if (FALSE != MOC_ISDIGIT(parseString[start + i]))
            {
                if (0 == dots)
                {
                    preDigits++;
                }
                else
                {
                    postDigits++;
                }
                continue;
            }
            else if ('.' == parseString[start + i])
            {
                dots++;
            }
            else
            {
                isNum = FALSE;
                break;
            }
        }

        if ((1 < dots) || (FALSE == isNum))
        {
			status = ERR_INVALID_INPUT;
			goto exit;
        }
        else if ((0 == dots) &&
                 (0 == preDigits))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        else if ((1 == dots) &&
                 ((0 == preDigits) || (0 == postDigits)))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (0 < dots)
        {
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
            token->type = JSON_Float;
            dots = sscanf((const char*)number, "%lf", &token->num.floatVal);
#else
            /* Floats are not supported */
            status = ERR_INVALID_INPUT;
            goto exit;
#endif
        }
        else
        {
            token->type = JSON_Integer;
            token->num.intVal = MOC_ATOL((const sbyte *)number,NULL);
            dots = 1;
         /*   dots = sscanf((const char*)number, "%lld", &token->num.intVal); */
        }
    }

    /* Special case? */
    if (1 != dots)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
parseJsonString(MJSON_Ctx *jsonctx, const sbyte *parseString,
                ubyte4 len, intBoolean just_counting)
{
	MSTATUS    status = OK;
	JSON_TokenType *tok;
	ubyte4     start = jsonctx->parserPos;
	intBoolean isHex = FALSE;

    jsonctx->parserPos++;

	/* Skip starting quote */
	for (; (jsonctx->parserPos < len) &&
	       ('\0' != parseString[jsonctx->parserPos]); jsonctx->parserPos++)
	{
		char c = parseString[jsonctx->parserPos];

		/* Quote: end of string */
		if ('\"' == c)
		{
			if (TRUE == just_counting)
			{
				return OK;
			}
			status = allocateToken(jsonctx, &tok);
			if (OK != status)
			{
				jsonctx->parserPos = start;
				goto exit;
			}

			tok->type = JSON_String;
			tok->pStart = parseString + start + 1;
			tok->len = jsonctx->parserPos - (start + 1);
			tok->elemCnt = 0;

			goto exit;
		}

		/* Backslash: Quoted symbol expected */
		if (('\\' == c) && (jsonctx->parserPos + 1 < len))
		{
			ubyte4 i = 0;
			jsonctx->parserPos++;

			switch (parseString[jsonctx->parserPos])
			{
			/* Allowed escaped symbols */
			case '\"': case '/' : case '\\' : case 'b' :
			case 'f' : case 'r' : case 'n' : case 't' :
				break;

			/* Allows escaped symbol \uXXXX */
			case 'u':
				jsonctx->parserPos++;
				for(i = 0; (4 > i) && (len > jsonctx->parserPos) &&
						   ('\0' != parseString[jsonctx->parserPos]); i++)
				{
					isHex = ( ((parseString[jsonctx->parserPos] >= '0') &&
							   (parseString[jsonctx->parserPos] <= '9')) ||
							  ((parseString[jsonctx->parserPos] >= 'A') &&
							   (parseString[jsonctx->parserPos] <= 'F')) ||
							  ((parseString[jsonctx->parserPos] >= 'a') &&
							   (parseString[jsonctx->parserPos] <= 'f')) );
					if (TRUE != isHex)
					{
					    jsonctx->parserPos = start;
					    status = ERR_INVALID_INPUT;
					    goto exit;
					}
					jsonctx->parserPos++;
				}
				jsonctx->parserPos--;
				break;

			/* Unexpected symbol */
			default:
			    jsonctx->parserPos = start;
			    status = ERR_INVALID_INPUT;
			    goto exit;
			}
		}
	}

    jsonctx->parserPos = start;
    status = ERR_INCOMPLETE_SEARCH;

exit:
	return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
parseJsonPrimitive(MJSON_Ctx *jsonctx, const sbyte *parseString,
                   ubyte4 len, intBoolean just_counting)
{
    MSTATUS status = OK;
    JSON_TokenType *tok;

    ubyte4 start = jsonctx->parserPos;
    jsonctx->parserPos++;

    for (; (jsonctx->parserPos < len) &&
           ('\0' != parseString[jsonctx->parserPos]); jsonctx->parserPos++)
    {
        if ( ('\t' == parseString[jsonctx->parserPos]) ||
                ('\r' == parseString[jsonctx->parserPos]) ||
                ('\n' == parseString[jsonctx->parserPos]) ||
                (' ' == parseString[jsonctx->parserPos]) ||
                (']' == parseString[jsonctx->parserPos]) ||
                ('}' == parseString[jsonctx->parserPos]) ||
                (',' == parseString[jsonctx->parserPos]) )
        {
            break;
        }
        else if ((' ' > parseString[jsonctx->parserPos]) ||
                ('~' < parseString[jsonctx->parserPos]))
        {
            jsonctx->parserPos = start;
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }

    if (TRUE == just_counting)
    {
        jsonctx->parserPos--;
        status = OK;
        goto exit;
    }

    status = allocateToken(jsonctx, &tok);
    if (OK != status)
    {
        jsonctx->parserPos = start;
        goto exit;
    }

    status = fillPrimitiveToken(tok, parseString, start, jsonctx->parserPos);
    if (OK != status)
        goto exit;

    jsonctx->parserPos--;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
JSON_parseInternal(MJSON_Ctx *jsonctx, ubyte4 *pNumTokensFound, intBoolean just_counting)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 parseLen = 0;
    int    i = 0;
    const sbyte    *parseString;
    JSON_TokenType *token = NULL;

    /* State flags for syntax checks:
     * (A) An object is an unordered set of name/value pairs. An object begins with
     *     { (left brace) and ends with } (right brace). Each name is followed by : (colon)
     *     and the name/value pairs are separated by , (comma).
     * (B) An array is an ordered collection of values. An array begins with [ (left bracket)
     *     and ends with ] (right bracket). Values are separated by , (comma).
     * (C) A value can be a string in double quotes, or a number, or true or false or null, or
     *     an object or an array. These structures can be nested.
     * (D) A string is a sequence of zero or more Unicode characters, wrapped in double
     *     quotes, using backslash escapes.
     */
    intBoolean unpairedEntry = FALSE;
    intBoolean expectComma  = FALSE;
    intBoolean expectColon  = FALSE;
    intBoolean expectString = FALSE;
    intBoolean expectValue  = FALSE;

    if (NULL == jsonctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    parseString = jsonctx->parserBuf;
    parseLen = jsonctx->parserBufLen;
    count = jsonctx->tokenNext;

    for (; (jsonctx->parserPos < parseLen) &&
           ('\0' != parseString[jsonctx->parserPos]); jsonctx->parserPos++)
    {
        char c;
        ubyte type;

        c = parseString[jsonctx->parserPos];
        switch (c)
        {
        case '{': case '[':
            unpairedEntry = FALSE;
            count++;
            if (TRUE == just_counting)
            {
                break;
            }

            if (TRUE == expectString)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            /* Start the object/array token. Filled in later on closing bracket */
            status = allocateToken(jsonctx, &token);
            if (OK != status)
                goto exit;

            if (-1 != jsonctx->tokenParent)
            {
                jsonctx->tokens[jsonctx->tokenParent].elemCnt++;
            }

            token->type = (c == '{' ? JSON_Object : JSON_Array);
            if (JSON_Object == token->type)
            {
                /* Next token should be a 'string' */
                expectString = TRUE;
                expectValue = FALSE;
                expectComma = FALSE;
                expectColon = FALSE;
            }
            else if (JSON_Array == token->type)
            {
                /* Next token should be a 'value' */
                expectString = FALSE;
                expectValue = TRUE;
                expectComma = FALSE;
                expectColon = FALSE;
            }
            token->pStart = parseString + jsonctx->parserPos;
            jsonctx->tokenParent = jsonctx->tokenNext - 1;
            break;

        case '}': case ']':
            if (TRUE == just_counting)
            {
                break;
            }

            if (TRUE == expectColon)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            type = ('}' == c ? JSON_Object : JSON_Array);
            /* Reset to initial values */
            expectString = FALSE;
            expectValue = FALSE;
            expectComma = FALSE;
            expectColon = FALSE;

            /* Back up to our opening bracket */
            for (i = jsonctx->tokenNext - 1; i >= 0; i--)
            {
                token = &(jsonctx->tokens[i]);
                if ( ((JSON_Object == token->type) ||
                      (JSON_Array == token->type)) &&
                	 ((NULL != token->pStart) && (0 == token->len)) )

                {
                    /* Error if unmatched closing bracket type */
                    if (token->type != type)
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    /* Next token should be a 'comma' or the delimiter */
                    expectString = FALSE;
                    expectValue = FALSE;
                    expectComma = TRUE;
                    expectColon = FALSE;

                    jsonctx->tokenParent = -1;
                    /* Update len info for this object or array... */
                    token->len = (ubyte4)(parseString + (jsonctx->parserPos + 1) - token->pStart);
                    break;
                }
            }

            /* Error if unmatched closing bracket */
            if (-1 == i)
            {
            	status = ERR_INVALID_INPUT;
            	goto exit;
            }

            /* Back up to next opening bracket */
            for (; i >= 0; i--)
            {
                token = &(jsonctx->tokens[i]);

                if ( ((JSON_Object == token->type) ||
                      (JSON_Array == token->type)) &&
                	 ((NULL != token->pStart) && (0 == token->len)) )
                {
                    jsonctx->tokenParent = i;
                    break;
                }
            }
            break;

        case '\"':
            unpairedEntry = FALSE;
            status = parseJsonString( jsonctx, parseString, parseLen, just_counting);
            if (OK != status)
                goto exit;

            count++;
            if (TRUE == just_counting)
            {
                break;
            }

            if ((FALSE == expectString) && (FALSE == expectValue))
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            if (NULL != token)
            {
                if ((JSON_Object == token->type) && (TRUE == expectString))
                {
                    /* Next token should be a ':' */
                    expectString = FALSE;
                    expectValue = FALSE;
                    expectComma = FALSE;
                    expectColon = TRUE;
                }
                else if ((JSON_Object == token->type)  && (TRUE == expectValue))
                {
                    /* Next token should be a ',' */
                    expectString = FALSE;
                    expectValue = FALSE;
                    expectComma = TRUE;
                    expectColon = FALSE;
                }
                else if ((JSON_Array == token->type)  && (TRUE == expectValue))
                {
                    /* Next token should be a ',' */
                    expectString = FALSE;
                    expectValue = FALSE;
                    expectComma = TRUE;
                    expectColon = FALSE;
                }
            }

            if (-1 != jsonctx->tokenParent)
            {
                jsonctx->tokens[jsonctx->tokenParent].elemCnt++;
            }
            break;

        case '\t' : case '\r' : case '\n' : case ' ':
            /* Any white space is a NO-OP */
            break;

        case ':':
            jsonctx->tokenParent = jsonctx->tokenNext - 1;
            unpairedEntry = TRUE;
            if (TRUE == just_counting)
            {
                break;
            }

            if (FALSE == expectColon)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }
            /* Next token should be a 'value' */
            expectColon = FALSE;
            expectValue = TRUE;
            break;

        case ',':
            if (TRUE == just_counting)
            {
                break;
            }
            if (FALSE == expectComma)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            if ((-1 != jsonctx->tokenParent) &&
                (JSON_Array != jsonctx->tokens[jsonctx->tokenParent].type) &&
                (JSON_Object != jsonctx->tokens[jsonctx->tokenParent].type))
            {
                for (i = jsonctx->tokenNext - 1; i >= 0; i--)
                {
                    if ((JSON_Array == jsonctx->tokens[i].type) ||
                        (JSON_Object == jsonctx->tokens[i].type))
                    {
                        if ((NULL != jsonctx->tokens[i].pStart) &&
                            (0 == jsonctx->tokens[i].len))
                        {
                            jsonctx->tokenParent = i;
                            break;
                        }
                    }
                }
            }

            if (-1 != jsonctx->tokenParent)
            {
                if (JSON_Object == jsonctx->tokens[jsonctx->tokenParent].type)
                {
                    /* Next token should be a 'string' */
                    expectString = TRUE;
                    expectValue = FALSE;
                    expectComma = FALSE;
                    expectColon = FALSE;
                }
                else if (JSON_Array == jsonctx->tokens[jsonctx->tokenParent].type)
                {
                    /* Next token should be a 'value' */
                    expectString = FALSE;
                    expectValue = TRUE;
                    expectComma = FALSE;
                    expectColon = FALSE;
                }
            }
            break;

        default:
            status = parseJsonPrimitive(jsonctx, parseString, parseLen, just_counting);
            if (OK != status)
                goto exit;
            unpairedEntry = FALSE;
            count++;
            if (TRUE == just_counting)
            {
                break;
            }
            if (FALSE == expectValue)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            /* Next token should be a ',' or a delimiter */
            expectValue = FALSE;
            expectComma = TRUE;

            if (-1 != jsonctx->tokenParent)
            {
                jsonctx->tokens[jsonctx->tokenParent].elemCnt++;
            }
            break;
        }
    }

    if (TRUE == unpairedEntry)
    {
        /* Left a dangling ':' */
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumTokensFound = count;

exit:
	return status;
}

/*---------------------------------------------------------------------------*/

/** NOTE: This function will parse a complete JSON data string, only.
 */

MOC_EXTERN MSTATUS
JSON_parse(JSON_ContextType *pCtx,
           const sbyte *parseString, ubyte4 parseStringLen,
           ubyte4 *pNumTokensFound)
{
    MSTATUS status = OK;
    MJSON_Ctx* jsonctx = NULL;
    ubyte4 count1 = 0;
    ubyte4 count2 = 0;

    if ((NULL == pCtx) ||
        (NULL == parseString) ||
        (NULL == pNumTokensFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    jsonctx = (MJSON_Ctx*)pCtx;

    if ((NULL != jsonctx->parserBuf) ||
        (NULL != jsonctx->tokens))
    {
        /* This parser has been used before. Clean up first */
    	JSON_releaseInternalParserMemory(jsonctx);
        JSON_initContextParser(jsonctx);
    }

    jsonctx->parserBuf = parseString;
    jsonctx->parserBufLen = parseStringLen;

    status = JSON_parseInternal(jsonctx, &count1, TRUE);
    /* Clean up our context whether an error or not. */
    JSON_initContextParser(jsonctx);

    if (OK != status)
    	goto exit;

#ifdef __MOCANA_JSON_HUGE_FILE__
    /* Use unlimited malloc() when it is expected that a very large JSON
     * text needs a large number of tokens
     */
    status = ERR_MEM_ALLOC_FAIL;
    jsonctx->tokens = malloc(count1*sizeof(JSON_TokenType));
    if ((void *)0 == jsonctx->tokens)
        goto exit;
#else
    status = MOC_MALLOC((void**)&jsonctx->tokens, count1*sizeof(JSON_TokenType));
    if (OK != status)
    	goto exit;
#endif

    MOC_MEMSET((ubyte*)jsonctx->tokens, 0, count1*sizeof(JSON_TokenType));
    jsonctx->tokenCount = count1;
    jsonctx->parserBuf = parseString;
    jsonctx->parserBufLen = parseStringLen;

    status = JSON_parseInternal(jsonctx, &count2, FALSE);
    if (OK != status)
    	goto exit;

    if (count1 != count2)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumTokensFound = count2;

exit:
    if (OK != status)
    {
        if (NULL != jsonctx)
        {
            /* Clean up our context if there's an error. */
            JSON_releaseInternalParserMemory(jsonctx);
            JSON_initContextParser(jsonctx);
        }
    }
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_getObjectIndex(JSON_ContextType *pCtx,
                    const sbyte* name, ubyte4 startingndx,
                    ubyte4 *ndx, intBoolean boundedSearch)
{
    MSTATUS        status = OK;
    ubyte4         i = 0;
    ubyte4         last_ndx = 0;
    MJSON_Ctx      *jsonctx = NULL;
    JSON_TokenType *ptoken;

    if ((NULL == pCtx) ||
        (NULL == name) ||
        (NULL == ndx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    jsonctx = (MJSON_Ctx*)pCtx;
    if (startingndx > jsonctx->tokenCount)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    if (TRUE == boundedSearch)
    {
        status = JSON_getLastIndexInObject (pCtx, startingndx, &last_ndx);
        if (OK != status)
            goto exit;
    }

    for (i = startingndx; i < jsonctx->tokenCount; i++)
    {
        ptoken = &(jsonctx->tokens[i]);

        if ((TRUE == boundedSearch) &&
            (last_ndx < i))
        {
            break;
        }

        if ((JSON_String == ptoken->type) && (0 < ptoken->len) &&
            (MOC_STRLEN((const sbyte*)name) == ptoken->len))
        {
            if (0 == MOC_STRNICMP(name,
                                  (const sbyte *)ptoken->pStart,
                                  ptoken->len))
            {
                *ndx = i;
                status = OK;
                goto exit;
            }
        }
    }
    status = ERR_NOT_FOUND;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_getLastIndexInObject(JSON_ContextType *pCtx,
                          ubyte4 startingndx, ubyte4 *last_ndx)
{
    MSTATUS        status = OK;
    ubyte4         i = 0;
    MJSON_Ctx      *jsonctx = NULL;
    const sbyte    *pEnd = NULL;
    JSON_TokenType *ptok;

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    jsonctx = (MJSON_Ctx*)pCtx;

    ptok = &(jsonctx->tokens[startingndx]);
    if (JSON_Object != ptok->type)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    pEnd = ptok->pStart + ptok->len;

    for (i = startingndx + 1; i < jsonctx->tokenCount; i++)
    {
        ptok = &(jsonctx->tokens[i]);
        if (pEnd < ptok->pStart)
        {
            break;
        }
    }
    *last_ndx = i - 1;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_getToken(JSON_ContextType *pCtx, ubyte4 ndx, JSON_TokenType *outputToken)
{
    MSTATUS status = OK;
    MJSON_Ctx *jsonctx = NULL;

    JSON_TokenType *ptok;

    if ((NULL == pCtx) ||
        (NULL == outputToken))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    jsonctx = (MJSON_Ctx*)pCtx;
    if (ndx >= jsonctx->tokenCount)
    {
    	status = ERR_INDEX_OOB;
    	goto exit;
    }

    ptok = &(jsonctx->tokens[ndx]);
    if ( (NULL == ptok) ||
         (ptok->pStart < jsonctx->parserBuf) ||
         (ptok->pStart >= jsonctx->parserBuf + jsonctx->parserBufLen) ||
         (ptok->pStart + ptok->len > jsonctx->parserBuf + jsonctx->parserBufLen))
    {
    	status = ERR_INDEX_OOB;
    	goto exit;
    }

    outputToken->type = ptok->type;
    outputToken->pStart = ptok->pStart;
    outputToken->len = ptok->len;
    outputToken->elemCnt = ptok->elemCnt;

    if (JSON_Integer == ptok->type)
    {
    	outputToken->num.intVal = ptok->num.intVal;
    }
    else if (JSON_Float == ptok->type)
    {
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
    	outputToken->num.floatVal = ptok->num.floatVal;
#else
    	/* Floats are not supported */
    	status = ERR_INVALID_INPUT;
    	goto exit;
#endif
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getNumTokens(JSON_ContextType *pCtx, ubyte4 *pNumTokensFound)
{
    MSTATUS status = OK;
    MJSON_Ctx *jsonctx = NULL;

    if ((NULL == pCtx) ||
        (NULL == pNumTokensFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    jsonctx = (MJSON_Ctx*)pCtx;

    *pNumTokensFound = jsonctx->tokenCount;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_utilReadJsonString(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex, sbyte* parentKeyName,
    sbyte* keyName, sbyte** ppvalueName, intBoolean boundedSearch)
{
    MSTATUS status = OK;
    sbyte *valueName = NULL;
    ubyte4 index = 0;
    JSON_TokenType token = {0};

    status = JSON_getObjectIndex(pJCtx, (sbyte*) keyName,
            jsonIndex + 1, &index, boundedSearch);
    if (ERR_NOT_FOUND == status)
    {
        goto exit;
    }

    status = JSON_getToken(pJCtx, index + 1, &token);
    if (JSON_String == token.type)
    {
        MOC_FREE ((void**)ppvalueName);
        status = MOC_CALLOC ((void**)&valueName, 1, token.len + 1);
        if (OK != status)
        {
            goto exit;
        }

        MOC_MEMCPY ( valueName, token.pStart, token.len);
        valueName[token.len] = '\0';
        *ppvalueName = valueName;
    }
    else
    {
        status = ERR_JSON_PARSE_FAILED;
        goto exit;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_utilReadJsonInt(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex, sbyte* parentKeyName,
    sbyte* keyName, sbyte4* pvalueName, intBoolean boundedSearch)
{
    MSTATUS status = OK;
    ubyte4 index = 0;
    JSON_TokenType token = {0};

    status = JSON_getObjectIndex(pJCtx, (sbyte*) keyName,
            jsonIndex + 1, &index, boundedSearch);
    if (ERR_NOT_FOUND == status)
    {
        goto exit;
    }

    status = JSON_getToken(pJCtx, index + 1, &token);
    if (JSON_Integer == token.type)
    {
        *pvalueName = (ubyte4)token.num.intVal;
    }
    else
    {
        status = ERR_JSON_PARSE_FAILED;
        goto exit;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_utilReadJsonBoolean(
    JSON_ContextType *pJCtx, ubyte4 jsonIndex, sbyte* parentKeyName,
    sbyte* keyName, intBoolean *pvalueName, intBoolean boundedSearch)
{
    MSTATUS status = OK;
    ubyte4 index = 0;
    JSON_TokenType token = {0};

    status = JSON_getObjectIndex(pJCtx, (sbyte *) keyName,
            jsonIndex + 1, &index, boundedSearch);
    if (ERR_NOT_FOUND == status)
    {
        goto exit;
    }

    status = JSON_getToken(pJCtx, index + 1, &token);
    if (JSON_True == token.type)
    {
        *pvalueName = TRUE;
    }
    else if (JSON_False == token.type)
    {
        *pvalueName = FALSE;
    }
    else
    {
        status = ERR_UM_JSON_PARSE_FAILED;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonString(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte **ppValue)
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    if (NULL == ppValue)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getToken(pJCtx, ndx, &token);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_String != token.type)
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

    status = MOC_MALLOC((void **) ppValue, token.len + 1);
    if (OK != status)
    {
        goto exit;
    }
    MOC_MEMCPY(*ppValue, token.pStart, token.len);
    (*ppValue)[token.len] = '\0';

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonTokenValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    JSON_TokenType *pToken,
    intBoolean boundedSearch)
{
    MSTATUS status;
    ubyte4 index = 0;

    status = JSON_getObjectIndex(
        pJCtx, pKeyName, ndx, &index, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    index++;
    status = JSON_getToken(pJCtx, index, pToken);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pNdx)
        *pNdx = index;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonBooleanValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    intBoolean *pValue,
    intBoolean boundedSearch)
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    if (NULL == pValue)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonTokenValue(
        pJCtx, ndx, pKeyName, NULL, &token, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_True == token.type)
    {
        *pValue = TRUE;
    }
    else if (JSON_False == token.type)
    {
        *pValue = FALSE;
    }
    else
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonIntegerValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    sbyte4 *pInteger,
    intBoolean boundedSearch)
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    if (NULL == pInteger)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonTokenValue(
        pJCtx, ndx, pKeyName, NULL, &token, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_Integer != token.type)
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

    *pInteger = (ubyte4) token.num.intVal;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonStringValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    sbyte **ppValue,
    intBoolean boundedSearch)
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    if (NULL == ppValue)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonTokenValue(
        pJCtx, ndx, pKeyName, NULL, &token, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_String != token.type)
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

    status = MOC_MALLOC((void **) ppValue, token.len + 1);
    if (OK != status)
    {
        goto exit;
    }
    MOC_MEMCPY(*ppValue, token.pStart, token.len);
    (*ppValue)[token.len] = '\0';

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonObjectIndex(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    intBoolean boundedSearch)
{
    MSTATUS status;
    ubyte4 index = 0;
    JSON_TokenType token = { 0 };

    if (NULL == pNdx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonTokenValue(
        pJCtx, ndx, pKeyName, &index, &token, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_Object != token.type)
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

    *pNdx = index;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JSON_getJsonArrayValue(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pKeyName,
    ubyte4 *pNdx,
    JSON_TokenType *pToken,
    intBoolean boundedSearch)
{
    MSTATUS status;
    ubyte4 index = 0;
    JSON_TokenType token = { 0 };

    if (NULL == pToken)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonTokenValue(
        pJCtx, ndx, pKeyName, &index, &token, boundedSearch);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_Array != token.type)
    {
        status = ERR_JSON_UNEXPECTED_TYPE;
        goto exit;
    }

    *pToken = token;
    if (NULL != pNdx)
        *pNdx = index;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_DBG_dumpContextInfo(JSON_ContextType *pCtx)
{
    MSTATUS   status = OK;
    MJSON_Ctx *jsonctx = NULL;

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    jsonctx = (MJSON_Ctx*)pCtx;

    DBG_PRINT("JSON_Ctx:vvv------------------\n");
    DBG_PRINT("JSON_Ctx.parserBuf    = %p\n", jsonctx->parserBuf);
    DBG_PRINT("JSON_Ctx.parserBufLen = %u\n", jsonctx->parserBufLen);
    DBG_PRINT("JSON_Ctx.parserPos    = %u\n", jsonctx->parserPos);
    DBG_PRINT("JSON_Ctx.tokenNext    = %u\n", jsonctx->tokenNext);
    DBG_PRINT("JSON_Ctx.tokenParent  = %d\n", jsonctx->tokenParent);
    DBG_PRINT("JSON_Ctx.tokens       = %p\n", jsonctx->tokens);
    DBG_PRINT("JSON_Ctx.tokenCount   = %u\n", jsonctx->tokenCount);
    DBG_PRINT("JSON_Ctx:^^^------------------\n");

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_DBG_dumpAllTokens(JSON_ContextType *pCtx,
                       intBoolean printFullObject)
{
    MSTATUS    status = OK;
    MJSON_Ctx *jsonctx = NULL;
    ubyte4     i;

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    jsonctx = (MJSON_Ctx*)pCtx;

    if ((NULL == jsonctx->tokens) || (0 == jsonctx->tokenCount))
    {
        DBG_PRINT("JSON_DumpTokens:vvv-----------------------------------\n");
        DBG_PRINT("JSON_DumpTokens:   <NO TOKENS FOUND> \n");
        DBG_PRINT("JSON_DumpTokens:^^^-----------------------------------\n");
        return OK;
    }
    DBG_PRINT("JSON_DumpTokens:vvv-----------------------------------\n");
    for (i = 0; i < jsonctx->tokenCount; i++)
    {
    	JSON_DBG_dumpToken(pCtx, i, printFullObject);
    }
    DBG_PRINT("JSON_DumpTokens:^^^-----------------------------------\n");

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

#define MAX_LINE_LEN 128

MOC_EXTERN MSTATUS
JSON_DBG_dumpToken(JSON_ContextType *pCtx,
                   ubyte4 ndx, intBoolean printFullObject)
{
    MSTATUS    status = OK;
    MJSON_Ctx  *jsonctx = NULL;
    JSON_TokenType *ptok;

    char smallprintbuf[MAX_LINE_LEN];
    sbyte *ptypestring = NULL;
    int  len;

    if (NULL == pCtx)
    {
        return ERR_NULL_POINTER;
    }
    jsonctx = (MJSON_Ctx*)pCtx;

    if (ndx >= jsonctx->tokenCount)
    {
        DBG_PRINT("Bad Index = %d\n", ndx);
    	return ERR_INDEX_OOB;
    }

    ptok = &(jsonctx->tokens[ndx]);
    if ((NULL == ptok) ||
        (ptok->pStart < jsonctx->parserBuf) ||
        (ptok->pStart >= jsonctx->parserBuf + jsonctx->parserBufLen) ||
        (ptok->pStart + ptok->len > jsonctx->parserBuf + jsonctx->parserBufLen))
    {
        DBG_PRINT("Token[%d].pStart-or-len is BAD.\n", ndx);
    	return ERR_INDEX_OOB;
    }

    DBG_PRINT("Token:vvv------------------\n");
    JSON_stringifyType(ptok->type, &ptypestring);
    DBG_PRINT("Token[%d].type    = %s\n", ndx, ptypestring);
    DBG_PRINT("Token[%d].pStart  = %p\n", ndx, ptok->pStart);
    DBG_PRINT("Token[%d].len     = %u\n", ndx, ptok->len);
    DBG_PRINT("Token[%d].elemCnt = %u\n", ndx, ptok->elemCnt);
    if (JSON_Integer == ptok->type)
    {
        DBG_PRINT("Token[%d].num.intVal   = %ld\n", ndx, (long int)ptok->num.intVal);
    }
    else if (JSON_Float == ptok->type)
    {
#ifndef __DISABLE_MOCANA_JSON_FLOAT_PARSER__
        DBG_PRINT("Token[%d].num.floatVal = %f\n", ndx, ptok->num.floatVal);
#else
        /* Floats are not supported */
        DBG_PRINT("Token[%d].num.floatVal = FLOAT_NOT_SUPPORTED.\n", ndx);
#endif
    }
    else if (JSON_String == ptok->type)
    {
        if (0 == ptok->len)
        {
            DBG_PRINT ("Token[%d].string  = <EMPTY_STRING>\n", ndx);
        }
        else
        {
            len = (MAX_LINE_LEN > ptok->len) ? ptok->len : MAX_LINE_LEN - 1;
            smallprintbuf[len] = '\0';
            MOC_MEMCPY(smallprintbuf, ptok->pStart, len);
            smallprintbuf[MAX_LINE_LEN - 1] = '\0';
            DBG_PRINT("Token[%d].string = \"%s\"\n", ndx, smallprintbuf);
        }
    }
    else if (JSON_Object == ptok->type)
    {
        if (TRUE == printFullObject)
        {
            DBG_PRINT("Token[%d].Object = %s\n", ndx, "NOT-IMPLEMENTED-YET");
        }
    }
    else if (JSON_Array == ptok->type)
    {
        if (TRUE == printFullObject)
        {
            DBG_PRINT("Token[%d].Array = %s\n", ndx, "NOT-IMPLEMENTED-YET");
        }
    }
    DBG_PRINT("Token:^^^------------------\n");

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
JSON_stringifyType(ubyte type, sbyte **stringType)
{
    MSTATUS    status = OK;
    ubyte4     index = 0;
    sbyte      *string = NULL;
    intBoolean found = FALSE;

    for (index = 0; index < (sizeof(typeLookupTable) / sizeof(typeTable)); index++)
    {
        if (type == typeLookupTable[index].type)
        {
            string = typeLookupTable[index].typeString;
            found = TRUE;
            break;
        }
    }

    if (FALSE == found)
    {
        *stringType = (sbyte *)"JSON_NotFound";
    }
    else
    {
        *stringType = string;
    }
    return status;
}

#endif /* __ENABLE_MOCANA_JSON_PARSER__ */
