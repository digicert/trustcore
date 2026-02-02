/*
 * xml_parse.c
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

#if ( defined (__ENABLE_DIGICERT_XML_PARSE__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/int64.h"
#include "../common/sizedbuffer.h"
#include "../common/xml_parse.h"



#include <string.h>
#include <stdio.h>

/* given input of "      <tag>" return "tag\0" */

extern MSTATUS findTagName(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagContents )
{
    MSTATUS status = OK;
    sbyte4 beginIndex = 0;
    sbyte4 endIndex = 0;
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_BEGIN_TAG;
        goto exit;
        
    }
    
    beginIndex = *bytesParsed + 1;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_END_TAG;
        goto exit;

    }
    
    endIndex = *bytesParsed ;
    
    *bytesParsed++;
    
    DIGI_MEMCPY(tagContents, pBuff+beginIndex, endIndex - beginIndex);
    
    DIGI_MEMCPY(tagContents+(endIndex - beginIndex), "\0", 2);

exit:
    return status;
    
}

extern MSTATUS findTagValue(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagValue )
{
    MSTATUS status = OK;
    sbyte4 beginIndex = 0;
    sbyte4 endIndex = 0;
    
    sbyte4 depth = 0;
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_BEGIN_TAG;
        goto exit;
        
    }
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_END_TAG;
        goto exit;
    }
    
    (*bytesParsed)++;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) == ' '); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_VALUE_NOT_FOUND;
        goto exit;
    }
    
    if ( *(pBuff+*bytesParsed) == '<' && *(pBuff+*bytesParsed+1) == '/')
        return ERR_XML_PARSE_END_TAG_TOO_EARLY;
    
    beginIndex = *bytesParsed;
    
    (*bytesParsed)++;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed >= maxBytesToParse) {
        
        status = ERR_XML_PARSE_VALUE_NOT_FOUND;
        goto exit;
        
    }
    
    endIndex = *bytesParsed;
    
    *bytesParsed++;
    
    DIGI_MEMCPY(tagValue, pBuff+beginIndex, endIndex - beginIndex);
    
    DIGI_MEMCPY(tagValue+(endIndex - beginIndex), "\0", 2);
    
#if 0
    /* come back to this later.  not necessary for now */
    /* handle case where value is after series of tags */
    if ( *(pBuff+*bytesParsed) == '<' )
    {
        depth++;
        /* handle case where value is after series of tags */
        
        while( depth != 0)
        {
            
            for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
            
            if (*bytesParsed == maxBytesToParse) {
                
                status = ERR_XML_PARSE_VALUE_NOT_FOUND;
                goto exit;
                            }
            
        }
        
    }
#endif

exit:
    return status;
    
}



#endif