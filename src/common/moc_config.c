/*
 * moc_config.c
 *
 * Update Message - Configuration Parser
 *
 * Copyright Mocana Corp 2012. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

/*! \file moc_config.c NanoUpdate developer API implementation.

\since 6.0
\version 6.0 and later

! Flags
Do not have __DISABLE_MOCANA_COMMON_CONFIG_PARSER__ defined

! External Functions
This file contains the following public ($extern$) functions:

- CONFIG_skipSpace
- CONFIG_nextLine
- CONFIG_gotoValue
- CONFIG_parseData
- CONFIG_copyString
- CONFIG_copyUByte4

*/

#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"

#include "../common/moc_config.h"

#if (!defined(__DISABLE_MOCANA_COMMON_CONFIG_PARSER__))

/*--------------------------------------------------------------------------*/

ubyte4
CONFIG_skipSpace(ubyte* data, ubyte4 dataLeft)
{
    ubyte4 offset = 0;

    while ( offset < dataLeft)
    {
        if ( !MOC_ISSPACE(data[offset]))
        {
            break;
        }
        ++offset;
    }
    return offset;
}

/*--------------------------------------------------------------------------*/

ubyte4
CONFIG_nextLine(ubyte* line, ubyte4 dataLeft)
{
  ubyte4 offset = 0;

  while ( offset < dataLeft)
  {
    sbyte c = line[offset];
    if ( c == '\r' || c == '\n')
    {
      break;
    }
    ++offset;
  }

  return offset + CONFIG_skipSpace( line+offset, dataLeft-offset);
}

MSTATUS CONFIG_readToEOL(sbyte* text,ubyte4 bytesLeft, ubyte4* length){
   ubyte4 i;
   MSTATUS status = OK;

   *length = 0;
   if(!text){
       status = ERR_NULL_POINTER;
       goto exit;
   }
   for( i = 0; i < bytesLeft; i++){
       switch(text[i]){
           case '\r':
           case '\n':
               (*length) = i;
               goto exit;
       }
   }

    /* If we run out of bytes, assume that is the EOF */
   (*length) = bytesLeft;
exit:
    return status;
}



/*--------------------------------------------------------------------------*/
MSTATUS CONFIG_getValue(sbyte* line, ubyte4 bytesLeft, const sbyte* fieldName,
        sbyte delimChar, sbyte** value,  ubyte4* valueOffset, ubyte4* valueLen){
    MSTATUS status = OK;
    
    *valueOffset = 0;
    MOC_CHECK(CONFIG_gotoValue((ubyte*) line,bytesLeft,fieldName,delimChar,valueOffset));
    MOC_CHECK(CONFIG_readToEOL(line+*valueOffset,bytesLeft - *valueOffset,valueLen));
    MOC_CHECK(MOC_MALLOC((void**) value,*valueLen+1));
    MOC_CHECK(MOC_MEMCPY(*value,line+*valueOffset,*valueLen));

    (*value)[*valueLen] = '\0';

exit:
    return status;

}
/*--------------------------------------------------------------------------*/

MSTATUS
CONFIG_gotoValue(ubyte* line, ubyte4 dataLeft, const sbyte* fieldName,
	      sbyte delimChar, ubyte4* bytesUsed)
{
    /* jumps over the <white space> = <white space> */
    MSTATUS retVal = ERR_CONFIG_PARSER;
    ubyte4 offset = *bytesUsed ? *bytesUsed : MOC_STRLEN(fieldName);
    offset += CONFIG_skipSpace( line+offset, dataLeft-offset);

    if ( offset == dataLeft )
    {
        
	retVal = ERR_CONFIG_NO_VALUE;
        goto exit;
    }
    if ( line[offset] != delimChar)
    {
        
        offset += CONFIG_nextLine( line+offset, dataLeft-offset);
	retVal = ERR_CONFIG_MISSING_DELIM;
        goto exit;
    }

    offset++;  /* Pass the delim Char */
    offset += CONFIG_skipSpace( line+offset, dataLeft-offset );
    if ( offset == dataLeft )
    {
        
	retVal = ERR_CONFIG_MISSING_VALUE;
        goto exit;
    }

    retVal = OK;

exit:

    *bytesUsed = offset;
    return retVal;
}

/*--------------------------------------------------------------------------*/

MSTATUS
CONFIG_gotoSection(ubyte* line, ubyte4 dataLeft, const sbyte* fieldName,
	      ubyte4* bytesUsed)
{
    /* jumps over the <white space> = <white space> */
    MSTATUS retVal = ERR_CONFIG_PARSER;
    ubyte4 offset = *bytesUsed ? *bytesUsed : MOC_STRLEN(fieldName); 
    ubyte4 eolOffset = 0;

    retVal = CONFIG_readToEOL((sbyte *)line+offset, dataLeft-offset, &eolOffset);
    if (OK == retVal)
    {
        offset += eolOffset;
        /* Move past the EOL */
        offset++;
        if ( offset >= dataLeft )
        {
            retVal = ERR_CONFIG_MISSING_VALUE;
            goto exit;
        }
    }

exit:

    *bytesUsed = offset;
    return retVal;
}


/*--------------------------------------------------------------------------*/

MSTATUS
CONFIG_parseData(ubyte* data, ubyte4 dataLen, CONFIG_ConfigItem* configs)
{
  ubyte4 offset = 0;
  ubyte4 index;
  MSTATUS result = OK;
  ubyte found;

  /* jump over white space */
  while ( MOC_ISSPACE( *data))
  {
    ++data;
    --dataLen;
  }

  while (offset < dataLen)
  {
    found = 0;

    for (index = 0; configs[index].key; index++)
    {
      /* Quickly skip lines that are empty or begin with # */
      if ('#' == *(data+offset) || '\r' == *(data+offset) ||
	  '\n' == *(data+offset))
	break;

      if ( 0 == MOC_STRNICMP( (sbyte*)data+offset, configs[index].key, MOC_STRLEN(configs[index].key )))
      {
	ubyte4 used = MOC_STRLEN(configs[index].key);

	/* Only call the callback if it's not-NULL */
	if (configs[index].callback)
	{
	  found = 1;
	  result = configs[index].callback(data+offset, dataLen-offset,
					   configs[index].callback_arg, &used);
	  if (result != OK)
	    goto exit;

	  offset += used;
	}

	break;
      }
    }

    if (!found)
      offset += CONFIG_nextLine(data+offset, dataLen-offset);
  }

 exit:

  return result;
}

/*--------------------------------------------------------------------------*/

MSTATUS
CONFIG_copyString(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4 *bytesUsed)
{
    MSTATUS status;
    sbyte** targetString = (sbyte**)arg;
    ubyte4 offset = *bytesUsed;   /* defaults to key length */
    ubyte4 i, pathLen;
    sbyte* param;

    /* Make sure we have an argument */
    if (!targetString)
        return ERR_INVALID_ARG;

    /* And make sure the argument hasn't already been set! */
    if (*targetString)
        return ERR_CONFIG_DUPLICATE;

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte*)"<configfile>", '=', &offset)))
        return status;

    /* value is the target parameter */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && MOC_ISSPACE(line[i]); --i)
    {
    }

    /* param is the string between offset and i */
    /* it needs to be null terminated so we will make a copy */
    /* i >= offset */
    pathLen =  i + 2 - offset;
    param = (sbyte*) MALLOC( pathLen);
    if (!param)
    {
        /* Memory allocation failure for parameter string. */
	    return ERR_MEM_ALLOC_FAIL;
    }
    MOC_MEMCPY( param, line+offset, pathLen-1);
    param[pathLen-1] = 0;

    *targetString = param;
    return OK;
}

/*--------------------------------------------------------------------------*/

MSTATUS
CONFIG_copyUByte4(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4 *bytesUsed)
{
    MSTATUS status;
    ubyte4* targetInt = (ubyte4*)arg;
    ubyte4 offset = *bytesUsed;   /* defaults to key length */

    /* Make sure we have an argument */
    if (!targetInt)
        return ERR_INVALID_ARG;

    /* And make sure the argument hasn't already been set! */
    if (*targetInt && *targetInt != (ubyte4)-1)
        return ERR_CONFIG_DUPLICATE;

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte*)"<configfile>", '=', &offset)))
        return status;

    *targetInt = MOC_ATOL( (sbyte*)(line+offset), NULL);

    return OK;
}

#endif /* __DISABLE_MOCANA_COMMON_CONFIG_PARSER__ */
