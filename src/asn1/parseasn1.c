/* ASN.1 object dumping code, copyright Peter Gutmann
   <pgut001@cs.auckland.ac.nz>, based on ASN.1 dump program by David Kemp
   <dpkemp@missi.ncsc.mil>, with contributions from various people including
   Matthew Hamrick <hamrick@rsa.com>, Bruno Couillard
   <bcouillard@chrysalis-its.com>, Hallvard Furuseth
   <h.b.furuseth@usit.uio.no>, Geoff Thorpe <geoff@raas.co.nz>, David Boyce
   <d.boyce@isode.com>, John Hughes <john.hughes@entegrity.com>, Life is hard,
   and then you die <ronald@trustpoint.com>, Hans-Olof Hermansson
   <hans-olof.hermansson@postnet.se>, Tor Rustad <Tor.Rustad@bbs.no>,
   Kjetil Barvik <kjetil.barvik@bbs.no>, James Sweeny <jsweeny@us.ibm.com>,
   and several other people whose names I've misplaced.  This code grew
   slowly over time without much design or planning, with features being
   tacked on as required.  It's not representative of my normal coding style.

   Available from http://www.cs.auckland.ac.nz/~pgut001/dumpasn1.c.
   Last updated 18 November 2002 (version 20021118, if you prefer it that
   way).  To build under Windows, use 'cl /MD dumpasn1.c'.  To build on OS390
   or z/OS, use '/bin/c89 -D OS390 -o dumpasn1 dumpasn1.c'.

   This version of dumpasn1 requires a config file dumpasn1.cfg to be present
   in the same location as the program itself or in a standard directory
   where binaries live (it will run without it but will display a warning
   message, you can configure the path either by hardcoding it in or using an
   environment variable as explained further down).  The config file is
   available from http://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg.

   This code assumes that the input data is binary, having come from a MIME-
   aware mailer or been piped through a decoding utility if the original
   format used base64 encoding.  If you need to decode it, it's recommended
   that you use a utility like uudeview, which will strip virtually any kind
   of encoding (MIME, PEM, PGP, whatever) to recover the binary original.

   You can use this code in whatever way you want, as long as you don't try
   to claim you wrote it.

   Editing notes: Tabs to 4, phasers to stun (and in case anyone wants to
   complain about that, see "Program Indentation and Comprehensiblity",
   Richard Miara, Joyce Musselman, Juan Navarro, and Ben Shneiderman,
   Communications of the ACM, Vol.26, No.11 (November 1983), p.861) */

/* The code described above was heavily modified, cleaned up
    However, the general decoding strategy is still the same. Therefore,
    we feel compelled to keep the notice above */

#include "../common/moptions.h"

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/dynarray.h"
#include "../common/memory_debug.h"
#include "../common/utf8.h"
#include "../crypto/rsa.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"

#include "../asn1/oidutils.h"

#include "../asn1/parseasn1.h"

#ifndef kMaxAsnParseStackDepth
#define kMaxAsnParseStackDepth          (40)
#endif

#define ASN_ERROR_NOT_RECOVERABLE(Status) \
   ((Status == ERR_NULL_POINTER) ||(Status == ERR_CERT_STACK_OVERFLOW) ||\
     (Status == ERR_MEM_ALLOC_FAIL) ||(Status == ERR_GENERAL))

typedef enum
{
   ASN_NODE_STATE_CREATE = 1,
   ASN_NODE_STATE_DONE,
   ASN_NODE_STATE_ERROR,
   ASN_NODE_STATE_MAX
} ASN1_ITEM_NODE_STATE;

/*internal structures*/
typedef struct SearchOIDInfo
{
    CStream         s;
    ubyte*          oid;
    byteBoolean     rootOnly;
    DynArray*       pDynArray;
} SearchOIDInfo;



/* static routine prototypes */
static MSTATUS      getValue(CStream s, const sbyte4 length, ubyte4 *pRetValue);
static MSTATUS      checkEncapsulate(CStream as, const ASN1_ITEM *parentItem, intBoolean *pRetBool);
static intBoolean   zeroLengthOK(const ASN1_ITEM *item);


/* visit tree routine to search OID */
static sbyte4 SearchOIDFun(TreeItem* treeItem, void* arg);


/*------------------------------------------------------------------*/

/* although the mem based stream implementation returned ERR_EOF, the
fseek() does not and advance past the EOF. It's necessary to check that
we don't go over the EOF for ASN.1 parsing of partial input */

static MSTATUS
ASN1_advanceStream(CStream as, ASN1_ITEM* pItem)
{
    sbyte4 filePos, fileSize;

    /* compute the total size */
    filePos = CS_tell(as);
    CS_seek( as, 0, MOCANA_SEEK_END);
    fileSize = CS_tell(as);
    CS_seek( as, filePos, MOCANA_SEEK_SET);
    if (pItem->length > (ubyte4)(fileSize - filePos))
    {
        return ERR_EOF;
    }
    CS_seek(as, (/*FSL*/sbyte4)pItem->length, MOCANA_SEEK_CUR);
    return OK;

}


/*------------------------------------------------------------------*/

/* Get an integer value */
static MSTATUS
getValue(CStream s, const sbyte4 length, ubyte4 *pRetValue)
{
    ubyte4  value;
    ubyte   ch;
    sbyte4  i;
    MSTATUS status;

    if (NULL == pRetValue)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CS_getc(s, &ch)))
        goto exit;

    value = ch;

    for (i = 0; i < length - 1; i++)
    {
        if (OK > (status = CS_getc(s, &ch)))
            goto exit;

        value = (value << 8) | ch;
    }

    *pRetValue = value;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Get an ASN.1 objects tag and length */
static MSTATUS
getItem(CStream as, ASN1_ITEM **newItem, intBoolean isStrictTest)
{
    ubyte       tagTemp;
    ubyte4      tag;
    ubyte       length;
    sbyte4      index = 0;
    ASN1_ITEM*  item = (ASN1_ITEM*)TREE_MakeNewTreeItem(sizeof(ASN1_ITEM));
    MSTATUS     strictError = OK;
    MSTATUS     status = OK;

    DEBUG_RELABEL_MEMORY(item);

    if (NULL == item)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)item, 0, sizeof(ASN1_ITEM));

    item->indefinite = FALSE;

    if (OK > (strictError = CS_getc(as, &tagTemp)))
        goto exit;

    tag                   = tagTemp;
    index++;
    item->id              = tag & ~TAG_MASK;
    tag                   = tag & TAG_MASK;

    if (TAG_MASK == tag)
    {
        ubyte value;

        /* Long tag encoded as sequence of 7-bit values.  This doesn't try to
           handle tags > INT_MAX, it'd be pretty peculiar ASN.1 if it had to
           use tags this large */
        tag = 0;

        do
        {
            if (OK > (strictError = CS_getc(as, &value)))
                goto exit;

            tag = ((tag << 7) | (value & 0x7F));
            index++;

        }
        while ((value & LEN_XTND) && (index < 5) && (!CS_eof(as)));

        if (index == 5)
        {
            strictError = ERR_ASN_UNEXPECTED_END;
            goto exit;
        }
    }

    item->tag = tag;

    if (CS_eof(as))
    {
        strictError = ERR_EOF;
        goto exit;
    }

    if (OK > (strictError = CS_getc(as, &length)))
        goto exit;

    index++;
    item->headerSize = (/*FSL*/ubyte4)index;

    if (length & LEN_XTND)
    {
        sbyte4 i;

        length &= LEN_MASK;

        if (4 < length)
        {
            /* impossible length value, probably because we've run into the weeds */
            strictError = ERR_ASN_BAD_LENGTH_FIELD;
            goto exit;
        }

        item->headerSize += length;
        item->length = 0;

        if (!length)
        {
            item->indefinite = TRUE;
        }

        for (i = 0; i < length; i++)
        {
            ubyte ch;

            if (OK > (strictError = CS_getc(as, &ch)))
                goto exit;

            item->length = (item->length << 8) | ch;
        }
    }
    else
    {
        item->length = length;
    }

    *newItem = item;
    item->dataOffset = CS_tell(as);
    item = NULL;

exit:
    if ((OK <= status) && (isStrictTest))
        status = strictError;

    if (NULL != item)
        TREE_DeleteTreeItem((TreeItem *)item);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
ASN1_GetItemHeader(CStream as, ubyte4 offset, ASN1_ITEM **newItem)
{
    MSTATUS status;
    sbyte4 filePos, fileSize;

    if (!newItem)
        return ERR_NULL_POINTER;

    *newItem = 0;

    /* compute the total size */
    filePos = CS_tell(as);
    CS_seek( as, 0, MOCANA_SEEK_END);
    fileSize = CS_tell(as);

    if (((sbyte4)offset) > fileSize)
    {
        status = ERR_EOF;
        goto exit;
    }

    CS_seek( as, (/*FSL*/sbyte4)offset, MOCANA_SEEK_SET);

    status = getItem( as, newItem, TRUE);

exit:

    CS_seek(as, filePos, MOCANA_SEEK_SET);
    return status;
}


/*------------------------------------------------------------------*/

/* Check whether a BIT STRING or OCTET STRING encapsulates another object */
static MSTATUS
checkEncapsulate(CStream as, const ASN1_ITEM *parentItem, intBoolean *pRetBool)
{
    ASN1_ITEM*      nestedItem = NULL;
    const sbyte4    currentPos = CS_tell(as);
    sbyte4          diffPos;
    MSTATUS         status;

    *pRetBool = FALSE;

    if (NULL == parentItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Read the details of the next item in the input stream */
    if ((OK > (status = getItem(as, &nestedItem, FALSE))) ||
            (!nestedItem))
    {
        goto exit;
    }

    diffPos = CS_tell(as) - currentPos;

    /* if it fits exactly within the current item and has a valid-looking */
    /* tag, treat it as nested data */
    if (BITSTRING == parentItem->tag)
    {
        *pRetBool = (((nestedItem->id & CLASS_MASK) == UNIVERSAL ||
                      (nestedItem->id & CLASS_MASK) == CONTEXT ) &&
                      (SEQUENCE == nestedItem->tag) &&
                      (nestedItem->length == parentItem->length - diffPos));

        if (*pRetBool)
        {
            /* further validate that this is a nested BITSTRING */
            TREE_DeleteTreeItem((TreeItem*)nestedItem);
            nestedItem = NULL;

            if ((OK > (status = getItem(as, &nestedItem, FALSE))) ||
                (!nestedItem) )
            {
                goto exit;
            }

            diffPos = CS_tell(as) - currentPos;

            /* only integers may be nested within a BITSTRING */
            *pRetBool = ((((nestedItem->id & CLASS_MASK) == UNIVERSAL) ||
                          ((nestedItem->id & CLASS_MASK) == CONTEXT)   ) &&
                          (INTEGER == nestedItem->tag) &&
                          (nestedItem->length < parentItem->length - diffPos));
        }
    }
    else
    {
        *pRetBool = ((((nestedItem->id & CLASS_MASK ) == UNIVERSAL) ||
                         ((nestedItem->id & CLASS_MASK ) == CONTEXT)    ) &&
                         ( nestedItem->tag > 0 && nestedItem->tag <= 0x31 ) &&
                         (nestedItem->length == parentItem->length - diffPos));
    }

exit:
    /* go back */
    diffPos = CS_tell(as) - currentPos;
    CS_seek(as, -diffPos, MOCANA_SEEK_CUR);

    if (nestedItem)
    {
        TREE_DeleteTreeItem((TreeItem*) nestedItem);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Check whether a zero-length item is OK */
static intBoolean
zeroLengthOK(const ASN1_ITEM *item)
{
    /* An implicitly-tagged NULL can have a zero length.  An occurrence of this
       type of item is almost always an error, however OCSP uses a weird status
       encoding which encodes result values in tags and then has to use a NULL
       value to indicate that there's nothing there except the tag which encodes
       the status, so we allow this as well if zero-length content is explicitly
       enabled */
    if (NULL == item)
    {
        return FALSE;
    }

#ifndef __DISABLE_DIGICERT_ASN1_ZERO_LENGTH_ALLOWED__
    if((item->id & CLASS_MASK) == CONTEXT)
    {
        return(TRUE);
    }
#endif

    /* If we can't recognise the type from the tag, reject it */
    if((item->id & CLASS_MASK) != UNIVERSAL)
    {
        return(FALSE);
    }

    /* The following types are zero-length by definition */
    if(item->tag == EOC || item->tag == NULLTAG)
    {
        return(TRUE);
    }

    /* A real with a value of zero has zero length */
    if(item->tag == REAL)
    {
        return(TRUE);
    }

#ifndef __DISABLE_DIGICERT_ASN1_ZERO_LENGTH_ALLOWED__
    /* An integer value of zero can have zero length. Though this is
       technically not allowed according to the ASN1 spec, there are
       CSRs in the wild that exhibit this quirk */
    if(item->tag == INTEGER)
    {
        return(TRUE);
    }
#endif

    /* String types can have zero length except for the Unrestricted
       Character String type ([UNIVERSAL 29]) which has to have at least one
       octet for the CH-A/CH-B index */
    if(item->tag == OCTETSTRING || item->tag == NUMERICSTRING || \
        item->tag == PRINTABLESTRING || item->tag == T61STRING || \
        item->tag == VIDEOTEXSTRING || item->tag == VISIBLESTRING || \
        item->tag == IA5STRING || item->tag == GRAPHICSTRING || \
        item->tag == GENERALSTRING || item->tag == UNIVERSALSTRING || \
        item->tag == BMPSTRING || item->tag == UTF8STRING || \
        item->tag == OBJDESCRIPTOR)
    {
        return(TRUE);
    }

    /* Everything after this point requires input from the user to say that
       zero-length data is OK (usually it's not, so we flag it as a
       problem) */
#ifdef __DISABLE_DIGICERT_ASN1_ZERO_LENGTH_ALLOWED__
        return(FALSE);
#else
    /* SEQUENCE and MOC_SET can be zero if there are absent optional/default
       components */
    return (item->tag == SEQUENCE || item->tag == MOC_SET);
#endif
}


/*------------------------------------------------------------------*/

/*
  Routine Description:

   parse the body of the ASN 1 object. assumes that current position in the
   stream is at the start of the object's data part (just beyond the object's
   header part).
   if object type is a primitive ASN 1 object, this function will jump over
   the object's data field.

 Arguments:
   as            - stream pointing to object's data field
   item          - pointer to the object who's data we would like to process.
   pIsPrimitive  - on return , if status is OK , this will hold a boolean value
                    indicating if the object type is a primitive object.

Returns:
   OK   parsing succeeded
   else error occured (see CS_getc() , CS_seek() , getValue() and checkEncapsulate()
                             for more error codes)
*/
static MSTATUS
ASN1_ParseASN1object(CStream as, ASN1_ITEM *item, intBoolean* pIsPrimitive)
{
    intBoolean  retBool;
    MSTATUS     status = OK;

    if (!item || !pIsPrimitive)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((item->id & CLASS_MASK) != UNIVERSAL)
    {
        if(!item->length && !item->indefinite && !zeroLengthOK(item))
        {
            /* zero length */
            status = ERR_ASN_ZERO_LENGTH;
            goto exit;
        }

        /* for primitives non universal types, just jump over the data */
        if((item->id & FORM_MASK) == PRIMITIVE)
        {
            *pIsPrimitive = TRUE;
            status = ASN1_advanceStream(as, item);
            goto exit;
        }
    }

    /* If it's constructed, just return to the loop to parse
    the sub items */
    if((item->id & FORM_MASK) == CONSTRUCTED)
    {
        *pIsPrimitive = FALSE;
        goto exit;
    }

    /* UNIVERSAL -PRIMITIVE -- parse the primitive type */
    if(!item->length && !zeroLengthOK(item))
    {
        /* zero length */
        status = ERR_ASN_ZERO_LENGTH;
        goto exit;
    }

    /* it's primitive unless BITSTRING or OCTETSTRING encapsulates */
    *pIsPrimitive = TRUE;
    switch(item->tag)
    {
        case BOOLEAN:
            if (OK > (status = CS_getc(as, (ubyte *)&item->data.m_boolVal)))
                goto exit;
            break;

        case INTEGER:
        case ENUMERATED:
#ifndef __DISABLE_DIGICERT_ASN1_ZERO_LENGTH_ALLOWED__
            if(item->length > 4 || item->length == 0)
#else
            if(item->length > 4)
#endif
            {
                /* jump over the data */
                if (OK > (status = ASN1_advanceStream(as, item)))
                    goto exit;
            }
            else
            {
                if (OK > (status = getValue(as, (/*FSL*/sbyte4)item->length, (ubyte4 *)&(item->data.m_intVal))))
                    goto exit;
            }
            break;

        case BITSTRING:
            /* first byte is the number of unused bits */

            if (OK > (status = CS_getc(as, &item->data.m_unusedBits)))
                goto exit;

            --item->length;
            ++item->dataOffset;

            if (0 == item->length && item->data.m_unusedBits !=0)
            {
                status = ERR_ASN_ZERO_LENGTH;
                goto exit;
            }

            /* note - fall through is intentional */

        case OCTETSTRING:

            if (OK > (status = checkEncapsulate(as, item, &retBool)))
                goto exit;

            if (retBool)
            {
                /* will attempt to treat it as encapsulating...
                 if it fails we'll recover and try treating it as a primitive */
                item->encapsulates = TRUE;
                *pIsPrimitive = FALSE;
            }
            else
            {
                /* jump over the data */
                status = ASN1_advanceStream(as, item);
            }
            break;

        case EOC:
        case NULLTAG:
            break;

        case OBJDESCRIPTOR:
        case GRAPHICSTRING:
        case VISIBLESTRING:
        case GENERALSTRING:
        case UNIVERSALSTRING:
        case NUMERICSTRING:
        case VIDEOTEXSTRING:
        case UTF8STRING:
        case PRINTABLESTRING:
        case BMPSTRING:
        case UTCTIME:
        case GENERALIZEDTIME:
        case IA5STRING:
        case T61STRING:
        case OID:
            /* jump over the data */
            status = ASN1_advanceStream(as, item);
            break;

        default:
            status = ASN1_advanceStream(as, item);
            if (OK <= status)
            {
                status = ERR_ASN_UNRECOGNIZED_PRIMITIVE;  /* Treat it as an error */
            }
            break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*

Routine Description:

   allocate memory for ASN 1 object , parse its headers and determine if it's a
   primitive or not.
   in case it's a primitive, at the end of the function the stream
   will point after the end of the object's data.
   if it's constructed, the stream will point to the begining of the object's data
   (first inner item).

 Arguments:
   as           - stream pointing to object's header field
   newItem      - pointer to the object who's data we would like to process.
   pParentItem  - this item's parent item
   stackDepth   - this item's stack depth
   pIsPrimitive - on return , if status is OK , this will hold a boolean value indicating
                       if the object type is a primitive object.

Returns:
   OK   parsing succeeded
   else error occured (see CS_getc() , CS_seek() , getValue() and checkEncapsulate()
                             for more error codes)
--*/
static MSTATUS
ASN1_createNode(CStream as, ASN1_ITEM **ppNewItem,
                sbyte4 stackDepth,
                intBoolean* pIsPrimitive)
{
    MSTATUS      status = OK;
    ASN1_ITEM*   pItem = 0;

    /* check depth */
    if (stackDepth > kMaxAsnParseStackDepth)
    {
        status = ERR_CERT_STACK_OVERFLOW;
        goto exit;
    }


    /* parse header - type and length */
    if (OK > (status = getItem(as, &pItem, TRUE) ) )
    {
        goto exit;
    }

    if (EOC == pItem->tag && (UNIVERSAL == (pItem->id & CLASS_MASK)))
    {
        /* do not parse the body of an EOC item */
        *pIsPrimitive = TRUE;
    }
    else
    {
        if (OK > (status = ASN1_ParseASN1object(as, pItem, pIsPrimitive)))
        {
            goto exit;
        }
    }
    *ppNewItem = pItem;
    pItem = 0;

exit:

    if (pItem)
    {
        /* free the pItem */
        /* This can be done only if the newItem is not linked to the tree */
        TREE_DeleteTreeItem( (TreeItem*) (pItem));
    }

    return status;
}


/*-----------------------------------------------------------------------------------*/

/*
Routine Description:

   receives a pointer to a node (ASN 1 item) which is the DONE node state
   (i.e. either primitive or all of its children are done) and determines if this
   node's parent is also done.

Arguments:
   as               - stream pointing just after the object's data field
   item             - pointer to the item who's parent we want to check.
   pIsParentDone    - on return , if status is OK , this will hold a boolean
                            value indicating if the item's parent is done.

Returns:
   OK   parsing succeeded
   else error occured
*/
static MSTATUS
ParentIsDone(CStream as, ASN1_ITEM *item, intBoolean* pIsParentDone)
{
    ASN1_ITEM*   parentNode;
    sbyte4       lengthLeft;
    ubyte        ch;
    MSTATUS      status = OK;

    parentNode = ASN1_PARENT(item);

    if (!parentNode)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((parentNode->treeItem).m_pParent == NULL)
    {
        /* the parent is the root item which has only one child.
        if this child is done then so is the root */
        *pIsParentDone = TRUE;
    }
    else if (parentNode->indefinite)
    {
        /* if parent has indefinite length, it must be terminated by EOC item. */
        *pIsParentDone = (item->tag == EOC
                        && (UNIVERSAL == (item->id & CLASS_MASK)) ) ? TRUE : FALSE;
    }
    else
    {
        /* parent has a definite length */
        lengthLeft = (/*FSL*/sbyte4)
            /* parent's (one after) last byte*/
            ((parentNode->dataOffset) + (parentNode->length)) -
            /* this item's (one after) last byte */
            CS_tell(as);

        if (lengthLeft < 0)
        {
            status =  ERR_ASN_INCONSISTENT_LENGTH;
            goto exit;
        }
        else if (lengthLeft == 1)
        {
            /* no item is one byte long */
            if (OK > (status = CS_getc(as, &ch)))
            {
                goto exit;
            }

            /* No object can be one byte long, try and recover.  This
            only works sometimes because it can be caused by
            spurious data in an OCTET STRING hole or an incorrect
            length encoding.  The following workaround tries to
            recover from spurious data by skipping the byte if
            it's zero or a non-basic-ASN.1 tag, but keeping it if
            it could be valid ASN.1 */
            if (ch && ch <= 0x31)
            {
                CS_ungetc(ch, as);

                /* if we're here then even if recovery succeded, parent isn't done */
                *pIsParentDone = FALSE;
            }
            else
            {
                status = ERR_ASN_INCONSISTENT_LENGTH;
                goto exit;
            }
        }
        else
        {
            *pIsParentDone = (lengthLeft == 0) ? TRUE:FALSE;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
ASN1_enoughSpaceForEncapsulatingParent( CStream as, const ASN1_ParseState* pState)
{
    /* this function is called when there is an EOF encountered to see if
    there is an encapsulating parent that can be completely read without EOF.
    If this is the case, then the encapsulation interpretation which
    reaches EOF is wrong (the child ends up outside the parent's limit) */
    ASN1_ITEM* pCurrNode;

    pCurrNode = pState->parentNode;

    /* don't check the rootNode for encapsulates ! */
    while (pCurrNode != pState->rootNode)
    {
        if (pCurrNode->encapsulates)
        {
            sbyte4 filePos, fileSize;

            /* compute the total size */
            filePos = CS_tell(as); /* save the file pos */
            CS_seek( as, 0, MOCANA_SEEK_END);
            fileSize = CS_tell(as);
            CS_seek( as, filePos, MOCANA_SEEK_SET); /* restore the file pos */

            return ( pCurrNode->dataOffset + ((sbyte4)pCurrNode->length) <= fileSize) ?
                    OK : ERR_FALSE;
        }

        pCurrNode = ASN1_PARENT( pCurrNode);
    }
    /* no encapsulating parent -> return FALSE */
    return ERR_FALSE;
}


/*------------------------------------------------------------------*/

/*
Routine Description:

   parse an entire ASN1 object, that's pointed by as.
   object is assumed to be a root object.
   note that tree parsing is done without any recursion to reduce stack usage.
   we can do this thanks to the following facts:

   1. the tree data structure used keeps in each node a pointer to the node's parent
   2. each "node" (i.e. ASN 1 item) is usually visited at most twice :
      1. once when the item is parsed , or "created"
      2. the second time is when we're done parsing this item and all of it's subitems.

   thanks to this, we simply need to keep track of which node we're currently at and
   if it's the first visit or the second visit.
   on the first visit - the node is created.
   on the second visit, we're done parsing this node, so if its parent is done,
   we move up to the parent (second visit for the parent) and if not, we move
   to create the current node's sibling.

   since the original code supported a "recovery" mechanism for encapsulating
   types, we added error propagation up the tree and recovery so our behavior
   will be the same.

   Pseudo code for the algorithm:

   parent = root
   state   = "create"

   WHILE (current != root) DO
      SWITCH (state)

         CASE "create" :
            create node
            IF (node is primitive)
               state   = "done"
            ELSE
               state   = "create"
               go to first son
            BREAK

          CASE "done" :
               IF (father is done)
                  state   = "done"
                  go to father
               ELSE
                  state   = "create"
                  go to brother
               BREAK

          CASE "error" :
               IF (encapsulating)
                  recover
                  state   = "done"
               ELSE
                  state   = "error"
                  go to father


Arguments:
   as - a stream that points to the root object's header.
   ppRootItem - on return, this will hold a pointer to the newly created item.
Returns:
   OK   parsing succeeded
   else error occured
*/

extern MSTATUS
ASN1_ParseASN1State(CStream as, ASN1_ParseState* pState,
          ProgressFun progressFun, void* cbArg)
{
    MSTATUS                 status = OK;
    intBoolean              isPrimitive = FALSE;
    intBoolean              isParentDone = FALSE;
    sbyte4                  filePos;
    ASN1_ITEM*              currentNode = NULL;
    ASN1_ITEM_NODE_STATE    state = ASN_NODE_STATE_CREATE;

    if (pState == NULL)
    {
        return ERR_NULL_POINTER;
    }

    /* to resume parsing */
    CS_seek(as, pState->filePos, MOCANA_SEEK_SET);

    /* main tree parsing loop */
    while ( pState->stackDepth > 0  &&  !(ASN_ERROR_NOT_RECOVERABLE(status)))
    {
        switch (state)
        {
        case ASN_NODE_STATE_CREATE:
            /* assumption: ParentNode is valid */

            filePos = CS_tell(as); /* remember the position */

            status = ASN1_createNode(as, &currentNode,
                                pState->stackDepth , &isPrimitive);
            if (status != OK)
            {
                if (ERR_EOF == status)
                {
                    /* we either ran out of space on the file OR
                     we are checking for encapsulation and it does not make sense after all
                     The difference between these two cases is that the encapsulating parent
                     specifies a length within the current boundary of the file */
                    if (OK > ASN1_enoughSpaceForEncapsulatingParent( as, pState))
                    {
                        pState->filePos = filePos;
                        return status;
                    }
                    /* otherwise recover by changing the parent to non-encapsulating */
                }

                state = ASN_NODE_STATE_ERROR;
                /* move up to parent, as currentNode is assumed to be invalid */
                currentNode = pState->parentNode;
                pState->parentNode = ASN1_PARENT(currentNode);
                pState->stackDepth--;
                break;
            }

            /* otherwise add the node to the parent */
            TREE_AppendChild((TreeItem*) pState->parentNode,
                             (TreeItem*) currentNode);

            if ( isPrimitive ||
                 ((currentNode->length == 0) &&
                  (!currentNode->indefinite)))
            {
                /* done with this node */
                state = ASN_NODE_STATE_DONE;
            }
            else
            {
                /* constructed/encapsulating */
                /* walk down */
                pState->parentNode = currentNode;
                pState->stackDepth++;

                /* note that:
                   1. we keep: State == ASN_NODE_STATE_CREATE
                   2. current node will be updated in the next loop iteration
                */
            }
            break;

        case ASN_NODE_STATE_DONE:
            /* assumption: currentNode and parentNode are valid */
            if (progressFun)
            {
                /* save the current position in stream before calling cb*/
                sbyte4 currentPos = CS_tell(as);
                progressFun( currentNode, as, cbArg);
                /* restore position */
                CS_seek(as, currentPos, MOCANA_SEEK_SET);
            }

            /* node is done, so go back to parent */
            status = ParentIsDone(as, currentNode, &isParentDone);

            if (status != OK)
            {
                state = ASN_NODE_STATE_ERROR;
                break;
            }

            if (isParentDone)
            {
                /* go up to parent node */
                currentNode = pState->parentNode;
                pState->parentNode = ASN1_PARENT(currentNode);
                pState->stackDepth--;

                 /* note that we keep State == ASN_NODE_STATE_DONE */
            }
            else
            {
                /* parse the next sibling (this is easy,
                since siblings are back to back in ASN1) */
                state = ASN_NODE_STATE_CREATE;

                /* note that:
                1. parentNode doesn't change
                2. current node will be updated in the next loop iteration
                3. stackDepth doesn't change
                */
            }
            break;


        case ASN_NODE_STATE_ERROR:
            /* assumption: CurrentNode and ParentNode are valid */
            /* parentNode is the parent of the node for which there was an error */

            if (currentNode->encapsulates)
            {
                /* we tried bu failed: rollback... */
                TREE_DeleteChildren( &(currentNode->treeItem));
                CS_seek(as, currentNode->dataOffset, MOCANA_SEEK_SET);
                if (OK > ( status = ASN1_advanceStream( as, currentNode)))
                {
                    /* if we cannot advance, then make sure the state is
                    in such that we can reparse it */
                    pState->stackDepth++;
                    pState->parentNode = currentNode;
                    pState->filePos = currentNode->dataOffset;
                    goto exit;
                }
                /* since it doesn't encapsulate, it's a primitive, (BIT/OCTET)STRING
                   so we're done parsing it */
                currentNode->encapsulates = FALSE;
                state = ASN_NODE_STATE_DONE;
            }
            else
            {
                /* roll error up to parent, so it might be caught by an
                   encapsulating ancestor */
                /* go up to parent node */
                currentNode = pState->parentNode;
                pState->parentNode = ASN1_PARENT(currentNode);
                pState->stackDepth--;
                 /* note that we keep:
                 State == ASN_NODE_STATE_ERROR */
            }
            break;

        default: /* unknown state */

             /* this will break the loop in the next loop condition check */
             status = ERR_GENERAL;
             break;
        }
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_InitParseState( ASN1_ParseState* pState)
{
    if (!pState)
    {
        return ERR_NULL_POINTER;
    }

    /* note: casting is safe since we allocate sizeof(ASN1_ITEM) of space. */
    pState->rootNode = (ASN1_ITEM*) TREE_MakeNewTreeItem(sizeof(ASN1_ITEM));

    DEBUG_RELABEL_MEMORY(pState->rootNode);

    if ( !pState->rootNode)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    /* initialization */
    pState->parentNode = pState->rootNode;
    pState->stackDepth = 1;
    pState->filePos = 0;

    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
ParseASN1(CStream as, ASN1_ITEM** ppRootItem,
          ProgressFun progressFun, void* cbArg)
{
    MSTATUS         status = OK;
    ASN1_ParseState parseState;

    if (ppRootItem == NULL)
    {
        return ERR_NULL_POINTER;
    }

    /* handle empty objects */
    if (CS_eof(as))
    {
        /* nothing to be done... */
        return OK;
    }

    if (OK > ( status = ASN1_InitParseState( &parseState)))
    {
        return status;
    }

    *ppRootItem = parseState.rootNode;
    return ASN1_ParseASN1State( as, &parseState, progressFun, cbArg);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_ParseEx(CStream s, ASN1_ITEM** ppRootItem, ProgressFun progressFun,
             void* cbArg)
{
    MSTATUS status;

    if (CS_eof(s))
        return ERR_EOF;

    status = ParseASN1(s, ppRootItem, progressFun, cbArg);

    if (OK > status)
    {
        /* an error occured while parsing, cleanup */
        TREE_DeleteTreeItem((TreeItem*)(*ppRootItem));
        *ppRootItem = NULL;
    }

    return status;
}  /* ASN1_ParseEx */


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_Parse(CStream s, ASN1_ITEM** ppRootItem)
{
    return ASN1_ParseEx( s, ppRootItem, NULL, NULL);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_IsItemComplete( const ASN1_ParseState* pState, const ASN1_ITEM *item,
                    CStream s, intBoolean* complete)
{
    /* item is complete (i.e. the stream is big enough to enclose it)
    if the parentNode of the state is not a child of the item or
    the item itself  -- primitive items are always complete since
    otherwise they would not be in the tree; the implementation below
    works for all types of item */

    MOC_UNUSED(s);
    if (!pState || !item || !complete)
        return ERR_NULL_POINTER;

    *complete = TRUE;

    if (pState->parentNode)
    {
        ASN1_ITEM* pCurr = pState->parentNode;
        while (pCurr != pState->rootNode)
        {
            if (pCurr == item)
            {
                *complete = FALSE;
                goto exit;
            }

            pCurr = ASN1_PARENT( pCurr);
        }
    }

exit:
    return OK;
}



/*-------------------------------------------------------------------------*/

extern ASN1_ITEMPTR
ASN1_GetNextSiblingFromPartialParse( const ASN1_ParseState* pState,
                                    ASN1_ITEMPTR pSibling, CStream cs)
{
    ASN1_ITEMPTR pRet = 0;

    if (!pState || !pSibling)
        return pRet;

    if (!ASN1_PARENT(pSibling)) /* unlinked */
        return pRet;

    /* try first the tree */
    pRet = ASN1_NEXT_SIBLING(pSibling);

    /* if not found and the parent is incomplete is the current context
    of the parse, try to find a header */
    if (!pRet && pState->parentNode == ASN1_PARENT(pSibling) )
    {
        ASN1_GetItemHeader( cs, pSibling->dataOffset + pSibling->length, &pRet);
    }
    return pRet;
}


/*-------------------------------------------------------------------------*/

extern ASN1_ITEMPTR
ASN1_GetFirstChildFromPartialParse(const ASN1_ParseState* pState,
                                    ASN1_ITEMPTR pParent, CStream cs)
{
    ASN1_ITEMPTR pRet = 0;

    if (!pState || !pParent)
        return pRet;

    if (!ASN1_PARENT(pParent)) /* unlinked */
        return pRet;

    /* try first the tree */
    pRet = ASN1_FIRST_CHILD(pParent);

    /* if not found, try to find a header */
    if (!pRet && pState->parentNode == pParent)
    {
        ASN1_GetItemHeader( cs, (/*FSL*/ubyte4)pParent->dataOffset, &pRet);
    }
    return pRet;
}


/*-----------------------------------------------------------------------*/

static intBoolean
isUnlinkedChild( const ASN1_ITEMPTR pItem )
{
	if ( pItem && !ASN1_PARENT( pItem ) )
		return TRUE;
	else
		return FALSE;
}


/*-----------------------------------------------------------------------*/

extern ubyte4
ASN1_GetData( const ASN1_ParseState* pState, CStream cs, ubyte4 streamSize,
            ASN1_ITEMPTR pItem, ubyte4* pOffset, const ubyte* src, ubyte* dest)
{
    ubyte4 copySize = 0;

    if (ASN1_CONSTRUCTED(pItem))
    {
		ASN1_ITEMPTR pChild = 0;
		ASN1_ITEMPTR pUnlinkedChild = 0;

        /* loop over children recursively */
        pChild = ASN1_GetFirstChildFromPartialParse( pState, pItem, cs);

        /* if pChild was returned an unlinked child then save it
        for deletion later */
        if (isUnlinkedChild(pChild))
			pUnlinkedChild = pChild;

        while (pChild)
        {
            ubyte4 copied = ASN1_GetData( pState, cs, streamSize, pChild,
                                        pOffset, src, dest);
            copySize += copied;
            if (dest)
            {
                dest += copied;
            }

            pChild = ASN1_GetNextSiblingFromPartialParse(pState, pChild, cs);

            /* If pChild was passed in to ASN1_GetNextSiblingFromPartialParse
            as an unlinked child then it should return NULL. Otherwise
            we need to see if it was returned an unlinked child and if
            so, we need to save it for deletion later */
            if (isUnlinkedChild(pChild))
            {
				/* pUnlinkedChild shouldn't be non-null in the case
				where pChild was just returned an unlinked child but
				but this is just to be safe. */
				if (pUnlinkedChild)
					TREE_DeleteTreeItem( (TreeItem*) pUnlinkedChild);

				pUnlinkedChild = pChild;
			}
        }

		/* delete unlinked ASN.1 Item if necessary */
		if (pUnlinkedChild)
		{
			TREE_DeleteTreeItem( (TreeItem*) pUnlinkedChild);
		}
    }
    else /* PRIMITIVE */
    {
        /* can this item contribute directly ? */
        if (pItem->dataOffset + pItem->length >  (*pOffset) )
        {
            /* yes */
            ubyte4 start, end;

            /* if offset is bigger than item start, start at offset */
            if ( ((sbyte4)(*pOffset)) > pItem->dataOffset)
            {
                start = *pOffset;
            }
            else
            {
                start = (/*FSL*/ubyte4)pItem->dataOffset;
            }

            /* if end of item is bigger than stream end, stop at stream end */
            if (pItem->dataOffset + pItem->length  <= streamSize)
            {
                end = pItem->dataOffset + pItem->length;
            }
            else
            {
                end = streamSize;
            }
            copySize = end - start;

            if (src && dest && copySize)
            {
                DIGI_MEMCPY( dest, src + start, (/*FSL*/sbyte4)copySize);
            }
            /* update the state */
            (*pOffset) = start + copySize;
        }
    }

    return copySize;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyOID(ASN1_ITEM* pItem, CStream s, const ubyte* whichOID)
{
    ubyte4  oidLen;
    MSTATUS status = ERR_FALSE;

    if (0 == pItem || 0 == whichOID)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* length of OID is first byte */
    oidLen = *whichOID;

    if (UNIVERSAL == (pItem->id & CLASS_MASK) &&
        OID == pItem->tag && oidLen == (ubyte4) pItem->length)
    {
        ubyte4 i;
        ubyte  digit;

        /* check if this is the target OID */
        /* compare OID */
        if (OK > (status = CS_seek(s, pItem->dataOffset, MOCANA_SEEK_SET)))
            goto exit;

        for (i = 0; i < oidLen; ++i)
        {
            if (OK > (status = CS_getc(s, &digit)))
                goto exit;

            if (whichOID[i+1] != digit)
            {
                status = ERR_FALSE;
                break;
            }
        }

        if (oidLen == i)
        {
            /* match */
            status = OK;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_CompareItems( ASN1_ITEM* pItem1, CStream s1, ASN1_ITEM* pItem2, CStream s2)
{
    const ubyte* item1Data;
    const ubyte* item2Data;
    sbyte4 cmpRes;
    MSTATUS status;

    if ( NULL == pItem1 || NULL == pItem2)
    {
        return ERR_NULL_POINTER;
    }

    if (pItem1->length != pItem2->length)
    {
        return ERR_FALSE;
    }

    item1Data = (const ubyte*) CS_memaccess( s1, pItem1->dataOffset, (/*FSL*/sbyte4)pItem1->length);
    item2Data = (const ubyte*) CS_memaccess( s2, pItem2->dataOffset, (/*FSL*/sbyte4)pItem2->length);

    /* DIGI_CTIME_MATCH will check for null pointer */
    status = DIGI_CTIME_MATCH( item1Data, item2Data, pItem1->length, &cmpRes);

    if (item1Data)
    {
        CS_stopaccess( s1, item1Data);
    }
    if (item2Data)
    {
        CS_stopaccess( s2, item2Data);
    }

    if ( OK == status)
    {
        status = ( 0== cmpRes) ? OK :ERR_FALSE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyOIDRoot(ASN1_ITEM* pItem, CStream s, const ubyte* whichOID, ubyte* subType)
{
    /* this routine works only if the subType is a single byte */
    /* see ASN1_VerifyOIDStart for a more generic version */
    /* length of OID is first byte */
    ubyte4  oidLen;
    MSTATUS status = ERR_FALSE;

    if (0 == pItem || 0 == whichOID)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    oidLen = *whichOID;

    if ((UNIVERSAL == (pItem->id & CLASS_MASK)) &&
        (OID == pItem->tag) && (oidLen + 1 == (ubyte4) pItem->length))
    {
        ubyte4  i;
        ubyte   digit;
        /* check if this is the target OID */
        /* compare OID */

        if (OK > (status = CS_seek(s, pItem->dataOffset, MOCANA_SEEK_SET)))
            goto exit;

        for (i = 0; i < oidLen; ++i)
        {
            if (OK > (status = CS_getc(s, &digit)))
                goto exit;

            if (whichOID[i+1] != digit)
            {
                status = ERR_FALSE;
                break;
            }
        }

        if (oidLen == i)
        {
            /* match */
            /* return the subtype */
            status = CS_getc(s, subType);
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyOIDStart(ASN1_ITEM* pItem, CStream s, const ubyte* whichOID)
{
    /* length of OID is first byte */
    ubyte4  oidLen;
    MSTATUS status = ERR_FALSE;

    if (0 == pItem || 0 == whichOID)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    oidLen = *whichOID;

    if ((UNIVERSAL == (pItem->id & CLASS_MASK)) &&
        (OID == pItem->tag) && (oidLen <= (ubyte4) pItem->length))
    {
        ubyte4  i;
        ubyte   digit;
        /* check if this is the target OID */
        /* compare OID */

        if (OK > (status = CS_seek(s, pItem->dataOffset, MOCANA_SEEK_SET)))
            goto exit;

        for (i = 0; i < oidLen; ++i)
        {
            if (OK > (status = CS_getc(s, &digit)))
                goto exit;

            if (whichOID[i+1] != digit)
            {
                status = ERR_FALSE;
                break;
            }
        }

        if (oidLen == i)
        {
            /* match */
            status = OK;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyType(ASN1_ITEM* pCurrent, ubyte4 type)
{
    if (NULL == pCurrent)
    {
        return ERR_NULL_POINTER;
    }

    if (UNIVERSAL != (pCurrent->id & CLASS_MASK) ||
        pCurrent->tag != type)
    {
        return ERR_FALSE;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyTag(ASN1_ITEM* pCurrent, ubyte4 tag)
{
    if (NULL == pCurrent)
    {
        return ERR_NULL_POINTER;
    }
    if (CONTEXT != (pCurrent->id & CLASS_MASK) ||
        pCurrent->tag != tag)
    {
        return ERR_FALSE;
    }
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_GetTag(ASN1_ITEM* pCurrent, ubyte4* pTag)
{
    if (NULL == pCurrent || NULL == pTag)
    {
        return ERR_NULL_POINTER;
    }
    if (CONTEXT != (pCurrent->id & CLASS_MASK))
    {
        return ERR_FALSE;
    }

    *pTag = pCurrent->tag;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_VerifyInteger(ASN1_ITEM* pCurrent, ubyte4 n)
{
    if (NULL == pCurrent)
    {
        return ERR_NULL_POINTER;
    }

    if (UNIVERSAL != (pCurrent->id & CLASS_MASK) ||
        pCurrent->tag != INTEGER ||
        pCurrent->length > sizeof(sbyte4) ||
        pCurrent->data.m_intVal != n)
    {
        return ERR_FALSE;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_GetChildWithOID(ASN1_ITEM* parent, CStream s, const ubyte* whichOID,
                ASN1_ITEM** ppChild)
{
    ASN1_ITEM* pItem;

    if ((NULL == parent) || (NULL == whichOID) || (NULL == ppChild))
    {
        return ERR_NULL_POINTER;
    }

    *ppChild = 0;

    pItem = ASN1_FIRST_CHILD( parent);

    while (pItem)
    {
        if (UNIVERSAL == (pItem->id & CLASS_MASK) &&
            SEQUENCE == pItem->tag)
        {
            ASN1_ITEM* pOID = ASN1_FIRST_CHILD(pItem);

            if (OK == ASN1_VerifyOID(pOID, s, whichOID))
            {
                    *ppChild = pOID;
                    return OK;
            }
        }

        pItem = ASN1_NEXT_SIBLING( pItem);
    }
    return OK; /* not found but not an error */
}



/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_GoToTag(ASN1_ITEM* parent, ubyte4 tag, ASN1_ITEM** ppTag)
{
    ASN1_ITEM* pItem;

    if (0 == parent || 0 == ppTag)
    {
        return ERR_NULL_POINTER;
    }

    *ppTag = 0;

    pItem = ASN1_FIRST_CHILD( parent);

    while (pItem)
    {
        if (CONTEXT == (pItem->id & CLASS_MASK) &&
            pItem->tag == tag)
        {
            /* found it - return it */
            *ppTag = pItem;
            return OK;
        }

        pItem = ASN1_NEXT_SIBLING( pItem);
    }

    return OK; /* not found but not an error */
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_GetChildWithTag(ASN1_ITEM* parent, ubyte4 tag, ASN1_ITEM** ppChild)
{
    ASN1_ITEM* pItem;

    if (0 == parent || 0 == ppChild)
    {
        return ERR_NULL_POINTER;
    }

    *ppChild = 0;

    ASN1_GoToTag( parent, tag, &pItem);

    if ( pItem)
    {
        *ppChild = ASN1_FIRST_CHILD( pItem);
    }

    return OK; /* not found but not an error */
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_GetNthChild(ASN1_ITEM* parent, ubyte4 n, ASN1_ITEM** ppChild)
{
    ubyte4 i;
    TreeItem* pItem;

    if ((NULL == parent) || (NULL == ppChild))
    {
        return ERR_NULL_POINTER;
    }

    *ppChild = 0;

    if ( 0 == n)
    {
        return ERR_INDEX_OOB;
    }

    pItem = parent->treeItem.m_pFirstChild;

    if (NULL == pItem)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    for (i = 1; i < n; ++i)
    {
        pItem = pItem->m_pNextSibling;
        if (NULL == pItem)
        {
            return ERR_INDEX_OOB;
        }
    }

    *ppChild = (ASN1_ITEM*)pItem;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_getBitStringBit( ASN1_ITEM* pBitString, CStream s,
                        ubyte4 bitNum, byteBoolean* bitVal)
{
    /* ASN1 bit strings are encoded like this bit[0]bit[1], etc... */
    MSTATUS status;
    ubyte4 byteNumber;
    ubyte b;

    if (!pBitString || !bitVal)
        return ERR_NULL_POINTER;

    /* assume pBitString has the correct type */

    byteNumber = bitNum / 8;

    if (byteNumber >= pBitString->length)
    {
        *bitVal = 0;
        return OK;
    }

    CS_seek( s, (/*FSL*/sbyte4)(pBitString->dataOffset + byteNumber), MOCANA_SEEK_SET);

    if (OK > ( status = CS_getc(s, &b)))
        return status;

    b <<= (bitNum % 8);

    *bitVal = (b & 0x80) ? 1 : 0;

    return OK;

}

/*------------------------------------------------------------------*/

static sbyte4 SearchOIDFun(TreeItem* treeItem, void* arg)
{
    ASN1_ITEMPTR pItem = (ASN1_ITEMPTR) treeItem;
    SearchOIDInfo* pInfo = (SearchOIDInfo*) arg;
    MSTATUS status;

    if (pInfo->rootOnly)
    {
        status = ASN1_VerifyOIDStart( pItem, pInfo->s, pInfo->oid+1);
    }
    else
    {
        status = ASN1_VerifyOID( pItem, pInfo->s, pInfo->oid+1);
    }

    if (OK == status) /* match -> add to array */
    {
        status = DYNARR_Append( pInfo->pDynArray, &pItem);
    }

    return (ERR_FALSE == status || OK == status);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1_OIDSearch( ASN1_ITEMPTR pItem, CStream s, const sbyte* whichOID,
                                ASN1_ITEMPTR **ppResults)
{
    SearchOIDInfo searchInfo;
    DynArray dynArray;
    MSTATUS status;
    TreeItem* pErrorItem;

    /* always init DynArray to some stable state */
    DYNARR_Init( sizeof(ASN1_ITEMPTR), &dynArray);

    if ( NULL == pItem || NULL == whichOID || NULL == ppResults)
    {
        return ERR_NULL_POINTER;
    }

    *ppResults = 0;

    if (0 == *whichOID)
    {
        return ERR_INVALID_ARG; /*empty string not allowed */
    }

    /* convert the string to a OID */
    /* check for a * wildcard at the end */
    if (OK > (status = BEREncodeOID( whichOID, &searchInfo.rootOnly, &searchInfo.oid)))
    {
        goto exit;
    }

    /* now visit the tree */
    searchInfo.pDynArray = &dynArray;
    searchInfo.s = s;

    pErrorItem = TREE_VisitTree(&(pItem->treeItem), SearchOIDFun, &searchInfo);
    /* if pErrorItem is not null, an error occurred */
    if ( pErrorItem)
    {
        status = ERR_INCOMPLETE_SEARCH;
        goto exit;
    }

    /* append a NULL element to the array. pErrorItem will do */
    if (OK > (status = DYNARR_Append( &dynArray, &pErrorItem)))
        goto exit;

    /* detach array from dynArray */
    if (OK > (status = DYNARR_DetachArray( &dynArray, (void**) ppResults)))
        goto exit;

exit:

    DYNARR_Uninit( &dynArray);

    if (searchInfo.oid)
    {
        FREE(searchInfo.oid);
    }
    return status;
}

extern MSTATUS ASN1_validateEncoding(
    ubyte type,
    ubyte *pEncoding,
    ubyte4 encodingLen,
    byteBoolean *pIsValid)
{
    MSTATUS status = OK;
    ubyte4 i;
    byteBoolean isValid;

    if (NULL == pEncoding || NULL == pIsValid)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsValid = FALSE;

    if (PRINTABLESTRING == type)
    {
        for (i = 0; i < encodingLen; i++)
        {
            /* Check if the character is valid for ASN.1 PRINTABLESTRING */
            isValid = ((pEncoding[i] >= 'A' && pEncoding[i] <= 'Z') ||  /* Uppercase letters */
                    (pEncoding[i] >= 'a' && pEncoding[i] <= 'z') ||  /* Lowercase letters */
                    (pEncoding[i] >= '0' && pEncoding[i] <= '9') ||  /* Digits */
                    (pEncoding[i] == ' ') ||              /* Space */
                    (pEncoding[i] == '\'') || (pEncoding[i] == '(') || (pEncoding[i] == ')') || (pEncoding[i] == '+') || 
                    (pEncoding[i] == ',') || (pEncoding[i] == '-') || (pEncoding[i] == '.') || (pEncoding[i] == '/') || 
                    (pEncoding[i] == ':') || (pEncoding[i] == '=') || (pEncoding[i] == '?')); /* Symbols */
            if (FALSE == isValid)
            {
                goto exit;
            }
        }
    }
    else if (UTF8STRING == type)
    {
        /* Validate UTF-8 encoding */
        status = UTF8_validateEncoding(pEncoding, encodingLen, &isValid);
        if (OK != status || FALSE == isValid)
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    *pIsValid = TRUE;

exit:

    return status;
}

#endif /* __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */
