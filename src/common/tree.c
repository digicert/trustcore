/*
 * tree.c
 *
 * Mocana ASN1 Tree Abstraction Layer
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
#include "../common/tree.h"

#if (!defined(__DISABLE_MOCANA_COMMON_TREE_ABS_LAYER__))

/*------------------------------------------------------------------*/

extern TreeItem*
TREE_MakeNewTreeItem(sbyte4 size)
{
    TreeItem* pRetVal = NULL;

    if (size < ((sbyte4)sizeof(TreeItem)))
    {
        /* assert is in order here probably */
        return pRetVal;
    }

    pRetVal = (TreeItem*) MALLOC( size);
    if (pRetVal)
    {
        pRetVal->m_pFirstChild = pRetVal->m_pNextSibling = pRetVal->m_pParent = NULL;
        pRetVal->m_dtorFun = 0;
    }
    return pRetVal;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TREE_AppendChild( TreeItem* pParent, TreeItem* pChild)
{
    if ((NULL == pChild) || (NULL == pParent))
    {
        return ERR_NULL_POINTER;
    }
    /* the child must not be linked to any parent already and must have no siblings
        (that could be linked to another parent) */
    if (pChild->m_pParent || pChild->m_pNextSibling)
    {
        return ERR_TREE_LINKEDCHILD;
    }

    if ( pParent->m_pFirstChild)
    {
        TreeItem* pLastChild = pParent->m_pFirstChild;
        while ( pLastChild->m_pNextSibling)
        {
            pLastChild = pLastChild->m_pNextSibling;
        }
        pLastChild->m_pNextSibling = pChild;
    }
    else
    {
        pParent->m_pFirstChild = pChild;
    }

    pChild->m_pParent = pParent;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TREE_DeleteTreeItem( TreeItem* pTreeItem)
{
    MSTATUS resDelete = OK;

    if (NULL == pTreeItem)
    {
        resDelete = ERR_NULL_POINTER;
        goto exit;
    }

    /* the child must not be linked to any parent already and must have no siblings
        (that could be linked to another parent) */
    if (pTreeItem->m_pParent || pTreeItem->m_pNextSibling)
    {
        resDelete = ERR_TREE_LINKEDCHILD;
        goto exit;
    }

    /* delete the children */
    TREE_DeleteChildren( pTreeItem);

    /* call the dtor function if there */
    if ( pTreeItem->m_dtorFun)
    {
        pTreeItem->m_dtorFun( pTreeItem);
    }
    /* we can free it now that there is no children without risking leak*/
    FREE(pTreeItem);

exit:
    return resDelete;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TREE_DeleteChildren( TreeItem* pTreeItem)
{
    MSTATUS resDelete = OK;

    if (NULL == pTreeItem)
    {
        resDelete = ERR_NULL_POINTER;
        goto exit;
    }

    /* delete the children */
    while ( pTreeItem->m_pFirstChild)
    {
        /* detach each child */
        TreeItem* pDetachedChild = pTreeItem->m_pFirstChild;
        pTreeItem->m_pFirstChild = pDetachedChild->m_pNextSibling;
        pDetachedChild->m_pParent = pDetachedChild->m_pNextSibling = NULL;

        /* delete it */
        resDelete = TREE_DeleteTreeItem( pDetachedChild);

        /* add an assertion OK == resDelete */
    }

exit:
    return resDelete;
}


/*------------------------------------------------------------------*/

extern TreeItem*
TREE_GetParent( TreeItem* pTreeItem)
{
    if (NULL == pTreeItem)
        return NULL;

    return pTreeItem->m_pParent;
}


/*------------------------------------------------------------------*/

extern TreeItem*
TREE_GetFirstChild( TreeItem* pTreeItem)
{
    if (NULL == pTreeItem)
    {
        return NULL;
    }
    return pTreeItem->m_pFirstChild;
}


/*------------------------------------------------------------------*/

extern TreeItem*
TREE_GetNextSibling(TreeItem* pTreeItem)
{
    if (NULL == pTreeItem)
    {
        return NULL;
    }
    return pTreeItem->m_pNextSibling;
}


/*------------------------------------------------------------------*/

extern sbyte4
TREE_GetTreeItemLevel(TreeItem* pTreeItem)
{
    sbyte4 level = -1;

    while (pTreeItem)
    {
        ++level;
        pTreeItem = pTreeItem->m_pParent;
    }

    return level;
}


/*------------------------------------------------------------------*/

extern TreeItem*
TREE_VisitTree(TreeItem* start, VisitTreeFunc visitTreeFunc, void* arg)
{
    TreeItem* currChild;

    if ((!start) || (!visitTreeFunc))
    {
        return NULL;
    }

    if (!visitTreeFunc(start, arg))
    {
        return start;
    }

    currChild = start->m_pFirstChild;
    while (currChild)
    {
        TreeItem* found = TREE_VisitTree( currChild, visitTreeFunc, arg);

        if (found)
        {
            return found;
        }

        currChild = currChild->m_pNextSibling;
    }

    return NULL;
}

#endif /* __DISABLE_MOCANA_COMMON_TREE_ABS_LAYER__ */
