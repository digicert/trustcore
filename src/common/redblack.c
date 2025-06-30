/*
 * redblack.c
 *
 * Red-Black Tree
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

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/redblack.h"

#if (!defined(__DISABLE_MOCANA_COMMON_REDBLACK_TREE__))

/*--------------------------------------------------------------------------*/

static struct redBlackNodeDescr null_rb_node = { &null_rb_node, &null_rb_node, &null_rb_node, NULL, BLACK };


/*--------------------------------------------------------------------------*/

#define RB_NULL             (&null_rb_node)


/*--------------------------------------------------------------------------*/

#if 0
static redBlackNodeDescr *
REDBLACK_getGrandparent(redBlackNodeDescr *pNode)
{
    if ((RB_NULL != pNode) && (RB_NULL != pNode->pParent))
        return pNode->pParent->pParent;

    return RB_NULL;
}


/*--------------------------------------------------------------------------*/

static redBlackNodeDescr *
REDBLACK_getUncle(redBlackNodeDescr *pNode)
{
    redBlackNodeDescr *pGrandparent;

    if ((RB_NULL != pNode) && (RB_NULL != pNode->pParent) && (RB_NULL != (pGrandparent = pNode->pParent->pParent)))
    {
        if (pNode->pParent == pGrandparent->pRight)
            return pGrandparent->pLeft;

        return pGrandparent->pRight;
    }

    return RB_NULL;
}
#endif


/*--------------------------------------------------------------------------*/

static redBlackNodeDescr *
REDBLACK_rotateLeft(redBlackTreeDescr *pTree, redBlackNodeDescr *pRoot)
{
    redBlackNodeDescr* pParent;
    redBlackNodeDescr* pNewRoot;

    /* anything to do? */
    if (RB_NULL == (pNewRoot = pRoot->pRight))
        return pRoot;

    pParent = pRoot->pParent;

    if (RB_NULL != (pRoot->pRight = pNewRoot->pLeft))
        pRoot->pRight->pParent = pRoot;

    pNewRoot->pLeft = pRoot;
    pRoot->pParent = pNewRoot;

    if (RB_NULL == pParent)
    {
        pTree->pRoot = pNewRoot;
    }
    else
    {
        if (pParent->pLeft == pRoot)
            pParent->pLeft  = pNewRoot;
        else
            pParent->pRight = pNewRoot;
    }

    pNewRoot->pParent = pParent;

    return pNewRoot;
}


/*--------------------------------------------------------------------------*/

static redBlackNodeDescr *
REDBLACK_rotateRight(redBlackTreeDescr *pTree, redBlackNodeDescr *pRoot)
{
    redBlackNodeDescr* pParent;
    redBlackNodeDescr* pNewRoot;

    /* anything to do? */
    if (RB_NULL == (pNewRoot = pRoot->pLeft))
        return pRoot;

    pParent = pRoot->pParent;

    if (RB_NULL != (pRoot->pLeft = pNewRoot->pRight))
        pRoot->pLeft->pParent = pRoot;

    pNewRoot->pRight = pRoot;
    pRoot->pParent = pNewRoot;

    if (RB_NULL == pParent)
    {
        pTree->pRoot = pNewRoot;
    }
    else
    {
        if (pParent->pLeft == pRoot)
            pParent->pLeft  = pNewRoot;
        else
            pParent->pRight = pNewRoot;
    }

    pNewRoot->pParent = pParent;

    return pNewRoot;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_traverse(redBlackTreeDescr *pTree, intBoolean doInsert, const void *pSearchKey,
                  redBlackNodeDescr **ppRetNode)
{
    redBlackNodeDescr*  pWalkingNode;
    redBlackNodeDescr*  pParent;
    redBlackNodeDescr*  pNewNode = NULL;
    sbyte4              result;
    MSTATUS             status = OK;

    if ((NULL == pTree) || (NULL == ppRetNode))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWalkingNode = pTree->pRoot;
    pParent = *ppRetNode = RB_NULL;

    /* standard binary tree traversal, we walk down the tree to the appropriate location */
    while (RB_NULL != pWalkingNode)
    {
        pParent = pWalkingNode;

        if (OK > (status = (*pTree->func_redBlackCompare)(pTree->pRedBlackCookie, pSearchKey, pWalkingNode->pKey, &result)))
            goto exit;

        if (0 > result)
        {
            pWalkingNode = pWalkingNode->pLeft;
        }
        else if (0 < result)
        {
            pWalkingNode = pWalkingNode->pRight;
        }
        else
        {
            /* fount it! not able to insert... */
            *ppRetNode = pWalkingNode;
            goto exit;
        }
    }

    /* not found, but we're not going to insert... */
    if (FALSE == doInsert)
        goto exit;

    /* allocate a new node */
    if (OK > (status = (*pTree->func_redBlackGetNode)(pTree->pAllocCookie, (void **)&pNewNode)))
        goto exit;

    /* init new node */
    pNewNode->pKey    = pSearchKey;
    pNewNode->pLeft   = RB_NULL;
    pNewNode->pRight  = RB_NULL;
    pNewNode->pParent = pParent;

    /* first node case */
    if (RB_NULL == pParent)
    {
        pTree->pRoot = pNewNode;  /* add root node */
        pNewNode->color = BLACK;  /* root node is always black */

        pNewNode = NULL;
        goto exit;
    }

    /* all new leaf nodes are red */
    pNewNode->color = RED;

    /* by key, add new node to parent node */
    if (OK > (status = (*pTree->func_redBlackCompare)(pTree->pRedBlackCookie, pSearchKey, pParent->pKey, &result)))
        goto exit;

    if (0 > result)
        pParent->pLeft = pNewNode;
    else
        pParent->pRight = pNewNode;

    /* we need to walk up the tree towards the root */
    pWalkingNode = pNewNode;

    /* clear for cleanup */
    pNewNode = NULL;

    while ((RB_NULL != pWalkingNode->pParent) && (RED == pWalkingNode->pParent->color))
    {
        if (pWalkingNode->pParent == pWalkingNode->pParent->pParent->pLeft)
        {
            if (RED == pWalkingNode->pParent->pParent->pRight->color) /* RB_NULL will be black */
            {
                /* case 1 */
                pWalkingNode->pParent->color = BLACK;
                pWalkingNode->pParent->pParent->pRight->color = BLACK;

                pWalkingNode = pWalkingNode->pParent->pParent;
                pWalkingNode->color = RED;
            }
            else
            {
                /* case 2 */
                if (pWalkingNode == pWalkingNode->pParent->pRight)
                {
                    pWalkingNode = pWalkingNode->pParent;
                    REDBLACK_rotateLeft(pTree, pWalkingNode);
                }

                /* case 3 */
                pWalkingNode->pParent->color = BLACK;
                pWalkingNode->pParent->pParent->color = RED;
                REDBLACK_rotateRight(pTree, pWalkingNode->pParent->pParent);
            }
        }
        else
        {
            if (RED == pWalkingNode->pParent->pParent->pLeft->color) /* RB_NULL will be black */
            {
                /* case 1 */
                pWalkingNode->pParent->color = BLACK;
                pWalkingNode->pParent->pParent->pLeft->color = BLACK;

                pWalkingNode = pWalkingNode->pParent->pParent;
                pWalkingNode->color = RED;
            }
            else
            {
                /* case 2 */
                if (pWalkingNode == pWalkingNode->pParent->pLeft)
                {
                    pWalkingNode = pWalkingNode->pParent;
                    REDBLACK_rotateRight(pTree, pWalkingNode);
                }

                /* case 3 */
                pWalkingNode->pParent->color = BLACK;
                pWalkingNode->pParent->pParent->color = RED;
                REDBLACK_rotateLeft(pTree, pWalkingNode->pParent->pParent);
            }
        }
    }

    pTree->pRoot->color = BLACK;

exit:
    if ((NULL != pTree) && (NULL != pNewNode))
        (*pTree->func_redBlackPutNode)(pTree->pAllocCookie, (void **)&pNewNode);

    return status;

} /* REDBLACK_traverse */


/*--------------------------------------------------------------------------*/

static const redBlackNodeDescr *
REDBLACK_getNext(const redBlackNodeDescr *pNextNode)
{
    if (RB_NULL != pNextNode->pRight)
    {
        pNextNode = pNextNode->pRight;

        while (RB_NULL != pNextNode->pLeft)
            pNextNode = pNextNode->pLeft;
    }
    else
    {
        while (RB_NULL != pNextNode)
        {
            if (pNextNode == pNextNode->pParent->pLeft)
            {
                pNextNode = pNextNode->pParent;
                break;
            }

            pNextNode = pNextNode->pParent;
        }
    }

    return pNextNode;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_lookupHelper(redBlackTreeDescr *pTree, enum redblackLookupMethods method, const void *pSearchKey,
                      const redBlackNodeDescr **ppRetNode)
{
    redBlackNodeDescr*  pWalkingNode;
    redBlackNodeDescr*  pParent;
    sbyte4              result;
    MSTATUS             status = OK;

    pWalkingNode = pTree->pRoot;
    pParent      = pWalkingNode->pParent;

    /* do non-search cases first */
    if (RB_LOOKUP_FIRST == method)
    {
        /* find left most node */
        while (RB_NULL != pWalkingNode)
        {
            pParent = pWalkingNode;
            pWalkingNode = pWalkingNode->pLeft;
        }

        *ppRetNode = pParent;
        goto exit;
    }

    while (RB_NULL != pWalkingNode)
    {
        pParent = pWalkingNode;

        if (OK > (status = (*pTree->func_redBlackCompare)(pTree->pRedBlackCookie, pSearchKey, pWalkingNode->pKey, &result)))
            goto exit;

        if (0 > result)
        {
            pWalkingNode = pWalkingNode->pLeft;
        }
        else if (0 < result)
        {
            pWalkingNode = pWalkingNode->pRight;
        }
        else
        {
            break;
        }
    }

    if (RB_LOOKUP_EQUAL == method)
    {
        *ppRetNode = pWalkingNode;
        goto exit;
    }

    if (RB_LOOKUP_NEXT == method)
    {
        if (!(RB_NULL != pWalkingNode))
        {
            *ppRetNode = RB_NULL;
            goto exit;
        }

        *ppRetNode = REDBLACK_getNext(pWalkingNode);
        goto exit;
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

static void
REDBLACK_deleteFixUp(redBlackTreeDescr *pTree, redBlackNodeDescr *pNode)
{
    redBlackNodeDescr*  pNodeSibbling;

    while ((RB_NULL != pNode->pParent) && (BLACK == pNode->color))
    {
        if (pNode == pNode->pParent->pLeft)
        {
            pNodeSibbling = pNode->pParent->pRight;

            if (RED == pNodeSibbling->color)
            {
                pNodeSibbling->color  = BLACK;
                pNode->pParent->color = RED;

                REDBLACK_rotateLeft(pTree, pNode->pParent);
                pNodeSibbling = pNode->pParent->pRight;
            }

            if ((BLACK == pNodeSibbling->pLeft->color) && (BLACK == pNodeSibbling->pRight->color))
            {
                pNodeSibbling->color = RED;
                pNode = pNode->pParent;
            }
            else
            {
                if (BLACK == pNodeSibbling->pRight->color)
                {
                    pNodeSibbling->pLeft->color = BLACK;
                    pNodeSibbling->color = RED;
                    REDBLACK_rotateRight(pTree, pNodeSibbling);
                    pNodeSibbling = pNode->pParent->pRight;
                }

                pNodeSibbling->color = pNode->pParent->color;
                pNode->pParent->color = BLACK;
                pNodeSibbling->pRight->color = BLACK;
                REDBLACK_rotateLeft(pTree, pNode->pParent);

                pNode = pTree->pRoot;
                break;
            }
        }
        else
        {
            pNodeSibbling = pNode->pParent->pLeft;

            if (RED == pNodeSibbling->color)
            {
                pNodeSibbling->color  = BLACK;
                pNode->pParent->color = RED;

                REDBLACK_rotateRight(pTree, pNode->pParent);
                pNodeSibbling = pNode->pParent->pLeft;
            }

            if ((BLACK == pNodeSibbling->pRight->color) && (BLACK == pNodeSibbling->pLeft->color))
            {
                pNodeSibbling->color = RED;
                pNode = pNode->pParent;
            }
            else
            {
                if (BLACK == pNodeSibbling->pLeft->color)
                {
                    pNodeSibbling->pRight->color = BLACK;
                    pNodeSibbling->color = RED;
                    REDBLACK_rotateLeft(pTree, pNodeSibbling);
                    pNodeSibbling = pNode->pParent->pLeft;
                }

                pNodeSibbling->color = pNode->pParent->color;
                pNode->pParent->color = BLACK;
                pNodeSibbling->pLeft->color = BLACK;
                REDBLACK_rotateRight(pTree, pNode->pParent);

                pNode = pTree->pRoot;
                break;
            }
        }
    }

    pNode->color = BLACK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_deleteThisNode(redBlackTreeDescr *pTree, redBlackNodeDescr *pNode)
{
    redBlackNodeDescr*  pChildOfDeleteNode;
    const redBlackNodeDescr*  pNodeToDelete;
    MSTATUS             status;

    /* find a replacement node to delete */
    if ((RB_NULL == pNode->pLeft) || (RB_NULL == pNode->pRight))
        pNodeToDelete = pNode;
    else
        pNodeToDelete = REDBLACK_getNext(pNode);

    /* now we find the child, we know that a replacement node will have at most one child; never two */
    if (RB_NULL != pNodeToDelete->pLeft)
        pChildOfDeleteNode = pNodeToDelete->pLeft;
    else
        pChildOfDeleteNode = pNodeToDelete->pRight;

    /* if not null, link up child to grandparent */
    if (RB_NULL != pChildOfDeleteNode)
        pChildOfDeleteNode->pParent = pNodeToDelete->pParent;

    /* link grandparent to child */
    if (RB_NULL == pNodeToDelete->pParent)
    {
        /* no grandparent, therefore root of tree */
        pTree->pRoot = pChildOfDeleteNode;
    }
    else
    {
        /* replace the deleted parent with the child */
        if (pNodeToDelete == pNodeToDelete->pParent->pLeft)
            pNodeToDelete->pParent->pLeft  = pChildOfDeleteNode;
        else
            pNodeToDelete->pParent->pRight = pChildOfDeleteNode;
    }

    if (pNode != pNodeToDelete)
    {
        /* we move data from the sacrificed node's key to the original node */
        pNode->pKey    = pNodeToDelete->pKey;
    }

    if (BLACK == pNodeToDelete->color)
    {
        REDBLACK_deleteFixUp(pTree, pChildOfDeleteNode);
    }

    /* release the node */
    status = (*pTree->func_redBlackPutNode)(pTree->pAllocCookie, (void **)&pNodeToDelete);

    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_condDeleteFirst(redBlackTreeDescr *pTree, const void **ppRetKey,
                         intBoolean (*func_checkKey)(const void *pFoundKey),
                         intBoolean *pDeleted)
{
    MSTATUS status = OK;

    redBlackNodeDescr *pNode;

    if ((NULL == pTree) || (NULL == ppRetKey) ||
        (NULL == func_checkKey) || (NULL == pDeleted))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetKey = NULL;
    *pDeleted = FALSE;

    /* find first node */
    if (RB_NULL == (pNode = pTree->pRoot))
    {
        goto exit; /* empty tree */
    }

    while (RB_NULL != pNode->pLeft)
    {
        pNode = pNode->pLeft;
    }

    *ppRetKey = pNode->pKey;

    /* delete it? */
    if (FALSE == (*pDeleted = func_checkKey(pNode->pKey)))
    {
        goto exit; /* NO */
    }

    /* see REDBLACK_deleteThisNode() */
    if (RB_NULL != pNode->pRight)
    {
        pNode->pRight->pParent = pNode->pParent;
    }

    if (RB_NULL == pNode->pParent)
    {
        pTree->pRoot = pNode->pRight;
    }
    else
    {
        pNode->pParent->pLeft = pNode->pRight;
    }

    if (BLACK == pNode->color)
    {
        REDBLACK_deleteFixUp(pTree, pNode->pRight);
    }

    status = (*pTree->func_redBlackPutNode)(pTree->pAllocCookie, (void **)&pNode);

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_defaultGetNode(void *pAllocCookie, void **ppNewNode)
{
    MOC_UNUSED(pAllocCookie);

    return MOC_MALLOC((void **)ppNewNode, sizeof(redBlackNodeDescr));
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_defaultPutNode(void *pAllocCookie, void **ppFreeNode)
{
    MOC_UNUSED(pAllocCookie);

    return MOC_FREE((void **)ppFreeNode);
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_allocTree(redBlackTreeDescr **ppRetNewTree,
                   MSTATUS (*func_redBlackGetNode)(void *, void **),
                   MSTATUS (*func_redBlackPutNode)(void *, void **),
                   MSTATUS (*func_redBlackCompare)(const void *, const void *, const void *, sbyte4 *),
                   void *pRedBlackCookie,
                   void *pAllocCookie)
{
    redBlackTreeDescr*  pNewTree;
    MSTATUS             status = OK;

    if (NULL == (pNewTree = (redBlackTreeDescr*) MALLOC(sizeof(redBlackTreeDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((ubyte *)pNewTree, 0x00, sizeof(redBlackTreeDescr));

    if (NULL == (pNewTree->func_redBlackGetNode = func_redBlackGetNode))
        pNewTree->func_redBlackGetNode = REDBLACK_defaultGetNode;

    if (NULL == (pNewTree->func_redBlackPutNode = func_redBlackPutNode))
        pNewTree->func_redBlackPutNode = REDBLACK_defaultPutNode;

    if (NULL == (pNewTree->func_redBlackCompare = func_redBlackCompare))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pNewTree->pRedBlackCookie = pRedBlackCookie;
    pNewTree->pAllocCookie    = pAllocCookie;
    pNewTree->pRoot           = RB_NULL;

    *ppRetNewTree = pNewTree;
    pNewTree = NULL;

exit:
    if (NULL != pNewTree)
        FREE(pNewTree);

    return status;
}



/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_lookup(redBlackTreeDescr *pTree, enum redblackLookupMethods method, const void *pSearchKey,
                const void **ppRetKey)
{
    /* *ppRetKey will be null, if key was not found using the search method */
    const redBlackNodeDescr*  pNode  = NULL;
    MSTATUS             status = OK;

    if (NULL == ppRetKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetKey = NULL;

    if (NULL == pTree)
        goto exit;

    if (OK > (status = REDBLACK_lookupHelper(pTree, method, pSearchKey, &pNode)))
        goto exit;

    *ppRetKey = (RB_NULL == pNode || NULL == pNode) ? NULL : pNode->pKey;

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_find(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetKey)
{
    /* *ppRetKey will be null, if key was not found */
    return REDBLACK_lookup(pTree, RB_LOOKUP_EQUAL, pSearchKey, ppRetKey);
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_findOrInsert(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetFoundKey)
{
    /* *ppRetFoundKey will be null, if a node was added to the tree */
    redBlackNodeDescr*  pNode  = NULL;
    MSTATUS             status;

    if ((NULL == pTree) || (NULL == ppRetFoundKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = REDBLACK_traverse(pTree, TRUE, pSearchKey, &pNode)))
        goto exit;

    *ppRetFoundKey = (RB_NULL == pNode) ? NULL : pNode->pKey;

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_delete(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetKey)
{
    redBlackNodeDescr*  pNode;
    MSTATUS             status;

    if ((NULL == pTree) || (NULL == pSearchKey) || (NULL == ppRetKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetKey = NULL;

    if (OK > (status = REDBLACK_traverse(pTree, FALSE, pSearchKey, &pNode)))
        goto exit;

    if (RB_NULL != pNode)
    {
        *ppRetKey = pNode->pKey;
        status = REDBLACK_deleteThisNode(pTree, pNode);
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_traverseFree(redBlackTreeDescr *pTree, redBlackNodeDescr *pNode, MSTATUS(*freeKey)(const void **ppFreeKey))
{
    redBlackNodeDescr*  pParent;
    intBoolean          isLeft;
    MSTATUS             status = OK;

    /* post order traversal */
    if (RB_NULL != pNode)
    {
        if (RB_NULL != pNode->pLeft)
            if (OK > (status = REDBLACK_traverseFree(pTree, pNode->pLeft, freeKey)))
                goto exit;

        if (RB_NULL != pNode->pRight)
            if (OK > (status = REDBLACK_traverseFree(pTree, pNode->pRight, freeKey)))
                goto exit;

        pParent = pNode->pParent;
        isLeft  = (pNode == pParent->pLeft);

        if ((NULL != freeKey) && (OK > (status = (*freeKey)(&pNode->pKey))))
            goto exit;

        /* free the node */
        if (OK > (status = (*pTree->func_redBlackPutNode)(pTree->pAllocCookie, (void **)&pNode)))
            goto exit;

        /* remove tangling parent pointer */
        if (isLeft)
            pParent->pLeft  = RB_NULL;
        else
            pParent->pRight = RB_NULL;
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_freeTree(redBlackTreeDescr **ppRetNewTree,
                  MSTATUS(*func_freeKey)(const void **ppFreeKey),
                  void **ppRetRedBlackCookie,
                  void **ppRetAllocCookie)
{
    MSTATUS status = OK;

    if ((NULL == ppRetNewTree) || (NULL == *ppRetNewTree))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppRetNewTree)->pRoot)
        if (OK > (status = REDBLACK_traverseFree(*ppRetNewTree, (*ppRetNewTree)->pRoot, func_freeKey)))
            goto exit;

    (*ppRetNewTree)->pRoot = NULL;

    /* return back search cookie */
    if (NULL != ppRetRedBlackCookie)
        *ppRetRedBlackCookie = (*ppRetNewTree)->pRedBlackCookie;

    /* return back alloc cookie */
    if (NULL != ppRetAllocCookie)
        *ppRetAllocCookie    = (*ppRetNewTree)->pAllocCookie;

    FREE(*ppRetNewTree);
    *ppRetNewTree = NULL;

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_traverseListInit(redBlackTreeDescr *pTree, redBlackListDescr **ppRetListTracker)
{
    redBlackNodeDescr*  pNode;
    MSTATUS             status;

    /* allocate memory for the list tracker */
    if (OK != (status = MOC_MALLOC((void **)ppRetListTracker, sizeof(redBlackListDescr))))
        goto exit;

    /* clear it out */
    MOC_MEMSET((ubyte *)(*ppRetListTracker), 0x00, sizeof(redBlackListDescr));

    /* setup for traverse */
    if (RB_NULL != (pNode = pTree->pRoot))
        while (RB_NULL != pNode->pLeft)
            pNode = pNode->pLeft;

    (*ppRetListTracker)->pNode = pNode;
    (*ppRetListTracker)->pTree = pTree;

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_traverseListGetNext(redBlackListDescr *pListTracker, const void **ppRetNextKey)
{
    MSTATUS status = ERR_REDBLACK_NULL_DATUM;

    if ((NULL == pListTracker) || (NULL == ppRetNextKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetNextKey = NULL;

    if (RB_NULL != pListTracker->pNode)
    {
        /* return the key that was previously located */
        *ppRetNextKey = pListTracker->pNode->pKey;

        /* setup for next round */
        pListTracker->pNode = REDBLACK_getNext(pListTracker->pNode);
        status = OK;
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_traverseListFree(redBlackListDescr **ppFreeListTracker)
{
    return MOC_FREE((void **)ppFreeListTracker);
}


/*--------------------------------------------------------------------------*/

typedef struct
{
    void*   pTraverseContext;   /* for callback purposes */
    ubyte4  traverseMask;       /* for determining when to "visit" a node */

} traverseContext;


/*--------------------------------------------------------------------------*/

static MSTATUS
REDBLACK_traverseTreeAndVisit(redBlackNodeDescr *pNode,
                              traverseContext *pTraverseCtx,
                              sbyte4 depth,
                              MSTATUS (*func_onVisit)(void *, const void *, enum nodeTraverseMethods traverseMethod, sbyte4))
{
    MSTATUS status = OK;

    if (RB_NULL == pNode)
        goto exit;

    if ((RB_NULL == pNode->pLeft) && (RB_NULL == pNode->pRight) && (REDBLACK_LEAF & pTraverseCtx->traverseMask))
    {
        /* leaf */
        if (OK > (status = (*func_onVisit)(pTraverseCtx->pTraverseContext, pNode->pKey, REDBLACK_LEAF, depth)))
            goto exit;
    }
    else
    {
        if ((REDBLACK_PREORDER & pTraverseCtx->traverseMask) && (OK > (status = (*func_onVisit)(pTraverseCtx->pTraverseContext, pNode->pKey, REDBLACK_PREORDER, depth))))
            goto exit;

        if (OK > (status = REDBLACK_traverseTreeAndVisit(pNode->pLeft, pTraverseCtx, depth+1, func_onVisit)))
            goto exit;

        if ((REDBLACK_POSTORDER & pTraverseCtx->traverseMask) && (OK > (status = (*func_onVisit)(pTraverseCtx->pTraverseContext, pNode->pKey, REDBLACK_POSTORDER, depth))))
            goto exit;

        if (OK > (status = REDBLACK_traverseTreeAndVisit(pNode->pRight, pTraverseCtx, depth+1, func_onVisit)))
            goto exit;

        if ((REDBLACK_INORDER & pTraverseCtx->traverseMask) && (OK > (status = (*func_onVisit)(pTraverseCtx->pTraverseContext, pNode->pKey, REDBLACK_INORDER, depth))))
            goto exit;
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
REDBLACK_traverseTree(redBlackTreeDescr *pTree, void *pTraverseContext, ubyte4 traverseMask,
                      MSTATUS (*func_onVisit)(void *, const void *, enum nodeTraverseMethods traverseMethod, sbyte4))
{
    traverseContext travCtx;
    MSTATUS         status;

    if ((NULL == pTree) || (NULL == func_onVisit))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* minimize recursion impact to stack */
    travCtx.pTraverseContext = pTraverseContext;
    travCtx.traverseMask     = (0 == traverseMask) ? 0xffffffff : traverseMask;

    status = REDBLACK_traverseTreeAndVisit(pTree->pRoot, &travCtx, 0, func_onVisit);

exit:
    return status;
}

#endif /* __DISABLE_MOCANA_COMMON_REDBLACK_TREE__ */
