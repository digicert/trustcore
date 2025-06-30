/*
 * redblack.h
 *
 * Red-Black Tree Header
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

#ifndef __REDBLACK_HEADER__
#define __REDBLACK_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------*/

enum node_color
{
    RED,
    BLACK

};

enum redblackLookupMethods
{
    RB_LOOKUP_EQUAL,
    RB_LOOKUP_FIRST,
    RB_LOOKUP_NEXT

};

enum nodeTraverseMethods
{
    /* a mask to select different search combinations */
    REDBLACK_PREORDER  = 1,
    REDBLACK_INORDER   = 2,
    REDBLACK_POSTORDER = 4,
    REDBLACK_LEAF      = 8

};


/*--------------------------------------------------------------------------*/

typedef struct redBlackNodeDescr
{
    struct redBlackNodeDescr*    pLeft;
    struct redBlackNodeDescr*    pRight;
    struct redBlackNodeDescr*    pParent;

    const void*                 pKey;
    enum node_color             color;

} redBlackNodeDescr;

typedef struct redBlackTreeDescr
{
    MSTATUS (*func_redBlackGetNode) (void *pAllocCookie, void **ppNewNode);
    MSTATUS (*func_redBlackPutNode) (void *pAllocCookie, void **ppFreeNode);
    MSTATUS (*func_redBlackCompare) (const void *pRedBlackCookie, const void *pSearchKey, const void *pNodeKey, sbyte4 *pRetResult);

    void*   pRedBlackCookie;
    void*   pAllocCookie;

    struct redBlackNodeDescr*   pRoot;

} redBlackTreeDescr;


/*--------------------------------------------------------------------------*/

typedef struct redBlackListDescr
{
    const redBlackNodeDescr*    pNode;
    redBlackTreeDescr*          pTree;

} redBlackListDescr;


/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS REDBLACK_allocTree(redBlackTreeDescr **ppRetNewTree, MSTATUS (*func_redBlackGetNode)(void *, void **), MSTATUS (*func_redBlackPutNode)(void *, void **), MSTATUS (*func_redBlackCompare)(const void *, const void *, const void *, sbyte4 *), void *pRedBlackCookie, void *pAllocCookie);
MOC_EXTERN MSTATUS REDBLACK_freeTree(redBlackTreeDescr **ppRetNewTree, MSTATUS(*func_freeKey)(const void **ppFreeKey), void **ppRetRedBlackCookie, void **ppRetAllocCookie);

MOC_EXTERN MSTATUS REDBLACK_find(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetKey);
MOC_EXTERN MSTATUS REDBLACK_findOrInsert(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetFoundKey);
MOC_EXTERN MSTATUS REDBLACK_lookup(redBlackTreeDescr *pTree, enum redblackLookupMethods, const void *pSearchKey, const void **ppRetKey);

MOC_EXTERN MSTATUS REDBLACK_delete(redBlackTreeDescr *pTree, const void *pSearchKey, const void **ppRetKey);
MOC_EXTERN MSTATUS REDBLACK_condDeleteFirst(redBlackTreeDescr *pTree, const void **ppRetKey,
                                            intBoolean (*func_checkKey)(const void *pFoundKey),
                                            intBoolean *pDeleted);

MOC_EXTERN MSTATUS REDBLACK_traverseListInit(redBlackTreeDescr *pTree, redBlackListDescr **ppRetListTracker);
MOC_EXTERN MSTATUS REDBLACK_traverseListGetNext(redBlackListDescr *pListTracker, const void **ppRetNextKey);
MOC_EXTERN MSTATUS REDBLACK_traverseListFree(redBlackListDescr **ppFreeListTracker);

MOC_EXTERN MSTATUS REDBLACK_traverseTree(redBlackTreeDescr *pTree, void *pTraverseContext, ubyte4 traverseMask, MSTATUS (*func_onVisit)(void *, const void *, enum nodeTraverseMethods, sbyte4));

#ifdef __cplusplus
}
#endif

#endif /* __REDBLACK_HEADER__ */
