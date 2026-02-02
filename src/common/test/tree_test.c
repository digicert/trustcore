/* tree_test.c
 *
 * unit test for tree.c
 * 
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../tree.c"
#include "../../../unit_tests/unittest.h"


int tree_test_1(void)
{
  int i;
    int errors = 0;
    TreeItem *pChild = NULL;
    TreeItem *pParent = NULL;
    TreeItem *pRoot = TREE_MakeNewTreeItem(32);

    if (NULL == pRoot)
    {
        errors++;
        return errors;
    }
   
    pParent = pRoot;

    for (i=0; i<1000;i++)
    {
        pChild = TREE_MakeNewTreeItem(32);
        if (NULL != pChild)
        {
          errors += UNITTEST_STATUS(1, TREE_AppendChild(pParent, pChild));
          pParent = pChild;
        }
    }

    errors += UNITTEST_STATUS(1, TREE_DeleteTreeItem(pRoot));

     return errors;
}
