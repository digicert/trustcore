/*
 * pkcs11_rsa.c
 *
 * RSA public key encryption
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


/*------------------------------------------------------------------*/

#include "../../common/moptions.h"

#if (defined(__RSAINT_HARDWARE__) && defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../crypto/crypto.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/prime.h"
#include "../../harness/harness.h"
#include "../../harness/hw_accel_async.h"
#include "../../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/fips.h"
#endif

#include "../../crypto/pkcs11.h"
#include "../../crypto/hw_offload/pkcs11_rsa.h"
#include "../../common/absstream.h"
#include "../../common/tree.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs7.h"


/*------------------------------------------------------------------*/

static MSTATUS
getPrivKeyObjHandle (CK_SESSION_HANDLE hSession,
                     CK_OBJECT_CLASS keyClass,
                     CK_OBJECT_HANDLE_PTR ppPrivKeyObj)
{
    CK_BYTE            ckaLabel[] = "Encryption";
    CK_OBJECT_CLASS    ckaClass = keyClass;
    CK_ATTRIBUTE       ckaTemplate[] = {{ CKA_CLASS, &ckaClass, sizeof(ckaClass) },
                                        { CKA_LABEL, ckaLabel, sizeof(ckaLabel) }};
    CK_ULONG           ulTmplCnt = 2;
    CK_ULONG           ulCnt = 0;
    MSTATUS            status = OK; /* CKR_OK == DIGICERT OK */

    if ((CK_SESSION_HANDLE)0    == hSession ||
        (CK_OBJECT_HANDLE_PTR)0 == ppPrivKeyObj)
    {
        status = ERR_NULL_POINTER; /* CKR_ARGUMENTS_BAD */
        goto exit;
    }

    /* Query the private key index object to for C_Decrypt' hKey */
    if (OK != (status = C_FindObjectsInit(hSession, ckaTemplate, ulTmplCnt)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        goto exit;
    }

    if (OK != (status = C_FindObjects(hSession, ppPrivKeyObj, 1, &ulCnt)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        C_FindObjectsFinal(hSession);
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
/* since RSAINT_decrypt was originally 'static', changed function parameters to fit PKCS#11 */

extern MSTATUS
RSAINT_decrypt(CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE pKey,
               CK_BYTE_PTR pEncryptedData,
               CK_ULONG ulEncryptedDataLen,
               CK_BYTE_PTR pData,
               CK_ULONG_PTR pulDataLen)
{
    CK_OBJECT_HANDLE   pPrivKeyObject = (CK_OBJECT_HANDLE)0;
    MSTATUS            status = OK; /* CKR_OK == DIGICERT OK */
    intBoolean         isFindObjectsInitDone = FALSE;

    if ((CK_SESSION_HANDLE)0 == hSession               ||
        NULL                 == (void *)pEncryptedData ||
        0                    == ulEncryptedDataLen     ||
        NULL                 == pulDataLen)
    {
        status = ERR_NULL_POINTER; /* CKR_ARGUMENTS_BAD */
        goto exit;
    }

    if ((CK_OBJECT_HANDLE)0 == pKey)
    {
        if (OK != (status = getPrivKeyObjHandle(hSession, CKO_PRIVATE_KEY, &pPrivKeyObject)))
            goto exit;
        pKey = pPrivKeyObject;
    }

    isFindObjectsInitDone = TRUE;

    if (CKR_OK != (status = C_DecryptInit(hSession, pMechanism, pKey)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        goto exit;
    }

    /* C_Decrypt is for single part decryption, meaning no loop is required */
    if (CKR_OK != (status = C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        goto exit;
    }


exit:
    /* C_FindObjectsFinal has to be called at the end of the PKCS#11 operations */
    if (isFindObjectsInitDone)
        C_FindObjectsFinal(hSession);

    return status;
}


/*------------------------------------------------------------------*/
/* since RSA_signMessage is 'public', kept the parameters unchanged */

extern MSTATUS
RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
                const ubyte* plainText, ubyte4 plainTextLen,
                ubyte* cipherText, vlong **ppVlongQueue)
{
    CK_OBJECT_HANDLE   pPrivKeyObject = (CK_OBJECT_HANDLE)0;
    MSTATUS            status = OK; /* CKR_OK == DIGICERT OK */
    intBoolean         isFindObjectsInitDone = FALSE;

    if ((hwAccelDescr)0 == hwAccelCtx ||
        NULL == plainText             ||
        NULL == cipherText            ||
        NULL == ppVlongQueue)
    {
        status = ERR_NULL_POINTER; /* CKR_ARGUMENTS_BAD */
        goto exit;
    }

    if (NULL == pKey)
    {
        if (OK != (status = getPrivKeyObjHandle((CK_SESSION_HANDLE)hwAccelCtx, CKO_PRIVATE_KEY, &pPrivKeyObject)))
            goto exit;
        pKey = (RSAKey *)pPrivKeyObject;
    }

    isFindObjectsInitDone = TRUE;
    if (CKR_OK != (status = C_SignInit((CK_SESSION_HANDLE)hwAccelCtx, NULL, pKey)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        goto exit;
    }

    if (CKR_OK != (status = C_Sign((CK_SESSION_HANDLE)hwAccelCtx, (CK_BYTE_PTR)plainText,(CK_ULONG)plainTextLen,
                                   (CK_BYTE_PTR)cipherText, (CK_ULONG_PTR)ppVlongQueue)))
    {
        status = CONVERT_ERRNO_CKR_TO_MOC(status);
        goto exit;
    }


exit:
    /* C_FindObjectsFinal has to be called at the end of the PKCS#11 operations */
    if (isFindObjectsInitDone)
        C_FindObjectsFinal((CK_SESSION_HANDLE)hwAccelCtx);

    return status;
}


/*------------------------------------------------------------------*/
/* Dummy functions just to make build through. None of them actually will be used. */

extern MSTATUS
DUMMYHARNESS_initDrv(void)
{
    return OK;
}

extern void
DUMMYHARNESS_termDrv(void)
{
}

extern MSTATUS
DUMMYHARNESS_listOfInitRegionDescrs(hwAccelAsyncRegionDescr **ppRetTable, sbyte4 *pRetNumEntries)
{
    return OK;
}

extern MSTATUS
DUMMYHARNESS_listOfInitIrqDescrs(hwAccelAsyncIrqDescr **ppRetTable, sbyte4 *pRetNumEntries)
{
    return OK;
}

extern MSTATUS
DUMMYHARNESS_verifyInit(void)
{
    return OK;
}

extern intBoolean
DUMMYHARNESS_interruptSecHandler(int irqNum, void *appContext, intBoolean *pRetRearmTimer)
{
    return TRUE;
}

extern intBoolean
DUMMYHARNESS_interruptTimerHandler(int irqNum, intBoolean testInterrupt)
{
    return TRUE;
}

extern int
DUMMYHARNESS_timerHandler(void)
{
    return OK;
}

extern int
DUMMYHARNESS_ioctl(int cmd, int arg)
{
    return OK;
}

extern intBoolean
DUMMYHARNESS_dispatchServiceRequests(void)
{
    return OK;
}

extern void
DUMMYHARNESS_initServiceRequestQueues(void)
{
}

extern intBoolean
DUMMYHARNESS_addServiceRequest(mahCellDescr *pCell, ubyte4* pRetIndexHint)
{
    return OK;
}

#endif /* __RSAINT_HARDWARE__ && __ENABLE_DIGICERT_PKCS11_CRYPTO__ */
