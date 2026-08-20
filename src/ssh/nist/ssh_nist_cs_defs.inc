/*
 * ssh_nist_cs_defs.inc
 *
 * Cipher Suite definitions for testing SSH against SP 800-135
 *
 */

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

typedef struct
{
    ubyte *pKey;
    ubyte4 keyLen;
} testCtx;

extern BulkCtx
CreateTestCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = OK;
    testCtx *ctx = NULL;
    MOC_UNUSED(encrypt);

    status = DIGI_MALLOC((void **)&ctx, sizeof(testCtx));
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&ctx->pKey, keyLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)ctx->pKey, keyMaterial, keyLength);
    if (OK != status)
        goto exit;

    ctx->keyLen = keyLength;

exit:
    if (OK != status)
        return NULL;

    return (BulkCtx)(ctx);
}

extern MSTATUS
DeleteTestCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    testCtx *pCtx = NULL;
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    pCtx = *ctx;
    if (NULL != pCtx)
    {
        if (NULL != pCtx->pKey)
        {
            DIGI_FREE((void **)&pCtx->pKey);
        }

        DIGI_FREE((void **)&pCtx);
    }

    return OK;
}

extern MSTATUS
DoTestCipher(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MOC_UNUSED(ctx);
    MOC_UNUSED(data);
    MOC_UNUSED(dataLength);
    MOC_UNUSED(encrypt);
    MOC_UNUSED(iv);

    return OK;
}

static BulkEncryptionAlgo TestSuite =
    { 16, CreateTestCtx, DeleteTestCtx, DoTestCipher };

#endif
