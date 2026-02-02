/**
 * @file fapi2_context.h
 * @brief This file contains code required to maintain state in FAPI2.
 * commands.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_CONTEXT_H__
#define __FAPI2_CONTEXT_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_types.h"

/*
 * This is the function that any applications using the FAPI are expected to
 * make. This creates a FAPI context with information required to be able
 * to communicate to a TPM2 device.
 * ppFapiContext - Opaque FAPI context that contains required information
 * for FAPI to operate. The context is not thread safe, therefore no more
 * than one thread can use the same FAPI context at any given time. Memory
 * is allocated for the context by the API. The application must call
 * FAPI2_CONTEXT_uninit to free the memory allocated here.
 *
 * tpmVersion - TODO: Remove this ?
 *
 * serverNameLen - length of the server name byte string provided in pServerName.
 *
 * pServerName - pointer to a NULL terminated string buffer specifying the location
 * at which the TPM exists. If one is not provided, common server names are tried.
 *
 * servePort - port at which the TPM is listening. This is useful for simulators and
 * remote TPMs.
 *
 * objCacheSize - Max number of FAPI2 objects that the context must be able to cache.
 * This must be at least 3. FAPI2 returns handles to FAPI2 objects(such as keys)
 * and object operations(such as Signing) expect handles as their input parameters.
 * This field is used to allocate the number of simultaneous handles/objects
 * the context is expected to hold. The FAPI2 context behaves similar to TPM hardware
 * in terms of number of object slots it contains.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_init(FAPI2_CONTEXT **ppFapiContext, ubyte4 serverNameLen, ubyte *pServerName,
        ubyte2 serverPort, ubyte objCacheSize, void *pReserved);

/*
 * Destroys the context created by FAPI2_CONTEXT_INIT and releases memory allocated
 * by context creation,
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_uninit(FAPI2_CONTEXT **ppFapiContext);

/*
 * An application is expected to call this API after creating a context
 * and set the authValues of all hierarchies. The hierarchy authValues
 * are used internally by many FAPI's. This is useful to applications
 * to avoid having to pass the authValue every time a FAPI is invoked.
 * If the application does not want the authValues lying around in the
 * context, it is expected to call this API with all inputs with size 0,
 * which will clear the authValues in memory.
 * The authValues are initialized to the EmptyBuffer(authValue of
 * size 0) during context creation.
 * If all parameters are of size 0, the function does NOT return
 * an error but does clear out the authValues in the context
 */

MOC_EXTERN TSS2_RC FAPI2_CONTEXT_setHierarchyAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetHierarchyAuthIn *pIn
);

/*
 * An application is expected to call this API after creating a context
 * and set the authValues of the EK and SRK. The EK and SRK objects are
 * created with authValues equal to the EmptyBuffer and will be used as
 * is unless the application explicitly sets their authValues.
 * This is useful to applications to avoid having to pass the authValue
 * every time a FAPI is invoked.
 * If the application does not want the authValues lying around in the
 * context, it is expected to call this API with all inputs with size 0,
 * which will clear the authValues in memory.
 *  If all parameters are of size 0, the function does NOT return an
 * error but does clear out the authValues in the context.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_setPrimaryKeyAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetPrimaryKeyAuthIn *pIn
);

/*
 * This API can be used to obtain the max length that can be used for authValues
 * for regular objects and hierarchies.
 * The default name algorithm in a FAPI2_CONTEXT is SHA256, so 32 bytes is the
 * default value/expected value.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getMaxAuthValueLength(
        FAPI2_CONTEXT *pCtx,
        ContextGetAuthValueLengthOut *pOut
);

/*
 * This API can be used to load an object into a FAPI2 CONTEXT. When a FAPI2
 * API to create an object is invoked, the serialized object suitable for storage
 * is returned. When a new context is created, this API must be used to make
 * the serialized object usable again.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_loadObject(
        FAPI2_CONTEXT *pCtx,
        ContextLoadObjectIn *pIn,
        ContextLoadObjectOut *pOut
);

/*
 * This API can be used to flush an object that is loaded into a FAPI2_CONTEXT.
 * This will destroy the object with the given Name and free all resources
 * used by the object. Objects are loaded when they are created or when they
 * are deserialized and explicitly loaded into the context.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_flushObject(
        FAPI2_CONTEXT *pCtx,
        ContextFlushObjectIn *pIn
);


/*
* This function evicts previously persisted key  
* It will return a failure if key is not found.
*/
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_evictKey(
        FAPI2_CONTEXT *pCtx,
        EvictKeyIn *pIn
);

/*
* This function looks up a FAPI2_OBJECT corresponding the given name.
* It will return a failure if an object is not found.
*/
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_lookupObject(
    FAPI2_CONTEXT *pCtx,
    TPM2B_NAME *pName,
    FAPI2_OBJECT **ppObject
);

/*
 * This API can be used to get the last error that the TPM provided in its response
 */
TSS2_RC FAPI2_CONTEXT_getLastTpmError(
        FAPI2_CONTEXT *pCtx,
        ContextGetLastTpmErrorOut *pOut
);

/*
 * This API informs the caller if the TPM is provisioned or not. If there is no EK
 * or SRK provisioned on the TPM, the TPM can only be used as a crypto engine and
 * Key creation, attestation, signing etc cannot be performed using
 * the TPM.
 * Success returned in the API does not mean that the TPM is provisioned. The output
 * parameter must be checked by the caller.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_isTpmProvisioned(
        FAPI2_CONTEXT *pCtx,
        ContextIsTpmProvisionedOut *pOut
);

/*
 * This API can be used to get handles/names of primary objects such as EK, SRK, AK etc.
 * For persistent/primary objects(which are typically primary keys), no handle is returned
 * when the objects are created. For non-persistent objects, a handle/name is returned
 * upon creation or when the serialized object is loaded into a context. Since the primary
 * keys/objects are persistent and no private area is returned by the TPM, there is no need
 * for a serialized object or handle to be returned. Any time there is a requirement to use
 * these primary/persistent objects, an application can provided the persistent handle to
 * this API to get a handle back, which can then be used in any other API's that require
 * a handle(such as FAPI2_ASYM_sign() etc). A slot in the object cache is used if an object
 * is created and does not already exist in the context.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getPrimaryObjectName(
        FAPI2_CONTEXT *pCtx,
        ContextGetPrimaryObjectNameIn *pIn,
        ContextGetPrimaryObjectNameOut *pOut
);

/*
 * This API can be used to set the authValue for an object once it has been loaded. An
 * application may want to load an object using FAPI2_CONTEXT_loadObject but not want to
 * provide the authValue during load and instead only provided it right before use. This
 * API can be used in such situations. Using an authValue of size 0 will clear the authValue
 * in memory and applications can use this API to clear an authValue that has been set.
 * For EK and SRK, FAPI2_CONTEXT_setPrimaryKeyAuth() or FAPI2_CONTEXT_setPrimaryKeyAuth
 * can be used.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_setObjectAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetObjectAuthIn *pIn
);

MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getObjectPrivateInfo(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPrivateInfoIn *pIn,
        ContextGetObjectPrivateInfoOut *pOut
);

MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getObjectPrivateInfoBlob(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPrivateInfoIn *pIn,
        ContextGetObjectPrivateInfoBlobOut *pPrivateBlob
);

/*
 * This API can be used to get an objects public information, which contains information about
 * its type, its name, its public key(if any), schemes, sizes, curvers, policy digests etc.
 * The object for which the information is required, must be loaded into the context.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getObjectPublicInfo(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPublicInfoIn *pIn,
        ContextGetObjectPublicInfoOut *pOut
);

MOC_EXTERN TSS2_RC FAPI2_CONTEXT_getObjectPublicInfoBlob(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPublicInfoIn *pIn,
        ContextGetObjectPublicInfoBlobOut *pPublicBlob
);


/*
 * This API retrieves FAPI2_OBJECT associated to the objectHandle.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_lookupPrimaryObjectByHandle(
        FAPI2_CONTEXT *pCtx,
        TPM2_HANDLE objectHandle,
        FAPI2_OBJECT **ppObject
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_CONTEXT_H__ */
