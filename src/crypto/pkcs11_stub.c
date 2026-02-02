/*
 * pkcs11_stub.c
 *
 * Mocana PKCS11 Stub
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_PKCS11_STUB__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/debug_console.h"
#include "../crypto/pkcs11.h"


/* General-purpose */

/* C_Initialize initializes the Cryptoki library. */
extern CK_RV
C_Initialize
(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO, "C_Initialize");
    return CKR_OK;
}


/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
extern CK_RV
C_Finalize
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Finalize");
    return CKR_OK;
}


/* C_GetInfo returns general information about Cryptoki. */
extern CK_RV
C_GetInfo
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetInfo");
    return CKR_OK;
}


/* C_GetFunctionList returns the function list. */
extern CK_RV
C_GetFunctionList
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetFunctionList");
    return CKR_OK;
}


/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
extern CK_RV
C_GetSlotList
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetSlotList");
    return CKR_OK;
}


/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
extern CK_RV
C_GetSlotInfo
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetSlotInfo");
    return CKR_OK;
}


/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
extern CK_RV
C_GetTokenInfo
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetTokenInfo");
    return CKR_OK;
}


/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
extern CK_RV
C_GetMechanismList
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetMechanismList");
    return CKR_OK;
}


/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
extern CK_RV
C_GetMechanismInfo
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetMechanismInfo");
    return CKR_OK;
}


/* C_InitToken initializes a token. */
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
extern CK_RV
C_InitToken
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_InitToken");
    return CKR_OK;
}


/* C_InitPIN initializes the normal user's PIN. */
extern CK_RV
C_InitPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_InitPIN");
    return CKR_OK;
}


/* C_SetPIN modifies the PIN of the user who is logged in. */
extern CK_RV
C_SetPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SetPIN");
    return CKR_OK;
}


/* Session management */

/* C_OpenSession opens a session between an application and a
 * token. */
extern CK_RV
C_OpenSession
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_OpenSession");
    return CKR_OK;
}


/* C_CloseSession closes a session between an application and a
 * token. */
extern CK_RV
C_CloseSession
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_CloseSession");
    return CKR_OK;
}


/* C_CloseAllSessions closes all sessions with a token. */
extern CK_RV
C_CloseAllSessions
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_CloseAllSessions");
    return CKR_OK;
}


/* C_GetSessionInfo obtains information about the session. */
extern CK_RV
C_GetSessionInfo
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetSessionInfo");
    return CKR_OK;
}


/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
extern CK_RV
C_GetOperationState
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetOperationState");
    return CKR_OK;
}


/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
extern CK_RV
C_SetOperationState
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SetOperationState");
    return CKR_OK;
}


/* C_Login logs a user into a token. */
extern CK_RV
C_Login
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Login");
    return CKR_OK;
}


/* C_Logout logs a user out from a token. */
extern CK_RV
C_Logout
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Logout");
    return CKR_OK;
}


/* Object management */

/* C_CreateObject creates a new object. */
extern CK_RV
C_CreateObject
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_CreateObject");
    return CKR_OK;
}


/* C_CopyObject copies an object, creating a new object for the
 * copy. */
extern CK_RV
C_CopyObject
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_CopyObject");
    return CKR_OK;
}


/* C_DestroyObject destroys an object. */
extern CK_RV
C_DestroyObject
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DestroyObject");
    return CKR_OK;
}


/* C_GetObjectSize gets the size of an object in bytes. */
extern CK_RV
C_GetObjectSize
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetObjectSize");
    return CKR_OK;
}


/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
extern CK_RV
C_GetAttributeValue
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetAttributeValue");
    return CKR_OK;
}


/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
extern CK_RV
C_SetAttributeValue

(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SetAttributeValue");
    return CKR_OK;
}


/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
extern CK_RV
C_FindObjectsInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_FindObjectsInit");
    return CKR_OK;
}


/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
extern CK_RV
C_FindObjects
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_FindObjects");
    return CKR_OK;
}


/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
extern CK_RV
C_FindObjectsFinal
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_FindObjectsFinal");
    return CKR_OK;
}


/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
extern CK_RV
C_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_EncryptInit");
    return CKR_OK;
}


/* C_Encrypt encrypts single-part data. */
extern CK_RV
C_Encrypt
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Encrypt");
    return CKR_OK;
}


/* C_EncryptUpdate continues a multiple-part encryption
 * operation. */
extern CK_RV
C_EncryptUpdate
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_EncryptUpdate");
    return CKR_OK;
}


/* C_EncryptFinal finishes a multiple-part encryption
 * operation. */
extern CK_RV
C_EncryptFinal
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_EncryptFinal");
    return CKR_OK;
}


/* C_DecryptInit initializes a decryption operation. */
extern CK_RV
C_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DecryptInit");
    return CKR_OK;
}


/* C_Decrypt decrypts encrypted data in a single part. */
extern CK_RV
C_Decrypt
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Decrypt");
    return CKR_OK;
}

/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
extern CK_RV
C_DecryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DecryptUpdate");
    return CKR_OK;
}


/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
extern CK_RV
C_DecryptFinal
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DecryptFinal");
    return CKR_OK;
}



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
extern CK_RV
C_DigestInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DigestInit");
    return CKR_OK;
}


/* C_Digest digests data in a single part. */
extern CK_RV
C_Digest
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Digest");
    return CKR_OK;
}


/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
extern CK_RV
C_DigestUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DigestUpdate");
    return CKR_OK;
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
extern CK_RV
C_DigestKey
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DigestKey");
    return CKR_OK;
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
extern CK_RV
C_DigestFinal
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DigestFinal");
    return CKR_OK;
}



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
extern CK_RV
C_SignInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignInit");
    return CKR_OK;
}


/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
extern CK_RV
C_Sign
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Sign");
    return CKR_OK;
}


/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
extern CK_RV
C_SignUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignUpdate");
    return CKR_OK;
}


/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature. */
extern CK_RV
C_SignFinal
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignFinal");
    return CKR_OK;
}


/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
extern CK_RV
C_SignRecoverInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignRecoverInit");
    return CKR_OK;
}


/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
extern CK_RV
C_SignRecover
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignRecover");
    return CKR_OK;
}



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
extern CK_RV
C_VerifyInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_VerifyInit");
    return CKR_OK;
}


/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
extern CK_RV
C_Verify
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_Verify");
    return CKR_OK;
}


/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
extern CK_RV
C_VerifyUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_VerifyUpdate");
    return CKR_OK;
}


/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
extern CK_RV
C_VerifyFinal
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_VerifyFinal");
    return CKR_OK;
}


/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
extern CK_RV
C_VerifyRecoverInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_VerifyRecoverInit");
    return CKR_OK;
}


/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
extern CK_RV
C_VerifyRecover
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_VerifyRecover");
    return CKR_OK;
}



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
extern CK_RV
C_DigestEncryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DigestEncryptUpdate");
    return CKR_OK;
}


/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
extern CK_RV
C_DecryptDigestUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DecryptDigestUpdate");
    return CKR_OK;
}


/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
extern CK_RV
C_SignEncryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SignEncryptUpdate");
    return CKR_OK;
}


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
extern CK_RV
C_DecryptVerifyUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DecryptVerifyUpdate");
    return CKR_OK;
}



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
extern CK_RV
C_GenerateKey
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GenerateKey");
    return CKR_OK;
}


/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects. */
extern CK_RV
C_GenerateKeyPair
(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GenerateKeyPair");
    return CKR_OK;
}


/* C_WrapKey wraps (i.e., encrypts) a key. */
extern CK_RV
C_WrapKey
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_WrapKey");
    return CKR_OK;
}


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
extern CK_RV
C_UnwrapKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_UnwrapKey");
    return CKR_OK;
}


/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
extern CK_RV
C_DeriveKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_DeriveKey");
    return CKR_OK;
}



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
extern CK_RV
C_SeedRandom
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_SeedRandom");
    return CKR_OK;
}


/* C_GenerateRandom generates random data. */
extern CK_RV
C_GenerateRandom
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GenerateRandom");
    return CKR_OK;
}



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
extern CK_RV
C_GetFunctionStatus
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_GetFunctionStatus");
    return CKR_OK;
}


/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
extern CK_RV
C_CancelFunction
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_CancelFunction");
    return CKR_OK;
}



/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
extern CK_RV
C_WaitForSlotEvent
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
    DEBUG_PRINT(DEBUG_CRYPTO,"C_WaitForSlotEvent");
    return CKR_OK;
}

#endif /* __ENABLE_DIGICERT_PKCS11_STUB__ */
