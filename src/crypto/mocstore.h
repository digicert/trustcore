/*
 * mocstore.h
 *
 * Declarations and definitions for keeping keys, certs, or other entries in a
 * storage facility. Where things are actually stored could be an in-memory
 * "database", it could be a real database, or in files, or on flash, or an SD
 * card, or so on.
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

#include "../crypto/mocsym.h"
#include "../crypto/mocasym.h"
#include "../asn1/mocasn1.h"
#include "../common/datetime.h"
#include "../crypto/certops.h"
#include "../crypto/certops/certobj.h"

// Temp: this will be in mocsym.h.
#define MOC_STORE_OP_CODE       0x40000

#ifndef __MOC_STORE_HEADER__
#define __MOC_STORE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* The mocstore.h file needs to include the certops.h file, and the certops.h
 * file needs the MocStore type.
 * So rather than have a circular reference, use this forward referencing. If it
 * is defined, don't define it again, but make sure it is defined in every file
 * it is used.
 */
#ifndef __MOC_STORE__
struct MocStoreObject;
typedef struct MocStoreObject *MocStore;
#define __MOC_STORE__
#endif

/* This storage facility will contain a set of entries. The entries will most
 * likely be certs, maybe a key or two, and maybe something else (called generic
 * value, which might be a URL, an IP address, or so on). The first field in an
 * entry is the type, which describes what the entry contains.
 */

/* Each entry in a cert store has a type. The type is a bit field that contains
 * bits specifying information about the entry. The following are the bits that
 * define the type.
 */

#define MOC_STORE_ENTRY_TYPE_UNDEF    0x0000

/** A Store contains entries. An entry will be a data struct containing a type
 * and data. See the MocStoreEntry struct. The data in an entry is dependant on
 * the type. The type is a bit field, where each bit is one of the
 * MOC_STORE_ENTRY_TYPE values.
 * <p>There are three types of entries: X.509, Generic, PSK. Each entry can be
 * either Data or not.
 * <p>Start from the last.
 * <pre>
 * <code>
 *   PSK is Pre-Shared Key and is not yet implemented. It is there for
 *     future use.
 *   With Generic, the data stored is generic data (a byte array and
 *     length).
 *   With X.509, the entry stored is an X.509 cert and associated private
 *     key, or the cert alone, or the key alone. They are stored as
 *     objects.
 * </code>
 * </pre>
 * <p>Each of the three types can be combined with Data.
 * <p>With Data, the contents do not contain objects, data only. When combined with
 * X.509, it means there is a key and cert, or key only, or cert only, and they
 * are data, not objects. A Generic entry will always also be Data.
 * <pre>
 * <code>
 *   X509
 *   X509     |  DATA
 *   GENERIC  |  DATA
 *   PSK
 * </code>
 * </pre>
 * <p>There is a struct for each type. The full MocStoreEntry struct contains a
 * field for type, then a union of all the structs for each type. To read an
 * Entry struct, look at the type. Depending on the type, look at the
 * corresponding element in the union.
 * <p>There is more information in the type field. If you want to examine only
 * those bits that tell you what struct to use, then look at the
 * type & MOC_STORE_ENTRY_TYPE_MASK.
 */

/** This bit will be set if the entry contains an X.509 key/cert.
 * <p>If this bit is set, and the ENTRY_TYPE_DATA bit is not set, the
 * MKeyCertEntry element in the union will contain the entry's contents.
 * <p>If this bit is set, and the ENTRY_TYPE_DATA bit is also set, the
 * MKeyCertDataEntry element in the union will contain the entry's contents.
 */
#define MOC_STORE_ENTRY_TYPE_X509     0x0001

/** This bit will be set if the entry contains a "generic" value. This is for
 * entries that are something else, not a key and/or cert. The only way to search
 * for generic items is with the label.
 * <p>It is not possible to store a cert/key plus generic combination. That is,
 * you either store a key/cert combo (or key alone or cert alone) or a generic
 * entry, but one entry cannot contain generic plus key/cert.
 * <p>If this bit is set, the MGenericEntry element in the union will contain the
 * entry's contents.
 */
#define MOC_STORE_ENTRY_TYPE_GENERIC  0x0002

/** This bit will be set if the entry is for a PSK.
 * <p>Currently unused, it is here for future releases.
 */
#define MOC_STORE_ENTRY_TYPE_PSK      0x0004

/** This bit will be set if the entry contains data only, not objects.
 */
#define MOC_STORE_ENTRY_TYPE_DATA     0x0008

/** You can use this value to mask off the part of the type that descibes what
 * format the data in the entry is.
 */
#define MOC_STORE_ENTRY_TYPE_MASK     0x000F

/** You can use this to differentiate between X509 in objects, and X509 in data.
 * <p>For example, you can create a value that is the type & MASK, then have a
 * switch statement on the result. TYPE_X509 will be different from
 * TYPE_X509_DATA.
 */
#define MOC_STORE_TYPE_X509_DATA      (MOC_STORE_ENTRY_TYPE_X509|MOC_STORE_ENTRY_TYPE_DATA)

/** Because a generic entry will always be data, use this flag to differentiate
 * between X509, PSK, and Generic.
 */
#define MOC_STORE_TYPE_GENERIC_DATA   \
    (MOC_STORE_ENTRY_TYPE_GENERIC|MOC_STORE_ENTRY_TYPE_DATA)

/** This bit will be set if the entry contains an RSA key/cert.
 */
#define MOC_STORE_ENTRY_TYPE_RSA      0x0010

/** This bit will be set if the entry contains a DSA key/cert.
 */
#define MOC_STORE_ENTRY_TYPE_DSA      0x0020

/** This bit will be set if the entry contains an ECC key/cert.
 */
#define MOC_STORE_ENTRY_TYPE_ECC      0x0040

/** This bit will be set if the entry contains a DH key/cert.
 */
#define MOC_STORE_ENTRY_TYPE_DH       0x0080

/* Unused bits at the moment:
 *   0x0100
 *   0x0200
 */

/** This bit will be set if the entry contains a key.
 */
#define MOC_STORE_ENTRY_TYPE_KEY      0x0400

/** This bit will be set if the entry contains a cert
 */
#define MOC_STORE_ENTRY_TYPE_CERT     0x0800

/** This bit will be set if the entry's cert is a trusted cert.
 */
#define MOC_STORE_ENTRY_TYPE_TRUSTED  0x1000

/** This bit will be set if the entry's generic value was copied by reference. If
 * it had been copied by value, the bit will not be set. There is no bit that
 * explicitly states that the value was copied by value.
 * <p>Note that this makes sense only for an in-memory storage facility.
 */
#define MOC_STORE_ENTRY_GENERIC_REF   0x2000

/** This bit will be set if the entry's key was copied by reference. If it had
 * been copied by value, the bit will not be set. There is no bit that explicitly
 * states that the key was copied by value.
 * <p>Note that this makes sense only for an in-memory storage facility.
 */
#define MOC_STORE_ENTRY_KEY_REF       0x4000

/** This bit will be set if the entry's cert was copied by reference. If it had
 * been copied by value, the bit will not be set. There is no bit that explicitly
 * states that the cert was copied by value.
 * <p>Note that this makes sense only for an in-memory storage facility.
 */
#define MOC_STORE_ENTRY_CERT_REF      0x8000

/** This is an entry that contains a key and cert as objects.
 * <p>It is the struct chosen if the type is
 * <pre>
 * <code>
 *   MOC_STORE_ENTRY_TYPE_X509
 * </code>
 * </pre>
 * <p>If there is a cert, the isTrusted field will be TRUE if the cert is
 * trusted, FALSE otherwise. If there is no cert, the isTrusted field is
 * meaningless but will be FALSE.
 */
typedef struct
{
  MocAsymKey       pPriKey;
  MCertObj            pCertObj;
  intBoolean          isTrusted;
} MKeyCertEntry;

/** This is an entry that contains a key and cert, but the key is data only, not
 * an object.
 * <p>The cert is still an object.
 * <p>It is the struct chosen if the type is
 * <pre>
 * <code>
 *   MOC_STORE_ENTRY_TYPE_X509 | MOC_STORE_ENTRY_TYPE_DATA
 * </code>
 * </pre>
 * <p>If there is a cert, the isTrusted field will be TRUE if the cert is
 * trusted, FALSE otherwise. If there is no cert, the isTrusted field is
 * meaningless but will be FALSE.
 */
typedef struct
{
  ubyte              *pKeyDer;
  ubyte4              keyDerLen;
  MCertObj            pCertObj;
  intBoolean          isTrusted;
} MKeyCertDataEntry;

/* This is an entry that contains a generic value.
 * It is the struct chosen if the type is
 *   MOC_STORE_ENTRY_TYPE_GENERIC | MOC_STORE_ENTRY_TYPE_DATA
 */
typedef struct
{
  ubyte              *pGenericValue;
  ubyte4              genericValueLen;
} MGenericEntry;

/** This is an entry in the MocStore.
 * <p>The type is a bit field indicating the contents (key/cert or PSK or
 * Generic, and Data or object). Which of the contents union fields used depends
 * on the type. Specifically, it depends on the MOC_STORE_ENTRY_TYPE_MASK bits.
 * <p>The type also contains other information, such as if the entry is X509
 * whether the contents contain the key, cert, or key and cert.
 */
typedef struct
{
  ubyte4                type;
  ubyte                *pLabel;
  ubyte4                labelLen;
  union
  {
    MKeyCertEntry       keyCert;
    MKeyCertDataEntry   keyCertData;
    MGenericEntry       generic;
  } contents;
} MocStoreEntry;

/** This is the signature of a StorageType.
 * <p>When building an instance of a Store, specify which type of store it will
 * be with a StorageType. A StorageType is actually a function. You won't call
 * that function directly, but simply use it as an argument to the MocStoreCreate
 * function.
 * <p>Each StorageType will document what associated info it needs in order to be
 * instantiated.
 * <p>If you need to build a new StorageType, write a function that has this
 * signature, then write the code to implement each of the opCodes you want to
 * support. Each opCode will describe what the input and output info is.
 * <p>A StorageType should not worry about threading. The upper API will acquire
 * a lock before calling the implementation.
 */
typedef MSTATUS (*MStorageType) (
  MocStore pStoreObj,
  ubyte4 opCode,
  void *pInput,
  void *pOutput
  );

/** Create a new instance of a storage facility.
 * <p>This creates a store that follows the rules of the given StorageType.
 * <p>The caller chooses a StorageType, and supplies the associated info that
 * type needs. For one StorageType, the associated info might be NULL, for
 * another, it could be a config file, or a database handle, or a password. Look
 * at the documentation for each StorageType to determine what it needs, then
 * collect that information in the form it needs and pass it as the pInfo arg.
 * <p>You can have more than one MocStore alive at any one time. Each will
 * contain only those entries that you add to the specific store. That is, any
 * particular element in one instance, is not in another instance, unless you
 * add the same value to both.
 * <p>A storage facility might be in-memory and the contents are alive only as
 * long as the Storage object is alive. Or it could be a persistent store, in
 * which case, every time you create a new instance, the object points to
 * existing entries.
 * <p>You might want to have two storage facilities alive at any one time. For
 * example, you might have one storage object contain root certs persistently,
 * and per-message certs in memory.
 * <p>There is another storage object in NanoCrypto (a cert store, see
 * cert_store.h). This store differs in that it offers multiple implementations,
 * generic entries, and it uses the new certificate operations (see certops.h),
 * the new ASN.1 engine, along with MocSym and MocAsymKey.
 * <p>You specify whether the store will be used by multiple threads or not. If
 * only one thread will access the store (either the app is single-threaded or
 * each thread in the app will have its own store), pass FALSE as the
 * isMultiThreaded arg. Otherwise, pass TRUE. Operations will be slower in
 * multi-threaded (when isMultiThreaded is TRUE).
 * <p>A note on sharing an object among threads: The safest way to do so is to
 * create the object in a main thread, then pass a reference to that object to
 * each created thread. Then, when all threads have completed (exited), free the
 * object. Don't free the object in one of the threads, don't free the object
 * until each thread has exited. The MocStore will do things to prevent threading
 * problems even if the app does something unrecommended. However, it is better
 * to just use it in the safest way.
 * <p>When done with the store, you must call MocStoreFree.
 * <pre>
 * <code>
 *   MocStore pStore = NULL;
 *
 *   status = MocStoreCreate (MStorageTypeMemory, NULL, TRUE, &pStore);
 *
 *    . . .
 *
 *   MocStoreFree (&pStore);
 * </code>
 * </pre>
 *
 * @param StorageType The underlying implementation.
 * @param pInfo The specific info the StorageType needs to operate.
 * @param isMultiThreaded Set to TRUE if the store will be shared among threads.
 * Set it to FALSE if the store will be used by only one thread.
 * @param ppNewStore The address where the function will deposit the new MocStore
 * object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreCreate (
  MStorageType StorageType,
  void *pInfo,
  intBoolean isMultiThreaded,
  MocStore *ppNewStore
  );

/** Free a MocStore created by MocStoreCreate.
 * <p>This will free the store object. If the store is in-memory, it will also
 * free and entries that had been loaded. If it is a persistent storage facility,
 * it will simply sever the connection to the entries, it will not delete them.
 *
 * @param ppStore The address where the function will find the store to free. It
 * will deposit a NULL at that address after successfully freeing the store.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreFree (
  MocStore *ppStore
  );

/** Implements MStorageType
 * <p>Use this as the StorageType arg in a call to MocStoreCreate when you want
 * to build an in-memory storage facility.
 * <p>The associated info to accompany this value is NULL.
 * <p>Upon creation, there will be no entries in the store. When the store is
 * freed, all entries will be freed as well.
 */
MOC_EXTERN MSTATUS MStorageTypeMemory (
  MocStore pStoreObj,
  ubyte4 opCode,
  void *pInput,
  void *pOutput
  );

/** Lock or unlock a MocStore.
 * <p>Locking a MocStore has nothing to do with threading. It is simply a way to
 * specify that a particluar store is allowed or not allowed to accept new or
 * delete old entries.
 * <p>Upon creation, a store is unlocked, meaning you can add and delete.
 * <p>If you want to lock a store, call this function with MOC_STORE_LOCK as the
 * lockFlag.
 * <p>If you want to unlock a store, call this function with MOC_STORE_UNLOCK as
 * the lockFlag.
 * <p>If a store is already locked and you call with MOC_STORE_LOCK, the function
 * will do nothing and return OK. If it is unlocked and you call with
 * MOC_STORE_UNLOCK, the function does nothing and returns OK.
 *
 * @param pStore The store to lock or unlock.
 * @param lockFlag Indicates whther to lock or unlock. It must be either of the
 * values MOC_STORE_LOCK or MOC_STORE_UNLOCK.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreSetLock (
  MocStore pStore,
  ubyte4 lockFlag
  );

/** Pass this value as the lockFlag arg if you want to lock the store.
 */
#define MOC_STORE_LOCK    1

/** Pass this value as the lockFlag arg if you want to unlock the store.
 */
#define MOC_STORE_UNLOCK  2

/** Add a new entry to the store.
 * <p>The label can be NULL, but you might have a label against which the cert is
 * stored and searched. This is sometimes called an alias. It can be an ASCII
 * string (something like "ABCSigningKey" or "Verisign Root Cert") or a binary
 * byte array.
 * <p>The maximum label length is 255 (0xff). The length of the label must fit in
 * one unsigned byte.
 * <p>Every time you add an entry with a label, the store will check to make sure
 * the label is unique. If an entry already exists with the given label, the
 * function will return an error. If you need to replace an entry, delete the old
 * entry, then add the new one. Note that you can only delete entries that have
 * labels.
 * <p>Note also that a generic entry must have a label. That is, you can store a
 * cert or key with or without a label, but a generic entry must have a label.
 * <p>If you want to add a generic value, pass in a pointer to a byte array with
 * the pGenericValue arg. If you pass in a generic value, the function will
 * ignore the key and cert args, it will load only the generic value.
 * <p>If the pGenericValue arg is NULL, or the genericValueLen arg is 0, the
 * function will load a key and/or cert. If the private key is NULL or empty
 * (key->type = akt_undefined = 0), the function will load only a cert. If you do
 * supply a key it must be a MocKey (key->type = akt_moc).
 * <p>If you supply a cert, it must be a cert object. See certops.h for more on
 * how to build an object.
 * <p>You must supply at least one element (generic, key, or cert). If all the
 * entry args are NULL, this function will return an error.
 * <p>If the cert is a trusted cert (generally these are root certs), pass in
 * TRUE for the isTrusted arg. Otherwise, pass in FALSE.
 * <p>The copyFlag arg is used only by in-memory storage implementations. It
 * indicates whether the value should be copied by reference or value. This arg
 * is a bit field. If you set the MOC_COPY_KEY_BY_REF bit only, the key will be
 * copied by reference and the cert by value. If you set only the
 * MOC_COPY_CERT_BY_REF bit, the cert will be copied by reference and the key by
 * value. If you set it to the OR of the two, or MOC_COPY_ENTRY_BY_REF, both will
 * be copied by reference.
 * <p>Similarly there is a bit to copy the generic value by reference:
 * MOC_COPY_GENERIC_BY_REF.
 * <p>If you set copyFlag to 0, the function will copy everything by value (the
 * function will allocate new memory for the generic value, or clone the key and
 * cert objects so that the store has its own copy of each).
 * <p>Copying by reference is faster and saves memory. However, remember that
 * copy by reference means the function will simply copy the pointers, so that
 * the entry will point to your objects, the objects you create and control. Make
 * sure those objects will remain valid for as long as the store is active.
 * <p>Note that the only way to store a cert is with a CertObj. If you have the
 * DER of a cert instead of a cert object, you can call X509_parseCert to get a
 * CertObj.
 * <p>The only way to pass in a key is with a MocAsymKey object. The reason
 * for this is that a key can be a hardware key, not necessarily a normal DER-
 * encoded key. Hence, the one format that is supported by all is the
 * MocAsymKey. Call CRYPTO_deserializeMocAsymKey to build an object if you have
 * the DER or PEM of a key or even a Mocana key blob. Some storage providers
 * won't be able to store objects, only data, but you still must pass the data in
 * as objects. It will be the implementation's repsonsibility to serialize the
 * data.
 * <p>Some Store implementations will have space limitations, and it is possible
 * that the total length of an entry must be less than some number. For example,
 * a single entry's length has a maximum of 4096 bytes. This should be no problem
 * because a cert with a 2048-bit RSA key is generally less thatn 1000 bytes and
 * even an encoded 2048-bit RSA key is less than 2000 bytes. ECC keys and certs
 * are smaller. But be aware of the possibility of space limitations.
 *
 * @param pStore The store to which the entry will be added.
 * @param pLabel The label (alias) against which the entry will be stored. This
 * can be NULL.
 * @param labelLen The length, in bytes, of the label.
 * @param pGenericValue If not NULL, the only thing that will be stored. The
 * function will simply copy this as a binary value.
 * @param genericValueLen The length, in bytes, of the generic value.
 * @param pPrivateKey The key to store. This can be NULL.
 * @param pCert The cert to store. This can be NULL.
 * @param isTrusted If you supply a cert, pass in TRUE if it is a trusted cert
 * (e.g. a trusted root cert, or a CA cert that has already been verified), or
 * FALSE otherwise.
 * @param copyFlag A flag to indicate how the function should copy the key and
 * cert. Pass in 0 to copy both by value (clone). Pass in a MOC_COPY_ value to
 * copy one or both by reference. This is only valid with an in-memory storage
 * facility.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreAddEntry (
  MocStore pStore,
  ubyte *pLabel,
  ubyte4 labelLen,
  ubyte *pGenericValue,
  ubyte4 genericValueLen,
  MocAsymKey pPrivateKey,
  MCertObj pCert,
  intBoolean isTrusted,
  ubyte4 copyFlag,
  vlong **ppVlongQueue
  );

/** Pass this value as the copyFlag arg in MocStoreAddEntry if you want the
 * generic value to be copied by reference.
 */
#define MOC_COPY_GENERIC_BY_REF   MOC_STORE_ENTRY_GENERIC_REF
/** Pass this value as the copyFlag arg in MocStoreAddEntry if you want the key
 * to be copied by reference.
 */
#define MOC_COPY_KEY_BY_REF       MOC_STORE_ENTRY_KEY_REF
/** Pass this value as the copyFlag arg in MocStoreAddEntry if you want the
 * cert to to be copied by reference.
 */
#define MOC_COPY_CERT_BY_REF      MOC_STORE_ENTRY_CERT_REF
/** Pass this value as the copyFlag arg in MocStoreAddEntry if you want both
 * the key and cert to to be copied by reference.
 */
#define MOC_COPY_ENTRY_BY_REF     \
    (MOC_COPY_KEY_BY_REF | MOC_COPY_CERT_BY_REF | MOC_COPY_GENERIC_BY_REF)

/* This is the signature of a SearchParam.
 * <p>When searching for an entry inside a MocStore, specify what the search
 * parameter is by passing in an argument that is a function that implements this
 * typedef.
 * <p>Do not call a SearchParam directly, only use it as the SearchParam arg in a
 * call to a FindEntry function.
 * <p>For each SearchParam, there is the actual data against which the search
 * will be made. See the documentation for each SearchParam for more info on what
 * exactly you need to pass in to make the search.
 */
typedef MSTATUS (*MStoreSearchParam) (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Get the entry in the MocStore associated with the given search type and
 * search parameter.
 * <p>The function will return the entry as a pointer to a MocStoreEntry. You
 * will pass in an address, the function will deposit at that address a pointer
 * to the struct containing the result. When you are done with the entry, call
 * MocStoreReleaseEntry. That memory belongs to the Store, do not alter or free
 * it, other than calling the Release function.
 * <p>Check the type on the returned entry. It will indicate which of the structs
 * in the contents union contains the actual data.
 * <p>If the return is data only, no objects, and you need the key and/or cert in
 * object form, you can call MocStoreFindEntryData and
 * CRYPTO_deserializeCustomKey (the latter with your list of supported
 * KeyOperators).
 * <p>This will return whatever was in the entry. If the entry contains a cert
 * only, it will return the cert only, no key. If it contains a key only, it will
 * return only the key.
 * <p>You must call MocStoreReleaseEntry function on the return value when you
 * are done with it.
 * <p>You can specify a search type or a search param, or both.
 * <p>If you pass 0 (MOC_STORE_SEARCH_TYPE_UNDEF) as the searchType arg, the
 * function will ignore it.
 * <p>Otherwise, the searchType must be the OR of the following flags:
 * <pre>
 * <code>
 *   MOC_STORE_SEARCH_TYPE_RSA
 *   MOC_STORE_SEARCH_TYPE_DSA
 *   MOC_STORE_SEARCH_TYPE_ECC
 *
 *   MOC_STORE_SEARCH_TYPE_KEY
 *   MOC_STORE_SEARCH_TYPE_CERT
 *
 *   MOC_STORE_SEARCH_TYPE_GENERIC
 * </code>
 * </pre>
 * <p>For example, if you set searchType to only RSA, then the function will look
 * at only entries of the RSA algorithm. That will be all entries that contain
 * either an RSA key only, an RSA cert only (the key in the cert is an RSA key),
 * or an RSA key and RSA cert. If you also set the KEY bit, it will look at only
 * entries of the RSA algorithm that also have keys (key alone or key and cert).
 * <p>Another example, you can set the RSA and ECC bits along with the CERT bit.
 * The search function will look at only entries that contain RSA or ECC certs
 * (cert only or key and cert).
 * <p>Another example, you can set the KEY bit only. The search function will
 * look at only entries that contain keys (of any algorithm).
 * <p>This can be useful, for example, if you know a CA has two certs, one for an
 * RSA key and another for an ECC key, and you want the ECC cert.
 * <p>Note that a generic entry will not have a KEY or CERT, nor will it be of
 * any algorithm. Hence, if you set the GENERIC bit, that must be the only bit
 * set. If you set the GENERIC bit with any other bit, no entry will be returned.
 * <p>If you specify a searchType but no search param, then the search function
 * will search by type only.
 * <p>You specify the search parameter with one of the MStoreSearchParam
 * implementations. For example, to search by label, use MStoreSearchParamLabel.
 * <p>For some search parameters there can be more than one entry. For example,
 * if you search by subject name, it is possible there are several certs with the
 * given name (e.g. a user has a signing cert and a decrypting cert). The caller
 * supplies the index in the cert store of the entry. If you want the first entry
 * that matches, pass in 0 as the index.
 * <p>If you need to cycle through the list (find the first, check if it really
 * the right one, and if not, find the next, and so on), you will likely write a
 * for loop. Init index to 0, then inside a loop, find the entry with the index.
 * If it is the one you want, break out of the loop. If not, increment index and
 * start the loop again. If the result is NULL, you ran out of entries.
 * <p>For some search params, there can be only one entry (label,
 * issuerAndSerial, among others), so the index will always be 0.
 * <p>Note that the index is for the entries that meet the requirements of the
 * search param, not all the entries. For example, there might be 10 entries in a
 * store, but only 2 with a given subject name. The function will search the
 * entire store, skipping any entries that don't match. When it reaches the first
 * entry that matches, that entry is index 0. If it is looking for the entry at
 * index 1, it will continue looking, skipping any entries that don't match until
 * it finds the next match. That is index 1.
 * <p>Note also that as a storage facility is altered (new additions and
 * deletions), the indices can change. If you build a store once and then use it
 * without adding or deleting, then two calls with the same input will return the
 * same results. But if you alter the store between two Find calls with the same
 * input, it is possible the results can be different, although it is possible
 * that they are the same.
 * <p>You can search by searchType only (NULL SearchParam) or by SearchParam only
 * (searchType is 0), or a combination of the two. For example, you can set the
 * searchType to search for RSA and the SearchParam to Subject name. The function
 * will look in the store at all entries that are RSA and the subject name
 * matches. It will not even look at DSA entries or entries that have no cert.
 * <p>Note that SearchParamLabel searches by label, and there can be only one
 * entry for each label. Hence, there is no need to set searchType to anything
 * other than 0 if you search by label.
 * <p>If there is no entry with the given search parameter, the function will set
 * the return arg to NULL and return OK. That is, it will not return an error if
 * it cannot find an entry with the given search param.
 *
 * @param pStore The store to search.
 * @param searchType If 0 (MOC_CERT_STORE_SEARCH_TYPE_UNDEF), this arg is
 * ignored, there are no restrictions on the search. Otherwise the OR of
 * MOC_CERT_STORE_SEARCH_TYPE_ values that limit the search by algorithm or
 * key/cert or generic.
 * @param SearchParam What the search will be based on.
 * @param pValue The value of the search param against which the search will be
 * made.
 * @param valueLen The length, in bytes, of the value.
 * @param index The index of the entry requested.
 * @param ppEntry The address where the function will deposit the entry found.
 * Call Release on the result when you are done with it.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreFindEntry (
  MocStore pStore,
  ubyte4 searchType,
  MStoreSearchParam SearchParam,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte4 index,
  MocStoreEntry **ppEntry
  );

#define MOC_STORE_SEARCH_TYPE_UNDEF    MOC_STORE_ENTRY_TYPE_UNDEF

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries of the RSA algorithm. This is valid for entries that contain
 * a key only, a cert only, or a key and cert.
 */
#define MOC_STORE_SEARCH_TYPE_RSA      MOC_STORE_ENTRY_TYPE_RSA

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries of the DSA algorithm. This is valid for entries that contain
 * a key only, a cert only, or a key and cert.
 */
#define MOC_STORE_SEARCH_TYPE_DSA      MOC_STORE_ENTRY_TYPE_DSA

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries of the ECC algorithm. This is valid for entries that contain
 * a key only, a cert only, or a key and cert.
 */
#define MOC_STORE_SEARCH_TYPE_ECC      MOC_STORE_ENTRY_TYPE_ECC

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries that contain keys (key only or key and cert, exclude entries
 * with cert only).
 */
#define MOC_STORE_SEARCH_TYPE_KEY      MOC_STORE_ENTRY_TYPE_KEY

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries that contain certs (cert only or key and cert, exclude
 * entries with key only).
 */
#define MOC_STORE_SEARCH_TYPE_CERT     MOC_STORE_ENTRY_TYPE_CERT

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries that contain generic values.
 */
#define MOC_STORE_SEARCH_TYPE_GENERIC  MOC_STORE_ENTRY_TYPE_GENERIC

#define MOC_STORE_ALG_MASK \
    (MOC_STORE_SEARCH_TYPE_RSA | MOC_STORE_SEARCH_TYPE_DSA | \
    MOC_STORE_SEARCH_TYPE_ECC)

#define MOC_STORE_CONTENT_MASK \
    (MOC_STORE_SEARCH_TYPE_KEY | MOC_STORE_SEARCH_TYPE_CERT | \
     MOC_STORE_SEARCH_TYPE_GENERIC)

/* Mask with a type. If not 0, the entry is a key/cert.
 */
#define MOC_STORE_KEYCERT_MASK \
    (MOC_STORE_SEARCH_TYPE_KEY | MOC_STORE_SEARCH_TYPE_CERT)

/** Set this bit in the type arg of MocStoreFindEntry if you want to limit the
 * search to entries that contain trusted certs (these will likely be entries
 * that contain a cert only).
 */
#define MOC_STORE_SEARCH_TYPE_TRUSTED  MOC_STORE_ENTRY_TYPE_TRUSTED

/** Release an Entry returned from a MocStore Find call.
 * <p>Depending on the implementation, this might do nothing, it might decrement
 * a reference count, it might free memory. The MocStore implementation will know
 * what it needs to do.
 * <p>The caller supplies the address. The function will go to that address and
 * expect to find a MocStoreEntry pointer. If not, the function does nothing and
 * returns OK. If it does find an entry, it will do what is necessary to release
 * it and and set *ppEntry to NULL.
 *
 * @param pStore The store from which the entry was originally retrieved.
 * @param ppEntry The address where the function will find the entry to release.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreReleaseEntry (
  MocStore pStore,
  MocStoreEntry **ppEntry
  );

/** Implements MStoreSearchParam.
 * <p>Use this as the SearchParam arg when you want to search by label.
 * <p>Using this SearchParam, the value is the label and the valueLen is the
 * length, in bytes, of the label.
 */
MOC_EXTERN MSTATUS MStoreSearchParamLabel (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Implements MStoreSearchParam.
 * <p>Use this as the SearchParam arg when you want to search by subject name.
 * <p>Using this SearchParam, the value is the DER of the subjectName and
 * valueLen is the length, in bytes, of the DER encoding.
 * <p>For example, if you want to find a CA cert, look in the leaf cert for
 * issuerName (see mss/src/crypto/certops.h and MGetName). Then search for the
 * entry that has that name as the subject.
 */
MOC_EXTERN MSTATUS MStoreSearchParamSubject (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Implements MStoreSearchParam.
 * <p>Use this as the SearchParam arg when you want to search by issuerAndSerial.
 * <p>Using this SearchParam, the value is the DER of the issuerAndSerialNumber,
 * and the valueLen is the length, in bytes, of the DER encoding.
 * <p>For example, if you receive a PKCS 7 Enveloped message whcih includes the
 * issuerAndSerialNumber of the cert used to encrypt, to find that cert, use this
 * Param. Note that you can get the IssuerAndSerialNumber out of cert by calling
 * MGetIssuerSerialAlloc (see mss/src/crypto/certops.h and MGetName).
 */
MOC_EXTERN MSTATUS MStoreSearchParamIssuerSerial (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Implements MStoreSearchParam.
 * <p>Use this as the SearchParam arg when you want to search by UniqueId.
 * <p>Using this SearchParam, the value is the SubjectUniqueId, and the valueLen
 * is the length, in bytes, of the UniqueId.
 * <p>Generally this is used to find an issuer cert. You get the IssuerUniqueId
 * out of a leaf cert (see MGetUniqueId in certops.h), then search based on this
 * Param. This Param will find the cert with the given Subject UniqueId.
 * <p>Note that there is an IssuerUniqueId and a SubjectUniqueId. This will
 * search for the cert with the SubjectUniqueId that matches the given value.
 * There is no way to search in the cert store based on the IssuerUniqueId.
 */
MOC_EXTERN MSTATUS MStoreSearchParamSubjUniqueId (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Implements MStoreSearchParam.
 * <p>Use this as the SearchParam arg when you want to search by SubjectKeyId.
 * <p>Using this SearchParam, the value is the SubjectKeyId, and the valueLen
 * is the length, in bytes, of the SubjectKeyId.
 * <p>Generally this is used to find an issuer cert. You get the AuthorityKeyId
 * out of a leaf cert (see MGetExtension and ExtensionTypeAuthKeyId), then search
 * based on this Param. This Param will find the cert with the given SubjectKeyId.
 * <p>Note that there is an AuthorityKeyId and a SubjectKeyId. This will search
 * for the cert with the SubjectKeyId that matches the given value. There is no
 * way to search in the cert store based on the AuthorityKeyId.
 */
MOC_EXTERN MSTATUS MStoreSearchParamSubjKeyId (
  MocStore, ubyte *, ubyte4, void *, intBoolean *);

/** Remove an entry from a MocStore.
 * <p>This will delete the entry with the given label. You can delete only
 * entries with labels.
 * <p>If the function can find no entry with the given label, it will do nothing
 * and return OK. That is, if you try to delete an entry that doesn't exist, that
 * is not an error. You wanted the cert store to not have the entry with the
 * given label, and it does not.
 * <p>Note that after deleting an entry, references can disappear. For example,
 * suppose you added the entry and copied by value (see MocStoreAddEntry and
 * the copyFlag). If you called MocStoreFindEntry and the search returned the
 * element or elements from this entry, you would have a reference to the key
 * and/or cert inside the entry. After deleting the entry, the key and/or cert
 * will be deleted so the references you have are no longer valid.
 * <p>If you Add an entry by reference, the delete will simply remove the
 * reference, it will not delete the elements. That is, if you Add by reference,
 * you own the key and/or cert objects, the cert store will not alter or delete
 * them.
 *
 * @param pStore The store from which the entry is to be deleted.
 * @param pLabel The label of the entry to be deleted.
 * @param labelLen The length, in bytes, of the label.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocStoreDeleteEntry (
  MocStore pStore,
  ubyte *pLabel,
  ubyte4 labelLen
  );

#ifdef __cplusplus
}
#endif

#endif /* __MOC_STORE_HEADER__ */
