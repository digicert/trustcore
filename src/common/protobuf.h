/*
 * protobuf.h
 *
 * Protobuf Definitions
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

/**
 @file       protobuf.h
 @brief      Header file for declaring Protobuf methods.
 
 @filedoc    protobuf.h
 */
#ifndef __PROTOBUF_HEADER__
#define __PROTOBUF_HEADER__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Field numbers */
#define TIMESTAMP_FIELD_NUMBER 1
#define METRIC_FIELD_NUMBER 2
#define SEQUENCE_FIELD_NUMBER 3
#define UUID_FIELD_NUMBER 4
#define BODY_FIELD_NUMBER 5

/* Metric Field Numbers */
#define METRIC_NAME_FIELD_NUMBER 1
#define METRIC_TIMESTAMP_FIELD_NUMBER 3
#define METRIC_DATATYPE_FIELD_NUMBER 4
#define METRIC_VALUE_INT_FIELD_NUMBER 10
#define METRIC_VALUE_BOOLEAN_FIELD_NUMBER 14
#define METRIC_VALUE_STRING_FIELD_NUMBER 15

/**
 * @enum ProtobufMessageParams
 * @brief Enumeration defining supported parameters for message types.
 *
 * @var PB_VARINT
 *      VARINT wire type
 * @var PB_I64
 *      I64 wire type
 * @var PB_LEN
 *      LEN wire type
 * @var PB_SGROUP
 *      SGROUP wire type
 * @var PB_EGROUP
 *      EGROUP wire type
 * @var PB_I32
 *      I32 wire type
 */
typedef enum
{
    PB_VARINT = 0,
    PB_I64 = 1,
    PB_LEN = 2,
    PB_SGROUP = 3,
    PB_EGROUP = 4,
    PB_I32 = 5
} ProtobufWireType;

/**
 * @enum ProtobufFieldType
 * @brief Enumeration defining supported message types.
 *
 * @var PB_UINT64
 *      Message type of uin64
 * @var PB_STRING
 *      Message type of string
 * @var PB_ONEOF
 *      Message type of oneof
 * @var PB_MESSAGE
 *      Message type of embedded message
 */
typedef enum
{
    /* VARINT range */
    PB_INT32    = (1 << PB_VARINT) | 0x100,
    PB_INT64    = (1 << PB_VARINT) | 0x200,
    PB_UINT32   = (1 << PB_VARINT) | 0x300,
    PB_UINT64   = (1 << PB_VARINT) | 0x400,
    PB_SINT32   = (1 << PB_VARINT) | 0x500,
    PB_SINT64   = (1 << PB_VARINT) | 0x600,
    PB_BOOL     = (1 << PB_VARINT) | 0x700,
    PB_ENUM     = (1 << PB_VARINT) | 0x800,
    /* I64 range */
    PB_FIXED64  = (1 << PB_I64) | 0x100,
    PB_SFIXED64 = (1 << PB_I64) | 0x200,
    PB_DOUBLE   = (1 << PB_I64) | 0x300,
    /* LEN range */
    PB_STRING   = (1 << PB_LEN) | 0x100,
    PB_BYTES    = (1 << PB_LEN) | 0x200,
    PB_MESSAGE  = (1 << PB_LEN) | 0x300,
    /* Special types */
    PB_ONEOF    = (1 << 8)
} ProtobufFieldType;

/**
 * @enum ProtobufMessageParams
 * @brief Enumeration defining bit fields for supported parameters.
 *
 * @var PB_OPTIONAL
 *      Defines the field as optional
 * @var PB_REPEATED
 *      Defines the field as repeated
 */
typedef enum
{
    PB_OPTIONAL = 1 << 0,
    PB_REPEATED = 1 << 1
} ProtobufMessageParams;

typedef enum
{
    PB_METRIC_DATA_TYPE_UNKNOWN = 0,
    PB_METRIC_DATA_TYPE_INT8 = 1,
    PB_METRIC_DATA_TYPE_INT16 = 2,
    PB_METRIC_DATA_TYPE_INT32 = 3,
    PB_METRIC_DATA_TYPE_INT64 = 4,
    PB_METRIC_DATA_TYPE_UINT8 = 5,
    PB_METRIC_DATA_TYPE_UINT16 = 6,
    PB_METRIC_DATA_TYPE_UINT32 = 7,
    PB_METRIC_DATA_TYPE_UINT64 = 8,
    PB_METRIC_DATA_TYPE_FLOAT = 9,
    PB_METRIC_DATA_TYPE_DOUBLE = 10,
    PB_METRIC_DATA_TYPE_BOOLEAN = 11,
    PB_METRIC_DATA_TYPE_STRING = 12
} ProtobufMetricDataType;
/**
 * @struct ProtobufMessage
 * @brief Structure used to define Protobuf message
 *
 * @var fieldNumber
 *      Field number for the field.
 * @var msgType
 *      Type of the field.
 * @var params
 *      Parameters for the field.
 * @var subCount
 *      Number of sub elements.
 */
typedef struct ProtobufMessage
{
    ubyte fieldNumber;
    ProtobufFieldType fieldType;
    ProtobufMessageParams params;
    struct ProtobufMessage *pSubMsg;
    ubyte4 subMsgCount;
} ProtobufMessage;

typedef void ProtobufContext;

/**
 * @struct ProtobufRawField
 * @brief Structure used to store raw Protobuf data
 *
 * @var fieldNumber
 *      Field number for this data chunk.
 * @var wireType
 *      Wire type for this data chunk.
 * @var pBuf
 *      Buffer to data.
 * @var bufLen
 *      Length of data buffer.
 * @var totalLen
 *      Total length for the field.
 */
typedef struct
{
    ubyte fieldNumber;
    ProtobufWireType wireType;
    ubyte *pBuf;
    ubyte4 bufLen;
    ubyte4 offset;
    ubyte4 totalLen;
} ProtobufRawField;

/**
 * @struct ProtobufDecodedField
 * @brief Structure used to store decoded Protobuf data
 *
 * @var fieldNumber
 *      Field number for this data chunk.
 * @var msgType
 *      Field type for this data chunk.
 * @var data.bytes.pBuf
 *      Buffer to data. Applies to string and byte field types.
 * @var data.bytes.bufLen
 *      Length of data buffer. Applies to string and byte field types.
 * @var data.uint32
 *      Unsigned 32-bit integer value. Applies to uint32 field types.
 * @var data.uint64
 *      Unsigned 64-bit integer value.  Applies to uint64 field types.
 */
typedef struct
{
    ubyte fieldNumber;
    ProtobufFieldType fieldType;
    union
    {
        struct
        {
            ubyte *pBuf;
            ubyte4 bufLen;
            ubyte4 offset;
            ubyte4 totalLen;
        } bytes;
        sbyte4 int32;
        ubyte4 uint32;
        ubyte8 uint64;
        byteBoolean boolean;
    } data;
} ProtobufDecodedField;

typedef struct
{
    sbyte *pName;
    ubyte4 nameLen;
    ubyte8 timestamp;
    ProtobufMetricDataType datatype;
    union protobuf
    {
        ubyte4 intValue;
        byteBoolean booleanValue;
        ubyte *stringValue; /* Other types can be added later as needed */
    }value;
    ubyte4 valueLen;
    ubyte4 totalLen;
} ProtobufMetric;

typedef struct
{
    ubyte8 timestamp;
    ProtobufMetric *pMetrics;
    ubyte4 metricCount;
    ubyte sequenceNumber;
    sbyte *pUuid;
    ubyte *pBody;
    ubyte4 bodyLen;
} ProtobufPayload;

/**
 * @details Handler invoked when receiving raw Protobuf data.
 *
 * @param pArg          User defined callback argument.
 * @param pField        Field contaning raw data.
 * @param finalChunk    TRUE if final chunk of raw data for this field, otherwise FALSE.
 */
typedef MSTATUS (*ProtobufRawDecodeCb)(
    void *pArg,
    ProtobufRawField *pField,
    byteBoolean finalChunk);

/**
 * @details Handler invoked when receiving decoded Protobuf data.
 *
 * @param pArg          User defined callback argument.
 * @param pField        Field contaning decoded data.
 * @param finalChunk    TRUE if final chunk of raw data for this field, otherwise FALSE.
 */
typedef MSTATUS (*ProtobufMessageDecodeCb)(
    void *pArg,
    ProtobufMessage *pMsg,
    ubyte4 index,
    ProtobufDecodedField *pField,
    byteBoolean finalChunk);

/**
 * @details Create Protobuf context to decode data
 *
 * @param ppContext Location where context is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_acquireContext(
    ProtobufContext **ppContext);

/**
 * @details Delete Protobuf context
 *
 * @param ppContext Location where context is deleted from.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_releaseContext(
    ProtobufContext **ppContext);

/**
 * @details Sets raw decoding callback to stream data back to the application.
 *
 * @param pContext Context to store callback in.
 * @param msgDecoder Callback invoked for raw data.
 * @param pArg Callback argument.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_setRawDecoder(
    ProtobufContext *pContext,
    ProtobufRawDecodeCb msgDecoder,
    void *pArg);

/**
 * @details Use to decode data and recieve raw data back to the application.
 *
 * @param pContext Protobuf context.
 * @param pInput Input data buffer.
 * @param inputLen Input data buffer length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_rawDecode(
    ProtobufContext *pContext,
    ubyte *pInput,
    ubyte4 inputLen);

/**
 * @details Sets message decoding callback to stream data back to the application.
 *
 * @param pContext Context to store callback in.
 * @param pMsg Message format.
 * @param msgCount Message count.
 * @param msgDecoder Callback invoked for decoded data.
 * @param pArg Callback argument.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_setMessageDecoder(
    ProtobufContext *pContext,
    ProtobufMessage *pMsg,
    ubyte4 msgCount,
    ProtobufMessageDecodeCb msgDecoder,
    void *pArg);

/**
 * @details Use to decode data and recieve decoded data back to the application.
 *
 * @param pContext Protobuf context.
 * @param pInput Input data buffer.
 * @param inputLen Input data buffer length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS PROTOBUF_messageDecode(
    ProtobufContext *pContext,
    ubyte *pInput,
    ubyte4 inputLen);

MOC_EXTERN MSTATUS PROTOBUF_resetSequenceNumber(void);

MOC_EXTERN MSTATUS PROTOBUF_preparePayload(
    ProtobufPayload *pPayload);  /* initialize payload, get timestamp in milliseconds, increment sequence */

MOC_EXTERN MSTATUS PROTOBUF_addMetricToPayload(
    ProtobufPayload *pPayload,
    ubyte *pName,
    void *pValue,
    ProtobufMetricDataType dataType,
    ubyte4 valueLen);  /* add metric to payload */

MOC_EXTERN MSTATUS PROTOBUF_encodePayload(
    ProtobufPayload *pPayload,
    ubyte **ppOutput,
    ubyte4 *pOutputLen);  /* encode payload */

MOC_EXTERN MSTATUS PROTOBUF_freePayload(
    ProtobufPayload *pPayload);  /* free payload */


#ifdef __cpluspslus
}
#endif

#endif /* __PROTOBUF_HEADER__ */