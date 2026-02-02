/*
 * aes_ccm_test.c
 *
 * unit test for aes_ccm.c
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
#include "../aes_ccm.c"

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"


typedef struct Packet
{
    ubyte4          keyLen;
    ubyte           key[32];
    ubyte4          nonceLen;
    ubyte           nonce[16];
    ubyte4          packetLen;
    ubyte4          packetHeaderLen;
    ubyte           packet[60];
    ubyte4          resultLen;
    ubyte           result[50];
} Packet;


Packet          gTestPackets[] = {

/*=============== Packet Vector #1 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     31, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E},
     39,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x58, 0x8C, 0x97,
      0x9A, 0x61, 0xC6, 0x63, 0xD2,
      0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89, 0x80, 0x6D, 0x5F, 0x6B,
      0x61, 0xDA, 0xC3, 0x84, 0x17,
      0xE8, 0xD1, 0x2C, 0xFD, 0xF9, 0x26, 0xE0}
     },

/*=============== Packet Vector #2 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     32, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
     40,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x72, 0xC9, 0x1A,
      0x36, 0xE1, 0x35, 0xF8, 0xCF,
      0x29, 0x1C, 0xA8, 0x94, 0x08, 0x5C, 0x87, 0xE3, 0xCC, 0x15, 0xC4,
      0x39, 0xC9, 0xE4, 0x3A, 0x3B,
      0xA0, 0x91, 0xD5, 0x6E, 0x10, 0x40, 0x09, 0x16}
     },

/*=============== Packet Vector #3 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x05, 0x04, 0x03, 0x02, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     33, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20},
     41,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x51, 0xB1, 0xE5,
      0xF4, 0x4A, 0x19, 0x7D, 0x1D,
      0xA4, 0x6B, 0x0F, 0x8E, 0x2D, 0x28, 0x2A, 0xE8, 0x71, 0xE8, 0x38,
      0xBB, 0x64, 0xDA, 0x85, 0x96,
      0x57, 0x4A, 0xDA, 0xA7, 0x6F, 0xBD, 0x9F, 0xB0, 0xC5}
     },

/*=============== Packet Vector #4 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x06, 0x05, 0x04, 0x03, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     31, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E},
     39,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0xA2, 0x8C, 0x68, 0x65,
      0x93, 0x9A, 0x9A, 0x79, 0xFA, 0xAA, 0x5C, 0x4C, 0x2A, 0x9D, 0x4A,
      0x91, 0xCD, 0xAC, 0x8C, 0x96,
      0xC8, 0x61, 0xB9, 0xC9, 0xE6, 0x1E, 0xF1}
     },

/*=============== Packet Vector #5 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x07, 0x06, 0x05, 0x04, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     32, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
     40,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0xDC, 0xF1, 0xFB, 0x7B,
      0x5D, 0x9E, 0x23, 0xFB, 0x9D, 0x4E, 0x13, 0x12, 0x53, 0x65, 0x8A,
      0xD8, 0x6E, 0xBD, 0xCA, 0x3E,
      0x51, 0xE8, 0x3F, 0x07, 0x7D, 0x9C, 0x2D, 0x93}
     },

/*=============== Packet Vector #6 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     33, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20},
     41,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x6F, 0xC1, 0xB0, 0x11,
      0xF0, 0x06, 0x56, 0x8B, 0x51, 0x71, 0xA4, 0x2D, 0x95, 0x3D, 0x46,
      0x9B, 0x25, 0x70, 0xA4, 0xBD,
      0x87, 0x40, 0x5A, 0x04, 0x43, 0xAC, 0x91, 0xCB, 0x94}
     },

/*=============== Packet Vector #7 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x09, 0x08, 0x07, 0x06, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     31, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E},
     41,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x01, 0x35, 0xD1,
      0xB2, 0xC9, 0x5F, 0x41, 0xD5,
      0xD1, 0xD4, 0xFE, 0xC1, 0x85, 0xD1, 0x66, 0xB8, 0x09, 0x4E, 0x99,
      0x9D, 0xFE, 0xD9, 0x6C, 0x04,
      0x8C, 0x56, 0x60, 0x2C, 0x97, 0xAC, 0xBB, 0x74, 0x90}
     },
/*=============== Packet Vector #8 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x0A, 0x09, 0x08, 0x07, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     32, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
     42,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7B, 0x75, 0x39,
      0x9A, 0xC0, 0x83, 0x1D, 0xD2,
      0xF0, 0xBB, 0xD7, 0x58, 0x79, 0xA2, 0xFD, 0x8F, 0x6C, 0xAE, 0x6B,
      0x6C, 0xD9, 0xB7, 0xDB, 0x24,
      0xC1, 0x7B, 0x44, 0x33, 0xF4, 0x34, 0x96, 0x3F, 0x34, 0xB4}
     },

/*=============== Packet Vector #9 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x0B, 0x0A, 0x09, 0x08, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     33, 8,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20},
     43,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x82, 0x53, 0x1A,
      0x60, 0xCC, 0x24, 0x94, 0x5A,
      0x4B, 0x82, 0x79, 0x18, 0x1A, 0xB5, 0xC8, 0x4D, 0xF2, 0x1C, 0xE7,
      0xF9, 0xB7, 0x3F, 0x42, 0xE1,
      0x97, 0xEA, 0x9C, 0x07, 0xE5, 0x6B, 0x5E, 0xB1, 0x7E, 0x5F, 0x4E}
     },

/*=============== Packet Vector #10 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x0C, 0x0B, 0x0A, 0x09, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     31, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E},
     41,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x07, 0x34, 0x25, 0x94,
      0x15, 0x77, 0x85, 0x15, 0x2B, 0x07, 0x40, 0x98, 0x33, 0x0A, 0xBB,
      0x14, 0x1B, 0x94, 0x7B, 0x56,
      0x6A, 0xA9, 0x40, 0x6B, 0x4D, 0x99, 0x99, 0x88, 0xDD}
     },
/*=============== Packet Vector #11 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x0D, 0x0C, 0x0B, 0x0A, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     32, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
     42,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x67, 0x6B, 0xB2, 0x03,
      0x80, 0xB0, 0xE3, 0x01, 0xE8, 0xAB, 0x79, 0x59, 0x0A, 0x39, 0x6D,
      0xA7, 0x8B, 0x83, 0x49, 0x34,
      0xF5, 0x3A, 0xA2, 0xE9, 0x10, 0x7A, 0x8B, 0x6C, 0x02, 0x2C}
     },
/*=============== Packet Vector #12 ==================*/
    {
     16, {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
	  0xCB, 0xCC, 0xCD, 0xCE, 0xCF},
     13, {0x00, 0x00, 0x00, 0x0E, 0x0D, 0x0C, 0x0B, 0xA0, 0xA1, 0xA2, 0xA3,
	  0xA4, 0xA5},
     33, 12,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20},
     43,
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0xC0, 0xFF, 0xA0, 0xD6,
      0xF0, 0x5B, 0xDB, 0x67, 0xF2, 0x4D, 0x43, 0xA4, 0x33, 0x8D, 0x2A,
      0xA4, 0xBE, 0xD7, 0xB2, 0x0E,
      0x43, 0xCD, 0x1A, 0xA3, 0x16, 0x62, 0xE7, 0xAD, 0x65, 0xD6, 0xDB}
     },
/*=============== Packet Vector #13 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x41, 0x2B, 0x4E, 0xA9, 0xCD, 0xBE, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     31, 8,
     {0x0B, 0xE1, 0xA8, 0x8B, 0xAC, 0xE0, 0x18, 0xB1, 0x08, 0xE8, 0xCF,
      0x97, 0xD8, 0x20, 0xEA, 0x25,
      0x84, 0x60, 0xE9, 0x6A, 0xD9, 0xCF, 0x52, 0x89, 0x05, 0x4D, 0x89,
      0x5C, 0xEA, 0xC4, 0x7C},
     39,
     {0x0B, 0xE1, 0xA8, 0x8B, 0xAC, 0xE0, 0x18, 0xB1, 0x4C, 0xB9, 0x7F,
      0x86, 0xA2, 0xA4, 0x68, 0x9A,
      0x87, 0x79, 0x47, 0xAB, 0x80, 0x91, 0xEF, 0x53, 0x86, 0xA6, 0xFF,
      0xBD, 0xD0, 0x80, 0xF8, 0xE7,
      0x8C, 0xF7, 0xCB, 0x0C, 0xDD, 0xD7, 0xB3}
     },
/*=============== Packet Vector #14 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x33, 0x56, 0x8E, 0xF7, 0xB2, 0x63, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     32, 8,
     {0x63, 0x01, 0x8F, 0x76, 0xDC, 0x8A, 0x1B, 0xCB, 0x90, 0x20, 0xEA,
      0x6F, 0x91, 0xBD, 0xD8, 0x5A,
      0xFA, 0x00, 0x39, 0xBA, 0x4B, 0xAF, 0xF9, 0xBF, 0xB7, 0x9C, 0x70,
      0x28, 0x94, 0x9C, 0xD0, 0xEC},
     40,
     {0x63, 0x01, 0x8F, 0x76, 0xDC, 0x8A, 0x1B, 0xCB, 0x4C, 0xCB, 0x1E,
      0x7C, 0xA9, 0x81, 0xBE, 0xFA,
      0xA0, 0x72, 0x6C, 0x55, 0xD3, 0x78, 0x06, 0x12, 0x98, 0xC8, 0x5C,
      0x92, 0x81, 0x4A, 0xBC, 0x33,
      0xC5, 0x2E, 0xE8, 0x1D, 0x7D, 0x77, 0xC0, 0x8A}
     },
/*=============== Packet Vector #15 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x10, 0x3F, 0xE4, 0x13, 0x36, 0x71, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     33, 8,
     {0xAA, 0x6C, 0xFA, 0x36, 0xCA, 0xE8, 0x6B, 0x40, 0xB9, 0x16, 0xE0,
      0xEA, 0xCC, 0x1C, 0x00, 0xD7,
      0xDC, 0xEC, 0x68, 0xEC, 0x0B, 0x3B, 0xBB, 0x1A, 0x02, 0xDE, 0x8A,
      0x2D, 0x1A, 0xA3, 0x46, 0x13,
      0x2E},
     41,
     {0xAA, 0x6C, 0xFA, 0x36, 0xCA, 0xE8, 0x6B, 0x40, 0xB1, 0xD2, 0x3A,
      0x22, 0x20, 0xDD, 0xC0, 0xAC,
      0x90, 0x0D, 0x9A, 0xA0, 0x3C, 0x61, 0xFC, 0xF4, 0xA5, 0x59, 0xA4,
      0x41, 0x77, 0x67, 0x08, 0x97,
      0x08, 0xA7, 0x76, 0x79, 0x6E, 0xDB, 0x72, 0x35, 0x06}
     },
/*=============== Packet Vector #16 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x76, 0x4C, 0x63, 0xB8, 0x05, 0x8E, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     31, 12,
     {0xD0, 0xD0, 0x73, 0x5C, 0x53, 0x1E, 0x1B, 0xEC, 0xF0, 0x49, 0xC2,
      0x44, 0x12, 0xDA, 0xAC, 0x56,
      0x30, 0xEF, 0xA5, 0x39, 0x6F, 0x77, 0x0C, 0xE1, 0xA6, 0x6B, 0x21,
      0xF7, 0xB2, 0x10, 0x1C},
     39,
     {0xD0, 0xD0, 0x73, 0x5C, 0x53, 0x1E, 0x1B, 0xEC, 0xF0, 0x49, 0xC2,
      0x44, 0x14, 0xD2, 0x53, 0xC3,
      0x96, 0x7B, 0x70, 0x60, 0x9B, 0x7C, 0xBB, 0x7C, 0x49, 0x91, 0x60,
      0x28, 0x32, 0x45, 0x26, 0x9A,
      0x6F, 0x49, 0x97, 0x5B, 0xCA, 0xDE, 0xAF}
     },

/*=============== Packet Vector #17 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0xF8, 0xB6, 0x78, 0x09, 0x4E, 0x3B, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     32, 12,
     {0x77, 0xB6, 0x0F, 0x01, 0x1C, 0x03, 0xE1, 0x52, 0x58, 0x99, 0xBC,
      0xAE, 0xE8, 0x8B, 0x6A, 0x46,
      0xC7, 0x8D, 0x63, 0xE5, 0x2E, 0xB8, 0xC5, 0x46, 0xEF, 0xB5, 0xDE,
      0x6F, 0x75, 0xE9, 0xCC, 0x0D},
     40,
     {0x77, 0xB6, 0x0F, 0x01, 0x1C, 0x03, 0xE1, 0x52, 0x58, 0x99, 0xBC,
      0xAE, 0x55, 0x45, 0xFF, 0x1A,
      0x08, 0x5E, 0xE2, 0xEF, 0xBF, 0x52, 0xB2, 0xE0, 0x4B, 0xEE, 0x1E,
      0x23, 0x36, 0xC7, 0x3E, 0x3F,
      0x76, 0x2C, 0x0C, 0x77, 0x44, 0xFE, 0x7E, 0x3C}
     },
/*=============== Packet Vector #18 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0xD5, 0x60, 0x91, 0x2D, 0x3F, 0x70, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     33, 12,
     {0xCD, 0x90, 0x44, 0xD2, 0xB7, 0x1F, 0xDB, 0x81, 0x20, 0xEA, 0x60,
      0xC0, 0x64, 0x35, 0xAC, 0xBA,
      0xFB, 0x11, 0xA8, 0x2E, 0x2F, 0x07, 0x1D, 0x7C, 0xA4, 0xA5, 0xEB,
      0xD9, 0x3A, 0x80, 0x3B, 0xA8,
      0x7F},
     41,
     {0xCD, 0x90, 0x44, 0xD2, 0xB7, 0x1F, 0xDB, 0x81, 0x20, 0xEA, 0x60,
      0xC0, 0x00, 0x97, 0x69, 0xEC,
      0xAB, 0xDF, 0x48, 0x62, 0x55, 0x94, 0xC5, 0x92, 0x51, 0xE6, 0x03,
      0x57, 0x22, 0x67, 0x5E, 0x04,
      0xC8, 0x47, 0x09, 0x9E, 0x5A, 0xE0, 0x70, 0x45, 0x51}
     },
/*=============== Packet Vector #19 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x42, 0xFF, 0xF8, 0xF1, 0x95, 0x1C, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     31, 8,
     {0xD8, 0x5B, 0xC7, 0xE6, 0x9F, 0x94, 0x4F, 0xB8, 0x8A, 0x19, 0xB9,
      0x50, 0xBC, 0xF7, 0x1A, 0x01,
      0x8E, 0x5E, 0x67, 0x01, 0xC9, 0x17, 0x87, 0x65, 0x98, 0x09, 0xD6,
      0x7D, 0xBE, 0xDD, 0x18},
     41,
     {0xD8, 0x5B, 0xC7, 0xE6, 0x9F, 0x94, 0x4F, 0xB8, 0xBC, 0x21, 0x8D,
      0xAA, 0x94, 0x74, 0x27, 0xB6,
      0xDB, 0x38, 0x6A, 0x99, 0xAC, 0x1A, 0xEF, 0x23, 0xAD, 0xE0, 0xB5,
      0x29, 0x39, 0xCB, 0x6A, 0x63,
      0x7C, 0xF9, 0xBE, 0xC2, 0x40, 0x88, 0x97, 0xC6, 0xBA}
     },
/*=============== Packet Vector #20 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x92, 0x0F, 0x40, 0xE5, 0x6C, 0xDC, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     32, 8,
     {0x74, 0xA0, 0xEB, 0xC9, 0x06, 0x9F, 0x5B, 0x37, 0x17, 0x61, 0x43,
      0x3C, 0x37, 0xC5, 0xA3, 0x5F,
      0xC1, 0xF3, 0x9F, 0x40, 0x63, 0x02, 0xEB, 0x90, 0x7C, 0x61, 0x63,
      0xBE, 0x38, 0xC9, 0x84, 0x37},
     42,
     {0x74, 0xA0, 0xEB, 0xC9, 0x06, 0x9F, 0x5B, 0x37, 0x58, 0x10, 0xE6,
      0xFD, 0x25, 0x87, 0x40, 0x22,
      0xE8, 0x03, 0x61, 0xA4, 0x78, 0xE3, 0xE9, 0xCF, 0x48, 0x4A, 0xB0,
      0x4F, 0x44, 0x7E, 0xFF, 0xF6,
      0xF0, 0xA4, 0x77, 0xCC, 0x2F, 0xC9, 0xBF, 0x54, 0x89, 0x44}
     },

/*=============== Packet Vector #21 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x27, 0xCA, 0x0C, 0x71, 0x20, 0xBC, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     33, 8,
     {0x44, 0xA3, 0xAA, 0x3A, 0xAE, 0x64, 0x75, 0xCA, 0xA4, 0x34, 0xA8,
      0xE5, 0x85, 0x00, 0xC6, 0xE4,
      0x15, 0x30, 0x53, 0x88, 0x62, 0xD6, 0x86, 0xEA, 0x9E, 0x81, 0x30,
      0x1B, 0x5A, 0xE4, 0x22, 0x6B,
      0xFA},
     43,
     {0x44, 0xA3, 0xAA, 0x3A, 0xAE, 0x64, 0x75, 0xCA, 0xF2, 0xBE, 0xED,
      0x7B, 0xC5, 0x09, 0x8E, 0x83,
      0xFE, 0xB5, 0xB3, 0x16, 0x08, 0xF8, 0xE2, 0x9C, 0x38, 0x81, 0x9A,
      0x89, 0xC8, 0xE7, 0x76, 0xF1,
      0x54, 0x4D, 0x41, 0x51, 0xA4, 0xED, 0x3A, 0x8B, 0x87, 0xB9, 0xCE}
     },

/*=============== Packet Vector #22 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x5B, 0x8C, 0xCB, 0xCD, 0x9A, 0xF8, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     31, 12,
     {0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25, 0x20, 0xC3, 0x3C, 0x49, 0xFD,
      0x70, 0xB9, 0x6B, 0x49, 0xE2,
      0x1D, 0x62, 0x17, 0x41, 0x63, 0x28, 0x75, 0xDB, 0x7F, 0x6C, 0x92,
      0x43, 0xD2, 0xD7, 0xC2},
     41,
     {0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25, 0x20, 0xC3, 0x3C, 0x49, 0xFD,
      0x70, 0x31, 0xD7, 0x50, 0xA0,
      0x9D, 0xA3, 0xED, 0x7F, 0xDD, 0xD4, 0x9A, 0x20, 0x32, 0xAA, 0xBF,
      0x17, 0xEC, 0x8E, 0xBF, 0x7D,
      0x22, 0xC8, 0x08, 0x8C, 0x66, 0x6B, 0xE5, 0xC1, 0x97}
     },

/*=============== Packet Vector #23 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x3E, 0xBE, 0x94, 0x04, 0x4B, 0x9A, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     32, 12,
     {0x47, 0xA6, 0x5A, 0xC7, 0x8B, 0x3D, 0x59, 0x42, 0x27, 0xE8, 0x5E,
      0x71, 0xE2, 0xFC, 0xFB, 0xB8,
      0x80, 0x44, 0x2C, 0x73, 0x1B, 0xF9, 0x51, 0x67, 0xC8, 0xFF, 0xD7,
      0x89, 0x5E, 0x33, 0x70, 0x76},
     42,
     {0x47, 0xA6, 0x5A, 0xC7, 0x8B, 0x3D, 0x59, 0x42, 0x27, 0xE8, 0x5E,
      0x71, 0xE8, 0x82, 0xF1, 0xDB,
      0xD3, 0x8C, 0xE3, 0xED, 0xA7, 0xC2, 0x3F, 0x04, 0xDD, 0x65, 0x07,
      0x1E, 0xB4, 0x13, 0x42, 0xAC,
      0xDF, 0x7E, 0x00, 0xDC, 0xCE, 0xC7, 0xAE, 0x52, 0x98, 0x7D}
     },
/*=============== Packet Vector #24 ==================*/
    {
     16, {0xD7, 0x82, 0x8D, 0x13, 0xB2, 0xB0, 0xBD, 0xC3, 0x25, 0xA7, 0x62,
	  0x36, 0xDF, 0x93, 0xCC, 0x6B},
     13, {0x00, 0x8D, 0x49, 0x3B, 0x30, 0xAE, 0x8B, 0x3C, 0x96, 0x96, 0x76,
	  0x6C, 0xFA},
     33, 12,
     {0x6E, 0x37, 0xA6, 0xEF, 0x54, 0x6D, 0x95, 0x5D, 0x34, 0xAB, 0x60,
      0x59, 0xAB, 0xF2, 0x1C, 0x0B,
      0x02, 0xFE, 0xB8, 0x8F, 0x85, 0x6D, 0xF4, 0xA3, 0x73, 0x81, 0xBC,
      0xE3, 0xCC, 0x12, 0x85, 0x17,
      0xD4},
     43,
     {0x6E, 0x37, 0xA6, 0xEF, 0x54, 0x6D, 0x95, 0x5D, 0x34, 0xAB, 0x60,
      0x59, 0xF3, 0x29, 0x05, 0xB8,
      0x8A, 0x64, 0x1B, 0x04, 0xB9, 0xC9, 0xFF, 0xB5, 0x8C, 0xC3, 0x90,
      0x90, 0x0F, 0x3D, 0xA1, 0x2A,
      0xB1, 0x6D, 0xCE, 0x9E, 0x82, 0xEF, 0xA1, 0x6D, 0xA6, 0x20, 0x59}
     }
};


int aes_ccm_test_vectors()
{
    MSTATUS status;
    Packet testPacket;
    Packet* pRefPacket;
    ubyte4 i, retVal = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for ( i = 0; i < (sizeof(gTestPackets)/ sizeof(Packet)); ++i)
    {
        ubyte   M, L;
        ubyte   output[16];
        sbyte4  resCmp;

        /* make a copy because we are going to be modifying it */
        DIGI_MEMCPY((ubyte*) &testPacket,
                   (ubyte*) (pRefPacket = gTestPackets+i), sizeof(Packet));

        M = testPacket.resultLen - testPacket.packetLen;
        L = 15 - testPacket.nonceLen;

        status = AESCCM_encrypt(MOC_SYM(hwAccelCtx) M, L, testPacket.key, testPacket.keyLen,
                    testPacket.nonce,
                    testPacket.packet + testPacket.packetHeaderLen,
                    testPacket.packetLen - testPacket.packetHeaderLen,
                    testPacket.packet, testPacket.packetHeaderLen, output);

        retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( testPacket.packet, testPacket.result,
                    testPacket.packetLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        DIGI_MEMCMP( output, testPacket.result + testPacket.packetLen,
                    M, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);


        /* decryption now --> decrypt what we just encrypted */
        status = AESCCM_decrypt(MOC_SYM(hwAccelCtx) M, L, testPacket.key, testPacket.keyLen,
                    testPacket.nonce,
                    testPacket.packet + testPacket.packetHeaderLen,
                    testPacket.packetLen - testPacket.packetHeaderLen,
                    testPacket.packet, testPacket.packetHeaderLen, output);

        retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( testPacket.packet, pRefPacket->packet,
                    testPacket.packetLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
  
    DBG_DUMP

    return retVal;
}

int aes_ccm_test_create_delete_cipher()
{
    MSTATUS status;
    Packet testPacket;
    Packet* pRefPacket;
    ubyte4 i, retVal = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for ( i = 0; i < (sizeof(gTestPackets)/ sizeof(Packet)); ++i)
    {
        ubyte   M, L;
        ubyte   output[16];
        sbyte4  resCmp;
        BulkCtx ctx = NULL;

        DIGI_MEMSET((ubyte*) &testPacket, 0, sizeof(Packet));
        /* make a copy because we are going to be modifying it */
        DIGI_MEMCPY((ubyte*) &testPacket,
                   (ubyte*) (pRefPacket = gTestPackets+i), sizeof(Packet));

        M = testPacket.resultLen - testPacket.packetLen;
        L = 15 - testPacket.nonceLen;

        ctx  = AESCCM_createCtx(MOC_SYM(hwAccelCtx) testPacket.key, testPacket.keyLen, 1);
        retVal += UNITTEST_VALIDPTR(0, ctx);

        status = AESCCM_cipher(MOC_SYM(hwAccelCtx) ctx, testPacket.nonce, testPacket.nonceLen,
                            testPacket.packet, testPacket.packetHeaderLen, 
                            testPacket.packet + testPacket.packetHeaderLen,
                            testPacket.packetLen - testPacket.packetHeaderLen, 
                            M, 1);

        retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( testPacket.packet, testPacket.result,
                    testPacket.packetLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        DIGI_MEMCMP((testPacket.packet + testPacket.packetLen), 
                    testPacket.result + testPacket.packetLen,
                    M, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        /* decryption now --> decrypt what we just encrypted */
        status = AESCCM_cipher(MOC_SYM(hwAccelCtx) ctx, testPacket.nonce, testPacket.nonceLen,
                            testPacket.packet, testPacket.packetHeaderLen, 
                            testPacket.packet + testPacket.packetHeaderLen,
                            testPacket.packetLen - testPacket.packetHeaderLen, 
                            M, 0);

        retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( testPacket.packet, pRefPacket->packet,
                    testPacket.packetLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        status = AESCCM_deleteCtx(MOC_SYM(hwAccelCtx) &ctx);

        retVal += UNITTEST_STATUS(i, status);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}
/*
   =============== Packet Vector #1 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5
   Total packet length = 31. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E
   CBC IV in: 59 00 00 00  03 02 01 00  A0 A1 A2 A3  A4 A5 00 17
   CBC IV out:EB 9D 55 47  73 09 55 AB  23 1E 0A 2D  FE 4B 90 D6
   After xor: EB 95 55 46  71 0A 51 AE  25 19 0A 2D  FE 4B 90 D6   [hdr]
   After AES: CD B6 41 1E  3C DC 9B 4F  5D 92 58 B6  9E E7 F0 91
   After xor: C5 BF 4B 15  30 D1 95 40  4D 83 4A A5  8A F2 E6 86   [msg]
   After AES: 9C 38 40 5E  A0 3C 1B C9  04 B5 8B 40  C7 6C A2 EB
   After xor: 84 21 5A 45  BC 21 05 C9  04 B5 8B 40  C7 6C A2 EB   [msg]
   After AES: 2D C6 97 E4  11 CA 83 A8  60 C2 C4 06  CC AA 54 2F
   CBC-MAC  : 2D C6 97 E4  11 CA 83 A8
   CTR Start: 01 00 00 00  03 02 01 00  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 50 85 9D 91  6D CB 6D DD  E0 77 C2 D1  D4 EC 9F 97
   CTR[0002]: 75 46 71 7A  C6 DE 9A FF  64 0C 9C 06  DE 6D 0D 8F
   CTR[MAC ]: 3A 2E 46 C8  EC 33 A5 48
   Total packet length = 39. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  58 8C 97 9A  61 C6 63 D2
              F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17
              E8 D1 2C FD  F9 26 E0


   =============== Packet Vector #2 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5
   Total packet length = 32. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
   CBC IV in: 59 00 00 00  04 03 02 01  A0 A1 A2 A3  A4 A5 00 18
   CBC IV out:F0 C2 54 D3  CA 03 E2 39  70 BD 24 A8  4C 39 9E 77
   After xor: F0 CA 54 D2  C8 00 E6 3C  76 BA 24 A8  4C 39 9E 77   [hdr]
   After AES: 48 DE 8B 86  28 EA 4A 40  00 AA 42 C2  95 BF 4A 8C
   After xor: 40 D7 81 8D  24 E7 44 4F  10 BB 50 D1  81 AA 5C 9B   [msg]
   After AES: 0F 89 FF BC  A6 2B C2 4F  13 21 5F 16  87 96 AA 33
   After xor: 17 90 E5 A7  BA 36 DC 50  13 21 5F 16  87 96 AA 33   [msg]
   After AES: F7 B9 05 6A  86 92 6C F3  FB 16 3D C4  99 EF AA 11
   CBC-MAC  : F7 B9 05 6A  86 92 6C F3
   CTR Start: 01 00 00 00  04 03 02 01  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 7A C0 10 3D  ED 38 F6 C0  39 0D BA 87  1C 49 91 F4
   CTR[0002]: D4 0C DE 22  D5 F9 24 24  F7 BE 9A 56  9D A7 9F 51
   CTR[MAC ]: 57 28 D0 04  96 D2 65 E5
   Total packet length = 40. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  72 C9 1A 36  E1 35 F8 CF
              29 1C A8 94  08 5C 87 E3  CC 15 C4 39  C9 E4 3A 3B
              A0 91 D5 6E  10 40 09 16

   =============== Packet Vector #3 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5
   Total packet length = 33. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
              20
   CBC IV in: 59 00 00 00  05 04 03 02  A0 A1 A2 A3  A4 A5 00 19
   CBC IV out:6F 8A 12 F7  BF 8D 4D C5  A1 19 6E 95  DF F0 B4 27
   After xor: 6F 82 12 F6  BD 8E 49 C0  A7 1E 6E 95  DF F0 B4 27   [hdr]
   After AES: 37 E9 B7 8C  C2 20 17 E7  33 80 43 0C  BE F4 28 24
   After xor: 3F E0 BD 87  CE 2D 19 E8  23 91 51 1F  AA E1 3E 33   [msg]
   After AES: 90 CA 05 13  9F 4D 4E CF  22 6F E9 81  C5 9E 2D 40
   After xor: 88 D3 1F 08  83 50 50 D0  02 6F E9 81  C5 9E 2D 40   [msg]
   After AES: 73 B4 67 75  C0 26 DE AA  41 03 97 D6  70 FE 5F B0
   CBC-MAC  : 73 B4 67 75  C0 26 DE AA
   CTR Start: 01 00 00 00  05 04 03 02  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 59 B8 EF FF  46 14 73 12  B4 7A 1D 9D  39 3D 3C FF
   CTR[0002]: 69 F1 22 A0  78 C7 9B 89  77 89 4C 99  97 5C 23 78
   CTR[MAC ]: 39 6E C0 1A  7D B9 6E 6F
   Total packet length = 41. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  51 B1 E5 F4  4A 19 7D 1D
              A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96
              57 4A DA A7  6F BD 9F B0  C5

   =============== Packet Vector #4 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 06  05 04 03 A0  A1 A2 A3 A4  A5
   Total packet length = 31. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E
   CBC IV in: 59 00 00 00  06 05 04 03  A0 A1 A2 A3  A4 A5 00 13
   CBC IV out:06 65 2C 60  0E F5 89 63  CA C3 25 A9  CD 3E 2B E1
   After xor: 06 69 2C 61  0C F6 8D 66  CC C4 2D A0  C7 35 2B E1   [hdr]
   After AES: A0 75 09 AC  15 C2 58 86  04 2F 80 60  54 FE A6 86
   After xor: AC 78 07 A3  05 D3 4A 95  10 3A 96 77  4C E7 BC 9D   [msg]
   After AES: 64 4C 09 90  D9 1B 83 E9  AB 4B 8E ED  06 6F F5 BF
   After xor: 78 51 17 90  D9 1B 83 E9  AB 4B 8E ED  06 6F F5 BF   [msg]
   After AES: 4B 4F 4B 39  B5 93 E6 BF  B0 B2 C2 B7  0F 29 CD 7A
   CBC-MAC  : 4B 4F 4B 39  B5 93 E6 BF
   CTR Start: 01 00 00 00  06 05 04 03  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: AE 81 66 6A  83 8B 88 6A  EE BF 4A 5B  32 84 50 8A
   CTR[0002]: D1 B1 92 06  AC 93 9E 2F  B6 DD CE 10  A7 74 FD 8D
   CTR[MAC ]: DD 87 2A 80  7C 75 F8 4E
   Total packet length = 39. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  A2 8C 68 65
              93 9A 9A 79  FA AA 5C 4C  2A 9D 4A 91  CD AC 8C 96
              C8 61 B9 C9  E6 1E F1

   =============== Packet Vector #5 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 07  06 05 04 A0  A1 A2 A3 A4  A5
   Total packet length = 32. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
   CBC IV in: 59 00 00 00  07 06 05 04  A0 A1 A2 A3  A4 A5 00 14
   CBC IV out:00 4C 50 95  45 80 3C 48  51 CD E1 3B  56 C8 9A 85
   After xor: 00 40 50 94  47 83 38 4D  57 CA E9 32  5C C3 9A 85   [hdr]
   After AES: E2 B8 F7 CE  49 B2 21 72  84 A8 EA 84  FA AD 67 5C
   After xor: EE B5 F9 C1  59 A3 33 61  90 BD FC 93  E2 B4 7D 47   [msg]
   After AES: 3E FB 36 72  25 DB 11 01  D3 C2 2F 0E  CA FF 44 F3
   After xor: 22 E6 28 6D  25 DB 11 01  D3 C2 2F 0E  CA FF 44 F3   [msg]
   After AES: 48 B9 E8 82  55 05 4A B5  49 0A 95 F9  34 9B 4B 5E
   CBC-MAC  : 48 B9 E8 82  55 05 4A B5
   CTR Start: 01 00 00 00  07 06 05 04  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: D0 FC F5 74  4D 8F 31 E8  89 5B 05 05  4B 7C 90 C3
   CTR[0002]: 72 A0 D4 21  9F 0D E1 D4  04 83 BC 2D  3D 0C FC 2A
   CTR[MAC ]: 19 51 D7 85  28 99 67 26
   Total packet length = 40. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  DC F1 FB 7B
              5D 9E 23 FB  9D 4E 13 12  53 65 8A D8  6E BD CA 3E
              51 E8 3F 07  7D 9C 2D 93

   =============== Packet Vector #6 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 08  07 06 05 A0  A1 A2 A3 A4  A5
   Total packet length = 33. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
              20
   CBC IV in: 59 00 00 00  08 07 06 05  A0 A1 A2 A3  A4 A5 00 15
   CBC IV out:04 72 DA 4C  6F F6 0A 63  06 52 1A 06  04 80 CD E5
   After xor: 04 7E DA 4D  6D F5 0E 66  00 55 12 0F  0E 8B CD E5   [hdr]
   After AES: 64 4C 36 A5  A2 27 37 62  0B 89 F1 D7  BF F2 73 D4
   After xor: 68 41 38 AA  B2 36 25 71  1F 9C E7 C0  A7 EB 69 CF   [msg]
   After AES: 41 E1 19 CD  19 24 CE 77  F1 2F A6 60  C1 6E BB 4E
   After xor: 5D FC 07 D2  39 24 CE 77  F1 2F A6 60  C1 6E BB 4E   [msg]
   After AES: A5 27 D8 15  6A C3 59 BF  1C B8 86 E6  2F 29 91 29
   CBC-MAC  : A5 27 D8 15  6A C3 59 BF
   CTR Start: 01 00 00 00  08 07 06 05  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 63 CC BE 1E  E0 17 44 98  45 64 B2 3A  8D 24 5C 80
   CTR[0002]: 39 6D BA A2  A7 D2 CB D4  B5 E1 7C 10  79 45 BB C0
   CTR[MAC ]: E5 7D DC 56  C6 52 92 2B
   Total packet length = 41. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  6F C1 B0 11
              F0 06 56 8B  51 71 A4 2D  95 3D 46 9B  25 70 A4 BD
              87 40 5A 04  43 AC 91 CB  94

   =============== Packet Vector #7 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 09  08 07 06 A0  A1 A2 A3 A4  A5
   Total packet length = 31. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E
   CBC IV in: 61 00 00 00  09 08 07 06  A0 A1 A2 A3  A4 A5 00 17
   CBC IV out:60 06 C5 72  DA 23 9C BF  A0 5B 0A DE  D2 CD A8 1E
   After xor: 60 0E C5 73  D8 20 98 BA  A6 5C 0A DE  D2 CD A8 1E   [hdr]
   After AES: 41 7D E2 AE  94 E2 EA D9  00 FC 44 FC  D0 69 52 27
   After xor: 49 74 E8 A5  98 EF E4 D6  10 ED 56 EF  C4 7C 44 30   [msg]
   After AES: 2A 6C 42 CA  49 D7 C7 01  C5 7D 59 FF  87 16 49 0E
   After xor: 32 75 58 D1  55 CA D9 01  C5 7D 59 FF  87 16 49 0E   [msg]
   After AES: 89 8B D6 45  4E 27 20 BB  D2 7E F3 15  7A 7C 90 B2
   CBC-MAC  : 89 8B D6 45  4E 27 20 BB  D2 7E
   CTR Start: 01 00 00 00  09 08 07 06  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 09 3C DB B9  C5 52 4F DA  C1 C5 EC D2  91 C4 70 AF
   CTR[0002]: 11 57 83 86  E2 C4 72 B4  8E CC 8A AD  AB 77 6F CB
   CTR[MAC ]: 8D 07 80 25  62 B0 8C 00  A6 EE
   Total packet length = 41. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  01 35 D1 B2  C9 5F 41 D5
              D1 D4 FE C1  85 D1 66 B8  09 4E 99 9D  FE D9 6C 04
              8C 56 60 2C  97 AC BB 74  90

   =============== Packet Vector #8 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 0A  09 08 07 A0  A1 A2 A3 A4  A5
   Total packet length = 32. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
   CBC IV in: 61 00 00 00  0A 09 08 07  A0 A1 A2 A3  A4 A5 00 18
   CBC IV out:63 A3 FA E4  6C 79 F3 FA  78 38 B8 A2  80 36 B6 0B
   After xor: 63 AB FA E5  6E 7A F7 FF  7E 3F B8 A2  80 36 B6 0B   [hdr]
   After AES: 1C 99 1A 3D  B7 60 79 27  34 40 79 1F  AD 8B 5B 02
   After xor: 14 90 10 36  BB 6D 77 28  24 51 6B 0C  B9 9E 4D 15   [msg]
   After AES: 14 19 E8 E8  CB BE 75 58  E1 E3 BE 4B  6C 9F 82 E3
   After xor: 0C 00 F2 F3  D7 A3 6B 47  E1 E3 BE 4B  6C 9F 82 E3   [msg]
   After AES: E0 16 E8 1C  7F 7B 8A 38  A5 38 F2 CB  5B B6 C1 F2
   CBC-MAC  : E0 16 E8 1C  7F 7B 8A 38  A5 38
   CTR Start: 01 00 00 00  0A 09 08 07  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 73 7C 33 91  CC 8E 13 DD  E0 AA C5 4B  6D B7 EB 98
   CTR[0002]: 74 B7 71 77  C5 AA C5 3B  04 A4 F8 70  8E 92 EB 2B
   CTR[MAC ]: 21 6D AC 2F  8B 4F 1C 07  91 8C
   Total packet length = 42. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  7B 75 39 9A  C0 83 1D D2
              F0 BB D7 58  79 A2 FD 8F  6C AE 6B 6C  D9 B7 DB 24
              C1 7B 44 33  F4 34 96 3F  34 B4

   =============== Packet Vector #9 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 0B  0A 09 08 A0  A1 A2 A3 A4  A5
   Total packet length = 33. [Input with 8 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
              20
   CBC IV in: 61 00 00 00  0B 0A 09 08  A0 A1 A2 A3  A4 A5 00 19
   CBC IV out:4F 2C 86 11  1E 08 2A DD  6B 44 21 3A  B5 13 13 16
   After xor: 4F 24 86 10  1C 0B 2E D8  6D 43 21 3A  B5 13 13 16   [hdr]
   After AES: F6 EC 56 87  3C 57 12 DC  9C C5 3C A8  D4 D1 ED 0A
   After xor: FE E5 5C 8C  30 5A 1C D3  8C D4 2E BB  C0 C4 FB 1D   [msg]
   After AES: 17 C1 80 A5  31 53 D4 C3  03 85 0C 95  65 80 34 52
   After xor: 0F D8 9A BE  2D 4E CA DC  23 85 0C 95  65 80 34 52   [msg]
   After AES: 46 A1 F6 E2  B1 6E 75 F8  1C F5 6B 1A  80 04 44 1B
   CBC-MAC  : 46 A1 F6 E2  B1 6E 75 F8  1C F5
   CTR Start: 01 00 00 00  0B 0A 09 08  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 8A 5A 10 6B  C0 29 9A 55  5B 93 6B 0B  0E A0 DE 5A
   CTR[0002]: EA 05 FD E2  AB 22 5C FE  B7 73 12 CB  88 D9 A5 4A
   CTR[MAC ]: AC 3D F1 07  DA 30 C4 86  43 BB
   Total packet length = 43. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  82 53 1A 60  CC 24 94 5A
              4B 82 79 18  1A B5 C8 4D  F2 1C E7 F9  B7 3F 42 E1
              97 EA 9C 07  E5 6B 5E B1  7E 5F 4E

   =============== Packet Vector #10 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 0C  0B 0A 09 A0  A1 A2 A3 A4  A5
   Total packet length = 31. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E
   CBC IV in: 61 00 00 00  0C 0B 0A 09  A0 A1 A2 A3  A4 A5 00 13
   CBC IV out:7F B8 0A 32  E9 80 57 46  EC 31 6C 3A  B2 A2 EB 5D
   After xor: 7F B4 0A 33  EB 83 53 43  EA 36 64 33  B8 A9 EB 5D   [hdr]
   After AES: 7E 96 96 BF  F1 56 D6 A8  6E AC F5 7B  7F 23 47 5A
   After xor: 72 9B 98 B0  E1 47 C4 BB  7A B9 E3 6C  67 3A 5D 41   [msg]
   After AES: 8B 4A EE 42  04 24 8A 59  FA CC 88 66  57 66 DD 72
   After xor: 97 57 F0 42  04 24 8A 59  FA CC 88 66  57 66 DD 72   [msg]
   After AES: 41 63 89 36  62 ED D7 EB  CD 6E 15 C1  89 48 62 05
   CBC-MAC  : 41 63 89 36  62 ED D7 EB  CD 6E
   CTR Start: 01 00 00 00  0C 0B 0A 09  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 0B 39 2B 9B  05 66 97 06  3F 12 56 8F  2B 13 A1 0F
   CTR[0002]: 07 89 65 25  23 40 94 3B  9E 69 B2 56  CC 5E F7 31
   CTR[MAC ]: 17 09 20 76  09 A0 4E 72  45 B3
   Total packet length = 41. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  07 34 25 94
              15 77 85 15  2B 07 40 98  33 0A BB 14  1B 94 7B 56
              6A A9 40 6B  4D 99 99 88  DD

   =============== Packet Vector #11 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 0D  0C 0B 0A A0  A1 A2 A3 A4  A5
   Total packet length = 32. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
   CBC IV in: 61 00 00 00  0D 0C 0B 0A  A0 A1 A2 A3  A4 A5 00 14
   CBC IV out:B0 84 85 79  51 D2 FA 42  76 EF 3A D7  14 B9 62 87
   After xor: B0 88 85 78  53 D1 FE 47  70 E8 32 DE  1E B2 62 87   [hdr]
   After AES: C9 B3 64 7E  D8 79 2A 5C  65 B7 CE CC  19 0A 97 0A
   After xor: C5 BE 6A 71  C8 68 38 4F  71 A2 D8 DB  01 13 8D 11   [msg]
   After AES: 34 0F 69 17  FA B9 19 D6  1D AC D0 35  36 D6 55 8B
   After xor: 28 12 77 08  FA B9 19 D6  1D AC D0 35  36 D6 55 8B   [msg]
   After AES: 6B 5E 24 34  12 CC C2 AD  6F 1B 11 C3  A1 A9 D8 BC
   CBC-MAC  : 6B 5E 24 34  12 CC C2 AD  6F 1B
   CTR Start: 01 00 00 00  0D 0C 0B 0A  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: 6B 66 BC 0C  90 A1 F1 12  FC BE 6F 4E  12 20 77 BC
   CTR[0002]: 97 9E 57 2B  BE 65 8A E5  CC 20 11 83  2A 9A 9B 5B
   CTR[MAC ]: 9E 64 86 DD  02 B6 49 C1  6D 37
   Total packet length = 42. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  67 6B B2 03
              80 B0 E3 01  E8 AB 79 59  0A 39 6D A7  8B 83 49 34
              F5 3A A2 E9  10 7A 8B 6C  02 2C

   =============== Packet Vector #12 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 0E  0D 0C 0B A0  A1 A2 A3 A4  A5
   Total packet length = 33. [Input with 12 cleartext header octets]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
              20
   CBC IV in: 61 00 00 00  0E 0D 0C 0B  A0 A1 A2 A3  A4 A5 00 15
   CBC IV out:5F 8E 8D 02  AD 95 7C 5A  36 14 CF 63  40 16 97 4F
   After xor: 5F 82 8D 03  AF 96 78 5F  30 13 C7 6A  4A 1D 97 4F   [hdr]
   After AES: 63 FA BD 69  B9 55 65 FF  54 AA F4 60  88 7D EC 9F
   After xor: 6F F7 B3 66  A9 44 77 EC  40 BF E2 77  90 64 F6 84   [msg]
   After AES: 5A 76 5F 0B  93 CE 4F 6A  B4 1D 91 30  18 57 6A D7
   After xor: 46 6B 41 14  B3 CE 4F 6A  B4 1D 91 30  18 57 6A D7   [msg]
   After AES: 9D 66 92 41  01 08 D5 B6  A1 45 85 AC  AF 86 32 E8
   CBC-MAC  : 9D 66 92 41  01 08 D5 B6  A1 45
   CTR Start: 01 00 00 00  0E 0D 0C 0B  A0 A1 A2 A3  A4 A5 00 01
   CTR[0001]: CC F2 AE D9  E0 4A C9 74  E6 58 55 B3  2B 94 30 BF
   CTR[0002]: A2 CA AC 11  63 F4 07 E5  E5 F6 E3 B3  79 0F 79 F8
   CTR[MAC ]: 50 7C 31 57  63 EF 78 D3  77 9E
   Total packet length = 43. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  08 09 0A 0B  C0 FF A0 D6
              F0 5B DB 67  F2 4D 43 A4  33 8D 2A A4  BE D7 B2 0E
              43 CD 1A A3  16 62 E7 AD  65 D6 DB

   =============== Packet Vector #13 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 41 2B 4E  A9 CD BE 3C  96 96 76 6C  FA
   Total packet length = 31. [Input with 8 cleartext header octets]
              0B E1 A8 8B  AC E0 18 B1  08 E8 CF 97  D8 20 EA 25
              84 60 E9 6A  D9 CF 52 89  05 4D 89 5C  EA C4 7C
   CBC IV in: 59 00 41 2B  4E A9 CD BE  3C 96 96 76  6C FA 00 17
   CBC IV out:33 AE C3 1A  1F B7 CC 35  E5 DA D2 BA  C0 90 D9 A3
   After xor: 33 A6 C8 FB  B7 3C 60 D5  FD 6B D2 BA  C0 90 D9 A3   [hdr]
   After AES: B7 56 CA 1E  5B 42 C6 9C  58 E3 0A F5  2B F7 7C FD
   After xor: BF BE 05 89  83 62 2C B9  DC 83 E3 9F  F2 38 2E 74   [msg]
   After AES: 33 3D 3A 3D  07 B5 3C 7B  22 0E 96 1A  18 A9 A1 9E
   After xor: 36 70 B3 61  ED 71 40 7B  22 0E 96 1A  18 A9 A1 9E   [msg]
   After AES: 14 BD DB 6B  F9 01 63 4D  FB 56 51 83  BC 74 93 F7
   CBC-MAC  : 14 BD DB 6B  F9 01 63 4D
   CTR Start: 01 00 41 2B  4E A9 CD BE  3C 96 96 76  6C FA 00 01
   CTR[0001]: 44 51 B0 11  7A 84 82 BF  03 19 AE C1  59 5E BD DA
   CTR[0002]: 83 EB 76 E1  3A 44 84 7F  92 20 09 07  76 B8 25 C5
   CTR[MAC ]: F3 31 2C A0  F5 DC B4 FE
   Total packet length = 39. [Authenticated and Encrypted Output]
              0B E1 A8 8B  AC E0 18 B1  4C B9 7F 86  A2 A4 68 9A
              87 79 47 AB  80 91 EF 53  86 A6 FF BD  D0 80 F8 E7
              8C F7 CB 0C  DD D7 B3

   =============== Packet Vector #14 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 33 56 8E  F7 B2 63 3C  96 96 76 6C  FA
   Total packet length = 32. [Input with 8 cleartext header octets]
              63 01 8F 76  DC 8A 1B CB  90 20 EA 6F  91 BD D8 5A
              FA 00 39 BA  4B AF F9 BF  B7 9C 70 28  94 9C D0 EC
   CBC IV in: 59 00 33 56  8E F7 B2 63  3C 96 96 76  6C FA 00 18
   CBC IV out:42 0D B1 50  BB 0C 44 DA  83 E4 52 09  55 99 67 E3
   After xor: 42 05 D2 51  34 7A 98 50  98 2F 52 09  55 99 67 E3   [hdr]
   After AES: EA D1 CA 56  02 02 09 5C  E6 12 B0 D2  18 A0 DD 44
   After xor: 7A F1 20 39  93 BF D1 06  1C 12 89 68  53 0F 24 FB   [msg]
   After AES: 51 77 41 69  C3 DE 6B 24  13 27 74 90  F5 FF C5 62
   After xor: E6 EB 31 41  57 42 BB C8  13 27 74 90  F5 FF C5 62   [msg]
   After AES: D4 CC 3B 82  DF 9F CC 56  7E E5 83 61  D7 8D FB 5E
   CBC-MAC  : D4 CC 3B 82  DF 9F CC 56
   CTR Start: 01 00 33 56  8E F7 B2 63  3C 96 96 76  6C FA 00 01
   CTR[0001]: DC EB F4 13  38 3C 66 A0  5A 72 55 EF  98 D7 FF AD
   CTR[0002]: 2F 54 2C BA  15 D6 6C DF  E1 EC 46 8F  0E 68 A1 24
   CTR[MAC ]: 11 E2 D3 9F  A2 E8 0C DC
   Total packet length = 40. [Authenticated and Encrypted Output]
              63 01 8F 76  DC 8A 1B CB  4C CB 1E 7C  A9 81 BE FA
              A0 72 6C 55  D3 78 06 12  98 C8 5C 92  81 4A BC 33
              C5 2E E8 1D  7D 77 C0 8A

   =============== Packet Vector #15 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 10 3F E4  13 36 71 3C  96 96 76 6C  FA
   Total packet length = 33. [Input with 8 cleartext header octets]
              AA 6C FA 36  CA E8 6B 40  B9 16 E0 EA  CC 1C 00 D7
              DC EC 68 EC  0B 3B BB 1A  02 DE 8A 2D  1A A3 46 13
              2E
   CBC IV in: 59 00 10 3F  E4 13 36 71  3C 96 96 76  6C FA 00 19
   CBC IV out:B3 26 49 FF  D5 9F 56 0F  02 2D 11 E2  62 C5 BE EA
   After xor: B3 2E E3 93  2F A9 9C E7  69 6D 11 E2  62 C5 BE EA   [hdr]
   After AES: 82 50 9E E5  B2 FF DB CA  9B D0 2E 20  6B 3F B7 AD
   After xor: 3B 46 7E 0F  7E E3 DB 1D  47 3C 46 CC  60 04 0C B7   [msg]
   After AES: 80 46 0E 4C  08 3A D0 3F  B9 A9 13 BE  E4 DE 2F 66
   After xor: 82 98 84 61  12 99 96 2C  97 A9 13 BE  E4 DE 2F 66   [msg]
   After AES: 47 29 CB 00  31 F1 81 C1  92 68 4B 89  A4 71 50 E7
   CBC-MAC  : 47 29 CB 00  31 F1 81 C1
   CTR Start: 01 00 10 3F  E4 13 36 71  3C 96 96 76  6C FA 00 01
   CTR[0001]: 08 C4 DA C8  EC C1 C0 7B  4C E1 F2 4C  37 5A 47 EE
   CTR[0002]: A7 87 2E 6C  6D C4 4E 84  26 02 50 4C  3F A5 73 C5
   CTR[MAC ]: E0 5F B2 6E  EA 83 B4 C7
   Total packet length = 41. [Authenticated and Encrypted Output]
              AA 6C FA 36  CA E8 6B 40  B1 D2 3A 22  20 DD C0 AC
              90 0D 9A A0  3C 61 FC F4  A5 59 A4 41  77 67 08 97
              08 A7 76 79  6E DB 72 35  06

   =============== Packet Vector #16 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 76 4C 63  B8 05 8E 3C  96 96 76 6C  FA
   Total packet length = 31. [Input with 12 cleartext header octets]
              D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44  12 DA AC 56
              30 EF A5 39  6F 77 0C E1  A6 6B 21 F7  B2 10 1C
   CBC IV in: 59 00 76 4C  63 B8 05 8E  3C 96 96 76  6C FA 00 13
   CBC IV out:AB DC 4E C9  AA 72 33 97  DF 2D AD 76  33 DE 3B 0D
   After xor: AB D0 9E 19  D9 2E 60 89  C4 C1 5D 3F  F1 9A 3B 0D   [hdr]
   After AES: 62 86 F6 2F  23 42 63 B0  1C FD 8C 37  40 74 81 EB
   After xor: 70 5C 5A 79  13 AD C6 89  73 8A 80 D6  E6 1F A0 1C   [msg]
   After AES: 88 95 84 18  CF 79 CA BE  EB C0 0C C4  86 E6 01 F7
   After xor: 3A 85 98 18  CF 79 CA BE  EB C0 0C C4  86 E6 01 F7   [msg]
   After AES: C1 85 92 D9  84 CD 67 80  63 D1 D9 6D  C1 DF A1 11
   CBC-MAC  : C1 85 92 D9  84 CD 67 80
   CTR Start: 01 00 76 4C  63 B8 05 8E  3C 96 96 76  6C FA 00 01
   CTR[0001]: 06 08 FF 95  A6 94 D5 59  F4 0B B7 9D  EF FA 41 DF
   CTR[0002]: 80 55 3A 75  78 38 04 A9  64 8B 68 DD  7F DC DD 7A
   CTR[MAC ]: 5B EA DB 4E  DF 07 B9 2F
   Total packet length = 39. [Authenticated and Encrypted Output]
              D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44  14 D2 53 C3
              96 7B 70 60  9B 7C BB 7C  49 91 60 28  32 45 26 9A
              6F 49 97 5B  CA DE AF

   =============== Packet Vector #17 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 F8 B6 78  09 4E 3B 3C  96 96 76 6C  FA
   Total packet length = 32. [Input with 12 cleartext header octets]
              77 B6 0F 01  1C 03 E1 52  58 99 BC AE  E8 8B 6A 46
              C7 8D 63 E5  2E B8 C5 46  EF B5 DE 6F  75 E9 CC 0D
   CBC IV in: 59 00 F8 B6  78 09 4E 3B  3C 96 96 76  6C FA 00 14
   CBC IV out:F4 68 FE 5D  B1 53 0B 7A  5A A5 FB 27  40 CF 6E 33
   After xor: F4 64 89 EB  BE 52 17 79  BB F7 A3 BE  FC 61 6E 33   [hdr]
   After AES: 23 29 0E 0B  33 45 9A 83  32 2D E4 06  86 67 10 04
   After xor: CB A2 64 4D  F4 C8 F9 66  1C 95 21 40  69 D2 CE 6B   [msg]
   After AES: 8F BE D4 0F  8B 89 B7 B8  20 D5 5F E0  3C E2 43 11
   After xor: FA 57 18 02  8B 89 B7 B8  20 D5 5F E0  3C E2 43 11   [msg]
   After AES: 6A DB 15 B6  71 81 B2 E2  2B E3 4A F2  B2 83 E2 29
   CBC-MAC  : 6A DB 15 B6  71 81 B2 E2
   CTR Start: 01 00 F8 B6  78 09 4E 3B  3C 96 96 76  6C FA 00 01
   CTR[0001]: BD CE 95 5C  CF D3 81 0A  91 EA 77 A6  A4 5B C0 4C
   CTR[0002]: 43 2E F2 32  AE 36 D8 92  22 BF 63 37  E6 B2 6C E8
   CTR[MAC ]: 1C F7 19 C1  35 7F CC DE
   Total packet length = 40. [Authenticated and Encrypted Output]
              77 B6 0F 01  1C 03 E1 52  58 99 BC AE  55 45 FF 1A
              08 5E E2 EF  BF 52 B2 E0  4B EE 1E 23  36 C7 3E 3F
              76 2C 0C 77  44 FE 7E 3C

   =============== Packet Vector #18 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 D5 60 91  2D 3F 70 3C  96 96 76 6C  FA
   Total packet length = 33. [Input with 12 cleartext header octets]
              CD 90 44 D2  B7 1F DB 81  20 EA 60 C0  64 35 AC BA
              FB 11 A8 2E  2F 07 1D 7C  A4 A5 EB D9  3A 80 3B A8
              7F
   CBC IV in: 59 00 D5 60  91 2D 3F 70  3C 96 96 76  6C FA 00 15
   CBC IV out:BA 37 74 54  D7 20 A4 59  25 97 F6 A3  D1 D6 BA 67
   After xor: BA 3B B9 C4  93 F2 13 46  FE 16 D6 49  B1 16 BA 67   [hdr]
   After AES: 81 6A 20 20  38 D0 A6 30  CB E0 B7 3C  39 BB CE 05
   After xor: E5 5F 8C 9A  C3 C1 0E 1E  E4 E7 AA 40  9D 1E 25 DC   [msg]
   After AES: 6D 5C 15 FD  85 2D 5C 3C  E3 03 3D 85  DA 57 BD AC
   After xor: 57 DC 2E 55  FA 2D 5C 3C  E3 03 3D 85  DA 57 BD AC   [msg]
   After AES: B0 4A 1C 23  BC 39 B6 51  76 FD 5B FF  9B C1 28 5E
   CBC-MAC  : B0 4A 1C 23  BC 39 B6 51
   CTR Start: 01 00 D5 60  91 2D 3F 70  3C 96 96 76  6C FA 00 01
   CTR[0001]: 64 A2 C5 56  50 CE E0 4C  7A 93 D8 EE  F5 43 E8 8E
   CTR[0002]: 18 E7 65 AC  B7 B0 E9 AF  09 2B D0 20  6C A1 C8 3C
   CTR[MAC ]: F7 43 82 79  5C 49 F3 00
   Total packet length = 41. [Authenticated and Encrypted Output]
              CD 90 44 D2  B7 1F DB 81  20 EA 60 C0  00 97 69 EC
              AB DF 48 62  55 94 C5 92  51 E6 03 57  22 67 5E 04
              C8 47 09 9E  5A E0 70 45  51

   =============== Packet Vector #19 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 42 FF F8  F1 95 1C 3C  96 96 76 6C  FA
   Total packet length = 31. [Input with 8 cleartext header octets]
              D8 5B C7 E6  9F 94 4F B8  8A 19 B9 50  BC F7 1A 01
              8E 5E 67 01  C9 17 87 65  98 09 D6 7D  BE DD 18
   CBC IV in: 61 00 42 FF  F8 F1 95 1C  3C 96 96 76  6C FA 00 17
   CBC IV out:44 F7 CC 9C  2B DD 2F 45  F6 38 25 6B  73 6E 1D 7A
   After xor: 44 FF 14 C7  EC 3B B0 D1  B9 80 25 6B  73 6E 1D 7A   [hdr]
   After AES: 57 C3 73 F8  00 AA 5F CC  7B CF 1D 1B  DD BB 4C 52
   After xor: DD DA CA A8  BC 5D 45 CD  F5 91 7A 1A  14 AC CB 37   [msg]
   After AES: 42 4E 93 72  72 C8 79 B6  11 C7 A5 9F  47 8D 9F D8
   After xor: DA 47 45 0F  CC 15 61 B6  11 C7 A5 9F  47 8D 9F D8   [msg]
   After AES: 9A CB 03 F8  B9 DB C8 D2  D2 D7 A4 B4  95 25 08 67
   CBC-MAC  : 9A CB 03 F8  B9 DB C8 D2  D2 D7
   CTR Start: 01 00 42 FF  F8 F1 95 1C  3C 96 96 76  6C FA 00 01
   CTR[0001]: 36 38 34 FA  28 83 3D B7  55 66 0D 98  65 0D 68 46
   CTR[0002]: 35 E9 63 54  87 16 72 56  3F 0C 08 AF  78 44 31 A9
   CTR[MAC ]: F9 B7 FA 46  7B 9B 40 45  14 6D
   Total packet length = 41. [Authenticated and Encrypted Output]
              D8 5B C7 E6  9F 94 4F B8  BC 21 8D AA  94 74 27 B6
              DB 38 6A 99  AC 1A EF 23  AD E0 B5 29  39 CB 6A 63
              7C F9 BE C2  40 88 97 C6  BA

   =============== Packet Vector #20 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 92 0F 40  E5 6C DC 3C  96 96 76 6C  FA
   Total packet length = 32. [Input with 8 cleartext header octets]
              74 A0 EB C9  06 9F 5B 37  17 61 43 3C  37 C5 A3 5F
              C1 F3 9F 40  63 02 EB 90  7C 61 63 BE  38 C9 84 37
   CBC IV in: 61 00 92 0F  40 E5 6C DC  3C 96 96 76  6C FA 00 18
   CBC IV out:60 CB 21 CE  40 06 50 AE  2A D2 BE 52  9F 5F 0F C2
   After xor: 60 C3 55 6E  AB CF 56 31  71 E5 BE 52  9F 5F 0F C2   [hdr]
   After AES: 03 20 64 14  35 32 5D 95  C8 A2 50 40  93 28 DA 9B
   After xor: 14 41 27 28  02 F7 FE CA  09 51 CF 00  F0 2A 31 0B   [msg]
   After AES: B9 E8 87 95  ED F7 F0 08  15 15 F0 14  E2 FE 0E 48
   After xor: C5 89 E4 2B  D5 3E 74 3F  15 15 F0 14  E2 FE 0E 48   [msg]
   After AES: 8F AD 0C 23  E9 63 7E 87  FA 21 45 51  1B 47 DE F1
   CBC-MAC  : 8F AD 0C 23  E9 63 7E 87  FA 21
   CTR Start: 01 00 92 0F  40 E5 6C DC  3C 96 96 76  6C FA 00 01
   CTR[0001]: 4F 71 A5 C1  12 42 E3 7D  29 F0 FE E4  1B E1 02 5F
   CTR[0002]: 34 2B D3 F1  7C B7 7B C1  79 0B 05 05  61 59 27 2C
   CTR[MAC ]: 7F 09 7B EF  C6 AA C1 D3  73 65
   Total packet length = 42. [Authenticated and Encrypted Output]
              74 A0 EB C9  06 9F 5B 37  58 10 E6 FD  25 87 40 22
              E8 03 61 A4  78 E3 E9 CF  48 4A B0 4F  44 7E FF F6
              F0 A4 77 CC  2F C9 BF 54  89 44


   =============== Packet Vector #21 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 27 CA 0C  71 20 BC 3C  96 96 76 6C  FA
   Total packet length = 33. [Input with 8 cleartext header octets]
              44 A3 AA 3A  AE 64 75 CA  A4 34 A8 E5  85 00 C6 E4
              15 30 53 88  62 D6 86 EA  9E 81 30 1B  5A E4 22 6B
              FA
   CBC IV in: 61 00 27 CA  0C 71 20 BC  3C 96 96 76  6C FA 00 19
   CBC IV out:43 07 C0 73  A8 9E E1 D5  05 27 B2 9A  62 48 D6 D2
   After xor: 43 0F 84 D0  02 A4 4F B1  70 ED B2 9A  62 48 D6 D2   [hdr]
   After AES: B6 0B C6 F5  84 01 75 BC  01 27 70 F1  11 8D 75 10
   After xor: 12 3F 6E 10  01 01 B3 58  14 17 23 79  73 5B F3 FA   [msg]
   After AES: 7D 5E 64 92  CE 2C B9 EA  7E 4C 4A 09  09 89 C8 FB
   After xor: E3 DF 54 89  94 C8 9B 81  84 4C 4A 09  09 89 C8 FB   [msg]
   After AES: 68 5F 8D 79  D2 2B 9B 74  21 DF 4C 3E  87 BA 0A AF
   CBC-MAC  : 68 5F 8D 79  D2 2B 9B 74  21 DF
   CTR Start: 01 00 27 CA  0C 71 20 BC  3C 96 96 76  6C FA 00 01
   CTR[0001]: 56 8A 45 9E  40 09 48 67  EB 85 E0 9E  6A 2E 64 76
   CTR[0002]: A6 00 AA 92  92 03 54 9A  AE EF 2C CC  59 13 7A 57
   CTR[MAC ]: 25 1E DC DD  3F 11 10 F3  98 11
   Total packet length = 43. [Authenticated and Encrypted Output]
              44 A3 AA 3A  AE 64 75 CA  F2 BE ED 7B  C5 09 8E 83
              FE B5 B3 16  08 F8 E2 9C  38 81 9A 89  C8 E7 76 F1
              54 4D 41 51  A4 ED 3A 8B  87 B9 CE

   =============== Packet Vector #22 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 5B 8C CB  CD 9A F8 3C  96 96 76 6C  FA
   Total packet length = 31. [Input with 12 cleartext header octets]
              EC 46 BB 63  B0 25 20 C3  3C 49 FD 70  B9 6B 49 E2
              1D 62 17 41  63 28 75 DB  7F 6C 92 43  D2 D7 C2
   CBC IV in: 61 00 5B 8C  CB CD 9A F8  3C 96 96 76  6C FA 00 13
   CBC IV out:91 14 AD 06  B6 CC 02 35  76 9A B6 14  C4 82 95 03
   After xor: 91 18 41 40  0D AF B2 10  56 59 8A 5D  39 F2 95 03   [hdr]
   After AES: 29 BD 7C 27  83 E3 E8 D3  C3 5C 01 F4  4C EC BB FA
   After xor: 90 D6 35 C5  9E 81 FF 92  A0 74 74 2F  33 80 29 B9   [msg]
   After AES: 4E DA F4 0D  21 0B D4 5F  FE 97 90 B9  AA EC 34 4C
   After xor: 9C 0D 36 0D  21 0B D4 5F  FE 97 90 B9  AA EC 34 4C   [msg]
   After AES: 21 9E F8 90  EA 64 C2 11  A5 37 88 83  E1 BA 22 0D
   CBC-MAC  : 21 9E F8 90  EA 64 C2 11  A5 37
   CTR Start: 01 00 5B 8C  CB CD 9A F8  3C 96 96 76  6C FA 00 01
   CTR[0001]: 88 BC 19 42  80 C1 FA 3E  BE FC EF FB  4D C6 2D 54
   CTR[0002]: 3E 59 7D A5  AE 21 CC A4  00 9E 4C 0C  91 F6 22 49
   CTR[MAC ]: 5C BC 30 98  66 02 A9 F4  64 A0
   Total packet length = 41. [Authenticated and Encrypted Output]
              EC 46 BB 63  B0 25 20 C3  3C 49 FD 70  31 D7 50 A0
              9D A3 ED 7F  DD D4 9A 20  32 AA BF 17  EC 8E BF 7D
              22 C8 08 8C  66 6B E5 C1  97


   =============== Packet Vector #23 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 3E BE 94  04 4B 9A 3C  96 96 76 6C  FA
   Total packet length = 32. [Input with 12 cleartext header octets]
              47 A6 5A C7  8B 3D 59 42  27 E8 5E 71  E2 FC FB B8
              80 44 2C 73  1B F9 51 67  C8 FF D7 89  5E 33 70 76
   CBC IV in: 61 00 3E BE  94 04 4B 9A  3C 96 96 76  6C FA 00 14
   CBC IV out:0F 70 3F 5A  54 2C 44 6E  8B 74 A3 73  9B 48 B9 61
   After xor: 0F 7C 78 FC  0E EB CF 53  D2 36 84 9B  C5 39 B9 61   [hdr]
   After AES: 40 5B ED 29  D0 98 AE 91  DB 68 78 F3  68 B8 73 85
   After xor: A2 A7 16 91  50 DC 82 E2  C0 91 29 94  A0 47 A4 0C   [msg]
   After AES: 3D 03 29 3C  FD 81 1B 37  01 51 FB C7  85 6B 7A 74
   After xor: 63 30 59 4A  FD 81 1B 37  01 51 FB C7  85 6B 7A 74   [msg]
   After AES: 66 4F 27 16  3E 36 0F 72  62 0D 4E 67  7C E0 61 DE
   CBC-MAC  : 66 4F 27 16  3E 36 0F 72  62 0D
   CTR Start: 01 00 3E BE  94 04 4B 9A  3C 96 96 76  6C FA 00 01
   CTR[0001]: 0A 7E 0A 63  53 C8 CF 9E  BC 3B 6E 63  15 9A D0 97
   CTR[0002]: EA 20 32 DA  27 82 6E 13  9E 1E 72 5C  5B 0D 3E BF
   CTR[MAC ]: B9 31 27 CA  F0 F1 A1 20  FA 70
   Total packet length = 42. [Authenticated and Encrypted Output]
              47 A6 5A C7  8B 3D 59 42  27 E8 5E 71  E8 82 F1 DB
              D3 8C E3 ED  A7 C2 3F 04  DD 65 07 1E  B4 13 42 AC
              DF 7E 00 DC  CE C7 AE 52  98 7D

   =============== Packet Vector #24 ==================
   AES Key =  D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B
   Nonce =    00 8D 49 3B  30 AE 8B 3C  96 96 76 6C  FA
   Total packet length = 33. [Input with 12 cleartext header octets]
              6E 37 A6 EF  54 6D 95 5D  34 AB 60 59  AB F2 1C 0B
              02 FE B8 8F  85 6D F4 A3  73 81 BC E3  CC 12 85 17
              D4
   CBC IV in: 61 00 8D 49  3B 30 AE 8B  3C 96 96 76  6C FA 00 15
   CBC IV out:67 AC E4 E8  06 77 7A D3  27 1D 0B 93  4C 67 98 15
   After xor: 67 A0 8A DF  A0 98 2E BE  B2 40 3F 38  2C 3E 98 15   [hdr]
   After AES: 35 58 F8 7E  CA C2 B4 39  B6 7E 75 BB  F1 5E 69 08
   After xor: 9E AA E4 75  C8 3C 0C B6  33 13 81 18  82 DF D5 EB   [msg]
   After AES: 54 E4 7B 62  22 F0 BB 87  17 D0 71 6A  EB AF 19 9E
   After xor: 98 F6 FE 75  F6 F0 BB 87  17 D0 71 6A  EB AF 19 9E   [msg]
   After AES: 23 E3 30 50  BC 57 DC 2C  3D 3E 7C 94  77 D1 49 71
   CBC-MAC  : 23 E3 30 50  BC 57 DC 2C  3D 3E
   CTR Start: 01 00 8D 49  3B 30 AE 8B  3C 96 96 76  6C FA 00 01
   CTR[0001]: 58 DB 19 B3  88 9A A3 8B  3C A4 0B 16  FF 42 2C 73
   CTR[0002]: C3 2F 24 3D  65 DC 7E 9F  4B 02 16 AB  7F B9 6B 4D
   CTR[MAC ]: 4E 2D AE D2  53 F6 B1 8A  1D 67
   Total packet length = 43. [Authenticated and Encrypted Output]
              6E 37 A6 EF  54 6D 95 5D  34 AB 60 59  F3 29 05 B8
              8A 64 1B 04  B9 C9 FF B5  8C C3 90 90  0F 3D A1 2A
              B1 6D CE 9E  82 EF A1 6D  A6 20 59

*/

typedef struct ccm_fips_vector
{
    const char* key;
    const char* nonce;
    const char* adata;
    const char* payload;
    const char* result;
} ccm_fips_vector;

ccm_fips_vector gFIPSVectors[] = 
{
/*[Nlen = 7]*/
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"f0f6f57185e175",
"bede01c0fe061a07b18ed90160f1a3112bdc3d73b184d62d303d4843ed499b2b",
"7808ffd5153b82328497b50602745d911c381a811728ec688e7ef56c5dbb8141",
"7e61b10c073d9e89901e76147f9f914522f8fc105faef929c901aa5d9017e226a7fd785719418475d45bd26ba36e0d3c"
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"2855b2dcca301e",
"04ae5c3b168fb58486a0a0a4bf6f0735000e456fb213224cf9e305eb89316532",
"d32460cf0ceafe6b196003654ba6e2f847db0c5dab33b786f449de0f9fb78972",
"5e242b58a43a359c68ad010e3ae3b6c8e5b4eab16d4a1d818c6e2d624a36ceadc4e952548e7083f28959e3dcd4c6dc30",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"46a5c59da16267",
"998ebe7724826440d77f6b6ec0ac70fc7f783477f981ef0551b5e7a714b640bb",
"dd67f28815b4740aba850496a16abd6b5ebf62d4623a9f5766c091300d7d89fe",
"0c35a1aea3b7233755f39ac912f36686bfe0a7dfc8d4bf3a7756f48734cd0bb719325d813838ba09fb74ca07271d0c44",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"7eb25cfee4bfb8",
"fc6e79e3f5fda034f081f0ee03ccc396eab664d9f26d157d160d579967716501",
"4f9f0ae959913c758cb0fc26eb7f0ac9dd5aa4b43068aa595dcb001a0e19345f",
"9fa5b609d6b5c6c7f84d09c1ee723891f4dfc0e0930dd1d75ac6d194db8df81c387986b0e662b7f57a4bc697974ba6b6",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"ee9f2ed261f080",
"a6576ed8f82cc8801f991afd93c540caab3aeedc629597ea5a828e0c21e86c87",
"55acf59bd7887908e69fa85d7e4a8a5409a1e26f8ae406811b1aed7199f78a3b",
"65046805d98a70d364520e6aae7cf7e7a3d037f2cca987f9d513c48edf344be23390060561ccc63fc0cf04ab141a2188",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"3dd8e3207aab0e",
"8d6b5342f21fce4e9bfbf2f89370bb653aec30878e0ad3eea8063be1897300ae",
"145d87ae37d1d7f6f709052966e24a2d2685fa93ce3b09119082cf321960084c",
"ff902f41f6e1dc8f3dfbbf022811d4c0a8f7c63eaca017976c25fa3d6cf3378559bda1ffaafffa90750c401f583448c5",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"5114ba253ba558",
"822bb4bc251c953d7dc0dffea06ce123ee89b375df441ab5ff86ad3036273693",
"14ba34b5d15246366e5ebc4723c5312609d01c84d9deacdbf75af701b0eb54fe",
"f361566618f8f09210cf8dfdfb4e90caeecb25c01d20bb3d2d620a2c86e4346851a353e3a7cc4084c66c10d23abfa1a4",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"093043e32cc5cb",
"f3158d7cde977f83702f11fdb583e45482eb803ec1764ae4092fb044729ea7d3",
"aad9547a34b49d53ccbf3f68e4bac9972ca117dffa81d4d0ef8b3e40d8672940",
"f6e34cb79542edd24e997cf98e3098646ea6a72a5ebd92f9b27f11999e745c538005d47925df17f51707400716288394",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"17fca1a6e7a790",
"56d46c1d90d599425b00b463e6d9fa54ff0457eb7c12e16bd99ba543228da7f9",
"d0b98342a0e37658d1370354325910176f55482c343263fe95cba848aedab0ce",
"1bb411b02e341ccd7fe208c12a1a4061ceaff3622a944f5a17400906581bc658649cf52d1bea3f6d7fc4d9d30c9b97e5",
},
{ 
"ead996729630c58a9d6f44990e8122ff1dd6e4bf0db38478",
"7be3f1e3ef97e8",
"b4aecbc692e013985ff797eef4b71e4568289e8b873c51df7fb30b99dd3ccb8a",
"493084db8e41f3ec7e41c05fe02e04b2c8189d210ecb396ffeaeb1e251eb9990",
"08a4d9de099253e61c97b280200d34566f655dea7a8199b05c9ee66a2e3a7245f4c3c0702f5a46f7abe599a72c1bdc69",
},
/*[Nlen = 8]*/
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"ba17704695e2417c",
"cad7023f3c545430f5c75a3ac3dce675ae83f483238be8c3527316c7d47d8709",
"576deb5fa69a558d1c783f854ed48eaed6754118540a980fb3607cf0aed81b3b",
"373cb209acb2de685b3543caedc6fd2579cbd5c2c129299d35865db929039956daed61e9747c13f0cb6c407d9a40773a",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"42fa2987e0eb37f9",
"15284a42f302a6b8368a4f2dc16f534d1e5db9d0b86659fc4ba6f16c98277411",
"747c4b57383a3765da33f381d978986dc4efcb4cfd029dfcbd94b0a558399c92",
"b904af599e6e8b21cd803a759bb5680021b957b01a69597bc585e3d82426261e74b53f8241d12e3ef16fcd3395a944a2",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"5b65cdf19fb4c2a1",
"f46c5a01642456dea03af792fb0448d1ea7486b2b8f777b37b9cfcfd4679eaea",
"ebe41d702ebfdd862f335bb8d1e5bd687ee6e0cf1cd8ed423c532db394871e7a",
"8094a01f5516f2fe2359dc7970bf62c89d0fbe11cc35eeb9c7a7e9df59521f4a7dd86c5ed1aa4d60669beabb20ef3b0f",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"dc2d1a6737d445c6",
"1bd78eda13c296a2527b444a8c79860ed806ccb6b43825234922a428f14b099b",
"6383d57ca20ab5bb85c3aac007cb28c2d32fdc45adba34910e0c21620eec1ce1",
"b5a759feb76b6f775373d1c8960f920f6d500db30d107137be792e2db8bc4042287a30f44031104ed5b54de5e59b0701",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"4b1644bf2f688d5d",
"9ab8282c1997c009cfca63aa8afce22e405c8158f3f1fa87d72dc4e8b7c694ea",
"b0980c58eb81c031c30938d7e0c7fec4a12f091f60c12590f7809c5282a60f8a",
"ddb3fba7bb4db979fd6d8c8906976df319aaf0264d4f2631aebed7d824bcc8053277a05cffd55626965eec2393952a1c",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"7de8937eeb45c746",
"6871e3584c6a4e5abdec8aa03bc835236474fbaf67b1aca2bc6c92f113e2016b",
"39b3a49f7607c62a4c6d249f7b6db668df48515bff37d327e4f4a1f2277b5340",
"6b0f173341bd75f6cf0cb8f006d1800b98c39e7c9e1511425d1f648a665381447140c8ce87ff9af21a46a5e054237037",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"e8d6eef137e60513",
"4f0f198a3ef7795f1c879108950891c082394ae462f544b308110a529184c912",
"d4fcab5b87fca3ca71db7069c4956b394b5565dcf3e945a88b73f2fac86274cc",
"349f99eefaefbc39959d530ccb304261091b039001c7365ef0a839783a0318f3b0718e7060457bd80be386f0acfe82ab",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"ee90b9801588cc9b",
"1e64414c3b685fb1084b1c90687115a28473564f6c2a1f680109e81812b0a218",
"10524a5da012fab3a81fa96d6d396176fbcb30b86b2088ea62d3e6a9da87b2cb",
"80d8d07529f050c01089799773a83de1119799756447b38fb5055d1de26dd1096ade17577dea623aeefe1c10002b04ef",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"66534092bd8544f4",
"d7f7794034efad93af61e6798d579bda288e200e87c1d442312a9d1e434791a5",
"c8c7d8a6a7175df65d49104a5c9497bd2af6485f65294acc04d3f704dffd8576",
"d7ecadd1f62d4ac16b0ccff5618c10af12f86754cd9e12d9072956e7aef135fb0e112f665656bd7ed60f88535d77bcef",
},
{
"f47bcf4dd6dfc931f65df203d3096585fcc6c6dad3fe26df",
"3834278dcd277566",
"8943277315502b2ce33f98749c9d1860d24f510ff8800a3ab2de8f0d50065735",
"55a902679cc03c7963b5bb261c8988223e200a0a82a3d6ea5222c8027e7e53ca",
"a91ec46746140fbd34a25a8dd7d81d47b2dd288e2e4ec452e1564e3e6d6e8170016278410c96383fd17e5d55f5af1856",
},
/* [Nlen = 9] */
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"f12ed47ea00bc64b8e",
"0899bdbab4642e322e8e2527ff4c9809e53453c72643eaef2524f21633af707a",
"a30880d0ace348acba0d0ed21ea443816706a216ce9eb682d1fe9dfc1d2e0bf3",
"5e9ef19f62f43142e36ed114d5a0e0304482570fd2b6c7dd304a3e44e31d49cf075e3dbafb5371793e68548a1780d1a3",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"76b2372a3def0a521e",
"2f5cb72cab4522bad7855970e120a095caa1a8246d0bb266bd12f7c64e8b48e2",
"a4fcbae5216136a86fef64dbe1c1bda15741d6cfaaf8e1584aa47709258b9576",
"197425115001253cd8cdb80a97a6c4b3ec727e2dc12aa4c4f223cbf9b5e3dc445a08bfb6fe19263de61e45bc1d3d0054",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"a824e5b4fe31d9ca28",
"8fbb3b64dccb6ce941fcf53eb97238c863e1e8ff25a2cc229606bf291beafcfb",
"3238a35afdb2e8b6af85ee63a3f6f96d470612851699a049c6d738c5c2d3b639",
"f625ba9bf3cf33361d4874331289f617af03bd13dd4ed2a86f9d582998c75efb471d23824f725e5f853c9825cd4e82fd",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"c853ddb10fd884568f",
"491e233b69aee4e4ebf4ec7c4e864a6bb016b5133647184baebf4e0f737d2975",
"2b744ae723e527f92c4cb743aa062b3a066ad5ffb1b744ef664ab176b0159a23",
"52f959a39285aaaf52eea87e9f3f3ef6fe7e53f61e48e3cbe7c68e7985328b44e9eb44af50aa2008236641d9c107a94b",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"96b4cb637179bd0b40",
"6547be74ace4cdd03d852f1f39162d4e6c8412537f22f6b66f4ad5503e47e453",
"bb88780dcc071fecf8688f28e20fa8f18d479b84cbe4fdf4f8271b2ae7e18e2a",
"6b13ceaf1221c6f01ddb06e806a2c375f7fb8b07752cc3a695cd9b91a64abc6d31f4d4be24fddca29648fb3ba3c42f1f",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"8ceec383fc191a40be",
"12fc2b45b518076675affd910edeca5f41ac64c1cc358b449909a19436cfbb3f",
"143ca4fcb5f9d3880b4d192b05f88eac1c200d90948b92ecff11e67704517fe3",
"6202093982b0437d3056548a471a6cb3db81a9df6911af7e941146a97d4a1b2038bd2ebbbfbc49d0d1081692d448c153",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"8047efed47abd835a4",
"7cef720000375f2bee5b611987ae51d3fbae81f2cedb421380caaa866d759446",
"f7be35588a983109c926e60f85c6c765dde9168f58d09f7e3194a5b4f2691da8",
"72ff99293af2c59c0213dfe33f6022dba6556cba79835dd8bb8fa8469daa102a4fba74f581df332cc217233c04b5a87d",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"00a513249546562f33",
"07f0c92c2ce5ff9418f39e94bf4ce7fcfc7128723344831f3565f0a863bb8560",
"6c4cd08b788554b610b714b2a49faa443748c8dfc1dac418d2b2545a79b896db",
"b9965866ac442a537b181d867327563bb4399b5383fbd9685faf3c23b1fc1ce6c684f723f328fb4d295f13d92c1fb083",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"df6aa0eafbedd559c4",
"18753e31a1e607c55aa2653c85b0cf7e7cd099e348bc239870af50450f2439ec",
"474fb245c645b5d2a16d51fe58d7a976b6b182f555baed5d64fa2706a8b1bd56",
"5d3feda96413f766c9bd50e745531ff02993ab9aa4d86f878f90c69e21c727c5a83e9657db116ee0002241ed240f2576",
},
{
"00882a86d723302a0f593c3b7a7de5487d31d1aa212a7164",
"e41ed1c91a2ae03b29",
"99cd82e001e0ac7a2ac2388a28820245e7b0724a1e7b08e37f173887316279a4",
"92e75a6119b50b3b02d747da6d03c0b640913d0e12d29ada48a30f017d42b5cc",
"03b12ba58c217502ccd06982c61702159b23fb177f30973b43a9512c7e55ee76df870dcf5923b7607ee481844c64482b",
},
/* [Nlen = 10] */
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"c9ef4f2860657d30d2a9",
"dafe0e1646110abfb3d1faa03afe6ca36bfa0a56efda639b6cbdeea1a95c4b12",
"6a1cca20ea5efbe7d03cf389848a03aa6e276138148c6d9d82a43939efdf490f",
"2474c413a1340a0634d82a9a9d7315d10b81e960255cad533153e8855676da90831e590144f2de3db886e3a7e3c96751",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"eabaaddab2bbe0e3f328",
"0b1315731a14c971109b347098bbeb3d94dd889f0310ab4428a03ffce9eaff25",
"a6d10b5dd8bdfe9f00bfd0e24ed1e112cc69256a9fa883418ad47a27b3080a30",
"de021dfa409ab5b65983354fb4be0648f5d74c0ac812238c7e5a51edc21c145a160052d09bac87ae0e0250340f8f6f41",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"93924024dcfc77689b5d",
"272c3c60ec903f0b0d097ba1ac47b26c3ef9a5b731e3d983d2319b7b6f0b422a",
"aaefa94e940fe9ebe2f7ff82d923850f0f25d752da47258b0872c683d04ecfcb",
"626a0b916bff03b07b745a44ffc352d0c1159c222d5d63f798583d76dc7848510e0ee0ef9ade7ce0e1c1575bcc239989",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"5fbb4ae99b83be69c645",
"2aae6dbbde44d256f19f46ad14fb247da394c68cd70e53333d15d81966419b41",
"3dfbb226ae5cae186aaf5f41782d3036a7b980a47f0b3e93770db6ec6985aa39",
"5eff0c3e67b57b4e744cde89e7a100e065e2db916b5aa247f6539584b8c0b10bf08abfac5fbd4621605883a044619ca3",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"9ed6ccfd5cd74c2ef6c2",
"7611d86bede5f880928b878c84b446dd264d40e27e524f9bdbe3e34ebb99ff7c",
"87e9737a64d858f4b9caed3344977aee28e7d53490482915957ef79f621a5a0c",
"e2d9470c0e1f9a6c3eac5872c84c2da73f249cf7eaa1550507edf3138818488ee6ddef68e71b30a141857c88fbfce935",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"441eadda381f5b0361f2",
"5d37255a6e08ee8f5fc53c4e6527faa5e942fde97ea994f715d961bf74d56704",
"e25dda054b1804b5f337a039a5abeaaaa5f66c3ce58fcfc37b88f276536e39f3",
"45557eda718697539a058db55ea3252c93609d6a896a71096004c5319ff31a6e4db6f96da7679d31fc22c1751ed44ead",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"111186f99e62f3d7d0a7",
"0075c3062aa18047374c55933fb7c663a05db91dfee192a088469c1d7d5eab2a",
"0920d57742f9f93c9c2ed482877ff2358a63c1982b57983a1376f7276e4a115b",
"e738b2fe238312c04921466ff9e4cf968fac7d637d9a94919484ced055cfa12bcf2783322901e181ecbf0121e1d0327b",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"5b5459ab08a891ad417c",
"bb7224396cadd354e330cf0eeda6ec78aac4dc11eb1ead39df4093e8effae89f",
"740d30f068497869461040f638b22eef3fff604f83505dcde8c74b48e1d76368",
"27651a951f4943cd663f04cc76c583ea2bd60631eef7445115c91459cfb0240ffe641dae3c2fab08850fd8f9bea12aec",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"bd8734415226840cfa4e",
"9e3180ea59f49da72ca16712ca6d51aa447419fe8058e570e82b92395f8f49ad",
"772bd4bbd2dbc32ff33d8e3bc51f1a43f01ee0e859199324e7e602968d43411a",
"640e837c4e62353b7c86dd71c8083f8ae6d5f0396f16c53283bdd5c75a3c5dc77495b25f73247d792537361fea352cd0",
},
{
"9373588cf98791c2f016c5c160ba388dd031be78d703d0e8",
"50d6f5b68499ce035734",
"bc1e0bfc2ff33e827bb642d990679eb75e08decbe75f43a098f7b9c5d968092b",
"fea36b9d5c4e555af45bf5693783ec7a64191098ab9db35c938f2960998184f7",
"68c907f7fb71ab4e6b88da832a0cfe9f30a1a788db2f49d6f973cb322d2b97d446a80f197a9c6961cfe9cb5e92c8fa34",
},
/*[Nlen = 11]*/
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"d3284d1de51559c1ddbfe6",
"21214ac2314fdfe07bc4d066245a97b1a10470df2a6d6b926cdcbff07f5b61ef",
"88a5c1c2ae4eb463a3283dc5c81f665b0f6d54495f6cc9d43aa8ee179d3950f8",
"65ed1e3919d208e9e5267370b9cf9b1431ef0c584dd2cf057d243a03523ca7562a18840cac2199030c008741d74fb220",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"50f7d182a3d5f0388465e4",
"6389bbe519992fd98a97842ecc4d2b2569328c10bd3d93c09ffb6b4044e089c4",
"68e9cca19882c4b0c817d0645a97f74016b3f0ac133829eadb9c0e4bcad687a3",
"72836a9a3c196e6c6e49b9a7808297d1bc2f0f02f018bb5418a4264215a9cadf691d71c18798554efcc028599a7d1e21",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"4535bcd6693c8afd857a5e",
"8e5018061b35089881ef5970d886fc8ac267c0499ec12404fe3069c15b99ec40",
"231291a36b06914eadbc393884b610a1c6becb33fe8567d01d8b748e6c3eb400",
"e55487389e1ab4c99a7145e1fa5237f9d803117e01890c3e3c54a14d6e3bbe68bb7b0ea88d8ddffb0ea9ee2b75872d1c",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"4517cd58232cc31e1ba95f",
"1e871638d2b6e10df1bceae5d21eed9caec77e845fb5f0b867f376ad34c7880a",
"2d8766b4f4e95bc347b5ee6973107c2455785889785b117d7de2f4a8c00ed227",
"e295fcb816dcf81291ce3fce5fa5d867401ef4158f393d3cc9ca04b3ac7d3568962fa8626e47a2e1ac4b0cdec47d210c",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"e393c6d850cdd8a238869b",
"eec5f00cd1685d0086d2bf38003e34ece7bc5ec9858363e7e38838fa2f5020cc",
"1dc7da9bd467e8e9c933c1e194f3639dc1915989d315df0288d346235fe39adb",
"633bef71c033a43ba305246ec34a68fd86a29977494b765ba70ea8e6df0eae33846ba9679400ba421008b581b7314593",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"d8d4a45a774f6d9641bb0d",
"bc3de7d3028be3759c7c0f31ef3511e1f90afd1c86e427b8a7e6368d60507a7c",
"2b754401c14946c16dc1ad5e5be7ac53eb2b41b2b5585cbbcbc643ad3dd235dc",
"bf7ee1f5fe24572994fc91d8b2ae75b8be80d0449d6ca7f8593baa2b88de49da10401930b06a7898f35bf53cbde4e3e6",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"19fc5cd49218b40787cc1e",
"a6339fd2c47a285df5b3568d7738e7b79b255af36b69afce8f1d6e3f7215eadd",
"3fedf9020e651e2623dcd3f432878ddd76057929a2890f3e1b3aea1f64dad733",
"d55e542a40f7c1b298701507bd3bc7d646d983de0d11502aec634c9cb0727bed4699d97c79d53a734f6258b8a2ea0737",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"b2cdfe1152d27457c7e23d",
"894fa88b4c4260f0b678a5ae11e234e21920b9d10b468acf00e195607935989c",
"d0341fc78075ac77b25db939ed65b25e90847fba71454f55c51c946340fa4e77",
"e81d0bdc89aa9719d87a6975ba500812d9eb093f0b5abe5c8bb2c3c603a741752ce8758f9662260b4a6d00fc467fbb0f",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"6cae6ae0eb301e4c4a6aaf",
"fba1bc359b69b3ab6f8aafcff65f395d0c1e39e904a2aec6f66da2275aed5e84",
"78f69d35f0a8732af14ae2236fcca34a043633733fa4cb443e8e92997f4d1226",
"bf3dc2bbb9cbe36f9ce619ae4721549e8fe280ba05cfdcbe8c191edfefb09df5ec5ca0d11b3fdbb7f4ec7680749316f2",
},
{
"7a182e4e3367194662d614bb11da11e86596f724204f48ff",
"a2cbb47a933bdcda307443",
"c6e30dfc1c654173b8caa0edc85ed6b1883c244f5812118312245c5b9a94349c",
"adc4b5f4f7dbd5a3fae2cecc7e953f23bb59c269be1772df0e4aaa0090570f6f",
"688563debce4715ea15619a457f3fca674e9001af716eb9fc2a30c6137396619d73aada4fc594b8faebfa8d6545d050f",
},
/*[Nlen = 12]*/
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"03a7c18b562bf8deb83b6cd7",
"ce9305db85f975e59d4bef697caa202f5db2406347a5a0e03bc582aeb2012ec8",
"f51548a98a07a343f84a7441ede47af7b9f71cb9b096f54fcfd790a3a32a70bd",
"6a4feb2bca5ae8f0c9fb4daecd5eda927f585d0ea0e874f3f08ae022e2b2785fb96476c9bf71ab81b729e6c26f83cdd8",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"55d958658e53b33aa594a296",
"74ef4752ab26526421ff55f4e3a6d83fc5ed7b319ca6d3e0ae50745a67f74fa0",
"4d7c7faf9fc2373261e3de53f28effca41cb11819a81eb3ebf3b7e833b2bc2b3",
"5bd210439881e2de918c4b28b819baa919fe6126cbc01e1bb3235ab1fb4c0c0453dc91319689c43bc9a2fa98e6815c4a",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"cadaef93f02cf0e633f232ac",
"245ed145f6686f738e78ffc9b8b45acdb2f7404aeb8142a20aeddf643264ee21",
"21e08c3eb78d78dee70c0d2f0ba3854f530bc65a02d23ae9dafedbd8d4f38d4d",
"a23fac896d3635dafbfa4f4b4fd549b5d55490740d885da6e59a2bfff0c30d3f82aa16ab2d6c3bd8d9c1524db6040f80",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"9d0523fb4f6ac2ef38a18d7f",
"77fb8a7def268d213bded056de6b094c5e0914bc9aebe7145e80c8d435f5be38",
"3411e12667e74c637d8032dccbaabb71c3de0906c8c6b22940fc74f4ea152435",
"734b0fe2d042b9afd4f080f238506d9e9b07a981cd098ecaa35f85d7bb037790f2e7b537346745fd80f757da2cc8d8b9",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"816e6674daa639cf93628f6c",
"9d7a181060bafbb6c0e2e60db26983e9495eae817252ce73e17166094bf2e7bb",
"740e30ea8e9b370acc464ad692b012a7e991fd80d2b53239db45caddef483d50",
"40679702ab73460d5b00d72cc07337fc16aec8107183c922a773aa69f1dcbb00316c7eb896e5f5f2381f9ed09c7a8d5d",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"548c19c403f1d514c5d8dc05",
"25893bfaea7dcb3d85c2f7068204ccff73db8d2ae4f14d239166bca6d6734250",
"413ce125f811bdc2c9ded53a58880a3f9ef931a13a210871083a6e66f551d37f",
"8070c48fad2fe395c1c66fd6c822e789c981fe1659f4d03a3c1cb5143731e874a11f4f911b111c43b88dab925bac2949",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"8c3ff652e895f396a7fb1865",
"b52867514d1f8a16bae842f255c5dbd6e0c538e775e967cabc86781f61ea904b",
"35771d17d740f537bfeeff1d4012d80379e81d238e89d1843961ff1382e4a0f5",
"a7436f9a247d463d1445049cc76b9461d5c629c2c48e895af4641d843434e2791dad43b55cdbf4b64876f5911477a5da",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"ddd900231f6d7094d091a458",
"1cfe0b3b53fe56b60c9c63159b265bae933a72b1f12bbeae96a64957fb966588",
"798f1d78066d2f75b2c16e45d8c736a3dba71ca0179b82e7185369450a998669",
"f902c437e165eaef6eee8bba4d2f3c5ab60c1672469f7de7bd374159bdf7567b2b6ce9ae12767bb82a3723cb91478514",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"99e0ea60ae625c5c01cf1f32",
"09521faf4b01edebdac29d48c831e7e3c6092af639ea19b7905ab07dd4096e25",
"cc9fd2a5976a27c22d29ad2662ab0aac32493e29b61033ab512294fe2b59e375",
"2d300a1d8c67f28a572ca7e39785fbdc2c60202f84dd51bb3cffdd91fab1cbe74a498a13589c4f971f1268ec16bc8fbc",
},
{
"7df900e4fb6358603faa821c99316c2377fe1250d9609410",
"cc9fd8861f59c79b71e9c1eb",
"16810b018f04fb01644a181710b3d444a7d5f97768c2e0f7928de3007a0a14b1",
"b99ed3bcdaa3cafed8956ee8da93acbfde2d29a845d4e1bc928e0f5e6fef4ccc",
"fd206d33e390b3474a8cb7a4209f250e26b09fddda4a66f0834209b55d99bf7618181c6e1b295e9ae6298f4e515f7700",
},
/*[Nlen = 13] */
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"5505bc3520cc2ecbde5490eed0",
"0cad8ecfce3ca3841288b6adb29600af500fde7ee0a87ab466e1a8e001f20e20",
"2327e577cb61dde6c3f3f952791fcc19a9428ba6de4bb78b3671fcd065265a8b",
"0c7fcff1ac10fcceb2ad22a67fbbc82a18e9db10aaff2943415a50e3e799c21e806dad9763d663454ec817d55514f4ad",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"34f2f98e847266bcd2393df91c",
"b43141edff7640c341a709977e07df6a4049c0178dadf591166de76cb157349f",
"e3a4343e5feb69bdcf1f8c5c13273173fb2c3188c1084c65d7fb136ee3a00632",
"9571600e05ab55b0c538b13950402a4081567cda9e5e0ff5beebfd607c9cb6661c0403cee633fc2a2763f505d3acc8ad",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"d30484fd13009bd672642c2c93",
"8da5314358ee9d6ae869e5a635c64a4b0e23bd8fa2818d9c457943e4712bcbb5",
"6a9b4833933e4baaea41633603fc5fffb7f579dfc7f72317c164044028cb3d84",
"70b8afcc6058ff09ffc7108f92c416382b908f779e9b56b0161cc39a6dacec4700e6ed1a00db4ae2a20c71d6f7b8c9ab",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"7d661c577faf991ac76220e686",
"33e291022295351c07966b1295d62b93168aa98c0d381fe41a12cc6a1f843c0c",
"cea086ede13f694af6ba07854bec21684f154657a9d0f6e17c460795e9a24817",
"f4a80835b2550609a371a01043f0766465cc62012ecf26638e9884331c26c0052c2332ce29d16288d55bf922116f90db",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"31a40b85382ae6e86ead31cea7",
"062f94769132e8a8aff67f75cf41dde4297a97c4a3045a9df1ca2ee6011bfc78",
"1c22d46100c05600f1c213bf0e964f22de7ed51a9c93e929d2097dc62ab4a803",
"72ae4a7a8b68261511be0c862a0b77bbad1f049869d342d92523cbef8fd2bfeacc6e9830151a7a90d8c3f130019684e2",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"277882e2fee1be0a328556f788",
"ad786f72e48a57a4d567f476a17a91580b4f1cd38657d86d92e552cd497d961f",
"655633c01e9f402393a92991111b4b017ed6537b9a29a6e28544001282f05a2b",
"ae61ed144730be2f4f43abffab22d03626fb455111b1634dc6e6f46958dcecfed3abbe4b48a088865240075467ea9176",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"716194e0828089556a307dad06",
"eccdc9a883bf13ad0e9185dd28813881483fe6f99d48f1ad3d6fa7477fbcc420",
"77ea1c17df08fc06a446dfca55866b7f66f667e27b43201ce40a0bdb6390aba7",
"e639b904e10091c37f1feb2b6c2fd0a42fdc3537129ef9c550f7c6f03b0b0700477caa53e0871048afcc2d80ea5a8094",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"3972ecfc8433ff00fd75752d0a",
"2d97dafa8bf68cb7220df3bca5127e8f115c36e2e2c89716865b9eff122923e7",
"971fedbc5761e0fd87377445eaa0b93132dffbaf2bda977937c00ddcfaee57be",
"208ba224bf1364dfca00d2fb71910e98625593b9612cabf68444222087d9913a3572187edc07a5117a1c51f2da49b405",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"81bca5108b5bd595f9535fdeaa",
"c1d042c1afce2b9c9fc62e0e182fb7628bc467483ad814cb52e911845a77af0d",
"b43ebc1fd3cc954f55550deda42c7c056ddb958ca4148df2c8eb80f6684310be",
"12fda5c6b5b995a9c3609ae2bb9aa56d7d1609e0b6d0d3511fdd5502fe6bf5b580189897fba01b90014d1eee1939ffc3",
},
{
"efddf921a0eaaac0ebd0e49238e7ebd8909ec39ca76f4d45",
"9f08cb7caeb48365fde6c934e8",
"8816ca830bc65074ee3fbde1c98a89b4ef7bc9fa4635a58d56ec0cf19fefa77d",
"815ff22868ecc67b3e3f94fb44dfd703f5b1f438f419cbc944628bf5b760cace",
"ad3ec557a06fb74a6d17e555e75237f49c79cc8bdedb7a2983da2db6c2b14a067f2df52f55733d984dd29607546738e2",
}
};


int aes_ccm_test_fips_vectors()
{
    MSTATUS status;
    ubyte4 i, retVal = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for ( i = 0; i < (sizeof(gFIPSVectors)/ sizeof(gFIPSVectors[0])); ++i)
    {
        sbyte4 resCmp;
        ubyte* adata = 0;
        ubyte* payload = 0;
        ubyte* nonce = 0;
        ubyte* key = 0;
        ubyte* result = 0;
        ubyte* copy = 0;
        ubyte4 adataLen, payloadLen, nonceLen, keyLen, resultLen; 

        adataLen = UNITTEST_UTILS_str_to_byteStr( gFIPSVectors[i].adata, &adata);
        payloadLen = UNITTEST_UTILS_str_to_byteStr( gFIPSVectors[i].payload, &payload);
        nonceLen = UNITTEST_UTILS_str_to_byteStr( gFIPSVectors[i].nonce, &nonce);
        keyLen = UNITTEST_UTILS_str_to_byteStr( gFIPSVectors[i].key, &key);
        resultLen = UNITTEST_UTILS_str_to_byteStr( gFIPSVectors[i].result, &result);
        /* do test */
        /* encrypt in place so copy */
        copy = MALLOC( resultLen);
        DIGI_MEMCPY( copy, payload, payloadLen);

        status = AESCCM_encrypt(MOC_SYM(hwAccelCtx) resultLen - payloadLen,  /* tagLen */
                                 15 - nonceLen, 
                                 key, keyLen, 
                                 nonce, copy, payloadLen, 
                                 adata, adataLen, copy + payloadLen);

       retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( copy, result, resultLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        /* decryption now --> decrypt what we just encrypted */
        status = AESCCM_decrypt(MOC_SYM(hwAccelCtx) resultLen - payloadLen, /* tagLen */ 
                    15 - nonceLen, key, keyLen, nonce,
                    copy, payloadLen, adata, adataLen, copy + payloadLen);

        retVal += UNITTEST_STATUS(i, status);

        DIGI_MEMCMP( copy, payload, payloadLen, &resCmp);
        retVal += UNITTEST_INT(i, resCmp,0);

        FREE(copy);
        FREE(adata);
        FREE(payload);
        FREE(nonce);
        FREE(key);
        FREE(result);

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

