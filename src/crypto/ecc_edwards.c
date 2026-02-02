/*
 * ecc_edwards.c
 *
 * Edward's (and Montgomery) Form Elliptic Curve Arithmetic
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

/*
 The methods in this file do arithmetic on two elliptic curves of the form
 
 ax^2 + y^2 = 1 + dx^2y^2
 
 Note this is a degree 4 equation, but after blowing up singularities, provided
 d is not a square mod p, this becomes an elliptic curve with identity (0,1).
 This is Edward's form. In addition, the two curve's we use contain a large cyclic
 group with no points on the line at infinity (so the formulas for point arithmetic
 are complete as is).
 
 The first curve is curve25519 which is over the field with p = 2^255-19 elements.
 a = -1 and d is given in the code below. When doing arithmetic on the curve we use
 projective coordinates (X,Y,Z,T) with an auxiliary coordinate T (so that modular
 inverses are not needed). We have methods to convert an affine point (x,y) in an
 encoded form to or from projective form. The encoded form is a 256 bit string,
 ie 32 bytes, for which the first 255 bits represent y in little endian bytes.
 The last bit, ie most significant bit of the 32nd byte, is the least significant
 bit of the x coordinate.
 
 The second curve is curve448 (also known as X448) which is over the field with
 p = 2^448 - 2^224 - 1 elements. This curve has a = 1 and d is given in the code.
 We use projective form coordinates (X,Y,Z). The encoding of an affine point (x,y)
 is a 456 bit (57 byte) string whose first 448 bits represent y in Little Endian
 bytewise form. The most significant bit of the 57th byte represents x, ie is the
 least significant bit of the x coordinate.
 
 The arithmetical operations described here for both curves are in...
 
 https://tools.ietf.org/pdf/rfc8032.pdf
 
 but IMPORTANT NOTE about the encodings: We use what spelled out in the curve25519
 and curve448 specific sections 5.1.2 and 5.2.2. We do not make encodings Little
 Endian bitwise, or encode x coordinates by using the "sign" of x, as in sections 2
 and 3.1. (yes, the paper is inconsistent).
 
 Another IMORTANT NOTE: The CURVE25519_X25519 and CURVE448_X448 methods are
 actually not Edward's form formulas but Montgomery form formulas. These are from
 
 https://tools.ietf.org/pdf/rfc7748.pdf
 
 and are used only for Diffie-Hellman.
 */

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_ECC__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
#include "../common/mrtos.h"
#endif

#include "../crypto/ecc_edwards.h"

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

/* 2 in Finite Field Form */
static const sbyte4 pTwo_25519[MOC_NUM_25519_UNITS] =
{
    0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

/* the Edward's form curve equation's d (Little endian words) */
static const sbyte4 pD_25519[MOC_NUM_25519_UNITS] =
{
    0x035978a3, 0x00d37284, 0x03156ebd, 0x006a0a0e, 0x0001c029,
    0x0179e898, 0x03a03cbb, 0x01ce7198, 0x02e2b6ff, 0x01480db3
};

/* 2d */
static const sbyte4 pTwoD_25519[MOC_NUM_25519_UNITS] =
{
    0x02b2f159, 0x01a6e509, 0x022add7a, 0x00d4141d, 0x00038052,
    0x00f3d130, 0x03407977, 0x019ce331, 0x01c56dff, 0x00901b67
};

/* sqrt(-1), ie 2^((p-1)/4). */
static const sbyte4 pSqrtNegOne_25519[MOC_NUM_25519_UNITS] =
{
    0x020ea0b0,0x00186c9d2,0x008f189d,0x0035697f,0x00bd0c60,
    0x01fbd7a7,0x002804c9e,0x01e16569,0x0004fc1d,0x00ae0c92
};

#ifdef MOCANA_ECC_25519_WIN_SIZE
#undef MOCANA_ECC_25519_WIN_SIZE
#endif

#define MOCANA_ECC_25519_WIN_SIZE 5
#define MOCANA_ECC_25519_COMB_SIZE (1<<MOCANA_ECC_25519_WIN_SIZE)
#define MOCANA_ECC_25519_COMB_D ((254 + MOCANA_ECC_25519_WIN_SIZE)/MOCANA_ECC_25519_WIN_SIZE)  /* ceil(255/win size) */

/* pre-computed comb table for the large cyclic group generator B */
static const projPoint25519 gpComb_25519[MOCANA_ECC_25519_COMB_SIZE] =
{
    {
        {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}
    },
    {
        {0x0325d51a,0x018b5823,0x00f6592a,0x0104a92d,0x01a4b31d,0x01d6dc5c,0x027118fe,0x007fd814,0x013cd6e5,0x0085a4db},
        {0x02666658,0x01999999,0x00cccccc,0x01333333,0x01999999,0x00666666,0x03333333,0x00cccccc,0x02666666,0x01999999},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x01b7dda3,0x01a2ace9,0x025eadbb,0x0003ba8a,0x0083c27e,0x00abe37d,0x01274732,0x00ccacdd,0x00fd78b7,0x019e1d7c}
    },
    {
        {0xffccbfe4,0x00746063,0xfd62e1d9,0xffbb8a1c,0x01c74d65,0xfe447086,0xfe1aaa0a,0xfe86ea98,0xfce3b1c7,0xff1f54ac},
        {0xff9bc2d6,0x00cd6043,0x0188bbd0,0xfef3c91b,0x00278d7b,0x0075afb0,0xff21a00e,0xffe618bf,0x01e0315b,0xfe6d912c},
        {0x00f94835,0x00f8c61d,0x02c4d783,0x000c0d2c,0xfe4cc9f3,0x00f1d999,0xfcf68408,0xfe434f38,0x00cd4b31,0x01541236},
        {0xfcab13a0,0x009a8200,0x0032a511,0xfe26ec10,0x03ae75a1,0x015a72ff,0x0071e2b4,0x00914b4b,0x03e7963a,0xff8d63c7}
    },
    {
        {0x0172dc52,0x01ffb0ba,0x031e0dda,0x01466583,0xfdd24680,0x001a5093,0x01aa8f24,0xfedff9e3,0x0036b8c1,0x01db3b55},
        {0xfe2b8d41,0xff7fd756,0xfee4752c,0xfe80fd0e,0xfdda8e56,0x003e0f56,0xfda727c9,0xffe77836,0xffb32df7,0xff8250fc},
        {0xfc146aaa,0xff28b1d3,0xfd1b05ee,0x01d1467c,0xfcee0137,0xff765c53,0xfd4d053e,0x0136e92b,0xfe09df0f,0xff9af79a},
        {0x013340bc,0x00e39b4d,0x03789e0d,0x01efca64,0x02c6aaa5,0xffcbe77b,0xffd5b5f6,0x00584db9,0x0291059f,0x013d9e9d}
    },
    {
        {0x001745f1,0xfe6ce021,0x0214eab8,0x013e10c2,0x01530c52,0xff466da3,0x029c4f3f,0x00120ad9,0x033ac804,0x01dea40e},
        {0xfca16883,0xff91e08b,0xfd0f8f6a,0xff484c18,0x00fd7742,0xffe5e5da,0xfc73fe3a,0xfe712625,0xfc1a173d,0xfebf544a},
        {0x02fe886b,0x00154d77,0xfcef8735,0xff7b5f55,0x0294e757,0xfed8fbb9,0x015b4406,0xfea4d1d5,0xfd8fcdda,0x0053caf2},
        {0x0081f501,0x015e53a1,0x006a3fa3,0x01956e2e,0x0278a501,0x007c52a3,0x03db61be,0x0101f162,0x0322ce06,0x01a476ee}
    },
    {
        {0xfe6e6516,0x00ce5f44,0x01985e40,0x01a19bde,0x03ed1393,0xff089aef,0xfd212f6c,0x010057f2,0x02dd70d1,0xfecd95a5},
        {0xfd949f26,0xfe1f611c,0xfec5f867,0xfe54b3c3,0xfde0e17c,0xffbda0b1,0xfdfe71a4,0xfef72e3b,0xfd911954,0xfe86c994},
        {0xfe1742c6,0xfe902c47,0xfe47d1b0,0xfe46b7f3,0xff60fb20,0xfeaa62e3,0xff953d50,0xffd4f3f2,0xfda376d9,0xfe3992dd},
        {0x02e8afce,0xfef9971c,0xfe035520,0x01bc618f,0xfd1a4bf1,0xfe8126a1,0xfdcd65cc,0xfe7ca8bd,0x00876c7e,0x01a6cca2}
    },
    {
        {0xfc57b0c2,0xfef0076a,0xfe00753d,0xfe09b8e9,0xfe8e3f5b,0xffe82c07,0xfe2fac63,0x018e6efb,0xfe3b67fb,0xfe7872e1},
        {0xfd65d043,0x004abf78,0x01b148eb,0xff6d75fc,0xfca8eba9,0xfe8ba03b,0xfcc20ddf,0xfe91a105,0xfc1cb818,0xfefc4d7b},
        {0xfc098ebc,0xffbbca77,0x01d5d93f,0x01e741ae,0xfc94b4df,0xfe80c520,0xfc8f63fd,0xfebb34de,0xfeab93c8,0xfe5e7cda},
        {0xfdc8b095,0xff3754a4,0xfdf263e2,0xfecbe6bb,0xfe312299,0xfe705c7b,0xff09d6b3,0x007796ea,0xff5b8cd5,0xffb6ca00}
    },
    {
        {0x03f04d36,0x00331a9b,0x023f2408,0x01bdd2cb,0x02775e0d,0x00024fbb,0xfc1bc408,0x007a8f9b,0x002fd3a7,0x01ed96f2},
        {0x017ca902,0x000ba6af,0x002928a7,0x008ed977,0x0221aa13,0x00f05ae5,0xfd99c114,0x000ef0c3,0xfc37fd6c,0x01f66a6c},
        {0xfdf5c3fd,0xff3d3d7e,0xfc6e4058,0x015837f8,0xff6a0df7,0xfe3d6504,0x034a14f2,0xfea0be97,0xff1a779d,0xfec4e82d},
        {0xfe2b5787,0xfee1fc80,0x0385cb8e,0xff5c0fcf,0xfc1be0a9,0xfe475a7f,0x0157fb1a,0xfeeaa80c,0x01b464e8,0xffc12297}
    },
    {
        {0xfe7835d9,0xfeda934c,0xfe711966,0x00898930,0x02d68c47,0x00ce495c,0x023c1bef,0x01836873,0x00bf29bb,0xff24f354},
        {0xfcd96bd1,0xfe061b56,0xff5838d4,0xfe20de00,0x020c37c5,0xff7e8e3b,0xffa5e5ca,0x00905992,0x0068bfcb,0xff197823},
        {0xfdf04430,0x01d28947,0xfdb981cd,0xffe41b3b,0x01ca35af,0x00562cc8,0xfe806035,0x003871c1,0x0016dbd4,0xfedfc7ef},
        {0xfed201bc,0xff412a0d,0xfc85e37d,0x01276eec,0x03954125,0x0198c96b,0x03395210,0x00560f5a,0xfd06c49d,0xfe90f864}
    },
    {
        {0x01790b71,0x00920e50,0xfe4d049c,0x004fb8c6,0x0157dbf2,0x0194e889,0xfdd41b2a,0xff7f586a,0x02bd17a8,0x00a65c5a},
        {0x034605d8,0xfefa51b6,0xfe3442ec,0x00c566c4,0x02b31133,0x016a970f,0x01a890cb,0x01e97871,0x01adcefe,0x01f472f9},
        {0xfcadc079,0x00d544fa,0x03a09679,0xffbb0814,0xfe8064bd,0xfe710a6f,0xfe6cb99e,0xfe7355f2,0xfc97e8b4,0xff12b386},
        {0xffefc618,0xfec61944,0xfc955e91,0xff8ac716,0xfcc1afe7,0x0135de19,0x007ef26c,0x00378fd6,0x0312a641,0xfe023575}
    },
    {
        {0xfef87d79,0x019d8001,0x02b8dfa8,0xffe509e3,0xfec0cd65,0xfef92e6e,0xfeb67a03,0xfffb350b,0x00f39449,0xff578c43},
        {0xfffd01f0,0xff8ce71e,0xfe32d55e,0xfe0496e3,0xff42d9a6,0xfff73b4d,0xfc63d162,0x019b899d,0xffd8ce48,0xfed8ee9f},
        {0x019cb426,0x018d7294,0x03945750,0xffa7774a,0xfd537ad9,0x01107313,0xfc29532b,0xffcbe9f1,0x021d6dbf,0x01844aed},
        {0xfe870f69,0xfed82cd4,0xfc07d903,0xffc4998e,0xfe0b23a4,0xffe44302,0xfc196a71,0xff61a2e0,0xfd74ccc0,0xfe6688d6}
    },
    {
        {0x03376d21,0xfee34fc3,0x03617e05,0xff863f0d,0x03c0516d,0x0088d6a8,0x03efb176,0x00645201,0xfd4ae167,0x01359ad8},
        {0xff732650,0x009c94f0,0x03b246eb,0x00178793,0x02ad4df8,0xff14cf5f,0xfd0b45dd,0x00e78787,0xff3ec8e4,0xfe78d51f},
        {0xfdc8c5f1,0x00958b29,0x01154bf1,0xff0e8e83,0xfd178f0e,0x005f027c,0xff3a837e,0x00891f73,0xfc3e2316,0xff878501},
        {0xfc718fc6,0xfec9450d,0x03029115,0xfe2395c0,0xfd3cc249,0xff019e45,0x011acbd6,0xfec38055,0xfc6e163e,0xfe2519c1}
    },
    {
        {0xff285d2e,0xfe74cb97,0x029edfb6,0x013e0132,0xfc1b723c,0xff97ae27,0x02968b7a,0x00ee222b,0xfcf85b69,0xffad63f4},
        {0xffe9a292,0xff9cd153,0xff54c723,0xfed3ac50,0xfca766c8,0xffb7f2a0,0xfe57c8af,0x001eeb51,0xfcbf471c,0xff53d135},
        {0xfc3701a5,0x00eb9194,0x00a248ad,0x0163d48b,0x034713c9,0xfe36c2be,0xfc2ca7dd,0x005ecd0a,0x02f259ad,0xfe4506af},
        {0xfe218755,0xfe7e7185,0xfd471a0e,0xff4e1176,0xfd2a3331,0xff2c200f,0x034ef814,0xffa9910d,0x02fd28c5,0xff3891d6}
    },
    {
        {0xffd2d658,0xff7f125f,0xfc97c2de,0xffae22fd,0xff74e113,0xfe912384,0xfc46c9bf,0x00a8050f,0x00094e36,0xfe55be2c},
        {0x0108c161,0x01e7572a,0xffb6e5c1,0xfe0afdbf,0xfc5c5035,0xfe063261,0xfe4aef89,0x0199826f,0xfeb89d5e,0x00ee3d2b},
        {0x00518133,0xfe0cd7fa,0x0328369d,0xff29c9a5,0xfc5c7ecc,0xffea2bfd,0xfcdfcf1f,0xff91ab5e,0xfdf7f7d7,0x00ecd740},
        {0xfda3a82d,0xff595eae,0xfc333022,0xfe75cff8,0xfe1d00da,0xfecfd2ec,0xfeabe24b,0xfe5c805d,0x010c2763,0xfe7e4089}
    },
    {
        {0xfd84715f,0xfec56705,0xfca20b0a,0xffbca126,0x001c793f,0x00bca3b2,0x022ee23b,0x01e99695,0xfc3ad01d,0xfe436bcd},
        {0xfd194d64,0x0116a7a7,0x01ddc40d,0x0004ff07,0x024522ce,0xff8e9519,0x02c39cf2,0x00263775,0x03026dda,0xffd89a99},
        {0xfc33de90,0x01a12dc2,0x007007eb,0x00de2109,0x029612eb,0xff451229,0x03a783dd,0x01e92839,0xfda11177,0xfe569f66},
        {0xfe0ab17d,0xff4b3629,0x0210911f,0xfe71154c,0x00f08163,0x01f3676a,0x0099cc4c,0x00290971,0x0225daff,0xfe597b4e}
    },
    {
        {0x030b816e,0xfe943e65,0x026333de,0x01b2cca3,0xfd024843,0xffe9a441,0xfc59359c,0x005191e2,0x00faa491,0x01a3b47b},
        {0x02169114,0x0106cdb9,0x009ca4e4,0x01274f24,0xfeb9c37a,0xff097196,0xfe11a796,0xfed41553,0xfcb15945,0x010fb608},
        {0x00ac4faf,0x01451281,0x02239563,0xff353ca4,0x036bcad6,0xfea32667,0xfff7e5c4,0xff4a4eb1,0x031032ae,0x01e530af},
        {0xfedb11d5,0xfff19387,0xfed271e1,0xfedc8a9e,0xff0b08f8,0xff2bb931,0xfcecd19d,0xffe347f7,0xfef2d437,0xfeb6c9cc}
    },
    {
        {0xfd81a270,0xfe8ec6d0,0x004fae16,0xfe225991,0xfe2fbb44,0x01ed9049,0x02c5e03c,0x01fbb51d,0xfcbc164a,0xff347e4e},
        {0x0128afde,0x007360c3,0x0024156d,0x00ec97fb,0x039c13cc,0x010861db,0x03c8db9d,0x00564091,0x0208fd16,0x01a8de39},
        {0x02fe552a,0x01ff1976,0x02adc506,0x003e8851,0x0016347e,0xff0a0e3a,0x008896c3,0x007ac9aa,0x018a80e4,0x0199c288},
        {0x026ef03c,0x00cc72ce,0xfcbf8be0,0x01d7f1e0,0x018d1ad6,0x013c0ffe,0x01726620,0xfee949db,0xfe3dfe09,0x0025ad3f}
    },
    {
        {0xfd40e48c,0x0132029a,0x0108ef20,0x00606211,0x0112d637,0xff0d4408,0xff5770dd,0x01ca00cd,0x0325331f,0xff8b0d60},
        {0x03f19713,0xfe2bb02a,0x005d7d65,0x01445b17,0x02aad42b,0x005d78e7,0x010ac283,0x01719714,0x03e41327,0x00162113},
        {0x00a310b5,0x01534966,0xfd56b248,0xfecce4ce,0xff884e04,0x003d0664,0x01c819dd,0x0135fc98,0x00a29572,0x00cb0db4},
        {0x02cc4292,0x01929cdf,0x00c51c13,0xfe6dc7f0,0xfddc68bc,0x00b68bcf,0xffd11433,0x0056478d,0x00772a68,0x01fa522d}
    },
    {
        {0x0238c7a3,0xfeebe25b,0xfe07beda,0xffcf72bc,0xfc483ecb,0x01959a43,0x0354de64,0xfe656afe,0x02a43bc6,0x00a2fbeb},
        {0xfcfada64,0xfee3f751,0xfeafedbf,0x01b2ec38,0x0186a04e,0x00e0c993,0xfed7c507,0xfe0017ec,0xfdf9489b,0xff5027d6},
        {0x003e973c,0x006555bd,0xfecd5add,0xffd1d8d0,0xfcb14244,0xff39469b,0x036c4d10,0x012b6e90,0x03999ca4,0x0041e714},
        {0xff222fa0,0xfede700d,0x034d7b86,0x01fea2ca,0x0022b71f,0xfe4f964e,0xfe74d47f,0x002a3e58,0x01479dd1,0xfef31ba3}
    },
    {
        {0xfec437d6,0xfecca5e7,0xffd511f7,0xfeb79208,0xfc0e594a,0xff0cfc2d,0xfeec55a0,0xfe3d65db,0xfc59d45f,0xfffc8eb9},
        {0x01415fc5,0x00828e75,0xff46686e,0x0107378f,0xfc7c46ed,0x00dfe14b,0x03502078,0xfff06938,0x03a0a8c1,0x01019dfa},
        {0x013c72a4,0x005bc487,0x00b6d306,0xfedf81de,0x02028ff6,0x00b781e1,0xfc8dd9c5,0x01d0dfd5,0x00063ff5,0x01d226ca},
        {0xfed9df0c,0xfe63fdcc,0x00c3102c,0xfe332e5b,0xfdbe1c0f,0xffa9bdb6,0x01dcbc97,0xfe8aff5a,0xfc4f9242,0xffd1fce4}
    },
    {
        {0xffc7aea7,0xfe6b1cc2,0xfe54c63c,0xff514c50,0xfe0b0a0f,0xfe92509a,0xff0a8427,0xfea04784,0xffb0954b,0xfe412d85},
        {0xfeee2486,0xff2c12c7,0xfeb1d7ce,0x003b5bda,0xff42acfc,0xffc4ded7,0xfe109ea4,0xfe3728d4,0xfdfd942c,0xfed533f4},
        {0xfddbdf23,0x01b3d98a,0xfc5a3efa,0xffb043aa,0xfe666799,0xfe54e3b8,0x02946984,0xfe45632e,0xfeee60ee,0xfe25b1ba},
        {0xfd8a638a,0xfe9cc6ad,0xfc065704,0xff868aaa,0xfc707ea5,0xfffe2f63,0xfd1e64aa,0xff8e66f9,0xff4dd1ff,0xffcfa19c}
    },
    {
        {0xff1dd34e,0xfe77ec13,0xfcb907b6,0xffa5c14c,0xfea9cbaa,0xfe5a4fa9,0xfeecf8ad,0xfe0929b6,0xfc61c3fd,0xfec5a961},
        {0xff914143,0x0025e788,0xff7fd00a,0x01e805fd,0xff23327a,0xffb58e2a,0xffed18d4,0xff66da18,0x0060bf7e,0xfebf5480},
        {0xfef48c6d,0xffe34dd3,0xfeec0ccd,0xff48769d,0xff24b176,0xff87fdcd,0xfcb300a8,0xff53a10c,0xfdcc07b7,0xffd8eddd},
        {0xff8a2ad7,0xfe9ddf1c,0x0101d2a2,0xff152f7a,0xfe39ef43,0xffb1adcd,0xfd8766ac,0xfff38395,0x00825861,0xff77b398}
    },
    {
        {0xff29917f,0xfef3dec7,0x004381b2,0x01090a6a,0xfe9e7d23,0xff5192b7,0xfe1c9b5b,0xff367e0f,0x01911fc1,0xfef15ec5},
        {0x00a8c6ef,0x015afb02,0x010a48f7,0x01d1a80d,0x02f5213e,0x00c8d26a,0x034b7221,0x0022a8d2,0x0218d0d2,0x01d802d9},
        {0xfca4cbb9,0xfe47c649,0xfcb65815,0xfeb4121a,0xfcebd181,0xffa77697,0xfdc409d5,0xfec80bba,0x00cd74c2,0xff653a1a},
        {0x0167577a,0x00472c10,0x0123a231,0x00742950,0x011dd299,0x0052182c,0x03263ab1,0x00e681a2,0x0278a77f,0x01ea1512}
    },
    {
        {0xff3fc16b,0x00a9ef47,0xfca8b6e9,0x018f053d,0xfd1ed016,0x01f5c571,0xfff9c8ce,0xff3fc223,0xff69978c,0xff05bf6b},
        {0x01d64d10,0xfe4ce71b,0xfc963e2f,0x00b3d447,0xfd640253,0x01b1a6cf,0x019d4c7a,0x0080faee,0x036f7887,0xff6c77c4},
        {0xff4e2ed1,0xfe43ef20,0x00e06c4c,0xfe2f1e18,0xfecbfd60,0x014774d8,0xff5abd85,0x0114c10d,0xfce934f6,0xfe993d80},
        {0xffc17250,0xfe452665,0x00aed78b,0x0150fc8a,0x012b01d2,0xff826ac7,0xfe66e54b,0xfee6c9ff,0xfda225ef,0xff20d0b2}
    },
    {
        {0xfff224a1,0xff906ffc,0xfd81ed57,0xfefc4e03,0xff6b986f,0xff13d475,0xfceea6ca,0xfe18b939,0xfec6b3a8,0xfea2e39a},
        {0xfe781831,0xff1fe9b6,0xfd87c9ef,0x00ff5b67,0x00e8df03,0x00f6c3de,0x00a15d6c,0xfe2b311d,0xfeec37fe,0xfeab96c2},
        {0xfdc18d1f,0xfecec223,0xfd853be2,0x019f4357,0x004fa2a2,0x01d4ab54,0x0136d7b9,0x01c251b3,0x008591c6,0xff34f302},
        {0xfc713ff9,0xfe972497,0xff315695,0xfea41b85,0x015791db,0xfff60f0a,0x0317c299,0xffb9e191,0xfdc4864e,0xfeb5175e}
    },
    {
        {0xfde97e77,0xfe2e8a14,0xff035107,0xfeb1a04c,0xfd984765,0x0105d0eb,0x03e537d3,0x01d3f3ab,0xfc4c41db,0xff0bbd4a},
        {0xfdb1bb0c,0xffe9d1d7,0xfdfa875a,0xffcb850f,0xfc418eb4,0x0135ad19,0xfff6a160,0xfe66847b,0xfed0fadc,0xfe766ff4},
        {0x006465f9,0x0175af39,0x0031840d,0x01a666af,0xfdaa2c06,0xff9f2c30,0xfd68b2ad,0x00030df3,0x02d6200e,0x01d0fa31},
        {0x035081de,0x01a38c7d,0x011f0fbd,0x0170f16d,0x0204fbda,0xff9f2b6b,0xff3eba1c,0xff70a37d,0x0267d411,0x00c47885}
    },
    {
        {0xff23ff23,0xff24dbfd,0xfdbe3a94,0x01500960,0xfffd2f5d,0xfea2dd18,0x033333a6,0xfe11f841,0xfedb824e,0xff1f4cc0},
        {0x02679be3,0x01b13888,0x007b02f1,0x008fc926,0x035ef82a,0x0137f1cb,0x03bffbe7,0x01943577,0x01f19bfb,0x01999e75},
        {0x00f250d7,0xfe00c6c3,0xfe7a5d3f,0xfe6a2af0,0xffc2d777,0xff02fa53,0xfedb7662,0xff6ddc28,0x00d74d6a,0x00f6fc45},
        {0x00b59aee,0x0000c140,0xfe71cdce,0xff42c7f5,0x03cc1925,0x00fa2cc8,0xfe348158,0x000f7245,0x039e84e0,0x01f76bf0}
    },
    {
        {0xfe4ae144,0xfff842c7,0xfff9ee2b,0x01a28a60,0xfec2ee4d,0xfecbbe39,0x0182686d,0xff061110,0xfd54bc91,0xfeeea123},
        {0x00ef1229,0x00495359,0x02b2d402,0x01f520bc,0xff798a57,0x005326f3,0x03361771,0x014800b8,0x03569541,0x00c78bee},
        {0x00d61619,0x0070e78b,0x03bf9446,0x01f77cc9,0xfdf4599c,0x005904b1,0xfd4dd4e6,0x011cd225,0x01ef067e,0x019834fe},
        {0x009d6fe4,0xff8f20e1,0xff47d12d,0xff3cb016,0x0219bfc2,0xfe6b0b87,0xfdb09308,0xff52aac7,0xfed85293,0x009aa564}
    },
    {
        {0x02ac2fd5,0x01888b49,0x0351117a,0x015f00c9,0xfe722950,0xfe7db08e,0x03219cc8,0x001334c9,0x0365f593,0x00944783},
        {0x00639760,0x00f29ad2,0x00cdc98f,0x015b0a6a,0x014f97f4,0x01a7ce85,0x0367b044,0x019f4e47,0x038cade9,0x0116f4c7},
        {0xfee63085,0xff9e72da,0x01bb29bf,0x016efb0d,0xfcd1430b,0xfe098343,0x010fbf27,0x0073c160,0x026fea90,0xff556cbf},
        {0x038c92cd,0xfefe79ac,0x00bd4191,0x00bc78c7,0xffbe019d,0xff1df461,0x020ee3ce,0xfef7fee9,0x00aa7511,0x007fbdcb}
    },
    {
        {0xfd6f1daa,0x00c089b2,0x01810290,0x0146669c,0x00327d41,0xfe5d8929,0xfc6a4111,0xff0ae2db,0xfe4981ca,0xffce71f4},
        {0x03cf69da,0x000990fd,0x009ca1ec,0x005e3d57,0x02affc15,0x019e1e91,0x004b412d,0x008576e2,0x01296092,0x011f37ae},
        {0x0075f569,0x0174abff,0x01ac1d71,0x01679749,0xfcd09d8a,0xfeece8db,0xfec8599f,0xfeb38c40,0xff711387,0x01ed289b},
        {0x018ef142,0x018a2d29,0x0260da36,0x01b747ec,0x029f65ab,0x005ed113,0x02a6df2a,0x00a6af18,0xfd7c10f0,0x01625e54}
    },
    {
        {0x03b23b3a,0xfea68780,0x01373d53,0x0063ae3c,0x0109f320,0x013623d2,0x009554ca,0x007461c7,0x009f735d,0x01912a12},
        {0x002b6d71,0x01434d49,0x03f1dc2a,0x019823f4,0x03b00b96,0x0061eac3,0x020f90ba,0xfe257f04,0xfc84f657,0x01785ac2},
        {0x01240c6b,0xff5869a0,0xfd9e4972,0xfe1b69bb,0xfdbd99af,0xfe53b4d9,0xfdc2abd3,0xff5f0c61,0xff974d12,0x0038d634},
        {0x00c08688,0xffc7a14c,0xfc6b3024,0xfe211f52,0xfc7a1d42,0xfe690aa3,0xfc2761d7,0xffde163c,0xff1cf5b1,0x00033249}
    },
    {
        {0x01a95365,0xfeedec93,0xfd6cedd1,0x01a07c1f,0x034799cd,0xff2e5e54,0xfddf6c55,0xfeb6bb3d,0xfeef83d1,0x009084bd},
        {0x010d0816,0xfee43483,0xfe57a8d4,0xff17ef73,0x002c55f4,0x010746d0,0xfd9a867a,0x00588e32,0x02f20ce6,0x0133f23b},
        {0x03ed135f,0x016dfcb8,0xff1ebd98,0x01428779,0x03768bb9,0x00206e63,0x0098bdeb,0x00cd2eb6,0x036f08d3,0x01aa6adb},
        {0xfe34ae70,0x019b965b,0x03820e45,0xff6522e6,0xfe533dc5,0x01d52965,0x03f7f84c,0x00e1548b,0xfcdf755c,0xff1e5442}
    }
};

#else /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */

#ifndef MOCANA_ECC_25519_WIN_SIZE
#define MOCANA_ECC_25519_WIN_SIZE 5 /* default of 5 */
#endif

#if MOCANA_ECC_25519_WIN_SIZE < 1 || MOCANA_ECC_25519_WIN_SIZE > 5
#error valid values for MOCANA_ECC_25519_WIN_SIZE for CURVE25519 is 1 through 5.
#endif

#define MOCANA_ECC_25519_COMB_SIZE (1<<MOCANA_ECC_25519_WIN_SIZE)  /* 2^(win size) */
#define MOCANA_ECC_25519_COMB_D ((254 + MOCANA_ECC_25519_WIN_SIZE)/MOCANA_ECC_25519_WIN_SIZE)  /* ceil(255/win size) */

static const projPoint25519 *gpComb_25519 = NULL;
static RTOS_MUTEX gpCombMutex_25519 = NULL;

#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */


/*
 Converts a 32 byte encoding of a point P, to its projective form on the curve.
 pEncodedInput must be defined and 32 bytes long.
 
 Returns ERR_NOT_FOUND if the point is not a valid point on the curve.
 */
MSTATUS CURVE25519_convertEncodedToProjective(projPoint25519 *pResult, const ubyte *pEncodedInput)
{
    MSTATUS status;
    int i;

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

    static const sbyte4 *pOne_25519 = (const sbyte4 *) gpComb_25519[0].pY;  /* re-use the table for the constant one */

#else
    
    /* 1 in Finite Field Form */
    static const sbyte4 pOne_25519[MOC_NUM_25519_UNITS] =
    {
        0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    /* the Edward's form curve equation's d (Little endian words) */
    static const sbyte4 pD_25519[MOC_NUM_25519_UNITS] =
    {
        0x035978a3, 0x00d37284, 0x03156ebd, 0x006a0a0e, 0x0001c029,
        0x0179e898, 0x03a03cbb, 0x01ce7198, 0x02e2b6ff, 0x01480db3
    };
    
    /* sqrt(-1), ie 2^((p-1)/4). */
    static const sbyte4 pSqrtNegOne_25519[MOC_NUM_25519_UNITS] =
    {
        0x020ea0b0,0x00186c9d2,0x008f189d,0x0035697f,0x00bd0c60,
        0x01fbd7a7,0x002804c9e,0x01e16569,0x0004fc1d,0x00ae0c92
    };
    
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
    
    ubyte pCoordBuffer[MOC_CURVE25519_BYTE_SIZE] = {0};
    ubyte xBit;
    
    /* We will use the coords of pResult as temp vars. Need two more vars though */
    sbyte4 *pX = NULL;
    sbyte4 *pU;
    
    /* Treat as an internal method. Skip NULL checks */
    
    /* Allocate memory for both temp vars in a single shot */
    status = DIGI_CALLOC((void**) &pX, 1, 2 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;
    
    pU = pX + MOC_NUM_25519_UNITS;
    
    /* Make a mutable copy of the input (as we may change at least one bit) */
    status = DIGI_MEMCPY(pCoordBuffer, pEncodedInput, MOC_CURVE25519_BYTE_SIZE);
    if (OK != status)
        goto exit;
    
    /* Get the odd/even bit of the x coord (ie the most significant bit) */
    xBit = ((pCoordBuffer[MOC_CURVE25519_BYTE_SIZE - 1] & 0x80) >> 7);
    
    /* Set that bit to zero so now we have a proper y */
    pCoordBuffer[MOC_CURVE25519_BYTE_SIZE - 1] &= 0x7f;
    
    /* Finalize Y in pResult, this method also ensures y < p */
    status = PF_25519_from_bytes(pResult->pY, pCoordBuffer, TRUE);
    if (OK != status){
        status = ERR_NOT_FOUND;
        goto exit;
    }
    
    /* Use pU as a temp var */
    PF_25519_square(pU, pResult->pY);      /* Y^2 */
    
    /* Use pX and pResult->pX/pZ as a temp variables, the value they represent is shown */
    PF_25519_multiply(pResult->pX, pU, (sbyte4 *) pD_25519); /* dY^2 */
    
    /* pU will be U from here on */
    PF_25519_subtract(pU, pU, pOne_25519, i);               /* U = Y^2 - 1 */
    
    PF_25519_add(pResult->pX, pResult->pX, pOne_25519, i);  /* V = dY^2 + 1 */
    PF_25519_square(pResult->pZ, pResult->pX);        /* V^2 */
    PF_25519_square(pResult->pT, pResult->pZ);        /* V^4 */
    PF_25519_multiply(pX, pResult->pX, pResult->pZ);  /* V^3 */
    PF_25519_multiply(pResult->pZ, pU, pX);                         /* UV^3 */
    PF_25519_multiply(pX, pResult->pT, pResult->pZ);  /* UV^7 */
    
    /* call specialExp with the flag false */
    status = PF_25519_specialExp(pResult->pT, pX, FALSE);           /* (UV^7)^((p-5)/8) */
    if (OK != status)
        goto exit;
    
    /* From here on pX will store the candidate for X */
    PF_25519_multiply(pX, pResult->pZ, pResult->pT);  /* X candidate */
    
    /* check if we found the correct square root. X^2 */
    PF_25519_square(pResult->pZ, pX);
    
    PF_25519_multiply(pResult->pT, pResult->pZ, pResult->pX); /* VX^2 */
    
    status = ERR_NOT_FOUND;
    if (PF_25519_match(pResult->pT,pU))  /* does VX^2 = U? */
    {
        /* if so we found a valid X */
        DIGI_MEMCPY(pResult->pX, pX, MOC_NUM_25519_ELEM_BYTES);  /* ok to ignore return value */
    }
    else
    {
        PF_25519_additiveInvert(pU, i);  /* ok to invert in place */
        
        if (PF_25519_match(pResult->pT,pU))  /* else does VX^2 = -U */
        {
            /* if yes then we can get a valid X by multiplying by sqrt(-1) */
            PF_25519_multiply(pResult->pX, pX, (sbyte4 *) pSqrtNegOne_25519);
        }
        else /* There is no such (X,Y) on the curve for the given Y */
        {
            goto exit;
        }
    }
    
    /*
     Use the xBit to choose the correct X. First put X back in full byte form,
     copy to pU as a temp var since PF_25519_to_bytes will mangle its input
     */
    DIGI_MEMCPY(pU, pResult->pX, MOC_NUM_25519_ELEM_BYTES);  /* ok to ignore return value */
    
    PF_25519_to_bytes(pCoordBuffer, pU);
    
    /* but check for X = 0 to make sure its encoding was valid (with no xBit set) */
    i = 0;
    while ( i < MOC_CURVE25519_BYTE_SIZE && (!pCoordBuffer[i]) )
    {
        i++;
    }
    if ((MOC_CURVE25519_BYTE_SIZE == i) && xBit)
    {
        goto exit;
    }
    
    /* Compare the least significant bit to the xBit taken from the encoded input */
    if ( xBit != (pCoordBuffer[0] & 0x01))
    {
        /* Then we want -X */
        PF_25519_additiveInvert(pResult->pX, i);
    }
    
    /* Compute the projective form T coordinate */
    PF_25519_multiply(pResult->pT, pResult->pX, pResult->pY);
    
    /* The projective form Z coordinate is just 1 */
    DIGI_MEMCPY(pResult->pZ, pOne_25519, MOC_NUM_25519_ELEM_BYTES);  /* ok to ignore return value */
    
    status = OK;
    
exit:
    
    if (NULL != pX)
    {
        DIGI_MEMSET((ubyte *) pX, 0x00, 2 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void**) &pX);                              /* don't change status */
    }
    
    pU = NULL;
    DIGI_MEMSET(pCoordBuffer, 0x00, MOC_CURVE25519_BYTE_SIZE);  /* don't change status */
    
    return status;
}


/*
 pResult = pP + pQ in the elliptic curve group.
 
 pResult MUST be a distinct pointer from pP or pQ.
 pTemps must have been allocated to hold four temp field elements.
 The variables in pResult will also hold temp vars.
 */
void CURVE25519_addPoints(projPoint25519 *pResult, const projPoint25519 *pP, const projPoint25519 *pQ, sbyte4 *pTemps)
{
    int i;  /* index for addition and subtraction routines */
    
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
    /* 2 in Finite Field Form */
    static const sbyte4 pTwo_25519[MOC_NUM_25519_UNITS] =
    {
        0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    /* 2d */
    static const sbyte4 pTwoD_25519[MOC_NUM_25519_UNITS] =
    {
        0x02b2f159, 0x01a6e509, 0x022add7a, 0x00d4141d, 0x00038052,
        0x00f3d130, 0x03407977, 0x019ce331, 0x01c56dff, 0x00901b67
    };

#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    sbyte4 *pE = pTemps;
    sbyte4 *pF = pE + MOC_NUM_25519_UNITS;
    sbyte4 *pG = pF + MOC_NUM_25519_UNITS;
    sbyte4 *pH = pG + MOC_NUM_25519_UNITS;
    
    /* skip NULL checks even though this method is used one time externally in the edDSA aglorithm */
    
    /* Section 5.1.4, put A, B, C, D in pResult->X/Y/Z/T respectively */
    PF_25519_subtract(pE, pP->pY ,pP->pX, i);  /* use pE as temp var */
    PF_25519_subtract(pF, pQ->pY ,pQ->pX, i);  /* use pF as temp var */
    PF_25519_multiply(pResult->pX, pE, pF);
    
    PF_25519_add(pE, pP->pY ,pP->pX, i);       /* use pE as temp var */
    PF_25519_add(pF, pQ->pY ,pQ->pX, i);       /* use pF as temp var */
    PF_25519_multiply(pResult->pY, pE, pF);

    PF_25519_multiply(pE, pP->pT, pQ->pT);   /* use pE as temp var */
    PF_25519_multiply(pResult->pZ, pE, pTwoD_25519);
    
    PF_25519_multiply(pE, pP->pZ, pQ->pZ);   /* use pE as temp var */
    PF_25519_multiply(pResult->pT, pE, pTwo_25519);
    
    PF_25519_subtract(pE, pResult->pY, pResult->pX, i);  /* E */
    PF_25519_subtract(pF, pResult->pT, pResult->pZ, i);  /* F */
    
    PF_25519_add(pG, pResult->pT, pResult->pZ, i);   /* G */
    PF_25519_add(pH, pResult->pY, pResult->pX, i);   /* H */
    
    PF_25519_multiply(pResult->pX, pE, pF);
    PF_25519_multiply(pResult->pY, pG, pH);
    PF_25519_multiply(pResult->pT, pE, pH);
    PF_25519_multiply(pResult->pZ, pF, pG);
}


/*
 pResult = 2 * pP in the elliptic curve group.
 
 pResult MUST be a distinct pointer from pP or pQ.
 pTemps must have been allocated to hold three temp field elements.
 The variables in pResult will also hold temp vars.
 */
static void CURVE25519_doublePoint(projPoint25519 *pResult, const projPoint25519 *pP, sbyte4 *pTemps)
{
    int i; /* index for addition and subtraction routines */
    
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    /* 2 in Finite Field Form */
    static const sbyte4 pTwo_25519[MOC_NUM_25519_UNITS] =
    {
        0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    sbyte4 *pE = pTemps;
    sbyte4 *pF = pE + MOC_NUM_25519_UNITS;
    sbyte4 *pG = pF + MOC_NUM_25519_UNITS;
    
    /* Section 5.1.4 put A, B, C, H in pResult->X/Y/T/Z respectively (note T,Z switched) */
    PF_25519_square(pResult->pX, pP->pX);
    PF_25519_square(pResult->pY, pP->pY);
    
    PF_25519_square(pE, pP->pZ);   /* use pE as a temp */
    PF_25519_multiply(pResult->pT, pE, pTwo_25519); /* C */
    
    PF_25519_add(pResult->pZ, pResult->pX, pResult->pY, i); /* H */
    
    PF_25519_add(pE, pP->pX, pP->pY, i); /* use pE as a temp */
    PF_25519_square(pF, pE);             /* use pF as a temp */
    
    PF_25519_subtract(pE, pResult->pZ, pF, i);
    PF_25519_subtract(pG, pResult->pX, pResult->pY, i);
    PF_25519_add(pF, pResult->pT, pG, i);
    
    PF_25519_multiply(pResult->pX, pE, pF);
    PF_25519_multiply(pResult->pY, pG, pResult->pZ);
    PF_25519_multiply(pResult->pT, pE, pResult->pZ);
    PF_25519_multiply(pResult->pZ, pF, pG);
}


static MSTATUS CURVE25519_createComb(projPoint25519 **ppComb, const projPoint25519 *pP)
{
    MSTATUS status = OK;
    projPoint25519 *pNewComb = NULL;
    
    projPoint25519 *pNextPoint = NULL;
    projPoint25519 *pTemp = NULL;
    sbyte4 *pScratch = NULL;
    
    int i,j;
    
    /* internal method NULL input validity checks not needed */

    /* allocate space for a temp var and scratch, 7 field elements in size */
    status = DIGI_MALLOC( (void **) &pTemp, 7 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        goto exit;
    
    /* allocate space for the full comb table */
    status = DIGI_MALLOC( (void **) &pNewComb, sizeof(projPoint25519) * MOCANA_ECC_25519_COMB_SIZE);
    if (OK != status)
        goto exit;

    pScratch = (sbyte4 *) (pTemp + 1); /* point pScratch to be the 3 field elements after pTemp */
    
    /* First element is the group identity O = (0,1,1,0), ok to ignore DIGI_MEMSET return code */
    DIGI_MEMSET((ubyte *) pNewComb, 0x00, sizeof(projPoint25519));

    pNewComb[0].pY[0] = 0x01;
    pNewComb[0].pZ[0] = 0x01;
    
    /* Next element is P, ok to ignore DIGI_MEMCPY return code */
    DIGI_MEMCPY((ubyte *) (pNewComb + 1), (ubyte *) pP, sizeof(projPoint25519));
    
    /* first loop: 2^d.P, 2^(2d).P,  2^(3d).P, etc... */
    for ( i = 1; i < MOCANA_ECC_25519_WIN_SIZE; ++i)
    {
        pNextPoint = pNewComb + (MOC_EC_ONE << i); /* next point in the table to be calculated */

        CURVE25519_doublePoint(pNextPoint, pNewComb + (MOC_EC_ONE << (i-1)), pScratch); /* begin with previous point in table */
        
        for (j = 1; j < (MOCANA_ECC_25519_COMB_D + 1)/2; ++j)
        {
            CURVE25519_doublePoint(pTemp, pNextPoint, pScratch);
            CURVE25519_doublePoint(pNextPoint, pTemp, pScratch);
        }

#if !(MOCANA_ECC_25519_COMB_D & 0x01)
        CURVE25519_doublePoint(pTemp, pNextPoint, pScratch);
        DIGI_MEMCPY((ubyte *) pNextPoint, (ubyte *) pTemp, sizeof(projPoint25519));
#endif
    }
    
    /* second loop: compute the remaining values by addition, pComb[i + j] = pComb[i] + pComb[j] */
    for (i = 2; i < MOCANA_ECC_25519_COMB_SIZE; i *= 2)
        for ( j = 1; j < i; ++j)
            CURVE25519_addPoints(pNewComb + i + j, pNewComb + i, pNewComb + j, (sbyte4 *) pTemp); /* use pTemp for scratch this time (4 elements needed) */
    
    *ppComb = pNewComb;

exit:
    
    /* no goto exits after pNewComb allocation, don't need to free it on error */
    
    if (NULL != pTemp)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pTemp, 0x00, 7 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void **) &pTemp);
    }
    
    return status;
}


static MSTATUS CURVE25519_combMultiply(projPoint25519 *pResult, const ubyte *pScalar, const projPoint25519 *pComb)
{
    MSTATUS status = OK;
    projPoint25519 *pTemp = NULL;
    sbyte4 *pScratch = NULL;

    ubyte index;
    ubyte4 bitNum;
    ubyte bit;
    int i,j;
    
    /* allocate space for a temp var and scratch, 8 field elements in size */
    status = DIGI_MALLOC( (void **) &pTemp, 2 * sizeof(projPoint25519));
    if (OK != status)
        goto exit;
    
    pScratch = (sbyte4 *) (pTemp + 1); /* point pScratch to be the 4 field elements after pTemp */
    
    /* set pResult to the origin O */
    DIGI_MEMSET((ubyte *) pResult, 0x00, sizeof(projPoint25519));
    
    pResult->pY[0] = 0x01;
    pResult->pZ[0] = 0x01;
    
    /* comb method for point multiplication */
    for ( i = MOCANA_ECC_25519_COMB_D - 1; i >= 0; --i)
    {
        CURVE25519_doublePoint(pTemp, pResult, pScratch);
        
        index = 0;
        for (j = MOCANA_ECC_25519_WIN_SIZE - 1; j >= 0; --j)
        {
            bitNum = (ubyte4) (i + j * MOCANA_ECC_25519_COMB_D);
            bit = ((0x01 << (bitNum & 0x07)) & (pScalar[bitNum >> 3])) >> (bitNum & 0x07);
            index <<= 1;
            index |= bit;
        }
    
        CURVE25519_addPoints(pResult, pTemp, pComb + index, pScratch);
    }

exit:
    
    if (NULL != pTemp)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pTemp, 0x00, 2 * sizeof(projPoint25519));
        DIGI_FREE((void **) &pTemp);
    }
    
    return status;
}

#ifndef __CURVE25519_HARDWARE_ACCELERATOR__
/*
 Multiplies a point pP by a pScalar in Little Endian byte form.
 pResult must be a distinct pointer from pP.
 pScalar must be 32 bytes in length for curve25519.
 if pP is NULL then this multiplies pScalar times the curve's large cyclic group generator B.
 */
MSTATUS CURVE25519_multiplyPoint(MOC_ECC(hwAccelDescr hwAccelCtx) projPoint25519 *pResult, const ubyte *pScalar, const projPoint25519 *pP)
{
    MSTATUS status;
    projPoint25519 *pComb = NULL;
    
    if (NULL == pResult || NULL == pScalar)
        return ERR_NULL_POINTER;
 
    if (NULL != pP)
    {
        status = CURVE25519_createComb(&pComb, pP);
        if (OK != status)
            goto exit;
    }
    else
#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    {
        pComb = (projPoint25519 *) gpComb_25519;
    }
#else
    {
        if (NULL == gpComb_25519)
        {
            MSTATUS fstatus;
            
            /* The curve's large cyclic group generator B */
            static const projPoint25519 pB =
            {
                {0x0325d51a,0x018b5823,0x00f6592a,0x0104a92d,0x01a4b31d,0x01d6dc5c,0x027118fe,0x007fd814,0x013cd6e5,0x0085a4db},
                {0x02666658,0x01999999,0x00cccccc,0x01333333,0x01999999,0x00666666,0x03333333,0x00cccccc,0x02666666,0x01999999},
                {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
                {0x01b7dda3,0x01a2ace9,0x025eadbb,0x0003ba8a,0x0083c27e,0x00abe37d,0x01274732,0x00ccacdd,0x00fd78b7,0x019e1d7c}
            };
            
            status = RTOS_mutexWait(gpCombMutex_25519);
            if (OK != status)
                goto exit;
            
            /* check again in case another thread created the comb after the first check */
            if (NULL == gpComb_25519)
            {
                status = CURVE25519_createComb((projPoint25519 **) &gpComb_25519, &pB);
            }
            
            /* release no matter what status */
            fstatus = RTOS_mutexRelease(gpCombMutex_25519);
            if (OK == status)
                status = fstatus;
        
            if (OK != status)
                goto exit;
        }

        pComb = (projPoint25519 *) gpComb_25519;
    }
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
    
    status = CURVE25519_combMultiply(pResult, pScalar, pComb);
    
exit:

    /* for either global constants or not, only delete the comb if it was not the generator point */
    if (NULL != pP && NULL != pComb)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pComb, 0x00, sizeof(projPoint25519) * MOCANA_ECC_25519_COMB_SIZE);
        DIGI_FREE((void **) &pComb);
    }
    
    return status;
}
#endif /* __CURVE25519_HARDWARE_ACCELERATOR__ */


/*
 Converts a projective point to an encoded form in a 32 byte buffer.
 The encoded form consists of 255 bits of the affine form Y in Little
 Endian (bytewise) form. The most significant 256th bit represents the least
 significant bit of the affine X. pBuffer must have room for 32 bytes.
 */
MSTATUS CURVE25519_convertProjectiveToEncoded(ubyte *pBuffer, const projPoint25519 *pInput)
{
    MSTATUS status;
    ubyte xLeastSigBit;
    
    sbyte4 *pXorY = NULL;
    sbyte4 *pZinv;
    
    /* Treat as an internal method. Skip NULL checks */
    
    /* Allocate memory for both temp vars in a single shot */
    status = DIGI_CALLOC((void**) &pXorY, 1, 2 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;
    
    pZinv = pXorY + MOC_NUM_25519_UNITS;
    
    status = PF_25519_specialExp(pZinv, pInput->pZ, TRUE);
    if (OK != status)
        goto exit;
    
    PF_25519_multiply(pXorY, pInput->pX, pZinv);
    
    /* first get x */
    PF_25519_to_bytes(pBuffer, pXorY);
    xLeastSigBit = pBuffer[0] & 0x01;
    
    PF_25519_multiply(pXorY, pInput->pY, pZinv);
    
    /* now put pY in pBuffer */
    PF_25519_to_bytes(pBuffer, pXorY);
    
    pBuffer[MOC_CURVE25519_BYTE_SIZE - 1] |= (xLeastSigBit << 7);
    
exit:
    
    if (NULL != pXorY)
    {
        DIGI_MEMSET((ubyte *) pXorY, 0x00, 2 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void**) &pXorY); /* don't change status */
    }
    
    return status;
}


#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
MSTATUS CURVE25519_createCombMutex(void)
{
    if (NULL == gpCombMutex_25519)
    {
        return RTOS_mutexCreate(&gpCombMutex_25519, EC_COMB_MUTEX, 1);
    }
    
    return OK;
}


MSTATUS CURVE25519_deleteCombAndMutex(void)
{
    MSTATUS status = OK, fstatus = OK;
    
    if (NULL != gpComb_25519)
    {   /* ok to ignore DIGI_MEMSET return code */
        DIGI_MEMSET((ubyte *) gpComb_25519, 0x00, sizeof(projPoint25519) * MOCANA_ECC_25519_COMB_SIZE);
        status = DIGI_FREE((void **) &gpComb_25519);
    }
    
    if (NULL != gpCombMutex_25519)
    {
        fstatus = RTOS_mutexFree(&gpCombMutex_25519);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */

/*****************************************************************************************/

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) && !defined(__CURVE25519_X_HARDWARE_ACCELERATOR__)

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

/* Constant a24 (section 5 of rfc 7748) (Little endian words) */
static const sbyte4 pA24_25519[MOC_NUM_25519_UNITS] =
{
    0x1DB41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* masks for constant time swap vs no-swap */
static const sbyte4 pPF_mask_25519[2] =
{
    0x00, 0xffffffff
};

#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */

/*
 macro that swaps x and y if swap is 1, and is a no-op but the same runtime,
 if swap is 0. Make sure pPF_mask_25519 and dummy are defined.
 */
#define CSWAP_25519( swap, x, y) \
for (k = 0; k < MOC_NUM_25519_UNITS; ++k) \
{\
dummy = pPF_mask_25519[swap] & (x[k] ^ y[k]); \
x[k] ^= dummy; \
y[k] ^= dummy; \
}

/*
 X25519 Function from RFC 7748, section 5.
 
 pScalar and pU must be Little Endian byte arrays of length 32.
 pU (after masking its highest bit) is the u coordinate of a point
 on the Montgomery form curve v^2 = u^3 + Au^2 + u. The result is the u coordinate
 of the scalar point multiply scalar * (u, v) where v is not ever needed.
 pResult must have room for 32 bytes and will also be Little Endian.
 
 It is ok for pU and pResult to be the same buffer.
 */
MSTATUS CURVE25519_X25519(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResult, ubyte *pScalar, ubyte *pU)
{
    MSTATUS status;
    int i,k;
    
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    /* Constant a24 (section 5 of rfc 7748) (Little endian words) */
    static const sbyte4 pA24_25519[MOC_NUM_25519_UNITS] =
    {
        0x1DB41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    /* masks for constant time swap vs no-swap */
    static const sbyte4 pPF_mask_25519[2] =
    {
        0x00, 0xffffffff
    };
#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    /*
     we will enforce highest bit of pScalar to be 0 and we begin at the next bit,
     so the j index will start at 1 and mask will start at 0x40.
     */
    int j = 1;
    ubyte mask = 0x40;
    
    ubyte kt = 0;
    sbyte4 dummy;
    ubyte swap = 0;
    
    sbyte4 *pX1 = NULL;
    sbyte4 *pX2;
    sbyte4 *pZ2;
    sbyte4 *pX3;
    sbyte4 *pZ3;
    sbyte4 *pA;
    sbyte4 *pB;
    sbyte4 *pAA;

    ubyte pUCopy[MOC_CURVE25519_BYTE_SIZE];
    ubyte pSCopy[MOC_CURVE25519_BYTE_SIZE];
    
    /* Treat as an internal method. Skip NULL checks. */
    
    /* Make mutable copies of the input */
    status = DIGI_MEMCPY(pUCopy, pU, MOC_CURVE25519_BYTE_SIZE);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pSCopy, pScalar, MOC_CURVE25519_BYTE_SIZE);
    if (OK != status)
        goto exit;

    /* Prune the scalar */
    pSCopy[0] &= 0xf8;
    pSCopy[MOC_CURVE25519_BYTE_SIZE - 1] &= 0x7f;
    pSCopy[MOC_CURVE25519_BYTE_SIZE - 1] |= 0x40;

    /* Prune the u-coord */
    pUCopy[MOC_CURVE25519_BYTE_SIZE - 1] &= 0x7f;
    
    /* allocate all the temp vars in a single shot */
    status = DIGI_CALLOC((void **)&pX1, 1, 8 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;
    
    pX2 = pX1 + MOC_NUM_25519_UNITS;
    pZ2 = pX2 + MOC_NUM_25519_UNITS;
    pX3 = pZ2 + MOC_NUM_25519_UNITS;
    pZ3 = pX3 + MOC_NUM_25519_UNITS;
    pA = pZ3 + MOC_NUM_25519_UNITS;
    pB = pA + MOC_NUM_25519_UNITS;
    pAA = pB + MOC_NUM_25519_UNITS;
    
    /* set pX1 to pU, ok for u to be >= p. No modular reduction is needed. */
    status = PF_25519_from_bytes(pX1, pUCopy, FALSE);
    if (OK != status)
        goto exit;
    
    /* pZ2 is already 0, also set pX2, pX3, pZ3 */
    pX2[0] = 0x01;
    pZ3[0] = 0x01;
    
    DIGI_MEMCPY(pX3, pX1, MOC_NUM_25519_ELEM_BYTES);  /* ok to ignore return value */
    
    for (i = MOC_CURVE25519_BYTE_SIZE - 1; i >= 0; --i)
    {
        for (; j < 8; ++j, mask >>= 1)
        {
            int l;
            
            kt = (mask & pSCopy[i]) >> (7-j);
            swap ^= kt;
            
            CSWAP_25519(swap, pX2, pX3);
            CSWAP_25519(swap, pZ2, pZ3);
            
            swap = kt;
        
            PF_25519_add(pA, pX2, pZ2, l);
            PF_25519_subtract(pB, pX2, pZ2, l);
            
            /* reuse pX2 as C */
            PF_25519_add(pX2, pX3, pZ3, l);
            
            /* reuse pZ2 as D */
            PF_25519_subtract(pZ2, pX3, pZ3, l);
            
            /* re-use pX3 as DA */
            PF_25519_multiply(pX3, pZ2, pA);
            
            /* re-use pZ3 as CB */
            PF_25519_multiply(pZ3, pX2, pB);
            
            /* use pAA as AA */
            PF_25519_square(pAA, pA);
            
            /* re-use pZ2 as BB */
            PF_25519_square(pZ2, pB);
            
            /* Use pA and pB as temps */
            PF_25519_add(pA, pX3, pZ3, l);
            PF_25519_subtract(pB, pX3, pZ3, l);
            
            /* Final pX3 calculation */
            PF_25519_square(pX3, pA);
            
            /* Final PZ3 calculation */
            PF_25519_square(pA, pB);
            PF_25519_multiply(pZ3, pX1, pA);
            
            /* Final PX2 calculation */
            PF_25519_multiply(pX2, pAA, pZ2);
            
            /* Final pZ2 calculation, use pA as E, re-use pB as temp */
            PF_25519_subtract(pA, pAA, pZ2, l);
            PF_25519_multiply(pB, pA24_25519, pA);
            PF_25519_add(pAA, pAA, pB, l); /* inplace ok, re-use pAA */
            PF_25519_multiply(pZ2, pAA, pA);
            
        }
        j = 0; mask = 0x80;
    }
    
    CSWAP_25519(swap, pX2, pX3);
    CSWAP_25519(swap, pZ2, pZ3);
    
    /* use pA as a temp, compute the result x2 * z2^-1 */
    PF_25519_specialExp(pA, pZ2, TRUE);
    PF_25519_multiply(pAA, pX2, pA);  /* re-use pAA as the result */
    
    PF_25519_to_bytes(pResult, pAA);
    
exit:
    
    /* zero memory, no need to check return */
    DIGI_MEMSET(pSCopy, 0x00, MOC_CURVE25519_BYTE_SIZE);
    DIGI_MEMSET(pUCopy, 0x00, MOC_CURVE25519_BYTE_SIZE);
    
    if (NULL != pX1)
    {
        DIGI_MEMSET((ubyte *) pX1, 0x00, 8 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void**) &pX1); /* don't change status */
    }
    if (OK != status && NULL != pResult)
    {
        DIGI_MEMSET(pResult, 0x00, MOC_CURVE25519_BYTE_SIZE);
    }
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) && !defined(__CURVE25519_X_HARDWARE_ACCELERATOR__) */


/*****************************************************************************************/


#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

/* 2 in Finite Field Form */
static const pf_unit pTwo_448[MOC_CURVE448_NUM_UNITS] =
{
#ifdef __ENABLE_DIGICERT_64_BIT__
    0x02ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL
#else
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#endif
};

/* the Edward's form curve equation's d (Little endian words) */
static const pf_unit pD_448[MOC_CURVE448_NUM_UNITS] =
{
#ifdef __ENABLE_DIGICERT_64_BIT__
    0xFFFFFFFFFFFF6756ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFEFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL
#else
    0xFFFF6756,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF
#endif
};

#ifdef MOCANA_ECC_448_WIN_SIZE
#undef MOCANA_ECC_448_WIN_SIZE
#endif

#define MOCANA_ECC_448_WIN_SIZE 5
#define MOCANA_ECC_448_COMB_SIZE (1<<MOCANA_ECC_448_WIN_SIZE)  /* 2^(win size) */
#define MOCANA_ECC_448_COMB_D ((447 + MOCANA_ECC_448_WIN_SIZE)/MOCANA_ECC_448_WIN_SIZE)  /* ceil(448/win size) */

/* pre-computed comb table for the large cyclic group generator B */
static const projPoint448 gpComb_448[MOCANA_ECC_448_COMB_SIZE] =
{
#ifdef __ENABLE_DIGICERT_64_BIT__
    {
        {0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL},
        {0x1ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL},
        {0x1ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL}
    },
    {
        {0x2626a82bc70cc05eULL,0x433b80e18b00938eULL,0x12ae1af72ab66511ULL,0xea6de324a3d3a464ULL,0x9e146570470f1767ULL,0x221d15a622bf36daULL,0x4f1970c66bed0dedULL},
        {0x9808795bf230fa14ULL,0xfdbd132c4ed7c8adULL,0x3ad3ff1ce67c39c4ULL,0x87789c1e05a0c2d7ULL,0x4bea73736ca39840ULL,0x8876203756c9c762ULL,0x693f46716eb6bc24ULL},
        {0x1ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL}
    },
    {
        {0xf4b3bbe7143539a3ULL,0x3250c9c67c3c1e4aULL,0xf769ddb920d42af2ULL,0x542d5a4ddf744623ULL,0xddd11aa7868f6798ULL,0xe4f1e8a2d2b9b572ULL,0xcc6da1d620cb755fULL},
        {0x849e20cade937641ULL,0xc7ff78e8647cca45ULL,0xbf41274bbd8e7960ULL,0x35372f892eb0a6acULL,0x9e0e8501bd9a6dbbULL,0xe1b18814c87911bbULL,0xb433b7d0b9b3c3f4ULL},
        {0x84129674a9fdab82ULL,0xda48c28e60712966ULL,0xcc853ffa2e1f0f78ULL,0x90e4d184ce614f66ULL,0x290e2e7f83c6a715ULL,0xc87bb972ce728d85ULL,0xa158780165414ac2ULL}
    },
    {
        {0x7fd169d107866cfaULL,0x60fd63ae114a8267ULL,0x24f1935b2e6cd551ULL,0xda1d4be640660cf2ULL,0x75c60143e4cf0213ULL,0x1d92516274d3d36ULL,0x317e2a1c839304baULL},
        {0x38aa7b2622192d9bULL,0x575f07f4dff67e61ULL,0x522a1d1e48c3fe53ULL,0xeabb93fae7425d29ULL,0x8e915ef792b17b3fULL,0xabd562ec60c2c152ULL,0xcf13e56e361776afULL},
        {0xb15c2e0803f54c11ULL,0xc0b16593f8b82c1dULL,0xeb87d58e2a54c859ULL,0xa66194a4c1808e01ULL,0x2a9e5deeb78df205ULL,0x308ff2fdf092bfd1ULL,0x65f47f901172cd43ULL}
    },
    {
        {0x5a48f3f75aa041c6ULL,0xab90f4d47c38e3bcULL,0x3d512cbc8e4844eaULL,0x55b8d75d8f7d9403ULL,0x90a46c1c6614ae77ULL,0x212087c94e74bb8fULL,0xcfe0233157c46491ULL},
        {0x77dd86d1c3f28704ULL,0x109be990044a00f5ULL,0xae62aa5e404ab1e0ULL,0x961a7d96efafef50ULL,0x876778054dbe27f3ULL,0x7d39bb24bbd1d0caULL,0x86e7017644f2a32fULL},
        {0x7a51efe297216154ULL,0x270f9873eef0c235ULL,0x5919e39b1407bc15ULL,0xd132fb1f780f22eeULL,0xabae06946c0599eeULL,0x2ef86904e6e08419ULL,0xa168882316553b86ULL}
    },
    {
        {0x4ff769f264dca4bULL,0xeb3f1aab7e0cc8fcULL,0x60e4a8f75bd78346ULL,0xd58c412a1ce33f5dULL,0x5837194a4c7a236ULL,0xa6c06c744faba5f6ULL,0x8ac62d2708848604ULL},
        {0x916fa639935f5588ULL,0xd4c847606724cf6fULL,0x6679451654b3cb9ULL,0x9b6d9a3259028968ULL,0x234db735ad01b26ULL,0x3f7bc90a7c36a184ULL,0xc02603a8bc224e22ULL},
        {0x6ca68109d2a566c1ULL,0xe6fd14bc204eb582ULL,0x9a75adf72a92e4e5ULL,0x68e52f6f7114a1e4ULL,0xc4ca31222222ffbULL,0x841e7d44e27bbf16ULL,0x37b53d595b9b3db9ULL}
    },
    {
        {0x867523001edf94f5ULL,0x370c923c189c1355ULL,0xd0df08aa24aeac6dULL,0x2853edea2a14a097ULL,0x9574db1562920b5aULL,0xda60877732d4c076ULL,0x5f329923300e24bcULL},
        {0xa71371ab21a94a8aULL,0x39b8fc292d5f0de2ULL,0xa25035db91f18922ULL,0x1cf3bee81ca4b2fULL,0x15017eeafa11fd18ULL,0x1bd572804a5df7eeULL,0x361157e7534fed7ULL},
        {0xb150807eeef59805ULL,0x435de1f327786c2dULL,0x974b5e1449b76a38ULL,0xd857fe95ce044b22ULL,0xf792a17801db40c8ULL,0x6df25cd37a4a16afULL,0x2f3a84669e357682ULL}
    },
    {
        {0xbd0feafdd48dfb1cULL,0xf3a90a05838eeefbULL,0x218545bf42f192ebULL,0x38674b80f255d4c2ULL,0x2d5332afae38b136ULL,0x7358d1ca057697cdULL,0x2eaf072d851fd19bULL},
        {0x1d16d79d951f65e2ULL,0x8f089184c9ac46efULL,0xccfede307795c8eeULL,0xb8827b3aba51f416ULL,0x27a5d448593fe03eULL,0xc4e276a47d727808ULL,0x779888be887627d1ULL},
        {0xf910cabd8d8d795cULL,0x566d1ccea1300da1ULL,0x82e499a59a0f0427ULL,0x5ae44345d3cd2ea0ULL,0x57ddc66cdec85254ULL,0xaac99f62161a808aULL,0xa8efc23862b3f9f9ULL}
    },
    {
        {0x88019ef3c8f4d757ULL,0xa39de81d6fd598f2ULL,0x22ba3274f5bc81f8ULL,0x600699aee5cfbbb8ULL,0x37eab28bfc09b949ULL,0x8bfce0ea3f13b51ULL,0xb9245f8995405dccULL},
        {0x135e95f9db6eb6aaULL,0x35d3e0bd10e9dd59ULL,0x6a742caa2c6a40e0ULL,0x45614a64f94b1ad1ULL,0xefcacfb196b1a5aULL,0x122ff9f31c1e9bdeULL,0xb562dd699af4a9e2ULL},
        {0xc334d2f6363938e8ULL,0xdbaa16b6292c5f95ULL,0x4099da0d2f77ff99ULL,0xe0237eba66aa3ebbULL,0x49df952faf1e7dafULL,0x942286303dbff9f8ULL,0xe3da821ec76f3a9eULL}
    },
    {
        {0x620a5f162227e929ULL,0x2721cad79f0df4edULL,0x7157c3e5176ea3e9ULL,0x803220d360ccfc02ULL,0xab3b017355224f02ULL,0x953ce6e598796ad0ULL,0x510ee93250383a64ULL},
        {0x5b6d9c0fe64aa93bULL,0x83dabaebbeefa93fULL,0x9c56da880740ca3dULL,0x402ebcb68b8f626ULL,0x7e50d0f1e43d0463ULL,0x3281c90e465af46fULL,0x9f8f456cfd08f6ceULL},
        {0xea814ed14d8b0acdULL,0x5301f86d9a753bcfULL,0x56f20d3e80179285ULL,0x577916116439f167ULL,0xfff017bb139092b5ULL,0xaf34b60a932e2190ULL,0xd41268d508c5a90fULL}
    },
    {
        {0x992d42dc8792763cULL,0x337a9e0e1dd16cc8ULL,0xb07c6192a46c0f6aULL,0x5cc94455c3ae0deaULL,0x6799d880d9b5651cULL,0xd8267ccb071762a6ULL,0xc0211c53a173891aULL},
        {0x4641f9f044ab5f02ULL,0x53c8bc9c1ab42041ULL,0x7b47fcf8af545ed2ULL,0x61503f3c3361f043ULL,0xb0cb8f8129b3cf1fULL,0xbce5f80a3f817193ULL,0xba85fddef0ea9ed8ULL},
        {0xb9e5efd753b2280fULL,0xca13e8043cf736afULL,0x4768743bfe65c8ffULL,0x3872f128318461fbULL,0xeac565a773d99fbbULL,0x92e21c4a19e4336cULL,0x88d9d3e926da764aULL}
    },
    {
        {0x6793ce0a0218a822ULL,0x8b940ab8b15a8facULL,0x188ab68fc48daf74ULL,0x2bf9268e2aa2d62fULL,0x92e558a59640bbbeULL,0xc34dfea332b265dfULL,0xe4f6c6512d102a24ULL},
        {0x952ad8cf714e52ffULL,0x45b4c95d900f0ba9ULL,0x206e76e10f1ea157ULL,0x10df368b181479e9ULL,0xfa367ad5155e0c68ULL,0x5378334a450ab790ULL,0x6e2b5bdf68d01119ULL},
        {0xc989758e5eb0e964ULL,0xeb0a4c2523980c0fULL,0x6c29b0ad8e11ca12ULL,0x6d92a0cb9979f2c4ULL,0x2b6370cfdd918528ULL,0x5a940e81447a9e17ULL,0x1b69a64f95bbbabULL}
    },
    {
        {0xd1e6a188bdb87636ULL,0x3cb0415c11f385beULL,0xb4c89d9196dd4ca7ULL,0x5242047d29d6cabeULL,0xf0014da7f36158b8ULL,0xf356b0bea32eeca9ULL,0xd30961627d6ff934ULL},
        {0x117bf7bd7353f672ULL,0x68efb2caa45dcaULL,0xc1781deff6197d8dULL,0xf34b550aa43cc530ULL,0xc8d63c1286ffcfbfULL,0x7ef81534e8b9a107ULL,0xdf7e666572298f63ULL},
        {0xd4e9ff7698a14bfbULL,0x24f6dae11cbce477ULL,0xe4102dbddfe4c612ULL,0xbd4372581b882651ULL,0x18825618e634a7d0ULL,0x6b855986f8e3b01ULL,0x8f1e4e9643192de9ULL}
    },
    {
        {0x60a8be8a8f7df020ULL,0x560d2618a2b4d7e5ULL,0xb25f7230ca508a46ULL,0x1ebda671063cae07ULL,0x5e4cc1e5995f1acULL,0xe34040743c1be188ULL,0x3fc98a9a5b941dc5ULL},
        {0xce1f04cbd512a8ceULL,0xc76ccf93e7c7aaacULL,0xa9b2c714edff71a9ULL,0xd43cbc4691031455ULL,0x55f45f9f00c2fe24ULL,0xfbadc3f1da391416ULL,0xbde69330ed07d8abULL},
        {0x6249ac96eab4d4b8ULL,0x6e0468eff0ab9a69ULL,0x965f57c64d135505ULL,0xd24c58e45f63c1bfULL,0xdb7df864c94b378bULL,0x97d1fef229e403deULL,0x205da20b63eb1527ULL}
    },
    {
        {0x911d0853a50bbdeaULL,0xce565da29fe3cc3dULL,0xc441263a4ef5d313ULL,0xe18a5389dc738d3eULL,0xdbf53f5bae7afe1ULL,0xfc64a97592467827ULL,0x54535a08c1668c6fULL},
        {0xc03798d09074df72ULL,0xb65fac35dca84d3bULL,0x4793ad96d0d6bd64ULL,0x4258bd3c2a5e72b1ULL,0x8aedbb6cdc527d65ULL,0x5d4f0d40bea903a1ULL,0x7530a8d1a77d441dULL},
        {0xa83de2cb44e66386ULL,0x8116a3e64d232b98ULL,0x3dc1eb02ec612eb5ULL,0x578b0d9e4cb85cf0ULL,0x7e57dc23eddfd8b4ULL,0xd5defa1bca858acdULL,0x38ee3d03bb308295ULL}
    },
    {
        {0x46910f602f4e9a1aULL,0x625e2eb79d5937caULL,0xc7141b18d4a7f3e4ULL,0x79fd848868d4fbebULL,0xd1daf1d1a7844479ULL,0x94a92b4d611694b4ULL,0xd0306a831bed7151ULL},
        {0xfa012027c8cb4d72ULL,0x7fa80a4d5fe27835ULL,0xde36d793f73713aeULL,0xdc16b0443fc68448ULL,0x7ac5a6721fa21b8aULL,0x9031be691feb40d4ULL,0x1c002ffd9ca34f68ULL},
        {0x47a2798f3d04cb8fULL,0x8a67889dba893918ULL,0xbfec5fc3b4ec5928ULL,0xd323718825248ec4ULL,0x2ed9d57996796b3eULL,0x3f3a04a509ecbdc7ULL,0x640535568bab6ab5ULL}
    },
    {
        {0x8af7b71f619f0aULL,0x9138e7e16ab51a3ULL,0x5d19bb7c1e9d1906ULL,0x15c92a59cca56450ULL,0xf6d761e881a3058ULL,0x43833621537cfe02ULL,0x4f5a46c41893bcf5ULL},
        {0xdf7cf7d0488fa88cULL,0x4c80b96ba376000fULL,0xd3bc7b1450c012e2ULL,0x37b5ccd53113172aULL,0xc6d550fcf438a46ULL,0x8a306ba59f9a3b54ULL,0x29971a40de668f8bULL},
        {0xca82965e0ec3a6adULL,0x4b01673faad66e3dULL,0xda095407fc142e2fULL,0x6251230d6037ceebULL,0xc2173fc0e31a433ULL,0x490c4f3bf635db63ULL,0x89834fd883cf04f3ULL}
    },
    {
        {0x1cab24049fbefe8aULL,0x8b1a74b797418d02ULL,0x859d4587c8d3a56bULL,0xdf603b6a7255ec16ULL,0x9658338b2df01716ULL,0xc5e80ba4b77e19e7ULL,0x80ed10ecad55bdc4ULL},
        {0x28817bbc73434e17ULL,0xc332408ecf7882e1ULL,0xe8334e9a0936831eULL,0x1648ec93c566efa7ULL,0x2767a1fa9257738bULL,0x6dd4385196acfc17ULL,0x344c1578ebba2496ULL},
        {0xc166bdefac64cd23ULL,0xcb3aa8c34c70a869ULL,0x75d231555e1b85eULL,0x7429dd4d0065e68ULL,0x771c9fd2b005ee30ULL,0xc41752051aa5af5eULL,0xe7d21ac858addb39ULL}
    },
    {
        {0x8d54fa29dc3ce2f8ULL,0xd0b1969eb80b660aULL,0x62e90352504aa7faULL,0xa8a97fe3ea04581dULL,0x4feb9f7b744f8320ULL,0xcdd28e0bfb7d00a0ULL,0xe544c5f270f9d661ULL},
        {0x9e2d6ae00a625412ULL,0xf36352cbe1ea7846ULL,0xb650350a4f627bdeULL,0xb71b7fddc2f9fa06ULL,0x64d4cc1b58df9173ULL,0x4a12d44086c4fdc0ULL,0x52947391c310745aULL},
        {0x152dd2bc61a34a5ULL,0x64f8427afe2b0af5ULL,0x1186cf1c5dd83c2ULL,0x7cbaa1359056af0ULL,0x5504a69247492b5bULL,0x41523f99c2a1ad23ULL,0x4af8481ab692f79bULL}
    },
    {
        {0x98dc850a21bf2816ULL,0xa41f816615fb7c34ULL,0x37f00dd75a099847ULL,0x1c96e102b838c192ULL,0x132b24eff7d985e3ULL,0xe902d8b71c3f3696ULL,0xd63ceb9b40aa461cULL},
        {0x595f47203ee4598fULL,0xba51831565d5e533ULL,0x787f126b43c84008ULL,0x1412d04a8fc3d79ULL,0xe1396e30869d57d7ULL,0x197eab1ed611b272ULL,0xf35d89e2fa198e17ULL},
        {0x621dea26f69b0351ULL,0x3a31f95fd699f3f1ULL,0x6b30d1138743f7a4ULL,0x750f584a10c1f8d2ULL,0x4ec23e8a324021f7ULL,0x87f93ece9e50c75cULL,0x53e0485dae0aa3b9ULL}
    },
    {
        {0x387f3a42e0053563ULL,0x8b1624213d2a8e45ULL,0xde9fa53ee313637aULL,0xa2d8d6ad45b097aeULL,0xcc69087b174b6fb4ULL,0x5e72c7ff0ad51e12ULL,0xd94167678d3ebdb6ULL},
        {0xd1f066fed8f34e79ULL,0x419a1174fb05e202ULL,0x4b668bfc53fcede8ULL,0xfb20cdd0c1c84c04ULL,0xdd627f06343eda0fULL,0xd3f03cf21c1b867ULL,0x6e22c198199c1eaULL},
        {0x2c85a611ebec30e5ULL,0xfb3a4772711eafcbULL,0x490050e868825406ULL,0xdcbdbde966e72755ULL,0x82d04d7ef7f5bbdbULL,0x752aa8f03a2a296eULL,0x157a1ec18cc9dc47ULL}
    },
    {
        {0xae5cb3795ef38149ULL,0x349cc106a2c2a02fULL,0x95713cabec816d5aULL,0xcdeac93e02473bd6ULL,0x6c4ed3678252a27fULL,0xd3cf17f32e66de1fULL,0xdf2623ccf6071ab5ULL},
        {0x6f4c67645ca0469bULL,0xacc2f56c2ae1d072ULL,0xeed3fff31bfc9cd1ULL,0xb209dc40f5ce00d4ULL,0x51efbc20bb1c4ea5ULL,0xebf6243d3978ce81ULL,0xb38607b5b33ba677ULL},
        {0x227f1d4bb8f2ac31ULL,0x30fe6f29acf15b6eULL,0x7556e3875f368001ULL,0x1e7d1d4fbd18f4c1ULL,0x97bd0ba78f585b52ULL,0x90f16242b0f4cbc4ULL,0x4887010481534a2eULL}
    },
    {
        {0x33c7656ab84c607bULL,0x45f5e22bd943617cULL,0x9be57b02cabee799ULL,0x52617e2da43adce8ULL,0xf0f3d8823c166d06ULL,0xb27acae1cf2a766dULL,0x76ded09dfacad723ULL},
        {0xa5575628df9d96f8ULL,0x42335dcb7435b5caULL,0x8361f689e4cd2829ULL,0x72f4a183eb7dc359ULL,0x92d09fd11c6b6b84ULL,0x8a7ee45a3c80c94eULL,0xa9669db45cbdaccfULL},
        {0x5d60c28b4a9efa6ULL,0xfedf6236f22c3378ULL,0xb8dc03b9fc94dd20ULL,0xcdb1aa271fc8a277ULL,0xb0e30acb119700e3ULL,0x83a657c98a54085ULL,0x465d138e6de8db2aULL}
    },
    {
        {0x1eef30c2f350aae0ULL,0x2680b390dbb6a42eULL,0xc403085b41b0fa5ULL,0x8f6324d4aa1f8087ULL,0xa88d82631b82bacaULL,0x355b00669134fd3ULL,0x5580b3319c49d51ULL},
        {0xa9ad50c74421863bULL,0x6e5f67ed8631841bULL,0x3ea948a4cd728870ULL,0x2fc843efb029005cULL,0xca7c5320785ff5f0ULL,0x159d26fc1235cec0ULL,0xbe3337a9e71b6df4ULL},
        {0x2fbcd7385a3c5376ULL,0xa9812534cbad99c5ULL,0xa43b0733ff73317cULL,0xe52e34aa41397ac6ULL,0x90a6687dea8e284cULL,0xf6c0325cdc08dfb6ULL,0x55959c82398a6becULL}
    },
    {
        {0x7293b1047907647ULL,0x782e104bd640622dULL,0x1b539101048db6dfULL,0xf702013caf90f09cULL,0xe1fa3e50ed8fdefbULL,0x5fc3cdb315fd9ea4ULL,0x548472d0dcfd5699ULL},
        {0xc9bc3875afd1c193ULL,0xfd1956508c0b197aULL,0x2292a7d4295cc8cfULL,0x84c7611f94dd37d2ULL,0xe953390e14e1751bULL,0x5201f872ea5b8bd2ULL,0x8068f05306bd1db8ULL},
        {0x6293fcf3b4a2360dULL,0xb7acac75f8093699ULL,0x19e1c395ed936432ULL,0xad8e2337b0766b55ULL,0x7ba2b4175bcd2b36ULL,0xa890da36e0380752ULL,0x2c51ab5b1e128c74ULL}
    },
    {
        {0x5ae3a77eec0f3294ULL,0x4eb0241473a0e3a3ULL,0x5f5c49dd60ba605fULL,0x96b585c1b761a13cULL,0x67e82e232d5051f9ULL,0x4fcd52db9b3edee4ULL,0xdc09551831e343fULL},
        {0x6be53193a8a2c65ULL,0x3fdaab791270892cULL,0x941bef4057659d7ULL,0x4894cca4d40be087ULL,0x7718c0ac325e8291ULL,0x620f2b24d4fce6bfULL,0xa8e8e6ea44840b40ULL},
        {0x233098cf63e04378ULL,0xfd6d6ea78c07e7fdULL,0x451e7044b89fdae2ULL,0x1d1601134e443e96ULL,0x88d09c8fd859204bULL,0x38d7ad2d749ceb7aULL,0xd76efe806e8e1d46ULL}
    },
    {
        {0x6b3164ddecf6f885ULL,0x1ff2c57f901a81f8ULL,0x496109c671eaa6cfULL,0x94eed5945bc35314ULL,0x923480034e73045aULL,0x5c9e745c65930564ULL,0x4f3de99fe4aae460ULL},
        {0xf7c357f7030b479fULL,0x367230ce775cbe41ULL,0x93dda46aeda74fc4ULL,0xf94cd59641905ce7ULL,0xc16b74ead5d2117fULL,0xa4dfa0e4ad318f6dULL,0xdaa1056fe958ea42ULL},
        {0xd79e6e3d9bf7d56eULL,0x1e2b00616564d342ULL,0xe5486fb92026a698ULL,0x706a0ce41a8efaf7ULL,0x50c43f79d6ffd01dULL,0x1e8bf1728e783779ULL,0x297c24ec66f976beULL}
    },
    {
        {0xd7fc011838eaca81ULL,0x299fb808d6403a76ULL,0x63102cdf7b6e2c38ULL,0x5549bc82453901a7ULL,0x3bc5a70bc2ecb75bULL,0x484dc1e0a607df98ULL,0x2940500bce8fb536ULL},
        {0xf642428e8dc5c939ULL,0x82b9bce9bbf42b8ULL,0x583438d10d89aa15ULL,0x26096f51faebbd61ULL,0x5cbe90cb3f224613ULL,0x9696894591ae3e7cULL,0x927820749fbf15e7ULL},
        {0xca273d5d0049a20eULL,0xd6de89f3ec501ca0ULL,0x700d9c11959b8398ULL,0xac179bbf81e7c06cULL,0x8b8e280efc783ba2ULL,0x323a5de82154c6c0ULL,0x3ad4045618ec3d22ULL}
    },
    {
        {0xf1d0cb09ca577f0fULL,0x3697aca9f0ffd02eULL,0x53b270c43c43c792ULL,0x8b46e7e850ff27a4ULL,0xce4ed08955a61d58ULL,0xc2d99e742c873e53ULL,0x180c7a02a033c847ULL},
        {0x59d3014ea3a76e46ULL,0xde3525bda9ce5aULL,0x81972e2fee6aa678ULL,0xdd9e0c29332367f6ULL,0x3fd8dc6642a89c1bULL,0x1c60b541b3115007ULL,0xae23f645bff2ae21ULL},
        {0x5956030cdb6c69bdULL,0xea196b4efa71f6baULL,0xc661233d76d1b85dULL,0xd14dfb356da04042ULL,0x7ff8e4835b9313e7ULL,0x9fb842ed159c3144ULL,0x6923b91d2fc057eULL}
    },
    {
        {0xe74b9193e134b745ULL,0x21ed317dbfdfff30ULL,0x9f0c7afc089594afULL,0x52092b2e32bdd44eULL,0xdca0c41a717cbb90ULL,0xe4b6371368eda0fdULL,0x85b3e9acd009863ULL},
        {0xd172f58b294c9034ULL,0xfe04733520bd5893ULL,0x93d4c88f12e3ce2dULL,0x16ed0f565a4e19f2ULL,0xfc5dabdae3357bfULL,0x177e56379b451eebULL,0x9f33f18b91fdebbcULL},
        {0xa53bdde48a772352ULL,0xdd8cdd43870fb63aULL,0x3cd9522a2c7f09d0ULL,0xb0db9c163444c23bULL,0x431ab83785881983ULL,0x625f2870aa2ed922ULL,0x9d060258526a4ce0ULL}
    },
    {
        {0xbd4978ff1a9e2ed3ULL,0xdd4fcb2b0ee71a79ULL,0xb8ecb6aec0f76f87ULL,0x162a9f7e0a278579ULL,0xfa0d209c4118de6cULL,0x255934156d25f34dULL,0x4cde13baa1986093ULL},
        {0xa43a1238d4cd8ce9ULL,0x5d7eb5be3a77aa0fULL,0x7a263ede2f3c2ceeULL,0xe3bed42e7e00b63fULL,0x92ed43f63538273aULL,0xbce2e42ad7316439ULL,0x348fd8169c45b818ULL},
        {0x23750de34cfdd7f2ULL,0x3db67df6e2f98f35ULL,0x8faaecca8d051e13ULL,0xbb662abc3ab354e6ULL,0x5a01cc0d680cbe03ULL,0xcbcf5c46be291176ULL,0xf161b4771d14249eULL}
    },
    {
        {0x2d0118b66d296bdcULL,0x345527a1adae0a1ULL,0xaf4b922d06a33e79ULL,0x94bce6786684aa2ULL,0x6868cbea1939b420ULL,0xb2371e70bd661f79ULL,0xb109dc6f75aff46cULL},
        {0x69f4b473699b6042ULL,0x3c24fcd90fbb1c04ULL,0x6400341b20786118ULL,0xd9bfcaffcd03df8bULL,0xb464ffcf22d1ec43ULL,0xce02a441f4b00b75ULL,0x1ef1c9c511a4feaeULL},
        {0xb3b8d33fbb3821dfULL,0xfb0e891a1e1287a8ULL,0x51b6bd0207d5189dULL,0x49a0b0080c088abfULL,0x84a8782ba8be59a9ULL,0xec402db47e3f81d1ULL,0x8354dd3bfc659d4fULL}
    }
#else
    {
        {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}
    },
    {
        {0xc70cc05e,0x2626a82b,0x8b00938e,0x433b80e1,0x2ab66511,0x12ae1af7,0xa3d3a464,0xea6de324,0x470f1767,0x9e146570,0x22bf36da,0x221d15a6,0x6bed0ded,0x4f1970c6},
        {0xf230fa14,0x9808795b,0x4ed7c8ad,0xfdbd132c,0xe67c39c4,0x3ad3ff1c,0x05a0c2d7,0x87789c1e,0x6ca39840,0x4bea7373,0x56c9c762,0x88762037,0x6eb6bc24,0x693f4671},
        {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}
    },
    {
        {0x143539a3,0xf4b3bbe7,0x7c3c1e4a,0x3250c9c6,0x20d42af2,0xf769ddb9,0xdf744623,0x542d5a4d,0x868f6798,0xddd11aa7,0xd2b9b572,0xe4f1e8a2,0x20cb755f,0xcc6da1d6},
        {0xde937641,0x849e20ca,0x647cca45,0xc7ff78e8,0xbd8e7960,0xbf41274b,0x2eb0a6ac,0x35372f89,0xbd9a6dbb,0x9e0e8501,0xc87911bb,0xe1b18814,0xb9b3c3f4,0xb433b7d0},
        {0xa9fdab82,0x84129674,0x60712966,0xda48c28e,0x2e1f0f78,0xcc853ffa,0xce614f66,0x90e4d184,0x83c6a715,0x290e2e7f,0xce728d85,0xc87bb972,0x65414ac2,0xa1587801}
    },
    {
        {0x07866cfa,0x7fd169d1,0x114a8267,0x60fd63ae,0x2e6cd551,0x24f1935b,0x40660cf2,0xda1d4be6,0xe4cf0213,0x75c60143,0x274d3d36,0x01d92516,0x839304ba,0x317e2a1c},
        {0x22192d9b,0x38aa7b26,0xdff67e61,0x575f07f4,0x48c3fe53,0x522a1d1e,0xe7425d29,0xeabb93fa,0x92b17b3f,0x8e915ef7,0x60c2c152,0xabd562ec,0x361776af,0xcf13e56e},
        {0x03f54c11,0xb15c2e08,0xf8b82c1d,0xc0b16593,0x2a54c859,0xeb87d58e,0xc1808e01,0xa66194a4,0xb78df205,0x2a9e5dee,0xf092bfd1,0x308ff2fd,0x1172cd43,0x65f47f90}
    },
    {
        {0x5aa041c6,0x5a48f3f7,0x7c38e3bc,0xab90f4d4,0x8e4844ea,0x3d512cbc,0x8f7d9403,0x55b8d75d,0x6614ae77,0x90a46c1c,0x4e74bb8f,0x212087c9,0x57c46491,0xcfe02331},
        {0xc3f28704,0x77dd86d1,0x044a00f5,0x109be990,0x404ab1e0,0xae62aa5e,0xefafef50,0x961a7d96,0x4dbe27f3,0x87677805,0xbbd1d0ca,0x7d39bb24,0x44f2a32f,0x86e70176},
        {0x97216154,0x7a51efe2,0xeef0c235,0x270f9873,0x1407bc15,0x5919e39b,0x780f22ee,0xd132fb1f,0x6c0599ee,0xabae0694,0xe6e08419,0x2ef86904,0x16553b86,0xa1688823}
    },
    {
        {0x264dca4b,0x04ff769f,0x7e0cc8fc,0xeb3f1aab,0x5bd78346,0x60e4a8f7,0x1ce33f5d,0xd58c412a,0xa4c7a236,0x05837194,0x4faba5f6,0xa6c06c74,0x08848604,0x8ac62d27},
        {0x935f5588,0x916fa639,0x6724cf6f,0xd4c84760,0x654b3cb9,0x06679451,0x59028968,0x9b6d9a32,0x5ad01b26,0x0234db73,0x7c36a184,0x3f7bc90a,0xbc224e22,0xc02603a8},
        {0xd2a566c1,0x6ca68109,0x204eb582,0xe6fd14bc,0x2a92e4e5,0x9a75adf7,0x7114a1e4,0x68e52f6f,0x22222ffb,0x0c4ca312,0xe27bbf16,0x841e7d44,0x5b9b3db9,0x37b53d59}
    },
    {
        {0x1edf94f5,0x86752300,0x189c1355,0x370c923c,0x24aeac6d,0xd0df08aa,0x2a14a097,0x2853edea,0x62920b5a,0x9574db15,0x32d4c076,0xda608777,0x300e24bc,0x5f329923},
        {0x21a94a8a,0xa71371ab,0x2d5f0de2,0x39b8fc29,0x91f18922,0xa25035db,0x81ca4b2f,0x01cf3bee,0xfa11fd18,0x15017eea,0x4a5df7ee,0x1bd57280,0x7534fed7,0x0361157e},
        {0xeef59805,0xb150807e,0x27786c2d,0x435de1f3,0x49b76a38,0x974b5e14,0xce044b22,0xd857fe95,0x01db40c8,0xf792a178,0x7a4a16af,0x6df25cd3,0x9e357682,0x2f3a8466}
    },
    {
        {0xd48dfb1c,0xbd0feafd,0x838eeefb,0xf3a90a05,0x42f192eb,0x218545bf,0xf255d4c2,0x38674b80,0xae38b136,0x2d5332af,0x057697cd,0x7358d1ca,0x851fd19b,0x2eaf072d},
        {0x951f65e2,0x1d16d79d,0xc9ac46ef,0x8f089184,0x7795c8ee,0xccfede30,0xba51f416,0xb8827b3a,0x593fe03e,0x27a5d448,0x7d727808,0xc4e276a4,0x887627d1,0x779888be},
        {0x8d8d795c,0xf910cabd,0xa1300da1,0x566d1cce,0x9a0f0427,0x82e499a5,0xd3cd2ea0,0x5ae44345,0xdec85254,0x57ddc66c,0x161a808a,0xaac99f62,0x62b3f9f9,0xa8efc238}
    },
    {
        {0xc8f4d757,0x88019ef3,0x6fd598f2,0xa39de81d,0xf5bc81f8,0x22ba3274,0xe5cfbbb8,0x600699ae,0xfc09b949,0x37eab28b,0xa3f13b51,0x08bfce0e,0x95405dcc,0xb9245f89},
        {0xdb6eb6aa,0x135e95f9,0x10e9dd59,0x35d3e0bd,0x2c6a40e0,0x6a742caa,0xf94b1ad1,0x45614a64,0x196b1a5a,0x0efcacfb,0x1c1e9bde,0x122ff9f3,0x9af4a9e2,0xb562dd69},
        {0x363938e8,0xc334d2f6,0x292c5f95,0xdbaa16b6,0x2f77ff99,0x4099da0d,0x66aa3ebb,0xe0237eba,0xaf1e7daf,0x49df952f,0x3dbff9f8,0x94228630,0xc76f3a9e,0xe3da821e}
    },
    {
        {0x2227e929,0x620a5f16,0x9f0df4ed,0x2721cad7,0x176ea3e9,0x7157c3e5,0x60ccfc02,0x803220d3,0x55224f02,0xab3b0173,0x98796ad0,0x953ce6e5,0x50383a64,0x510ee932},
        {0xe64aa93b,0x5b6d9c0f,0xbeefa93f,0x83dabaeb,0x0740ca3d,0x9c56da88,0x68b8f626,0x0402ebcb,0xe43d0463,0x7e50d0f1,0x465af46f,0x3281c90e,0xfd08f6ce,0x9f8f456c},
        {0x4d8b0acd,0xea814ed1,0x9a753bcf,0x5301f86d,0x80179285,0x56f20d3e,0x6439f167,0x57791611,0x139092b5,0xfff017bb,0x932e2190,0xaf34b60a,0x08c5a90f,0xd41268d5}
    },
    {
        {0x8792763c,0x992d42dc,0x1dd16cc8,0x337a9e0e,0xa46c0f6a,0xb07c6192,0xc3ae0dea,0x5cc94455,0xd9b5651c,0x6799d880,0x071762a6,0xd8267ccb,0xa173891a,0xc0211c53},
        {0x44ab5f02,0x4641f9f0,0x1ab42041,0x53c8bc9c,0xaf545ed2,0x7b47fcf8,0x3361f043,0x61503f3c,0x29b3cf1f,0xb0cb8f81,0x3f817193,0xbce5f80a,0xf0ea9ed8,0xba85fdde},
        {0x53b2280f,0xb9e5efd7,0x3cf736af,0xca13e804,0xfe65c8ff,0x4768743b,0x318461fb,0x3872f128,0x73d99fbb,0xeac565a7,0x19e4336c,0x92e21c4a,0x26da764a,0x88d9d3e9}
    },
    {
        {0x0218a822,0x6793ce0a,0xb15a8fac,0x8b940ab8,0xc48daf74,0x188ab68f,0x2aa2d62f,0x2bf9268e,0x9640bbbe,0x92e558a5,0x32b265df,0xc34dfea3,0x2d102a24,0xe4f6c651},
        {0x714e52ff,0x952ad8cf,0x900f0ba9,0x45b4c95d,0x0f1ea157,0x206e76e1,0x181479e9,0x10df368b,0x155e0c68,0xfa367ad5,0x450ab790,0x5378334a,0x68d01119,0x6e2b5bdf},
        {0x5eb0e964,0xc989758e,0x23980c0f,0xeb0a4c25,0x8e11ca12,0x6c29b0ad,0x9979f2c4,0x6d92a0cb,0xdd918528,0x2b6370cf,0x447a9e17,0x5a940e81,0xf95bbbab,0x01b69a64}
    },
    {
        {0xbdb87636,0xd1e6a188,0x11f385be,0x3cb0415c,0x96dd4ca7,0xb4c89d91,0x29d6cabe,0x5242047d,0xf36158b8,0xf0014da7,0xa32eeca9,0xf356b0be,0x7d6ff934,0xd3096162},
        {0x7353f672,0x117bf7bd,0xcaa45dca,0x0068efb2,0xf6197d8d,0xc1781def,0xa43cc530,0xf34b550a,0x86ffcfbf,0xc8d63c12,0xe8b9a107,0x7ef81534,0x72298f63,0xdf7e6665},
        {0x98a14bfb,0xd4e9ff76,0x1cbce477,0x24f6dae1,0xdfe4c612,0xe4102dbd,0x1b882651,0xbd437258,0xe634a7d0,0x18825618,0x6f8e3b01,0x06b85598,0x43192de9,0x8f1e4e96}
    },
    {
        {0x8f7df020,0x60a8be8a,0xa2b4d7e5,0x560d2618,0xca508a46,0xb25f7230,0x063cae07,0x1ebda671,0x5995f1ac,0x05e4cc1e,0x3c1be188,0xe3404074,0x5b941dc5,0x3fc98a9a},
        {0xd512a8ce,0xce1f04cb,0xe7c7aaac,0xc76ccf93,0xedff71a9,0xa9b2c714,0x91031455,0xd43cbc46,0x00c2fe24,0x55f45f9f,0xda391416,0xfbadc3f1,0xed07d8ab,0xbde69330},
        {0xeab4d4b8,0x6249ac96,0xf0ab9a69,0x6e0468ef,0x4d135505,0x965f57c6,0x5f63c1bf,0xd24c58e4,0xc94b378b,0xdb7df864,0x29e403de,0x97d1fef2,0x63eb1527,0x205da20b}
    },
    {
        {0xa50bbdea,0x911d0853,0x9fe3cc3d,0xce565da2,0x4ef5d313,0xc441263a,0xdc738d3e,0xe18a5389,0xbae7afe1,0x0dbf53f5,0x92467827,0xfc64a975,0xc1668c6f,0x54535a08},
        {0x9074df72,0xc03798d0,0xdca84d3b,0xb65fac35,0xd0d6bd64,0x4793ad96,0x2a5e72b1,0x4258bd3c,0xdc527d65,0x8aedbb6c,0xbea903a1,0x5d4f0d40,0xa77d441d,0x7530a8d1},
        {0x44e66386,0xa83de2cb,0x4d232b98,0x8116a3e6,0xec612eb5,0x3dc1eb02,0x4cb85cf0,0x578b0d9e,0xeddfd8b4,0x7e57dc23,0xca858acd,0xd5defa1b,0xbb308295,0x38ee3d03}
    },
    {
        {0x2f4e9a1a,0x46910f60,0x9d5937ca,0x625e2eb7,0xd4a7f3e4,0xc7141b18,0x68d4fbeb,0x79fd8488,0xa7844479,0xd1daf1d1,0x611694b4,0x94a92b4d,0x1bed7151,0xd0306a83},
        {0xc8cb4d72,0xfa012027,0x5fe27835,0x7fa80a4d,0xf73713ae,0xde36d793,0x3fc68448,0xdc16b044,0x1fa21b8a,0x7ac5a672,0x1feb40d4,0x9031be69,0x9ca34f68,0x1c002ffd},
        {0x3d04cb8f,0x47a2798f,0xba893918,0x8a67889d,0xb4ec5928,0xbfec5fc3,0x25248ec4,0xd3237188,0x96796b3e,0x2ed9d579,0x09ecbdc7,0x3f3a04a5,0x8bab6ab5,0x64053556}
    },
    {
        {0x1f619f0a,0x008af7b7,0x16ab51a3,0x09138e7e,0x1e9d1906,0x5d19bb7c,0xcca56450,0x15c92a59,0x881a3058,0x0f6d761e,0x537cfe02,0x43833621,0x1893bcf5,0x4f5a46c4},
        {0x488fa88c,0xdf7cf7d0,0xa376000f,0x4c80b96b,0x50c012e2,0xd3bc7b14,0x3113172a,0x37b5ccd5,0xcf438a46,0x0c6d550f,0x9f9a3b54,0x8a306ba5,0xde668f8b,0x29971a40},
        {0x0ec3a6ad,0xca82965e,0xaad66e3d,0x4b01673f,0xfc142e2f,0xda095407,0x6037ceeb,0x6251230d,0x0e31a433,0x0c2173fc,0xf635db63,0x490c4f3b,0x83cf04f3,0x89834fd8}
    },
    {
        {0x9fbefe8a,0x1cab2404,0x97418d02,0x8b1a74b7,0xc8d3a56b,0x859d4587,0x7255ec16,0xdf603b6a,0x2df01716,0x9658338b,0xb77e19e7,0xc5e80ba4,0xad55bdc4,0x80ed10ec},
        {0x73434e17,0x28817bbc,0xcf7882e1,0xc332408e,0x0936831e,0xe8334e9a,0xc566efa7,0x1648ec93,0x9257738b,0x2767a1fa,0x96acfc17,0x6dd43851,0xebba2496,0x344c1578},
        {0xac64cd23,0xc166bdef,0x4c70a869,0xcb3aa8c3,0x55e1b85e,0x075d2315,0xd0065e68,0x07429dd4,0xb005ee30,0x771c9fd2,0x1aa5af5e,0xc4175205,0x58addb39,0xe7d21ac8}
    },
    {
        {0xdc3ce2f8,0x8d54fa29,0xb80b660a,0xd0b1969e,0x504aa7fa,0x62e90352,0xea04581d,0xa8a97fe3,0x744f8320,0x4feb9f7b,0xfb7d00a0,0xcdd28e0b,0x70f9d661,0xe544c5f2},
        {0x0a625412,0x9e2d6ae0,0xe1ea7846,0xf36352cb,0x4f627bde,0xb650350a,0xc2f9fa06,0xb71b7fdd,0x58df9173,0x64d4cc1b,0x86c4fdc0,0x4a12d440,0xc310745a,0x52947391},
        {0xc61a34a5,0x0152dd2b,0xfe2b0af5,0x64f8427a,0xc5dd83c2,0x01186cf1,0x59056af0,0x07cbaa13,0x47492b5b,0x5504a692,0xc2a1ad23,0x41523f99,0xb692f79b,0x4af8481a}
    },
    {
        {0x21bf2816,0x98dc850a,0x15fb7c34,0xa41f8166,0x5a099847,0x37f00dd7,0xb838c192,0x1c96e102,0xf7d985e3,0x132b24ef,0x1c3f3696,0xe902d8b7,0x40aa461c,0xd63ceb9b},
        {0x3ee4598f,0x595f4720,0x65d5e533,0xba518315,0x43c84008,0x787f126b,0xa8fc3d79,0x01412d04,0x869d57d7,0xe1396e30,0xd611b272,0x197eab1e,0xfa198e17,0xf35d89e2},
        {0xf69b0351,0x621dea26,0xd699f3f1,0x3a31f95f,0x8743f7a4,0x6b30d113,0x10c1f8d2,0x750f584a,0x324021f7,0x4ec23e8a,0x9e50c75c,0x87f93ece,0xae0aa3b9,0x53e0485d}
    },
    {
        {0xe0053563,0x387f3a42,0x3d2a8e45,0x8b162421,0xe313637a,0xde9fa53e,0x45b097ae,0xa2d8d6ad,0x174b6fb4,0xcc69087b,0x0ad51e12,0x5e72c7ff,0x8d3ebdb6,0xd9416767},
        {0xd8f34e79,0xd1f066fe,0xfb05e202,0x419a1174,0x53fcede8,0x4b668bfc,0xc1c84c04,0xfb20cdd0,0x343eda0f,0xdd627f06,0x21c1b867,0x0d3f03cf,0x8199c1ea,0x06e22c19},
        {0xebec30e5,0x2c85a611,0x711eafcb,0xfb3a4772,0x68825406,0x490050e8,0x66e72755,0xdcbdbde9,0xf7f5bbdb,0x82d04d7e,0x3a2a296e,0x752aa8f0,0x8cc9dc47,0x157a1ec1}
    },
    {
        {0x5ef38149,0xae5cb379,0xa2c2a02f,0x349cc106,0xec816d5a,0x95713cab,0x02473bd6,0xcdeac93e,0x8252a27f,0x6c4ed367,0x2e66de1f,0xd3cf17f3,0xf6071ab5,0xdf2623cc},
        {0x5ca0469b,0x6f4c6764,0x2ae1d072,0xacc2f56c,0x1bfc9cd1,0xeed3fff3,0xf5ce00d4,0xb209dc40,0xbb1c4ea5,0x51efbc20,0x3978ce81,0xebf6243d,0xb33ba677,0xb38607b5},
        {0xb8f2ac31,0x227f1d4b,0xacf15b6e,0x30fe6f29,0x5f368001,0x7556e387,0xbd18f4c1,0x1e7d1d4f,0x8f585b52,0x97bd0ba7,0xb0f4cbc4,0x90f16242,0x81534a2e,0x48870104}
    },
    {
        {0xb84c607b,0x33c7656a,0xd943617c,0x45f5e22b,0xcabee799,0x9be57b02,0xa43adce8,0x52617e2d,0x3c166d06,0xf0f3d882,0xcf2a766d,0xb27acae1,0xfacad723,0x76ded09d},
        {0xdf9d96f8,0xa5575628,0x7435b5ca,0x42335dcb,0xe4cd2829,0x8361f689,0xeb7dc359,0x72f4a183,0x1c6b6b84,0x92d09fd1,0x3c80c94e,0x8a7ee45a,0x5cbdaccf,0xa9669db4},
        {0xb4a9efa6,0x05d60c28,0xf22c3378,0xfedf6236,0xfc94dd20,0xb8dc03b9,0x1fc8a277,0xcdb1aa27,0x119700e3,0xb0e30acb,0x98a54085,0x083a657c,0x6de8db2a,0x465d138e}
    },
    {
        {0xf350aae0,0x1eef30c2,0xdbb6a42e,0x2680b390,0xb41b0fa5,0x0c403085,0xaa1f8087,0x8f6324d4,0x1b82baca,0xa88d8263,0x69134fd3,0x0355b006,0x19c49d51,0x05580b33},
        {0x4421863b,0xa9ad50c7,0x8631841b,0x6e5f67ed,0xcd728870,0x3ea948a4,0xb029005c,0x2fc843ef,0x785ff5f0,0xca7c5320,0x1235cec0,0x159d26fc,0xe71b6df4,0xbe3337a9},
        {0x5a3c5376,0x2fbcd738,0xcbad99c5,0xa9812534,0xff73317c,0xa43b0733,0x41397ac6,0xe52e34aa,0xea8e284c,0x90a6687d,0xdc08dfb6,0xf6c0325c,0x398a6bec,0x55959c82}
    },
    {
        {0x47907647,0x07293b10,0xd640622d,0x782e104b,0x048db6df,0x1b539101,0xaf90f09c,0xf702013c,0xed8fdefb,0xe1fa3e50,0x15fd9ea4,0x5fc3cdb3,0xdcfd5699,0x548472d0},
        {0xafd1c193,0xc9bc3875,0x8c0b197a,0xfd195650,0x295cc8cf,0x2292a7d4,0x94dd37d2,0x84c7611f,0x14e1751b,0xe953390e,0xea5b8bd2,0x5201f872,0x06bd1db8,0x8068f053},
        {0xb4a2360d,0x6293fcf3,0xf8093699,0xb7acac75,0xed936432,0x19e1c395,0xb0766b55,0xad8e2337,0x5bcd2b36,0x7ba2b417,0xe0380752,0xa890da36,0x1e128c74,0x2c51ab5b}
    },
    {
        {0xec0f3294,0x5ae3a77e,0x73a0e3a3,0x4eb02414,0x60ba605f,0x5f5c49dd,0xb761a13c,0x96b585c1,0x2d5051f9,0x67e82e23,0x9b3edee4,0x4fcd52db,0x831e343f,0x0dc09551},
        {0x3a8a2c65,0x06be5319,0x1270892c,0x3fdaab79,0x057659d7,0x0941bef4,0xd40be087,0x4894cca4,0x325e8291,0x7718c0ac,0xd4fce6bf,0x620f2b24,0x44840b40,0xa8e8e6ea},
        {0x63e04378,0x233098cf,0x8c07e7fd,0xfd6d6ea7,0xb89fdae2,0x451e7044,0x4e443e96,0x1d160113,0xd859204b,0x88d09c8f,0x749ceb7a,0x38d7ad2d,0x6e8e1d46,0xd76efe80}
    },
    {
        {0xecf6f885,0x6b3164dd,0x901a81f8,0x1ff2c57f,0x71eaa6cf,0x496109c6,0x5bc35314,0x94eed594,0x4e73045a,0x92348003,0x65930564,0x5c9e745c,0xe4aae460,0x4f3de99f},
        {0x030b479f,0xf7c357f7,0x775cbe41,0x367230ce,0xeda74fc4,0x93dda46a,0x41905ce7,0xf94cd596,0xd5d2117f,0xc16b74ea,0xad318f6d,0xa4dfa0e4,0xe958ea42,0xdaa1056f},
        {0x9bf7d56e,0xd79e6e3d,0x6564d342,0x1e2b0061,0x2026a698,0xe5486fb9,0x1a8efaf7,0x706a0ce4,0xd6ffd01d,0x50c43f79,0x8e783779,0x1e8bf172,0x66f976be,0x297c24ec}
    },
    {
        {0x38eaca81,0xd7fc0118,0xd6403a76,0x299fb808,0x7b6e2c38,0x63102cdf,0x453901a7,0x5549bc82,0xc2ecb75b,0x3bc5a70b,0xa607df98,0x484dc1e0,0xce8fb536,0x2940500b},
        {0x8dc5c939,0xf642428e,0x9bbf42b8,0x082b9bce,0x0d89aa15,0x583438d1,0xfaebbd61,0x26096f51,0x3f224613,0x5cbe90cb,0x91ae3e7c,0x96968945,0x9fbf15e7,0x92782074},
        {0x0049a20e,0xca273d5d,0xec501ca0,0xd6de89f3,0x959b8398,0x700d9c11,0x81e7c06c,0xac179bbf,0xfc783ba2,0x8b8e280e,0x2154c6c0,0x323a5de8,0x18ec3d22,0x3ad40456}
    },
    {
        {0xca577f0f,0xf1d0cb09,0xf0ffd02e,0x3697aca9,0x3c43c792,0x53b270c4,0x50ff27a4,0x8b46e7e8,0x55a61d58,0xce4ed089,0x2c873e53,0xc2d99e74,0xa033c847,0x180c7a02},
        {0xa3a76e46,0x59d3014e,0xbda9ce5a,0x00de3525,0xee6aa678,0x81972e2f,0x332367f6,0xdd9e0c29,0x42a89c1b,0x3fd8dc66,0xb3115007,0x1c60b541,0xbff2ae21,0xae23f645},
        {0xdb6c69bd,0x5956030c,0xfa71f6ba,0xea196b4e,0x76d1b85d,0xc661233d,0x6da04042,0xd14dfb35,0x5b9313e7,0x7ff8e483,0x159c3144,0x9fb842ed,0xd2fc057e,0x06923b91}
    },
    {
        {0xe134b745,0xe74b9193,0xbfdfff30,0x21ed317d,0x089594af,0x9f0c7afc,0x32bdd44e,0x52092b2e,0x717cbb90,0xdca0c41a,0x68eda0fd,0xe4b63713,0xcd009863,0x085b3e9a},
        {0x294c9034,0xd172f58b,0x20bd5893,0xfe047335,0x12e3ce2d,0x93d4c88f,0x5a4e19f2,0x16ed0f56,0xae3357bf,0x0fc5dabd,0x9b451eeb,0x177e5637,0x91fdebbc,0x9f33f18b},
        {0x8a772352,0xa53bdde4,0x870fb63a,0xdd8cdd43,0x2c7f09d0,0x3cd9522a,0x3444c23b,0xb0db9c16,0x85881983,0x431ab837,0xaa2ed922,0x625f2870,0x526a4ce0,0x9d060258}
    },
    {
        {0x1a9e2ed3,0xbd4978ff,0x0ee71a79,0xdd4fcb2b,0xc0f76f87,0xb8ecb6ae,0x0a278579,0x162a9f7e,0x4118de6c,0xfa0d209c,0x6d25f34d,0x25593415,0xa1986093,0x4cde13ba},
        {0xd4cd8ce9,0xa43a1238,0x3a77aa0f,0x5d7eb5be,0x2f3c2cee,0x7a263ede,0x7e00b63f,0xe3bed42e,0x3538273a,0x92ed43f6,0xd7316439,0xbce2e42a,0x9c45b818,0x348fd816},
        {0x4cfdd7f2,0x23750de3,0xe2f98f35,0x3db67df6,0x8d051e13,0x8faaecca,0x3ab354e6,0xbb662abc,0x680cbe03,0x5a01cc0d,0xbe291176,0xcbcf5c46,0x1d14249e,0xf161b477}
    },
    {
        {0x6d296bdc,0x2d0118b6,0x1adae0a1,0x0345527a,0x06a33e79,0xaf4b922d,0x86684aa2,0x094bce67,0x1939b420,0x6868cbea,0xbd661f79,0xb2371e70,0x75aff46c,0xb109dc6f},
        {0x699b6042,0x69f4b473,0x0fbb1c04,0x3c24fcd9,0x20786118,0x6400341b,0xcd03df8b,0xd9bfcaff,0x22d1ec43,0xb464ffcf,0xf4b00b75,0xce02a441,0x11a4feae,0x1ef1c9c5},
        {0xbb3821df,0xb3b8d33f,0x1e1287a8,0xfb0e891a,0x07d5189d,0x51b6bd02,0x0c088abf,0x49a0b008,0xa8be59a9,0x84a8782b,0x7e3f81d1,0xec402db4,0xfc659d4f,0x8354dd3b}
    }
#endif /* __ENABLE_DIGICERT_64_BIT__ */
};

#else /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */

#ifndef MOCANA_ECC_448_WIN_SIZE
#define MOCANA_ECC_448_WIN_SIZE 5 /* default of 5 */
#endif

#if MOCANA_ECC_448_WIN_SIZE < 1 || MOCANA_ECC_448_WIN_SIZE > 8
#error valid values for MOCANA_ECC_448_WIN_SIZE for CURVE448 is 1 through 8.
#endif

#define MOCANA_ECC_448_COMB_SIZE (1<<MOCANA_ECC_448_WIN_SIZE)  /* 2^(win size) */
#define MOCANA_ECC_448_COMB_D ((447 + MOCANA_ECC_448_WIN_SIZE)/MOCANA_ECC_448_WIN_SIZE)  /* ceil(448/win size) */

static const projPoint448 *gpComb_448 = NULL;
static RTOS_MUTEX gpCombMutex_448 = NULL;

#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */


/*
 Converts a 57 byte encoding of a point P (56 bytes for y followed by 1 byte for x),
 to its projective form on the curve. pEncodedInput must be defined and 57 bytes long.
 
 Returns ERR_NOT_FOUND if the point is not a valid point on the curve.
 */
MSTATUS CURVE448_convertEncodedToProjective(projPoint448 *pResult, const ubyte *pEncodedInput)
{
    MSTATUS status = ERR_NOT_FOUND;
    int i = 0;

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
    static const pf_unit *pOne_448 = (const pf_unit *) gpComb_448[0].pY;  /* re-use the table for the constant one */

#else

    /* 1 in Finite Field Form */
    static const pf_unit pOne_448[MOC_CURVE448_NUM_UNITS] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0x1ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL
#else
        0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
#endif
    };
    
    /* the Edward's form curve equation's d (Little endian words) */
    static const pf_unit pD_448[MOC_CURVE448_NUM_UNITS] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0xFFFFFFFFFFFF6756ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFEFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL
#else
        0xFFFF6756,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
        0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF
#endif
    };
    
#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    /* We will use the coords of pResult as temp vars. Need three more vars though */
    PFEPtr pV = NULL;
    PFEPtr pU = NULL;
    PFEPtr pTemp = NULL;
    
    ubyte pCoordBuffer[MOC_CURVE448_BYTE_SIZE] = {0};
    
    /* temp buffer for multiplication and square routines */
    pf_unit hilo[2*MOC_CURVE448_NUM_UNITS] = {0};
    
    /*
     Treat as an internal method. Skip NULL checks and no need to check return
     codes of the called PRIMEFIELD arithmetic methods. ERR_NULL_POINTER is
     their only error code and we are certainly ok with respect to that.
     */
    
    /* Quick check that the last byte has at most the first bit set */
    if ( pEncodedInput[MOC_CURVE448_BYTE_SIZE] & 0x7f )
    {
        goto exit;
    }
    
    /* Copy over the first 56 bytes of input to Big Endian */
    for (i = 0; i < MOC_CURVE448_BYTE_SIZE; ++i)
    {
        pCoordBuffer[i] = pEncodedInput[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }
    
    /* Get as a PRIMEFIELD element, this method will check for Y >= p */
    status = PRIMEFIELD_setToByteString(PF_p448, (PFEPtr) pResult->pY, pCoordBuffer, MOC_CURVE448_BYTE_SIZE);
    if (OK != status)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }
    
    status = PRIMEFIELD_newElement(PF_p448, &pV);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(PF_p448, &pU);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(PF_p448, &pTemp);
    if (OK != status)
        goto exit;
    
    /* Use pU as a temp var */
    PRIMEFIELD_squareAux(PF_p448, pU, (PFEPtr) pResult->pY, hilo);             /* Y^2 */
    
    /* Use pResult->pX/pZ as a temp variables, the value they represent is shown */
    PRIMEFIELD_multiplyAux(PF_p448, pV, pU, (ConstPFEPtr) pD_448, hilo); /* dY^2 */
    
    /* pU,pV will be U,V from here on */
    PRIMEFIELD_subtract(PF_p448, pU, (ConstPFEPtr) pOne_448);                      /* U = Y^2 - 1 */
    PRIMEFIELD_subtract(PF_p448, pV, (ConstPFEPtr) pOne_448);                      /* V = dY^2 - 1 */
    
    PRIMEFIELD_squareAux(PF_p448, (PFEPtr) pResult->pZ, pU, hilo);             /* U^2 */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, (PFEPtr) pResult->pZ, pU, hilo);  /* U^3 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp, (PFEPtr) pResult->pX, pV, hilo);           /* U^3 V */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, pTemp, (PFEPtr) pResult->pZ, hilo);  /* U^5 V */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pZ, pV, (PFEPtr) pResult->pX, hilo);     /* U^5 V^2 */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, pV, (PFEPtr) pResult->pZ, hilo);     /* U^5 V^3 */
    
    /* call specialExp with the flag false */
    PRIMEFIELD_specialExp448((PFEPtr) pResult->pZ, (PFEPtr) pResult->pX, FALSE);        /* (U^5 V^3)^((p-3)/4) */
    
    /* candidate X = U^3 V (U^5 V^3)^((p-3)/4)  */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, pTemp, (PFEPtr) pResult->pZ, hilo);
    
    PRIMEFIELD_squareAux(PF_p448, (PFEPtr) pResult->pZ, (PFEPtr) pResult->pX, hilo);
    PRIMEFIELD_multiplyAux(PF_p448, pTemp, (PFEPtr) pV, (PFEPtr) pResult->pZ, hilo);  /* V X^2 */
    
    if (PRIMEFIELD_match(PF_p448, pTemp, pU))  /* does VX^2 = U? */
    {
        if (PRIMEFIELD_cmpToUnsigned(PF_p448, (PFEPtr)pResult->pX, 0))  /* if not 0 */
        {
            /*
             Check the bit representing x to see if it matches the X we just calculated,
             and if not, additively invert x.
             */
            if ( (pEncodedInput[MOC_CURVE448_BYTE_SIZE] >> 7) != ((pResult->pX[0]) & MOC_EC_ONE) )
            {
                PRIMEFIELD_additiveInvert(PF_p448, (PFEPtr) pResult->pX);
            }
        }
        else if (pEncodedInput[MOC_CURVE448_BYTE_SIZE])
        {
            /* X = 0 but x-coord bit set is an invalid encoding */
            status = ERR_NOT_FOUND;
            goto exit;
        }
        
        /* The projective form Z coordinate is just 1 */
        PRIMEFIELD_copyElement(PF_p448, (PFEPtr) pResult->pZ, (ConstPFEPtr) pOne_448);
    }
    else  /* No such X for the given Y */
    {
        status = ERR_NOT_FOUND;
    }
    
exit:
    
    if( NULL != pV )
    {
        /* don't change status */
        PRIMEFIELD_deleteElement(PF_p448, &pV);
    }
    if (NULL != pU)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pU);
    }
    if (NULL != pTemp)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pTemp);
    }
    
    /* zero temp memory, don't change status */
    DIGI_MEMSET(pCoordBuffer, 0x00, MOC_CURVE448_BYTE_SIZE);
    DIGI_MEMSET((ubyte *) hilo, 0x00, 2*MOC_CURVE448_NUM_UNITS*sizeof(pf_unit));
    
    return status;
}


/*
 pResult = pP + pQ in the elliptic curve group.
 It is NOT ok for pResult to be the same pointer as pP or pQ.
 
 pTemps must be allocated to hold 7 temp elements.
 */
void CURVE448_addPoints(projPoint448 *pResult, const projPoint448 *pP, const projPoint448 *pQ, pf_unit *pTemps)
{
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
    /* the Edward's form curve equation's d (Little endian words) */
    static const pf_unit pD_448[MOC_CURVE448_NUM_UNITS] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0xFFFFFFFFFFFF6756ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFEFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL
#else
        0xFFFF6756,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
        0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF
#endif
    };
    
#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    /* We use pResult->pX/pY/pZ as temp vars at first, need also 5 more temps */
    PFEPtr pA = (PFEPtr) pTemps;
    PFEPtr pC = (PFEPtr) &pTemps[MOC_CURVE448_NUM_UNITS];
    PFEPtr pF = (PFEPtr) &pTemps[2*MOC_CURVE448_NUM_UNITS];
    PFEPtr pG = (PFEPtr) &pTemps[3*MOC_CURVE448_NUM_UNITS];
    PFEPtr pH = (PFEPtr) &pTemps[4*MOC_CURVE448_NUM_UNITS];
    
    /* and a temp pf_unit buffer (2 elements in size) for multiplication and square routines */
    pf_unit *hilo = &pTemps[5*MOC_CURVE448_NUM_UNITS];
    
    /*
     Treat as an internal method (although this is called once in edDSA verify.
     Skip NULL checks and no need to check return codes of the called
     PRIMEFIELD arithmetic methods. ERR_NULL_POINTER is their only error code
     and we are certainly ok with respect to that.
     */
    
    /* Section 5.2.4 Point Addition on X448. B,E,D are the most short lived so re-use vars in pResult to store those */
    PRIMEFIELD_multiplyAux(PF_p448, pA, (PFEPtr) pP->pZ, (PFEPtr) pQ->pZ, hilo);
    PRIMEFIELD_squareAux(PF_p448, (PFEPtr) pResult->pX, pA, hilo);                                 /* store B in pResult->pX */
    PRIMEFIELD_multiplyAux(PF_p448, pC, (PFEPtr) pP->pX, (PFEPtr) pQ->pX, hilo);
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pZ, (PFEPtr) pP->pY, (PFEPtr) pQ->pY, hilo); /* store D in pResult->pZ */
    
    PRIMEFIELD_multiplyAux(PF_p448, pF, (PFEPtr) pD_448, pC, hilo);                                /* use pF as a temp var */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pY, pF, (PFEPtr) pResult->pZ, hilo);         /* store E in pResult->pY */
    
    PRIMEFIELD_subtract2(PF_p448, pF, (PFEPtr) pResult->pX, (PFEPtr) pResult->pY);
    PRIMEFIELD_add2(PF_p448, pG, (PFEPtr) pResult->pX, (PFEPtr) pResult->pY);
    
    /* done with B and E, ie pResult->pX and pResult->pY, use as temps, calculate H */
    PRIMEFIELD_add2(PF_p448, (PFEPtr) pResult->pX, (PFEPtr) pP->pX, (PFEPtr) pP->pY);
    PRIMEFIELD_add2(PF_p448, (PFEPtr) pResult->pY, (PFEPtr) pQ->pX, (PFEPtr) pQ->pY);
    PRIMEFIELD_multiplyAux(PF_p448, pH, (PFEPtr) pResult->pX, (PFEPtr) pResult->pY, hilo);
    
    /* Calculate X = A*F*(H-C-D)*/
    PRIMEFIELD_subtract(PF_p448, pH, pC);
    PRIMEFIELD_subtract(PF_p448, pH, (PFEPtr) pResult->pZ);
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pY, pF, pH, hilo);     /* use (PFEPtr) pResult->pY as temp */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, pA, (PFEPtr) pResult->pY, hilo);
    
    /* Compute Y = A*G*(D-C) */
    PRIMEFIELD_subtract2(PF_p448, pH, (PFEPtr) pResult->pZ, pC);    /* use pH as temp, done with pC */
    PRIMEFIELD_multiplyAux(PF_p448, pC, pG, pH, hilo);              /* use pC as temp */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pY, pA, pC, hilo);
    
    /* Compute Z = F*G */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pZ, pF, pG, hilo);
}


/*
 pResult = 2 * pP in the elliptic curve group.
 It is NOT ok for pResult to be the same pointer as pP or pQ.
 
 pTemps must be allocated to hold 6 temp elements.
 */
static void CURVE448_doublePoint(projPoint448 *pResult, const projPoint448 *pP, pf_unit *pTemps)
{
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
    /* 2 in Finite Field Form */
    static const pf_unit pTwo_448[MOC_CURVE448_NUM_UNITS] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0x02ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL,0x00ULL
#else
        0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#endif
    };

#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    /* We use pResult->pY/pZ as temp vars at first, need also 4 more temps */
    PFEPtr pB = (PFEPtr) pTemps;
    PFEPtr pC = (PFEPtr) &pTemps[MOC_CURVE448_NUM_UNITS];
    PFEPtr pE = (PFEPtr) &pTemps[2*MOC_CURVE448_NUM_UNITS];
    PFEPtr pJ = (PFEPtr) &pTemps[3*MOC_CURVE448_NUM_UNITS];
    
    /* and a temp pf_unit buffer (2 elements in size) for multiplication and square routines */
    pf_unit *hilo = &pTemps[4*MOC_CURVE448_NUM_UNITS];
    
    /*
     Treat as an internal method. Skip NULL checks and no need to check return
     codes of the called PRIMEFIELD arithmetic methods. ERR_NULL_POINTER is
     their only error code and we are certainly ok with respect to that.
     */
    
    /* Section 5.2.4 Point Double on X448. D and H are the most short lived so re-use vars in pResult to store those */
    PRIMEFIELD_add2(PF_p448, pC, (PFEPtr) pP->pX, (PFEPtr) pP->pY); /* use pC as a temp */
    PRIMEFIELD_squareAux(PF_p448, pB, pC, hilo);
    PRIMEFIELD_squareAux(PF_p448, pC, (PFEPtr) pP->pX, hilo);
    PRIMEFIELD_squareAux(PF_p448, (PFEPtr) pResult->pY, (PFEPtr) pP->pY, hilo);  /* store D in pResult->pY */
    PRIMEFIELD_add2(PF_p448, pE, pC, (PFEPtr) pResult->pY);
    PRIMEFIELD_squareAux(PF_p448, (PFEPtr) pResult->pZ, (PFEPtr) pP->pZ, hilo);  /* store H in pResult->pZ */
    
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, (PFEPtr) pResult->pZ, (PFEPtr) pTwo_448, hilo); /* use pResult->pX as temp */
    PRIMEFIELD_subtract2(PF_p448, (PFEPtr) pJ, pE, (PFEPtr) pResult->pX);
    
    /*   X = (B-E)*J   */
    PRIMEFIELD_subtract(PF_p448, pB, pE);
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pX, pB, (PFEPtr) pJ, hilo);
    
    /*   Y = E*(C-D)   */
    PRIMEFIELD_subtract(PF_p448, pC, (PFEPtr) pResult->pY);
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pY, pE, pC, hilo);
    
    /*   Z = E*J    */
    PRIMEFIELD_multiplyAux(PF_p448, (PFEPtr) pResult->pZ, pE, (PFEPtr) pJ, hilo);
}


static MSTATUS CURVE448_createComb(projPoint448 **ppComb, const projPoint448 *pP)
{
    MSTATUS status = OK;
    projPoint448 *pNewComb = NULL;
    
    projPoint448 *pNextPoint = NULL;
    projPoint448 *pTemp = NULL;
    pf_unit *pScratch = NULL;
    
    int i,j;
    
    /* internal method NULL input validity checks not needed */
    
    /* allocate space for a temp var and scratch, 9 field elements in size */
    status = DIGI_MALLOC( (void **) &pTemp, 9 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
    if (OK != status)
        goto exit;
    
    /* allocate space for the full comb table */
    status = DIGI_MALLOC( (void **) &pNewComb, sizeof(projPoint448) * MOCANA_ECC_448_COMB_SIZE);
    if (OK != status)
        goto exit;
    
    pScratch = (pf_unit *) (pTemp + 1); /* point pScratch to be the 6 field elements after pTemp */
    
    /* First element is the group identity O = (0,1,1), ok to ignore DIGI_MEMSET return code */
    DIGI_MEMSET((ubyte *) pNewComb, 0x00, sizeof(projPoint448));

    pNewComb[0].pY[0] = MOC_EC_ONE;
    pNewComb[0].pZ[0] = MOC_EC_ONE;
    
    /* Next element is P, ok to ignore DIGI_MEMCPY return code */
    DIGI_MEMCPY((ubyte *) (pNewComb + 1), (ubyte *) pP, sizeof(projPoint448));
    
    /* first loop: 2^d.P, 2^(2d).P,  2^(3d).P, etc... */
    for ( i = 1; i < MOCANA_ECC_448_WIN_SIZE; ++i)
    {
        pNextPoint = pNewComb + (MOC_EC_ONE << i); /* next point in the table to be calculated */

        CURVE448_doublePoint(pNextPoint, pNewComb + (MOC_EC_ONE << (i-1)), pScratch); /* begin with previous point in table */

        for (j = 1; j < (MOCANA_ECC_448_COMB_D + 1)/2; ++j)
        {
            CURVE448_doublePoint(pTemp, pNextPoint, pScratch);
            CURVE448_doublePoint(pNextPoint, pTemp, pScratch);
        }
        
#if !(MOCANA_ECC_448_COMB_D & 0x01)
        CURVE448_doublePoint(pTemp, pNextPoint, pScratch);
        DIGI_MEMCPY((ubyte *) pNextPoint, (ubyte *) pTemp, sizeof(projPoint448));
#endif
    }
    
    /* second loop: compute the remaining values by addition, pComb[i + j] = pComb[i] + pComb[j] */
    for (i = 2; i < MOCANA_ECC_448_COMB_SIZE; i *= 2)
        for ( j = 1; j < i; ++j)
            CURVE448_addPoints(pNewComb + i + j, pNewComb + i, pNewComb + j, (pf_unit *) pTemp); /* use pTemp for scratch this time (7 elements needed) */
    
    *ppComb = pNewComb;

exit:
    
    /* no goto exits after pNewComb allocation, don't need to free it on error */
    
    if (NULL != pTemp)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pTemp, 0x00, 9 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
        DIGI_FREE((void **) &pTemp);
    }
    
    return status;
}


static MSTATUS CURVE448_combMultiply(projPoint448 *pResult, const ubyte *pScalar, const projPoint448 *pComb)
{
    MSTATUS status = OK;
    projPoint448 *pTemp = NULL;
    pf_unit *pScratch = NULL;
    
    ubyte index;
    ubyte4 bitNum;
    ubyte bit;
    int i,j;
    
    /* allocate space for a temp var and scratch, 10 field elements in size */
    status = DIGI_MALLOC( (void **) &pTemp, 10 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
    if (OK != status)
        goto exit;
    
    pScratch = (pf_unit *) (pTemp + 1); /* point pScratch to be the 7 field elements after pTemp */
    
    /* set pResult to the origin O */
    DIGI_MEMSET((ubyte *) pResult, 0x00, sizeof(projPoint448));

    pResult->pY[0] = MOC_EC_ONE;
    pResult->pZ[0] = MOC_EC_ONE;
    
    /* comb method for point multiplication */
    for ( i = MOCANA_ECC_448_COMB_D - 1; i >= 0; --i)
    {
        CURVE448_doublePoint(pTemp, pResult, pScratch);
        
        index = 0;
        for (j = MOCANA_ECC_448_WIN_SIZE - 1; j >= 0; --j)
        {
            bitNum = (ubyte4) (i + j * MOCANA_ECC_448_COMB_D);
            bit = ((0x01 << (bitNum & 0x07)) & (pScalar[bitNum >> 3])) >> (bitNum & 0x07);
            index <<= 1;
            index |= bit;
        }
        
        CURVE448_addPoints(pResult, pTemp, pComb + index, pScratch);
    }
    
exit:
    
    if (NULL != pTemp)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pTemp, 0x00, 10 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
        DIGI_FREE((void **) &pTemp);
    }
    
    return status;
}

#ifndef __CURVE448_HARDWARE_ACCELERATOR__
/*
 Multiplies a point pP by a pScalar in Little Endian byte form.
 pResult must be a distinct pointer from pP.
 pScalar must be 57 bytes in length for curve448 zero padded on the right side.
 if pP is NULL then this multiplies pScalar times the curve's large cyclic group generator B.
 */
MSTATUS CURVE448_multiplyPoint(MOC_ECC(hwAccelDescr hwAccelCtx) projPoint448 *pResult, const ubyte *pScalar, const projPoint448 *pP)
{
    MSTATUS status;
    projPoint448 *pComb = NULL;
    
    if (NULL == pResult || NULL == pScalar)
        return ERR_NULL_POINTER;
    
    if (NULL != pP)
    {
        status = CURVE448_createComb(&pComb, pP);
        if (OK != status)
            goto exit;
    }
    else
#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    {
        pComb = (projPoint448 *) gpComb_448;
    }
#else
    {
        if (NULL == gpComb_448)
        {
            MSTATUS fstatus;
            
            /* The curve's large cyclic group generator B */
            static const projPoint448 pB =
#ifdef __ENABLE_DIGICERT_64_BIT__
            {
                {0x2626a82bc70cc05eULL,0x433b80e18b00938eULL,0x12ae1af72ab66511ULL,0xea6de324a3d3a464ULL,0x9e146570470f1767ULL,0x221d15a622bf36daULL,0x4f1970c66bed0dedULL},
                {0x9808795bf230fa14ULL,0xfdbd132c4ed7c8adULL,0x3ad3ff1ce67c39c4ULL,0x87789c1e05a0c2d7ULL,0x4bea73736ca39840ULL,0x8876203756c9c762ULL,0x693f46716eb6bc24ULL},
                {0x1ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL,0x0ULL}
            };
#else
            {
                {0xc70cc05e,0x2626a82b,0x8b00938e,0x433b80e1,0x2ab66511,0x12ae1af7,0xa3d3a464,0xea6de324,0x470f1767,0x9e146570,0x22bf36da,0x221d15a6,0x6bed0ded,0x4f1970c6},
                {0xf230fa14,0x9808795b,0x4ed7c8ad,0xfdbd132c,0xe67c39c4,0x3ad3ff1c,0x05a0c2d7,0x87789c1e,0x6ca39840,0x4bea7373,0x56c9c762,0x88762037,0x6eb6bc24,0x693f4671},
                {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}
            };
#endif /* __ENABLE_DIGICERT_64_BIT__ */
            
            status = RTOS_mutexWait(gpCombMutex_448);
            if (OK != status)
                goto exit;
            
            /* check again in case another thread created the comb after the first check */
            if (NULL == gpComb_448)
            {
                status = CURVE448_createComb((projPoint448 **) &gpComb_448, &pB);
            }
            
            /* release no matter what status */
            fstatus = RTOS_mutexRelease(gpCombMutex_448);
            if (OK == status)
                status = fstatus;
            
            if (OK != status)
                goto exit;
        }
        
        pComb = (projPoint448 *) gpComb_448;
    }
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
    
    status = CURVE448_combMultiply(pResult, pScalar, pComb);
    
exit:
    
    /* for either global constants or not, only delete the comb if it was not the generator point */
    if (NULL != pP && NULL != pComb)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET((ubyte *) pComb, 0x00, sizeof(projPoint448) * MOCANA_ECC_448_COMB_SIZE);
        DIGI_FREE((void **) &pComb);
    }
    
    return status;
}
#endif /* __CURVE448_HARDWARE_ACCELERATOR__ */

/*
 Converts a projective point to an encoded form in a 57 byte buffer.
 The encoded form consists of 56 bytes of the affine form Y in Little
 Endian form. The most significant bit of the 57-th byte represents the least
 significant bit of the affine X. pBuffer must have room for 57 bytes.
 */
MSTATUS CURVE448_convertProjectiveToEncoded(ubyte *pBuffer, const projPoint448 *pInput)
{
    MSTATUS status;
    int i;
    PFEPtr pXorY = NULL;
    PFEPtr pZinv = NULL;
    
    /* Treat as an internal method. Skip NULL checks */
    
    status = PRIMEFIELD_newElement(PF_p448, &pXorY);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(PF_p448, &pZinv);
    if (OK != status)
        goto exit;
    
    PRIMEFIELD_specialExp448(pZinv, (PFEPtr)pInput->pZ, TRUE);
    
    PRIMEFIELD_multiply(PF_p448, pXorY, (PFEPtr)pInput->pX, pZinv);

    pBuffer[MOC_CURVE448_BYTE_SIZE] = ((ubyte)(pXorY->units[0] & MOC_EC_ONE)) << 7;
    
    PRIMEFIELD_multiply(PF_p448, pXorY, (PFEPtr)pInput->pY, pZinv);
    
    /* now put pY in pBuffer */
    status = PRIMEFIELD_writeByteString(PF_p448, pXorY, pBuffer, MOC_CURVE448_BYTE_SIZE);
    if (OK != status)
        goto exit;
    
    /* reverse endianness */
    for (i = 0; i < MOC_CURVE448_BYTE_SIZE/2; ++i)
    {
        /* swap with xor */
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i];
        pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i] = pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i] ^ pBuffer[i];
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }
    
exit:
    
    if (NULL != pZinv)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pZinv);
    }
    if (NULL != pXorY)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pXorY);
    }
    
    return OK;
}


#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
MSTATUS CURVE448_createCombMutex(void)
{
    if (NULL == gpCombMutex_448)
    {
        return RTOS_mutexCreate(&gpCombMutex_448, EC_COMB_MUTEX, 1);
    }
    
    return OK;
}


MSTATUS CURVE448_deleteCombAndMutex(void)
{
    MSTATUS status = OK, fstatus = OK;
    
    if (NULL != gpComb_448)
    {   /* ok to ignore DIGI_MEMSET return code */
        DIGI_MEMSET((ubyte *) gpComb_448, 0x00, sizeof(projPoint448) * MOCANA_ECC_448_COMB_SIZE);
        status = DIGI_FREE((void **) &gpComb_448);
    }
    
    if (NULL != gpCombMutex_448)
    {
        fstatus = RTOS_mutexFree(&gpCombMutex_448);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */

/*****************************************************************************************/

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) && !defined(__CURVE448_X_HARDWARE_ACCELERATOR__)

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

/* Constant a24 (section 5 of rfc 7748) (Little endian words) */
static const pf_unit pA24_448[MOC_CURVE448_NUM_UNITS] =
{
#ifdef __ENABLE_DIGICERT_64_BIT__
    0x98A9ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL
#else
    0x98A9,0,0,0,0,0,0,0,0,0,0,0,0,0
#endif
};

/* masks for constant time swap vs no-swap */
static const pf_unit pPF_mask_448[2] =
{
#ifdef __ENABLE_DIGICERT_64_BIT__
    0x00ULL, 0xffffffffffffffffULL
#else
    0x00,0xffffffff
#endif
};

#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */

/*
 macro that swaps x and y if swap is 1, and is a no-op but the same runtime,
 if swap is 0. Make sure gpPF_mask_448 and dummy are defined.
 */
#define CSWAP_448( swap, x, y) \
for (k = 0; k < MOC_CURVE448_NUM_UNITS; ++k) \
{\
dummy = pPF_mask_448[swap] & (x[k] ^ y[k]); \
x[k] ^= dummy; \
y[k] ^= dummy; \
}


/*
 X448 Function from RFC 7748, section 5.
 
 pScalar and pU must be Little Endian byte arrays of length 56.
 pU is the u coordinate of a point on the Montgomery form curve
 v^2 = u^3 + Au^2 + u. The result is the u coordinate
 of the scalar point multiply scalar * (u, v) where v is not ever needed.
 pResult must have room for 56 bytes and will also be Little Endian.
 
 It is ok for pU and pResult to be the same buffer.
 */
MSTATUS CURVE448_X448(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResult, ubyte *pScalar, ubyte *pU)
{
    MSTATUS status;
    int i,j;
    ubyte4 k;
    ubyte mask = 0x80; /* begin at first bit */
    
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
    /* Constant a24 (section 5 of rfc 7748) (Little endian words) */
    static const pf_unit pA24_448[MOC_CURVE448_NUM_UNITS] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0x98A9ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL, 0x00ULL
#else
        0x98A9,0,0,0,0,0,0,0,0,0,0,0,0,0
#endif
    };
    
    /* masks for constant time swap vs no-swap */
    static const pf_unit pPF_mask_448[2] =
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        0x00ULL, 0xffffffffffffffffULL
#else
        0x00,0xffffffff
#endif
    };
    
#endif /* !defined(__ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__) */
    
    ubyte kt = 0;
    pf_unit dummy;
    ubyte swap = 0;

    PFEPtr pX1 = NULL;
    PFEPtr pX2;
    PFEPtr pZ2;
    PFEPtr pX3;
    PFEPtr pZ3;
    PFEPtr pA;
    PFEPtr pB;
    PFEPtr pAA;
    pf_unit *pHilo;
    
    ubyte pUCopy[MOC_CURVE448_BYTE_SIZE];
    ubyte pSCopy[MOC_CURVE448_BYTE_SIZE];
    
    /* Treat as an internal method. Skip NULL checks. */
    
    /* Make mutable copies of the input, swap endianness of u */
    for (i = MOC_CURVE448_BYTE_SIZE - 1; i >= 0; --i)
    {
        pUCopy[MOC_CURVE448_BYTE_SIZE - 1 - i] = pU[i];
    }
    
    status = DIGI_MEMCPY(pSCopy, pScalar, MOC_CURVE448_BYTE_SIZE);
    if (OK != status)
        goto exit;
    
    /* Prune the scalar */
    pSCopy[0] &= 0xfc;
    pSCopy[MOC_CURVE448_BYTE_SIZE - 1] |= 0x80;
    
    /* u need not be pruned */
    
    /* allocate all the temp vars in a single shot including space for a (2 element) multiplication buffer pHilo */
    status = DIGI_CALLOC((void **)&pX1, 10 * MOC_CURVE448_NUM_UNITS, sizeof(pf_unit));
    if (OK != status)
        return status;
   
    /*
     set the temp vars, recall each has an internal size of
     1 unit, so we move each ptr MOC_CURVE448_NUM_UNITS units
     */
    pX2 = (PFEPtr) &pX1[MOC_CURVE448_NUM_UNITS];
    pZ2 = (PFEPtr) &pX2[MOC_CURVE448_NUM_UNITS];
    pX3 = (PFEPtr) &pZ2[MOC_CURVE448_NUM_UNITS];
    pZ3 = (PFEPtr) &pX3[MOC_CURVE448_NUM_UNITS];
    pA = (PFEPtr) &pZ3[MOC_CURVE448_NUM_UNITS];
    pB = (PFEPtr) &pA[MOC_CURVE448_NUM_UNITS];
    pAA = (PFEPtr) &pB[MOC_CURVE448_NUM_UNITS];
    pHilo = (pf_unit *) &pAA[MOC_CURVE448_NUM_UNITS];
    
    /*
     set pX1 to pU, we use the BI_... methods directly since we allow u >= p and do
     the modular reduction if needbe.
     */
    BI_setUnitsToByteString(PF_p448->n, (pf_unit *) pX1, pUCopy, MOC_CURVE448_BYTE_SIZE);
    if (BI_cmp(PF_p448->n, (pf_unit *) pX1, PF_p448->units) >= 0)
    {
        BI_sub(PF_p448->n, (pf_unit *) pX1, PF_p448->units);
    }
    
    /* pZ2 is already 0, also set pX2, pX3, pZ3 */
    ((pf_unit *)pX2)[0] = MOC_EC_ONE;
    ((pf_unit *)pZ3)[0] = MOC_EC_ONE;
    
    PRIMEFIELD_copyElement(PF_p448, pX3, pX1);
    
    for (i = MOC_CURVE448_BYTE_SIZE - 1; i >= 0; --i)
    {
        for (j = 0; j < 8; ++j, mask >>= 1)
        {
            kt = (mask & pSCopy[i]) >> (7-j);
            swap ^= kt;
            
            CSWAP_448(swap, ((pf_unit *) pX2), ((pf_unit *) pX3));
            CSWAP_448(swap, ((pf_unit *) pZ2), ((pf_unit *) pZ3));
            
            swap = kt;
            
            /* ok to ignore return codes of arithmetic methods */
            
            PRIMEFIELD_add2(PF_p448,pA, pX2, pZ2);
            PRIMEFIELD_subtract2(PF_p448, pB, pX2, pZ2);
            
            /* reuse pX2 as C */
            PRIMEFIELD_add2(PF_p448, pX2, pX3, pZ3);
            
            /* reuse pZ2 as D */
            PRIMEFIELD_subtract2(PF_p448, pZ2, pX3, pZ3);
            
            /* re-use pX3 as DA */
            PRIMEFIELD_multiplyAux(PF_p448, pX3, pZ2, pA, pHilo);
            
            /* re-use pZ3 as CB */
            PRIMEFIELD_multiplyAux(PF_p448, pZ3, pX2, pB, pHilo);
            
            /* use pAA as AA */
            PRIMEFIELD_squareAux(PF_p448, pAA, pA, pHilo);
            
            /* re-use pZ2 as BB */
            PRIMEFIELD_squareAux(PF_p448, pZ2, pB, pHilo);
            
            /* Use pA and pB as temps */
            PRIMEFIELD_add2(PF_p448, pA, pX3, pZ3);
            PRIMEFIELD_subtract2(PF_p448, pB, pX3, pZ3);
            
            /* Final pX3 calculation */
            PRIMEFIELD_squareAux(PF_p448, pX3, pA, pHilo);
            
            /* Final PZ3 calculation */
            PRIMEFIELD_squareAux(PF_p448, pA, pB, pHilo);
            PRIMEFIELD_multiplyAux(PF_p448, pZ3, pX1, pA, pHilo);
            
            /* Final PX2 calculation */
            PRIMEFIELD_multiplyAux(PF_p448, pX2, pAA, pZ2, pHilo);
            
            /* Final pZ2 calculation, use pA as E, re-use pB as temp */
            PRIMEFIELD_subtract2(PF_p448, pA, pAA, pZ2);
            PRIMEFIELD_multiplyAux(PF_p448, pB, (PFEPtr) pA24_448, pA, pHilo);
            PRIMEFIELD_add(PF_p448, pAA, pB);  /* inplace ok, re-use pAA */
            PRIMEFIELD_multiplyAux(PF_p448, pZ2, pAA, pA, pHilo);
            
        }
        mask = 0x80;
    }
    
    CSWAP_448(swap, ((pf_unit *) pX2), ((pf_unit *) pX3));
    CSWAP_448(swap, ((pf_unit *) pZ2), ((pf_unit *) pZ3));
    
    /* use pA as a temp, compute the result x2 * z2^-1 */
    status = PRIMEFIELD_specialExp448(pA, pZ2, TRUE);
    if (OK != status)
        goto exit;
    
    PRIMEFIELD_multiplyAux(PF_p448, pAA, pX2, pA, pHilo); /* re-use pAA as the result */
    
    status = PRIMEFIELD_writeByteString(PF_p448, pAA, pResult, MOC_CURVE448_BYTE_SIZE);

    /* swap pResult to Little Endian (regardless of last status) */
    for (i = 0; i < MOC_CURVE448_BYTE_SIZE/2; ++i)
    {
        pResult[i] = pResult[i] ^ pResult[MOC_CURVE448_BYTE_SIZE - 1 - i];
        pResult[MOC_CURVE448_BYTE_SIZE - 1 - i] = pResult[MOC_CURVE448_BYTE_SIZE - 1 - i] ^ pResult[i];
        pResult[i] = pResult[i] ^ pResult[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }

exit:
    
     /* don't change status */
    if (NULL != pX1)
    {
        DIGI_MEMSET((ubyte *) pX1, 0x00, 10 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
        DIGI_FREE((void**) &pX1); /* don't change status */
    }
    if (OK != status && NULL != pResult)
    {
        DIGI_MEMSET((ubyte *) pResult, 0x00, MOC_CURVE448_BYTE_SIZE);
    }
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDH_448__) && !defined(__CURVE448_X_HARDWARE_ACCELERATOR__) */
#endif /* __ENABLE_DIGICERT_ECC__ */
