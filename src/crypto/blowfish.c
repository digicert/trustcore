/*
 * blowfish.c
 *
 * Blowfish Encipher & Decipher Block Encryption
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

/**
@file       blowfish.c
@brief      C source code for the NanoCrypto Blowfish API.
@details    This file contains the NanoCrypto Blowfish API functions.

@copydoc    overview_blowfish

@flags
There are no flag dependencies to enable the Blowfish functions.

@filedoc    blowfish.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLOWFISH_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_BLOWFISH_CIPHERS__) && !defined(__BLOWFISH_HARDWARE_CIPHER__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/blowfish.h"


/*------------------------------------------------------------------*/

#define N               16


/*------------------------------------------------------------------*/

static ubyte4 bfp[] =
{
    0x243f6a88LU, 0x85a308d3LU, 0x13198a2eLU, 0x03707344LU,
    0xa4093822LU, 0x299f31d0LU, 0x082efa98LU, 0xec4e6c89LU,
    0x452821e6LU, 0x38d01377LU, 0xbe5466cfLU, 0x34e90c6cLU,
    0xc0ac29b7LU, 0xc97c50ddLU, 0x3f84d5b5LU, 0xb5470917LU,
    0x9216d5d9LU, 0x8979fb1bLU
};


/*------------------------------------------------------------------*/

static ubyte4 ks0[] =
{
    0xd1310ba6LU, 0x98dfb5acLU, 0x2ffd72dbLU, 0xd01adfb7LU,
    0xb8e1afedLU, 0x6a267e96LU, 0xba7c9045LU, 0xf12c7f99LU,
    0x24a19947LU, 0xb3916cf7LU, 0x0801f2e2LU, 0x858efc16LU,
    0x636920d8LU, 0x71574e69LU, 0xa458fea3LU, 0xf4933d7eLU,
    0x0d95748fLU, 0x728eb658LU, 0x718bcd58LU, 0x82154aeeLU,
    0x7b54a41dLU, 0xc25a59b5LU, 0x9c30d539LU, 0x2af26013LU,
    0xc5d1b023LU, 0x286085f0LU, 0xca417918LU, 0xb8db38efLU,
    0x8e79dcb0LU, 0x603a180eLU, 0x6c9e0e8bLU, 0xb01e8a3eLU,
    0xd71577c1LU, 0xbd314b27LU, 0x78af2fdaLU, 0x55605c60LU,
    0xe65525f3LU, 0xaa55ab94LU, 0x57489862LU, 0x63e81440LU,
    0x55ca396aLU, 0x2aab10b6LU, 0xb4cc5c34LU, 0x1141e8ceLU,
    0xa15486afLU, 0x7c72e993LU, 0xb3ee1411LU, 0x636fbc2aLU,
    0x2ba9c55dLU, 0x741831f6LU, 0xce5c3e16LU, 0x9b87931eLU,
    0xafd6ba33LU, 0x6c24cf5cLU, 0x7a325381LU, 0x28958677LU,
    0x3b8f4898LU, 0x6b4bb9afLU, 0xc4bfe81bLU, 0x66282193LU,
    0x61d809ccLU, 0xfb21a991LU, 0x487cac60LU, 0x5dec8032LU,
    0xef845d5dLU, 0xe98575b1LU, 0xdc262302LU, 0xeb651b88LU,
    0x23893e81LU, 0xd396acc5LU, 0x0f6d6ff3LU, 0x83f44239LU,
    0x2e0b4482LU, 0xa4842004LU, 0x69c8f04aLU, 0x9e1f9b5eLU,
    0x21c66842LU, 0xf6e96c9aLU, 0x670c9c61LU, 0xabd388f0LU,
    0x6a51a0d2LU, 0xd8542f68LU, 0x960fa728LU, 0xab5133a3LU,
    0x6eef0b6cLU, 0x137a3be4LU, 0xba3bf050LU, 0x7efb2a98LU,
    0xa1f1651dLU, 0x39af0176LU, 0x66ca593eLU, 0x82430e88LU,
    0x8cee8619LU, 0x456f9fb4LU, 0x7d84a5c3LU, 0x3b8b5ebeLU,
    0xe06f75d8LU, 0x85c12073LU, 0x401a449fLU, 0x56c16aa6LU,
    0x4ed3aa62LU, 0x363f7706LU, 0x1bfedf72LU, 0x429b023dLU,
    0x37d0d724LU, 0xd00a1248LU, 0xdb0fead3LU, 0x49f1c09bLU,
    0x075372c9LU, 0x80991b7bLU, 0x25d479d8LU, 0xf6e8def7LU,
    0xe3fe501aLU, 0xb6794c3bLU, 0x976ce0bdLU, 0x04c006baLU,
    0xc1a94fb6LU, 0x409f60c4LU, 0x5e5c9ec2LU, 0x196a2463LU,
    0x68fb6fafLU, 0x3e6c53b5LU, 0x1339b2ebLU, 0x3b52ec6fLU,
    0x6dfc511fLU, 0x9b30952cLU, 0xcc814544LU, 0xaf5ebd09LU,
    0xbee3d004LU, 0xde334afdLU, 0x660f2807LU, 0x192e4bb3LU,
    0xc0cba857LU, 0x45c8740fLU, 0xd20b5f39LU, 0xb9d3fbdbLU,
    0x5579c0bdLU, 0x1a60320aLU, 0xd6a100c6LU, 0x402c7279LU,
    0x679f25feLU, 0xfb1fa3ccLU, 0x8ea5e9f8LU, 0xdb3222f8LU,
    0x3c7516dfLU, 0xfd616b15LU, 0x2f501ec8LU, 0xad0552abLU,
    0x323db5faLU, 0xfd238760LU, 0x53317b48LU, 0x3e00df82LU,
    0x9e5c57bbLU, 0xca6f8ca0LU, 0x1a87562eLU, 0xdf1769dbLU,
    0xd542a8f6LU, 0x287effc3LU, 0xac6732c6LU, 0x8c4f5573LU,
    0x695b27b0LU, 0xbbca58c8LU, 0xe1ffa35dLU, 0xb8f011a0LU,
    0x10fa3d98LU, 0xfd2183b8LU, 0x4afcb56cLU, 0x2dd1d35bLU,
    0x9a53e479LU, 0xb6f84565LU, 0xd28e49bcLU, 0x4bfb9790LU,
    0xe1ddf2daLU, 0xa4cb7e33LU, 0x62fb1341LU, 0xcee4c6e8LU,
    0xef20cadaLU, 0x36774c01LU, 0xd07e9efeLU, 0x2bf11fb4LU,
    0x95dbda4dLU, 0xae909198LU, 0xeaad8e71LU, 0x6b93d5a0LU,
    0xd08ed1d0LU, 0xafc725e0LU, 0x8e3c5b2fLU, 0x8e7594b7LU,
    0x8ff6e2fbLU, 0xf2122b64LU, 0x8888b812LU, 0x900df01cLU,
    0x4fad5ea0LU, 0x688fc31cLU, 0xd1cff191LU, 0xb3a8c1adLU,
    0x2f2f2218LU, 0xbe0e1777LU, 0xea752dfeLU, 0x8b021fa1LU,
    0xe5a0cc0fLU, 0xb56f74e8LU, 0x18acf3d6LU, 0xce89e299LU,
    0xb4a84fe0LU, 0xfd13e0b7LU, 0x7cc43b81LU, 0xd2ada8d9LU,
    0x165fa266LU, 0x80957705LU, 0x93cc7314LU, 0x211a1477LU,
    0xe6ad2065LU, 0x77b5fa86LU, 0xc75442f5LU, 0xfb9d35cfLU,
    0xebcdaf0cLU, 0x7b3e89a0LU, 0xd6411bd3LU, 0xae1e7e49LU,
    0x00250e2dLU, 0x2071b35eLU, 0x226800bbLU, 0x57b8e0afLU,
    0x2464369bLU, 0xf009b91eLU, 0x5563911dLU, 0x59dfa6aaLU,
    0x78c14389LU, 0xd95a537fLU, 0x207d5ba2LU, 0x02e5b9c5LU,
    0x83260376LU, 0x6295cfa9LU, 0x11c81968LU, 0x4e734a41LU,
    0xb3472dcaLU, 0x7b14a94aLU, 0x1b510052LU, 0x9a532915LU,
    0xd60f573fLU, 0xbc9bc6e4LU, 0x2b60a476LU, 0x81e67400LU,
    0x08ba6fb5LU, 0x571be91fLU, 0xf296ec6bLU, 0x2a0dd915LU,
    0xb6636521LU, 0xe7b9f9b6LU, 0xff34052eLU, 0xc5855664LU,
    0x53b02d5dLU, 0xa99f8fa1LU, 0x08ba4799LU, 0x6e85076aLU
};


/*------------------------------------------------------------------*/

static ubyte4 ks1[]=
{
    0x4b7a70e9LU, 0xb5b32944LU, 0xdb75092eLU, 0xc4192623LU,
    0xad6ea6b0LU, 0x49a7df7dLU, 0x9cee60b8LU, 0x8fedb266LU,
    0xecaa8c71LU, 0x699a17ffLU, 0x5664526cLU, 0xc2b19ee1LU,
    0x193602a5LU, 0x75094c29LU, 0xa0591340LU, 0xe4183a3eLU,
    0x3f54989aLU, 0x5b429d65LU, 0x6b8fe4d6LU, 0x99f73fd6LU,
    0xa1d29c07LU, 0xefe830f5LU, 0x4d2d38e6LU, 0xf0255dc1LU,
    0x4cdd2086LU, 0x8470eb26LU, 0x6382e9c6LU, 0x021ecc5eLU,
    0x09686b3fLU, 0x3ebaefc9LU, 0x3c971814LU, 0x6b6a70a1LU,
    0x687f3584LU, 0x52a0e286LU, 0xb79c5305LU, 0xaa500737LU,
    0x3e07841cLU, 0x7fdeae5cLU, 0x8e7d44ecLU, 0x5716f2b8LU,
    0xb03ada37LU, 0xf0500c0dLU, 0xf01c1f04LU, 0x0200b3ffLU,
    0xae0cf51aLU, 0x3cb574b2LU, 0x25837a58LU, 0xdc0921bdLU,
    0xd19113f9LU, 0x7ca92ff6LU, 0x94324773LU, 0x22f54701LU,
    0x3ae5e581LU, 0x37c2dadcLU, 0xc8b57634LU, 0x9af3dda7LU,
    0xa9446146LU, 0x0fd0030eLU, 0xecc8c73eLU, 0xa4751e41LU,
    0xe238cd99LU, 0x3bea0e2fLU, 0x3280bba1LU, 0x183eb331LU,
    0x4e548b38LU, 0x4f6db908LU, 0x6f420d03LU, 0xf60a04bfLU,
    0x2cb81290LU, 0x24977c79LU, 0x5679b072LU, 0xbcaf89afLU,
    0xde9a771fLU, 0xd9930810LU, 0xb38bae12LU, 0xdccf3f2eLU,
    0x5512721fLU, 0x2e6b7124LU, 0x501adde6LU, 0x9f84cd87LU,
    0x7a584718LU, 0x7408da17LU, 0xbc9f9abcLU, 0xe94b7d8cLU,
    0xec7aec3aLU, 0xdb851dfaLU, 0x63094366LU, 0xc464c3d2LU,
    0xef1c1847LU, 0x3215d908LU, 0xdd433b37LU, 0x24c2ba16LU,
    0x12a14d43LU, 0x2a65c451LU, 0x50940002LU, 0x133ae4ddLU,
    0x71dff89eLU, 0x10314e55LU, 0x81ac77d6LU, 0x5f11199bLU,
    0x043556f1LU, 0xd7a3c76bLU, 0x3c11183bLU, 0x5924a509LU,
    0xf28fe6edLU, 0x97f1fbfaLU, 0x9ebabf2cLU, 0x1e153c6eLU,
    0x86e34570LU, 0xeae96fb1LU, 0x860e5e0aLU, 0x5a3e2ab3LU,
    0x771fe71cLU, 0x4e3d06faLU, 0x2965dcb9LU, 0x99e71d0fLU,
    0x803e89d6LU, 0x5266c825LU, 0x2e4cc978LU, 0x9c10b36aLU,
    0xc6150ebaLU, 0x94e2ea78LU, 0xa5fc3c53LU, 0x1e0a2df4LU,
    0xf2f74ea7LU, 0x361d2b3dLU, 0x1939260fLU, 0x19c27960LU,
    0x5223a708LU, 0xf71312b6LU, 0xebadfe6eLU, 0xeac31f66LU,
    0xe3bc4595LU, 0xa67bc883LU, 0xb17f37d1LU, 0x018cff28LU,
    0xc332ddefLU, 0xbe6c5aa5LU, 0x65582185LU, 0x68ab9802LU,
    0xeecea50fLU, 0xdb2f953bLU, 0x2aef7dadLU, 0x5b6e2f84LU,
    0x1521b628LU, 0x29076170LU, 0xecdd4775LU, 0x619f1510LU,
    0x13cca830LU, 0xeb61bd96LU, 0x0334fe1eLU, 0xaa0363cfLU,
    0xb5735c90LU, 0x4c70a239LU, 0xd59e9e0bLU, 0xcbaade14LU,
    0xeecc86bcLU, 0x60622ca7LU, 0x9cab5cabLU, 0xb2f3846eLU,
    0x648b1eafLU, 0x19bdf0caLU, 0xa02369b9LU, 0x655abb50LU,
    0x40685a32LU, 0x3c2ab4b3LU, 0x319ee9d5LU, 0xc021b8f7LU,
    0x9b540b19LU, 0x875fa099LU, 0x95f7997eLU, 0x623d7da8LU,
    0xf837889aLU, 0x97e32d77LU, 0x11ed935fLU, 0x16681281LU,
    0x0e358829LU, 0xc7e61fd6LU, 0x96dedfa1LU, 0x7858ba99LU,
    0x57f584a5LU, 0x1b227263LU, 0x9b83c3ffLU, 0x1ac24696LU,
    0xcdb30aebLU, 0x532e3054LU, 0x8fd948e4LU, 0x6dbc3128LU,
    0x58ebf2efLU, 0x34c6ffeaLU, 0xfe28ed61LU, 0xee7c3c73LU,
    0x5d4a14d9LU, 0xe864b7e3LU, 0x42105d14LU, 0x203e13e0LU,
    0x45eee2b6LU, 0xa3aaabeaLU, 0xdb6c4f15LU, 0xfacb4fd0LU,
    0xc742f442LU, 0xef6abbb5LU, 0x654f3b1dLU, 0x41cd2105LU,
    0xd81e799eLU, 0x86854dc7LU, 0xe44b476aLU, 0x3d816250LU,
    0xcf62a1f2LU, 0x5b8d2646LU, 0xfc8883a0LU, 0xc1c7b6a3LU,
    0x7f1524c3LU, 0x69cb7492LU, 0x47848a0bLU, 0x5692b285LU,
    0x095bbf00LU, 0xad19489dLU, 0x1462b174LU, 0x23820e00LU,
    0x58428d2aLU, 0x0c55f5eaLU, 0x1dadf43eLU, 0x233f7061LU,
    0x3372f092LU, 0x8d937e41LU, 0xd65fecf1LU, 0x6c223bdbLU,
    0x7cde3759LU, 0xcbee7460LU, 0x4085f2a7LU, 0xce77326eLU,
    0xa6078084LU, 0x19f8509eLU, 0xe8efd855LU, 0x61d99735LU,
    0xa969a7aaLU, 0xc50c06c2LU, 0x5a04abfcLU, 0x800bcadcLU,
    0x9e447a2eLU, 0xc3453484LU, 0xfdd56705LU, 0x0e1e9ec9LU,
    0xdb73dbd3LU, 0x105588cdLU, 0x675fda79LU, 0xe3674340LU,
    0xc5c43465LU, 0x713e38d8LU, 0x3d28f89eLU, 0xf16dff20LU,
    0x153e21e7LU, 0x8fb03d4aLU, 0xe6e39f2bLU, 0xdb83adf7LU
};


/*------------------------------------------------------------------*/

static ubyte4 ks2[] =
{
    0xe93d5a68LU, 0x948140f7LU, 0xf64c261cLU, 0x94692934LU,
    0x411520f7LU, 0x7602d4f7LU, 0xbcf46b2eLU, 0xd4a20068LU,
    0xd4082471LU, 0x3320f46aLU, 0x43b7d4b7LU, 0x500061afLU,
    0x1e39f62eLU, 0x97244546LU, 0x14214f74LU, 0xbf8b8840LU,
    0x4d95fc1dLU, 0x96b591afLU, 0x70f4ddd3LU, 0x66a02f45LU,
    0xbfbc09ecLU, 0x03bd9785LU, 0x7fac6dd0LU, 0x31cb8504LU,
    0x96eb27b3LU, 0x55fd3941LU, 0xda2547e6LU, 0xabca0a9aLU,
    0x28507825LU, 0x530429f4LU, 0x0a2c86daLU, 0xe9b66dfbLU,
    0x68dc1462LU, 0xd7486900LU, 0x680ec0a4LU, 0x27a18deeLU,
    0x4f3ffea2LU, 0xe887ad8cLU, 0xb58ce006LU, 0x7af4d6b6LU,
    0xaace1e7cLU, 0xd3375fecLU, 0xce78a399LU, 0x406b2a42LU,
    0x20fe9e35LU, 0xd9f385b9LU, 0xee39d7abLU, 0x3b124e8bLU,
    0x1dc9faf7LU, 0x4b6d1856LU, 0x26a36631LU, 0xeae397b2LU,
    0x3a6efa74LU, 0xdd5b4332LU, 0x6841e7f7LU, 0xca7820fbLU,
    0xfb0af54eLU, 0xd8feb397LU, 0x454056acLU, 0xba489527LU,
    0x55533a3aLU, 0x20838d87LU, 0xfe6ba9b7LU, 0xd096954bLU,
    0x55a867bcLU, 0xa1159a58LU, 0xcca92963LU, 0x99e1db33LU,
    0xa62a4a56LU, 0x3f3125f9LU, 0x5ef47e1cLU, 0x9029317cLU,
    0xfdf8e802LU, 0x04272f70LU, 0x80bb155cLU, 0x05282ce3LU,
    0x95c11548LU, 0xe4c66d22LU, 0x48c1133fLU, 0xc70f86dcLU,
    0x07f9c9eeLU, 0x41041f0fLU, 0x404779a4LU, 0x5d886e17LU,
    0x325f51ebLU, 0xd59bc0d1LU, 0xf2bcc18fLU, 0x41113564LU,
    0x257b7834LU, 0x602a9c60LU, 0xdff8e8a3LU, 0x1f636c1bLU,
    0x0e12b4c2LU, 0x02e1329eLU, 0xaf664fd1LU, 0xcad18115LU,
    0x6b2395e0LU, 0x333e92e1LU, 0x3b240b62LU, 0xeebeb922LU,
    0x85b2a20eLU, 0xe6ba0d99LU, 0xde720c8cLU, 0x2da2f728LU,
    0xd0127845LU, 0x95b794fdLU, 0x647d0862LU, 0xe7ccf5f0LU,
    0x5449a36fLU, 0x877d48faLU, 0xc39dfd27LU, 0xf33e8d1eLU,
    0x0a476341LU, 0x992eff74LU, 0x3a6f6eabLU, 0xf4f8fd37LU,
    0xa812dc60LU, 0xa1ebddf8LU, 0x991be14cLU, 0xdb6e6b0dLU,
    0xc67b5510LU, 0x6d672c37LU, 0x2765d43bLU, 0xdcd0e804LU,
    0xf1290dc7LU, 0xcc00ffa3LU, 0xb5390f92LU, 0x690fed0bLU,
    0x667b9ffbLU, 0xcedb7d9cLU, 0xa091cf0bLU, 0xd9155ea3LU,
    0xbb132f88LU, 0x515bad24LU, 0x7b9479bfLU, 0x763bd6ebLU,
    0x37392eb3LU, 0xcc115979LU, 0x8026e297LU, 0xf42e312dLU,
    0x6842ada7LU, 0xc66a2b3bLU, 0x12754cccLU, 0x782ef11cLU,
    0x6a124237LU, 0xb79251e7LU, 0x06a1bbe6LU, 0x4bfb6350LU,
    0x1a6b1018LU, 0x11caedfaLU, 0x3d25bdd8LU, 0xe2e1c3c9LU,
    0x44421659LU, 0x0a121386LU, 0xd90cec6eLU, 0xd5abea2aLU,
    0x64af674eLU, 0xda86a85fLU, 0xbebfe988LU, 0x64e4c3feLU,
    0x9dbc8057LU, 0xf0f7c086LU, 0x60787bf8LU, 0x6003604dLU,
    0xd1fd8346LU, 0xf6381fb0LU, 0x7745ae04LU, 0xd736fcccLU,
    0x83426b33LU, 0xf01eab71LU, 0xb0804187LU, 0x3c005e5fLU,
    0x77a057beLU, 0xbde8ae24LU, 0x55464299LU, 0xbf582e61LU,
    0x4e58f48fLU, 0xf2ddfda2LU, 0xf474ef38LU, 0x8789bdc2LU,
    0x5366f9c3LU, 0xc8b38e74LU, 0xb475f255LU, 0x46fcd9b9LU,
    0x7aeb2661LU, 0x8b1ddf84LU, 0x846a0e79LU, 0x915f95e2LU,
    0x466e598eLU, 0x20b45770LU, 0x8cd55591LU, 0xc902de4cLU,
    0xb90bace1LU, 0xbb8205d0LU, 0x11a86248LU, 0x7574a99eLU,
    0xb77f19b6LU, 0xe0a9dc09LU, 0x662d09a1LU, 0xc4324633LU,
    0xe85a1f02LU, 0x09f0be8cLU, 0x4a99a025LU, 0x1d6efe10LU,
    0x1ab93d1dLU, 0x0ba5a4dfLU, 0xa186f20fLU, 0x2868f169LU,
    0xdcb7da83LU, 0x573906feLU, 0xa1e2ce9bLU, 0x4fcd7f52LU,
    0x50115e01LU, 0xa70683faLU, 0xa002b5c4LU, 0x0de6d027LU,
    0x9af88c27LU, 0x773f8641LU, 0xc3604c06LU, 0x61a806b5LU,
    0xf0177a28LU, 0xc0f586e0LU, 0x006058aaLU, 0x30dc7d62LU,
    0x11e69ed7LU, 0x2338ea63LU, 0x53c2dd94LU, 0xc2c21634LU,
    0xbbcbee56LU, 0x90bcb6deLU, 0xebfc7da1LU, 0xce591d76LU,
    0x6f05e409LU, 0x4b7c0188LU, 0x39720a3dLU, 0x7c927c24LU,
    0x86e3725fLU, 0x724d9db9LU, 0x1ac15bb4LU, 0xd39eb8fcLU,
    0xed545578LU, 0x08fca5b5LU, 0xd83d7cd3LU, 0x4dad0fc4LU,
    0x1e50ef5eLU, 0xb161e6f8LU, 0xa28514d9LU, 0x6c51133cLU,
    0x6fd5c7e7LU, 0x56e14ec4LU, 0x362abfceLU, 0xddc6c837LU,
    0xd79a3234LU, 0x92638212LU, 0x670efa8eLU, 0x406000e0LU
};


/*------------------------------------------------------------------*/

static ubyte4 ks3[] =
{
    0x3a39ce37LU, 0xd3faf5cfLU, 0xabc27737LU, 0x5ac52d1bLU,
    0x5cb0679eLU, 0x4fa33742LU, 0xd3822740LU, 0x99bc9bbeLU,
    0xd5118e9dLU, 0xbf0f7315LU, 0xd62d1c7eLU, 0xc700c47bLU,
    0xb78c1b6bLU, 0x21a19045LU, 0xb26eb1beLU, 0x6a366eb4LU,
    0x5748ab2fLU, 0xbc946e79LU, 0xc6a376d2LU, 0x6549c2c8LU,
    0x530ff8eeLU, 0x468dde7dLU, 0xd5730a1dLU, 0x4cd04dc6LU,
    0x2939bbdbLU, 0xa9ba4650LU, 0xac9526e8LU, 0xbe5ee304LU,
    0xa1fad5f0LU, 0x6a2d519aLU, 0x63ef8ce2LU, 0x9a86ee22LU,
    0xc089c2b8LU, 0x43242ef6LU, 0xa51e03aaLU, 0x9cf2d0a4LU,
    0x83c061baLU, 0x9be96a4dLU, 0x8fe51550LU, 0xba645bd6LU,
    0x2826a2f9LU, 0xa73a3ae1LU, 0x4ba99586LU, 0xef5562e9LU,
    0xc72fefd3LU, 0xf752f7daLU, 0x3f046f69LU, 0x77fa0a59LU,
    0x80e4a915LU, 0x87b08601LU, 0x9b09e6adLU, 0x3b3ee593LU,
    0xe990fd5aLU, 0x9e34d797LU, 0x2cf0b7d9LU, 0x022b8b51LU,
    0x96d5ac3aLU, 0x017da67dLU, 0xd1cf3ed6LU, 0x7c7d2d28LU,
    0x1f9f25cfLU, 0xadf2b89bLU, 0x5ad6b472LU, 0x5a88f54cLU,
    0xe029ac71LU, 0xe019a5e6LU, 0x47b0acfdLU, 0xed93fa9bLU,
    0xe8d3c48dLU, 0x283b57ccLU, 0xf8d56629LU, 0x79132e28LU,
    0x785f0191LU, 0xed756055LU, 0xf7960e44LU, 0xe3d35e8cLU,
    0x15056dd4LU, 0x88f46dbaLU, 0x03a16125LU, 0x0564f0bdLU,
    0xc3eb9e15LU, 0x3c9057a2LU, 0x97271aecLU, 0xa93a072aLU,
    0x1b3f6d9bLU, 0x1e6321f5LU, 0xf59c66fbLU, 0x26dcf319LU,
    0x7533d928LU, 0xb155fdf5LU, 0x03563482LU, 0x8aba3cbbLU,
    0x28517711LU, 0xc20ad9f8LU, 0xabcc5167LU, 0xccad925fLU,
    0x4de81751LU, 0x3830dc8eLU, 0x379d5862LU, 0x9320f991LU,
    0xea7a90c2LU, 0xfb3e7bceLU, 0x5121ce64LU, 0x774fbe32LU,
    0xa8b6e37eLU, 0xc3293d46LU, 0x48de5369LU, 0x6413e680LU,
    0xa2ae0810LU, 0xdd6db224LU, 0x69852dfdLU, 0x09072166LU,
    0xb39a460aLU, 0x6445c0ddLU, 0x586cdecfLU, 0x1c20c8aeLU,
    0x5bbef7ddLU, 0x1b588d40LU, 0xccd2017fLU, 0x6bb4e3bbLU,
    0xdda26a7eLU, 0x3a59ff45LU, 0x3e350a44LU, 0xbcb4cdd5LU,
    0x72eacea8LU, 0xfa6484bbLU, 0x8d6612aeLU, 0xbf3c6f47LU,
    0xd29be463LU, 0x542f5d9eLU, 0xaec2771bLU, 0xf64e6370LU,
    0x740e0d8dLU, 0xe75b1357LU, 0xf8721671LU, 0xaf537d5dLU,
    0x4040cb08LU, 0x4eb4e2ccLU, 0x34d2466aLU, 0x0115af84LU,
    0xe1b00428LU, 0x95983a1dLU, 0x06b89fb4LU, 0xce6ea048LU,
    0x6f3f3b82LU, 0x3520ab82LU, 0x011a1d4bLU, 0x277227f8LU,
    0x611560b1LU, 0xe7933fdcLU, 0xbb3a792bLU, 0x344525bdLU,
    0xa08839e1LU, 0x51ce794bLU, 0x2f32c9b7LU, 0xa01fbac9LU,
    0xe01cc87eLU, 0xbcc7d1f6LU, 0xcf0111c3LU, 0xa1e8aac7LU,
    0x1a908749LU, 0xd44fbd9aLU, 0xd0dadecbLU, 0xd50ada38LU,
    0x0339c32aLU, 0xc6913667LU, 0x8df9317cLU, 0xe0b12b4fLU,
    0xf79e59b7LU, 0x43f5bb3aLU, 0xf2d519ffLU, 0x27d9459cLU,
    0xbf97222cLU, 0x15e6fc2aLU, 0x0f91fc71LU, 0x9b941525LU,
    0xfae59361LU, 0xceb69cebLU, 0xc2a86459LU, 0x12baa8d1LU,
    0xb6c1075eLU, 0xe3056a0cLU, 0x10d25065LU, 0xcb03a442LU,
    0xe0ec6e0eLU, 0x1698db3bLU, 0x4c98a0beLU, 0x3278e964LU,
    0x9f1f9532LU, 0xe0d392dfLU, 0xd3a0342bLU, 0x8971f21eLU,
    0x1b0a7441LU, 0x4ba3348cLU, 0xc5be7120LU, 0xc37632d8LU,
    0xdf359f8dLU, 0x9b992f2eLU, 0xe60b6f47LU, 0x0fe3f11dLU,
    0xe54cda54LU, 0x1edad891LU, 0xce6279cfLU, 0xcd3e7e6fLU,
    0x1618b166LU, 0xfd2c1d05LU, 0x848fd2c5LU, 0xf6fb2299LU,
    0xf523f357LU, 0xa6327623LU, 0x93a83531LU, 0x56cccd02LU,
    0xacf08162LU, 0x5a75ebb5LU, 0x6e163697LU, 0x88d273ccLU,
    0xde966292LU, 0x81b949d0LU, 0x4c50901bLU, 0x71c65614LU,
    0xe6c6c7bdLU, 0x327a140aLU, 0x45e1d006LU, 0xc3f27b9aLU,
    0xc9aa53fdLU, 0x62a80f00LU, 0xbb25bfe2LU, 0x35bdd2f6LU,
    0x71126905LU, 0xb2040222LU, 0xb6cbcf7cLU, 0xcd769c2bLU,
    0x53113ec0LU, 0x1640e3d3LU, 0x38abbd60LU, 0x2547adf0LU,
    0xba38209cLU, 0xf746ce76LU, 0x77afa1c5LU, 0x20756060LU,
    0x85cbfe4eLU, 0x8ae88dd8LU, 0x7aaaf9b0LU, 0x4cf9aa7eLU,
    0x1948c25cLU, 0x02fb8a8cLU, 0x01c36ae4LU, 0xd6ebe1f9LU,
    0x90d4f869LU, 0xa65cdea0LU, 0x3f09252dLU, 0xc208e69fLU,
    0xb74e6132LU, 0xce77e25bLU, 0x578fdfe3LU, 0x3ac372e6LU
};

/*------------------------------------------------------------------*/

static ubyte4
F(blf_ctx *bc, ubyte4 x)
{
    ubyte4  a;
    ubyte4  b;
    ubyte4  c;
    ubyte4  d;
    ubyte4  y;

    d = x & 0x00FF;
    x >>= 8;
    c = x & 0x00FF;
    x >>= 8;
    b = x & 0x00FF;
    x >>= 8;
    a = x & 0x00FF;
    y = bc->S[0][a] + bc->S[1][b];
    y = y ^ bc->S[2][c];
    y = y + bc->S[3][d];

    return y;
}


/*------------------------------------------------------------------*/

static void
Blowfish_encipher(blf_ctx *bc, ubyte4 *xl, ubyte4 *xr)
{
    ubyte4  Xl;
    ubyte4  Xr;
    ubyte4  temp;
    sbyte2  i;

    Xl = *xl;
    Xr = *xr;

    for (i = 0; i < N; ++i)
    {
        Xl = Xl ^ bc->P[i];
        Xr = F(bc, Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ bc->P[N];
    Xl = Xl ^ bc->P[N + 1];

    *xl = Xl;
    *xr = Xr;
}


/*------------------------------------------------------------------*/

static void
Blowfish_decipher(blf_ctx *bc, ubyte4 *xl, ubyte4 *xr)
{
    ubyte4  Xl;
    ubyte4  Xr;
    ubyte4  temp;
    sbyte2  i;

    Xl = *xl;
    Xr = *xr;

    for (i = N + 1; i > 1; --i)
    {
        Xl = Xl ^ bc->P[i];
        Xr = F(bc, Xl) ^ Xr;

        /* Exchange Xl and Xr */
        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    /* Exchange Xl and Xr */
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ bc->P[1];
    Xl = Xl ^ bc->P[0];

    *xl = Xl;
    *xr = Xr;
}


/*------------------------------------------------------------------*/

static MSTATUS
BLOWFISH_initKey(blf_ctx *p_blowfishContext, ubyte *pKey, sbyte4 keyLen)
{
    sbyte2  i;
    sbyte2  j;
    sbyte2  k;
    ubyte4  data;
    ubyte4  datal;
    ubyte4  datar;
    MSTATUS status = OK;

    if ((NULL == p_blowfishContext) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialise p & s-boxes without file read */
    for (i = 0; i < N+2; i++)
    {
        p_blowfishContext->P[i] = bfp[i];
    }

    for (i = 0; i < 256; i++)
    {
        p_blowfishContext->S[0][i] = ks0[i];
        p_blowfishContext->S[1][i] = ks1[i];
        p_blowfishContext->S[2][i] = ks2[i];
        p_blowfishContext->S[3][i] = ks3[i];
    }

    j = 0;

    for (i = 0; i < N + 2; ++i)
    {
        data = 0x00000000L;

        for (k = 0; k < 4; ++k)
        {
            data = (data << 8) | (ubyte4)pKey[j];
            j += 1;

            if (j >= keyLen)
            {
                j = 0;
            }
        }
        p_blowfishContext->P[i] ^= data;
    }

    datal = 0x00000000L;
    datar = 0x00000000L;

    for (i = 0; i < N + 2; i += 2)
    {
        Blowfish_encipher(p_blowfishContext, &datal, &datar);

        p_blowfishContext->P[i] = datal;
        p_blowfishContext->P[i + 1] = datar;
    }

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 256; j += 2)
        {
            Blowfish_encipher(p_blowfishContext, &datal, &datar);

            p_blowfishContext->S[i][j] = datal;
            p_blowfishContext->S[i][j + 1] = datar;
        }
    }

exit:
    return status;

} /* BLOWFISH_initKey */


/*------------------------------------------------------------------*/

static MSTATUS
BLOWFISH_encipherCBC(blf_ctx *p_blowfishContext, ubyte *pSrc,
                     ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte4  halfBlock0;
    ubyte4  halfBlock1;
    ubyte4  ivBlock0;
    ubyte4  ivBlock1;
    ubyte4  blocks = numBytes / BLOWFISH_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_blowfishContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * BLOWFISH_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of BLOWFISH_BLOCK_SIZE */
        status = ERR_BLOWFISH_BAD_LENGTH;
        goto exit;
    }

    ivBlock0  = (ubyte4)pIV[0] << 24;
    ivBlock0 |= (ubyte4)pIV[1] << 16;
    ivBlock0 |= (ubyte4)pIV[2] << 8;
    ivBlock0 |= (ubyte4)pIV[3];

    ivBlock1  = (ubyte4)pIV[4] << 24;
    ivBlock1 |= (ubyte4)pIV[5] << 16;
    ivBlock1 |= (ubyte4)pIV[6] << 8;
    ivBlock1 |= (ubyte4)pIV[7];

    while (0 < blocks)
    {
        halfBlock0  = (ubyte4)pSrc[0] << 24;
        halfBlock0 |= (ubyte4)pSrc[1] << 16;
        halfBlock0 |= (ubyte4)pSrc[2] <<  8;
        halfBlock0 |= (ubyte4)pSrc[3];

        halfBlock1  = (ubyte4)pSrc[4] << 24;
        halfBlock1 |= (ubyte4)pSrc[5] << 16;
        halfBlock1 |= (ubyte4)pSrc[6] <<  8;
        halfBlock1 |= (ubyte4)pSrc[7];

        halfBlock0 ^= ivBlock0;
        halfBlock1 ^= ivBlock1;

        Blowfish_encipher(p_blowfishContext, &halfBlock0, &halfBlock1);

        ivBlock0 = halfBlock0;
        ivBlock1 = halfBlock1;

        pDest[0] = (ubyte)(halfBlock0 >> 24);
        pDest[1] = (ubyte)(halfBlock0 >> 16);
        pDest[2] = (ubyte)(halfBlock0 >>  8);
        pDest[3] = (ubyte)(halfBlock0);

        pDest[4] = (ubyte)(halfBlock1 >> 24);
        pDest[5] = (ubyte)(halfBlock1 >> 16);
        pDest[6] = (ubyte)(halfBlock1 >>  8);
        pDest[7] = (ubyte)(halfBlock1);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

    pIV[0] = (ubyte)(ivBlock0 >> 24);
    pIV[1] = (ubyte)(ivBlock0 >> 16);
    pIV[2] = (ubyte)(ivBlock0 >> 8);
    pIV[3] = (ubyte)(ivBlock0);

    pIV[4] = (ubyte)(ivBlock1 >> 24);
    pIV[5] = (ubyte)(ivBlock1 >> 16);
    pIV[6] = (ubyte)(ivBlock1 >> 8);
    pIV[7] = (ubyte)(ivBlock1);

exit:
    return status;

} /* BLOWFISH_encipherCBC */


/*------------------------------------------------------------------*/

static MSTATUS
BLOWFISH_decipherCBC(blf_ctx *p_blowfishContext, ubyte *pSrc,
                     ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte4  halfBlock0;
    ubyte4  halfBlock1;
    ubyte4  ivBlock0;
    ubyte4  ivBlock1;
    ubyte4  tmpBlock0;
    ubyte4  tmpBlock1;
    ubyte4  blocks = numBytes / BLOWFISH_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_blowfishContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * BLOWFISH_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of BLOWFISH_BLOCK_SIZE */
        status = ERR_BLOWFISH_BAD_LENGTH;
        goto exit;
    }

    ivBlock0  = (ubyte4)pIV[0] << 24;
    ivBlock0 |= (ubyte4)pIV[1] << 16;
    ivBlock0 |= (ubyte4)pIV[2] << 8;
    ivBlock0 |= (ubyte4)pIV[3];

    ivBlock1  = (ubyte4)pIV[4] << 24;
    ivBlock1 |= (ubyte4)pIV[5] << 16;
    ivBlock1 |= (ubyte4)pIV[6] << 8;
    ivBlock1 |= (ubyte4)pIV[7];

    while (0 < blocks)
    {
        halfBlock0  = (ubyte4)pSrc[0] << 24;
        halfBlock0 |= (ubyte4)pSrc[1] << 16;
        halfBlock0 |= (ubyte4)pSrc[2] <<  8;
        halfBlock0 |= (ubyte4)pSrc[3];

        halfBlock1  = (ubyte4)pSrc[4] << 24;
        halfBlock1 |= (ubyte4)pSrc[5] << 16;
        halfBlock1 |= (ubyte4)pSrc[6] <<  8;
        halfBlock1 |= (ubyte4)pSrc[7];

        tmpBlock0 = halfBlock0;
        tmpBlock1 = halfBlock1;

        Blowfish_decipher(p_blowfishContext, &halfBlock0, &halfBlock1);

        halfBlock0 ^= ivBlock0;
        halfBlock1 ^= ivBlock1;

        ivBlock0 = tmpBlock0;
        ivBlock1 = tmpBlock1;

        pDest[0] = (ubyte)(halfBlock0 >> 24);
        pDest[1] = (ubyte)(halfBlock0 >> 16);
        pDest[2] = (ubyte)(halfBlock0 >>  8);
        pDest[3] = (ubyte)(halfBlock0);

        pDest[4] = (ubyte)(halfBlock1 >> 24);
        pDest[5] = (ubyte)(halfBlock1 >> 16);
        pDest[6] = (ubyte)(halfBlock1 >>  8);
        pDest[7] = (ubyte)(halfBlock1);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

    pIV[0] = (ubyte)(ivBlock0 >> 24);
    pIV[1] = (ubyte)(ivBlock0 >> 16);
    pIV[2] = (ubyte)(ivBlock0 >> 8);
    pIV[3] = (ubyte)(ivBlock0);

    pIV[4] = (ubyte)(ivBlock1 >> 24);
    pIV[5] = (ubyte)(ivBlock1 >> 16);
    pIV[6] = (ubyte)(ivBlock1 >> 8);
    pIV[7] = (ubyte)(ivBlock1);

exit:
    return status;

} /* BLOWFISH_decipherCBC */


/*------------------------------------------------------------------*/

extern BulkCtx
CreateBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    blf_ctx* p_blowfishContext = MALLOC(sizeof(blf_ctx));
    MOC_UNUSED(encrypt);

    if (NULL != p_blowfishContext)
    {
        DIGI_MEMSET((ubyte *)p_blowfishContext, 0x00, sizeof(blf_ctx));

        if (OK > BLOWFISH_initKey(p_blowfishContext, pKeyMaterial, keyLength))
        {
            FREE(p_blowfishContext);  p_blowfishContext = NULL;
        }
    }

    return (BulkCtx)p_blowfishContext;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DoBlowfish(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    blf_ctx*    p_blowfishContext = (blf_ctx *)ctx;
    MSTATUS     status;

    if (encrypt)
        status = BLOWFISH_encipherCBC(p_blowfishContext, data, data, dataLength, iv);
    else
        status = BLOWFISH_decipherCBC(p_blowfishContext, data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT,(sbyte*) "DoBlowfish: cipher failed, error = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = ERR_NULL_POINTER;

    blf_ctx* pOld = (blf_ctx *) pCtx;
    blf_ctx* pNew = NULL;

    if (NULL == pCtx || NULL == ppNewCtx)
        goto exit;
  
    status = DIGI_MALLOC((void **) &pNew, sizeof(blf_ctx));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) pNew, (ubyte *) pOld, sizeof(blf_ctx));
    if (OK != status)
        goto exit;

    *ppNewCtx = (BulkCtx) pNew; pNew = NULL;

exit:

    if (NULL != pNew)
    {
        (void) DIGI_MEMSET_FREE((ubyte **) &pNew, sizeof(blf_ctx));
    }

    return status;
}
#endif /* defined(__ENABLE_BLOWFISH_CIPHERS__) && !defined(__BLOWFISH_HARDWARE_CIPHER__) */
