#ifndef __DIGICERT_SHA224_CI_TESTS__
#define __DIGICERT_SHA224_CI_TESTS__

/* Sha224Test is defined in crypto_interface_sha224_test.c */
static Sha224Test gpSha224ShortTests[] =
{
    {
        .msgLen = 0,
        .pMsg = (ubyte*) "",
        .pMD = (ubyte*) "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    },
    {
        .msgLen = 8,
        .pMsg = (ubyte*) "75",
        .pMD = (ubyte*) "991a908ad5fc70a65e7d36714f4d2088809a8842c89d56dd421fcb45",
    },
    {
        .msgLen = 16,
        .pMsg = (ubyte*) "ed43",
        .pMD = (ubyte*) "313389231813a93cdd9b721168f5eff433a7a707f111f743732b31a1",
    },
    {
        .msgLen = 24,
        .pMsg = (ubyte*) "01be1c",
        .pMD = (ubyte*) "47571cb7cda9cf6fb0bb6fc30a01ddced607cbd6a145cbee1d5050f2",
    },
    {
        .msgLen = 32,
        .pMsg = (ubyte*) "d4e8509b",
        .pMD = (ubyte*) "2feed65eeabd61fa2640b9cc01542550d13053502a069fab8d2147c5",
    },
    {
        .msgLen = 40,
        .pMsg = (ubyte*) "c7d3609885",
        .pMD = (ubyte*) "314090db7a3cc0f95eaf998e238c880606c6d9c0ab94b61d0b63c1a6",
    },
    {
        .msgLen = 48,
        .pMsg = (ubyte*) "8a950f846a19",
        .pMD = (ubyte*) "ddc87026186083831a5a945ce5bad63af3e94f63a31c12989853b57c",
    },
    {
        .msgLen = 56,
        .pMsg = (ubyte*) "39ea964749750a",
        .pMD = (ubyte*) "6ee78371fe0496c77b0c971c91581322dd587ec7387d33a22ca4686d",
    },
    {
        .msgLen = 64,
        .pMsg = (ubyte*) "8c77e11458675624",
        .pMD = (ubyte*) "c31969cc46b0737578592486a362759f811427334360c23d957c8239",
    },
    {
        .msgLen = 72,
        .pMsg = (ubyte*) "4c2a608045379127e7",
        .pMD = (ubyte*) "96bbc49f831b6ce97713332ab688b8c9c5939b960833fc77a7f4a8a7",
    },
    {
        .msgLen = 80,
        .pMsg = (ubyte*) "732d1f5c1976cee9e208",
        .pMD = (ubyte*) "0e1f3205fcb19f28185fe9069e06e6a7ea217001850c410a4f25f70b",
    },
    {
        .msgLen = 88,
        .pMsg = (ubyte*) "d778fd27aa876e2fbb17b5",
        .pMD = (ubyte*) "a33ce5d804c9296773a5e23990617aeea81187ca916606b0f790cd1c",
    },
    {
        .msgLen = 96,
        .pMsg = (ubyte*) "edb19c2cb6d8e1681e8b4aeb",
        .pMD = (ubyte*) "834012d6e3837b2e4354955c0c5446543fdfebfabc1aac273f68f38e",
    },
    {
        .msgLen = 104,
        .pMsg = (ubyte*) "4650b81993fe25ac931db09094",
        .pMD = (ubyte*) "73969e458f9769fddfb26d765932c2b5f386dfefc61c63a9dd6daba4",
    },
    {
        .msgLen = 112,
        .pMsg = (ubyte*) "1b7f884242a87779d3921f8eafee",
        .pMD = (ubyte*) "c0bb24a1ec7d8ef883cf1c3da8caf4a1c5d8956817d604cbf261ab1f",
    },
    {
        .msgLen = 120,
        .pMsg = (ubyte*) "c544b40cbf665e1ca3b9a3d42575ea",
        .pMD = (ubyte*) "f82f5b29378981971f181c9bd4dc3c571e5c8ecbe88baf0f6bf78e38",
    },
    {
        .msgLen = 128,
        .pMsg = (ubyte*) "cb1c68395b2a4ca9fbb5a4f363edf361",
        .pMD = (ubyte*) "5542e4de456ace767753d098288d7901bfe8161c4279a050f4712037",
    },
    {
        .msgLen = 136,
        .pMsg = (ubyte*) "c109279dbd04acf158b0756d9cfa8d8285",
        .pMD = (ubyte*) "1be6b7d926a0a54a3d718efec63f86f1965e83121ef0ad136b442083",
    },
    {
        .msgLen = 144,
        .pMsg = (ubyte*) "eaf492b6c0f16139ab129615e342bdb8f274",
        .pMD = (ubyte*) "5581ffba9d90aef20c152652b9bf32df8118edff5337fa77a38938c0",
    },
    {
        .msgLen = 152,
        .pMsg = (ubyte*) "0a8037ba6b197b05890330cbc1f9b73d9448b7",
        .pMD = (ubyte*) "05ccce0c8a3eaad081c35305cfc8c8e41f7db1317e7f4744f1e44424",
    },
    {
        .msgLen = 160,
        .pMsg = (ubyte*) "45a0e509f78c5e2837385974dde89fdf21c938a3",
        .pMD = (ubyte*) "0ee2a0493f4f9543c8a0e4ad7d188806405d5679d51e78b49b0a3a90",
    },
    {
        .msgLen = 168,
        .pMsg = (ubyte*) "b41af9d4ce70473ddcaab2f31431cecc47a39271c4",
        .pMD = (ubyte*) "a5d7d672146df7431f07fb1e5217fe2d3e3f7a5c9dccc1fb55cdc40a",
    },
    {
        .msgLen = 176,
        .pMsg = (ubyte*) "361b2b312efb7ab87da5f70f4fe64e01d77664ae421f",
        .pMD = (ubyte*) "51d5ce860621c71d6d38e4de96ef5bff8b62415612287e240e779932",
    },
    {
        .msgLen = 184,
        .pMsg = (ubyte*) "9890be658f9ff3e10aa4c11baeff1c0734d79da91901d5",
        .pMD = (ubyte*) "217e8d5015c336ccec4dc90ff9d367f02283091069e0c47dea365006",
    },
    {
        .msgLen = 192,
        .pMsg = (ubyte*) "1927c77dccf7e1d12c076084b9a8e11608f0b4e313bad448",
        .pMD = (ubyte*) "c076380f28efe21a64a9de71598b66feafd662a663e6e35354b921bb",
    },
    {
        .msgLen = 200,
        .pMsg = (ubyte*) "e64fdc08760aaae35b3bb71bd1bdc0900b892f0b78e2881a45",
        .pMD = (ubyte*) "ddc4f3acd5f81b9c3bb1ee870ea2f82372f2383669fa16b2306b6172",
    },
    {
        .msgLen = 208,
        .pMsg = (ubyte*) "42616b4c1dfe51a727d048ba40ccc049f0e72d05f087ada6ec38",
        .pMD = (ubyte*) "05d3c0adb7fda1842bb7fb4996b4c43d7e0b1834bf43bc71fe5d5bec",
    },
    {
        .msgLen = 216,
        .pMsg = (ubyte*) "6bae70b5b9ea8f263c1b0eb4b2963e7a9a732b67f43f7d9448f19c",
        .pMD = (ubyte*) "2dd4c66957a3a3b1c8de65f721dc81c66a7f75f55b783dd1d298ff61",
    },
    {
        .msgLen = 224,
        .pMsg = (ubyte*) "23be785a7417cd7bf331f7cfbbcc893385d09aeecae00ee628311714",
        .pMD = (ubyte*) "b781619a25397620f3233512148a505fd48785c1f8596bbebfb2b2f3",
    },
    {
        .msgLen = 232,
        .pMsg = (ubyte*) "324625667970ee7a2faf476aac90dc439aa44748f979318c65cabac09c",
        .pMD = (ubyte*) "f25233e668549394853b808df7b3229fa1531c3299598daf9788f394",
    },
    {
        .msgLen = 240,
        .pMsg = (ubyte*) "d9998d46c7f355aba66edc6f904cab07f7ca5db5e75101598bf0bf8af30a",
        .pMD = (ubyte*) "d1165e841c7346243230a2cc8102b1641b55f03c41d5a264a8762cee",
    },
    {
        .msgLen = 248,
        .pMsg = (ubyte*) "f534371b15e33a220e0cbed57f63fb9902a9fe57b21f4e8aea40d0974fafe8",
        .pMD = (ubyte*) "95bb7df1853fcf5f7d22f648e9a9c96fc37799530cb71a6732e3d672",
    },
    {
        .msgLen = 256,
        .pMsg = (ubyte*) "917944c93dcf7bbae69bfec163ae66e235d26cc20365fe664747923e46f7ba62",
        .pMD = (ubyte*) "f322247d420a429bcc7923a1c3952b9692a7543b05771cd2e91703be",
    },
    {
        .msgLen = 264,
        .pMsg = (ubyte*) "3a37d6e8d4d8e81662284459d174d584f942db63c4e233f29346d9cddd14abe819",
        .pMD = (ubyte*) "ff8c2101c1c7855c7f153022a5c5eaddfe030ad81ba966d26e3b7579",
    },
    {
        .msgLen = 272,
        .pMsg = (ubyte*) "8fea983c76c594e3ee572f5fd5d65736a4a5767746d3ec562be5bc1698d5852c415a",
        .pMD = (ubyte*) "77689f2a70f9ce7e04f365294fe875d1992b80c28efc8e0b1cc49d90",
    },
    {
        .msgLen = 280,
        .pMsg = (ubyte*) "99f9f36ac3ae791d13bd8f582f469f697833bbaa33cae1b3e7827ece051630acced9d0",
        .pMD = (ubyte*) "01229cdd86d7eb2a3b0d099a685a889db531808ac9d2b37db2ccdbd0",
    },
    {
        .msgLen = 288,
        .pMsg = (ubyte*) "238d2e226b0fd8ccb59d2f097a1a948549293190bc4d8d69ac4e5dbda1de9e6b8c7ce08a",
        .pMD = (ubyte*) "30d3b32557374eaa49d0b6b69d4b84cdfba2a76e9bb6c2ef10afc556",
    },
    {
        .msgLen = 296,
        .pMsg = (ubyte*) "f594d177633c4618c38b4d64f7e98025eca4c62e7a40634b8b0e317880002c51d0bb34caf2",
        .pMD = (ubyte*) "685cddcaa6be2fa0cbe419d4648107bbc130629ad1402896b1eae7bf",
    },
    {
        .msgLen = 304,
        .pMsg = (ubyte*) "30c5ed2bfecdba56065968999cbe06937038f5f30889fa3b6de391c5240884035fb0bd0a752b",
        .pMD = (ubyte*) "775d723ae67f00e665e6c53399e0e4ccbcee18c4580783360e185b1e",
    },
    {
        .msgLen = 312,
        .pMsg = (ubyte*) "719a80a1f252ebe3e2a4cef1d9999eb42d03733cc10574601dd590a5c4c17062c170a921846b35",
        .pMD = (ubyte*) "9d5da5b3c64ec9846cba2eaa37b3fc0fee0f575e20d97afc0d5be4b8",
    },
    {
        .msgLen = 320,
        .pMsg = (ubyte*) "8b2e8ec680de14b47cdd7b8919edd42786135ce6888fa02cbf11e53e2b2ac655ef011ff554472a7a",
        .pMD = (ubyte*) "f861f02db427915e1ea23b0b22dab2bc1807a8196b94ec41384a556c",
    },
    {
        .msgLen = 328,
        .pMsg = (ubyte*) "c2348b72292a68e10b3a59e4be2c9b16811a7000c974143dd546f3db88be190578e9eadf43bd13b222",
        .pMD = (ubyte*) "cc634e4599381cb8ebf8c3abb28e608ef82ce19f3c6e6ee002c9d518",
    },
    {
        .msgLen = 336,
        .pMsg = (ubyte*) "540aa9773fc259214ea4be0d79a09d3fbb8b01e0b167789b63e57e4662283ac513cc682b4a2797231ace",
        .pMD = (ubyte*) "a66638981bcfef41981dea8aa5bb80bb9bcb943993b4c8a41da24dad",
    },
    {
        .msgLen = 344,
        .pMsg = (ubyte*) "43ef63919a34f6f55683bdbde563b83965481b22b959fc80dd764ecb767a1251aebdccd73ede3483ccbf2f",
        .pMD = (ubyte*) "f1a2f467d33d13a7cde0e70ccb1fcc378bd556441e95da05084d8a87",
    },
    {
        .msgLen = 352,
        .pMsg = (ubyte*) "d041a1d9d6dff39bab52075f9d01b07d3990174c05c00a2c729097ca0ca9da9ff4f813ba909dfbc081045931",
        .pMD = (ubyte*) "b9db1884e7d42e833928dce000ca0ead33382b6b6fd893bb431e7fe9",
    },
    {
        .msgLen = 360,
        .pMsg = (ubyte*) "d785785f598c041a4a90af2d1563da05c3fb6d791c0c1cff10dde9205654ea2953524d243d47990680fd362a61",
        .pMD = (ubyte*) "0dd0d0c50c46cd8acb2bf24e06b9045647cb05686ad5f6e882079a74",
    },
    {
        .msgLen = 368,
        .pMsg = (ubyte*) "25627f9b226ba0c3456d9a10e72bb8f5be51812bb2fd2e52eb7d61db2f5b13256b96cee68f331dcd9ff442660768",
        .pMD = (ubyte*) "21d00228d856325e191770714c742f031510e2421ab1384b1c357fc2",
    },
    {
        .msgLen = 376,
        .pMsg = (ubyte*) "67f940e14f070603cb2b16a2c6f1dc4733d3fcd4fe5aeac54386b5b5bf702324842e0377f0f7bf40df8731c020c5b7",
        .pMD = (ubyte*) "5c9d5693ca4b6f83bfcad1c1b3c64633f648a3494410cd950b37edb0",
    },
    {
        .msgLen = 384,
        .pMsg = (ubyte*) "42a223ef0fd117d076c7f72cb1666f0c7a0fa60ccd5d20aff014e3f5b154d830ef1375135bca990c806db7d401a13744",
        .pMD = (ubyte*) "664fa23762c95d8d536ef1579dc0a637a2bd1b2e2cba0fea3c8afe59",
    },
    {
        .msgLen = 392,
        .pMsg = (ubyte*) "db7f4c258e6daebdcdd7390387426d456404592afbaa693b469680a152ed46303bb0c4a558282e2cb388ff26bcce4b283e",
        .pMD = (ubyte*) "af238e4ccc6cf602ce102c5b1e4339d2366cd603925c043dee6cb022",
    },
    {
        .msgLen = 400,
        .pMsg = (ubyte*) "811f3a79bce3cf539c373055689bf09377564832e75d696f92760fe23e9d5a0414a7daf05425e866468b3d157492bd1a16da",
        .pMD = (ubyte*) "d9b0ac020423055d4dc86df76c11e2daa491251d0506b1f409e79c0a",
    },
    {
        .msgLen = 408,
        .pMsg = (ubyte*) "9310d1d717cdfb7624289dac68e8f80a42c17e8ad31b86725815437bb7c8f73357d064a035098326359679aab628c7f8687cc1",
        .pMD = (ubyte*) "bfb48e61652aad1e67207a359507c8a204ea372b46f080bb93c91a31",
    },
    {
        .msgLen = 416,
        .pMsg = (ubyte*) "08700e21d6dd84caf184e6dc5ab0688510bb0b943b7371f3aac2f0717f8fe5c529df4bd093408c239b6796c1c618322632469188",
        .pMD = (ubyte*) "0e747d4162371697bbf690097953c01f29c3afaadbfe0c247536ab4a",
    },
    {
        .msgLen = 424,
        .pMsg = (ubyte*) "1a6592d3e5a04ca3b7a02ca416a10e8fe1d6e8d2e4ae00edaa565c1c927f7a36256142d5a7ff39b7ecadf7646ed0db119ce6fdc574",
        .pMD = (ubyte*) "055425cb83610969f76aeafcfe632557d939e4eaa82271a81ab5f007",
    },
    {
        .msgLen = 432,
        .pMsg = (ubyte*) "72b76f1f3863b2c14c76ccb8d7c258036be788d9f273bdeee54e54f1bf56c259b046e36195dc8f51283b6f00748e0e978dee33977d86",
        .pMD = (ubyte*) "86c0cf11012e2c7d298cce7a96964164be9618ccf8ab673ce8f86541",
    },
    {
        .msgLen = 440,
        .pMsg = (ubyte*) "00ee6c4b15364ad84278680d2c582dcd02d8e34603cd5e0e4190df72a5f5380b3481309290d728f4c274ffa9369c344207944a427e1271",
        .pMD = (ubyte*) "3ae4993212244a5ec5fd446afbfed39a7f67e5b4539c8cc479df6996",
    },
    {
        .msgLen = 448,
        .pMsg = (ubyte*) "3b8da36d5a65bf7093332bed17f5390161cbe0d7bc6360c105b42587b2efeeff13b22eddd87fb2cdd46e85bf001e1182c3f186957079803a",
        .pMD = (ubyte*) "5fc70a235f0e0faff42281898491e8b2b112263d3babc900a3019e83",
    },
    {
        .msgLen = 456,
        .pMsg = (ubyte*) "f227fbd6337fe09eb3b84c56d3be497485cbf919b039228bd695e9e5f4f4de0da98a39e79b7863c817e6b92ef7528caec9276c2d2d92a6537f",
        .pMD = (ubyte*) "78fc15d24337e4ea315a7f31a7d79c044bc37aa9bf6eb72478b14171",
    },
    {
        .msgLen = 464,
        .pMsg = (ubyte*) "e37e78d9bd2cfce414ff3a47d24c0221f034c1bade790301259136394bf9b1eff6ccf52f559432f7bc600dec8e17a04c600bc2245bd189c3e251",
        .pMD = (ubyte*) "abbdaeb386db64bd52cfebd62753ff7df2adaaf97fcc51e3a8b75506",
    },
    {
        .msgLen = 472,
        .pMsg = (ubyte*) "482e987b20322737ed0732babae02e72cd35c23c2169d82617a9f5796817c5f75e28fb61444a583c1bcb08d58ef63583287fd72cc521c90a468522",
        .pMD = (ubyte*) "9ddea0cce8e2f89cf5240121d1abd8a7a0b67c250764dc21c79b7ee5",
    },
    {
        .msgLen = 480,
        .pMsg = (ubyte*) "9a5794b14d52a8ab00911deb9cedbf25d2dc7b9da8e4093c3156cee39b3800ff70830b5e158f334197cb7bb2a6b1c617e2f93d08560df05e42bec08c",
        .pMD = (ubyte*) "40009546bf6e278ab796940b6b9d44305b0554c71cc7aae9caff63ff",
    },
    {
        .msgLen = 488,
        .pMsg = (ubyte*) "e0a0997730f7fa58b914b81dacb5a817a84e7ff32daae68753d4d1ccbc380c26c70616ec06d73324f393bd8ede92bbe52a01b561b988c680a529f20631",
        .pMD = (ubyte*) "d5e9e0911d61231caaeab4919bf070a6e75c52f4f5c496b9198cabdc",
    },
    {
        .msgLen = 496,
        .pMsg = (ubyte*) "acfbeb6e1ed9f5a9a8c7c5b1683d7d6fb20f3cdfa8a74a6e0a9196a64f3e630cf4013e49145e33893984402172180a74a534cf1727b09c338aa0c02bb61d",
        .pMD = (ubyte*) "04e8716d6fd885f48b63cedcc6d87fe9292a473ff09b7617e7f79df5",
    },
    {
        .msgLen = 504,
        .pMsg = (ubyte*) "2cb7bda62c47a18435841fa640541cab7bfd52b39d2d497d763d83cdcab6f7115f15c24355cb1811b688803c4eb9413ebd50172fcac32be9fa57426b629e35",
        .pMD = (ubyte*) "091c3e209097a892cd16562dc9a07d4cddb61bbe816ab2fd5ab39ab5",
    },
    {
        .msgLen = 512,
        .pMsg = (ubyte*) "d91c046859db42770e5358f9749b51e4797c1c723c287a7715281af2d59701e24f8e305b17df81d88906d3d30d5c66939a8e8846794e724f4c486de14e5839cd",
        .pMD = (ubyte*) "701c3b9e557f72563f37e01b2e1aeda3f1c1ccaf3e72f046bde644cd",
    }
};
#endif /* __DIGICERT_SHA224_CI_TESTS__ */

