#ifndef __DIGICERT_SHA1_CI_TESTS__
#define __DIGICERT_SHA1_CI_TESTS__

/* Sha1Test is defined in crypto_interface_sha1_test.c */
static Sha1Test gpSha1ShortTests[] =
{
    {
        .msgLen = 0,
        .pMsg = (ubyte*) "",
        .pMD = (ubyte*) "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    },
    {
        .msgLen = 8,
        .pMsg = (ubyte*) "e0",
        .pMD = (ubyte*) "c2204edbfb1b72c9e996a5e6464f6ab0198c494f",
    },
    {
        .msgLen = 16,
        .pMsg = (ubyte*) "4138",
        .pMD = (ubyte*) "099e1f1eb47d200538412efd1b5980ecdf3551ed",
    },
    {
        .msgLen = 24,
        .pMsg = (ubyte*) "a0638c",
        .pMD = (ubyte*) "bb9d681d461aacddf11a00857539b24ccd114a03",
    },
    {
        .msgLen = 32,
        .pMsg = (ubyte*) "e5c4d8f8",
        .pMD = (ubyte*) "7a2e4ac03e42adc965baa9d8d757da7a48b8b5c2",
    },
    {
        .msgLen = 40,
        .pMsg = (ubyte*) "41fd2295c3",
        .pMD = (ubyte*) "a78edfd9ebc8692afc6b9c48e3e87e59773251a4",
    },
    {
        .msgLen = 48,
        .pMsg = (ubyte*) "0c0c36ea2599",
        .pMD = (ubyte*) "6faa2d4763d357921cdd19d6fd315e6c9a9641fd",
    },
    {
        .msgLen = 56,
        .pMsg = (ubyte*) "2c95e7ba95f91f",
        .pMD = (ubyte*) "82741d15c9b9f284e55eecd858fee220ad793be4",
    },
    {
        .msgLen = 64,
        .pMsg = (ubyte*) "b40b85885cb6d4ea",
        .pMD = (ubyte*) "a721a6902ed91aab788b1eb8446b709dd72ef8d6",
    },
    {
        .msgLen = 72,
        .pMsg = (ubyte*) "bdf45c6e06c718d832",
        .pMD = (ubyte*) "725dbadad9f0b50b1fe7ec188959dc6ed3e1a733",
    },
    {
        .msgLen = 80,
        .pMsg = (ubyte*) "f708889f819a84d89272",
        .pMD = (ubyte*) "6c7e1a7ecdf3255ea0aacdf423c21d6a2da45350",
    },
    {
        .msgLen = 88,
        .pMsg = (ubyte*) "1cd55ca75024eead495d1a",
        .pMD = (ubyte*) "cceef29e2619161135bc5d445c0b47a068c2245c",
    },
    {
        .msgLen = 96,
        .pMsg = (ubyte*) "4f68e01da8b33f813bf7b984",
        .pMD = (ubyte*) "11d93fcf874ef17004236b4f23acae09647c4ba0",
    },
    {
        .msgLen = 104,
        .pMsg = (ubyte*) "05a0a9f11dffd7cbaa4869085b",
        .pMD = (ubyte*) "59fb66b2e2275eb6028dd3d93798846bd6258545",
    },
    {
        .msgLen = 112,
        .pMsg = (ubyte*) "270780fb49d0d33253e9298c6a6c",
        .pMD = (ubyte*) "67e0605937a92f0666c6817d896aec24423984cb",
    },
    {
        .msgLen = 120,
        .pMsg = (ubyte*) "0d620370ab27194622178a67a132af",
        .pMD = (ubyte*) "f85ce770617bec605701e1380d9b35d52ea1c39c",
    },
    {
        .msgLen = 128,
        .pMsg = (ubyte*) "4486e9b913959379d58652c49c7dcb79",
        .pMD = (ubyte*) "565b793a4298083d15f28742e82a8d3cbfcdc8ec",
    },
    {
        .msgLen = 136,
        .pMsg = (ubyte*) "d3811b90d6c0bfbd41f023fa941b74ca14",
        .pMD = (ubyte*) "98f96df74a358a0150f7c13ca697ff4a731c070a",
    },
    {
        .msgLen = 144,
        .pMsg = (ubyte*) "817bed60de52df6c584cfb38cd9b3c2b1e72",
        .pMD = (ubyte*) "55ea65ec9fc245e4c7a04fdcb87319ab3e00ee1c",
    },
    {
        .msgLen = 152,
        .pMsg = (ubyte*) "b6e964eae9ead675e17139ac62c20b227d3793",
        .pMD = (ubyte*) "757a0ef748882d7857e840a41b78fc72cbb1a94b",
    },
    {
        .msgLen = 160,
        .pMsg = (ubyte*) "a6db993bf360083477c931d19aaddfffaaf4e596",
        .pMD = (ubyte*) "d1c09d3e40d5af6e089c56ad223acdc4ca7f5e72",
    },
    {
        .msgLen = 168,
        .pMsg = (ubyte*) "4c6632b6e6ce9cd3b72773eae09b8a8c8354b15c86",
        .pMD = (ubyte*) "38e593cc6b82838e4c186579365a90e2b15ed753",
    },
    {
        .msgLen = 176,
        .pMsg = (ubyte*) "78c167a35440f4249d4681d8aecff2a5221b51fef549",
        .pMD = (ubyte*) "4d2a7bf4323a3a4327e8638dfb706d89071ae057",
    },
    {
        .msgLen = 184,
        .pMsg = (ubyte*) "094b4507de75073f00f421703444aaa271536ec7f1409b",
        .pMD = (ubyte*) "db1f928b6ceea8dc3803252a987bf6f005117546",
    },
    {
        .msgLen = 192,
        .pMsg = (ubyte*) "9e3f01f6d5b1a36baccbc019d307348097124ec1633877b3",
        .pMD = (ubyte*) "65f8a12b853c93528f0fde55c2c915ef9d819de3",
    },
    {
        .msgLen = 200,
        .pMsg = (ubyte*) "cca966633afcd230e9f422da56a36b38d5a52ed58d0e7d8bc4",
        .pMD = (ubyte*) "9e46b3ee30fd282e7694106a8d261b4d3f8d0bd5",
    },
    {
        .msgLen = 208,
        .pMsg = (ubyte*) "676662345b42e89697a3c8315bd9e1f428705fed25053dbcc15"
                "9",
        .pMD = (ubyte*) "9a7e948d71fe43bb71d52c526947ce8d12c80f10",
    },
    {
        .msgLen = 216,
        .pMsg = (ubyte*) "d061838b57b8f709970ef35efdeb6bfd42f5044e3f708251020"
                "17f",
        .pMD = (ubyte*) "2a89a126637f077101055ccbff9a0a838dd2bb04",
    },
    {
        .msgLen = 224,
        .pMsg = (ubyte*) "fe9a98da525e50e5d8178375f1b62e2029a2e7b65f531f78271"
                "ca484",
        .pMD = (ubyte*) "4763566d88452bb8f0b153581e1e8b31dc477993",
    },
    {
        .msgLen = 232,
        .pMsg = (ubyte*) "f34d7e1ed65882ea2c647606318b9cfa5a3f3361e98ca44abe9"
                "dfcdd70",
        .pMD = (ubyte*) "fee23252835cd2dcb005f5a85ccf785d377c9363",
    },
    {
        .msgLen = 240,
        .pMsg = (ubyte*) "077cd4113b0cd72db66d85f23e9609ad76ee3ba910b471b13e9"
                "e97d069c0",
        .pMD = (ubyte*) "097b0c082fc6ca2e70031fe67ba083abf76682f6",
    },
    {
        .msgLen = 248,
        .pMsg = (ubyte*) "e928d5028caf3250b1505fd730d21737bd6dc208192e4665859"
                "d1fab7c9cb2",
        .pMD = (ubyte*) "bda20be172b464b70a67c240c12a8fa89326406e",
    },
    {
        .msgLen = 256,
        .pMsg = (ubyte*) "3e726357d53a9a40ae3172c05af032cf7ae2a2e931f01dc9d95"
                "de875f5eec27a",
        .pMD = (ubyte*) "ab3bc7e80a3c6b92285cf01b119dde6654c3903b",
    },
    {
        .msgLen = 264,
        .pMsg = (ubyte*) "77a9646e0dad473d7d0971431e449f583e0a1eaa1f22e8553fa"
                "01134dc5c61f6b8",
        .pMD = (ubyte*) "c19b3f4da5cfc969109b061ac99fbf318b2d058b",
    },
    {
        .msgLen = 272,
        .pMsg = (ubyte*) "9a0861db87288df79eeb6b23042f74c71c222e21b3a7fed37bf"
                "c3d9ebb998f6d445b",
        .pMD = (ubyte*) "ca44de1a2372bf36e42f110502a55a7e881443aa",
    },
    {
        .msgLen = 280,
        .pMsg = (ubyte*) "ea43cb6c0e0a1cc753785da3231e6cb56dffcec1f796a1baf61"
                "bd12bdc038fd571c6ff",
        .pMD = (ubyte*) "03d6dd76a70019350086243a5e5d7c1beac2c34c",
    },
    {
        .msgLen = 288,
        .pMsg = (ubyte*) "5a38700190503ba8c95a379c6a3a8ff482d45eedaa69b7db302"
                "3e96674ee01f2918a905f",
        .pMD = (ubyte*) "b1b5e3e457365df06f82a343627c30700c01d713",
    },
    {
        .msgLen = 296,
        .pMsg = (ubyte*) "48139c3116e99de70620202a1f77755559d38504f73cc030172"
                "8569c88fcaa70dbd00424bd",
        .pMD = (ubyte*) "b8323238452f5865cf9c038bfe074038c0f9498b",
    },
    {
        .msgLen = 304,
        .pMsg = (ubyte*) "50c1a1d66909526beeec8c50c900a3580e5965e42df2f5626b4"
                "fd71493614713e8aacf935fa2",
        .pMD = (ubyte*) "d35f1dbfc65d6e829c0244b54ef168dfb4a054e8",
    },
    {
        .msgLen = 312,
        .pMsg = (ubyte*) "2f239a2dbea0e83703e22998b39fd244fd15b41662937272c73"
                "a3829c905aa9c50071b2567f400",
        .pMD = (ubyte*) "3a2cc63b3d66bef580b834a2eb27dc52806d66d4",
    },
    {
        .msgLen = 320,
        .pMsg = (ubyte*) "b07dd8f6bcfeacb41478f301085286234eb6f9303cf26f883a1"
                "eb3a378ff850ddc2c32ae3f6f684f",
        .pMD = (ubyte*) "f4f25314ab0bdcb265d471d446a1e705973a0674",
    },
    {
        .msgLen = 328,
        .pMsg = (ubyte*) "f39030db668f67dbbcd01b935305ccd6c927171aca022e1e26f"
                "486d027f2cf6d21cb29ea4ab19593cc",
        .pMD = (ubyte*) "6ace97a1a8e5cc3a82fc99459e245d32ea527670",
    },
    {
        .msgLen = 336,
        .pMsg = (ubyte*) "1fd7042f891bf083896d4bbd369395f1a65a337c122db73b36e"
                "562faf7e3e72f485c72e94ef5e903c290",
        .pMD = (ubyte*) "da1ad47b958b041d2f490845c53890dd189bd22b",
    },
    {
        .msgLen = 344,
        .pMsg = (ubyte*) "0488a1db4e7d890a454b44ae2396f32b4b8438707f1f037c53f"
                "ba920e2183707bf0905f52f568e4c95207e",
        .pMD = (ubyte*) "0bb0bbf6e394a3e6f42524ce51719359153a5e79",
    },
    {
        .msgLen = 352,
        .pMsg = (ubyte*) "690f50e25bd2765c687e3a00f3bb2e634d6258c3cd3fe6eb231"
                "61d57e9e393997b669efb09df0c66ea171482",
        .pMD = (ubyte*) "b5bd6524ea20dbcf98c10012599cf35661f9985c",
    },
    {
        .msgLen = 360,
        .pMsg = (ubyte*) "5f7a981f5116a979e3c999d0a277065fb443de6b1abac419324"
                "db5828005eb09ad7201edd0e5591aeddfbb45bb",
        .pMD = (ubyte*) "3c755c83d3b2dbf56822ea621e43fada214d3330",
    },
    {
        .msgLen = 368,
        .pMsg = (ubyte*) "5834c88031067a320315fbe778355cbe45181b8bffcc9a7a2f8"
                "5d0f5a89d3fc718d92681deeef71c1b440be10cf9",
        .pMD = (ubyte*) "7399be7a4e27d1df6bf1b74745eef38de756320c",
    },
    {
        .msgLen = 376,
        .pMsg = (ubyte*) "92252b8b0016e7e77f20728b066f1821ea166e7cffa594ce00f"
                "eb81b3064dbed42d5d84a769aa2e3061ccd8ec0f950",
        .pMD = (ubyte*) "3161d1552020abdd016e11d179469d24e4364f39",
    },
    {
        .msgLen = 384,
        .pMsg = (ubyte*) "c6c13eea2d7e71503bd4274a412645f184f45c67320039159aa"
                "fb7379bb1d89b5de414a54076f197124bd40f859e17d2",
        .pMD = (ubyte*) "755e18b0d51a296f16a61940313e69049a70a54c",
    },
    {
        .msgLen = 392,
        .pMsg = (ubyte*) "7dd33fa4ab628c0dba951161563bf57bfea3d4d15ba7b79fd1e"
                "94342555d30e17e08fd53de07e23d92d2077b18c2f3c261",
        .pMD = (ubyte*) "5f0f6c6ea01c771e6cd4e83c82cd812c91da9090",
    },
    {
        .msgLen = 400,
        .pMsg = (ubyte*) "193e156bcab64b3083b417ba60f21ea7d034e009f7203ccf505"
                "0368197a6f931e6df18ae1e6b19fa887c34febc5e587dc206",
        .pMD = (ubyte*) "f41aa999bac8e4fcbcbba89d3e9b1191aae67b68",
    },
    {
        .msgLen = 408,
        .pMsg = (ubyte*) "195ef723253c90fde93bf8d767def470300730d9e16ade87ee4"
                "2a0a79e42a8b157cf1d401c6cc1215476d2aacd112e4d0062ba",
        .pMD = (ubyte*) "410f4bb4f89d86822e3b7f41441d7210079c4840",
    },
    {
        .msgLen = 416,
        .pMsg = (ubyte*) "6c8d8e0812bfcc18ca2a17d5f8ae9f42e77ca1336b293003c40"
                "23586c6a0b53e37bc52d2794415bb68ad6a41868c6ca6566063a1",
        .pMD = (ubyte*) "8542f56f8dda4d900f7644e96308ee796141e8a3",
    },
    {
        .msgLen = 424,
        .pMsg = (ubyte*) "614ef07e6b0e52a832240ebc5ea8aab744aac1530bc94d360d0"
                "1266980c5c50b564e4e476132ce83bb38c0da656bd7cd2e6df735d7",
        .pMD = (ubyte*) "f640703acf07c5b003b811db5cf47ca4cd03119f",
    },
    {
        .msgLen = 432,
        .pMsg = (ubyte*) "f03e4f9edf7faa77d55a22327c23ce5bbb72f3ef2eca1e1fd47"
                "86f5108be3868b331c745bf607f8dcfb62ead2da29a1c03f45de0cf8b",
        .pMD = (ubyte*) "6bde81ce5558bda077db867f16ffd27f7510ae4a",
    },
    {
        .msgLen = 440,
        .pMsg = (ubyte*) "8e608d4bac688c4afdcd93cdeae3fcd935f530403a7e0f72749"
                "b929642c1aedaebab7c07e097985842b2c78ca4d1dc3a1261dc6552a160",
        .pMD = (ubyte*) "4ca82efd6e7b10a3cb7da9ca79b064001a867646",
    },
    {
        .msgLen = 448,
        .pMsg = (ubyte*) "6e29c28d97ab8a8bd9670837a3e82e0f844b30c085478049bc6"
                "afd5e1ea5680a950b179953d6edb565ab89cf8b1fbec1477943b134b9ac3"
                "8",
        .pMD = (ubyte*) "33c29860b4a4af2167185f857aa20307d6b4f3b1",
    },
    {
        .msgLen = 456,
        .pMsg = (ubyte*) "edc303ac635a904af6993193d9f15eadecd983e49921039efb8"
                "37c91467c4d33635a5572da95fea6f5627ac423864dd49a680ca5406b64b"
                "fcc",
        .pMD = (ubyte*) "0116527fcbadbad8eb3d35331d32eaa2c6a954ae",
    },
    {
        .msgLen = 464,
        .pMsg = (ubyte*) "f276348b81989b2c5b1e14e4129af870ff567714ef3beb951af"
                "1668755488dcf88d7aa6061e3fc484a8252f099ffd89f0781304164e8c46"
                "789f8",
        .pMD = (ubyte*) "919fc0b98deae5abd2aab99af2aca2fb15da6d09",
    },
    {
        .msgLen = 472,
        .pMsg = (ubyte*) "d62db0c0359a0ef8d810d17d1e01f56f75b2fc5221ebd7643af"
                "30a2ef4bc0c5a245aecc4ffb93ad42490250add91e1daa1e34cbbded1d07"
                "bf6c48b",
        .pMD = (ubyte*) "90abc83e0d9e5bd51688c08145707a2407c83d14",
    },
    {
        .msgLen = 480,
        .pMsg = (ubyte*) "0767803701044a36266ad0b9a22b32ec3dfc18687f54f662183"
                "68e227f4ab6b7d8335bea1b1dc67073951e64e49e2ef43101695afde42b0"
                "e309e4239",
        .pMD = (ubyte*) "5802bbf6c09bc4089d4720bc43e4b64cfb6afc2a",
    },
    {
        .msgLen = 488,
        .pMsg = (ubyte*) "1d53dfa05ca020a922ed947a6b1e21ae773d3a4165c00ef3030"
                "a00ede53458a7b40c3809c95ed1d1fa73d634b4d831c84b60f6a18d6c95b"
                "a9d6a5397ff",
        .pMD = (ubyte*) "545a42bce41155470de371fcac5a1f95293f5728",
    },
    {
        .msgLen = 496,
        .pMsg = (ubyte*) "84e5d1d3adf549b75f00052f35088df31138f320b0250596825"
                "5c89eb9fe22d1a00fd7352f74b7a8dc961582b3227a76a90c9bb92ed3896"
                "6010628224807",
        .pMD = (ubyte*) "f22856dbc728c55b51a458d0165cb07d83a3e1df",
    },
    {
        .msgLen = 504,
        .pMsg = (ubyte*) "6a2466c4ef8d878d4b917223c8a2e41d2bc3e531e7eaa0b191a"
                "87256940b413d26c40f2f7a85ce2537ad760b2a2756c5378fa770969767e"
                "a3caa659496cf98",
        .pMD = (ubyte*) "6d378f822e2b705865492c3a2afde8ab6cff886e",
    },
    {
        .msgLen = 512,
        .pMsg = (ubyte*) "4f86cf9bedc40560a5c9b74c1ee8f7f819349da85f9fe189f86"
                "329379ea11f8272480772ed39508918a9684700c6d5f4649d8299b23b565"
                "032120bbd809f3edd",
        .pMD = (ubyte*) "7233a0f331054dbc9589f1a8912611847a4993b0",
    }
};
#endif /* __DIGICERT_SHA1_CI_TESTS__ */

