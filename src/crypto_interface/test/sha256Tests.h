#ifndef __DIGICERT_SHA256_CI_TESTS__
#define __DIGICERT_SHA256_CI_TESTS__

/* Sha256Test is defined in crypto_interface_sha256_test.c */
static Sha256Test gpSha256ShortTests[] =
{
    {
        .msgLen = 0,
        .pMsg = (ubyte*) "",
        .pMD = (ubyte*) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        .msgLen = 8,
        .pMsg = (ubyte*) "a7",
        .pMD = (ubyte*) "2dbf9365a0b09d85bbd6176d8b2332aa5ae97bef652712473bc69165e74b22ed",
    },
    {
        .msgLen = 16,
        .pMsg = (ubyte*) "18b3",
        .pMD = (ubyte*) "1db739a6f15a1cb37d907929c926e91ec62219865a81f3ec57275b9e80d6b9e4",
    },
    {
        .msgLen = 24,
        .pMsg = (ubyte*) "05b111",
        .pMD = (ubyte*) "9d4aa69181dd878d0b345bf534096e6627d4a92bd05009685c1b565facc6848e",
    },
    {
        .msgLen = 32,
        .pMsg = (ubyte*) "f79680de",
        .pMD = (ubyte*) "7dea442d2473fee22f12ab3e1838fcb7c32bbde18efd9ac875ef310b3640e07a",
    },
    {
        .msgLen = 40,
        .pMsg = (ubyte*) "549a9ad07f",
        .pMD = (ubyte*) "537afccc9538e9e15ce6db6b1ca3af7b0e61c5c35d8f6cfeaebb38ef0fae90ab",
    },
    {
        .msgLen = 48,
        .pMsg = (ubyte*) "3e80de89a991",
        .pMD = (ubyte*) "18009e66190c4911088ce92a049cdac1687f9c9d531f2d8d4858fc3833b4aa43",
    },
    {
        .msgLen = 56,
        .pMsg = (ubyte*) "dad46562cb2642",
        .pMD = (ubyte*) "35741ab099373cefa6e4a365163cd871903bcd2cdfe830d83b62e9e64a827567",
    },
    {
        .msgLen = 64,
        .pMsg = (ubyte*) "8aa389b064c26b95",
        .pMD = (ubyte*) "a8fdd7e22153c783e1b5762c7a91d147ec9df5b587ff10df108df800de5212e5",
    },
    {
        .msgLen = 72,
        .pMsg = (ubyte*) "8262a65e1ddd97a43a",
        .pMD = (ubyte*) "08d34848df4311ae2d954ba6aeda4bec112bdcce6fa47a33aec35bb02f9a9783",
    },
    {
        .msgLen = 80,
        .pMsg = (ubyte*) "a892011bc747eb855c53",
        .pMD = (ubyte*) "ec64830dfaf245899f774fce9d3114498367286ce16de3556674bff82b0c0931",
    },
    {
        .msgLen = 88,
        .pMsg = (ubyte*) "a48abedef43fecaad5134c",
        .pMD = (ubyte*) "68f73ba49807dc9f486e9c51ad5e136076ba8f2f8670f46d68c331145015b9c7",
    },
    {
        .msgLen = 96,
        .pMsg = (ubyte*) "85654ee556d4997a790575db",
        .pMD = (ubyte*) "c43021501e4d3f78bf99614d227e10a692e37e4386724cd344a9cebfa856ca79",
    },
    {
        .msgLen = 104,
        .pMsg = (ubyte*) "f6cdb07ea3b956948ac435313f",
        .pMD = (ubyte*) "88b08e6b0173ab36badf2580623b612ca5e547bbaa6b160be4bc472d02342ccd",
    },
    {
        .msgLen = 112,
        .pMsg = (ubyte*) "77f6a409be62e403e3fa41b5ac3f",
        .pMD = (ubyte*) "ec52e3c3f1fea5ffe1f4a1a822c4a23f0200e1828c413122d5041c1d83536935",
    },
    {
        .msgLen = 120,
        .pMsg = (ubyte*) "80f6c9dd65319251e5612e344f2bff",
        .pMD = (ubyte*) "766cd2aa76b2c730aec2ecc02177688b096ae77eea5508b5013def8d451f4fee",
    },
    {
        .msgLen = 128,
        .pMsg = (ubyte*) "99aea7024dc119e62fb6ab1d040b72b7",
        .pMD = (ubyte*) "9fcb6fee14b3ae23509da574d77722221355ade3c5437f6e52255dd2e6675d58",
    },
    {
        .msgLen = 136,
        .pMsg = (ubyte*) "668f18a2068202d8c65d650f3ce83c6bcd",
        .pMD = (ubyte*) "c009543872397d101e09c12688288e6d200ccbf951e410f8a57d4ea7935a6fd2",
    },
    {
        .msgLen = 144,
        .pMsg = (ubyte*) "1e9f1f41e702fece03a95a0b9f1c6bdb6276",
        .pMD = (ubyte*) "bc52dc9e46db7b08a290391f6bd9538e72712d235449a7a2696a107c054af095",
    },
    {
        .msgLen = 152,
        .pMsg = (ubyte*) "5eaddb6b1dd47b90e8076392ef0861de803c50",
        .pMD = (ubyte*) "c28f931e78cdb9223b669fa6f2e226aad05744f22e4a7d61425dca62bccb0d4e",
    },
    {
        .msgLen = 160,
        .pMsg = (ubyte*) "d11dd2d3a22e5377826b43f08174586a297b8263",
        .pMD = (ubyte*) "4aee0fb36639c4b0dfef44d59a1d6e1624e26ad059de7608a5eb6c424ef7ae02",
    },
    {
        .msgLen = 168,
        .pMsg = (ubyte*) "b4ba5898f8289b6ee26b0e9ff48ee5a19ad7981bb1",
        .pMD = (ubyte*) "b53160a059f2af627d9df426400362837dc043f7fc3da869ff4d5dcbc78fbc71",
    },
    {
        .msgLen = 176,
        .pMsg = (ubyte*) "0b7d448c0aff7fd581e438b4053ad2541f354221a22f",
        .pMD = (ubyte*) "201b8638bb6609480b4f129017b875e13c3cb80edc2a4e42abc8e1594c65fedb",
    },
    {
        .msgLen = 184,
        .pMsg = (ubyte*) "747572afcbae51b8ff6477a9448c5b2b6e390f1db55820",
        .pMD = (ubyte*) "d45badfed16ab292d68f1c048e36846fcc61253a28cf3911e67327d53ea59b43",
    },
    {
        .msgLen = 192,
        .pMsg = (ubyte*) "ea25e2ce50e8f5c12e6672a1cd121605f3eceaa310ed17cd",
        .pMD = (ubyte*) "bd9cb5ede2285363b5352b7d4874de663203f8484c6d432cab7a4b76a8ac3987",
    },
    {
        .msgLen = 200,
        .pMsg = (ubyte*) "2ff54429f160311748384e09d4aedec78cef231e5d41218d13",
        .pMD = (ubyte*) "b1d42021a03c5bbf61fc8c4aa93dedcbcc7b4c5d83b78b1dc2ba77249c4664ec",
    },
    {
        .msgLen = 208,
        .pMsg = (ubyte*) "1d42723a4c828f8e8c55a3ede13983e27f2b8d67461747fb8994",
        .pMD = (ubyte*) "18c850a9456c6fab38c444f3dee341c1ac41076888938579385822d09c89030d",
    },
    {
        .msgLen = 216,
        .pMsg = (ubyte*) "21daacb0e865b0f94eb387722897c827e31676debec9d49c36837b",
        .pMD = (ubyte*) "899b7603aaa9be2b01e34dd9afce7bc2dcb82f561689276fb9ad959e47bb81f8",
    },
    {
        .msgLen = 224,
        .pMsg = (ubyte*) "4e4eeaae4bab14ac1f05c69a8871cde3d55019849e2e1413b3ea3200",
        .pMD = (ubyte*) "64dc75e4558925624a8826dc96761ab9aa94859110f5bed375a88054149a9d83",
    },
    {
        .msgLen = 232,
        .pMsg = (ubyte*) "24d86ec9d01ff7510f24eab9541af9fa8bd0097559e393cfa6324afe59",
        .pMD = (ubyte*) "39719d0e76f0a65c8ac8c7f57c0c70a7ed493fc8f255ff9a97324c7d99d97711",
    },
    {
        .msgLen = 240,
        .pMsg = (ubyte*) "693dadc6b001ce5568e82a547aca857e83591a3a1e56f57065059e9cb5de",
        .pMD = (ubyte*) "f4736ea93d2976610e98e49fb76d7d9ae4a550e250980f644c1b84639b7787fe",
    },
    {
        .msgLen = 248,
        .pMsg = (ubyte*) "f1badf63af339fe42c00af8ce6f4a76554ffc87fd5528d35e7c482b1997559",
        .pMD = (ubyte*) "aa77b9b6ea5de6dd595eaa58776bef0319a49f7d3a28092c91f41db57a603fb6",
    },
    {
        .msgLen = 256,
        .pMsg = (ubyte*) "a9ab044b342d560d02c5c26b423c000d8a1a8466100f513a1c91125ebdc767c0",
        .pMD = (ubyte*) "8d978f9bf44fbb319a61b5032f3afa62c6e68326f02011328bf99e35c9560bce",
    },
    {
        .msgLen = 264,
        .pMsg = (ubyte*) "939dcffc1cf1409e989c2674b69d54997cf39c26e8b292edd855926a275605f619",
        .pMD = (ubyte*) "22c71000a6a82e46692bb5e4b012f89d6cae25451dd69a2ff26e972097d1176d",
    },
    {
        .msgLen = 272,
        .pMsg = (ubyte*) "f55413f3e97adf162fd38a2dde326dc39dab1da851a532a2f92f4d60d59859afce39",
        .pMD = (ubyte*) "a40904c9d3a1f828d6ab3e6c4e647b79c7593de92bf7407c31a2323e1a73a2f4",
    },
    {
        .msgLen = 280,
        .pMsg = (ubyte*) "f51162355943f926a066e59fbbb83ee72ec238f0702ea8ce90d8c36d1e282884499e21",
        .pMD = (ubyte*) "d7077b4ecb349f0c1fb9cb1a9379d841c02231e180d4de19e4147e48594cbc3a",
    },
    {
        .msgLen = 288,
        .pMsg = (ubyte*) "b44950d79bb1fe5d97548d82f322c248b9c92269ca78ad3e2de9c9dfa89e7d8c8d6bdf4c",
        .pMD = (ubyte*) "74d5f188b083c55c1bdd33f2c1d51554d3916fa4830c6cb3f9b64239ca5e49f9",
    },
    {
        .msgLen = 296,
        .pMsg = (ubyte*) "566077029ffd71dbf97a9ac165231c05798269225982cffde2d44c6b2892a3f42322afd7a5",
        .pMD = (ubyte*) "1733c457eef6542e60f33c735017926ae3aeb366fea41d1b60853af1ad05b1cd",
    },
    {
        .msgLen = 304,
        .pMsg = (ubyte*) "e59481fa4109cc636d9249df56f8f09d45f2ec2a619a4186761eb27df4b8e2343be0b90315c0",
        .pMD = (ubyte*) "d4d4f7c95c373d7c08ee8e79e76c9ad3eaa7645d6eb91585c8ba39e9469ac233",
    },
    {
        .msgLen = 312,
        .pMsg = (ubyte*) "70a066038e3324a16daeb23ff91885cf6c97c13820eda9fca14359180726b72c83cfa7db37a77e",
        .pMD = (ubyte*) "33b089126e3b43701d824d757412b201f3ac61e43061556c95e23b954ef8913f",
    },
    {
        .msgLen = 320,
        .pMsg = (ubyte*) "0a4852d3a3aecab07d0a3439d184a970a6d29662e9ff6c07bf6b996a1a14b8098b13047f576a1360",
        .pMD = (ubyte*) "761af1709a07db3a226f5dc5587a494c602a3cedaa1abe9683be7ea7e1e968f0",
    },
    {
        .msgLen = 328,
        .pMsg = (ubyte*) "8ad8c03b20a2fcfad1089fd52d6a5561c81cf4a4e07549c94022171864c05d26deabd849f910c94f9b",
        .pMD = (ubyte*) "b0d4a767c25e9a918770e89cb5d033a777690347e0a61afa727004297a0c9ab6",
    },
    {
        .msgLen = 336,
        .pMsg = (ubyte*) "fd3fe4e77b94be0d286dcd533fb1acf7d5a9cfaaa7b569e6163e8c8170eb92837118bd350a841a7a6049",
        .pMD = (ubyte*) "b243112739ef93061b097d725054488d16e644e1a1483c1726a68ff524495250",
    },
    {
        .msgLen = 344,
        .pMsg = (ubyte*) "533071913629d6ad3f3484799f0b5a235af29facfb9a4eef8544b0dfac293010451a6c79fc64887845f6c7",
        .pMD = (ubyte*) "120420cdfd9a06d49786f8e799c9c7f39b286cf1a27e859423e69ea4d7f6ede7",
    },
    {
        .msgLen = 352,
        .pMsg = (ubyte*) "e224b725d6842a59dbd45b9bcf0cb8ba139947af8f52d12ef7ad467b4d335d7fa8317b1b33b1d6bc78a8da30",
        .pMD = (ubyte*) "e55a4fd463956bcfb55b0b575c01dc1f8fdabd1fe6767de48a90e0b592302de4",
    },
    {
        .msgLen = 360,
        .pMsg = (ubyte*) "8c9baa39042a556e0395195306b77635b7df8d8063763582aee24c7186a94bb055da1d4e7ba932d0fb59cf3074",
        .pMD = (ubyte*) "282d3801326a99ecb6b395af3adc71bc5642624decb0974e345c271877f47b41",
    },
    {
        .msgLen = 368,
        .pMsg = (ubyte*) "e19ab20fba68813ab540dfb0e634a5b3124bcf291d278858c2e587ee87459e44ef0b90e3f1a52448a90d77e44ef1",
        .pMD = (ubyte*) "4bd25dddc429cb66f3e6e52e7de46267f7ca51ee36d2d02f63bd7781554bf5b7",
    },
    {
        .msgLen = 376,
        .pMsg = (ubyte*) "43dc01f175a0e6ecc336eada53bbfef24d453314e2d5da5d8d87eaf8980ca337e35a71e2e1a213cfe383fcb2997dfa",
        .pMD = (ubyte*) "141461340002885d44998f0f08b8ae1b05966f86f3347629e46987e5e6618b79",
    },
    {
        .msgLen = 384,
        .pMsg = (ubyte*) "beed7cecf1d480f3ecf81d42c16d2248b9a940b749a0a9d0412ddee147b4c10c8406f2499d8458aee588feefd1002121",
        .pMD = (ubyte*) "52c7dd969e8e8e3ec0fd56655a0cfcc5b1c9357a4d41ee455b60b6ba04fb4269",
    },
    {
        .msgLen = 392,
        .pMsg = (ubyte*) "9c6ab07843a89a15a12f5ff3bff4f4c6cb7c9c58bdeeab373b6c90aab9a312eae4a1da8f41e7324911c00cd079d1461edf",
        .pMD = (ubyte*) "cf5fe29cf4b334f8b9ab0ed28486f0f4ace4e60523254978139767e13b8312fe",
    },
    {
        .msgLen = 400,
        .pMsg = (ubyte*) "30b092771683cee5ac6193bafe38e67cc9e30401ddffebe0c5fa1c25aa6ca04975ab4961349a3a95bfc1a9d49ba3e4c61e4b",
        .pMD = (ubyte*) "2ed5812ee174636d5f99240349a84a07e31abbddc800179dbdf905b99598ba49",
    },
    {
        .msgLen = 408,
        .pMsg = (ubyte*) "25d388615a907e330a4f104c8e98f797f5cd59ab4960349f14420020239f90c28ac83a94e97137f7ed1c4cb019d5aa3bc62014",
        .pMD = (ubyte*) "bbdfbd21f411e380cf88fdf05be81317f28a68ea0607930a9b2d33a0114cf140",
    },
    {
        .msgLen = 416,
        .pMsg = (ubyte*) "68429334013e89d2e787f8e1e64da32a6ec92dd3df737e33037569e5dc5f8b1ba11c763503250f93b4f434a72abca24ea1571660",
        .pMD = (ubyte*) "b26ff2cf1748a64727d90506d8199bdd8ff0b169b8d45fee8671fc587fcbf838",
    },
    {
        .msgLen = 424,
        .pMsg = (ubyte*) "e582205a1c75bd5ada4476fcc45036572df0041c89162063252f4faa164a731a707d5e0db884e8ce9bac3f9fdff07f019b61832fa3",
        .pMD = (ubyte*) "73668a9572a5fda71b6632fd19ec9255f4b8d34baafc19c23669fb925e8fafe3",
    },
    {
        .msgLen = 432,
        .pMsg = (ubyte*) "e4c7cb2c6f637fb3315b1d86f1a8ca032b2bf2b9be93986fe580ea6868e819e614bb67ed68c2824991cd10d3990d8befdbbf4f59ba0a",
        .pMD = (ubyte*) "5d3d69bb2c44b716b4a63d55066a22dcc83a4713f7f8b6466e9cfd532e7ab080",
    },
    {
        .msgLen = 440,
        .pMsg = (ubyte*) "29cc5d2d691f693507618f41a67aa51fec45a72ad997ac6e577e180d12c612e289c23963664992cc0afec57a6dd48a9425d25ef1c4147a",
        .pMD = (ubyte*) "0eb47df776929a6b94fc2f15587c452e1935d5a3bd893e3a1c9f57f905144db1",
    },
    {
        .msgLen = 448,
        .pMsg = (ubyte*) "e9fa78185cd399f8361b7a6403c1a4d331089dc2177d0c4c362c1dfbbe1327de54d78ddb12b6e247cfbd50b4a13b3a0aa17520daee9bc3ee",
        .pMD = (ubyte*) "bdfb333cdd617c7ca3dc2530b9f66c1285418d0b48916ff22ca7b53563c68c31",
    },
    {
        .msgLen = 456,
        .pMsg = (ubyte*) "2b7de5854e6673412dd640bd471df0646d98f62ad37a4d7068cc682763b36b391ef29b2428af13e8967aba24998b717c564b913df1179444eb",
        .pMD = (ubyte*) "af8186c0466ac0c6d707a13c6d6b2881ac8ea19cd5f7db236fa5151065cb3374",
    },
    {
        .msgLen = 464,
        .pMsg = (ubyte*) "f2231468e243252134197dc9673b2bc8995be680ef1c99c837241f9ccc724a12baf22b90234f8d3de209c3b56dc7a40100eed3c6f87244bc7ded",
        .pMD = (ubyte*) "9aae18b35aa2c7db0d84b855b4f439f1502ddb416e932487e674a83de8a8dd4e",
    },
    {
        .msgLen = 472,
        .pMsg = (ubyte*) "10c15fde078d2a351d3c871f9f394af11d2599051ac146ba070f5cbd73b4f7877ca1592789f23b423b166158a0317148aabe0517e079ffed547c1d",
        .pMD = (ubyte*) "57c991d8a38bc0b64502032cd37fa800553ba32e50e6c4038fae297e66368c0f",
    },
    {
        .msgLen = 480,
        .pMsg = (ubyte*) "32a4cc8d8b01bce16143e9c3c155609db81e37bab95816b53ea0f732b2c929cb8f769b4ec4e8572559144d1555f9522ce03068f4a5c540ed7a45fd3a",
        .pMD = (ubyte*) "137e406695a4a36632a418b7ac652aae50196a8236f43dd152adba6579d75db2",
    },
    {
        .msgLen = 488,
        .pMsg = (ubyte*) "692c3f60a1e33d3ad25038c7f0e5e7b28b466d60ffae2e78eb8fe0a3e478e5906a3cd83c1a51667026765f8b03980c8161f7c4246085baa2018e194fda",
        .pMD = (ubyte*) "e8caf9af1abe00d0e0f2775129f4dc7c3bd9a36d99d1aa1352ccfe677f7b3b69",
    },
    {
        .msgLen = 496,
        .pMsg = (ubyte*) "36af09d8471257c53662506114fc2d0b8c6a9fc76bd96d4960cd5e4fff1359340cf8cbc2f7b84949a33977ed6bf928446745c621ebadf5aa51b473b1f9cc",
        .pMD = (ubyte*) "fe06fe917fbdbf8e43ce32bfed2e60868755067bebd2f8e0e34a538c3cf3d82e",
    },
    {
        .msgLen = 504,
        .pMsg = (ubyte*) "e16f495fa00165d037c0dc92c2e64fcaa7d6e517d452a86a48ee2b18d5c4702d246a0a04f9217f14b84ff00d2930fc2478c8e1aa801ce4e448a1f417cef58a",
        .pMD = (ubyte*) "59592ad2985e128e9ea50ef7563356331cb64089370ba5edbded70cb11cc694a",
    },
    {
        .msgLen = 512,
        .pMsg = (ubyte*) "3a56b8a02f5e2ce3c8af2576d861ab4c58162b34af2dd5aa313842f3e5b05a698be87513dd40c078169be3b5b113e0ce73eb3e42abc468e2b91450e2cdd55731",
        .pMD = (ubyte*) "54fbc8ab4b2b242dfce7b34e318ebbeab12aba9a5a7f94ea02fadcd1969d18e0",
    }
};
#endif /* __DIGICERT_SHA256_CI_TESTS__ */

