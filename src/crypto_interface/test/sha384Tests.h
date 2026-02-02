#ifndef __DIGICERT_SHA384_CI_TESTS__
#define __DIGICERT_SHA384_CI_TESTS__

/* Sha384Test is defined in crypto_interface_sha384_test.c */
static Sha384Test gpSha384ShortTests[] =
{
    {
        .msgLen = 0,
        .pMsg = (ubyte*) "",
        .pMD = (ubyte*) "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    {
        .msgLen = 8,
        .pMsg = (ubyte*) "45",
        .pMD = (ubyte*) "175806a86d07e809e30caaaa915c0babfe938800262bc9556408a54306ce48dd71923ce40a48bb2f0496ca53d3b84904",
    },
    {
        .msgLen = 16,
        .pMsg = (ubyte*) "0ecb",
        .pMD = (ubyte*) "77caae4f31b1cf17ade881287d541a34ccb3a59a73f33351b6850916186eb5eb9c0b81e4e4133551344d5e8ca8b3f328",
    },
    {
        .msgLen = 24,
        .pMsg = (ubyte*) "408192",
        .pMD = (ubyte*) "a1f1d333f5fcffae1c9ae8215b7c054ed8e819bacf93756d885ac62637d08c0f1694c55c5d15b2b92885fb5a13689f2e",
    },
    {
        .msgLen = 32,
        .pMsg = (ubyte*) "d6dd84cb",
        .pMD = (ubyte*) "22eb076d824924c92c142b329587d0e16cb7560991235db97a1501f94bbed9c838bfb1ccf9ea48b5106b46d902ed2753",
    },
    {
        .msgLen = 40,
        .pMsg = (ubyte*) "91ea536a22",
        .pMD = (ubyte*) "8179e0de3f50a07c34acb2dd9735c435e9146086b5c79787c481f78e22a7a1bb840a68d76956a31a0d0675b3c1333e4c",
    },
    {
        .msgLen = 48,
        .pMsg = (ubyte*) "264f1e00d885",
        .pMD = (ubyte*) "12ee80d63039a4319dc10c815f741de2a18b0c2799931eee32bd3833b4aebefbc384301a00f3960a5fe9c1ad6a0b09c2",
    },
    {
        .msgLen = 56,
        .pMsg = (ubyte*) "909f0de33437f9",
        .pMD = (ubyte*) "911462ed7f726707d98b2c1724aa8d24a8ad947224bb34ff2b424861e5b7d5a3308c08d52cfcb72085de253ae52de0bf",
    },
    {
        .msgLen = 64,
        .pMsg = (ubyte*) "e0f0c566948533d4",
        .pMD = (ubyte*) "a07eed0018e40407b1329d89ff4dfa1974c9a64b0ed37e2d822f9ed9bdf538e1db0e089db2d8f089511c08ed0582a640",
    },
    {
        .msgLen = 72,
        .pMsg = (ubyte*) "124491331f937c2187",
        .pMD = (ubyte*) "bce810cebd5dbb97ecad2cab680b3f7e182234129e175e4aba5fdf74734d19f856c7daa5620f805de6dd3e8b997fba11",
    },
    {
        .msgLen = 80,
        .pMsg = (ubyte*) "d45a595c41f524690fea",
        .pMD = (ubyte*) "0f31cf98bc4b0afff5b82e6f59dca5e1371dcd3f4190d5e2b1a3245287cb3f0bbeacb5535c53f30bb5dd69f31533579d",
    },
    {
        .msgLen = 88,
        .pMsg = (ubyte*) "7b6ffcc8febfc0a13fd145",
        .pMD = (ubyte*) "90bbcd43a210a5af3a4182cdfcbb3e1586553edbfec85aa479e0835f35332f6dd5d7a69461c8f508dd6a338eece3a189",
    },
    {
        .msgLen = 96,
        .pMsg = (ubyte*) "a4dbe4eed0de844d346ee153",
        .pMD = (ubyte*) "2a2ce088c426abebcbc0b01850b1740932330a0608ae44ad3e35bb84113ce8d18f48f391deea53f80cf3304b29986543",
    },
    {
        .msgLen = 104,
        .pMsg = (ubyte*) "ed04bb4f552e57734490e0054a",
        .pMD = (ubyte*) "6584a0c5323c6ab2319932bbbd2edac18ab653f27b4e6ce423f254c28742ca583583da99ea3c846ff729eb79e730c1da",
    },
    {
        .msgLen = 112,
        .pMsg = (ubyte*) "c4ebf353fd114a32f0c4cf087c33",
        .pMD = (ubyte*) "d48993390b287986bc2828b9764bef646e0da69074bd1f93b3994b7befaa0716651ca735ac7d5104ab795f62a09850b8",
    },
    {
        .msgLen = 120,
        .pMsg = (ubyte*) "3bcd62f7aed567d2a0b6e344d6af67",
        .pMD = (ubyte*) "31dff3a6aea62ff2cb3ddde04c172852084fd6a899038dff5042796a7286770d6d14b961dfc1de491174aa4225de1ed7",
    },
    {
        .msgLen = 128,
        .pMsg = (ubyte*) "9706b36eeb94a9e99f50306a1d09a661",
        .pMD = (ubyte*) "105f2742fc36fa79c09bb787727c95109e421e41d9a84fd4f6cf064a69e26c611056117f303be10e2ef82395a5d74931",
    },
    {
        .msgLen = 136,
        .pMsg = (ubyte*) "3e4ca01d66c1bd8e0261c119dba1d88b9f",
        .pMD = (ubyte*) "d5e134c0c2ca562c1ecf086808716db962542e61c67ac0c03e0fd4b8efd1f71e466a3b70607113d08b5786fb6dbf2542",
    },
    {
        .msgLen = 144,
        .pMsg = (ubyte*) "7bc028b7624df91de3ecef00344f082f7466",
        .pMD = (ubyte*) "0364a800f453cf4e80930609cbd8ca08d768d4576dd2fa32b5f8539703d7ca500ecf558f03d63ac1fa5e826fec93c9dd",
    },
    {
        .msgLen = 152,
        .pMsg = (ubyte*) "3e7cf13bd0659375fe8093c36c734d20f63232",
        .pMD = (ubyte*) "267a1ff2e68a35b97fd81005d115595840108d7cf977c35984e235b038f343b79d50c03ac993688a4a78db2e9832449f",
    },
    {
        .msgLen = 160,
        .pMsg = (ubyte*) "246b52574cd3b697876c4df0674f58eb5a03d8db",
        .pMD = (ubyte*) "72ab6d948f3583ff4d521cb0a12ede3ea94d8309f15d8d5d094713061568e0c84c8e9bd24a241d1d635ceba812c4ad72",
    },
    {
        .msgLen = 168,
        .pMsg = (ubyte*) "731223120f2d4499fb2082da89c7db2cbfe0a1e6ab",
        .pMD = (ubyte*) "06c30c60a95f0cf75ef420bd9ad4bb332a5a7805d86b2374e96414281b62b4d8bd599fae9d547103dde84cd05f725c6b",
    },
    {
        .msgLen = 176,
        .pMsg = (ubyte*) "f051b61e8c015959ac6809dab6e9ec4098460c7c5113",
        .pMD = (ubyte*) "45ee78659558ca935f824ab933e1d6327f960ba899a2d88233d48615bc297280e80e4d01ca1bd760821da773e19e20ac",
    },
    {
        .msgLen = 184,
        .pMsg = (ubyte*) "5e8178a26509415e291269591ad989db2f06fae82edd3a",
        .pMD = (ubyte*) "31de3fd9f6c0c3913bd0b174e4d92df193702806dc1cf0d8f402c3ba55054df4dc74bd272516a6240c992573529adcbd",
    },
    {
        .msgLen = 192,
        .pMsg = (ubyte*) "523558f9adb850cb44095ee7658d5d86f0f44f770b1dac1e",
        .pMD = (ubyte*) "92ca0477a0804a1aa124a55cae3e535d37f2f56b79ecc262dd9745d9d23564b3c16a26cdab1c7c893571cc6c8518cb61",
    },
    {
        .msgLen = 200,
        .pMsg = (ubyte*) "a565efde9a3b8de625f87de4f65d0758a76ac0d094dcfe9aed",
        .pMD = (ubyte*) "e6c4c49cd3513e1381e9eb08569ae05ecba45f7c2c5c93ee8286b6a37a8ed78828f838c77fb3d6c175b3769545224549",
    },
    {
        .msgLen = 208,
        .pMsg = (ubyte*) "47743c67118408578694cf5f99194337b1311c8b5a8668fe3a76",
        .pMD = (ubyte*) "140e0ac70c42ca3500c6df4967545b528c6cd0de7c66d3ffc799e1112e20ab9aab41b997a2d28c73afc7787ea6e56ce6",
    },
    {
        .msgLen = 216,
        .pMsg = (ubyte*) "a81284081e689ac2424d3649d9416cb3b2a99a3937179a9742cc3c",
        .pMD = (ubyte*) "5b6f7a0c6c749b0f42412033af723202461445adb954adde7442d42d5e4bcd45e2a7f176b2dfd6e94e41e6c66b02c308",
    },
    {
        .msgLen = 224,
        .pMsg = (ubyte*) "e2b5a8783cc36ab15768dc7bd97ffa32c2dddbe2fc8fe3ad3264396d",
        .pMD = (ubyte*) "2498727a925b79866b780d3284b074373f6f58c1cac1c5437211c6d91b161eb22f6fe7e757de9efd3670f6783ea57aaf",
    },
    {
        .msgLen = 232,
        .pMsg = (ubyte*) "4e6ccd6b81df9ad8ff569cd7355fbff48b91cc233a13e05f5d5e1d924c",
        .pMD = (ubyte*) "31e0d84fe8510ce2c06fddfca9d106acba088192c6af0e2e901d0bb2c64ec3c0cf95a5c69be74c0c1d0d3fdfb93505cd",
    },
    {
        .msgLen = 240,
        .pMsg = (ubyte*) "5225e4b316ac1ed769b05894348a5b1b3410711da0af27850dbb50669002",
        .pMD = (ubyte*) "ad17d5d12fa80993e23b8e34bb4f7b236ad529671be48b89e1bcab239b7ccc86cac3d671b50c0cc307ef7e2141f88fd1",
    },
    {
        .msgLen = 248,
        .pMsg = (ubyte*) "e3628275157f54cceca2329b8503c9eb971118d0b0abd340c1940524dd21fa",
        .pMD = (ubyte*) "120026466eec30f804cf086038e07d41e2e7a301c44970eb71677782dcc999ff57b66c55611a0415057c1be6cadaaf72",
    },
    {
        .msgLen = 256,
        .pMsg = (ubyte*) "ffe4e448a2f9f17c36e95ccfc2f2771b4a5a8468430dcbb24b87eaec17f46d44",
        .pMD = (ubyte*) "4b6c946d85d4f3cd209f274e0c25d590e3943040fcd0363231aa4eb029ebe6053c3f73014be789005e012edcef64ae7b",
    },
    {
        .msgLen = 264,
        .pMsg = (ubyte*) "b66ece4591484030450b978c4fd4cd7920d98e0168a09bf0947070e5950625aae4",
        .pMD = (ubyte*) "f435468f8657c1b2c5b4676053cb40c0b1ec68d9fe67af9be3301bbcbe0d6a9f50aedf18f8cd69a770d9e7226ba6e4f4",
    },
    {
        .msgLen = 272,
        .pMsg = (ubyte*) "219aee2794f508974130cf1c68de9a7c3faf6a8ae594795f972316e8263eafa1a8ef",
        .pMD = (ubyte*) "d6bb691e5609f49cf4792417fdbc8dfddd6c6a587ebafb305a4f17f5bd3e4890fa4c5c73e6a837e691b9d2cd1eacaa7e",
    },
    {
        .msgLen = 280,
        .pMsg = (ubyte*) "82d6a2598fcab2a381c1a67926a2da9cc8da167da6feaaffa6b1bd7d44c9e20fceadec",
        .pMD = (ubyte*) "ef0d533ce31f34e951b7dfede886298af7c76d5cd4217c9d1a00d1577c82e6f7598c1ec10b03a9b3f2cd5b1716dffacf",
    },
    {
        .msgLen = 288,
        .pMsg = (ubyte*) "16ec3a15a54270055ac8283cd72f9f13ddbe4f2c574614049a588ecbebb5c67341061407",
        .pMD = (ubyte*) "2392924773ee66c3644b14d954da48a0f702aad159fc0f75da6d5746d91b41458fc05c976a5e860e3b6558f3bc603578",
    },
    {
        .msgLen = 296,
        .pMsg = (ubyte*) "de7d0e3e7628f5158e489b4bb3c59e180bbeecc197c3286db5454f35e94a9b7adc65a77ba5",
        .pMD = (ubyte*) "e7006b4b2c029e92da50ab71a711bbae3af5bf51c6bc379c8581641c06adc44d85d76e2ae61fe236b7700381342c67d4",
    },
    {
        .msgLen = 304,
        .pMsg = (ubyte*) "42b48b7597010811c8a0d4f4922da93aac512167a1412907dc87b3910105ac9184372e0674b8",
        .pMD = (ubyte*) "c1043153398edf3bfffa5c00e9c6ed46c424c88e0eb54c0e954e59c0eaadbe9b449af82d07d14b795f5e1c889fa121cb",
    },
    {
        .msgLen = 312,
        .pMsg = (ubyte*) "7b627bb5a27acb3ce6632d011d6f3c7fe789c3a485be2f7beffd4408201b1074b51a1d6ab6abeb",
        .pMD = (ubyte*) "2e319cab4ba129dce55dd633155298004313a2411ab1366bcf725af7de95b98462e8955642cff38e6c9ffc19d68a2c76",
    },
    {
        .msgLen = 320,
        .pMsg = (ubyte*) "2ecccdad12c0523c4da238221320890febfb11701cad7037624e6ddae6b88d9e6deae515d0aa2ce5",
        .pMD = (ubyte*) "4706eebf36d718696e2e613a1676fe17cc643569159d470824bc096c08c8d861384a9367eafa87736a81afdb02f149ac",
    },
    {
        .msgLen = 328,
        .pMsg = (ubyte*) "d79ad21341d5f08ba488830cb3e9fa1c6a4f5e6b48972a5bb8c65ebfd0efcfe33d58c1ce7ed8b7c351",
        .pMD = (ubyte*) "484ba7ccc0703500d2c4327d67c8bca4860601a949179c3b0120d5731cf189b61d201def9012207f5c2ffb8d517e704a",
    },
    {
        .msgLen = 336,
        .pMsg = (ubyte*) "987f56df086f029fb8cce453cd37e2d90195224e451dccc8aaaf114881686ceac173275faa22229da83d",
        .pMD = (ubyte*) "05bf2a443ff391f81646c5be3b09411b58c1cd007208a7bece7eb08868c1e1efdb5cb6ea9ea0b3890f5a0bc5b73d0f17",
    },
    {
        .msgLen = 344,
        .pMsg = (ubyte*) "0f8a7411dc8598a752b881a760a4bc3c1470e4610e8bbaa433937829a67663f1f4d7a05c8eb348ed7d44bf",
        .pMD = (ubyte*) "0d8717d2b08edf45b1c4adf1c46dd332a5dac3a2d009958731f5bf5f1512ad31e28b278a50d16350e6ccaaa21ca394e3",
    },
    {
        .msgLen = 352,
        .pMsg = (ubyte*) "ea46b8bfc2e3b87d91a23514ddc1094873af75a7b41312b130100a3c76c78717291e6cee57c0446d076677a8",
        .pMD = (ubyte*) "e2fbe72cc4fdf59f076ef9091880d36786654b9b8c576a426005aca1a6525fc86e50fa02af272ddb7e2b48aeb270465c",
    },
    {
        .msgLen = 360,
        .pMsg = (ubyte*) "c070a75aa73ff0a69738e94b34fff929ad966a7142d210b8030b2c4bda188fc3cb7a03d97bd8e67befac181f97",
        .pMD = (ubyte*) "6928ddcf9b4428fec8ffc7c943f1c0a7771a47ad0c613764849df2c5b246228caba9910b9232214b8a969735dde99a6b",
    },
    {
        .msgLen = 368,
        .pMsg = (ubyte*) "f9b811f766e08de4b8e8c596d91ba0e0a400628e03e7e59c54c225a6123603a0b1f242c7c940d6d777d95e7f01fe",
        .pMD = (ubyte*) "8a55f58c96d0ffeb7382d5df5f014ece7dda3d311345abdbb55ff06121be6305942273e82cfa395167a8b6d59ffeddce",
    },
    {
        .msgLen = 376,
        .pMsg = (ubyte*) "472703ace8bd0b6a646312b3b33b78f2e0383bc26aea7461e9982561f49031a143bbac7c11745540c49a61e2d0e47b",
        .pMD = (ubyte*) "42d5bebf7cdd522f1a4adc6734e93df11015d794d4e63be50916a1780ca4bff22dc84bed07fd896d79cfdfd491dfc826",
    },
    {
        .msgLen = 384,
        .pMsg = (ubyte*) "0f8881dda1be5b18d0ce9470fde3ba0b49ef0cfc054a8b0c6b9c54ba8bfc2c8087595d580319c17fd8011c790855ae55",
        .pMD = (ubyte*) "116164fff79f295ad9b5657c8db50c412ab55129f5ac0d26cb601b304f8b91f1fe3be44d87c6106ae015e06fb397cef7",
    },
    {
        .msgLen = 392,
        .pMsg = (ubyte*) "eebf107e0240951bed79397c1d3278c477c60d4d417afe9a400dd88d1d913cda0e799abcb2f23de73c7788bdd39f7fc439",
        .pMD = (ubyte*) "6e55c3284275bd23a9347b313794286d92d32d6626a967e8e71a9f371a55704f587c27c02a884f7b6f40592a30aa525c",
    },
    {
        .msgLen = 400,
        .pMsg = (ubyte*) "5293ff20bf4a1f32769d003f7a52e1e00e6f3fe8cbfc9147ef09362ff8f3ac7572e402390d9990c9f268e5c35781017a5174",
        .pMD = (ubyte*) "541a2060a49a8126a55d1c8f7d317bf8fdd24a3297773282ee57c80dd91cc0bab8d454bf3205920ba16b65e0eb7f3b21",
    },
    {
        .msgLen = 408,
        .pMsg = (ubyte*) "5a15a1f581f1592525aa7e0da9aa1b991c51673603a2a42c583c472ed28c592f67421d781001f3f8cc5b7cdbe7fcff5e7c250c",
        .pMD = (ubyte*) "18fce5e50ce4553abffe8549c6c38842622d47d5da76eec9af95da750d56acf9597558b937f34a8e80293931e65f3499",
    },
    {
        .msgLen = 416,
        .pMsg = (ubyte*) "a510d6a15d82f813bd7df1af991dba965baec38a901c9501a6aab678f3e7cc0afadf0641ea8eb82c689a45b28e414225348fd81b",
        .pMD = (ubyte*) "44c991cef9c8e0f2ade1a9dbd46d500caca2b4b047a00785e9aada6b850c3c9550072776dcfcf2deeb4f885e02bd8445",
    },
    {
        .msgLen = 424,
        .pMsg = (ubyte*) "b67b497c3f4cd61ad48491011bfa855ca3d9c54430a25ee453708adb3e8026e1d7f066ae0bc7c8186536467bdf1ed05df8d1f95206",
        .pMD = (ubyte*) "c2d7dcb9312ea3e83bbcc4f916c8c8a6146a30b4fb91d90fcb5f3a0865cf3a39a22a35fc7a46c2b52d2cff6799ff98f7",
    },
    {
        .msgLen = 432,
        .pMsg = (ubyte*) "a8c2523932ecc16c597279a0e8853d9e525eaf8cf475bac199f42dd8436ba80329c5bca2fc7b4e156e073ccef59c44aacc1421813c2a",
        .pMD = (ubyte*) "aed998618da8cb3f70790ec9970f69631a1e707da209d03bb39c86953116e1cf12fd0830f5dc2e13c75a40b24adead50",
    },
    {
        .msgLen = 440,
        .pMsg = (ubyte*) "5e0b83922f6649f71a9c06eb04cde4389fb6411f3b3217f7df01bb1798c9cbf6115a619164368d0d3051039eec1510a77aa9d323ff73a9",
        .pMD = (ubyte*) "75ced4d9684fd880adfe5313cf9d0377c83cd7a8c9e704e80a95849add4fdddcee307c44b0805c33115ca9a99cb9f7d5",
    },
    {
        .msgLen = 448,
        .pMsg = (ubyte*) "4a56081c5191a6981ea829fb79523bd4ffc70538c8d2f66f4628c0ee70f8a48520c3f0daba6ec6160f961ede81230e8567204a80b3cae71a",
        .pMD = (ubyte*) "a6941a11bf465f4f590b9cbf91e3423a73dc64ab8127941c56fe20bd8d5d5d9b416f09de853f4e987ae4f0be510447e2",
    },
    {
        .msgLen = 456,
        .pMsg = (ubyte*) "456413d356f5537c67e07a8fd8d20fc88312d3354cbef59bf958851745812b012f03191598153ed50ddbbc29e22d9d498099c1dcffab1b62f8",
        .pMD = (ubyte*) "22b2358bd89830ec107b42f20f2416314f1dfe94bc67db287df2a6b2d877253be86a6c269191f49b51fb7b8c1c43e0e7",
    },
    {
        .msgLen = 464,
        .pMsg = (ubyte*) "6051e2accb284ed83a4306d41b6690a0b9bd36ea6270523ac977c96da9b0d664ab2f09fd8ad58f427524b3e1b551a5dd8f9b7a826cdc759e375e",
        .pMD = (ubyte*) "642a537cbca726f2802e76eca05fb1d8450ccf72c4af05835c04a3b8369405b2f35580bc0b6fe7a89e8db9438816dcbb",
    },
    {
        .msgLen = 472,
        .pMsg = (ubyte*) "98a4191f529620b1de678a19f2885766319af16af4260e0f4a8ed7ef3e434a1e5839dd4a669864077bb53464394089c24cbf25e6373a3a4c53388a",
        .pMD = (ubyte*) "12d9575fe7311a27849e4d39981dd1441e6c565ffecc5663705f3343a3454553c7214edf51e1ebb1beb03185a294a473",
    },
    {
        .msgLen = 480,
        .pMsg = (ubyte*) "115bdf1b43a4a52164e91e216231c2029e272063421ed3cad552b1fe0c7145b1e35a8062ed24ab82e862a0d695a53a1cc7430af1b9574bf2a4091822",
        .pMD = (ubyte*) "f0f693ce7798c4b64eb85bc70aeb378840ab845a149fefc9182769a966a7ec06f1e659d07d60d65516b2fd0f42c55ff9",
    },
    {
        .msgLen = 488,
        .pMsg = (ubyte*) "07c914b2c66fb55396294b83729353d96226b0c0fcaf4c822b0002a62fe6bc7ce55bd8f649fcd1b939bd1b747cdb4e710212876a6d110b9dd12b2e22b8",
        .pMD = (ubyte*) "041162407f5c93f41a89e7f39765de46a9c2a1159c27ef1f44699ad1099e18356c64f4f2eeaf78f6b44e0440560a82b2",
    },
    {
        .msgLen = 496,
        .pMsg = (ubyte*) "dda2d17dc04e1327b4e34110d81513a53cc3bbdd46cb6ab4552315dba52679ae732b5d66615c17901bc651be3bac0d7c6a21e785c8d69a378f30c645f39d",
        .pMD = (ubyte*) "4067211813fb224c09726d08a0fec35fdc42e36b585611928d2ac1333768ac0c8f9b5b17cfeaf673cebf4a9043aee7d4",
    },
    {
        .msgLen = 504,
        .pMsg = (ubyte*) "520508e11cc2bb43c1b4815b7bbd0439ef7db59ab2c46d010b4d5409fba903f97a79e59904e0e3445438403f7004c149e5261273545365322dc35cb3bb2d29",
        .pMD = (ubyte*) "b1327eba4889a7f6d7e1d71e34eab850327220e1274b90e088b3f090ac9d46bdae85ec373e7552ee4bf4bcc25ed1c6be",
    },
    {
        .msgLen = 512,
        .pMsg = (ubyte*) "f6fc078170f90db5456e11c01e321ed0876e47fd45a39972e9ef4ecea58c43ca5f99ad1b041d079a1f494fa2aafd71b9238e0473e3c73494ac2dff758187a5a9",
        .pMD = (ubyte*) "4de1d6f2d504980c5f82e0473977d948e639b3a7046fb628741e52d5a9b3f843d9e7c5ecac874e0fae248df8c9ebf388",
    },
    {
        .msgLen = 520,
        .pMsg = (ubyte*) "017e5eaa30d00deeb2a1d32c82cfa6d65df93d16d13fc4b49749d43b228ba25778c7778241d360df1d9c26663b6b804228678877e45c6cc83bba66d852e1ee8f81",
        .pMD = (ubyte*) "051a27118744d91627a45bbb5a4d895e46bce7a060a82f5f0fceb1204cf4bc95506a6c823508ea52e0851e9fc1fb0eb9",
    },
    {
        .msgLen = 528,
        .pMsg = (ubyte*) "e6291acf0691cd31af6a0675526f664b31f3c3be79747067b172bee05881c27cca9e593564bf6ae6e8ae6bbb231627e5cddebe92b0b7ed1c0df18f803b93641391aa",
        .pMD = (ubyte*) "20405bfb491f5efe972d1f357f87975019170cd84a29895844d9da512302b7426e61bd1af04a308ee0e39ca48928916c",
    },
    {
        .msgLen = 536,
        .pMsg = (ubyte*) "17754bebd13c59d70addcdb21043795766ae2ab060fbda1bec262613b30d020c6176ab9e4054dde60c46472a03613cbb3b2fab2038f75170be3f2d00e490343e6a7947",
        .pMD = (ubyte*) "05775808ee728605abcb231f17c644cfc25ef49255d5600e6acb535531c5c7d13fb406c3453a2bd752de8c9739361d31",
    },
    {
        .msgLen = 544,
        .pMsg = (ubyte*) "191e399ad1cce89cdbb84081a825c6c68ba023860835834b4ee23b24024caef73eb17119da1ead1ceae2c5e88742390dd36ecb5837b4e0a5eff428f3c95481be29341989",
        .pMD = (ubyte*) "90123e6f67469b69b5b4222d64fc25ee67adbd854ac69437cb591f0802ebf6e11f2fab046468c2f3bd88ae41ee19e5e7",
    },
    {
        .msgLen = 552,
        .pMsg = (ubyte*) "dfb6ed45b6a5059155818318fb1c49463563dc985cd50caf5f3ad8a3c2918c99e74a2c988db5159896bbe2dc0dcc8d826718d6590902e9f20bd13bfa3ca9b5c666bb1430d3",
        .pMD = (ubyte*) "16f72bddb17ed5493549dc7827cc5125073a8f577718e02b28c37af326d466e841bab066933d3575f93583b7d9358f7d",
    },
    {
        .msgLen = 560,
        .pMsg = (ubyte*) "72b76f1f3863b2c14c76ccb8d7c258036be788d9f273bdeee54e54f1bf56c259b046e36195dc8f51283b6f00748e0e978dee33977d866f1e81f4f26676f3a28e8e376f9d4799",
        .pMD = (ubyte*) "019d5f3d9f3cb2d0549f05a50aeb287937120938b392c9e55b84366f0d9b16f34f90e1efe8758404a3d5f36955b2282d",
    },
    {
        .msgLen = 568,
        .pMsg = (ubyte*) "b69c2b2ec124da88c0407cff7ce540dcac3eb2476a52d509e4e17296548eaf4a3244e3f3a7d2a99046d83458f7e7e2fe33e4133477ad3b6ef2ff36e88198dceade98d64b152db0",
        .pMD = (ubyte*) "ca7f0051f7126c869d326da3c552409e908231e7b5f2f0beb8815600b47828e3e56e55e1b73089d428da885ce8ec2095",
    },
    {
        .msgLen = 576,
        .pMsg = (ubyte*) "8ae24e1f1bcef52f2257c0d93fee6fb2456c8401ebf99ac7c52df8fc7376661c19ba40e20f3dc853d9c4c0ff59fb39844314a653d2b134b7b9045e135d34bb6b41031b25c1afd311",
        .pMD = (ubyte*) "432f72ef069b9821db507151e8cc1634a7339a9f2af348ef1c22adde3f8ef8ce5cf3f20afb1e350b055366ea63096753",
    },
    {
        .msgLen = 584,
        .pMsg = (ubyte*) "b1f86f9b14a141fab0de94211b41c4cdab14fe3f2e409d3fdb6db361896be5871fd07da74ce3bace78b96a65fa9ebbb48bb74fa4fae58ec922eb409f1ad45b14ab8f194707dd4e90b7",
        .pMD = (ubyte*) "f812f732df731bd59d7aeeb0c1ab13bb2183f61c0348904ab959633471edbd805c81eaf8160401ef319f71cf10c39d83",
    },
    {
        .msgLen = 592,
        .pMsg = (ubyte*) "0b6fca5a36a92b496d35345ede1535b9f2a36dac8bc872858b6ed3a79538fbe0177058f68841bd83ee260503a4a2fa2c5a32757e5d80c61a19d955d7dce18a93dc85ebc77c32845ecb44",
        .pMD = (ubyte*) "d168dcb16c5b07f32b97d20babce6ab4ce445c802d12d707ffd2681b2789b482c4200c601c5ae9596c6d43362fe80863",
    },
    {
        .msgLen = 600,
        .pMsg = (ubyte*) "923499f7e9e2b9618f8458373556d13637977e25cee8865a87f6f67ff4581496a1bbf03b493c3b294a155c00577cc1466dc873ab08d6ee9196ab2fcb2c5a0ea57828ce25f7eff39167c053",
        .pMD = (ubyte*) "8d2098c339fc04881b4d7b39f513491d3617d85e599568d7aabb382cd27e1d26048b4397d9348929218d68802633a1cb",
    },
    {
        .msgLen = 608,
        .pMsg = (ubyte*) "7d038fc2150662f5b6b5e30ce60c6910558ad17c659a2050e95269612d5ff2f3384092894db35dfcb86d84cbc70e76b216544b7e0f8f631fb2554aff9276df922032b62f2caaba1ea99517f2",
        .pMD = (ubyte*) "0b377bfe28920939c8610d62295323178de5c20c93ec291bdff206174fde78592a0cb49997225080d6abcf7ac13b6a16",
    },
    {
        .msgLen = 616,
        .pMsg = (ubyte*) "e39e54b090c3a1d735c5069f301b754b8b36e00c7dffe7193480b301d1e12240b5972411fbd8658445522cd0bc1c83ea52ed98574b8c633efb8789c1d128808d94a5f4b0ed976aac26ad24c931",
        .pMD = (ubyte*) "d6cd07e05e646e2534f3368bbd13145d8e77a21a7c3c9c116c4687982b9a6820bdee6be46a5747f972226bbfb238f4d8",
    },
    {
        .msgLen = 624,
        .pMsg = (ubyte*) "f63cc60bc569b51653f1c917ddeb4c7b2bd554511ed9f4af894eb35141823d8478b75942466b1b9f89dd5b64efcc66f95182f2884311585fe9ddfd960c5a11f26c177d0a58fc16a87dd01772fcfd",
        .pMD = (ubyte*) "fd060699676a224e1a7ecf2360bb115ed95a999cc922257365ba07f8d0896d2afba5167a1633e2a29e0c13cf2d30dc89",
    },
    {
        .msgLen = 632,
        .pMsg = (ubyte*) "f40ac78699df3d80d101b1d30df625c87df480f76dea8668d4c506f92aec55ff7b0cfc30ba1baec157977dcb130f4df314e5884a345213729faa81039de2872cac4fb09ed2b052a5316fc198dc24c2",
        .pMD = (ubyte*) "332b0121633c6d234f8266dbe2d0161e10ee714c9e8e4d9648e7ac286bf205091a3adf0c493e57ec188553ee9a2c2fd1",
    },
    {
        .msgLen = 640,
        .pMsg = (ubyte*) "0215e4d3a831aa7231a4693239eab9164faabb90a596648c0c9218af20197be1c0dd8409c2aed317e49d44480561c4a595fa63ce4a94abf514ad302d547a69e54987beafca9fe2473beb63d0ba5d8060",
        .pMD = (ubyte*) "8f5804a1f2e0fba4f5e0c402d97d695e594cf5b3081e83cd4897c6a01343dfd6282382ec71f9aba2f767bb64f9a09be2",
    },
    {
        .msgLen = 648,
        .pMsg = (ubyte*) "5576cbd025aa7c1495e765bbb489bd350697c6c788adf525ee3953422fea23674366c5832b3cdac23319a960743ec2c09c31e0b8f2b3142f94f320eb030121a4e285725dfbb1ccf48374b2f79ff10cb927",
        .pMD = (ubyte*) "1a9db81e63f42c5cca6313e141aa51ef80e2cc0475bc435205eace6465fe116887591bb53e9d8a1f5d799f3ad22fe023",
    },
    {
        .msgLen = 656,
        .pMsg = (ubyte*) "dab38a96acea205a0721e31fd2b77f6dc19bfdbbc21944e298f3dfd2c5b40084ae41c530fab1bbbf3b5ea183d03c6e260a6a95e08d0787edf947793fcac668707d1c5bfaf5b1e9aa1cd3fa52cd05d2bff29a",
        .pMD = (ubyte*) "db0919eaf7c6753327a201c37696549ad6fccdc8bf4141d0d2d1780bb2f1ae3694acb9c9e13ff0bb54170d65a6c8a34a",
    },
    {
        .msgLen = 664,
        .pMsg = (ubyte*) "d0b1b08096f371e4b5f49160ec8c53bd34de204ae8e8cf1a2958236c81a1956bc64f541842978b841033e242c96d471c6179ee054b07964fe4190f1e0e12f91d1b10ce6fee7c23e95ce02a7ed8f87cfa500b15",
        .pMD = (ubyte*) "66b8fe950a7436cd98023456b7ac53205e1311fadea03f515c2fa1870ee424995b2b95eadbfa2a4016af177042e4528c",
    },
    {
        .msgLen = 672,
        .pMsg = (ubyte*) "5715eca85d6fd63ee24e2f8f1a67e994aa16fc3a5f47b7622096532c21b5ce755a0ef79e38aac58f9252ecfcdef4b2e7a548ff6734b2b4a7956b3e31bddc6b6d074a7c64e1b87bcac509cf3c6c660dc63edf11a8",
        .pMD = (ubyte*) "432713a0365060b02718cec2d02d35b23448ba8bf846f62715e51adeb4239b4f35ec194064311b9cc879c99e92e54285",
    },
    {
        .msgLen = 680,
        .pMsg = (ubyte*) "44095fe07f2bc1a4b736c46d26ce8c9f2f19bb2994213f0ae9796d14492454ef47b24b6227accdce4f3287fbf8e3ae1729fd96fce6c581b2a52ab53501a5d178b26360a9bda6afb7e869dc12714330b2ff8dae5ad9",
        .pMD = (ubyte*) "60d12952583302bdfbef7c3a94df3d6e3515ac38f4fe2a57baca84d121f945df0fea42c8a458a1015e9a9bc69dc6f1da",
    },
    {
        .msgLen = 688,
        .pMsg = (ubyte*) "e5f422351751783266d0ed34769bd9c8f3bfe680747f14e8a6ee00bba6bd6557ae51e36ff418ff00cf1e6c861cdb896fe0502ad02f529b574c25e281114c450c91a00cb0fda0880ac40854d9fea5db6c0b671a5b77b8",
        .pMD = (ubyte*) "c4ac22d593b666d3f06560af4a2c0b747dfbadce59203147e4ecea6a907eeded9424539ed9c6abdd0f330c5677b2b37a",
    },
    {
        .msgLen = 696,
        .pMsg = (ubyte*) "566077029ffd71dbf97a9ac165231c05798269225982cffde2d44c6b2892a3f42322afd7a55ef84d8ff184124504f0225f1bbfc0a239f1bd2e4bd7f7f8c327207b844cc1abfeff7e2b9a1b9bbf58adbf04b64bf85fd5a8",
        .pMD = (ubyte*) "60410b50a4ec2b1a3be633b829557d5b836b59c1e3cfbbee6d844ad70d113d233786f3f81dae42877ddfc4097a3cb452",
    },
    {
        .msgLen = 704,
        .pMsg = (ubyte*) "619c293993d54f955355cb68448674fd15a3a21cfb6540d35fe02377d4a79ae54b37470d8a932db2da2b096b0002e6ee6f10ec8dbce679015290736767bfdc882f28a65d4f27c9d394a894cbe547406576b6cb7e3f5f0477",
        .pMD = (ubyte*) "ee4e12c285091ae2f7ed57c9ee8c90cca0743a70fc02c05e1ee8e1d534a5ae9fb744d6bdd76f1a30c91809037a8332bf",
    },
    {
        .msgLen = 712,
        .pMsg = (ubyte*) "26cda1f9e3010415057b37dec817f43360cba8e039ddd6708353b643eeac23e0b2cdb48bd33e281ba3960706883486beff30ab40e191b3e9e6c1b18c673e77c36891b982d58470f20c907d7c9c958f234cce46186003998817",
        .pMD = (ubyte*) "c749c053d47c5450a121bbb7e3a42616f9a69d8127377823cd20a3b5fc54af80dc1829b3c0346b52502f810cee5aac9f",
    },
    {
        .msgLen = 720,
        .pMsg = (ubyte*) "2ed2b316894fcc5a51771290d9a28c7281fdc13b2c30ce66f43db7b81cabfb8045e56b1ee5dd3bc2f6f45a76eb1eff5fe841853f32df783fe5f5f0ece5231d7f160c2461d00029ee8dd9ad7ae5221b91bd7f9d83bb483420fd78",
        .pMD = (ubyte*) "3b6d6c8d2f3ddde960b8a1ddc6bcdf59450ec9910aa18f6e9a61e3affe80f23a82a233ecfc54d736cdaf5a9e0f4d905c",
    },
    {
        .msgLen = 728,
        .pMsg = (ubyte*) "f69979f2e7d8c5300e0694fa43eb9812d3f2a7c1754255197f2ac87e59c2c86532cf165af3e8ff4871d730f5e742cccca38bbcdffff4472c9307e21fa9354959f1bdceb077cff177d1f132ff9da3235d2b3ec16e762204195910b5",
        .pMD = (ubyte*) "08ccfcad7b14d9f7773ced011bb55f4a4b58bfc6031262e052b4fb4f8bfaf0f425a7b1a49b4816ce4e6a312f90a05746",
    },
    {
        .msgLen = 736,
        .pMsg = (ubyte*) "b6d8fc6462bbe5348f985ce481fbd1f44af618b4860bbf4f494b9f0756c0b1c2920923c6b844abc14d311c0cd79337304adac3aac300e0eb78b198a3efaeb73f6f73dcb0b518d16fe77518bece89c6303f1d956bdaa4342df866e18d",
        .pMD = (ubyte*) "e65d55e997d51a287277a7edeebe87396495e657a615c0d694646f83abbaad3f182abf52d0fd1e5966652b85039fc5e2",
    },
    {
        .msgLen = 744,
        .pMsg = (ubyte*) "8c7bce623193b17ae2cf4cfba7e8030b1cdd6e2ec4f1516a9ff2cfa9ffc1da5e970fee6bd565ff437267b04b4759c58762e2db725910562dde9d9cdc9471814e216701dc85543593aa4680953b090abcbaf06f81cdd1b81cd9528aedd2",
        .pMD = (ubyte*) "0b91656506158950b24ab35d3f08537be062933dd8bc05bddbd494e4f253e3f1a53f3630dd5d81f76a8142975ec30376",
    },
    {
        .msgLen = 752,
        .pMsg = (ubyte*) "d60dd4e861036a04b6490525bf338245daafdd018266f44d2b048d666dd39b08658fbde2597608479a9e0626af8bfe3caf017688ef17f7ffdd8d10822c5f9d0d329a4a318e6f52c40d868dd7cf95a9e8a530b759bee3ea21837e9cc2bfb0",
        .pMD = (ubyte*) "f1552f115287c0991fdf45ed5f6ed583275c9d5bcf384ebcaabddbd81ba0d5476a97f27479462eb8d83675356f6b3ad3",
    },
    {
        .msgLen = 760,
        .pMsg = (ubyte*) "669e8cee783d752b1b81608014ed591edfdae4c846bc343333a89db2c3134c139bdd36c37f8e4e3921dffb92367cc979cf085f4ae761b1773826762a5477dd2cf0fc7b058329886510c04cc23f97d443b39be9dd981543bc7b2cf9e45fab3c",
        .pMD = (ubyte*) "1cab3fe5453d77d30716f2cfbda90c66a59d22da1b04e72335c03ae71c621b4891822a3f29429641a2cd439ac2edaca6",
    },
    {
        .msgLen = 768,
        .pMsg = (ubyte*) "5b400bab7506b6ef1df4764a73fa8dcbdd35b417fc12afaedfb5246f769cad5f497f2ca6697b5fdaa770b48005a85ed06ab9a8b99aac8925645e797e1e2784714eba9df2aa4c348043f90baafd6345d2429cc031f746a41baff83c841fe405c4",
        .pMD = (ubyte*) "3abc162dec0d5431e34026d8c694ec7dc1e53a6fbbc3ffce7c3f9421f7e40018a8ed0eba576a221a82e525ceaf19deb3",
    },
    {
        .msgLen = 776,
        .pMsg = (ubyte*) "b3dc34641764bda3109cf0b80658203a88fdf1d0ef9218e83e1962ac4d1ff8312792e1f2b0d3c87e8b0c006d3ac4c59887b0c58a23ccdf318eab2ad9360b395ce3ad9d925264ac0f206b810eebfb44a8b31dac4a86bec1655c01e76740d918ebb0",
        .pMD = (ubyte*) "fb54cfadac2430989a00f39e62829719013ada1fbb100234a419c2fae0dd79f255f77ea92505fe3b5300b21b9400356d",
    },
    {
        .msgLen = 784,
        .pMsg = (ubyte*) "fa66ebf43f9c77ff4c221ab6859e6f9979349f7cb703d52fe3f2f25d09ac81b530e9ed4833f0f132cc59517df218c84265b7411187e34a936d2ac56e3603e0699b0f48d1c89e9a1b6a751bca0acfa89499a1f0c04c22e0d2aa8b5f6ae31b3c6a635f",
        .pMD = (ubyte*) "52c40104c216093e87980dfb331e72d3fb9eb0f7b94d0154d1957be38049c2daa31fd3cab23bf2e799a1e1ca8b727821",
    },
    {
        .msgLen = 792,
        .pMsg = (ubyte*) "0500444c6b58e2c15fc7f897d3c430a2de616619692b019b2c52846fd90a601096300de9b131585d8f28ff0ae6467b4f2c771d0b50425ca8a7f16e5929f3159fdd7ebc129279c25ed098168c0ec9048325cf4ece052c7f9fa7457c1443c15cbac23279",
        .pMD = (ubyte*) "dd1eccc6ce8631ac881c521f7a9a630e1591679c34ea90fd03f84b73a8d2089943550c8df7d10a937bfca9aee8dc63b6",
    },
    {
        .msgLen = 800,
        .pMsg = (ubyte*) "cc177cf05cac31b1b221b6c0f44e8d5feb32cb216c962aac17ed59be457f966e3bc67fb5a418252c3e876317d3066ea36bcdac6cc0feca42f288092d7c4bd8ae677ea848bd4efc3f41c8bfa05df9db815c54078ad954e0b577623c51d3f8bb4db7079fb3",
        .pMD = (ubyte*) "8edcc5bee5d6435202fc82a4fb407d26b68e93695e5fb54053b3cba48d503a753a6f1a1b69707010ebe162a59fd720a5",
    },
    {
        .msgLen = 808,
        .pMsg = (ubyte*) "cf192a581d92d46036f1fc5a3571407c422ea2d014912f42b30fdff88313bde17e384791c1bc184c4a32c460007604b8f3e613afe6cf57220b2644c90d797ec753243d7f84c8f6aa46f938a64c37d4118f204097dbe33d088ef8b8ae9d0feeddd746d4cb6e",
        .pMD = (ubyte*) "8db7566296a5b97d0606f54df2976aac278df1291fc47ffe80648e383b6f2d7ae3fce53651ef48ecb27008969d3a9344",
    },
    {
        .msgLen = 816,
        .pMsg = (ubyte*) "154346861dc34167442da1a99730ee06f4fb25d76348ad34a9998c5d1bc1db58b1a777dc5b47fa6e98f9eaca44f63084b118cbeffae1c53e94bf66e9268ea9539b5feca97578eb0d649ceff4178c43cc52cde8e341ac89840c80b163ab2f3c3afcf30cb5125e",
        .pMD = (ubyte*) "170f760d130ba2c9610ad878ca6eddd55c30f9efbdba93ed18bac3afc609930a7901496c87eefcf5d187fd9e3b8c2ec7",
    },
    {
        .msgLen = 824,
        .pMsg = (ubyte*) "9e0136a796b778f89bfdea181c11234f139a7ca143df75a2bd37558ba9c0118c43546f6424b96b30c318da803bb14db04fcc3876abf354b76c5e419fe3af70f096e0409a8879678dbb0694cbf2c853c1bbab30d7ad781f46ef4c1b29fa490ed89f8bf1714b5d34",
        .pMD = (ubyte*) "b9be18d9ea89994b8345e3b7de89e2a44f43d95763430b878485e29deb47228e9c4694e9a00a1ad80e1b4572b66471cc",
    },
    {
        .msgLen = 832,
        .pMsg = (ubyte*) "2e3ce22f7f1530ff213ae1c965c774a555abe92099ffc8319c97646fead76180ddc874d5786b6a94934e6cd6385c81134ef954da744f38c630e269ad496b941a71e39afe27de92a2dc1a0de055589d93506a984c6a8e194740fa489dd5b8dbba34b4dd125614ae10",
        .pMD = (ubyte*) "11bfd68fdf0e3b84f0a95eab847c00ce36e2577d5c31dc1cb568fb448a944eacb46ee3b5bc15165b42faa375f19f3dd6",
    },
    {
        .msgLen = 840,
        .pMsg = (ubyte*) "7d46417fa53d47e646218899088698ecc472b5354611aa2452a9f353e4cf221ebcdc82b51a9bf96fc744336254aefc30a6c0ee23b3294d7d86502f09898ee0f6039c84e5e047fe41b16b11cff31ec586942c0da0b3c4a6f1a8704278444ae634596e91387dab1e020c",
        .pMD = (ubyte*) "8f0da0aeb850238ad82d1e04da9d91effb8ac5ca8f3abad54f5492d5ca63fee1dc9260d2d975a003323e4f6efe96a75e",
    },
    {
        .msgLen = 848,
        .pMsg = (ubyte*) "3a6339b8665062a79be832b14da5c7cfa0e793f6c2f3553f7e3b48460ee09acf31751fb07e0647ebf8584e1ae273b210d55eeabd0f2a55520e3171a65ea04dd8af3341372a40dc5e05f71ea355e8e7b324c6b076c46a7939621a020bde0c3e67db2605141208094aeb4c",
        .pMD = (ubyte*) "0eb91b52757afa91c3be82cb19d23ecf662663330bd03ea4b09c60e556ff809c7c394aa3e172417bd8a3fdea0286d0c7",
    },
    {
        .msgLen = 856,
        .pMsg = (ubyte*) "7ca5e89b0374938e842040b3d147e5b5360fe00ba5bb3b26107c2def1789e470e37181d152b065875481abc895f4f5425c406c0cb35a02ddc8c7fb7c93aeab77b9318118b0fd449524209d879a1cd69d5439e192741f9c5c64a353a774e28681c58ced576783ba20bea51e",
        .pMD = (ubyte*) "1d1163ab26cfb6fd9ae22dc98496ff672f5ceca34e6b6841d096fbc8ebed091ec61d810308a1e46179316403f4c6482e",
    },
    {
        .msgLen = 864,
        .pMsg = (ubyte*) "006175079700a58913c4f40b86c135dd8c78f62939fb103450527ce1b61c687726798aa32528b5c139edaa57563630e299fd67d639f059e0bad0d26e63177271f3dd006190fc0182007389671b0852b480320b288835f2da788fa5c2fb93357ccf547d49bec4b257d01d3b42",
        .pMD = (ubyte*) "4526a824ca0eff68ef975c5f31b0eda96b4445142347ffe6434fc3586d9a2e86eb4f52974465883665285d7e248bd07e",
    },
    {
        .msgLen = 872,
        .pMsg = (ubyte*) "25f65d471630be3079f5e9815243b348c9b41e128b51db5c6eaa0d4a5427509c5199fadd1014a1dd7201dd62796f4e1b65aae1d51c0f50f1cf1ee816dbd18f23ed2c05686a166a150e6701f2d342335114a5d742f23eb005f78137c5f9f79b8341d90750eddd23bf9350dd9a27",
        .pMD = (ubyte*) "b6d5324501435b14862b7ff73c81d13558b79f244a1fb0810a8aaa4c75a866e44bba803cdd8f1f7a85f7fc96945a892b",
    },
    {
        .msgLen = 880,
        .pMsg = (ubyte*) "2d25d919b093e23ebd3cbc6f2d1ebdbaacc9844d7813ded3650deb0125367c6bc6eec09d7c2d2067a1746778fa04262e3c4f57adceac402fd14e9a9b5e77f3580ee95163c09e189f96b82d6d41bb5c7d7ffaf7e4e14fc06ed20f0935d53d1a720efed394044d938fa5f058778bab",
        .pMD = (ubyte*) "2d6d5030ffee884b3b5ec578c89b36fe596d0036ab326ac50210293ba3b3f1760455094f686226b2d77c4718d99ba862",
    },
    {
        .msgLen = 888,
        .pMsg = (ubyte*) "2090662320b9b03b35a1c3ddff78e4ca87300aab25d4e603a11b2161983de5da21059eb6b127026a3cd54fc79d8dd3703835b291de69e4cef1147d7ac83d310a542417c9048eadcde75d1d291163be643f78de2abecabf428875dfc0b1547c7c011658c2e394ba4b7d61b56c21a3ac",
        .pMD = (ubyte*) "85fe404617ed6613bd29fe6f2a18fcc410839292df0f6ab48e216032d64113cf84382a28eeff372da4bc4b32e5d54dd9",
    },
    {
        .msgLen = 896,
        .pMsg = (ubyte*) "d0df0d64eb22c9ddb65e81b5739baad86ad5e2c239ffde9f6c47a4b14d9cfaf3fd6d1efcc4b4b725a6340cee37fe749eb03a0d2a4124b158a955262405449563e50c3ea6a5706961fb1ca04dcc2d1b0a44f47c0925f7bda95f3966a0e2bc039db043d52c365cc8d9dc9ea598db308964",
        .pMD = (ubyte*) "1b1702a48f41e1bb24a582aa446a6ab3e7cf1e99132cd10d830cd3eeb06af7caee6dc03b51fa0187763faaa30a996f02",
    },
    {
        .msgLen = 904,
        .pMsg = (ubyte*) "4909cf5b4e1d694c83ac772fed725546d860c1a1269cd83ee8c842752b87a993143d6fc63017a039054c257feda23b35243324e31f711c241f688f07074389b46a126e53e9caeb29bc8d2c048e2c50da8eeb1aadc384e9b19f6eeab1d85e8caf730f34cb223f3366cffaf586791a7a7c3f",
        .pMD = (ubyte*) "908b55d1fca1e424732111bc43123bd3c345592573051aa073af6d3443a072544416a433f04544878bf6ea981dffa909",
    },
    {
        .msgLen = 912,
        .pMsg = (ubyte*) "9e1f2525dcc83fd704cfe9e01a3add9e527e923e754dbd2f85b019d6a4556384322aa9a5362bc53aff7725890baacd1227679ec6d834d874fa8bde84a72d39e75abae04e547fb69a3f8f559412150adf34e8202be46062aad869dbc824d5e0175ef75188006d1be10d3d016bf8249debc12a",
        .pMD = (ubyte*) "1dd83d9b9457f02faf16e4123dc59af75ee715f3e13360d5cb00df2adb4b132252d179ad0eef7f7faab9d1b3ef81e261",
    },
    {
        .msgLen = 920,
        .pMsg = (ubyte*) "1f389f84fdc7ba19c321e62d0717ff343ae799852ab3a168ca31427036a5060bf20c3e57729aa337e0673da71966844cf996c64fd87cc86c54d0b046517722fe3fb1aa039c945a2cb9b9b404c035ca65f6caa3483e5fe1dbdfaea1d4863da3058f8fab31809b261fd67d11ec056c17a5baecf9",
        .pMD = (ubyte*) "49d4b2f5dabb1efb44c44f0dc26eba424dfdabb1cab634d9a5f7b0c6275fe610b2f2ceabaa32f7750f2026c62e4bdd08",
    },
    {
        .msgLen = 928,
        .pMsg = (ubyte*) "5d135c2fe1bd00a4a15bcc8f2d0fe8cdff39c94e53f7a5be39e82a64e8366f4a55d32b9e040225581e1aeb1dc586c763a411efd7ca61fcfbb8c09d14b8238d437164c2f2b9d3e871aaed0de1f86b9e52817f9228265ae5c3daf1485ff8011738da508bf2a73731396c5d9aa56fc554e0c00b1a0a",
        .pMD = (ubyte*) "c3f992fd3ce5b55a3ce1e694c20073dba18debe516d18897149d6fff0725c7a2686dd6860a0a7a72093c8ff6939522c6",
    },
    {
        .msgLen = 936,
        .pMsg = (ubyte*) "cd129588e51db893ad4cdc522fcc8afc55301b575c13cb7d86fe0fe00f8c298c63cbf9ac8ee61650f4011d6d42654925a4dd4449395f3d1dc4ef3b5ba4c1b17a069e522f5988263502a1de4a5149657ab487b79f2baaf629fc30bb1ba8e6aa561d51491a2d4d12ca3ff4c6ef45c10580eef51c611c",
        .pMD = (ubyte*) "5f6a00742d7da31d4a7473746561b99a602c21d3f73d231ff2e6efdb9f755a9df68c4005fead92c20e609c12b00c7cce",
    },
    {
        .msgLen = 944,
        .pMsg = (ubyte*) "76bbcceeba2ef61f541758ec590abe3e1bde3637426bc7191e9260643b7e0f3f362a7319d023749041903192cf6f3ac29e21001dca298addb331699d984dedbf6884990bd48dd598a9d6e3f05dcb146fe7543cecd49f639c9821bd3222d7dd4bb3d2250aeff281ff35f2554e2ca4b30d9e7ed2ed8a56",
        .pMD = (ubyte*) "8bf0f11bc016ca987933b20790e153fd66eb2e1727c0fc69bc369450403b0faf32c8486626fd4a43be47c3aa597eacf4",
    },
    {
        .msgLen = 952,
        .pMsg = (ubyte*) "d78677597edec2bbd0c5b90e6f61bebc6d8c0aab6c72f26c035b68b564c5c4113cb6c5d6db50d25795a6865c68ce6ccfdf3807b8353d166cbefb1500836107042c86736e243fadd5f7f056e0ffa226fd3f56e9568f99c801fa59ca7664f79b476f9d8b0ba0d2d99bbe4c32827b0575ae5791b96cc0ae91",
        .pMD = (ubyte*) "0d20635e20c04b6bc1bc1fbfee7bcd51ed2c8137f3023f703524f947a576a9e994b601cb0e27b5bcff913db320cd0061",
    },
    {
        .msgLen = 960,
        .pMsg = (ubyte*) "c5720b156654579bd92e7482aa68fa93cd3b0feb3dc32eace45527f2bb12670932bc7addd2c9ceb121b6ba14c69ebe11ed0b0da7ed0c487928888dc533d1b09a387cc8469871ee0ed43e4123adb12ed18aa5eef81b1c4fc03c8eb8891c8167219e5afe3aff733e1bba6d1295a8c8cf396cb0bac80e1acbeb",
        .pMD = (ubyte*) "66961b7d6b11472726f441068953eab3476aa962c823b42dd24df53120b1f14c54135d683536c6469d0125509e0cc1db",
    },
    {
        .msgLen = 968,
        .pMsg = (ubyte*) "15bfdc259bb8954e66c84eaa031c1067fbebc817a4fbb0573d660baf3a9e15baddaf3a8706c4863e4ced5d074c1f6c27417ddf6cd6d5d4cc386e10496e01f118ed05a401672f9809e53a334f15e4c334e539b7be50130f3f78e21131f6a93e656e49845d6602b5f6583738490571ffd40da7b8d5bdbd48f728",
        .pMD = (ubyte*) "56af8225087d7f46cbd9f3875e8f49f6bb1c5de704bd79d1187f81b7e2706a83610b1ebd9daf0a6de1ba1ce79aef43dd",
    },
    {
        .msgLen = 976,
        .pMsg = (ubyte*) "b5455da93a96032e8f35956b3664dc5f44b6add373d1a83a727326dc7fb36c33388a2595ae910f14bc0cf4a39728dc7aa58181bb93e70355a262dd284173186be19dbe4b052492d59815fe1684864d81801f1a9129da08af5506b455a492e8745888121366d8f439cc579c0e2607973d7c99629c5f30210f3468",
        .pMD = (ubyte*) "ceec9555fb9bd54107b0051f50c1e084e64408a770e7052677dbcfe54f2c5c635bc40eb146f0eb4eb47a8a0b77e0296d",
    },
    {
        .msgLen = 984,
        .pMsg = (ubyte*) "197ce0bb09b175a49482edba16e82fd854acb12917793ee11a37f62a269496617ce3f983732adfe26276ee1dc072f64e8a387985e5676b760576366e4d48018cb800322d771631a8dcab6f3c7619a8467ecf65b7715cc4c6ffc97be2242c1beb957a92a15d9df45dc8c67bff8005cc27f6177ba8037fd239d0d8ce",
        .pMD = (ubyte*) "5bc5ca6d3773f21be2c164b80041e89f50da1432a563bcbd101ce1da9abf1db6e6140321e11aacd259b52f21bbaa19bc",
    },
    {
        .msgLen = 992,
        .pMsg = (ubyte*) "1a26cd632e94c209eb926a6908c860fe222f48310f19bc7c6f7289d083451c34438137b0aafee96955bbbc0d4c6a3071202e687936a32439621fef59b7379abe9e85e86626a98b949b8e4f2e5aef9663e319049030f27b65463a4a440911a1e954b94950499e91d3e6938c94d95f791a9678833fa60eab49424b0257",
        .pMD = (ubyte*) "3a3a966971cf47167f2590e356cb699e13885d4a8d7c64752549f408bacbc64e29d34a3e1327899dac9bfe0925e2362b",
    },
    {
        .msgLen = 1000,
        .pMsg = (ubyte*) "d5e17019d08aef737d8916cd43028ffa340b246d8455d1ff400f1eed3c07ac204e130db2b9afd8adece7fd166d78572a103280e76ca0e9ce8feb2ae8f1fc9607a7e1134ed97229f376345844267dafe881d99a687eadfcee2e1a7d4caa24263f4a142bf5171a07ce8337ce60585abfbdefca19f8a2c331e58364c0214f",
        .pMD = (ubyte*) "5bf3af7197b5d6868c55d61eeeacf3feac7f46053a359caf87e9345ce4ba5c9372f14b3381535fb12ed1d583b4527809",
    },
    {
        .msgLen = 1008,
        .pMsg = (ubyte*) "1bcec1f890c032077bf8e61ceeca2d536261d554b3b24ee06cb20ca945c72d67ea7d5c28fe7bf5e760b56961ade3e52406312ee91338d023472d77d866589db045c8654cd246c7d85387eee4f3a6de6f7ad15a455c42058cf570c79913877208b516a60b1208f202ddd63b4cc8fb625d47a7211196b73640fde5c493533c",
        .pMD = (ubyte*) "895d0618830ac81bbcb93313a62d743ede124f0c78d507f1bb48ccf0b3863b489074fdae91348d4097533e93781c1184",
    },
    {
        .msgLen = 1016,
        .pMsg = (ubyte*) "b2165838d2c368ffd5ef7f23704d1a7d2527e25d15e9272c15e38a4f034bf94f5b81e13705979e3e711137a6e6e948e417d73f01f8cfcb40cfca92018ec923e560172b3382cfeb7b549fe979b0cbe63b7a751186781b7a776461c9664011300fea609ef4f07336fda521ff6275fbddca7589c0b53ed71b17fc309845c22a0a",
        .pMD = (ubyte*) "493beb2adf3f7172a1f596088ebb3f3fe2e2acd1b653be4aa59b79a46cef36baca80d3ad7bd3b158a9b04f83dae54621",
    },
    {
        .msgLen = 1024,
        .pMsg = (ubyte*) "3ebea3f8609d78668eed38518eed7cfc651b17ff1eebf99bc6bf534bbb14fc9b27f9143dc7c6e75af10a1326d5c5eeb703d822172db99a982e6ba2674cae4964ba730a316192ac89e1bf67d4d2bb48f84fc7d771b55ef6a4a8230c70571963070112cffcb96a919d66f47a820d35546653d07d363d42d5683bcfda8e65bc122b",
        .pMD = (ubyte*) "6f2e522d9a1445cef3a36873dcdf136b9ebb0b32de445253ec7050313217f0322af9ae8fbc0ec8a7fb8ea72d2a887b2b",
    }
};
#endif /* __DIGICERT_SHA384_CI_TESTS__ */
