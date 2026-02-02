/*
 * primeec_mqv_test.c
 *
 * unit test for primeec_mqv.c
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
#include "../primeec_mqv.c"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

typedef struct MQV_TestVectorFull
{
    const char* dsCAVS;
    const char* QsCAVSx;
    const char* QsCAVSy;
    const char* deCAVS;
    const char* QeCAVSx;
    const char* QeCAVSy;
    const char* dsIUT;
    const char* QsIUTx;
    const char* QsIUTy;
    const char* deIUT; 
    const char* QeIUTx;
    const char* QeIUTy;
    const char* Z;
} MQV_TestVectorFull;


typedef struct MQV_TestVectorOnePassInit
{
    const char* dsCAVS;
    const char* QsCAVSx;
    const char* QsCAVSy;
    const char* dsIUT;
    const char* QsIUTx;
    const char* QsIUTy;
    const char* deIUT; 
    const char* QeIUTx;
    const char* QeIUTy;
    const char* Z;
} MQV_TestVectorOnePassInit;


typedef struct MQV_TestVectorOnePassResp
{
    const char* dsCAVS;
    const char* QsCAVSx;
    const char* QsCAVSy;
    const char* deCAVS;
    const char* QeCAVSx;
    const char* QeCAVSy;
    const char* dsIUT;
    const char* QsIUTx;
    const char* QsIUTy;
    const char* Z;
} MQV_TestVectorOnePassResp;


static const MQV_TestVectorFull gMQVTest192Full[] = 
{
    /* init.txt */
/*COUNT = 4*/
{
	"c6e317ac0e5eaed20b2e3f588f80a950e811a21d5ab7657f",    /* dsCAVS */
	"eb16b7c2b88cd9709566decd1c78a0f82093d7c8a2bc105e",    /* QsCAVSx */
	"66a9d1d1de3d8b308a09e094e7ac4997712b62eaaab78eca",    /* QsCAVSy */
	"5df8aa6b3c2327a7ed93a4cb460921819754721a75c47373",    /* deCAVS */
	"e4a7619584860692cc98ff3139917cc0d131666689b733f6",    /* QeCAVSx */
	"5dc59705ed52d54c0b794c47d50a5602832a4929f124b5dc",    /* QeCAVSy */
	"f82a6c66cbbd4967851afcc78f45aeac2bb2226c5b65cfa3",    /* dsIUT */
	"597263332d70525625ec111759fe29ea6fef6c38cd72c59b",    /* QsIUTx */
	"7206cc75ffde649e75714553cde381c0f1b4c1e774019c8d",    /* QsIUTy */
	"5ea1d037520e6e4e07f2ff0203b51130b4738759360fc812",    /* deIUT */
	"3dc714251248e1f8eb2a3706acc9b9fff2665fc3f2a576b5",    /* QeIUTx */
	"2af9222c2d24e2c4aa96ac7bd3a45d0ac05035899eb095be",    /* QeIUTy */
	"1bb0398e8ee11696de5d6d2e2f34d043eef3c2ffd316c831",    /* Z */
},
/*COUNT = 6*/
{
	"516c9fe1f89f853bb30db7ebbc64c25a416dbd42f92dedd4",    /* dsCAVS */
	"ce1fa5a6ba1a61b111fad97f5f3290a11869fdbd00103a6f",    /* QsCAVSx */
	"be72e9c2e63075a992b9de5f9033b418356d45e1230c2cba",    /* QsCAVSy */
	"4fb63893375753c059bb12e6594864014735a7344ba1338c",    /* deCAVS */
	"ab7d693d1b5d57cf13f8257f17828f40a197e170d2f06f07",    /* QeCAVSx */
	"4aa7ab743ba926b8bd73f819a78a993a63b1e2a4742a1cbb",    /* QeCAVSy */
	"10715ba756a7995083ca885f7f91b3fc2b1d21e7331f17a9",    /* dsIUT */
	"be885db4c4679e260a0f8993280bfcb389e0d13a834246f8",    /* QsIUTx */
	"1943df811faee225f9de68e499d5ba717a1103601d80bf06",    /* QsIUTy */
	"16f17921ffbff7ff0f01326ce91271a66faf1da0f47413a4",    /* deIUT */
	"4ae1f0d99a8817fd6ca56e22ea0dde49a09ff6982d446ee7",    /* QeIUTx */
	"88d1dddcdb8b994a7df68fdf3076d5ad6aecaab6dead3d30",    /* QeIUTy */
	"b1a1b56802bf9cc6f0be878eaeb02d73bd1909b407b73d14",    /* Z */
},
/*COUNT = 13*/
{
	"7a04ad280a39a69fa9d87762565d1730f257119588bce4ba",    /* dsCAVS */
	"9bc6c5c2b3b05eb460ef6c12e3923a16af139921c066d5b2",    /* QsCAVSx */
	"db6b9a46eb53b0c01968787bff04a467d6c588df2c61704b",    /* QsCAVSy */
	"6892c912bbc5ccb25acd999043c3d26daa143342188bbbd6",    /* deCAVS */
	"0a98ea5f4b3dc9f52c9c12a1bcfd94364d961093a7663e03",    /* QeCAVSx */
	"c9911c127b17009f648c7a5ab72f45c137327af9bf6e5572",    /* QeCAVSy */
	"c9a64a293de2ec7d6135f37cb645db1027821ecaec583917",    /* dsIUT */
	"9194300a8bc6aed4a2ebddf3c3d70b49c12794221015b039",    /* QsIUTx */
	"36186114acd8fa39d9da6bf71efd6d2479539eb00ed771bb",    /* QsIUTy */
	"2b089f3f26874146945fe9ca0d1e44cb3d7a1fd90d65f330",    /* deIUT */
	"73c69413d4b8e220dd186984725426d2d1148d467f1b4cf9",    /* QeIUTx */
	"db0d1f60e2f5a1bab1540ad1d3820fc09936f456c70c92fa",    /* QeIUTy */
	"0c4580138ea19389900ff3674c24d56b933c8fdb561c114c",    /* Z */
},
/*COUNT = 17*/
{
	"178b45d95396bde31ebf738d8598169b7fc14e68e757ac8b",    /* dsCAVS */
	"bab4041362cdb724c79015d560d2ff24a11c7d0caf36a523",    /* QsCAVSx */
	"caa522c4cb0d5fa2dbf832fa8b38a1cdc77ad133279dbf52",    /* QsCAVSy */
	"0fe6c3fbb1d5d7fe89e59cb51631d9b9b04ddd7f08e8da7f",    /* deCAVS */
	"3d9e25b4e3adb7ce4c4c4e2c376d8fc719552695cc26ede0",    /* QeCAVSx */
	"695fa6dc60e84874185d2b05258e1e46018a87582dc70384",    /* QeCAVSy */
	"10eae5c0e83f80433cfe689b7fadbeb7b04c4fa8be0075b1",    /* dsIUT */
	"5797960d4b529d941a201799ad463ad860efd4b219473095",    /* QsIUTx */
	"e991adb03f1d8c144b349b8ae3fb47ee73f87f2a8c0a3ac0",    /* QsIUTy */
	"12bf89fc6fd3b9d6252cd6e6d7e84e3528de5b068071c33a",    /* deIUT */
	"b3487d6bc5a8ae41b2ed689887c0978a5c70d10d0487b6c2",    /* QeIUTx */
	"30ca8c859699cc5345535e7981fdcdec83b0c426abd1a3f2",    /* QeIUTy */
	"d477c3edeeec70e3726ad027a2ba6bca1dd05f5e8594d51c",    /* Z */
},
/*COUNT = 23*/
{
	"8a3e091727609300791eeb9930e560ac84285e1072161e86",    /* dsCAVS */
	"2d34e835f20830b6d7abb7cba338f215264f7f3070b66c55",    /* QsCAVSx */
	"bb53c7669060aeda9708c3e19a8337671c189807f4373633",    /* QsCAVSy */
	"72e38a18196ac49fbbc6a54d81a7e233ef1c000653aa1b0a",    /* deCAVS */
	"7fbfd457490a806d2e8963456ea1c1068c562b4653cfa4e2",    /* QeCAVSx */
	"aabe9e27f04cf05a02b39b8ed1a0d77bd587a7ab95cd36b7",    /* QeCAVSy */
	"65f4cf1d21bc20f56f1a58a3e9961e5840b3256e658c86a3",    /* dsIUT */
	"8f32ce92353e1745ca77fa074dc1462dd9c2a44a9d347cb1",    /* QsIUTx */
	"f2f9d7864af4fc4572d0748a717c1286ac8503fe9d6588d1",    /* QsIUTy */
	"87736ec0d5cc44c450d7da876f2fd08938fa5c4c0d941b25",    /* deIUT */
	"db3c9306ef1f9718a24659f043d1c336b9bb1c6de794b2a8",    /* QeIUTx */
	"63a4724cebd2bb95854c9f466c924a11274f733b5919c617",    /* QeIUTy */
	"0522d1d64622d5514b987a7fa73a41e9b2489f308bed128e",    /* Z */
},
/*COUNT = 25*/
{
	"922860ad74d94c67092b282e245a03540ce94022429ef524",    /* dsCAVS */
	"f62e33612dd1ddd6877d10218397e2e35fa9a1dd651a7f5e",    /* QsCAVSx */
	"c2f6bdae923f8eb82af64bd5fc8c737721998c3f1970c2e3",    /* QsCAVSy */
	"b66f4360de6436495da290b629fbbcf46652a546638a3640",    /* deCAVS */
	"88aed6387fd222831281eab39019b0e3a7a08fe41ec20101",    /* QeCAVSx */
	"29285046438a22e71326041763fc1c25c575ed25552a86ec",    /* QeCAVSy */
	"9ebb57a6f0efb578df4b1ba121c34c400694b772348200ab",    /* dsIUT */
	"2f7a6906d1d529679621fd7298105ad0ffebf538e63ff293",    /* QsIUTx */
	"3ab0eecd7d12f137027eba599bca370286cf40e02e96e261",    /* QsIUTy */
	"4f1b3ea478a4857d5159cc53d2ba4f885a4d431e18345bc8",    /* deIUT */
	"02c49947834d229a27b3575f1ba8d8b4098f3a5d612218eb",    /* QeIUTx */
	"b096338e68c06b1b81b0643d7650128ee008baecd6526dce",    /* QeIUTy */
	"95a41cb65868c292cbeef0f8a0b9bef181bf4bde7d50726d",    /* Z */
},
    /* resp.txt */
/*COUNT = 1*/
{
	"6333419fc3f8cbfe507867a113ac6d8cec3ed5736dd2aecf",    /* dsCAVS */
	"75b7d9d28386e2e1003a04f5980b49a5285f952791f11dc8",    /* QsCAVSx */
	"8915b729869fa61bfacd539615767f16ff094466d49c88a5",    /* QsCAVSy */
	"2be09d52ba1234caa94e3878a2400ccfe10f8ee8ab32aa58",    /* deCAVS */
	"a7bf1251ca917db9b8b00a6034f1dbd71c60aec3f4b03fcd",    /* QeCAVSx */
	"3e14e44f35b863962fdbf6d88bacd735be1a27d6ca40cfb5",    /* QeCAVSy */
	"dd7ba49abf8915214697feac77888822a422cce37e99f1ed",    /* dsIUT */
	"9918ca1988c3f7ae8b2f946c7fd408c4a1c2160f82ae6c4a",    /* QsIUTx */
	"4b7b1beaf784e285b38a1953f738658e09136fcea8ab8538",    /* QsIUTy */
	"8addc3046b916cd96c0602100a0c04894dde58130d9a542b",    /* deIUT */
	"90654fc56b9dd0041cad9856b8be48755e68d41d72353cbb",    /* QeIUTx */
	"340262dd92fd5594d711d0b476e997418a3052a0b1a546e9",    /* QeIUTy */
	"16f309c1e8e5c11691e871b0dc6de75a4365eadf3de3e5d0",    /* Z */
},
/*COUNT = 7*/
{
	"97b5177b8db38e02a2466b10dbb0e32cddc01a948283bb15",    /* dsCAVS */
	"2b3130e33c2a47794be1e46d28c3bbe619c9ca2c7c5562c2",    /* QsCAVSx */
	"e2c001c51ce431f572dd0fffa98f1d0334344a7b18bcf74a",    /* QsCAVSy */
	"7cc4d4a31a18dc69273d8f4faabf44e4f43edc425d05ff4b",    /* deCAVS */
	"ac50537ba25fb7318ab69ba08f77df294165d2646d671f0b",    /* QeCAVSx */
	"568fff74fa5c95a97dc0c960016854628d94cfaeee76a94b",    /* QeCAVSy */
	"cb49b4b920603f7e332221ba1fa0cb45cae9852887338f4f",    /* dsIUT */
	"fb3c36690b4f0604c152a0c4c450a30e61caa52a90d085ad",    /* QsIUTx */
	"9d6ebc2262c09cd73704f4c853b0ce483c14ef25d2a69597",    /* QsIUTy */
	"bd140bbef193733e6e1cfb140de421440764530d873fc2a5",    /* deIUT */
	"669167d4dfeff33487a2be1ea643a50f5cb13a18c25358ed",    /* QeIUTx */
	"cb2785a2a886fa139845472d2d339895a5113c11c7530a5b",    /* QeIUTy */
	"0092b9ee566d19f66a98f96eddb5daeb932c2cc6c73f7624",    /* Z */
},
/*COUNT = 14*/
{
	"128e2472f8fd47d3a4a727bc3fbbd59ea181d96ad52177ec",    /* dsCAVS */
	"de1de3cb1aeb81a9a2eff996d4f3b12ab2339dc06f19985e",    /* QsCAVSx */
	"84c7cdf6710bc34725a7e6e21e40498d3dd8515ba1be89f7",    /* QsCAVSy */
	"add03d28d0bf70a9aee53c763b5e653a522299d3ce992693",    /* deCAVS */
	"063eb79e2b7c9c440b779005178e3459118a31a125d3116a",    /* QeCAVSx */
	"319287307e5f6caca482e772b35e279d153c6b1b46793759",    /* QeCAVSy */
	"4a71060f785ff3f53fd75514bbe69b7de23dfac4e77a9c91",    /* dsIUT */
	"cd78cabf5385abe8582ee2dd9e6d62e5a6811a710bf506b4",    /* QsIUTx */
	"8d798037808e12785edb76639c927596b22d7c1d2a974fba",    /* QsIUTy */
	"168a21b82e2543be94b39916809d54a4bfc6e2af9a8c158d",    /* deIUT */
	"fda7a17a634021af47d8627cf934b7035daa9270a28adc50",    /* QeIUTx */
	"c298d617230248fa1a2891c9923af403a1fbdd0fe2d0d99a",    /* QeIUTy */
	"5fb127a0c9467dce3712015decc3b258723c85098a4fa717",    /* Z */
},
/*COUNT = 17*/
{
	"7830c0f5a4085abd979f6b45e4f9741fdde51dbf9105360f",    /* dsCAVS */
	"d3081f79d5308d3f3b4ba68d87ca63a6dbad89fe36d65ddf",    /* QsCAVSx */
	"35187c3eded2b78c6f5f19d6db11cfad35d7f2c9c45b59b4",    /* QsCAVSy */
	"88807fb35a7360369a85d384962b4acc68a0296362c362be",    /* deCAVS */
	"5af95c84b2e8bb6efcfe42f7a0bd830509a07faf8aa15d92",    /* QeCAVSx */
	"0e8e5ebb4ea81c2e237af1c52400c2dfebbf39342838fe26",    /* QeCAVSy */
	"e18f32394fc8f5a9a0c031584211c10f2b79adcbecc91cc2",    /* dsIUT */
	"45965b7b0580df5a6a415ec4b3c99cefdd3074c9b3f3113c",    /* QsIUTx */
	"dbd748e8f88a8de566ef92886dda94a2863c7570c921bfb6",    /* QsIUTy */
	"d0d39e82af1227aad05a509cc84457dbab2193627f3ae77d",    /* deIUT */
	"962fcc6d51837a3768d5591f8bab4ff003017830e72f51bc",    /* QeIUTx */
	"63bb12a1e53f86f50d1c5366e144286e53f629aee9f972ca",    /* QeIUTy */
	"0b5a9c95b923867701c143eb69f6ea3ffdf4dd873bd22405",    /* Z */
},
/*COUNT = 22*/
{
	"635638bca5ee9d0759ce0d67b8479b2ef9a9d6487d98a127",    /* dsCAVS */
	"06730579195f0fdebf0368ceb88ccff8f8726666470047bb",    /* QsCAVSx */
	"31adecca3f43b773b84063905259f249089567275cb921dd",    /* QsCAVSy */
	"6b68791c2898673649b3a8f6169ad2da0c343bfa56b8583c",    /* deCAVS */
	"e8f78f9f1443e32157b5e12d41c82d4a355b81fb732f3ed1",    /* QeCAVSx */
	"c8172cb8ea09aea1a292a0798ef5cc262b449f59a4d52660",    /* QeCAVSy */
	"0fc1fadef04949c3c7da8a1d7b1d3dbb43688aa23dc88291",    /* dsIUT */
	"34e759ab04a9e359650b1fa20c55a4c13bc0f1e8442703cc",    /* QsIUTx */
	"139a8f24d7edb9bdba67af1fcc970d7c34a0694b68ea381d",    /* QsIUTy */
	"070cf3535a1fba25c9e8648ff1077b383fe2ec9c5f76cd24",    /* deIUT */
	"446368132f8dddbcbf6c9298bdf127faf2cde2ae0de2e7cb",    /* QeIUTx */
	"a0965183521fc15d8171a341d9b160d0528f860d93b927c2",    /* QeIUTy */
	"2e55624d49f89e4bf80b3b18b22fdb0d889a3b2980d74865",    /* Z */
},
/*COUNT = 25*/
{
	"5a78c3252678909464d2a2dd139e263cad3f2b65121e11d6",    /* dsCAVS */
	"817e2ae727269545f5254c70c5b707e9527a8f266dfe6657",    /* QsCAVSx */
	"519c60f896c1ae8b94afb7506db43a76866de3db203c331c",    /* QsCAVSy */
	"ecb0c8e7e1cd8afe48c752ae7b5d2494c0cb171b8b46584a",    /* deCAVS */
	"59d473535c3eb6141b9cea238e6f0d926b049f51b5fe4a4b",    /* QeCAVSx */
	"cbcb98fb9eec708f798b2533e2fdef1bbfd6044528f35747",    /* QeCAVSy */
	"738d6a3d942694cfffbc56f2a0763ef62c8f0f6cff2de23a",    /* dsIUT */
	"83e895e7a7b812064f45b2d857f4cc2405978a65b5f6daa4",    /* QsIUTx */
	"488bfad1495208f6454c946863eca7142051571a5282a57d",    /* QsIUTy */
	"df49b1abbbe45ad8703557f6de8df8a3c243c89655914607",    /* deIUT */
	"61a5646f96296d5f6ae23bb4e3295dac66f5678ef0dcf469",    /* QeIUTx */
	"5f9226b602d6b46ccc2277b456d07beed396643a6b03a0db",    /* QeIUTy */
	"08ec2997faf07a6f8304ecda06757eae2b858f53d36de3d6",    /* Z */
},
};

static const MQV_TestVectorOnePassInit gMQVTest192OnePassInit[] = 
{
    /* init.txt */
/*COUNT = 4*/
{
	"c38b8c148565fc16b81c0782181e1c514bf8819b521cd4a7",    /* dsCAVS */
	"a735dd1e12426b097346f90225cb37a667c302655fa30961",    /* QsCAVSx */
	"5ce98a820ed6d86800e3911ebd90073805941a57bcc66307",    /* QsCAVSy */
	"988f60ea7af9a47288afb443c0e25eee0a07431e76b29a70",    /* dsIUT */
	"9b9b3ffc79c01db377d2363f1ba1cabd292784611cd7d6b4",    /* QsIUTx */
	"6883296b91e54d457a23073ea75d5e8b843d5e3c157fd6f5",    /* QsIUTy */
	"c3af234c9c8f79fcae407f8f8ffccec3cbf1e922b966fc3d",    /* deIUT */
	"07acaee3517bce05fd0cf339e419011fc315858efc39f98c",    /* QeIUTx */
	"5ad37bb6463ad5994c9925740162c4b63c5969bd6ef0b9a4",    /* QeIUTy */
	"ee41a77983e9b5624d156b37b0b63fc767c7bc53768ea551",    /* Z */
},
/*COUNT = 5*/
{
	"8e5fba4f9f6fd7479e06e92ffd77781531d2f88f6b82df88",    /* dsCAVS */
	"38bf9eb1bd536c0877f9f027b52f381acbd6455268e05570",    /* QsCAVSx */
	"bd536cc0f05952db77759e0b4519606563139e31e5c1d0e2",    /* QsCAVSy */
	"49de8c542cbd0e203dd4b3b714a52c66992ef29bb046b691",    /* dsIUT */
	"f342da7ab71ecc6bc3133efb573e939c3c4f3ad5f23d2eb0",    /* QsIUTx */
	"2b61b218ceb647768ba67a41c7c3f52b216d161f1940cbf8",    /* QsIUTy */
	"3fc9108d3be2b7c182203ae3b45af3d09688a594b9f7b64f",    /* deIUT */
	"71a5e7fa10b9193ec2342dc1e17f5bf4603a7fc022937d67",    /* QeIUTx */
	"8b81f6292e1891cf42fb0927700568c813488732de38f7bf",    /* QeIUTy */
	"0aa5bb69814b3d21122286573a137e9eec4ca2a74ae7b233",    /* Z */
},
/*COUNT = 8*/
{
	"15e9a483a426db2ceffa15a2b84edb896f993a0213414c32",    /* dsCAVS */
	"a078ce52189af2fd53a6a2c2ec500405054fca83237b56d1",    /* QsCAVSx */
	"91bfed0ba7c0de18f2f2baf4e123ea262dc6d42a3f99df1e",    /* QsCAVSy */
	"5b8d2f948b66e4b89dfa86aa45d53235a4cc9ccf75e73181",    /* dsIUT */
	"939f35d416357c6d7d8c1dcfb60eb9f371bf0b58fba4e94c",    /* QsIUTx */
	"50ddee246175dd1c55bbddcd06d1702afce1c5bc6954415b",    /* QsIUTy */
	"47430c4add760e4d5766f75de80ef1ffd309db7ccab562b3",    /* deIUT */
	"1045e5fdb7154417d38ab47a490af94c09e5770edd08c994",    /* QeIUTx */
	"2189db5d1c89e7056fc608d515af6127409098bea34d5227",    /* QeIUTy */
	"00a7bfcf22c11b4334a4e26a7343567af0a5b91afad59575",    /* Z */
},
/*COUNT = 10*/
{
	"24535e10aebdf80debaf53b4287840320750bea35f70ecae",    /* dsCAVS */
	"872933d49b23da6e1d449bfbdab1fbf228e56938a700fbdc",    /* QsCAVSx */
	"c4e9c4e77a76ce5ce24d68f74ea711e9639b70490d35b282",    /* QsCAVSy */
	"ccda6514825c4b433e58fdce1794248945a7d05a968b069b",    /* dsIUT */
	"46cf2edf4249472d9ce859011a1923312717a5a7817f545f",    /* QsIUTx */
	"373edf5fdb909422f5710419f90201f1b6ab0aa84237f4d2",    /* QsIUTy */
	"6517b5c785074879e336aac80120ce0fdbda655b520f003b",    /* deIUT */
	"36b489e7d421afd6ebca5d91a9dcb2b2fec6dc0966fe89c0",    /* QeIUTx */
	"38338ea18ade91162b75af74a8589382edf1e1727da067f2",    /* QeIUTy */
	"9176960a04fa320f37c6e77fb06ef1a9af3dc46606dca414",    /* Z */
},
/*COUNT = 14*/
{
	"ee10997a536b1c3992b912de6482e742640b9c1c93dcf122",    /* dsCAVS */
	"9b6d392501fbda94f99c1563e67d6c85ddf22a7c6fc08bec",    /* QsCAVSx */
	"f10a8c1754bb61e01b4f9a5bbe20aed79f08a9a3b3cf7db2",    /* QsCAVSy */
	"1923e2ea7d26f5b0c6658921e13557eda014e6594509da74",    /* dsIUT */
	"aa1aaf13f8fe11e1217adb4014f8efbb052b396089095016",    /* QsIUTx */
	"3fb3a90b0d631de198cce9bb79f633715748ed7cecb33f58",    /* QsIUTy */
	"b3b8477b67407605f43fef5a420b0370fe53b310ee1740a7",    /* deIUT */
	"adb6e461bd4afb9e3ca4d07987067566b4a0359ddefb3192",    /* QeIUTx */
	"904b4d541be2dd720f7fe77dc5340227fb54835373398aca",    /* QeIUTy */
	"ec1d680a636ef94f84e42cea2f726f285eea930bde23407a",    /* Z */
},
/*COUNT = 23*/
{
	"44328f504c9d5dc08048222ce098e11ac0574b42f9aca5f1",    /* dsCAVS */
	"30feb14316e6a9b5539274545dd3ce263fb706eaa5a0233d",    /* QsCAVSx */
	"045041d2f8f96819656ee772de173b51abf150edd41d4e1f",    /* QsCAVSy */
	"809ef8f54c9079134a56d41c354b756de0e73bf8ed29771a",    /* dsIUT */
	"e28d43b90e534e0c608a00811accf117399bd195a3c7f233",    /* QsIUTx */
	"37da224f92ed966ddeeb4da7be4a815b0b9d899ee06f50de",    /* QsIUTy */
	"fbb01665db95d7e3a21943aac5d48c9efafb98469db218ad",    /* deIUT */
	"e0bc166225a48206011018cd1d22e3021cb0745cce9ab3c4",    /* QeIUTx */
	"bc2b0dd670922cb82f44a272c9a251bf6fdbd4dcd0c8639f",    /* QeIUTy */
	"5d00e81ec1bf0d35b27797509d40560751130ef82819f172",    /* Z */
},
/*COUNT = 25*/
{
	"b4a1a9a35af36ce755de721371ff2c92973ea3ac496a83f7",    /* dsCAVS */
	"16d5a0adbb090075fb0882553541418011b678661dc6c519",    /* QsCAVSx */
	"d7f00c52fd7e301735491d4a7f1ea17282afa79c369da80c",    /* QsCAVSy */
	"6947fb6bc01cd169e4914ca9416462cc84e24241905869fa",    /* dsIUT */
	"fbe60d60a493877b7064a432d9e68b94aad5e8ed2200a430",    /* QsIUTx */
	"a973c8b7fcea2939356e71ef265dc3c7d02f2f7bf7c26c2e",    /* QsIUTy */
	"f95d19cdeb09b30e08c2b0f679a59f0d58845534b18a6fa8",    /* deIUT */
	"357b5cf68628f5bed8e6f032664c258661d8a1faa9a121d7",    /* QeIUTx */
	"c2b039a196bd37adf31e080e45543de6ba8e4606f4b01135",    /* QeIUTy */
	"3b79fce2baa24becf60607cd43741654fc0ad0a0e355728a",    /* Z */
},
/*COUNT = 26*/
{
	"dfffe3ede870e01f6ce25bf12b2a4745e34dab0d5c2cb31a",    /* dsCAVS */
	"148d87e98dc551b67e369af93589bce435cb59e27ba0226d",    /* QsCAVSx */
	"bd071b15e76ff52105144c871922f37e792656e7b024236b",    /* QsCAVSy */
	"d587eeaeba6dee4228919b4a425ed9f4ef14c83ce248c113",    /* dsIUT */
	"fb8109625a7ec8a6d3f4e8aa594197ebc65eee4cf45adadc",    /* QsIUTx */
	"db71a4d41cdf039bf642d19ec71b9e61a580b601fa3b0771",    /* QsIUTy */
	"c8e48a7ba55cc4ff91352ba018fc7ecf466b1a46473387bb",    /* deIUT */
	"36718f98aa273208c4da38485b6f5389e2c8d59db1147a3a",    /* QeIUTx */
	"f96b494cc0b861727982487ac303454edfbd87f799b0b31f",    /* QeIUTy */
	"02a56833f599e189b7ee93f6a698c267aa885e9349a21c52",    /* Z */
},
/*COUNT = 28*/
{
	"913b287f50b38272e88b9da82e99bb6b6c99702cce132acb",    /* dsCAVS */
	"cba58eda33f83228b43831e3a4fbf802b81429bd9cc4a33f",    /* QsCAVSx */
	"e1de9e20cfc46283cd615a050cbb527c574796082cc8522a",    /* QsCAVSy */
	"0b89c63ce23f3cd1c77e66773b387f52c2836e10c8e184b5",    /* dsIUT */
	"734e670c76dd4b1113bff0b63f0e7aa98858ccb5fad5178f",    /* QsIUTx */
	"aacddea7119ee10b5c763ca21cfde965238ad3645c336722",    /* QsIUTy */
	"e2a5c0e47bdf64254e496ad0e86931f7a263e00f96048abc",    /* deIUT */
	"898fca2dd079f23b0a2630ba197fbb56086748b9644278fe",    /* QeIUTx */
	"55013219fd7d8418a9303d592b65002cfadc9337c5d5c16e",    /* QeIUTy */
	"0216ad8b9bdc3ce57a259ea348e4aaa0516413e964d07d1d",    /* Z */
},
/*COUNT = 29*/
{
	"d39728db40f7b49482e056c8153b0b9e118b9783ed6fd949",    /* dsCAVS */
	"bb9c458bd794c6289f7e351e72c22487acf9ec40600edaeb",    /* QsCAVSx */
	"aaa71aac8fe32d08a50b3039049e30a2906eff9b5df96b5c",    /* QsCAVSy */
	"fcbdd209fff489818eeffff575e8198e33ee8c889c198f12",    /* dsIUT */
	"e11cd60a11e93112ee40b468858c8bbc995c45981c983ba6",    /* QsIUTx */
	"5f55aedd6c465a788e86a5de334f93a05b56a508f6b9ec31",    /* QsIUTy */
	"9244f3745882c480ac170b6bc433eb0962747a011a99b013",    /* deIUT */
	"e6190c47d37dfb1979485536c4a6a7a45d0e24db4c735cce",    /* QeIUTx */
	"e2ef9d670a3ee3b0493355ab906c77af986eadd5d2b1c64e",    /* QeIUTy */
	"c00253560f5e2bc2de0a64bc5bf5e81211cd136a617706d2",    /* Z */
},
};

static const MQV_TestVectorOnePassResp gMQVTest192OnePassResp[] = 
{/* resp.txt */
/*COUNT = 1*/
{
	"65cedc803d7c107657d4524b8746e012f91e0b14289d0d46",    /* dsCAVS */
	"b70d833864b8337511f2d9056c7174373cfb057389c617fd",    /* QsCAVSx */
	"f1139a01459b424d85381f79732bfd169783c86c47c0d490",    /* QsCAVSy */
	"83a1899a044097aed127c763b51ce630eeac783328a372df",    /* deCAVS */
	"8c6ad466a3faa5286a4f71efbb948f299063720f819d474c",    /* QeCAVSx */
	"b403faaae0f57b9c6ff11c6433d45af31b5b6a641c2e13ce",    /* QeCAVSy */
	"14da31b9c81442cbec3d1255a74369e06aafc783b5aa715d",    /* dsIUT */
	"447d9700008f0253ebf6b9e1df8cc2a5cb0b019d901bf0c4",    /* QsIUTx */
	"62d0c2434797258bd34271d07f0ca9d8fdb4f3dae545255f",    /* QsIUTy */
	"df8d613155ec274e5aebe3b0d4fc112b3b0a3be4b14be1f1",    /* Z */
},
/*COUNT = 10*/
{
	"5782a11a4220975dba674703808b85df79bb73b5636a6d9d",    /* dsCAVS */
	"53218c61d8a452e933460298128ea70a4a680db0a880e158",    /* QsCAVSx */
	"08b32717a9a69db95fb2884fbbccb962685786e58d9f919e",    /* QsCAVSy */
	"54d0061487df6a045901dc71d805308bed26dfa95a2488e7",    /* deCAVS */
	"fff3ff5a11c915e0548294de6afa9141e8a223788c1ef6fd",    /* QeCAVSx */
	"67e4b10077a4d95f8f76a21f5f5338fb1f41719bc2ff152a",    /* QeCAVSy */
	"b6a685156dc75e98cc36138c30072ca34ded737647b631a6",    /* dsIUT */
	"604b0cf8060951e43e9d01917b1dbb931ffa5c6a84a4df93",    /* QsIUTx */
	"2b4f5ee8717bbd1c678772c735ade440db5523bbff8cb38e",    /* QsIUTy */
	"0b10d586dc57389cc00965a6c77842af8a5975090b97ae56",    /* Z */
},
/*COUNT = 12*/
{
	"1eb1dfa950cfee4cb1db1362cc6703b0122f50fd911986bc",    /* dsCAVS */
	"78d38670a973d06ea2360e147d3ee0a31e717bf3fe09b837",    /* QsCAVSx */
	"e2e85c0d6a6d2ef79e709e4a3017af01e9b1d8e4ba8e8fb4",    /* QsCAVSy */
	"bac150338fe49b859f7771b854f2369b8c361dd330bd58d9",    /* deCAVS */
	"200a73ee334cc1193cba1d2a35936aa99600051901a4b630",    /* QeCAVSx */
	"ffe5684b75d9b80280161530055aa4aef68efd0071bdf5e3",    /* QeCAVSy */
	"f0114b20bb1697e9e457cd187b4dc2fcc6f21ceaff8b7a05",    /* dsIUT */
	"dc0a0c551943b1f3e5419feafc95b7335a28855c01ff1801",    /* QsIUTx */
	"742ae98bd49edb500cc938fdff9966fbaa237b49fdb50870",    /* QsIUTy */
	"fb5cec4a931cd0bea8ef49cb02b3feb0cdc29c329905ed50",    /* Z */
},
/*COUNT = 17*/
{
	"8775f6c388b9213c934e9787274332f470a1a6229e3514d6",    /* dsCAVS */
	"88e96c8d06fefd158fc5fbf2d7ec0235d6902ae8b93a9eaa",    /* QsCAVSx */
	"cdd7681ca6ebe2b638ba49f58b122c06fa204282847cbfc8",    /* QsCAVSy */
	"c9e46c19d8eb1b86bcc2c7a1fd132e6dcf641f570b171807",    /* deCAVS */
	"c510525fb171f34cb7f9455e239754dcad03cf95a930aca1",    /* QeCAVSx */
	"039e683d062728653d44604b536d6a203c138179aee96a28",    /* QeCAVSy */
	"3453d2768ddda1f73a8c751e3eee6175f6c746f4840c038b",    /* dsIUT */
	"bb350010c71c12d67ca214705d67e33c61faf5e45c97171f",    /* QsIUTx */
	"4017e56d8670dc6b3c1dddeffe3713da80753b002d3f5c32",    /* QsIUTy */
	"f303ee59c0bb1d7828b56882b192e1ca366d73f101834cab",    /* Z */
},
/*COUNT = 18*/
{
	"fff256503f927f735b73daddf660467674902b03c5188543",    /* dsCAVS */
	"70f511b8faba71fc30d6068a6c059980e2ee15816c7483ba",    /* QsCAVSx */
	"52d8d371419c6e022697845c1342320061f90466b9cf96a7",    /* QsCAVSy */
	"4f75df93ae5392ce0cba735b3b4f0bc29720bdc5abeb656a",    /* deCAVS */
	"c5331c78128ddb089c3365b3d238fac90876eae24e14fc6f",    /* QeCAVSx */
	"2f25cad6aea7cbba19b09788ef36171a13aeb975c351f78c",    /* QeCAVSy */
	"60f7a46c8bb2f53e8414b7b27bb66f679213592618f66c54",    /* dsIUT */
	"4768693e1d02c99ad9296b2c6595309c5b9115b3ded6b74b",    /* QsIUTx */
	"d2974303b68546b63edfa9942d2b5f029b4e000476de0c58",    /* QsIUTy */
	"0dba802cadfa2641700f4873f82dda86b0dd21bffb8dffdb",    /* Z */
},
/*COUNT = 29*/
{
	"4e7a3df79ef21177bccc4a4b267f72625fd806cbdba0f73d",    /* dsCAVS */
	"11e90fd07b12a83c320773fa4b5c8a2a202bea15beb3722c",    /* QsCAVSx */
	"cf6b79ac38139abac363da9e3d0ffd60aad54601d87cd99e",    /* QsCAVSy */
	"a4ef9a0d2569ad1e0c2d1ff4ea0208bf0e9525ebe730f635",    /* deCAVS */
	"d20bde467cc572c1d4e964cbed07aac6697e0aaf16bbbace",    /* QeCAVSx */
	"6b1f416ea3a24fd5181c26437a93f03b5f12a68b2ebd166e",    /* QeCAVSy */
	"13754b59391811770b140bcd5321d8fe268f5758c9338a14",    /* dsIUT */
	"d14bb507d3ad73aae913cab0307c4636865e08be1d650409",    /* QsIUTx */
	"a96b1920f8c618e809ef14881e3f97a11506ab58f12e0f81",    /* QsIUTy */
	"f8af7efa289b867c3478aefce6d4e50a465b26c878da7253",    /* Z */
},
};


static const MQV_TestVectorOnePassInit gMQVTest384OnePassInit[] = 
{
    /* init.txt */
/*COUNT = 0*/
{
	"10f6ec1c8995aaacdd70f3be28bd2a3937a0a13def47395b3a4cc904a8f85a4868e2b344967fc74897d3c02a21b92657",    /* dsCAVS */
	"1f26490e535b0d89b2158a45ec57f51ec24afa1930a251fe93aaa3b1d465ea0bbf7d47d9a6a81f8e4a661fad88abec96",    /* QsCAVSx */
	"a8f9439c6cf73126ac88d8c6a5637644bd6d2ea686248a4aeeb16107c483cfbb7ec6f700339cdfac32655be98aeaf655",    /* QsCAVSy */
	"be95557ec07ed1ba0170daefd51547e9524c2362416935d1d297e35814094888bd4f4d38222718a0aaac9589264ac9d3",    /* dsIUT */
	"eae8c4f0681b077f924b7ce47ce6e5e02d1489cbe4e118be0929503abc016ffff34082286fefe269399eed9bf15432db",    /* QsIUTx */
	"bb5c021d4fbd19d9e3cd82506557348d35578ff3ac22ce44abfbf7f2705c13c4b3373a993d5f78524a6f69a61bdcb92b",    /* QsIUTy */
	"0c882a0c027fb710afeb4f7c115d6f9aa4f5a5b74e11ad2a9188e2fe3f2f1264966b938f63220d189b22da511cd202c5",    /* deIUT */
	"84dc3d10fe916b2f74b9af82f1d0f41e51a291732b1a2257b6e2886a990ecbbfbf0cfd31528b322bf8a859bb422e32eb",    /* QeIUTx */
	"9e789229f8ecd3c203134cb0ff033bab97b69dc311743f6a208035ce8355709d2a1934d633349d8f4717fe0c06a5c0e5",    /* QeIUTy */
	"2725f3fe01ba805191d096963f7eff71dbb8eaa5e42db199399eeca9554ab44c3b66800f7b4c98ea9f31788705064f4c",    /* Z */
},
/*COUNT = 1*/
{
	"50208ed203ef5275744d482521edd813fda96ca2023ee3cb2d89192d3d503f41a68f2e7a3f7657fae4fb51e7ea8ed37e",    /* dsCAVS */
	"668a7794c943bcb49173f2d8aaa407d3a138af1b5fc558cc84d6342d9b1ce482dc1f681b567b786d8b976b55b12a5d17",    /* QsCAVSx */
	"92781ae98b653408d1c052d620b183aba88b9ad10c641ce2f8def1cbc89631ce0bde1e85993b68cf2f28100b895fe036",    /* QsCAVSy */
	"f2ed427c6999dbf5e1cff150b327e7398265f7a39cf2139ac17b29369f19f79b1e91c2723ce85eb133846e565c9c7db0",    /* dsIUT */
	"d07d90994b563dd14776d9045c3da4ccb07ec2eee3b5e015460077843f3ee50ee97305f3b62186dba1c74fb1670ae90f",    /* QsIUTx */
	"2477486a70c0b375d4cd7417cf808d61f2794ec807b111573423fb7bdaa95e754099ddddd22fbf6b7e426c01d694a005",    /* QsIUTy */
	"c8c63f83addbb51ed539398e88ef7441f8ec8f4b94288f29af73a1d77b16b55887cb7da863de33cf06e807430b201691",    /* deIUT */
	"be1accd8ecc7dd358415b72f3b4c171890248dac672035251a78484c54f2b6c939ae11ee75a63a0974d89f99e9dcc42a",    /* QeIUTx */
	"982087485543a9a961839b84eb7ca849958497cf3840c0e6354a1014b06932cdc5ccb67cd3e535528f2c38d3c1a5baed",    /* QeIUTy */
	"d4c23e737b2dcf5640f7ae33f9ad1f953757826224fe2ebb99c1ef5c3d91a88fc70a74578fbfdeecf4c59dcda91e2434",    /* Z */
},
/*COUNT = 4*/
{
	"258c5f134c1f43a61068dc8b85d90d5147c85e28685f0a61111da1a15e96d319e306b60d87f4a6ad7e19f73066b60949",    /* dsCAVS */
	"66a2293059aa887df2067edd9083dff37a6832b96d8f826b2845fc8f0e598f4ad875bdb89827590cd9ebf160930c760a",    /* QsCAVSx */
	"7d6a62ce50dad143a2688c24251c7e54ab20bd594376dcb58fa47cc33fb08d9cc0057a37ae55ed227128033ad1f20bef",    /* QsCAVSy */
	"edbc84161d63a5baeed63fe900cfb32fc6d412c9374bedbc397e315e333c7046d99ec99595ac1e679c7aa8ecf20c5573",    /* dsIUT */
	"e6abfb84b92212c15ddcb6adde9ccb084d6d8bdddc84d29b6c41aac5ab261bf68b5a7f3ecb78ba9a00690161c9463c71",    /* QsIUTx */
	"279cec1e1392b1912c4cf69db1daea21052a59a6382a331049503727a456e61be88a8ffa50e2ee1dcfdf97d961bcbbb4",    /* QsIUTy */
	"89fac105eae87323e51ceb0f7f2f06b31309e1301e66e1e252f124c3aad8d68a10e89966419fe3b8c2010c08684eb1c4",    /* deIUT */
	"f08574596ff7a8690c27e6c411b9dc7e0a3d00bdaaf66a4b76d67f4508ce4365af5a7fa09fe39b22b357f9815c42581d",    /* QeIUTx */
	"9bad4609f6e4f6b56164ef8a1ef955e26154f8da15188fe1b488764f825bdbf403cab8a96a78e5b85bd4dc31cc42e570",    /* QeIUTy */
	"0ff317ce03f7e71de465c0c0866c5508fe06caaa9a290da8d7b6a825a884a709fca78a67afc7629109a12e213f0db867",    /* Z */
},
/*COUNT = 5*/
{
	"9088d9c2d4eeb495240ae5887297a5bf043f47ee40681281497025d880da1973a9199c6815b9fecacdee6f4d61a8e657",    /* dsCAVS */
	"59d5b66189a28912bc6a27ad15339c5b5f9d7996666ce6dde4b0e125cba80240c7beb561ec37c63efe3373829a2111ee",    /* QsCAVSx */
	"2c3c3306c11456f75f53340600bea25862c1e66fb58f81fe3b75ce8d22a5356c354caac7dfa1096b16f81b6496ef34aa",    /* QsCAVSy */
	"958645da42189d318dc546acaba3c28d02493d4f10c47b635e85de7f2f47723d20f8f351bbdf9dd8bd0fd91658081dd4",    /* dsIUT */
	"831f2ff378add319a2ce6eaf133a75065020ce9c3835667f3a02ade1fa612045c0a5330e368df3b75f82766d7c307f95",    /* QsIUTx */
	"9932e9db01b780b8144aad7a13b17949397ced83899728c852de31aa21b0a24c8dc068b8469baedab89316ab82e8478e",    /* QsIUTy */
	"041f95248f1a3bfc00780d6324d3432726403b9831a41e10327622486870f47e576ef7658ecf542117ade04a3fab801d",    /* deIUT */
	"f352dc6f063bc700a2ccf9b3c33dda05462ecbede947a7e0ac255148b332d6653c91b467875b7157186b310ed2f7c455",    /* QeIUTx */
	"034944bd080c8bf55ca0d0cd9291ccf6cc8778da5c96b86e688fd93af464612a3c042068cd7a89ce5169ddb9da9b0a7d",    /* QeIUTy */
	"c877262284b63c8127e9bac8e35124684bfd18e0d2c15354b5ed4069db36611145dc1f44f0e08d90a52d96c69cb0db1c",    /* Z */
},
/*COUNT = 9*/
{
	"88d2fc1b631782dc3ab3ecd98e25434ff621701acb6260258fae237953065c2516a0a76a6edbfb93a9da222bb344cf77",    /* dsCAVS */
	"ad44b958b13647a16300f41f729eb1b16b44261a0c7e07cf9aab0c04e9b2581c5abc6906e8601836bb7fa9a7370a0000",    /* QsCAVSx */
	"1546077b06383ec2699cf3ced8e0da89ec217315761ba811cb564ceae0475ce99637b5736cfa4387263844e05179656d",    /* QsCAVSy */
	"0280257f7044933ec7938f68a05a2134879c93f450a1424837b531c2e9d798a17cbe5052865daa1d56b148379d7c99a3",    /* dsIUT */
	"e7158f23f2c49b9452225b06cb9c4908b3386878a8440e515c04a24bfe1b0b43548aab8f96581b7a75b493fd3deb98ef",    /* QsIUTx */
	"0f936745c6fa0c9841703c3c8029a1926f94d5d65cd1ae73b6e092d4925fd70f88ee273b144c1e08566497e6555083a3",    /* QsIUTy */
	"ec265220596949ff18abc4fb213511b09af802b0d298dfbd16a8b04d146c359f7cab45f216da7e223da14262af2bdaba",    /* deIUT */
	"64cd2d8a7bea8e6b8f3815de1d0a817ef316b11ff019119bfd8c8b9642d18c2d258b717c6ef4589ccb7eed0e73189a7f",    /* QeIUTx */
	"6145f7651041ca229633318966134630c974a3fcc9c8164c95fdb2cff26873bf7de84a010a342a669f0b1f70caa03677",    /* QeIUTy */
	"66e0800a57a996a4f920f9ae7c51edd5c7451017f062b509ff2c4e0c818e96502b149b77a1d51924031242b812dfd46b",    /* Z */
},
/*COUNT = 15*/
{
	"bc4554a0103838973fcec3513b4cd4eee5034dee848ab32f060088c28bfcb574a9a2b06b2200ddbfb997dac9c733e879",    /* dsCAVS */
	"37861bb9843359d85c4906357786004e27163f91fe3c1c8c47c6099a0947fd130fcd1c49a962dfcba557cf94d8efdb7a",    /* QsCAVSx */
	"735ddb543610f49426f1856d51a47da6ec1afdf288014f3b8c532d9fae6fcbdb38827999b128a0756eeaf5ab31da1bdb",    /* QsCAVSy */
	"5ccf7b8509601752541f9ed059880db2213eac0d83e2cb9638b1abaa49a2fec1d5a4e4e4f78019f70dec4be0185afce5",    /* dsIUT */
	"907729bab856a9fda24b5594608b46378d419d337d138f7fc53cb151b4d7bd6f3b67d378a78f752552270359f566df49",    /* QsIUTx */
	"241fd8fddc0f5be6f2e0fcf4a01290e269f091d4e699372496393707c762bd1df1d70fa53726f2cc16c293b8f414ae82",    /* QsIUTy */
	"3fe230963d644150710f5085b7991a9a54262ed3b10f37fba4f1648749633c938b3d57727c87ce66a681fa9bc6c6fefd",    /* deIUT */
	"a39fa890a1e08b025691f8a426e872c38b4f0b740d35bb89dbcc89c6b89dfde186d5cac475a3dcde891253cf38fb76c5",    /* QeIUTx */
	"0f7704d779f293481057056d59fdd65d6fe0172868b28a0ba89edfa273646b2f6c62ac322c53f4d3f5cd09296929f343",    /* QeIUTy */
	"c9cfadbc1bd8a7365f50a608dce4f35682ae12dc327ae82189f2604c5a27fd50d896030ca710f8051f94cd8fe422f007",    /* Z */
},
/*COUNT = 19*/
{
	"6e989d5e0f633e4c5ac4427a4463fa3415d7fbf0ac4347c3f795a86cb18333e494a2f3a6cdc4987b3594b51ddd46ceba",    /* dsCAVS */
	"4d8ed45c99dd3e97bf217dd034db4e55585620794a1d2d1855a889426cd4a4029b306b21df5504a02a5e7a473017eb76",    /* QsCAVSx */
	"4e4467317d840fbce068cf74d2eb7fd603bb3aec32480cfe3a81fa0a0b4172ff6f4ee20153424270f94a87199e7ef823",    /* QsCAVSy */
	"48652cf59c4e511282613ca2ddff0c16317908e0b09ca09f48bbd0e3000cdb63b1391a51b02a37873c68b5cc0783e734",    /* dsIUT */
	"1a10be4fdfb763f5c70e01c13db536dd17d1f849bf481c4b36d2e3330cd3e30ae44e93f5652dc7126a5dd370960cd9f6",    /* QsIUTx */
	"b75e5c55e044602a813a57a380b43823c8620ce511f27fc2be2e087f0306a94e32b109657f89daedfe72c0db05378f9a",    /* QsIUTy */
	"17fe386c0c731e4350c4c4a2f0838fbfd1ab7bc2b3b658b9d7d39136315b6221d19b274d26af4cd12c8f829f76871b11",    /* deIUT */
	"6c22243c03fff4ff9998fba61c4f6f15864268c8683d2a721f94af22512106f08bb559deed576c6d79328b9062ee1980",    /* QeIUTx */
	"09f69cf75bacbc8fdcf48e14d0d88b401689625b900a11bda08632dade2a7c1d72e438f9c6d7d5835df0aa230ecbf786",    /* QeIUTy */
	"1cd4389452ed0c7e03064107093cb9e5f393a445ff1ace6a1163b0dabe963cc6ccfd35d1116038762bfef75f42c6f7ba",    /* Z */
},
/*COUNT = 22*/
{
	"2edb1d92288917abb427ab9e03f4b0e5238d4702ab7c74cd2aecf8c8cdfc9b7dc41f77edeeb9d08f464853d8179fbfff",    /* dsCAVS */
	"755546c0dcc60d48009e241fb23310f7abc695888fcc21db964e226e40741a35ab5b91ec19410698320e129317162b1e",    /* QsCAVSx */
	"28e8cbd49b3d8758948a1972650c92fc91922016a3ec1e890ee968f05ea90913272b732fc71e75d05153a645dc051bbd",    /* QsCAVSy */
	"194c030bd7ae06eb5ffa986f7ea22135ed748755090a5920bcee5bd0c23c3b6a41f42ed1bdc0b0cb91a20b781229130f",    /* dsIUT */
	"002e7f119cb725f7ac6f5a9c2c45a37e744eb8965cba55fa97a755285174fc152e2e98ddbfefc563fe89a93273ed5d24",    /* QsIUTx */
	"290315cdd76c67ae9f3a424314749bd00d38a7bb54f96b06aaa6433ad6dbef5677a617c452e634415500a1495fcbf05c",    /* QsIUTy */
	"e8e2c1a201d65c3fa036911dde3b37deb3142a9c75267195e82d874ae39b66402dcb26a682186760e321ba26d8210c0b",    /* deIUT */
	"e496e475adf22f207a89edd8d0afdec9ca5c19acabc101c9b6090992c75d13b1644ddc7ad1c41b6a5606b6b9f984164c",    /* QeIUTx */
	"fcd2066c1706e9211b615eec1896180d84cedac53639a90c5c2bd24cbb159697537c629bb304847aa2eeaa61c9f5c22e",    /* QeIUTy */
	"a5cda71816b1bdd1a4261e0faf3946d42982772d8d64b0ee89defa120b84a8616453b5d5c27d9990496d7e810be67790",    /* Z */
},
/*COUNT = 24*/
{
	"f9844def4ff0a4ff71a690daf303c73b6f4bbb7e2bda53dc591f818507c9925aad16f7d8e74325b4c77d70ed04e19af4",    /* dsCAVS */
	"8c3d214704fc7c4a184dfef71811a1ed4235ef0517e08daa51b31e99b07a9f13ef94f42d6bad18cb2094bd9d570f437f",    /* QsCAVSx */
	"8b055f0cfc681d24f46e872222f6fb0883aeb49cd4154f3e88e0d321cec5663d14f75286fc575b56c08b65f36110cef9",    /* QsCAVSy */
	"fa57d90c07ff4ee916182db30c8199c8cbe2458ae0bdc29561d55883ee9126c7379f8a913c89ef24054ab8c9f1a6c629",    /* dsIUT */
	"7fe82a9c8ab5878355681608d36f885f17c32184599fdfde742d7206006379b96fba9b72e449d66c475749c73eacb316",    /* QsIUTx */
	"dce6270a2508c0bad7e2e06e6ffc420bfdd7d00c5c26f2e12dcbc91858a3d0ba63f6a7488e79307eedcfeb0f056bc356",    /* QsIUTy */
	"82d71a7dcf7da3c26d98a6a5906c702eeb76cd351db51cead290a521f3a16409b48cb31fb9b77b3a44ae17f8ebde9fdd",    /* deIUT */
	"3df5d250323b7c9ae0a254c64d9c43ecda88fe379100148e7adaa04ea7f29bc992aef27408a0172a3862ce4568ba3f02",    /* QeIUTx */
	"077c0b9497a7f395467a415e86cc59195ee6fb548e6686a99a678c47aec2bc67881eae1490bf6e236d2cbd9a565ca9f7",    /* QeIUTy */
	"067b2d217189d6e1a9e078dc453949c379f50fe0248b47b57f02dad5766ff6c040d1ae126e550f7c576ff44997079577",    /* Z */
},
/*COUNT = 28*/
{
	"e37db99b775f274ddd1582870b410d2c90e8fe2884a495037aca2f325b327f66850031ee8e1567d049398a6b8dccd5db",    /* dsCAVS */
	"d103952f322daf52ca53f18fa592a165d18ea3bcb758f0d8fe6a5d4befeded7e203067d57c92714711ffcdad219aed67",    /* QsCAVSx */
	"482652eccfbfb0457bc8957c6f0b31c99b708fae5d2f7a32f9b545157ead14bd2f885f0e06a40abe560b8f72a783c841",    /* QsCAVSy */
	"936d23212102dc421c5e8b0961ed430f77572cc6d63bddc472047f3b40a3514a5e3d3508805ff0802efd6a04dc5409c6",    /* dsIUT */
	"176afd089adb642226316b999261d8b7637f220ec5111eb257c9597451ec4692034bac2795d5e93f4285e939e305698d",    /* QsIUTx */
	"06280542b816ce56acc7b041693e15f0471580828cb59da0fea4bac25cb5c0a2067d0cc8b31e91f59164d68201fd5599",    /* QsIUTy */
	"f85c621a693ea4feef35c3c307f327d42942a2c7271d0620f003f2e76c55fd88de50812ac5ddfa6673cad2b2ae3cc136",    /* deIUT */
	"3572ae13efe7cd2a4c489fad3e933bdc47ca5a6f59a1750845dcd7fb31142f9a31e1d4cd63d2a7f553185e15d8ec0041",    /* QeIUTx */
	"44aed9b4b8ea8f02b2fb56c2237bd05b6e799d684d89fd18b30fcd228b706e900b7896520f1eea34fa0b10c477926e62",    /* QeIUTy */
	"bebc0c3c44f090e9474f982755d8be7eb96c3ba0c1a8b96a7634550f8a1b3f99bae66d952b3b7bbb09d0c473546ca197",    /* Z */
},
};

static const MQV_TestVectorOnePassResp gMQVTest384OnePassResp[] = 
{
/* resp.txt */
/*COUNT = 1*/
{
	"cd5ec39c4c24f96820318b73b3c96acdf54819e633f1e59755a79e2f56f2c8398e40a549877a055fa63aba526f1e61e7",    /* dsCAVS */
	"648a1528730df7e0df90f1744d19886bac556770ac19f62d819d1d489c4af269e3e6500a5cd5476d8174cf0965c7f808",    /* QsCAVSx */
	"62a6df7f29fbe3164a4b58302fbdd148094c66d1d44e746b56dc3a4fddd9de66ba020d1cadbac94c76aed31e5af42816",    /* QsCAVSy */
	"74c2cd6d6198dc1734e1615fa19590bf3860d299b9dfe5755fef6c8af67b591420be65322a80ed3c8de71f1c4f2e586c",    /* deCAVS */
	"31c0184338c6e6e494a94462145ce2516617de38bf7e0fc9108a0222f9a38cd52511819db0d00a960e4bff3e86b6a09c",    /* QeCAVSx */
	"96403f12687350e950735a4ddcb288fb3d1027bf526e23a58d9546e1089a394b54cfb26a095dad12063c1b396fd742c5",    /* QeCAVSy */
	"7a2d4f0e085c834c6fcacf133ee8ae55e7221184ff6243a1f637decd8248c733ea713d5d0ea7e1b8b35e86b901d3fde7",    /* dsIUT */
	"6b2f661e4d79c1cbe2066840ac16958c4421562acfd519589162c59c4c388e64f2cabcd93631cc698a901c6e3a4d9e8b",    /* QsIUTx */
	"d84f80adca4232499a77966c8c94842fbe8a5d97b9d92a5bb42d261b2fd4dcb36c3de5d435f9d3a2d217d508f9da2157",    /* QsIUTy */
	"e7f2d8c3687ccc1c3cb82e3495156beff1ce63d100931e080d509e99dbbac6f2c22da047c3b568186087de4fba2ababc",    /* Z */
},
/*COUNT = 2*/
{
	"8eb4aea991dda50e0357f0140e2435d4ba89c2b50c9ab43590b1edc75d154847d8a02ccca05aadcf8219a9cd90135647",    /* dsCAVS */
	"8ded5873a4dcd2ad654e6d4cfb35d51dc60b15abf97e92992fe254da43df4c544c2991636d4aa27c0f438fbec5fa4471",    /* QsCAVSx */
	"cfa7587a0355da6fee1139c8a3a14f58ed98a43a679e64a22b8438a2630feda45baa96f452fdedec8e3815229b77264b",    /* QsCAVSy */
	"aac014b1f5e9491f8c525994f490e436a7abde8622cbb471887daa35beb795ebca6c6ca1d998e992a4e8513d4fc0a218",    /* deCAVS */
	"a3e216f1e7cc1dedd71a1f6a459fc324b4b1022f31034932f0bfdddbb1c43fc80e98a83cad8a3836cd07f85ebbfd4d73",    /* QeCAVSx */
	"72d9eda54d79a16f1c5b15fed8f75b114dba2023257757b1e2163292baf5ab22926337cab83823e2c3d69c4d379fe660",    /* QeCAVSy */
	"a71aab49708fc20e86a6847873681af2d17a4417d2851befc73ab4dbeff0c5003f275be6e173fa5e3e1ddb597cfa82e1",    /* dsIUT */
	"086289222bc3cca862c95bd88dc3aad1c086ab96035a9e60d24082fa7fbcd22ead0cba6bf40e997e5e267682d1ed569e",    /* QsIUTx */
	"23f066664be7b742a56bcbe1708d2bc6fd7910204f184b06c8a0c12b0b43897a1c544357747de82466edf69f0982b6b9",    /* QsIUTy */
	"003067a3dead06afc40d1e1d462f02198912ed6276f3317f46cb34748baffff2dd9a000a2496544a02364ae338a26ee9",    /* Z */
},
/*COUNT = 3*/
{
	"3e66e098f676c77598054bd1018016bac726d09af85c9f6a33ba09fe5a918491184c3655d2b80c453e09e783ce85f3dc",    /* dsCAVS */
	"30644a8256e45a83ca19f3d92f3269cf1678cf591306f3ad24d143c40f3922e64c5af8a5f276afbab8256aa078db9875",    /* QsCAVSx */
	"450db4f6a9479402e154551202a8f100e5dd28c83bf987de4812fd670bd52297be4dac585776d5bbd20bc4176f906410",    /* QsCAVSy */
	"3de3b4a0576a439903dfb4fa543f59327fecc1940f2d531b1e4fd66e991e7e290b9ba4943ac7e172e87ed1fc32a5b799",    /* deCAVS */
	"a6eb4613eb0d58e6302f96d084ce52ffaa7d393a732e58ea2f7de0e06614c6ab44893796764a7ec80f403891ca8bc0a3",    /* QeCAVSx */
	"8de874569104e770e3085cd5e66429d563446c7ccfad4d2dc705a50b526997467fd5e1796e96f701522b35faf6c7385e",    /* QeCAVSy */
	"620a720bc191ee7def73fd8d744ef6481c379263c1369bb35d8bef49acb3f30e0897334542aa52ee3b74f598f42dab48",    /* dsIUT */
	"cbc5c142241001ed28da191f071ea1f948b3d28c027748e299c8e4c8cb781ced4dd06799e280bf873c2e3bab6f34e910",    /* QsIUTx */
	"0d5e490c5e3a36d16042b2b79a91cebd7daa4bf70cb0873698787cb4f1f0ae143c34faa44a26daa1600a083b95cc4e8f",    /* QsIUTy */
	"4b205776190440a046fee3d54361662a8b5e746cf7f15f9b20722b192c135adf523d079e2c0cdeb42063f30508f3dcae",    /* Z */
},
/*COUNT = 21*/
{
	"e212c04d8b4e567c3c72ac5f07bae8394c17a10dc1fca3f51a8901886805579497aa38af7438eaee2ce45acc4cbb6509",    /* dsCAVS */
	"7cf6692026f3901cadae7f15415c06de1c3078cdc35476c4e2cca61b1b9fc049b74924f5936f528250b7c5eb1a4006cf",    /* QsCAVSx */
	"d7ee6dc16c227cf042e9a3c928f6078b154c0acf026a3f583c2d4cf992a2558afa2c83a51b644aa934408c37ed1f579d",    /* QsCAVSy */
	"6c91962f50fa07dab7c355500f7645adbf1d977dc898449d91f82542acccb67c785150c956bce86f5edc144d8d152011",    /* deCAVS */
	"b8215dd2b28fff6bfd84ef50e1c7388c19d618b7ab9f7dc421a34f3e2eb3d2fc3043443c69db1e743ccc2be486fb6ceb",    /* QeCAVSx */
	"efb00c2381b11b93dbbd716bc73c03ef523c2307e623da09058e530d16ac368381034f9462c00efa01ec83b8e9beb148",    /* QeCAVSy */
	"02814f7400c19820aa5a04c9c513eb1f7fce69a4c8d155ac84d3afb34dc00d175816c4ea01201ebc80014ac268a6e13e",    /* dsIUT */
	"ea0002d4ddeedb464e405ebee2bbad20ca27d65fdaf7c441fb2e0c451936d95af619db08090e068ba636abbe9c726cd5",    /* QsIUTx */
	"0a360b8075dfd769b1d086f462adf67a5edf80184d2dbe870ccf11052a011c8fb4702fa95d5b564eb0a70debe25bb206",    /* QsIUTy */
	"46e8f1a28d2932f9db9ac522748905462023ce8c7bb326bbd48fb9a2994699e63020081788816f472e6a4372c8e03ecd",    /* Z */
},
/*COUNT = 26*/
{
	"4ab578089692cafdc82141d2fd767a4e92c59ad9990c103b56808beea740785bb90ec56dee5456a7b93ccd37db0f97e1",    /* dsCAVS */
	"bcf5938c3df3a9e09986fe69bdbe1333e2a80bf28c1ee2f19d90aa6ca7d50f2d8b88a2d92d8ca63a602d6f44e9c5c3fb",    /* QsCAVSx */
	"3bdb6cd252ea66e1f6dab487775b88456b9fc0b2e333b084e9aca28046ab4a9585bf80d0660b758b9674da8d02c36ba6",    /* QsCAVSy */
	"b3da4b133fee4b30623337e1b214a2972b116dc6aefd3177b89e1478b4170cbe7bafe35f86a5c9dec88487bd6984ef13",    /* deCAVS */
	"4db12ab22e8d649b62c17b5e3150990db8f5dcd889be68609a7b8d8c4f1e02763f978ca8f551c4dd59a7ca40416720c5",    /* QeCAVSx */
	"b86ea239c1cdd03e29bc83a73fcaf39e51c9b2dfb941550c6aeaafc5beb562af27258a176434fdab96078c9b3de2b47b",    /* QeCAVSy */
	"3d5c0065b045a106eb9770fc69fdb585b8d920fd2ce3beac9de2219c13f26e60556c3d204dae95b3f9e2c5bf0866a592",    /* dsIUT */
	"209a2893e5bbcdb24567198c6e37e7261e688d11ec79393785aec84ff22062c718d1a536858e945f96f04257e61ec343",    /* QsIUTx */
	"363ceec9f1eccd572923fecc44ca6dd70209e4b7c2aa978ee14f4b7d32836f82466cdd8720ed6665553ef0dccf486d08",    /* QsIUTy */
	"ecadba3b14856d7e12b5adf4310ac4cc06abebc9db3af04712ee556765c6775196f829f1123bd6618f8017ff7699c462",    /* Z */
},
/*COUNT = 27*/
{
	"cde71e6c1ae9fdef2caf7bc87358e02e705e76e4797c566c117b4a316bb5edd05c198017f96a947f4f52697f0fac9f7b",    /* dsCAVS */
	"42633c75c72a532eb7fe79bc6829fe31d468b09b99c2e31dfd8b3720117c33a6faba4fd46c8d5be4249d932cc8c94a72",    /* QsCAVSx */
	"7da12c8a9af296a60d356d36f9818d647386a558fd42c781bb594796b5d85f2deeb72a383e69fc24f3b12f1bdbceb8fb",    /* QsCAVSy */
	"a4223eec4b91039573acf8133003afdd1a1b5497f4898a97b3cb0d099e4f9de01f43a3b076dbc43c0fdb117a3ef81bcb",    /* deCAVS */
	"b48b3871cfb4b0ff85985a3bb932399e46c73a040e037f1a1b4981093d451147c64edb19a07c3d7ab8eca7f3582fde1c",    /* QeCAVSx */
	"61428b957cd4424467ca19a21a4eb413a325acd4645815c5fc7897739e03af281560fafbf15debf2909012b67418542f",    /* QeCAVSy */
	"7bd24e254ac7626f0bda716af42aa785d6ddd74d193c0ea8d1e1210d831259deba4f1588e471b9c1e4d81baf5735d586",    /* dsIUT */
	"f9740130964b85b5e12f0b99447d407b27f9ff49b07532a6093eb97775f355c1476699dec8ff1c017343db96ccb8dc24",    /* QsIUTx */
	"ee7a025c445296900dda9dfd09d8a6df873b9d018d7229d96ee2ed6840a70cc4672f484b3caba5b3310b6dfb62a6e05d",    /* QsIUTy */
	"04084c5479672ad8fb3433755720f8607580e9097ad0d49c193e35e39dc372088eb9e6192b40e0a8937689b403758a12",    /* Z */
},
};

static const MQV_TestVectorOnePassInit gMQVTest521OnePassInit[] = 
{
    /* init.txt */
/*COUNT = 0*/
{
	"000001f9cbca9f7f1054292634b02dc1416f218b4e3123ee3ece915b1f3165d2d9c6fa4aeb7cc5aaa9dda05527ebe2ff88ca717f030a74ef6d2169313afc96ae4ace4c50",    /* dsCAVS */
	"000001f5c157115b4e93a34c5f3d73424595a7b2baef0e09c575f6726b50d04bd557cd9cfb3c333cf73e1596bc8fa63761a6961b5b5dca739a9c51f7bacc92d1b57d399a",    /* QsCAVSx */
	"0000000f2489b551b5dd2e114dc29f867582066fbcc24906979cc07aae8b897583669a20daf689117952a7d871a4e33d3be9c2e7a65843e72809fb0b7d2b2e1517046145",    /* QsCAVSy */
	"00000084bbf6a3c6e9b4fbe277e9e9048b2532c9b441e7bc89b63debae72fec875173549e75862796c4bd0182d835adcbb337429f3d8cabeb5e41ed9410b1a4a5a0bee7b",    /* dsIUT */
	"000000bda41d2b336043ea326a1f571259aa6eaf49c420c1ebd783356ba4a22daa8d3179a0e4eb691d97424f19fa30444b56ce749be2e11c57f3ca66a35cd55c53dba194",    /* QsIUTx */
	"0000000cdaf2daa6f9302086320d20108d4852d52fec3966ad894b2e8e75f198ad85c5a62cb7421f64b1b43e14b799cf676ea14c2b1c965da54b5a71ab782575396cc86b",    /* QsIUTy */
	"00000081e84637eda1ce89b8d1cd647cba31d7b8c405e77fde4ffce4b50013e19397260e7d4f75b4883923dddc52a2938e7a46a959ad9aee7d531065e4b7a0cfa5a7b7f1",    /* deIUT */
	"000000821c98fcc54f1a3549c4125cdc1fc3ce8e699f357e32a927f6bd4492557afecb3bfdeaf7f945a77ce98192bb4c0300c90327d6edd02861f93bbae351499b890cca",    /* QeIUTx */
	"000000ffb0f51fc38287496c7f4a2ab452ad89ce6674bc4e2468236c7d76c69def9298310cd8b6eefd108a4ec55edfb01de43c5a0726aa597ae38ff5a0bedab8c327fcc7",    /* QeIUTy */
	"01564bbda5e8689597ee68b2ef8e52d72e52ad990bece1ad115c5764b5133d01759b764d8ee02d15e41c6a83db589cc495bcc00e9928c0bc8e025a8ef872bf48538b",    /* Z */
},
/*COUNT = 3*/
{
	"000000a69df3ac1d76e27013d74adf60897efb086376c2b304e97e7f6df0f19234a0148354330ae7968043c28562936456e4629f61aa44849ef721f510bd5945f9dcdfe3",    /* dsCAVS */
	"000000f7dc694b3706413ef266943f0f7ad6c1c209d309bad7291a13038d44e8689e9da7846cfd2f8e177953f6f1d4314d83fd508a50485b9a33192585df53976a70c55d",    /* QsCAVSx */
	"000001b2f08b71952378d06f42a52202d357b06becd504e2100c9b340e85fe771554158f3c96902b8f971307331780a62d30f6dc894c04b3a0cdfba0bf207af1d9d51c7f",    /* QsCAVSy */
	"000000cca75b812cf9d7284bfab9305d8b53b837efc9bd7744a8c2a77a4fc67cfdd6c74bbc11420f1ba2778eba18073006c764ecefc909ee24cc6a337ab30bf3f37afb4f",    /* dsIUT */
	"00000019f08ac2d26dc89e9e040b5630fa8b10c383aa10917bad08b5615aa293978e523ba766c0060892edbb194b47d0c698006b63fe9ac9f0b1069a2a222efdfd34c1c8",    /* QsIUTx */
	"000001830608282128f79f9a411aad83878baf9eb4b15f3d4c4b69d8d4e3d1bdf09de7634cf28d64957dac65c2cdca362ddfcbe6b99db6a35f8ab59cc85b5007c7be52a6",    /* QsIUTy */
	"0000002d109240b7a4efba3687ce1f38b40a727a06abe76bf19160dc9854e970052c5c0e22937ca3ef29e46ed0aa457d1cdd7b61085eec9d67944548e125e614fdcaa837",    /* deIUT */
	"0000003e44b7c8c7f6061be8961146f68b1a59072f9ed4050b2778edd2c022104300fd40f34ab9bfb8530c7b858825a6ce332a8650f556affdf78d23f1f2731f2677d07f",    /* QeIUTx */
	"0000004e9faac5724b3f099a6e1ce9dc627b88ec2ce5228fb789a5794d4c98cd6865b5cb5ceb87612d54d33d417da16ed32baa2775a80925787f3a2203dd82e42d054b7e",    /* QeIUTy */
	"0191f16dc3c0ef38f2a2d55d9fb1a237e1e841eafa3eb15406c891509f58335030a3e9a9eea4ee29c2181907a2fe89c18d9dff5510aca466575a7934ba46055dbfc3",    /* Z */
},
/*COUNT = 4*/
{
	"000000b0c26784e5308633940040ae23001ef5b15b5695ed7029d03b52eaae1c215279967722f19540f570183877e9f2f392b6ab30baa53512e6978282cabaf91d32b2d1",    /* dsCAVS */
	"000001295442b037db90020fb4942e1be37c872b33740e9c12f3ae405a25391e409a9b4f0ad4e7040c8e672edce3e797b27aa3eaca6cb9b0ee1235bf659a7e9b8bc653b2",    /* QsCAVSx */
	"000001ce867a726d6391f0b7762c68f38ceab771dbbb317758170dc3fd0d814b30193c9a4d1fb6bfae8cb1455ce334aac32c456850c4f965699ea77fc8f8a822a644c938",    /* QsCAVSy */
	"00000050b2ed8b8c328e13971130eb455c5520ae5a9b0a6cacdf6eeb136a47253988ae0dc476574d7b243f62191545897a294566eba609d78336affb1b152a2175f77bc4",    /* dsIUT */
	"0000010a63ad6be45fa3437f092f797efe578dd72bc75974ebb82c7a0d21cde436a3e99f08185a1de49f9d82b00cefdee015c150dcc272f1261571b00b6d86929be70be9",    /* QsIUTx */
	"0000000d9e5fa67244906aef4925607a670ea5caaa8ba5d662114e50c4a28e56e005789b5b9e7243069dc62e1287e8d5cd0fa29d8124e676110ccac641922a6bf260b50b",    /* QsIUTy */
	"00000084a1bf81a6e0a0eaf3a78553fc6cc1aba350fa5ce5e2bd0814b0b9912aca013c6827f64fe35b101d995932b7542b187e6ef77a62faf40e75d374d47cfdc1b27543",    /* deIUT */
	"000001bd561622a9ee1963a69b892122c7b901d0ad86c1c6d909a67d38e05e3fec2ce8af4ae44a396b0998d65fa81cb1306cc1fe333d2feac56f29077ef61d645d793e91",    /* QeIUTx */
	"000001ef417106427321557df60d249f297a12dd68b57a1a0eccc0663660629b517c96303df294370f397bf7bf7953c00c30018552868a8cd3e434dcad2635a1140062b8",    /* QeIUTy */
	"018a58ee6bf9b9d7cb3546bc8b80c9f7c2d082fb275627dbb42e284abf81d8dec7393954e445b2a9268355de184b737dd82598fa873f9152526ebf4925471606ad55",    /* Z */
},
/*COUNT = 7*/
{
	"000000404a5d98917c87b154ebcc729d8da4d29e09d27f76fa670d4832e33dfed1bf8196c10ce021edad7b42ff51721f10b7f146b592e935cbc512bf20a93fef9647a829",    /* dsCAVS */
	"000001553d2a365fdbd6940849a9e5377c1837bbcf4daa7d065f98405e6e6f06797326bde98b0679c4636ff88007247efd0c60d9d75e49f433ad94f26c88b939a4661b2b",    /* QsCAVSx */
	"0000001d6fedcc3269aafef69d7913bf5f4f6190856cb379b7ca853064782c138890cedbbe6c86eeef88adf82fadcd64c6c65d16aa63f7d62f122fdfc2ac51756f838f8f",    /* QsCAVSy */
	"000001a51440a5739d3424ac5079b519e6ec46a7e4b01296f5d607ab45281d7e50eb391a2337b9d4ebb0f1d054f5d85082cf2dccaf1e016892174a3a0336c6a7bbd9bf95",    /* dsIUT */
	"000001ed86c54f4bcffc33cadd87bca35d795a87094648696fcb5bd1c2dfc0b944ec3bbef0bbfff5860c9504b8d673720da9236844999388c83eb33a4ce941ba14590ea1",    /* QsIUTx */
	"0000018f794490d3e9a7cd7d64eecf126f8f065bba48b1ed8d8e133d506a2fa97f7894f46fc7b2066dd7729623588feac516c4c2b7c4a8281ded72b1f19655da42164bc0",    /* QsIUTy */
	"0000002d321e3e3983e41970566e64065ace45815f3caf47c3ce247b0dc0ebb71d56e7a111ac23c230ce9f7913c75947eb66360bb693f58fc309068f1646e872f35bad2e",    /* deIUT */
	"00000075ed403c741813907ffdf7ddaed65479ed9b39c57351df98c9379929305478b7e34b226ae52fde85507a263642f0f19ec20778b5c920ae014cbb4fe81e0071f99d",    /* QeIUTx */
	"0000011363184dd6767772f35b1284ea9ba627e240d62544aafad300d2111e4b3bd45f9093b40eee22b2d3e51bc9d9a72510cb11d962955a36180a0ca199b95799262ab1",    /* QeIUTy */
	"01311f540c4ceabb63c5966fe7868e6c73d9a7db9db669e137310052ad9b32e8db49fffd604accdcd4eec230ac69360e120d801a17f9b672f624f3911b4e753736f9",    /* Z */
},
/*COUNT = 9*/
{
	"0000018efc3f787ec79d398264ebbc689cb0a16c810ada34f0aa614c899406c2c07a7837c72822c78e9e59d95c658fdc886418ea115e116bd1f8a08e8bf2c749467dece7",    /* dsCAVS */
	"000000bbb46503aff25b8600fe761718fc0590f11191ae38a05aa76305ee1a9be9b409eb080a63a895f7363cd042379c83445e96c74c39017f183a70e1f815ea104e6872",    /* QsCAVSx */
	"000001f430928777025ae9c22836fbde8718ac52d4c96d1b35e68780761902b448d182accc0deb667329fd46bc65b00521f79a5b728ddf7f2364ea03739a23345be74025",    /* QsCAVSy */
	"000000304af29381ef7b8914c7337d706a6c4594a962c61cf20d1d0d34aa118d2aa1862bd8940367ac5645f8a86bb5f1790f126ef0a404839a91c215958165a24111a9b7",    /* dsIUT */
	"000001b6935222a17902c75e4c1bf26e4fe7a87f7e1efb1ac551c6098956cd53e7876ee7e51c22ae8489f330e91a478fc1624f65a77ac35763f89432069737cd50276180",    /* QsIUTx */
	"00000122cba811144be7ddc35a7fcf8f725d39e95b726a85c5ed2c1ce6e7d50a2f0437e3e84db164908e1298e446f46f8f188d35f501d1297cfbe00ee148e0e242585220",    /* QsIUTy */
	"000000cf47643b4e2615567e42ce17f8c1a9270d77051ac8ee6cea885d647125fdae585e040d5aa0e13d60793215c99929c25703242535326d52eaaf03eb40200e2f483b",    /* deIUT */
	"000001091bc132b2ee42c818ce71d0194017869b061ab04af2832de8f121a0d1e50bd50d3515c4fa73b04b68952caf76ec680bad8ce237877f202ac1a8c4e7457f1da9ee",    /* QeIUTx */
	"000001e79a9c58fcc1f378d4f8352f8dac410afb7303b219540bdf834e8ea17edb9b337b4ef3673a36b717403eb88e965d343be6fccd5c39937ba2cb4fee4e827ac0a94a",    /* QeIUTy */
	"00b593470aadfcf8f0dbeb4af509d8bd3184a9cf929d2322b4e48987a9b51c717eafbe4b7f36a22bcbf332a961feeeed16eb2421b9bb6632614af34de68bac32ba2e",    /* Z */
},
/*COUNT = 17*/
{
	"000001224d4bf6569374c0e5ecf47f8a34ff5e2d1efb319ddd7bf1f5b77144589ce747d86cb9b7a6b35641c3d50856f0aba7931dfeeb0f4e91125c5539cfd837887a7a87",    /* dsCAVS */
	"000001e888bfd0efb2a7d3597417520833e7c73b8d3221603d7f9973a8729959c795f19b9052c7d0c901e14bb441603684d955ae9526c83ea0a3bd39aab6af20854ada2d",    /* QsCAVSx */
	"000000be7636c36017975bfed545c19f05a48c77a2b1f5b2e48c9dcba21ce65dfe4286923d2954fa3b0ed38282c9e7793257a31dada1ed3cdeaf749cf4fe7af2fb598c6f",    /* QsCAVSy */
	"000000252135fdd8016e54742b1d157d45c551e220c1e108927344521c3a673211045e0eb1cab7855cad31939121e9a0324c7647dc555d67b6bb58885bf9164a8b31323a",    /* dsIUT */
	"0000018bf2c7be8efb2ef3a2f0abea265324471c45a1db53dd0c4df211d8f5d47ca90d9dfae03b4adb781e1644b9d78e3b8083c70f5c3deedc994f0001ab29f51c2d93f1",    /* QsIUTx */
	"000001d0392ebdea9dae01f8311d43a2ae73f2c2806c95ab675fd824e4c96be5861b03bbfdf9d2fa35cb43618ab183dcbcd442788873eaea54765839ee409e56eefaa253",    /* QsIUTy */
	"000000c891010f9a0fae3ae993ba97bf184eb869fdbf9e1935a4b76b5416a926996416a44fc73d026a3d0886c22063708a8625401f665b547f480bbee374a0ff60212221",    /* deIUT */
	"0000004eb17cd560ddfc6b957c64e71ab96724ee513844222335f35cf6ec8250c41171c384279ad89411039615ac041795143f3751cde5d998582effd97ae0b43c1d2d44",    /* QeIUTx */
	"000000e4a21e11c97b5cd67bc55a076fa9978482fe8c1dff8ca780c645ea3a00f534246d030beb4be75070261d4a69e96622db3928368d6d68cecb240d1b5a6ae7ed6396",    /* QeIUTy */
	"00fe63a21675098ec09d9f47295301db8f1c6a2ec42e86dba59a0bcbc6e6ed52289ff2d400fb51ed617b5dbfb9046c09a0a5479c6fd15f88256203477ed7ddfe8a97",    /* Z */
},
/*COUNT = 20*/
{
	"000001dee8121a6b8cd1e3c1759f3823e3a0ad778ea657f619703cca61dfc9b25fcb9bcd08273fcf19fa9cd0c70de1b7ec4e567e4fc4dbbd6001d0fb7d0319974344f860",    /* dsCAVS */
	"000000cdafdf2c474f5f61609bafe92ad323eaa44002b6f9d246cf64064e9649ba48fdaec4ef36e0e02337790bc86c03c88bbf79cf39af2d9469d68fc7b71fa0219b3cf1",    /* QsCAVSx */
	"000000da3502866aa69b677efdf9d4dee5e6760248e87b89930cc1a4209aadb5cc6a70def3faba96cfc359bd1eeda71ea41127f566d525024fa85f60b14de644b0594a15",    /* QsCAVSy */
	"00000070a8b2ddc0ee691b82a1a6e9a8fe3a635737ec2766483c7ca12866d9933ef531c1bdb04d1b9517af52097d52d33cbc0ebdd529ba93346b15ea400164896eb70769",    /* dsIUT */
	"000001e0517a10e905a9bfbd2cc3fffe6b29ab75ada5f56a0e256c0086a561336a5243d8aeeba778d4cd108af8ee3f90e0b9f21b77bf80e608b30b0581b3b3fd7e5ef2fb",    /* QsIUTx */
	"000000d86e155f2dee5142e655a06afbb90d65ff9452e00f540bad50f7530cdfdf692443acd334769e22e5b1be14c2ad4dd85ed396db9a8ef4f1cc6bb857de6d45536f28",    /* QsIUTy */
	"000001b793634cbc37f82baf40ad841293c7d9ea714aac9a2827a57de41864e766bb6a49ae260a34235200bd4245fac0716b42f16ecf4f049d794725c14ecf519b91cb34",    /* deIUT */
	"000000dbbddd901017fabf0e94c2c960c049f09aced6f09f16c89afa9417a0ec2ece47c163ca229cb7190d3d603943f265f0ea06c757f45ec00b0018deb71cc9ae86c94e",    /* QeIUTx */
	"0000013e3fcb124470490c849028689f68552dedfa374e0f4950a211468288970f2a941e2a7de1ae36cb3ce61093f68a51a2a163945987c03f5fd7961caa89f4b657756a",    /* QeIUTy */
	"001cab228cf9ca39a790bca42d0d57de2dd07cb4655f245139054e0a1790f6b8a8682dcff25769a55a942518cc5d8f2a1b7b57ae20aa3854ec84a14a67f92e2d6d89",    /* Z */
},
/*COUNT = 21*/
{
	"000001b6f6832899c55571cc4c592d4dfaf1da8d99443904b15758b4ce323142e594ab39131bf49794acbb0ea6029756fd125b7c5260e0a363fb6a6eb32f1a2bf6cf8849",    /* dsCAVS */
	"0000004b09f5d238e954fd3658a79403e69a5b30ab69255801e450da77f7b3bb44c21e8d65de9b6229fecaed5a144f586cf1c0776aabbc45224b7259140c49239eac1671",    /* QsCAVSx */
	"0000005224431123a9d6856a5e5dada86bbdcb5417aecff4ebc53a0d75d9271a0784f0fe4d37d67eabb9eb48f0b94c37bbef03825ad7b9f0cf8f7380e3aa7eace2b20922",    /* QsCAVSy */
	"000000fcc4f5032982e09355de9049badc6a49ac153eff63452ee9817480b9f9f53c7b1ffd02761b681805bea167aa6732b7a522cfca04a6c43ad704ef6a16b85a36835a",    /* dsIUT */
	"00000141fa79290b1b96013c486ca088563788bbe039027d2ba275353350712f1f18919f974d9ce045567e867451b19cd5b9bf0cf4071c23ba92c64562af201d4747fa7d",    /* QsIUTx */
	"000000e7a2993204eaf11641b1897a29ff581c59d587b67486a8d0733248801b1f6f653027a3fea22bd629199e52b0c6646f30902d8b8796e5d3d3aa6631d34fb6c3bfbe",    /* QsIUTy */
	"000000087b4f8ce1affaea68b1cacb7c8753b5fd2913b88d1d9525c8ea764043a02dc36bf0ba646ad05ad130f74edef2156251010b5471fb8c20f366f531c2aa1ba9e9c8",    /* deIUT */
	"000000c374702ca75dc39bacd215d6e473fbfc82548ad48e65df0d8992c52dedec7602d3f29501cb21ad6de3e0d3e98ca153456fe2a893fde38469fc5ffdf986a094d472",    /* QeIUTx */
	"00000119566eaa093568145645cb51fdc1d47fea1d933fcf7401394d4ac21d6d64c7f6b675db1a1686edf049d5d570059984a41006928d35a5f010e7443314cc2c4b70df",    /* QeIUTy */
	"01086049be02e839cf429dc619a8fedebf672c71a22db878cb8f98819da0b5e37d9239e851fb6665553c09b97b1da4a163fe4d248c3df8f26f8e2cd412f2ba4ee7d3",    /* Z */
},
/*COUNT = 25*/
{
	"0000010da94775e74a8593680c9564687f1373dc55cd8a087d8ffa2f226fbe3e9ea53e8bf649e9ffa7d9d2f9f58946c55d8697fd1b7ce9acfcc7bd8c028a0e3c3d8e93ff",    /* dsCAVS */
	"000001b90ba970c329a0dba9fb9e4b74419184b6950af391e43c673fd1ee544900069b3eb4947f61a5e1ffa9c778e937e8b345968891d98067f751d9b089c0d63a8eba96",    /* QsCAVSx */
	"000000d6d768281a433549d690fe0126d098805d17e2938134313533bfdd6c11a9951ad6784807b326980587761d32ab2a260aadfb90b4a0dd94009a84ed9b161cb900ab",    /* QsCAVSy */
	"000000efcd7a48f5680dff56d56d906c41d75907f9b6dc712a806f57eecbc8ba9e4882d8a15a222814e258fe591d31826ec27b92955a45fef8fdbed77e43ef1d981336d2",    /* dsIUT */
	"00000188d87ba4dc70876065722f00793fa37cb289c1f6daf3ef9c0ed971253ee4894f4ce1085db09b23294d82ebf26a5ad6e3c41746e811ea3d85bd21f96afe48f90654",    /* QsIUTx */
	"000001dbb67fd2ead2bb642b172a90ed2721ca056c45063834db88d49fac8eaf4658b9b38fee358397c06e85e61467e062fae953c59a46c2fadac2e915a7336e32e31756",    /* QsIUTy */
	"000001802f484687aa72c20bc5a402c30f4b5f2d76a9f5bc3bdf38e79a8c623d4aee9bf9e5848f94f0f5b032cfe13880aa30b4e9af7cbc12eb482baae9a0db5339f7429f",    /* deIUT */
	"000000a2b0935a5ac5e0202256cb81622bd6885eae72378fb079181a722bb36f8e6e83f1dc10d23e9cea9403fc9921a6a5947f8ee1d8650a13d114a019991ca56ffb872f",    /* QeIUTx */
	"000001ccad8a560d051872116d1e22793325fd3230fd22c31d6c1bf4023bf1dd25f06c4da0ea9c3c9be97d820f28163e25a2e7d3710a8ca2181cdba795b961e0a12c7187",    /* QeIUTy */
	"01bbba8b7bb352548fa3a2ea6a867d031c7da70c610fbb04085157098d8d319bbb33a4139c2ad9c0f9b1121a4c8ba87dddfd9c570704148d099ca43c2a12a9b78a85",    /* Z */
},
/*COUNT = 28*/
{
	"00000172f9edd438731ed168b3b3590b8e6243f1526aecf2d6b56bb9935fd5259f2f03fc0d07ce4dbb969e45ef1a8505ef0968d57e5dad2fe4ae09c54e97690275c6de09",    /* dsCAVS */
	"000000e4a82dc0c7da49d409a75c6bfdb72977dbec32e2320b594649f8b3a2f095af22f428dc8ffe16bff043bed7f1a20ff9fb639640ffb9634e4e3ecfa02a26c4b0e83f",    /* QsCAVSx */
	"0000014b94ec8255e9431e1ad3d586a9bac578fc8298f3afbba2306e22b392808a97c967ffd55ef0f8edd818c3727fe46db2d5e6d10004ec49d4f9f60b455d087f22d4ff",    /* QsCAVSy */
	"000000620f6a2d1d0eb4027e0d6016773be8f0d296c617a3d261f43291a2e571d8edbcb3e7327273f7d68ad5319568412facc70320d3c29f0d848bbe6ad1d1ef94677c47",    /* dsIUT */
	"000000e0b35357283d298610a773ff2793308765b7dfcf31aec6836de32e1bc07882074e07a3e983368971a18dece43d66615e985f11e5c5a624ca071fa74242e75f5889",    /* QsIUTx */
	"0000003304e5358cbcff64b70ecd494689a98e44705df7bfef813a8e635f791927c9f9dea2a8cd4878aba59c4937c4b6d29c81772b9dab43301b902b5ae7668f2cfd42df",    /* QsIUTy */
	"000000a61aeb7a76f30503b7fa0fa38a36cf8ab358029eb733fef71fcbce0445a5f3cf0752c3ad9c2ebd4086a741e7cf7764485250cb8300035f31a7b0f261b96c19c809",    /* deIUT */
	"000000afb64da42291b228c035aeea655b5545ff55c2e877119b9b4746e922b0c8582e5c68ee3af542228a5cc38fb314d40ea46e122b574981c760750f6e5189387a0153",    /* QeIUTx */
	"000000ff498fe7fd17416375846746c0ca84a2d832bef0e76b9ecd44053124c4869c21a6c9f1776552f4085636ad191a90e94b38c682d89a4a5ff02aac1b738219bd2928",    /* QeIUTy */
	"0161dcc2c145bb3ebd8ef5ffbabfdb6d3cab592ee144bc802322d85c3efd705f743656e3506279af819bbfb4a60ef0af5fae738acad571860996fcecc378fece823a",    /* Z */
},
};

static const MQV_TestVectorOnePassResp gMQVTest521OnePassResp[] = 
{
/* resp.txt */
/*COUNT = 0*/
{
	"000000729b200a6b4b5ca0315da91b7d96076cb070b4dda306f84ed972fcd876c1d312f45c696b21024e80c070c74c07556664d28747091f7ed123db405c2346f4db606a",    /* dsCAVS */
	"0000000f156138416957830348b7b337fc563c95c749c325896fd898ff516911d3a7de7d511fe4686acb6373cb269c2d2804c875d2d8a5a17d93a08c5aae02878084eff5",    /* QsCAVSx */
	"0000001552d7084082a8cc6a5c959e25897bdbdfdb216e95f889cbbe91a8bccb3741da31a1d74160df6dec91ca1adbeb331d29438034e5a7720b7bc70d7698702930a4bb",    /* QsCAVSy */
	"00000177876545ef6ffabe156f3e6a03a11583d9ec262fc9e52e38f21e9d1d4ba67a95880b8aa2ec66d81346e11a67c37ffb5f1d7805df8e2a817a7991fb8e0a4962b1fa",    /* deCAVS */
	"0000012b445ef4914def7f2e8e36a8666d7760be9f9ce0b4ba4f1e039f6e63f6db3418260fe5542e4ce8b356e1a93cdf75349506a335955f33cdb20aecd6b06ea48d8583",    /* QeCAVSx */
	"000001f3378567b19e46363f0d75e66bf38c765a24a0b9b58c80f2cb551d0f86ffa0c8aed5e93ac9f652a6a066095698dd137a52b57ba329f79f752c6f9a7227e559a995",    /* QeCAVSy */
	"00000108e9e6284a693a9c03b35020ad35fd01f2b615cf7e1911eb44b2dff2f13f4b8957043fd36a3c51b83cdc39348139fad1db817382ad10663477084029b587a54da0",    /* dsIUT */
	"000001569503f530ef5e5dbf835cedf8a4ab4eeecbf22777d9d8806b7ffd6e8e1ff12a3c619638027227863b5ac5cc3c2b9e1cd98e4e81f820f6fda9e64bb5b7735edc90",    /* QsIUTx */
	"0000002ea44ff715ffc1be418ad5650cbb7cd4cbd9bf0e9fa5311f4b7e59126f6f9351cc4e9be01e8425551a7db7c4e3dd665d35334f8f705c7d2931597203dc86fc059e",    /* QsIUTy */
	"004f8feb0e0ef875881ce397828cc00715c7a7b1bd880fcf0e2d153fb8723e9f53c0797fbfc7abe7138b20df441aaa44ed6e7cf73313b1b767dd020527a6663cc6e5",    /* Z */
},
/*COUNT = 8*/
{
	"000000a79509a26a9baa05ff56f18f87d21c60bd7e5befeab7a88af9c07487cae1cd67c5cd937390971da80cea82b1096d3bdbd26c370bb6b9ede532a640528cbe84c5e4",    /* dsCAVS */
	"000001dc65097b36183d823148ab9fb0ba443b1604e952448de5a0f7033a22c7babb15961db0e50b2f62d663c1a0d05bd5e1f6f5d5577b0672a1be6cade2c6e81d80cbb5",    /* QsCAVSx */
	"0000002247d89df6027e6ebc4ee0f8dd47e6373b9fc700248b5fb4a39ced51b0a15fd3060884a1d781208bc207209263d16207b7c3e5aab0a27da24f293ae0ec67507cce",    /* QsCAVSy */
	"0000002e5929022604d7dc7f9c91b1625017094bb7decbecb74837c59f3eb600a7dc071935c41332f4d6ddb59c02d7157636c5724fa53f3459be4d9ad5f694d5c998002c",    /* deCAVS */
	"000000f71087b0966a287e443391d89801b1871b8909b34c57432115f4f212d33345474dcb3b150f558bbce87b01983f8e4470d53a67bd5c7e2207dcdb39372970e2fe07",    /* QeCAVSx */
	"000001bc3eaee4f34b195410ee6fec986c352ba028d0837db48a917a00215e29abb111896c76c944fccabfb654a1558fcee9ff0d9f90c20c7444d096dcc8bcbbc77c5ccf",    /* QeCAVSy */
	"000000c9b7937f3836d2f6f9d1bb2d32ebc7444a464969385a52d264dd45973e0ee28cfa9083e051a134210cdec67e8366c4303181139844962590e64fb346e9ab1b2aaa",    /* dsIUT */
	"000001dd922737de8f67d2bc33e7fc1b39eeb924cbe73a0238af9f02d48e9978f04c62193bd7513b9da54bd949385c1d85b47121a87ae8319a1cacf8f50a10e6f86fb563",    /* QsIUTx */
	"0000010c020d4382b8b4d4aae635d967175b5d9595d2035f6c75311ed4c4af4e05167973fd87ff4282af2b4a0e20af11eeac48da62e91a41102686ef3480a76ffc0b841d",    /* QsIUTy */
	"015898b044254f7b98c88e095ff742d2479a70b0d26c11397d41e5c9f64bed255cd51db34f840dc11cc5c8bc975dc72aba60e8025ed64e5a360069f2fcd4385d384c",    /* Z */
},
/*COUNT = 12*/
{
	"000001bbccb2eeb2fa2fe2e17cbf488e5b2c0b713e4681de53f3a2bfd5d1373a975d4cf0a62cde5c46c48e4f49ec2eca42316c5eafad005221bdc01a344f2534250164ac",    /* dsCAVS */
	"000000dd6a0b865abaae0dd72343734da2e73d84007694c132630d99a1686cfc5ebef6d160d2a60c6f85772f6b1a50840ce432a35ffabbbf3667ab6c2f9c104919b27a42",    /* QsCAVSx */
	"00000052806bae8a0359360cae276fd7f3373d3fc7ab9633861b40e5bc7d6e830f24ce4b2660ee166f9ada99de0a4a593582f025da581b71cf5292d8b61387e37f8b7381",    /* QsCAVSy */
	"000001e5fefc56c8e9837207aa8a13855266ff6881f09fa9ce5338c91ea033b70be962ae3836e43358dc35c545b2f68138121a73a467b5179f53e39ad0c6c5cb557c32f3",    /* deCAVS */
	"0000018f11099cd59c9fc41dbba6345d90d16ca6b2dc3f0024c053500e59728ce6774f8d8d8798f3c31a3ec539b42ba60149d97fdf42546274ee35d447570a21161e6664",    /* QeCAVSx */
	"000000fac493808a359f8dd547a123d8b066584f3fd3ec3679e6977d17406d03a0589ffea125cf47532dfcf427de1f1d85eaa06d9900079c82e9f7914a409052df294d0f",    /* QeCAVSy */
	"0000000990bf481562ba67ed934dca1f77f480af6bdef98239cef33ea5303933b2b7b884765eecd19ef19ba8e4cbc01f4048232099cfa730a8b545c0a11e7161c81e89e9",    /* dsIUT */
	"000001ed5f1b23723a6e4accd428fbccdc04b55b781616e1a45fea69168161c7d96c20f5011266ca646cd4f1e6da1db85775e1fc1bdc9955e68b9c1afadbbae844450c93",    /* QsIUTx */
	"0000010e569179134e4364f48710a6124ad5fb4b85ef7fed4dec72c101b045664d3d145721ecdf627db2f65f1a343798aec75dd04de56028188097e702d2c18136860045",    /* QsIUTy */
	"00ce579ffc92a62adf788b24cd40d3c7d2e1a3bec0af48444604896bca1a299230f44a54a178374266fdcf7b4eedb8bc184c1f31819f61cb088856765894f6e320e7",    /* Z */
},
/*COUNT = 18*/
{
	"0000019921397ba9e9aed6fea90ea72e3740199f334bc07451e8d82c92c47596a0321164dd6aba047c2d6d277f6d5905a84b791434dfc3b7d9eec1fe93bcf6e4873e5ff9",    /* dsCAVS */
	"0000013a0c4ff97293f3d682aebdac0fdebc992f33d8638a11aee0d0244815e8a7b726d9b974cf6dc51ebcb6c5b844f634569d7c9644d74bcc4554cfebd3a3e31e0cc7d8",    /* QsCAVSx */
	"000001e20e75456c7799fc4f228aa9497491a295c58a8494a406545289e1b236b18a29eda66e802295289579ad11810248260ec47f27d475c7301dee66c01f4d9e018c92",    /* QsCAVSy */
	"00000165bf8d676e80e8c18d2485f5a63a24053a4a234c9bdd5dd4567f3e1af0c23873d05bfe4fb089a2efb515967f80452e0174bd6527b1897d2894a6fd7bfda8be8a61",    /* deCAVS */
	"0000008e13ec58c4e4f712fcd05bbbcf5c1edf37184ee5b4fdd2ab8e3336382e1956d6ae9977680663104304723590803b63ee6f5f4ffc6e83c6794556f60e17e4d51a03",    /* QeCAVSx */
	"0000007975b8f4991cebe97e36487f54c8f4dd5f4a343b4ca8523faaa58da990510495b28d8a99cfdf15ed473e4112ec8932d249c6eb5c64bb83d9ba5ef8d405f584bed8",    /* QeCAVSy */
	"000000d30150d47352a102f67ca070535020d9546b10f0b952230afda10ea941a4d682c337f8a8433ffe62b7f22582a4e1cb9283cfd36ef45e39bbb0270834e6f1417ba0",    /* dsIUT */
	"000001834e3b0c662395b2a8ab7fd212f63d6bfa5e292f2ebf5d150a7520887593d5429007f30451536d14a0836ed6d8d8992e3e0d9c593dce54cd9d67baaf7f3a9abd98",    /* QsIUTx */
	"000001865f17f503e981c4b888e09fb7ef87ddf2dda74ded43345306cf3b58090392719be199931f734f71409a7b8c389274d9b2fddbc9aadf0b85a6b520e6baab37ee77",    /* QsIUTy */
	"003bfc9a643cdf7d6d99be5c6d41ca2cbf63ad2ddd0d86934c2a2f41b35b683f9b5a29d33ca5902a5da5b1c53ba724ee85e7b721f75e9b00e117cba3f51ce938a8df",    /* Z */
},
/*COUNT = 24*/
{
	"000000f2b4065b8ef1bb05337a3bb3c1722599a00e030f14678d910e7cc3f21d48853b7e68e273c3d4b368196cbbccfd612aca193d16528dc11b85da760dd8511eb01dd3",    /* dsCAVS */
	"000000d7d9dfb6cb8066298db142aabaad9da38d0e6d49aca00fc174cec4aeb28b930607959c4bf3276eb815901b55388081dd91e0b162bd2be624a3a13601041627ecf9",    /* QsCAVSx */
	"0000015eea591fa5734717c61c018c067fffad186d9bab4033f33b2878e96ca265ae0f76df1eb4e0e3e16dde1f6813a6db76474a218f09e072ac90e762a8827b05710eb4",    /* QsCAVSy */
	"000001d78dcfb7964bf9f2d17de899878694138a128c1f5072ae5cd75c21056db5f1301beee65e48de551cb4e589973a9dba3b405ac5663834435e525c6a3ba5b1149091",    /* deCAVS */
	"00000046428f7725f78137817da9618874cf41199f96f64183bacd109fb15e30cc80ddb84ac19b188d5ef766278455db38dead6c0088b8115d037f8d406a23f66dbca6f6",    /* QeCAVSx */
	"00000034e479c2b0614b8f95782d4f39cc2d43dfb9707c3f4084195529805f80a3cef8b0158dbc705d8378b5895a85fc73a77b902751a23661cf83109a24e6a5686cf1ba",    /* QeCAVSy */
	"000000ca652c9eed67df6929df0493b0667ed77ce250ecac70344848c5b6a20566a744cac48b65072ec6a8aa312befec1ab0517a08f394c4bde3289aa4d5d61a82701ce4",    /* dsIUT */
	"000001b5503dfcfeade638a61a1ceb013b8cee506fd4bab198e97f65989f1a48ce91d428479e6f2e3d0ccfd43053e5c4bd396dc75e2ae58d6374aa25f142152e989c2373",    /* QsIUTx */
	"000000beb9ed4d0e0d9e8c565f703c3b7bb3fd1d7591a5ce064d2d5d3d5cd81d21bd64deb0ffd24cac763e9a7f2325d99c429cde23aa06996ef213ff83fe11e4cd3409e1",    /* QsIUTy */
	"00adb5c91a523c344d38098014a66f6af0425d61485813cc0d0805ea766284fb660a71749cfcbe235d821c9f05145a49ce85641f9d5b4f8bc1e8d49c5f0ac3bf4569",    /* Z */
},
/*COUNT = 27*/
{
	"0000012048d43d3f26d3ebe09019b990bd65fc85bf540fe0519cea0ffffa4f1e396f1591a66405d2397c18ec28164691143703d628a1d2f0c7a3487a66d7dea4ac5766f7",    /* dsCAVS */
	"000000d7eb35149b47e63f2a1fdd3c66b0a36e45714cabb84dd0cb0ec99c60cd299929ecfddd36fc951e536a78a5b9669da21812098ecefb9f664acdc9a03fb8456bbb37",    /* QsCAVSx */
	"00000089f6989aba0efb4c09e35db6d8a0a2c4c6376984ddc91839866876e8b1ccec46f6438054206bc63121866e5db325e0e0f1dbbb0fd6756a6bcf68b57b28e81c9e78",    /* QsCAVSy */
	"000001a46d754ca075f59dd2c1fabed92af81982b53ccfd5832b8d9aac104d222a10527636aab79b1ac94c3f53344e9eed82f668e2c6093dbf6c625cfb099ed339c80293",    /* deCAVS */
	"0000007f814e5a2ba333655244b134dc959498ecdefd93f58d48e725d3474e4a25889802f8f041b19a75ef3cadd4b90c99a671539ca80184b757c69273587f277da8fe11",    /* QeCAVSx */
	"000001ebb1d31594d460d7ee918ec2c472195c4be5a1673da66586e8737f9a89751fcd00478f7d4cdcd90172a18869f987d19d5ffee828072ed80762282d2ead68b3715d",    /* QeCAVSy */
	"0000001cbabb6ef635ec325b562377ba68cce370ae1a2d5e4bae641f10363017737b54d7b01133dbd1f9f63afbb13d6546a08a4e8b32b17cbb8a2a240b80cd9520c59972",    /* dsIUT */
	"000001511178663882bdae3699526a44ec6eab9df017ea7c1ec9745a5b04edb6c5ebcee2a9a50d6b69a6a72caaffa122aeab1a7351f20787efe9eb32407e1af3641179b7",    /* QsIUTx */
	"000000ddadcd3f36a00096d42d30957a7ec1e265ff9327f4d3afbe933d5158acc7a6241515221e5917923bdfe4d9e7e6cfbc89a88dfdd172796a927b4c874453fc4f1887",    /* QsIUTy */
	"00108de9da9bb8b7a9aa482c2065732ef2aad89bad5c2c41bdbb168f21fb5f4c763334b71ce485271af12662a77b5423c73518ccaebd23aa0c0609aba6fd51ff85f0",    /* Z */
},
};


/*------------------------------------------------------------------------------*/

int mqv_exchange( int hint, PEllipticCurvePtr pEC, randomContext* pRandomContext )
{
    int i, retVal = 0;

    MSTATUS status;
    ECCKey* pQ1U = 0;
    ECCKey* pQ2U = 0;
    ECCKey* pQ1V = 0;
    ECCKey* pQ2V = 0;
    PFEPtr pSharedU = 0;
    PFEPtr pSharedV = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pEC);


    if (OK > ( status = EC_newKey( pEC, &pQ1U)) ||
        OK > ( status = EC_newKey( pEC, &pQ2U)) ||
        OK > ( status = EC_newKey( pEC, &pQ1V)) ||
        OK > ( status = EC_newKey( pEC, &pQ2V)) )
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    pQ1U->pCurve = pQ2U->pCurve = pQ1V->pCurve = pQ2V->pCurve = pEC;
    pQ1U->privateKey = pQ2U->privateKey = pQ1V->privateKey = pQ2V->privateKey = 1;

    /* generate the static keys */
    if (OK > ( status = EC_generateKeyPair( pEC, RANDOM_rngFun, pRandomContext, 
                                            pQ1U->k, pQ1U->Qx, pQ1U->Qy)) ||
        OK > ( status = EC_generateKeyPair( pEC, RANDOM_rngFun, pRandomContext, 
                                            pQ1V->k, pQ1V->Qx, pQ1V->Qy)) )
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }


    hint *= 10000;

    for (i = 0; i < 100; ++i)
    {

        /* generate ephemeral keys */
        if (OK > ( status = EC_generateKeyPair( pEC, RANDOM_rngFun, pRandomContext, 
                                            pQ2U->k, pQ2U->Qx, pQ2U->Qy)) ||
            OK > ( status = EC_generateKeyPair( pEC, RANDOM_rngFun, pRandomContext, 
                                            pQ2V->k, pQ2V->Qx, pQ2V->Qy)) )
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        /* compute pSharedU */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1U, pQ2U, pQ1V, pQ2V, &pSharedU)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }
        /* compute pSharedV */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1V, pQ2V, pQ1U, pQ2U, &pSharedV)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }

        if (  0 == retVal)
        {
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pSharedV));
        }
        
        PRIMEFIELD_deleteElement( pPF, &pSharedU); 
        PRIMEFIELD_deleteElement( pPF, &pSharedV);

        if (retVal)
        {
            goto exit;
        }

    }
    
exit:

    PRIMEFIELD_deleteElement( pPF, &pSharedU);
    PRIMEFIELD_deleteElement( pPF, &pSharedV);

    EC_deleteKey( &pQ1U);
    EC_deleteKey( &pQ2U);
    EC_deleteKey( &pQ1V);
    EC_deleteKey( &pQ2V);

    return retVal;
}


/*------------------------------------------------------------------------------*/

int primeec_mqv_test_exchange()
{
    int retVal = 0;
    MSTATUS status = OK;
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
#ifdef __ENABLE_DIGICERT_ECC_P192__
    retVal += mqv_exchange( 192, EC_P192, g_pRandomContext);
#endif
    retVal += mqv_exchange( 224, EC_P224, g_pRandomContext);
    retVal += mqv_exchange( 256, EC_P256, g_pRandomContext);
    retVal += mqv_exchange( 384, EC_P384, g_pRandomContext);
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += mqv_exchange( 521, EC_P521, g_pRandomContext);
#endif
    
exit:
   
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}


/*------------------------------------------------------------------------------*/

static MSTATUS SetPFEFromStr( PrimeFieldPtr pPF, PFEPtr pA, const char* s)
{
    MSTATUS status = ERR_FALSE;
    ubyte4 bsLen;
    ubyte* bs = 0;

    bsLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*) s, &bs);
    if (bsLen && bs)
    {
        status = PRIMEFIELD_setToByteString( pPF, pA, bs, bsLen);
    }

    if (bs)
    {
        FREE(bs);
    }

    return status;
}


/*------------------------------------------------------------------------------*/

static MSTATUS SetECCKeyFromStrs( PrimeFieldPtr pPF, ECCKey* pKey, const char* const first[])
{
    MSTATUS status;

    if (OK > ( status = SetPFEFromStr(pPF, pKey->k, first[0])))
        goto exit;

    if (OK > ( status = SetPFEFromStr(pPF, pKey->Qx, first[1])))
        goto exit;

    if (OK > ( status = SetPFEFromStr(pPF, pKey->Qy, first[2])))
        goto exit;

exit:

    return status;
}


/*------------------------------------------------------------------------------*/

int mqv_vectors_full( int hint, PEllipticCurvePtr pEC, 
                     const MQV_TestVectorFull* pVectors, int numVectors)
{
    int i, retVal = 0;

    MSTATUS status;
    ECCKey* pQ1U = 0;
    ECCKey* pQ2U = 0;
    ECCKey* pQ1V = 0;
    ECCKey* pQ2V = 0;
    PFEPtr pSharedU = 0;
    PFEPtr pSharedV = 0;
    PFEPtr pZ = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pEC);


    if (OK > ( status = EC_newKey( pEC, &pQ1U)) ||
        OK > ( status = EC_newKey( pEC, &pQ2U)) ||
        OK > ( status = EC_newKey( pEC, &pQ1V)) ||
        OK > ( status = EC_newKey( pEC, &pQ2V)) ||
        OK > ( status = PRIMEFIELD_newElement(pPF, &pZ)) )
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    pQ1U->pCurve = pQ2U->pCurve = pQ1V->pCurve = pQ2V->pCurve = pEC;
    pQ1U->privateKey = pQ2U->privateKey = pQ1V->privateKey = pQ2V->privateKey = 1;

    hint *= 10000;

    for (i = 0; i < numVectors; ++i)
    {
        const MQV_TestVectorFull* pVector = pVectors + i;

        /* read key from vector */
        if (OK > ( status = SetECCKeyFromStrs(pPF, pQ1U, &pVector->dsCAVS)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ2U, &pVector->deCAVS)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ1V, &pVector->dsIUT)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ2V, &pVector->deIUT)) )
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        if (OK > ( status = SetPFEFromStr( pPF, pZ, pVector->Z)))
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        /* compute pSharedU */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1U, pQ2U, pQ1V, pQ2V, &pSharedU)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }
        /* compute pSharedV */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1V, pQ2V, pQ1U, pQ2U, &pSharedV)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }

        if ( 0 == retVal)
        {
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pSharedV));
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pZ));
        }
        
        PRIMEFIELD_deleteElement( pPF, &pSharedU); 
        PRIMEFIELD_deleteElement( pPF, &pSharedV);

        if (retVal)
        {
            goto exit;
        }

    }
    
exit:

    PRIMEFIELD_deleteElement( pPF, &pZ);
    PRIMEFIELD_deleteElement( pPF, &pSharedU);
    PRIMEFIELD_deleteElement( pPF, &pSharedV);

    EC_deleteKey( &pQ1U);
    EC_deleteKey( &pQ2U);
    EC_deleteKey( &pQ1V);
    EC_deleteKey( &pQ2V);

    return retVal;
}


/*------------------------------------------------------------------------------*/

int mqv_vectors_onepass_init( int hint, PEllipticCurvePtr pEC, 
                        const MQV_TestVectorOnePassInit* pVectors,
                        int numVectors)
{
    int i, retVal = 0;

    MSTATUS status;
    ECCKey* pQ1U = 0;
    ECCKey* pQ1V = 0;
    ECCKey* pQ2V = 0;
    PFEPtr pSharedU = 0;
    PFEPtr pSharedV = 0;
    PFEPtr pZ = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pEC);

    if (OK > ( status = EC_newKey( pEC, &pQ1U)) ||
        OK > ( status = EC_newKey( pEC, &pQ1V)) ||
        OK > ( status = EC_newKey( pEC, &pQ2V)) ||
        OK > ( status = PRIMEFIELD_newElement(pPF, &pZ)) )
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    pQ1U->pCurve = pQ1V->pCurve = pQ2V->pCurve = pEC;
    pQ1U->privateKey = pQ1V->privateKey = pQ2V->privateKey = 1;

    hint *= 10000;

    for (i = 0; i < numVectors; ++i)
    {
        const MQV_TestVectorOnePassInit* pVector = pVectors + i;

        /* read key from vector */
        if (OK > ( status = SetECCKeyFromStrs(pPF, pQ1U, &pVector->dsCAVS)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ1V, &pVector->dsIUT)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ2V, &pVector->deIUT)) )
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        if (OK > ( status = SetPFEFromStr( pPF, pZ, pVector->Z)))
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        /* compute pSharedU */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1U, pQ1U, pQ1V, pQ2V, &pSharedU)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }
        /* compute pSharedV */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1V, pQ2V, pQ1U, pQ1U, &pSharedV)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }

        if ( 0 == retVal)
        {
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pSharedV));
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pZ));
        }
        
        PRIMEFIELD_deleteElement( pPF, &pSharedU); 
        PRIMEFIELD_deleteElement( pPF, &pSharedV);

        if (retVal)
        {
            goto exit;
        }
    }
    
exit:

    PRIMEFIELD_deleteElement( pPF, &pZ);
    PRIMEFIELD_deleteElement( pPF, &pSharedU);
    PRIMEFIELD_deleteElement( pPF, &pSharedV);

    EC_deleteKey( &pQ1U);
    EC_deleteKey( &pQ1V);
    EC_deleteKey( &pQ2V);

    return retVal;
}


/*------------------------------------------------------------------------------*/

int mqv_vectors_onepass_resp( int hint, PEllipticCurvePtr pEC, 
                        const MQV_TestVectorOnePassResp* pVectors,
                        int numVectors)
{
    int i, retVal = 0;

    MSTATUS status;
    ECCKey* pQ1U = 0;
    ECCKey* pQ2U = 0;
    ECCKey* pQ1V = 0;
    PFEPtr pSharedU = 0;
    PFEPtr pSharedV = 0;
    PFEPtr pZ = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pEC);

    if (OK > ( status = EC_newKey( pEC, &pQ1U)) ||
        OK > ( status = EC_newKey( pEC, &pQ2U)) ||
        OK > ( status = EC_newKey( pEC, &pQ1V)) ||
        OK > ( status = PRIMEFIELD_newElement(pPF, &pZ)) )
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    pQ1U->pCurve = pQ2U->pCurve = pQ1V->pCurve = pEC;
    pQ1U->privateKey = pQ2U->privateKey = pQ1V->privateKey = 1;

    hint *= 10000;

    for (i = 0; i < numVectors; ++i)
    {
        const MQV_TestVectorOnePassResp* pVector = pVectors + i;

        /* read key from vector */
        if (OK > ( status = SetECCKeyFromStrs(pPF, pQ1U, &pVector->dsCAVS)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ2U, &pVector->deCAVS)) ||
            OK > ( status = SetECCKeyFromStrs(pPF, pQ1V, &pVector->dsIUT)) )
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        if (OK > ( status = SetPFEFromStr( pPF, pZ, pVector->Z)))
        {
            retVal += UNITTEST_STATUS( hint + i, status);
            goto exit;
        }

        /* compute pSharedU */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1U, pQ2U, pQ1V, pQ1V, &pSharedU)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }
        /* compute pSharedV */
        if (OK > ( status = ECMQV_generateSharedSecret(pQ1V, pQ1V, pQ1U, pQ2U, &pSharedV)))
        {
            retVal += UNITTEST_STATUS(hint + i, status);
        }

        if ( 0 == retVal)
        {
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pSharedV));
            retVal += UNITTEST_TRUE( hint + i, 0 == PRIMEFIELD_cmp( pPF, pSharedU, pZ));
        }
        
        PRIMEFIELD_deleteElement( pPF, &pSharedU); 
        PRIMEFIELD_deleteElement( pPF, &pSharedV);

        if (retVal)
        {
            goto exit;
        }
    }
    
exit:

    PRIMEFIELD_deleteElement( pPF, &pZ);
    PRIMEFIELD_deleteElement( pPF, &pSharedU);
    PRIMEFIELD_deleteElement( pPF, &pSharedV);

    EC_deleteKey( &pQ1U);
    EC_deleteKey( &pQ2U);
    EC_deleteKey( &pQ1V);

    return retVal;
}


/*------------------------------------------------------------------------------*/

int primeec_mqv_test_vectors()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_ECC_P192__
    retVal += mqv_vectors_full( 192, EC_P192, gMQVTest192Full, COUNTOF(gMQVTest192Full));
    retVal += mqv_vectors_onepass_init( 192, EC_P192, gMQVTest192OnePassInit, COUNTOF(gMQVTest192OnePassInit));
#endif
    retVal += mqv_vectors_onepass_init( 384, EC_P384, gMQVTest384OnePassInit, COUNTOF(gMQVTest384OnePassInit));
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += mqv_vectors_onepass_init( 521, EC_P521, gMQVTest521OnePassInit, COUNTOF(gMQVTest521OnePassInit));
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
    retVal += mqv_vectors_onepass_resp( 192, EC_P192, gMQVTest192OnePassResp, COUNTOF(gMQVTest192OnePassResp));
#endif
    retVal += mqv_vectors_onepass_resp( 384, EC_P384, gMQVTest384OnePassResp, COUNTOF(gMQVTest384OnePassResp));
#ifndef __ENABLE_COFACTOR_MUL_TEST__
    retVal += mqv_vectors_onepass_resp( 521, EC_P521, gMQVTest521OnePassResp, COUNTOF(gMQVTest521OnePassResp));
#endif
    return retVal;
}
