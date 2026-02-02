/*
 * moc_ecc_wrapper_test.c
 *
 * test ECC wrapper API
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/primeec.h"

#include <stdio.h>
/* for known vectors, complete data needed for a single test */
typedef struct KVT_ecdsa
{
    /* key material */
    ubyte pPrivKey[66];
    ubyte4 privKeyLen;
    ubyte pPubX[66];
    ubyte4 pubXLen;
    ubyte pPubY[66];
    ubyte4 pubYLen;
    /* signature, intermediate value, and message */
    ubyte pKValue[66];
    ubyte4 kValueLen;
    ubyte pRVal[66];
    ubyte4 rValLen;
    ubyte pSVal[66];
    ubyte4 sValLen;
    ubyte4 curveId;
    ubyte pMsg[30];
    ubyte4 msgLen;
    ubyte hashAlgo;

} KVT_ecdsa;

static MocCtx gpMocCtx = NULL;
static void *gOpInfo = NULL;
static ubyte *gpKValue = NULL;
static ubyte4 gKValueLen = 0;


/*------------------------------------------------------------------*/

/* takes a char that represents a hex value, and stores its binary value into
 * out */
int hex2bin(const char hex, char *out)
{
    if (NULL == out)
        return 0;

    if ('0' <= hex && '9' >= hex)
        *out = hex - '0';
    else if ('A' <= hex && 'F' >= hex)
        *out = hex - 'A' + 10;
    else if ('a' <= hex && 'f' >= hex)
        *out = hex - 'a' + 10;
    else
        return 0;
    return 1;
}

/* takes a hex string, and stores its binary array into out */
size_t hexs2bin(const char *hex, unsigned char **out)
{
    size_t len;
    char b1;
    char b2;
    size_t i;

    if (NULL == hex || *hex == '\0' || NULL == out)
        return 0;

    len = DIGI_STRLEN((const sbyte *) hex);

    if (len % 2 == 0)
        len = (len / 2);
    else
        len = ((len + 1) / 2);


    DIGI_MALLOC((void **) out, (ubyte4) len);

    for (i = 0; i < len; i++)
    {
        if (!hex2bin(hex[i * 2], &b1) || !hex2bin(hex[i * 2 + 1], &b2))
        {
            return 0;
        }
        (*out)[i] = (b1 << 4) | b2;
    }

    return len;
}


/*----------------------------------------------------------------------------*/

/* defined after this function */
int testKnownVectors(KVT_ecdsa knownVector);


/*----------------------------------------------------------------------------*/

int runKnownVectorTests()
{
    /* order for each test:
     * private key,
     * x coordinate,
     * y coordinate, k value,
     * r value,
     * s value
     */

    ubyte *data[] = {
        /* test #1: p192 sha1 */
        (ubyte *) "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        (ubyte *) "AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
        (ubyte *) "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43",
        (ubyte *) "37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021",
        (ubyte *) "98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF",
        (ubyte *) "57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64",

        /* test #2: p192 sha224 */
        (ubyte *) "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        (ubyte *) "AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
        (ubyte *) "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43",
        (ubyte *) "4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8",
        (ubyte *) "A1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5",
        (ubyte *) "E07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A",

        /* test #3: p192 sha256 */
        (ubyte *) "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        (ubyte *) "AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
        (ubyte *) "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43",
        (ubyte *) "32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496",
        (ubyte *) "4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55",
        (ubyte *) "CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85",

        /* test #4: p192 sha384 */
        (ubyte *) "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        (ubyte *) "AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
        (ubyte *) "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43",
        (ubyte *) "4730005C4FCB01834C063A7B6760096DBE284B8252EF4311",
        (ubyte *) "DA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5",
        (ubyte *) "C3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E",

        /* test #5: p192 sha512 */
        (ubyte *) "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        (ubyte *) "AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
        (ubyte *) "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43",
        (ubyte *) "A2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1",
        (ubyte *) "4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8",
        (ubyte *) "3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67",

        /* test #6: p224 sha1 */
        (ubyte *) "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        (ubyte *) "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
        (ubyte *) "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
        (ubyte *) "7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BC",
        (ubyte *) "22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC",
        (ubyte *) "66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69",
        /* test #7: p224 sha224 */
        (ubyte *) "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        (ubyte *) "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
        (ubyte *) "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
        (ubyte *) "C1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D",
        (ubyte *) "1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E",
        (ubyte *) "A6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC",
        /* test #8: p224 sha256 */
        (ubyte *) "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        (ubyte *) "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
        (ubyte *) "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
        (ubyte *) "AD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC",
        (ubyte *) "61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA",
        (ubyte *) "BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101",
        /* test #9: p224 sha384 */
        (ubyte *) "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        (ubyte *) "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
        (ubyte *) "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
        (ubyte *) "52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40",
        (ubyte *) "0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953",
        (ubyte *) "830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D",
        /* test #10: p224 sha512 */
        (ubyte *) "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        (ubyte *) "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
        (ubyte *) "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
        (ubyte *) "9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14",
        (ubyte *) "074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397",
        (ubyte *) "A4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084",

        /* test #11: p256 sha1 */
        (ubyte *) "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        (ubyte *) "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        (ubyte *) "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        (ubyte *) "882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4",
        (ubyte *) "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32",
        (ubyte *) "6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB",
        /* test #12: p256 sha224 */
        (ubyte *) "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        (ubyte *) "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        (ubyte *) "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        (ubyte *) "103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473",
        (ubyte *) "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F",
        (ubyte *) "B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",
        /* test #13: p256 sha256 */
        (ubyte *) "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        (ubyte *) "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        (ubyte *) "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        (ubyte *) "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
        (ubyte *) "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        (ubyte *) "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        /* test #14: p256 sha384 */
        (ubyte *) "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        (ubyte *) "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        (ubyte *) "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        (ubyte *) "09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4",
        (ubyte *) "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
        (ubyte *) "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
        /* test #15: p256 sha512 */
        (ubyte *) "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        (ubyte *) "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        (ubyte *) "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        (ubyte *) "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5",
        (ubyte *) "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
        (ubyte *) "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",

        /* test #16: p384 sha1 */
        (ubyte *) "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        (ubyte *) "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
        (ubyte *) "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        (ubyte *) "4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB096630F29E5938D25106C3C340045A2DB01A7",
        (ubyte *) "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2",
        (ubyte *) "A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443",
        /* test #17: p384 sha224 */
        (ubyte *) "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        (ubyte *) "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
        (ubyte *) "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        (ubyte *) "A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06A5899EA56C51B5879",
        (ubyte *) "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122",
        (ubyte *) "9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D",
        /* test #18: p384 sha256 */
        (ubyte *) "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        (ubyte *) "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
        (ubyte *) "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        (ubyte *) "180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60",
        (ubyte *) "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
        (ubyte *) "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0",
        /* test #19: p384 sha384 */
        (ubyte *) "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        (ubyte *) "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
        (ubyte *) "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        (ubyte *) "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9",
        (ubyte *) "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
        (ubyte *) "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
        /* test #20: p384 sha512 */
        (ubyte *) "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        (ubyte *) "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
        (ubyte *) "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        (ubyte *) "92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3",
        (ubyte *) "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
        (ubyte *) "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5",

        /* prefixed a 0 to all hex strings to make test work. Original vectors are of 131 length. With prefix, they are 132, and generate
         * a 66 byte string. Sign/verify succeeds now */
        /* test #21: p521 sha1 */
        (ubyte *) "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        (ubyte *) "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
        (ubyte *) "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        (ubyte *) "0089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D0F9",
        (ubyte *) "00343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D",
        (ubyte *) "00E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16",
        /* test #22: p521 sha224 */
        (ubyte *) "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        (ubyte *) "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
        (ubyte *) "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        (ubyte *) "0121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B92113F3",
        (ubyte *) "01776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E",
        (ubyte *) "0050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F",
        /* test #23: p521 sha256 */
        (ubyte *) "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        (ubyte *) "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
        (ubyte *) "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        (ubyte *) "00EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0",
        (ubyte *) "01511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
        (ubyte *) "004A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC",
        /* test #24: p521 sha384 */
        (ubyte *) "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        (ubyte *) "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
        (ubyte *) "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        (ubyte *) "01546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211",
        (ubyte *) "01EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451",
        (ubyte *) "01F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61",
        /* test #25: p521 sha512 */
        (ubyte *) "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        (ubyte *) "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
        (ubyte *) "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        (ubyte *) "01DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3",
        (ubyte *) "00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
        (ubyte *) "00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
    };

    int errorCount = 0;
    ubyte *pMsg = (ubyte *) "sample";

    int i, j;
    /* each iteration should build a complete test with those 12 variables */
    ubyte *ptr = NULL;
    int size = 6 * 25;
    /*
     * Each test is formatted:
     *      private key
     *      public x value
     *      public y value
     *      k value used when signing
     *      expected r value
     *      expected s value
     */
    for (i = 0; i < size; i += 6)
    {
        KVT_ecdsa singleTest;
        /* private key */
        singleTest.privKeyLen = (ubyte4) hexs2bin((const char *) data[i], &ptr);
        DIGI_MEMCPY(singleTest.pPrivKey, ptr, singleTest.privKeyLen);

        DIGI_FREE((void **) &ptr);
        /* x value of public key */
        singleTest.pubXLen = (ubyte4) hexs2bin((const char *) data[i + 1],
                                               &ptr);
        DIGI_MEMCPY(singleTest.pPubX, ptr, singleTest.pubXLen);

        DIGI_FREE((void **) &ptr);

        /* y value of public key */
        singleTest.pubYLen = (ubyte4) hexs2bin((const char *) data[i + 2],
                                               &ptr);
        DIGI_MEMCPY(singleTest.pPubY, ptr, singleTest.pubYLen);

        DIGI_FREE((void **) &ptr);

        /* k value of used to sign */
        singleTest.kValueLen = (ubyte4) hexs2bin((const char *) data[i + 3],
                                                 &ptr);
        DIGI_MEMCPY(singleTest.pKValue, ptr, singleTest.kValueLen);

        /* subtract one from each k to compensate for ecc keygen later adding one */
        
        
        /* The ECC code adds 1 to the raw result of the RNG, so subtract one here
           start with the last byte. */
        j = singleTest.kValueLen - 1;
        singleTest.pKValue[j]--;
        
        /* keep borrowing if needbe */
        while (0xFF == singleTest.pKValue[j] && j > 0)
        {
            j--;
            singleTest.pKValue[j]--;
        }
        
        DIGI_FREE((void **) &ptr);
        /* r value of signature */
        singleTest.rValLen = (ubyte4) hexs2bin((const char *) data[i + 4],
                                               &ptr);
        DIGI_MEMCPY(singleTest.pRVal, ptr, singleTest.rValLen);

        DIGI_FREE((void **) &ptr);
        /* s value of signature */
        singleTest.sValLen = (ubyte4) hexs2bin((const char *) data[i + 5],
                                               &ptr);
        DIGI_MEMCPY(singleTest.pSVal, ptr, singleTest.sValLen);

        DIGI_FREE((void **) &ptr);

        /* copy str over */
        singleTest.msgLen = DIGI_STRLEN((const sbyte *) pMsg);
            DIGI_MEMCPY(singleTest.pMsg, pMsg, singleTest.msgLen);

        /* first 30 tests use p192, nexts 30 use p224, etc. */
        if (0 == i)
            singleTest.curveId = cid_EC_P192;
        else if (30 == i)
            singleTest.curveId = cid_EC_P224;
        else if (60 == i)
            singleTest.curveId = cid_EC_P256;
        else if (90 == i)
            singleTest.curveId = cid_EC_P384;
        else if (120 == i)
            singleTest.curveId = cid_EC_P521;

        /*
         * Since each test is 6 lines long, i/6 gives you the test number.
         * first test is sha1, second is sha224, etc.
         * tests ordered like this:
         *
         * p192 sha1
         * p192 sha224
         * p192 sha256
         * p192 sha384
         * p192 sha512
         * p224 sha1
         * p224 sha224
         * p224 sha256
         * p224 sha384
         * p224 sha512
         * ...
         * p521 sha512*/

        switch ((i / 6) % 5)
        {
            case 0:
                singleTest.hashAlgo = ht_sha1;
                break;
            case 1:
                singleTest.hashAlgo = ht_sha224;
                break;
            case 2:
                singleTest.hashAlgo = ht_sha256;
                break;
            case 3:
                singleTest.hashAlgo = ht_sha384;
                break;
            case 4:
                singleTest.hashAlgo = ht_sha512;
                break;
            default:
                return 1;
        }


        /* point the global pointers to the correct K buffer, and the
         * correct length so that our custom random function can use the
         * value. If this is not set, TESTRAND_rngFun won't have correct
         * k value for sign step of test */
        gpKValue = singleTest.pKValue;
        gKValueLen = singleTest.kValueLen;

        /* the tests are enumerated in the array about inside this function */
        if (testKnownVectors(singleTest))
        {
            printf("test %d failed\n", (i/6) + 1);
            errorCount = (errorCount + 1);
        }

    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

/* custom random function that isn't random, it provies buffer
 * with the correct K value for known vector tests. */
sbyte4 TESTRAND_rngFun(void *rngFunArg, ubyte4 length, ubyte *buffer)
{

    ubyte4 kLength = gKValueLen;
    ubyte4 i;

    if (length < kLength)
    {
        return ERR_RAND;
    }
    for (i = 0; i < kLength; ++i)
    {
        buffer[kLength - i - 1] = gpKValue[i];
    }

    return OK;
}


/*----------------------------------------------------------------------------*/

int hashStr(ubyte *pMsg,
            ubyte4 msgLen,
            ubyte **ppDigest,
            ubyte4 *pDigestLen,
            ubyte hashAlgo)
{
    MSTATUS status = ERR_NULL_POINTER;
    BulkHashAlgo *pHashAlgo = NULL;
    BulkCtx pCtx = NULL;

    status = CRYPTO_getECCHashAlgo(hashAlgo, &pHashAlgo);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    *pDigestLen = pHashAlgo->digestSize;

    status = DIGI_MALLOC((void **) ppDigest, (ubyte4) *pDigestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = pHashAlgo->allocFunc(&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = pHashAlgo->initFunc(pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = pHashAlgo->updateFunc(pCtx, (const ubyte *)pMsg, msgLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = pHashAlgo->finalFunc(pCtx, *ppDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if ( (NULL != pCtx) && (NULL != pHashAlgo) )
    {
        pHashAlgo->freeFunc(&pCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

int testKnownVectors(KVT_ecdsa knownVector)
{
    MSTATUS status = ERR_NULL_POINTER;

    ECCKey *pKey = NULL;
    sbyte4 cmpRes = 667, elemLen;
    ubyte signature[150];
    ubyte *pSignature = signature;
    ubyte4 signatureLen =
        knownVector.pubXLen + knownVector.pubYLen;

    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;

    ubyte *pPoint = NULL;
    ubyte4 pointLen = knownVector.pubXLen
                      + knownVector.pubYLen + 1;
    status = DIGI_MALLOC((void **) &pPoint, pointLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }
    /* first byte of point buffer is always a compression byte with
     * a value of 4 */
    pPoint[0] = 0x04;

    status = DIGI_MEMCPY(pPoint + 1, (const void *) knownVector.pPubX,
                        knownVector.pubXLen);

    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* */
    status = DIGI_MEMCPY(
        pPoint + 1 + knownVector.pubXLen,
        (const void *) knownVector.pPubY,
        knownVector.pubYLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = EC_newKeyEx(knownVector.curveId, &pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* size of an element */
    status = EC_getElementByteStringLen(pKey, &elemLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = EC_setKeyParameters(pKey, pPoint, pointLen,
                                 knownVector.pPrivKey,
                                 knownVector.privKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* UNITTEST_STATUS was called in hashStr, just forward status */
    status = hashStr((ubyte *) knownVector.pMsg,
                     knownVector.msgLen, &pDigest, &digestLen,
                     knownVector.hashAlgo);
    if (OK != status)
    {
        goto exit;
    }

    status = ECDSA_signDigest(
        pKey,
        TESTRAND_rngFun,
        g_pRandomContext,
        pDigest,
        digestLen,
        pSignature,
        signatureLen,
        &signatureLen
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    signatureLen = signatureLen / 2;
    status = ECDSA_verifySignatureDigest(
        pKey,
        pDigest,
        digestLen,
        pSignature,
        signatureLen,
        pSignature + signatureLen,
        signatureLen,
        &cmpRes
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    cmpRes = 667;
    status = DIGI_MEMCMP(knownVector.pRVal, pSignature,
                        knownVector.rValLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    cmpRes = 667;

    status = DIGI_MEMCMP(knownVector.pSVal,
                        pSignature + knownVector.rValLen,
                        knownVector.sValLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    /* pSignature in this function points to a buffer on stack.
     * Calling free on it will result in memory corruption.
     */
    pSignature = NULL;

    if(NULL != pDigest)
    {
        DIGI_FREE((void**)&pDigest);
    }
    if(NULL != pPoint)
    {
        DIGI_FREE((void**)&pPoint);
    }

    EC_deleteKey(&pKey);
    if (OK != status)
        return 1;
    return cmpRes;
}


/*----------------------------------------------------------------------------*/

int testGenKeyAlloc(ubyte4 curveId)
{
    MSTATUS status = ERR_NULL_POINTER;

    ECCKey *pKey = NULL;
    ubyte4 otherCurveId;
    ubyte4 verifyRes = 667;

    ubyte *pHash = (ubyte *) "123456781234567812345678";
    ubyte4 hashLen = DIGI_STRLEN((const sbyte *) pHash);

    ubyte *pSignature = NULL;
    ubyte4 signatureLen = 667; /* will write size of signature here */

    status = EC_generateKeyPairAlloc(
        curveId,
        &pKey,
        RANDOM_rngFun,
        g_pRandomContext
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = EC_getCurveIdFromKey(pKey, &otherCurveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (curveId != otherCurveId)
    {
        status = ERR_CRYPTO;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }



    status = EC_getElementByteStringLen(pKey, (sbyte4 *) &signatureLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (667 == signatureLen)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    signatureLen = signatureLen * 2;


    status = DIGI_MALLOC((void **) &pSignature, signatureLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = ECDSA_signDigest(
        pKey,
        RANDOM_rngFun,
        g_pRandomContext,
        pHash,
        hashLen,
        pSignature,
        signatureLen,
        &signatureLen
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    signatureLen = signatureLen / 2;
    status = ECDSA_verifySignatureDigest(
        pKey,
        pHash,
        hashLen,
        pSignature,
        signatureLen,
        pSignature + signatureLen,
        signatureLen,
        &verifyRes
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != verifyRes)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
exit:
    if(NULL != pSignature)
    {
        DIGI_FREE(&pSignature);
    }

    EC_deleteKey(&pKey);
    if (OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

int testNewKeyWithGenKey(ubyte4 curveId)
{
    MSTATUS status = ERR_NULL_POINTER;

    ECCKey *pKey = NULL;
    ubyte4 otherCurveId = 0;
    ubyte4 verifyRes = 667;
    ubyte *pHash = (ubyte *) "123456781234567812345678";
    ubyte4 hashLen = DIGI_STRLEN((const sbyte *) pHash);

    ubyte *pSignature = NULL;
    ubyte4 signatureLen = 667; /* will write size of signature here */

    status = EC_newKeyEx(curveId, &pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = EC_getCurveIdFromKey(pKey, &otherCurveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (curveId != otherCurveId)
    {
        status = ERR_CRYPTO;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = EC_generateKeyPairEx(pKey, RANDOM_rngFun, g_pRandomContext);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* gets length of a single element and stores it in signatureLen */
    status = EC_getElementByteStringLen(pKey, (sbyte4 *) &signatureLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }


    if (667 == signatureLen)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* size of signature is twice the length of a single element */
    signatureLen = signatureLen * 2;

    status = DIGI_MALLOC((void **) &pSignature, signatureLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = ECDSA_signDigest(
        pKey,
        RANDOM_rngFun,
        g_pRandomContext,
        pHash,
        hashLen,
        pSignature,
        signatureLen,
        &signatureLen
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* verifySignatureDigest splits R and S, so we have to cut length in half */
    signatureLen = signatureLen / 2;
    status = ECDSA_verifySignatureDigest(
        pKey,
        pHash,
        hashLen,
        pSignature,
        signatureLen,
        pSignature + signatureLen,
        signatureLen,
        &verifyRes
    );
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != verifyRes)
    {
        status = ERR_CRYPTO_FAILURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if(NULL != pSignature)
    {
        DIGI_FREE((void**)&pSignature);
    }

    EC_deleteKey(&pKey);

    if (OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

int moc_ecc_wrapper_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;


    InitMocanaSetupInfo setupInfo = {};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

    errorCount = (errorCount + runKnownVectorTests());

    errorCount = (errorCount + testNewKeyWithGenKey(cid_EC_P192));
    errorCount = (errorCount + testNewKeyWithGenKey(cid_EC_P224));
    errorCount = (errorCount + testNewKeyWithGenKey(cid_EC_P256));
    errorCount = (errorCount + testNewKeyWithGenKey(cid_EC_P384));
    errorCount = (errorCount + testNewKeyWithGenKey(cid_EC_P521));

    errorCount = (errorCount + testGenKeyAlloc(cid_EC_P192));
    errorCount = (errorCount + testGenKeyAlloc(cid_EC_P224));
    errorCount = (errorCount + testGenKeyAlloc(cid_EC_P256));
    errorCount = (errorCount + testGenKeyAlloc(cid_EC_P384));
    errorCount = (errorCount + testGenKeyAlloc(cid_EC_P521));

exit:
    DIGICERT_free(&gpMocCtx);
    return errorCount;
}

