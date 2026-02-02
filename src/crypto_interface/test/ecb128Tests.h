#ifndef __DIGICERT_ECB_128_TESTS__
#define __DIGICERT_ECB_128_TESTS__

typedef struct aesTest{
    ubyte *pKey;
    ubyte *pPlain;
    ubyte *pCipher;
} aesTest;

static aesTest gpEcb128Tests[] =
{
    {
        .pKey    = (ubyte*) "80000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "0edd33d3c621e546455bd8ba1418bec8",
    },
    {
        .pKey    = (ubyte*) "c0000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "4bc3f883450c113c64ca42e1112a9e87",
    },
    {
        .pKey    = (ubyte*) "e0000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "72a1da770f5d7ac4c9ef94d822affd97",
    },
    {
        .pKey    = (ubyte*) "f0000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "970014d634e2b7650777e8e84d03ccd8",
    },
    {
        .pKey    = (ubyte*) "f8000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f17e79aed0db7e279e955b5f493875a7",
    },
    {
        .pKey    = (ubyte*) "fc000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9ed5a75136a940d0963da379db4af26a",
    },
    {
        .pKey    = (ubyte*) "fe000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "c4295f83465c7755e8fa364bac6a7ea5",
    },
    {
        .pKey    = (ubyte*) "ff000000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b1d758256b28fd850ad4944208cf1155",
    },
    {
        .pKey    = (ubyte*) "ff800000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "42ffb34c743de4d88ca38011c990890b",
    },
    {
        .pKey    = (ubyte*) "ffc00000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9958f0ecea8b2172c0c1995f9182c0f3",
    },
    {
        .pKey    = (ubyte*) "ffe00000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "956d7798fac20f82a8823f984d06f7f5",
    },
    {
        .pKey    = (ubyte*) "fff00000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "a01bf44f2d16be928ca44aaf7b9b106b",
    },
    {
        .pKey    = (ubyte*) "fff80000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b5f1a33e50d40d103764c76bd4c6b6f8",
    },
    {
        .pKey    = (ubyte*) "fffc0000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "2637050c9fc0d4817e2d69de878aee8d",
    },
    {
        .pKey    = (ubyte*) "fffe0000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "113ecbe4a453269a0dd26069467fb5b5",
    },
    {
        .pKey    = (ubyte*) "ffff0000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "97d0754fe68f11b9e375d070a608c884",
    },
    {
        .pKey    = (ubyte*) "ffff8000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "c6a0b3e998d05068a5399778405200b4",
    },
    {
        .pKey    = (ubyte*) "ffffc000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "df556a33438db87bc41b1752c55e5e49",
    },
    {
        .pKey    = (ubyte*) "ffffe000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "90fb128d3a1af6e548521bb962bf1f05",
    },
    {
        .pKey    = (ubyte*) "fffff000000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "26298e9c1db517c215fadfb7d2a8d691",
    },
    {
        .pKey    = (ubyte*) "fffff800000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "a6cb761d61f8292d0df393a279ad0380",
    },
    {
        .pKey    = (ubyte*) "fffffc00000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "12acd89b13cd5f8726e34d44fd486108",
    },
    {
        .pKey    = (ubyte*) "fffffe00000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "95b1703fc57ba09fe0c3580febdd7ed4",
    },
    {
        .pKey    = (ubyte*) "ffffff00000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "de11722d893e9f9121c381becc1da59a",
    },
    {
        .pKey    = (ubyte*) "ffffff80000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "6d114ccb27bf391012e8974c546d9bf2",
    },
    {
        .pKey    = (ubyte*) "ffffffc0000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "5ce37e17eb4646ecfac29b9cc38d9340",
    },
    {
        .pKey    = (ubyte*) "ffffffe0000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "18c1b6e2157122056d0243d8a165cddb",
    },
    {
        .pKey    = (ubyte*) "fffffff0000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "99693e6a59d1366c74d823562d7e1431",
    },
    {
        .pKey    = (ubyte*) "fffffff8000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "6c7c64dc84a8bba758ed17eb025a57e3",
    },
    {
        .pKey    = (ubyte*) "fffffffc000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "e17bc79f30eaab2fac2cbbe3458d687a",
    },
    {
        .pKey    = (ubyte*) "fffffffe000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "1114bc2028009b923f0b01915ce5e7c4",
    },
    {
        .pKey    = (ubyte*) "ffffffff000000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9c28524a16a1e1c1452971caa8d13476",
    },
    {
        .pKey    = (ubyte*) "ffffffff800000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ed62e16363638360fdd6ad62112794f0",
    },
    {
        .pKey    = (ubyte*) "ffffffffc00000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "5a8688f0b2a2c16224c161658ffd4044",
    },
    {
        .pKey    = (ubyte*) "ffffffffe00000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "23f710842b9bb9c32f26648c786807ca",
    },
    {
        .pKey    = (ubyte*) "fffffffff00000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "44a98bf11e163f632c47ec6a49683a89",
    },
    {
        .pKey    = (ubyte*) "fffffffff80000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "0f18aff94274696d9b61848bd50ac5e5",
    },
    {
        .pKey    = (ubyte*) "fffffffffc0000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "82408571c3e2424540207f833b6dda69",
    },
    {
        .pKey    = (ubyte*) "fffffffffe0000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "303ff996947f0c7d1f43c8f3027b9b75",
    },
    {
        .pKey    = (ubyte*) "ffffffffff0000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "7df4daf4ad29a3615a9b6ece5c99518a",
    },
    {
        .pKey    = (ubyte*) "ffffffffff8000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "c72954a48d0774db0b4971c526260415",
    },
    {
        .pKey    = (ubyte*) "ffffffffffc000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "1df9b76112dc6531e07d2cfda04411f0",
    },
    {
        .pKey    = (ubyte*) "ffffffffffe000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "8e4d8e699119e1fc87545a647fb1d34f",
    },
    {
        .pKey    = (ubyte*) "fffffffffff000000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "e6c4807ae11f36f091c57d9fb68548d1",
    },
    {
        .pKey    = (ubyte*) "fffffffffff800000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "8ebf73aad49c82007f77a5c1ccec6ab4",
    },
    {
        .pKey    = (ubyte*) "fffffffffffc00000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "4fb288cc2040049001d2c7585ad123fc",
    },
    {
        .pKey    = (ubyte*) "fffffffffffe00000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "04497110efb9dceb13e2b13fb4465564",
    },
    {
        .pKey    = (ubyte*) "ffffffffffff00000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "75550e6cb5a88e49634c9ab69eda0430",
    },
    {
        .pKey    = (ubyte*) "ffffffffffff80000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b6768473ce9843ea66a81405dd50b345",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffc0000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "cb2f430383f9084e03a653571e065de6",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffe0000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ff4e66c07bae3e79fb7d210847a3b0ba",
    },
    {
        .pKey    = (ubyte*) "fffffffffffff0000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "7b90785125505fad59b13c186dd66ce3",
    },
    {
        .pKey    = (ubyte*) "fffffffffffff8000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "8b527a6aebdaec9eaef8eda2cb7783e5",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffc000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "43fdaf53ebbc9880c228617d6a9b548b",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffe000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "53786104b9744b98f052c46f1c850d0b",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffff000000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b5ab3013dd1e61df06cbaf34ca2aee78",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffff800000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "7470469be9723030fdcc73a8cd4fbb10",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffc00000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "a35a63f5343ebe9ef8167bcb48ad122e",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffe00000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "fd8687f0757a210e9fdf181204c30863",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffff00000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "7a181e84bd5457d26a88fbae96018fb0",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffff80000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "653317b9362b6f9b9e1a580e68d494b5",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffc0000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "995c9dc0b689f03c45867b5faa5c18d1",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffe0000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "77a4d96d56dda398b9aabecfc75729fd",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffff0000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "84be19e053635f09f2665e7bae85b42d",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffff8000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "32cd652842926aea4aa6137bb2be2b5e",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffc000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "493d4a4f38ebb337d10aa84e9171a554",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffe000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "d9bff7ff454b0ec5a4a2a69566e2cb84",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffff000000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "3535d565ace3f31eb249ba2cc6765d7a",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffff800000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f60e91fc3269eecf3231c6e9945697c6",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffc00000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ab69cfadf51f8e604d9cc37182f6635a",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffe00000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "7866373f24a0b6ed56e0d96fcdafb877",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffff00000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "1ea448c2aac954f5d812e9d78494446a",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffff80000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "acc5599dd8ac02239a0fef4a36dd1668",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffc0000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "d8764468bb103828cf7e1473ce895073",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffe0000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "1b0d02893683b9f180458e4aa6b73982",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffff0000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "96d9b017d302df410a937dcdb8bb6e43",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffff8000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ef1623cc44313cff440b1594a7e21cc6",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffc000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "284ca2fa35807b8b0ae4d19e11d7dbd7",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffe000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f2e976875755f9401d54f36e2a23a594",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffff000000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ec198a18e10e532403b7e20887c8dd80",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffff800000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "545d50ebd919e4a6949d96ad47e46a80",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffc00000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "dbdfb527060e0a71009c7bb0c68f1d44",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffe00000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9cfa1322ea33da2173a024f2ff0d896d",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffff00000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "8785b1a75b0f3bd958dcd0e29318c521",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffff80000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "38f67b9e98e4a97b6df030a9fcdd0104",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffc0000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "192afffb2c880e82b05926d0fc6c448b",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffe0000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "6a7980ce7b105cf530952d74daaf798c",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffff0000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ea3695e1351b9d6858bd958cf513ef6c",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffff8000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "6da0490ba0ba0343b935681d2cce5ba1",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffc000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f0ea23af08534011c60009ab29ada2f1",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffe000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ff13806cf19cc38721554d7c0fcdcd4b",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffff000000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "6838af1f4f69bae9d85dd188dcdf0688",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffff800000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "36cf44c92d550bfb1ed28ef583ddf5d7",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffc00000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "d06e3195b5376f109d5c4ec6c5d62ced",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffe00000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "c440de014d3d610707279b13242a5c36",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffff00000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f0c5c6ffa5e0bd3a94c88f6b6f7c16b9",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffff80000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "3e40c3901cd7effc22bffc35dee0b4d9",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffc0000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b63305c72bedfab97382c406d0c49bc6",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffe0000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "36bbaab22a6bd4925a99a2b408d2dbae",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffff0000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "307c5b8fcd0533ab98bc51e27a6ce461",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffff8000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "829c04ff4c07513c0b3ef05c03e337b5",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffc000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "f17af0e895dda5eb98efc68066e84c54",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffe000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "277167f3812afff1ffacb4a934379fc3",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffff000000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "2cb1dc3a9c72972e425ae2ef3eb597cd",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffff800000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "36aeaa3a213e968d4b5b679d3a2c97fe",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffc00000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9241daca4fdd034a82372db50e1a0f3f",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffe00000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "c14574d9cd00cf2b5a7f77e53cd57885",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffff00000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "793de39236570aba83ab9b737cb521c9",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffff80000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "16591c0f27d60e29b85a96c33861a7ef",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffc0000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "44fb5c4d4f5cb79be5c174a3b1c97348",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffe0000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "674d2b61633d162be59dde04222f4740",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffff0000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "b4750ff263a65e1f9e924ccfd98f3e37",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffff8000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "62d0662d6eaeddedebae7f7ea3a4f6b6",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffc000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "70c46bb30692be657f7eaa93ebad9897",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffe000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "323994cfb9da285a5d9642e1759b224a",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffff000",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "1dbf57877b7b17385c85d0b54851e371",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffff800",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "dfa5c097cdc1532ac071d57b1d28d1bd",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffc00",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "3a0c53fa37311fc10bd2a9981f513174",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffe00",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "ba4f970c0a25c41814bdae2e506be3b4",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffff00",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "2dce3acb727cd13ccd76d425ea56e4f6",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffff80",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "5160474d504b9b3eefb68d35f245f4b3",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffffc0",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "41a8a947766635dec37553d9a6c0cbb7",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffffe0",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "25d6cfe6881f2bf497dd14cd4ddf445b",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffff0",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "41c78c135ed9e98c096640647265da1e",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffff8",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "5a4d404d8917e353e92a21072c3b2305",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffffc",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "02bc96846b3fdc71643f384cd3cc3eaf",
    },
    {
        .pKey    = (ubyte*) "fffffffffffffffffffffffffffffffe",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "9ba4a9143f4e5d4048521c4f8877d88e",
    },
    {
        .pKey    = (ubyte*) "ffffffffffffffffffffffffffffffff",
        .pPlain  = (ubyte*) "00000000000000000000000000000000",
        .pCipher = (ubyte*) "a1f6258c877d5fcd8964484538bfc92c",
    }
};
#endif /* __DIGICERT_ECB_128_TESTS__ */

