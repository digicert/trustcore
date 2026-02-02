/* Test vectors for edECC Keys on curve25519 */

static TestVector gTestVectorDH_p25519[] =
{
    {   /* 0 private key ok as it is pruned to 2^254 */
        "0000000000000000000000000000000000000000000000000000000000000000",
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        generateKey
    },
    {
        "0900000000000000000000000000000000000000000000000000000000000000",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        "0900000000000000000000000000000000000000000000000000000000000000",
        0,
        generateKey
    },
    {   /* same key as above, different pruning */
        "0F000000000000000000000000000000000000000000000000000000000000c0",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        "0F000000000000000000000000000000000000000000000000000000000000c0",
        0,
        generateKey
    },
    {
        "43535399d981004b2099f848f219a306930ec563348003795160b013a783769d",
        "6ad1bd33cb31ee92ce7a22d557394d884eabe98b8356b4061e00d1693c7a0c35",
        "43535399d981004b2099f848f219a306930ec563348003795160b013a783769d",
        0,
        generateKey
    },
    {
        "5314c9160bbae790d4699b77da7eef15927a4d96643ce862e00054fddc4d9918",
        "8f572a5a7029c9e0747558a7cc92a64cd9af9c49a279e43a41cebe2208b1e76b",
        "5314c9160bbae790d4699b77da7eef15927a4d96643ce862e00054fddc4d9918",
        0,
        generateKey
    },
    {   /* private keys */
        "0000000000000000000000000000000000000000000000000000000000000000",
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
        NULL,
        0,
        getSetMethods
    },
    {
        "0900000000000000000000000000000000000000000000000000000000000000",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        0,
        getSetMethods
    },
    {
        "0F000000000000000000000000000000000000000000000000000000000000c0",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        0,
        getSetMethods
    },
    {
        "43535399d981004b2099f848f219a306930ec563348003795160b013a783769d",
        "6ad1bd33cb31ee92ce7a22d557394d884eabe98b8356b4061e00d1693c7a0c35",
        NULL,
        0,
        getSetMethods
    },
    {
        "5314c9160bbae790d4699b77da7eef15927a4d96643ce862e00054fddc4d9918",
        "8f572a5a7029c9e0747558a7cc92a64cd9af9c49a279e43a41cebe2208b1e76b",
        NULL,
        0,
        getSetMethods
    },
    {   /* public keys */
        NULL,
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "6ad1bd33cb31ee92ce7a22d557394d884eabe98b8356b4061e00d1693c7a0c35",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "8f572a5a7029c9e0747558a7cc92a64cd9af9c49a279e43a41cebe2208b1e76b",
        NULL,
        0,
        getSetMethods
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
        NULL,
        0,
        validateKey
    },
    {
        "0900000000000000000000000000000000000000000000000000000000000000",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        0,
        validateKey
    },
    {
        "0F000000000000000000000000000000000000000000000000000000000000c0",
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        0,
        validateKey
    },
    {
        "43535399d981004b2099f848f219a306930ec563348003795160b013a783769d",
        "6ad1bd33cb31ee92ce7a22d557394d884eabe98b8356b4061e00d1693c7a0c35",
        NULL,
        0,
        validateKey
    },
    {
        "5314c9160bbae790d4699b77da7eef15927a4d96643ce862e00054fddc4d9918",
        "8f572a5a7029c9e0747558a7cc92a64cd9af9c49a279e43a41cebe2208b1e76b",
        NULL,
        0,
        validateKey
    },
    {   /* public value differs by high bit only */
        "0000000000000000000000000000000000000000000000000000000000000000",
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3bF4",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {    /* public value differs by low bit only */
        "0900000000000000000000000000000000000000000000000000000000000000",
        "432c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {   /* public value correct if pruning didn't occur */
        "0f000000000000000000000000000000000000000000000000000000000000c0",
        "be3302bde5732e6b39a0491c3501685dd54e1c4691b8c5bad447d630b7c1ac39",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {   /* public value differs by high bit only */
        "43535399d981004b2099f848f219a306930ec563348003795160b013a783769d",
        "6ad1bd33cb31ee92ce7a22d557394d884eabe98b8356b4061e00d1693c7a0cb5",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {
        "5314c9160bbae790d4699b77da7eef15927a4d96643ce862e00054fddc4d9918",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    }
};


static TestVector gTestVectorDSA_p25519[] =
{
    {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        0,
        generateKey
    },
    {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        0,
        generateKey
    },
    {
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        0,
        generateKey
    },
    {
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        0,
        generateKey
    },
    {
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        0,
        generateKey
    },
    { /* private keys */
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL,
        0,
        getSetMethods
    },
    {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        NULL,
        0,
        getSetMethods
    },
    {
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        0,
        getSetMethods
    },
    {
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        NULL,
        0,
        getSetMethods
    },
    {
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        NULL,
        0,
        getSetMethods
    },
    { /* public keys */        /* vector index 10 */
        NULL,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        NULL,
        0,
        getSetMethods
    },
    { /* private keys */
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL,
        0,
        validateKey
    },
    {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        NULL,
        0,
        validateKey
    },
    {
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        0,
        validateKey
    },
    {
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        NULL,
        0,
        validateKey
    },
    {
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        NULL,
        0,
        validateKey
    },
    { /* public keys */      /* vector index 20 */
        NULL,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        NULL,
        0,
        validateKey
    },
    { /* changed private key */
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f6f",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* changed public key */
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "2d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* x-bit only change in public key */
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb9115489080a5",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key not on curve */
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "f851cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key not a field element, p */  /* vector index 70 */
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* not on curve */          /* vector index 30 */
        NULL,
        "f851cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* not a field element, p */
        NULL,
        "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* not a field element, > p */
        NULL,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key representing (0,1) but invalid encoding for the x bit */
        NULL,
        "0100000000000000000000000000000000000000000000000000000000000080",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key representing (0,-1) but invalid encoding for the x bit */
        NULL,
        "ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    }
};
