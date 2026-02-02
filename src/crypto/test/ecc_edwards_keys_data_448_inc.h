/* Test vectors for edECC Keys on curve448 */

static TestVector gTestVectorDH_p448[] =
{
    {   /* 0 private key ok as it is pruned to 2^447 */
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5d40",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0,
        generateKey
    },
    {
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0,
        generateKey
    },
    {   /* same key as above, different pruning */
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        0,
        generateKey
    },
    {
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b6517399ad",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b6517399ad",
        0,
        generateKey
    },
    {
        "fa7ccabd97887646bfcebb12b966ccdc369ef4b679f5c4b42cd44ff47ac0c4e7ab4aeb86228960576cd2110eff7ad26ea526ebee0b814e28",
        "d0c46b3f31536f3a96961aee8b020a7b7feb9035335403d6077ab612cf962a2559247c8c1bbcd9da33f3d663ec5e25c9561150455349f14b",
        "fa7ccabd97887646bfcebb12b966ccdc369ef4b679f5c4b42cd44ff47ac0c4e7ab4aeb86228960576cd2110eff7ad26ea526ebee0b814e28",
        0,
        generateKey
    },
    {   /* private keys */
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5d40",
        NULL,
        0,
        getSetMethods
    },
    {
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        0,
        getSetMethods
    },
    {
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        0,
        getSetMethods
    },
    {
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b6517399ad",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        NULL,
        0,
        getSetMethods
    },
    {
        "fa7ccabd97887646bfcebb12b966ccdc369ef4b679f5c4b42cd44ff47ac0c4e7ab4aeb86228960576cd2110eff7ad26ea526ebee0b814e28",
        "d0c46b3f31536f3a96961aee8b020a7b7feb9035335403d6077ab612cf962a2559247c8c1bbcd9da33f3d663ec5e25c9561150455349f14b",
        NULL,
        0,
        getSetMethods
    },
    {   /* public keys */
        NULL,
        "e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5d40",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "d0c46b3f31536f3a96961aee8b020a7b7feb9035335403d6077ab612cf962a2559247c8c1bbcd9da33f3d663ec5e25c9561150455349f14b",
        NULL,
        0,
        getSetMethods
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5d40",
        NULL,
        0,
        validateKey
    },
    {
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        0,
        validateKey
    },
    {
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        0,
        validateKey
    },
    {
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b6517399ad",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        NULL,
        0,
        validateKey
    },
    {
        "fa7ccabd97887646bfcebb12b966ccdc369ef4b679f5c4b42cd44ff47ac0c4e7ab4aeb86228960576cd2110eff7ad26ea526ebee0b814e28",
        "d0c46b3f31536f3a96961aee8b020a7b7feb9035335403d6077ab612cf962a2559247c8c1bbcd9da33f3d663ec5e25c9561150455349f14b",
        NULL,
        0,
        validateKey
    },
    {   /* public value differs by high bit only */
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5dc0",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {    /* public value differs by low bit only */
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "3e482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {   /* public value correct if pruning didn't occur */
        "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "2eab1d0af5d77abe2647cd6dd3a62e0170b5289085194fc664c48eca2994b2210b06a8fa3ca7291abd2d5376c59d17396e1e5e60f1bb2620",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {   /* public value differs by high bit only */
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b6517399ad",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33689",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {   /* public value (u) is not even on the curve */
        "fa7ccabd97887646bfcebb12b966ccdc369ef4b679f5c4b42cd44ff47ac0c4e7ab4aeb86228960576cd2110eff7ad26ea526ebee0b814e28",
        "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    }
};

static TestVector gTestVectorDSA_p448[] =
{
    {
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        0,
        generateKey
    },
    {
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        0,
        generateKey
    },
    {
        "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        0,
        generateKey
    },
    {                                     /* vector index 3 */
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        0,
        generateKey
    },
    {
        "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        0,
        generateKey
    },
    {
        "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        0,
        generateKey
    },
    {
        "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        0,
        generateKey
    },
    {
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        0,
        generateKey
    },
    { /* private keys */
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        NULL,
        0,
        getSetMethods
    },
    {
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        NULL,
        0,
        getSetMethods
    },
    {
        "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        NULL,
        0,
        getSetMethods
    },
    {
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        NULL,
        0,
        getSetMethods
    },
    {
        "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        NULL,
        0,
        getSetMethods
    },
    {                                      /* vector index 13 */
        "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        NULL,
        0,
        getSetMethods
    },
    {
        "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        NULL,
        0,
        getSetMethods
    },
    {
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        NULL,
        0,
        getSetMethods
    },
    { /* public keys */
        NULL,
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        NULL,
        0,
        getSetMethods
    },
    {
        NULL,
        "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        NULL,
        0,
        getSetMethods
    },
    {                                      /* vector index 23 */
        NULL,
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        NULL,
        0,
        getSetMethods
    },
    { /* private keys */
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        NULL,
        0,
        validateKey
    },
    {
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        NULL,
        0,
        validateKey
    },
    {
        "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        NULL,
        0,
        validateKey
    },
    {
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        NULL,
        0,
        validateKey
    },
    {
        "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        NULL,
        0,
        validateKey
    },
    {
        "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        NULL,
        0,
        validateKey
    },
    {
        "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        NULL,
        0,
        validateKey
    },
    {
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        NULL,
        0,
        validateKey
    },
    { /* public keys */
        NULL,
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        NULL,
        0,
        validateKey
    },
    {                                       /* vector index 33 */
        NULL,
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        NULL,
        0,
        validateKey
    },
    {
        NULL,
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        NULL,
        0,
        validateKey
    },
    { /* changed private key */
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95c",
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* changed public key */
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274f",
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* changed just the x-bit of the public key */
        "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001480",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key not on curve */            /* vector index 43 */
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        "dc9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081c00",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key not a field element, p */
        "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key > p (due to invalid last byte) */
        "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f01",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key (0,1) but invalid x-bit encoding */
        "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    {  /* public key (0,-1) but invalid x-bit encoding */
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        "FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key not on curve */
        NULL,
        "dc9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081c00",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key = p */
        NULL,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key > p */
        NULL,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key > p (due to invalid last byte) */
        NULL,
        "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081fff",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key (0,1) but invalid x-bit encoding */
        NULL,
        "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    },
    { /* public key (0,-1) but invalid x-bit encoding */  /* vector index 53 */
        NULL,
        "FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80",
        NULL,
        (ubyte4) ERR_FALSE,
        validateKey
    }
};
