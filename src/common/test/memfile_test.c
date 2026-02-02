/*
 *  memfile_test.c
 *  dsf
 *
 *  Created by Fabrice Ferino on 2/10/16.
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../memfile.c"

#include "../../../unit_tests/unittest.h"

static const char* kSampleData =
"Gallia est omnis divisa in partes tres, quarum unam incolunt Belgae, "
"aliam Aquitani, tertiam qui ipsorum lingua Celtae, nostra Galli appellantur."
"Hi omnes lingua, institutis, legibus inter se differunt. Gallos ab Aquitanis "
"Garumna flumen, a Belgis Matrona et Sequana dividit. Horum omnium "
"fortissimi sunt Belgae, propterea quod a cultu atque humanitate provinciae "
"longissime absunt, minimeque ad eos mercatores saepe commeant atque ea quae "
"ad effeminandos animos pertinent important, proximique sunt Germanis, "
"qui trans Rhenum incolunt, quibuscum continenter bellum gerunt. Qua de causa "
"Helvetii quoque reliquos Gallos virtute praecedunt, quod fere cotidianis "
"proeliis cum Germanis contendunt, cum aut suis finibus eos prohibent aut "
"ipsi in eorum finibus bellum gerunt. Eorum una, pars, quam Gallos obtinere "
"dictum est, initium capit a flumine Rhodano, continetur Garumna flumine, "
"Oceano, finibus Belgarum, attingit etiam ab Sequanis et Helvetiis flumen "
"Rhenum, vergit ad septentriones. Belgae ab extremis Galliae finibus "
"oriuntur, pertinent ad inferiorem partem fluminis Rheni, spectant in "
"septentrionem et orientem solem. Aquitania a Garumna flumine ad Pyrenaeos "
"montes et eam partem Oceani quae est ad Hispaniam pertinet; spectat inter "
"occasum solis et septentriones.";


int memfile_test_read()
{
    MemFile mf;
    int retVal = 0;
    int textLen = DIGI_STRLEN((sbyte*)kSampleData);
    int numRead;
    sbyte4 cmpRes;
    char* readBuffer;
    int i, numBlocks;

    readBuffer = (char*) MALLOC(textLen+10);
    if (0 == readBuffer)
    {
        retVal += UNITTEST_TRUE(0, readBuffer!=0);
        goto exit;
    }

    UNITTEST_STATUS_GOTO(0, MF_attach(&mf, textLen+1, (ubyte*) kSampleData),
                         retVal, exit);

    /* read textLen+1 bytes */
    numRead = MF_read(readBuffer, 1, textLen+1, &mf);
    retVal += UNITTEST_INT(0, numRead, textLen+1);

    DIGI_MEMCMP((const ubyte*)kSampleData, (ubyte*) readBuffer, textLen+1, &cmpRes);
    retVal += UNITTEST_INT(0, cmpRes, 0);

    DIGI_MEMSET((ubyte*)readBuffer, 0, textLen+10);

    /* try to read past textLen+1 bytes */
    numRead = MF_read(readBuffer, 1, 1, &mf);
    retVal += UNITTEST_INT(0, numRead, 0);

    /* rewind and try to read 1 block of textLen+1 bytes */
    UNITTEST_STATUS_GOTO(0, MF_seek(&mf, 0, MOCANA_SEEK_SET),
                         retVal, exit);

    numRead = MF_read(readBuffer, textLen+1, 1, &mf);
    retVal += UNITTEST_INT(0, numRead, 1);

    DIGI_MEMCMP((const ubyte*) kSampleData, (ubyte*) readBuffer, textLen+1, &cmpRes);
    retVal += UNITTEST_INT(0, cmpRes, 0);

    DIGI_MEMSET((ubyte*)readBuffer, 0, textLen+10);

    /* rewind and try to read 1 block of textLen+2 bytes */
    UNITTEST_STATUS_GOTO(0, MF_seek(&mf, 0, MOCANA_SEEK_SET),
                         retVal, exit);

    numRead = MF_read(readBuffer, textLen+2, 1, &mf);
    retVal += UNITTEST_INT(0, numRead, 0);

    DIGI_MEMSET((ubyte*)readBuffer, 0, textLen+10);

    /* rewind and try to read textLen+2 bytes */
    UNITTEST_STATUS_GOTO(0, MF_seek(&mf, 0, MOCANA_SEEK_SET),
                         retVal, exit);

    numRead = MF_read(readBuffer, 1, textLen+2, &mf);
    retVal += UNITTEST_INT(0, numRead, textLen+1);

    DIGI_MEMCMP((const ubyte*) kSampleData, (ubyte*) readBuffer, textLen+1, &cmpRes);
    retVal += UNITTEST_INT(0, cmpRes, 0);

    DIGI_MEMSET((ubyte*)readBuffer, 0, textLen+10);

    /* read with various block sizes */
    for (i = 2; i <= 19; ++i)
    {
        numBlocks = (textLen+1) / i;

        UNITTEST_STATUS_GOTO(0, MF_seek(&mf, 0, MOCANA_SEEK_SET),
                             retVal, exit);

        numRead = MF_read(readBuffer, i, numBlocks+1, &mf);
        retVal += UNITTEST_INT(0, numRead, numBlocks);

        DIGI_MEMCMP((const ubyte*) kSampleData, (ubyte*)readBuffer, numRead*i, &cmpRes);
        retVal += UNITTEST_INT(0, cmpRes, 0);

        DIGI_MEMSET((ubyte*) readBuffer, 0, textLen+10);
    }

exit:


    return retVal;
}
