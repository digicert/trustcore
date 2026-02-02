/*
 * otp_test.c
 *
 * OTP  Test
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
#include "../otp.c"

#include "../../../unit_tests/unittest.h"

/*------------------------------------------------------------------*/

typedef struct
{
    const sbyte*    pass;
    const sbyte*    seed;
    ubyte4          count;
    ubyte           md4_result[8];
    ubyte           md5_result[8];
    ubyte           sha1_result[8];
} OTPTest;


OTPTest gOTPTests[] =
{
    {"This is a test.", "TeSt",     0,  
        { 0xD1, 0x85, 0x42, 0x18, 0xEB, 0xBB, 0x0B, 0x51 },
        { 0x9E, 0x87, 0x61, 0x34, 0xD9, 0x04, 0x99, 0xDD},
        { 0xBB, 0x9E, 0x6A, 0xE1, 0x97, 0x9D, 0x8F, 0xF4 },
    },

    {"This is a test.", "TeSt",     1,
        { 0x63, 0x47, 0x3E, 0xF0, 0x1C, 0xD0, 0xB4, 0x44 },
        { 0x79, 0x65, 0xE0, 0x54, 0x36, 0xF5, 0x02, 0x9F },
        { 0x63, 0xD9, 0x36, 0x63, 0x97, 0x34, 0x38, 0x5B },
    },

    {"This is a test.", "TeSt",    99,  
        { 0xC5, 0xE6, 0x12, 0x77, 0x6E, 0x6C, 0x23, 0x7A },
        { 0x50, 0xFE, 0x19, 0x62, 0xC4, 0x96, 0x58, 0x80 },
        { 0x87, 0xFE, 0xC7, 0x76, 0x8B, 0x73, 0xCC, 0xF9 },
    },

    {"AbCdEfGhIjK",     "alpha1",   0,  
        { 0x50, 0x07, 0x6F, 0x47, 0xEB, 0x1A, 0xDE, 0x4E },
        { 0x87, 0x06, 0x6D, 0xD9, 0x64, 0x4B, 0xF2, 0x06 },
        { 0xAD, 0x85, 0xF6, 0x58, 0xEB, 0xE3, 0x83, 0xC9 },
    },

    {"AbCdEfGhIjK",     "alpha1",   1,  
        { 0x65, 0xD2, 0x0D, 0x19, 0x49, 0xB5, 0xF7, 0xAB },
        { 0x7C, 0xD3, 0x4C, 0x10, 0x40, 0xAD, 0xD1, 0x4B },
        { 0xD0, 0x7C, 0xE2, 0x29, 0xB5, 0xCF, 0x11, 0x9B },
    },
    {"AbCdEfGhIjK",     "alpha1",   99,  
        { 0xD1, 0x50, 0xC8, 0x2C, 0xCE, 0x6F, 0x62, 0xD1 },
        { 0x5A, 0xA3, 0x7A, 0x81, 0xF2, 0x12, 0x14, 0x6C },
        { 0x27, 0xBC, 0x71, 0x03, 0x5A, 0xAF, 0x3D, 0xC6 },
    },

    {"OTP's are good",  "correct",  0,  
        { 0x84, 0x9C, 0x79, 0xD4, 0xF6, 0xF5, 0x53, 0x88 },
        { 0xF2, 0x05, 0x75, 0x39, 0x43, 0xDE, 0x4C, 0xF9 },
        { 0xD5, 0x1F, 0x3E, 0x99, 0xBF, 0x8E, 0x6F, 0x0B },
    },

    {"OTP's are good",  "correct",  1,  
        { 0x8C, 0x09, 0x92, 0xFB, 0x25, 0x08, 0x47, 0xB1 },
        { 0xDD, 0xCD, 0xAC, 0x95, 0x6F, 0x23, 0x49, 0x37 },
        { 0x82, 0xAE, 0xB5, 0x2D, 0x94, 0x37, 0x74, 0xE4 },
    },
    
    {"OTP's are good",  "correct",  99,  
        { 0x3F, 0x3B, 0xF4, 0xB4, 0x14, 0x5F, 0xD7, 0x4B },
        { 0xB2, 0x03, 0xE2, 0x8F, 0xA5, 0x25, 0xBE, 0x47 },
        { 0x4F, 0x29, 0x6A, 0x74, 0xFE, 0x15, 0x67, 0xEC },
    }

};


typedef struct
{
    const sbyte* pass;
    const sbyte* challenge;
    sbyte res[20];
} OTPExTest;


OTPExTest gOTPExTests[] =
{
    /* MD4 */
    { "This is a test.", "otp-md4 0 TeSt", "D185 4218 EBBB 0B51" },
    { "This is a test.", "otp-md4 1 TeSt", "6347 3EF0 1CD0 B444" },
    { "This is a test.", "otp-md4 99 TeSt", "C5E6 1277 6E6C 237A" },

    { "AbCdEfGhIjK", "otp-md4 0 alpha1", "5007 6F47 EB1A DE4E" },
    { "AbCdEfGhIjK", "otp-md4 1 alpha1", "65D2 0D19 49B5 F7AB" },
    { "AbCdEfGhIjK", "otp-md4 99 alpha1", "D150 C82C CE6F 62D1" },

    { "OTP's are good", "otp-md4 0 correct", "849C 79D4 F6F5 5388" },
    { "OTP's are good", "otp-md4 1 correct", "8C09 92FB 2508 47B1" },
    { "OTP's are good", "otp-md4 99 correct", "3F3B F4B4 145F D74B" },

    /* MD5 */
    { "This is a test.", "otp-md5 0 TeSt", "9E87 6134 D904 99DD" },
    { "This is a test.", "otp-md5 1 TeSt", "7965 E054 36F5 029F" },
    { "This is a test.", "otp-md5 99 TeSt", "50FE 1962 C496 5880" },

    { "AbCdEfGhIjK", "otp-md5 0 alpha1", "8706 6DD9 644B F206" },
    { "AbCdEfGhIjK", "otp-md5 1 alpha1", "7CD3 4C10 40AD D14B" },
    { "AbCdEfGhIjK", "otp-md5 99 alpha1", "5AA3 7A81 F212 146C" },

    { "OTP's are good", "otp-md5 0 correct", "F205 7539 43DE 4CF9" },
    { "OTP's are good", "otp-md5 1 correct", "DDCD AC95 6F23 4937" },
    { "OTP's are good", "otp-md5 99 correct", "B203 E28F A525 BE47" },

    /* SHA1 */
    { "This is a test.", "otp-sha1 0 TeSt", "BB9E 6AE1 979D 8FF4" },
    { "This is a test.", "otp-sha1 1 TeSt", "63D9 3663 9734 385B" },
    { "This is a test.", "otp-sha1 99 TeSt", "87FE C776 8B73 CCF9" },

    { "AbCdEfGhIjK", "otp-sha1 0 alpha1", "AD85 F658 EBE3 83C9" },
    { "AbCdEfGhIjK", "otp-sha1 1 alpha1", "D07C E229 B5CF 119B" },
    { "AbCdEfGhIjK", "otp-sha1 99 alpha1", "27BC 7103 5AAF 3DC6" },

    { "OTP's are good", "otp-sha1 0 correct", "D51F 3E99 BF8E 6F0B" },
    { "OTP's are good", "otp-sha1 1 correct", "82AE B52D 9437 74E4" },
    { "OTP's are good", "otp-sha1 99 correct", "4F29 6A74 FE15 67EC" },        
};


int otp_test_all()
{
    int retVal = 0;
    int i;
    sbyte4 cmpRes;
    sbyte res[OTP_RESULT_SIZE];
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for (i = 0; i < COUNTOF(gOTPTests); ++i)
    {
        retVal += UNITTEST_STATUS(i, 
            OTP_otp(MOC_HASH(hwAccelCtx) ht_md4, gOTPTests[i].seed, gOTPTests[i].pass, 
                gOTPTests[i].count, res)); 

        DIGI_MEMCMP( res, gOTPTests[i].md4_result, OTP_RESULT_SIZE, &cmpRes);

        retVal += UNITTEST_INT(i, cmpRes, 0);

        retVal += UNITTEST_STATUS(i, 
            OTP_otp(MOC_HASH(hwAccelCtx) ht_md5, gOTPTests[i].seed, gOTPTests[i].pass, 
                gOTPTests[i].count, res)); 

        DIGI_MEMCMP( res, gOTPTests[i].md5_result, OTP_RESULT_SIZE, &cmpRes);

        retVal += UNITTEST_INT(i, cmpRes, 0);

        retVal += UNITTEST_STATUS(i, 
            OTP_otp(MOC_HASH(hwAccelCtx) ht_sha1, gOTPTests[i].seed, gOTPTests[i].pass, 
                gOTPTests[i].count, res)); 

        DIGI_MEMCMP( res, gOTPTests[i].sha1_result, OTP_RESULT_SIZE, &cmpRes);

        retVal += UNITTEST_INT(i, cmpRes, 0);

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

int otp_test_all_ex()
{
    int retVal = 0;
    int i;
    sbyte4 cmpRes;
    sbyte res[OTP_STR_RESULT_SIZE];
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for (i = 0; i < COUNTOF(gOTPExTests); ++i)
    {
        retVal += UNITTEST_STATUS(i, 
                                  OTP_otpEx(MOC_HASH(hwAccelCtx) gOTPExTests[i].challenge, 
                                            gOTPExTests[i].pass, res));
        DIGI_MEMCMP( res, gOTPExTests[i].res, 20, &cmpRes);

        retVal += UNITTEST_INT(i, cmpRes, 0);

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}










