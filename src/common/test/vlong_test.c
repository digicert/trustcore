/*
 * vlong_test.c
 *
 * unit test for vlong.c
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

#define __ENABLE_DIGICERT_MODEXP_CLASSIC__

#include "../vlong.h"

#include "../vlong/vlong_barrett.c"
#include "../vlong/vlong_div.c"
#include "../vlong/vlong_monty.c"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../random.h"

#include "print_vlong.c"

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#elif defined (__RTOS_WIN32__)
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)

static int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (30)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
                             mContinueTest = 1;          \
                             alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__)    */

/* structure used by the test */
typedef struct MultTest
{
    char* mul1;
    char* mul2;
    char* res;
} MultTest;


#define bn1 "BBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51F" \
            "B8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807F" \
            "AFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394E" \
            "E0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB"

#define bn2 "00EB7A19ACE9E3006350E329504B45E2CA82310B26DCD87D5C68F1EEA8F55267"\
            "C31B2E8BB4251F84D7E0B2C04626F5AFF93EDCFB25C9C2B3FF8AE10E839A2DDB"\
            "4CDCFE4FF47728B4A1B7C1362BAAD29AB48D2869D5024121435811591BE392F9"\
            "82FB3E87D095AEB40448DB972F3AC14F7BC275195281CE32D2F1B76D4D353E2D"

#define bn3 "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF7"\
            "63722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6"\
            "D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48"\
            "DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955"

#define bn4 "403E7B596795392574DC16F23DAF3C6D59801FD277E523832657694568E950A0"\
            "65C400EC2167250F79FA6E02423B5A8F20CA75E43EE10BF969B909D1242D3122"\
            "525641EE373C12037CCB098D00AA751734B160AE18050D05362956C64382697F"\
            "6B2822C03FEF6F6A13127C4244E91C3F088B1A31194F18B1198A7A77"


#define bug1_a "E923B1FF4CDDED1F36DD7149525EB6F1D6429FB59774636D"   \
    "005B89757E56E25FB5F6A57A7B843DE8D08D10AE2D04AE41"              \
    "2726C215CEF2DC7606615422FFC31627A0244553A03A6171"              \
    "B431EE237FC141A6ABB21C235FF69E9DE92EDC0C83710283"              \
    "FE7680B07B6AF974AA5587807F851D3ED94700957B1CF208"              \
    "1F7812BCA23EFF24"

#define bug1_b "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"   \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"              \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"              \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"              \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"              \
    "FFFFFFFFFFFFFFFF"

#define bug1_ab "E923B1FF4CDDED1F04D5363EF3679653FAA15B48C25DB1D9"  \
    "F7AA7CD7D2CC74943D9F0F64430BF8B7345F26E9435006FB"              \
    "D65063D66E1FA782BA9A93752E38A8E597526F31EC14FCB7"              \
    "6F8B79E52F52CC6F6B7C7822C7FA33EDF153F00BC15D557B"              \
    "6388DF695FE9ACA0DC9A4747408AFF6DF1B51EB010184472"              \
    "316E0B65BA5F0B18047E46704C527F0AF8214572EA689820"              \
    "166C2583B184A707C59F892B641D3434DDBC542AAD08606A"              \
    "224A7A271AE459676372F8E47903F9B260B86D4CFDFADE9F"              \
    "C82ED2940007ABCF6EA889CD26723181EB3177BC7965EFEB"              \
    "8B5B9BC81FCEC499AD6F3E7013E82192E0F63A3771326181"              \
    "5C089601BFF14A3FE087ED435DC100DC"

MultTest gTests[] = {
    { "12", "23", "276" }, /* 0 */
    { "0", "1", "0" },     /* 1 */
    { "FEF", "FEF", "FDE121" }, 
    { "FEFE", "FEFE", "FDFD0404" },
    { "FEFED", "FEFED", "FDFEA26169" },
    { "FEFEDA", "FEFEDA", "FDFEB64D51A4" },
    { "FEFEDAB", "FEFEDAB", "FDFEB7ABF01039" },
    { "FEFEDABC", "FEFEDABC", "FDFEB7C3D7F4BA10" },
    { "FFFFFFFF", "FFFFFFFF", "FFFFFFFE00000001" },
    { "123456789", "123456789", "14B66DC326FB98751" },
    { "1234567890", "1234567890", "14B66DC326FB9875100" },
    { "CCCCCCCCCC", "CCCCCCCCCC", "A3D70A3D6F5C28F5C290" },
    { "B66DC326FB98", "34567890ABC", "254BEA6E05CF949A2CCB3A0" },
    { "B66DC326FB98751", "34567890ABCDEF", "254BEA6E05D99A6C59790D2AC319F" },
    { "4B66DC326FB98751", "234567890ABCDEF", "A638152FEAC42408C59790D2AC319F" },
    { "14B66DC326FB98751", "1234567890ABCDEF", "1790FC50E7922A8818C59790D2AC319F" },/*15*/
    { "1790FC50E7922A8818C59790D2AC319F", "23786489734234DFEBC64324",
      "343E7B69F5863AD06277B177A63C1FC7FA2EB4D13ECBFBD072D975C" }, /*16 */
    { "343E7B69F5863AD06277B177A63C1FC7FA2EB4D13ECBFBD072D975C", "FE10AB1CE1115199615A",
      "33D96546796E409B57C72579548B60840BD6CEAA727B044ED7CF18A9882AB3FA86C5E5D1258" },/*17*/
    { "33D96546796E409B57C72579548B60840BD6CEAA727B044ED7CF18A9882AB3FA86C5E5D1258",
      "343E7B69F5863AD06277B177A63C1FC7FA2EB4D13ECBFBD072D975C",
      "A94D037C14971B3E556A3D021C546B6728E8E892240DF764E2E88023381161E4AB7E"
      "7E777CDB6127354D64F8F6555E62F9052662B40801ECE355FC76F70BC7FA0" }, /* 18 */
    { bn1, "1", bn1 },
    { bn1, "0", "0" }, /* 20 */
    { "EB4D13ECBFBD072D975C", "EB4D13ECBFBD072D975C",
      "D84699C9A5FD624C288192285B004C3D97D5A910"
    }, /* 21 */
    { "B4D13ECBFBD072D975C", "B4D13ECBFBD072D975C",
      "7FB6EB567295BC5FA092285B004C3D97D5A910"
    },/* 22 */
    { "4D13ECBFBD072D975C", "4D13ECBFBD072D975C", 
      "1734FDF8571E749EAA285B004C3D97D5A910"
    },/* 23 */
    { "D13ECBFBD072D975C", "D13ECBFBD072D975C", 
      "AB0798789ADDD2FC285B004C3D97D5A910"
    },/* 24 */
    { "343E7B69F5863AD06277B177A63C1FC7FA2EB4D13ECBFBD072D975C",
      "343E7B69F5863AD06277B177A63C1FC7FA2EB4D13ECBFBD072D975C",
      "AA971630E9072B3750B0296D858C527F897F5E630C9806F75441F9B085F1A4E6FBAF"\
      "D5183D4B17F7C694D00F192285B004C3D97D5A910"
    }, /* 25 */
    { bn1, bn2, "ACE67A4DE65A39DCC91A3E0759E43A8AB3FD9398AE4EEC360BF2D481B3F88CC11480"\
                "1D77A6DA50C8C53CC7157D80F48014DF6B6064BD68A5B70E968446852CFCB3AD956E"\
                "45F1F7122F4E72BF3CAA3FA2C01AA331F6AD50F1AF173447186478F74A37BB243B3C"\
                "9F0D49C86B0A27055AC9C9385ABFF9FB6264031EE98C459DA40101FA2E8D7281B220"\
                "65175BA9601590E2CD843474F77AFD805C85EA37AB032B3EAFF16B20EBF28B472AC5"\
                "36EA5AB2F9D79A781789D53E8EC1038CA1E0457356DE6B03DF64A0C64BC43ABE3944"\
                "AB97DF357EDD3F49C2D20D70EC6D32F448BB3644611CC9C513029FCFC5A9122B2CC9"\
                "274C4F9CD4F8EC952DD105775D283886AF" },
    { bn1, bn3, "D75097822A3CECB8E06453C46C5C574113CE2FB4897D307311F03F7B3A2AC53C4211"\
                "DEE7FC417F85796C8AB793D1D026A0371D61CF1430457BECEE6C50DF3AAB4977357F"\
                "0794D8D0C519D6C42A4A3C9AAFE66F1198E12B8DA126EB9A3AB0B28AFD7E88F9252E"\
                "57F1632E27E4479162CCD86CB7745D4945BF5989004829915D1D4A72C15B16262103"\
                "9CA51A001FBB34691E16C32B1C5BEDE65974AAFD7B53A9F53E3C6E773C94CE960028"\
                "7E93E9F8076319EF9EE2CD16273BED5635ABF8AF3894445A0C9DF0C9CDE2C6E4D28D"\
                "C076080CBE849E3F9BBBB22C0988CD68C11FA0BEF526354571AB526AC3BC01EB8F86"\
                "2A63D2E38ED08E74D74F01239AECBB62767" },
    { bn1, bn4, "2F2BEC6F89C063EEF462D56EEC02F23913DACBC472E26CF914FFF921B226FDA24F3B"\
                "A7C8C8AEEA3B7B77E0762939E28555B15AB144425084FE06113503D5E37DF6403B64"\
                "FDEFA7C6DF3835DE5A32599EEF9D19F02F9ABF53937960BD5BF841BF64F404D0B9C4"\
                "637B27B6A64E25C7141B5B66B5DC29F5F822B1E6DE2D9405DC135968E6492C41B385"\
                "758AD144EEC5BF1DB87F8351B2F1512ED00790BFE5E9D2FA12CD005CBF844E888376"\
                "D8D3CD190F5F4F3E2729F9534F47D010804C4455518AF9B0AB9AEAA99D4B9C97ED12"\
                "C0113F727D2E44E6C860B1E7EC5A997390DF97E5DE1E70F1D98FE4E9527A52EB335E"\
                "6B5A7FF92553C79891E38BB3F75D" },
    { bn2, bn3, "10DBBCB6D6E65E1D4A966930AF856D1E89289F1CF7E62ADFE09ED0DD0A8E39BFAB5E"\
                "4504A11C3C8A1BC3289753AA2BC7B541FAF99632D5EFD0EC94866AAA838D64CC5708"\
                "CFA5B303C61A852119BA557C0FF99D39BB9616CA1517FE629CE14A219A30E6DB0534"\
                "341CBD7BD2B494FC819A4951AACD42BCFC16E08B492AE8D7146FF1F7CB6316DED196"\
                "39CD1D9EE34DFDADDF489AC1F21047A2637C2ED828F30EE74B0E5C3DDC5DCCA1D1B5"\
                "EC7EA1D7A2D6FD56E3328CC51E189CCA2DE1A427000CFA8C8723FE1691254F9A487B"\
                "15B8FE279CD4BFF9CA7DF9C8B0F8F18B125D0A71998E04E4B5F846C480701097009F"\
                "CC81BD12EAB4180BE4ED6082F99EC339F1" },
    { bn2, bn4, "3B17FF735969C98674FAADC09B478EE2D0CACBA4158218DFBEA9038D36224512913B"\
                "17B441175A51A29EA2E86C04B2C9DDE08030656B717DCA6FF3F4FA2CAE1624CCEAF5"\
                "2B2187C0CB605758ADC2E4666D550DE3AD0D769194945430290712E8D3C5A8A881DF"\
                "B73AB1900A5FDEF4B870EAAFD22C0D09DA031D50A40A380962DA02FDEA8FB7F912FD"\
                "368CCBC5B13EA5832BDE8D4D5F9245E93199267783EAF4E600D1DDF4AD063746204E"\
                "92618DCA2341441CDC34C1DE040BEAE3D3AD7F6B95C4359EA9B70BAB1ACC1FFBAD3B"\
                "C1DBAE6F9412003DDC59A9C21E4ABB6DADD00B1081EDFC90CFD25B972FF8ABE8C8B4"\
                "4F7821F44AC1C3617D2CA358EB"},
    { bn3, bn4, "49971387656BB226649CD22B68062592B4B2198728363EF6F9978121B6A9431A8F26"\
                "BB536BF255D5EE9386283368EFEA07833ACDDC037EBC481FD809B91D9E98D67EAAF9"\
                "44EFFAF7D16E3BBC7194C16FCAE28E616F7AD28CA072F6A503523DFD0828265F971C"\
                "FD10A1D8792A7E6ECEB3D49E3DFFCFC954E03612EE80B003029F0747E1DC9984DA81"\
                "0DDD0FCF8371E642C8A0B8A56268384AC277BF92514B070EB7693E8F9F7D7600B55D"\
                "6D8911042CAC9ECB6B1A5DC07A92E89092BD014AD17739E11A1B225BC8ACD48E0702"\
                "D18143C8A0FE6B333E0D5C1DB69429E563CF2EA026A9F78086F45786EE2ECFCC91D4"\
                "3E542548E5204834295CC1AD883"},
    { bug1_a, bug1_b, bug1_ab } 
};


static ubyte g[] = {    0x00, 0x00, 0x00, 0x02};

static ubyte p[]  =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


/* modulus of various sizes to use for performance testing */
static ubyte modulus1[] = {
    0xCC, 0xCB, 0x64, 0x54, 0xC2, 0xFA, 0xA3, 0x7A, 0x81, 0x36, 0x5F, 0x1B, 0xD5, 0x10,
    0x81, 0x75, 0xB7, 0x42, 0x02, 0x31, 0x83, 0xB1, 0xD5, 0x5A, 0x76, 0x72, 0x6A, 0x77, 0xBE,
    0x62, 0x69, 0x16, 0xAB, 0xEB, 0x39, 0x66, 0xB5, 0x20, 0x39, 0x33, 0xD1, 0xB4, 0x01, 0x7D,
    0x23, 0x40, 0x24, 0x9E, 0x60, 0x1C, 0xA8, 0x32, 0x83, 0xEA, 0x9D, 0xF1, 0xF2, 0xD9, 0xF0,
    0x18, 0x85, 0x9D, 0xE1, 0xC0, 0xE2, 0x99, 0xFF, 0x89, 0xA4, 0xF9, 0x15, 0xBD, 0x5D, 0xBA,
    0x3F, 0x39, 0x2E, 0x26, 0x14, 0x48, 0x80, 0x75, 0xEF, 0xB5, 0xC0, 0x94, 0x6E, 0x2A, 0x62,
    0xD2, 0x42, 0x34, 0x2C, 0x4A, 0x15, 0x17, 0x58, 0xB0, 0x55, 0x98, 0x11, 0x6E, 0x91, 0xFD,
    0x28, 0x0D, 0x80, 0xC5, 0x21, 0xC2, 0x3E, 0xFB, 0x78, 0x6F, 0x38, 0x31, 0x4A, 0x78, 0xF2,
    0x81, 0x2D, 0x85, 0xC9, 0xB8, 0x2B, 0xF1, 0x86, 0xC9
};

static ubyte modulus2[] = {
    0xDC, 0xD0, 0xD4, 0x77, 0x7A, 0xDF, 0x5E, 0x43, 0xF4, 0x0A, 0xB9, 0xD9, 0x18, 0xDD,
    0xF4, 0x4D, 0x72, 0x1F, 0x54, 0xCE, 0xF1, 0x5F, 0xAC, 0x1E, 0x67, 0x36, 0x8B, 0x32, 0xA7,
    0xD5, 0x43, 0x3B, 0x50, 0xE1, 0xF7, 0x72, 0x34, 0x46, 0x4C, 0xE0, 0xDA, 0x7F, 0x6F, 0xF7,
    0x95, 0x42, 0x9E, 0xA8, 0xD5, 0x38, 0xF0, 0x5B, 0xF6, 0x1E, 0xFB, 0x0B, 0xCC, 0x20, 0x48,
    0x65, 0xC3, 0x73, 0x58, 0x10, 0x5B, 0x2C, 0x25, 0x7C, 0xAD, 0xDB, 0x91, 0xD8, 0x08, 0x16,
    0xBE, 0x8B, 0xCB, 0x61, 0x4A, 0xA3, 0x29, 0x38, 0x38, 0xAE, 0x35, 0xED, 0x3E, 0x1B, 0xF7,
    0x74, 0x4C, 0x55, 0xCC, 0x38, 0x70, 0x0A, 0x60, 0xCC, 0xD8, 0x68, 0xB1, 0xBF, 0x05, 0xB2,
    0xAE, 0x18, 0xB2, 0x1C, 0x94, 0xFB, 0x42, 0xCF, 0xA1, 0x99, 0x41, 0xC3, 0x92, 0xBF, 0x20,
    0x73, 0x9D, 0xF6, 0x8C, 0xB6, 0x30, 0xC7, 0x1C, 0x2B, 0x38, 0x9C, 0x84, 0xD0, 0x41, 0xDF,
    0xB3, 0x3B, 0x51, 0x86, 0x4F, 0xBA, 0x1C, 0x09, 0x32, 0x37, 0xF1, 0xC1, 0x88, 0x39, 0x6F,
    0x08, 0xE3, 0xA6, 0x29, 0x3D, 0x49, 0xA8, 0xE9, 0x1F, 0x49, 0xB0, 0x66, 0x0B, 0x4D, 0x01,
    0x1C, 0x27, 0xFB, 0x1E, 0x65, 0xFE, 0x9A, 0xEE, 0x12, 0xE9, 0xA8, 0x10, 0x7D, 0xA7, 0x21,
    0x79, 0xC9, 0x4B, 0x24, 0x1D, 0x43, 0x37, 0xB1, 0x68, 0x02, 0x8B, 0x3A, 0xAE, 0x2F, 0xF1,
    0x62, 0x26, 0x79, 0xDC, 0xEE, 0xE5, 0x12, 0x4A, 0x36, 0x9E, 0x3C, 0xFF, 0x3C, 0xEB, 0x80,
    0x5B, 0x67, 0x68, 0xAC, 0xAA, 0x75, 0x7B, 0xF3, 0x85, 0xD0, 0x68, 0xAB, 0xAD, 0x26, 0x23,
    0x1A, 0x99, 0xBD, 0xF6, 0x05, 0x1A, 0x7E, 0xD6, 0xAA, 0xCD, 0x4A, 0x89, 0x68, 0x72, 0x86,
    0xFC, 0x6B, 0xB8, 0x96, 0xE0, 0x51, 0xA0, 0x79, 0xAF, 0x7B, 0x06, 0x91, 0x92, 0x48, 0x86,
    0x04, 0xB5
};

static ubyte modulus3[] = {
    0xC5, 0xB6, 0xC7, 0x19, 0x5C, 0xDB, 0x22, 0x60, 0xD4, 0x9D, 0xC6, 0x87, 0xB9, 0xD7,
    0xA8, 0xF1, 0xCA, 0xBE, 0x3E, 0x0D, 0xE1, 0x3C, 0x07, 0x63, 0x4C, 0x85, 0x38, 0x81, 0x34,
    0x5E, 0x64, 0x5F, 0x07, 0xB3, 0xBC, 0xA3, 0xEE, 0x27, 0xDD, 0x38, 0x83, 0x1E, 0xD5, 0xB6,
    0x80, 0x2D, 0x7B, 0x05, 0xD5, 0xD3, 0x23, 0x46, 0xC7, 0xDB, 0x4A, 0xFD, 0xA4, 0x18, 0x02,
    0xFE, 0x34, 0xEC, 0x12, 0x42, 0x13, 0x24, 0x00, 0x4F, 0x54, 0x87, 0x23, 0x4E, 0xAA, 0xDE,
    0x31, 0x2E, 0x8D, 0xDF, 0x55, 0xF2, 0xAC, 0x11, 0x79, 0x1E, 0xEF, 0x50, 0x77, 0x42, 0xD7,
    0x21, 0xD5, 0x9A, 0xE8, 0xF4, 0x23, 0xF6, 0x6E, 0xA5, 0xC2, 0x5C, 0x25, 0x85, 0x2A, 0xF1,
    0x6B, 0x1F, 0xA7, 0x69, 0xE5, 0xBC, 0xD2, 0xF0, 0x5B, 0x68, 0x8E, 0xFB, 0x1F, 0x0F, 0x66,
    0xD3, 0x06, 0x30, 0x5C, 0x90, 0x49, 0x1D, 0x07, 0x15, 0xB1, 0x2F, 0x8D, 0xE7, 0x75, 0x55,
    0x87, 0xC2, 0x2D, 0x25, 0x33, 0xCF, 0x99, 0xC5, 0xB0, 0xC5, 0x09, 0x91, 0x0A, 0x43, 0xB5,
    0xF4, 0x08, 0x69, 0x7D, 0x06, 0x74, 0xDB, 0x5F, 0xB5, 0x14, 0x13, 0x20, 0x99, 0xF4, 0x57,
    0x50, 0xAF, 0x77, 0xA8, 0x56, 0xB0, 0xA1, 0x58, 0x6B, 0x54, 0x16, 0x87, 0x8A, 0xBD, 0x49,
    0xAE, 0x41, 0x40, 0xC4, 0xF5, 0x8B, 0x01, 0x46, 0x70, 0x21, 0x59, 0x09, 0x82, 0x1F, 0x71,
    0x39, 0x95, 0x69, 0x08, 0xD4, 0xF1, 0x5A, 0x2D, 0x8A, 0x75, 0x8E, 0xD1, 0xD5, 0xF6, 0xA0,
    0x4E, 0x6C, 0x11, 0x80, 0xF3, 0x52, 0x01, 0x41, 0x62, 0x44, 0xA1, 0x90, 0xB9, 0x8B, 0x02,
    0xA8, 0x99, 0x6D, 0x2C, 0xCF, 0x83, 0x8E, 0x91, 0x85, 0x2D, 0x2A, 0x4E, 0x51, 0x98, 0x39,
    0x77, 0x4A, 0xEE, 0xFE, 0x56, 0xA2, 0x07, 0x5B, 0x5B, 0xA7, 0x6D, 0xEF, 0x3A, 0xA0, 0x10,
    0x2A, 0xA0, 0x71, 0x46, 0x96, 0x49, 0xB2, 0x01, 0xF7, 0xC1, 0x8F, 0xFD, 0x60, 0xF9, 0xF0,
    0x11, 0x74, 0x1A, 0x5A, 0x43, 0x51, 0x4E, 0x0F, 0xB4, 0x4A, 0x2F, 0xC4, 0xFB, 0x58, 0xBD,
    0x1B, 0x6D, 0x9B, 0x08, 0xE8, 0xBA, 0x36, 0x54, 0xBD, 0xDF, 0xB1, 0x29, 0xF6, 0xEB, 0x72,
    0xE4, 0x67, 0x8F, 0xA8, 0xDF, 0x04, 0xF7, 0xFE, 0xD2, 0x84, 0x7F, 0x47, 0x96, 0xD3, 0xF6,
    0x29, 0x8C, 0x42, 0xAC, 0x97, 0x73, 0x83, 0x09, 0x55, 0xD8, 0x8B, 0x02, 0x49, 0x1D, 0xCF,
    0x1C, 0xD4, 0xDE, 0x69, 0x6B, 0x3B, 0x12, 0xC6, 0xF9, 0x4E, 0xC3, 0x4B, 0x81, 0xFD, 0x0A,
    0xFC, 0x78, 0xE2, 0x58, 0x17, 0xE1, 0x06, 0x22, 0xCC, 0x2E, 0x11, 0x22, 0x2C, 0xEE, 0xD6,
    0x6A, 0x75, 0xEE, 0xB2, 0x60, 0x70, 0xFB, 0xE3, 0x07, 0x8E, 0x60, 0x01, 0x5C, 0xB0, 0x0F,
    0x8B, 0xEE, 0xC7, 0xE7, 0x90, 0x15, 0x96, 0xD8, 0x74, 0x5F
};


/*---------------------------------------------------------------------------*/

void MakeVlongFromString(const sbyte* s, vlong** newVlong, vlong** ppQueue)
{
    ubyte4 bsLen;
    ubyte* bs;

    bsLen = UNITTEST_UTILS_str_to_byteStr( s, &bs);
    VLONG_vlongFromByteString( bs, bsLen, newVlong, ppQueue);
    FREE( bs);
}


/*---------------------------------------------------------------------------*/

int DoMulTest( int i, const sbyte* numStr1, const sbyte* numStr2,
                     const sbyte* resStr)
{
    MSTATUS status;
	vlong* pNum1 = 0;
	vlong* pNum2 = 0;
    vlong* pExpectedRes = 0;
	vlong* pRes = 0;
    int retVal = 0;

	MakeVlongFromString( numStr1, &pNum1, NULL);
	MakeVlongFromString( numStr2, &pNum2, NULL);
	MakeVlongFromString( resStr, &pExpectedRes, NULL);

    if (OK > (status = VLONG_allocVlong(&pRes, NULL)))
        goto exit;

    if  (OK > (status = VLONG_vlongSignedMultiply(pRes, pNum1, pNum2)))
        goto exit;

    retVal += UNITTEST_INT(i, VLONG_compareSignedVlongs( pRes, pExpectedRes), 0);

    if (retVal)
    {
        print_vlong("expected = \n", pExpectedRes);
        print_vlong("computed = \n", pRes);
    }


    if ( 0 == VLONG_compareSignedVlongs( pNum1, pNum2))
    {
        int res1;

        if  (OK > (status = VLONG_vlongSignedSquare(pRes, pNum1)))
        goto exit;

        res1 = UNITTEST_INT(i, VLONG_compareSignedVlongs( pRes, pExpectedRes), 0);
        retVal += res1;

        if (res1)
        {
            print_vlong("expected = \n", pExpectedRes);
            print_vlong("computed = \n", pRes);
        }
    }


   
exit:

    VLONG_freeVlong( &pNum1, NULL);
    VLONG_freeVlong( &pNum2, NULL);
    VLONG_freeVlong( &pRes, NULL);
    VLONG_freeVlong( &pExpectedRes, NULL);

    return retVal;
}

#if (defined(WIN32) && defined(_DEBUG))
#include <crtdbg.h>
#endif


/*--------------------------------------------------------------------------*/

int vlong_test_1()
{
    int retVal = 0;
    int i;

    for ( i = 0; i < COUNTOF(gTests); ++i)
    {
        retVal += DoMulTest(i, gTests[i].mul1, gTests[i].mul2, gTests[i].res);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

static const MultTest gDivTests[] = {
    {
        "0001" 
        "0000000000000000000000000000000000000000000000000000000000000000" 
        "0000000000000000000000000000000000000000000000000000000000000000" 
        "0000000000000000000000000000000000000000000000000000000000000000" 
        "0000000000000000000000000000000000000000000000000000000000000000",
        "100009DCB6726C45C2A7E22AA4D845D0FD706E9993C747AEBACA2C61CE113193"
        "01F9DCAAA259A8F10AC937A4F8A426B01701A2B1BD99A3BA226AAD8E17BD7",
        "FFFF6234FA1C1DD2D775B87F095228B2E1C20902390A4E802D2A0FD01D090DCF"
        "9EFE7F6D669BB05E0911B4937BC0FB29DAD7565C6DB7B20A4EAD7FBFD144B99E2430",
    },
    {
        "FFFFFFFFFFFFFFFF", /* this exercise step 2 of the division algorithm */
        "FFFF0000",
        "0100010001"
    }
};


/*--------------------------------------------------------------------------*/

int DoDivTest( int i, const sbyte* numStr1, const sbyte* numStr2,
               const sbyte* resStr)
{
    MSTATUS status;
	vlong* pNum1 = 0;
	vlong* pNum2 = 0;
    vlong* pExpectedRes = 0;
	vlong* pRes = 0;
	vlong* pRemainder = 0;
    int retVal = 0;

	MakeVlongFromString( numStr1, &pNum1, NULL);
	MakeVlongFromString( numStr2, &pNum2, NULL);
	MakeVlongFromString( resStr, &pExpectedRes, NULL);

    if (OK > (status = VLONG_allocVlong(&pRes, NULL)))
        goto exit;
    if (OK > (status = VLONG_allocVlong(&pRemainder, NULL)))
        goto exit;

    if  (OK > (status = VLONG_unsignedDivide(pRes, pNum1, pNum2, pRemainder, NULL)))
        goto exit;

    retVal += UNITTEST_INT(i, VLONG_compareSignedVlongs( pRes, pExpectedRes), 0);

    if (retVal)
    {
        print_vlong("expected = \n", pExpectedRes);
        print_vlong("computed = \n", pRes);
    }

exit:

    VLONG_freeVlong( &pNum1, NULL);
    VLONG_freeVlong( &pNum2, NULL);
    VLONG_freeVlong( &pRes, NULL);
    VLONG_freeVlong( &pRemainder, NULL);
    VLONG_freeVlong( &pExpectedRes, NULL);

    return retVal;
}

/*--------------------------------------------------------------------------*/

int vlong_test_divide()
{
    int retVal = 0;
    int i;

    for ( i = 0; i < COUNTOF(gDivTests); ++i)
    {
        retVal += DoDivTest(i, gDivTests[i].mul1, gDivTests[i].mul2, gDivTests[i].res);
    }

    return retVal;
}



/*------------------------------------------------------------------*/

int DH_test(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const ubyte* gBytes, sbyte4 gLen,
            const ubyte* pBytes, sbyte4 pLen,
            const ubyte* yBytes, sbyte4 yLen,
            const ubyte* eBytes, sbyte4 eLen,
            const ubyte* fBytes, sbyte4 fLen,
            const ubyte* kBytes, sbyte4 kLen)
{
    vlong* g = 0;
    vlong* p = 0;
    vlong* y = 0;
    vlong* e = 0;
    vlong* f = 0;
    vlong* k = 0;
    vlong* pQueue = 0;

    vlong* comp_f = 0;
    vlong* comp_k = 0;

    int retVal = 0;

    VLONG_vlongFromByteString( gBytes, gLen, &g, &pQueue);
    VLONG_vlongFromByteString( pBytes, pLen, &p, &pQueue);
    VLONG_vlongFromByteString( yBytes, yLen, &y, &pQueue);
    VLONG_vlongFromByteString( eBytes, eLen, &e, &pQueue);
    VLONG_vlongFromByteString( fBytes, fLen, &f, &pQueue);
    VLONG_vlongFromByteString( kBytes, kLen, &k, &pQueue);

    /* test 1 */
    VLONG_modexp(MOC_MOD(hwAccelCtx) g, y, p, &comp_f, &pQueue);

    retVal +=  UNITTEST_INT(hint, VLONG_compareSignedVlongs( comp_f, f), 0);

    /* test 2 */
    VLONG_modexp(MOC_MOD(hwAccelCtx) e, y, p, &comp_k, &pQueue);
    retVal += UNITTEST_INT(hint, VLONG_compareSignedVlongs( comp_k, k), 0);

    VLONG_freeVlong( &g, 0);
    VLONG_freeVlong( &p, 0);
    VLONG_freeVlong( &y, 0);
    VLONG_freeVlong( &e, 0);
    VLONG_freeVlong( &f, 0);
    VLONG_freeVlong( &k, 0);

    VLONG_freeVlong( &comp_f, 0);
    VLONG_freeVlong( &comp_k, 0);

    VLONG_freeVlongQueue(&pQueue);
    return retVal;
}


/*---------------------------------------------------------------------------*/

int vlong_test_2()
{
    int retVal = 0;

    static ubyte y_s[] =
    {
    0xC0, 0x95, 0x0D, 0xE5, 0xA2, 0x86, 0x42, 0x85, 0x24, 0x42, 0x10, 0x9E,
    0x3C, 0x71, 0x26, 0x9E, 0x4F, 0x04, 0xFF, 0x2C, 0xD0, 0x45, 0x5A, 0x6F,
    };

    static ubyte f_s[] =
    {
    0x23, 0x15, 0x67, 0xC0, 0xA4, 0x8E, 0x67, 0x34, 0x7E, 0xFD, 0xD5, 0x34,
    0x82, 0x12, 0x6A, 0xE0, 0x07, 0x39, 0xCC, 0x9A, 0x73, 0x96, 0xDC, 0x89,
    0x16, 0x12, 0x00, 0x1C, 0x6E, 0x18, 0x8A, 0x98, 0x26, 0xCE, 0x3E, 0x2A,
    0x05, 0x17, 0x6D, 0x07, 0x5E, 0xEB, 0x15, 0x33, 0x40, 0x67, 0x09, 0x6D,
    0xC5, 0x04, 0xDA, 0x75, 0x80, 0x3F, 0xBB, 0xAE, 0xDB, 0x78, 0x3D, 0x85,
    0x38, 0xFD, 0x51, 0xA0, 0x3A, 0x6F, 0x88, 0x64, 0x4F, 0xC5, 0x09, 0x4E,
    0x72, 0xAD, 0xF6, 0xD6, 0xC2, 0xD9, 0xCF, 0xEE, 0x9A, 0x92, 0xD5, 0x81,
    0x60, 0x1E, 0x45, 0xD6, 0xBA, 0x61, 0x8A, 0x04, 0xA3, 0x19, 0xCB, 0x7D,
    0x95, 0x8B, 0x2E, 0xE0, 0xFA, 0x1F, 0xFD, 0x77, 0x3A, 0x5F, 0xDC, 0x07,
    0xE0, 0xCF, 0x7D, 0x9C, 0x84, 0x7A, 0xF3, 0x7A, 0x15, 0xF9, 0x28, 0xDD,
    0x04, 0x2E, 0xD7, 0x8C, 0x59, 0x33, 0x3D, 0xAD,
    };


    static ubyte e_s[] =
    {
    0x92, 0x41, 0xEC, 0xA5, 0x08, 0x38, 0xC0, 0xFE, 0x37, 0xA9, 0x05, 0xB2,
    0x2C, 0x6E, 0x11, 0x5C, 0xF1, 0xDB, 0x15, 0x95, 0x09, 0xA9, 0x8E, 0x5A,
    0x67, 0xBB, 0xB6, 0x7B, 0xF6, 0xBF, 0x57, 0x94, 0x45, 0x04, 0x84, 0x8A,
    0x45, 0xC8, 0x20, 0x4E, 0x04, 0x4D, 0xC2, 0xFD, 0xF2, 0x2D, 0x28, 0x50,
    0xAC, 0x39, 0x27, 0xF2, 0xA0, 0x06, 0x4D, 0x81, 0x8A, 0xFC, 0x1B, 0xA6,
    0x07, 0x28, 0x3C, 0x64, 0xD7, 0xBA, 0xA1, 0xFB, 0xC4, 0xBC, 0xC2, 0xE9,
    0x9C, 0x78, 0xDD, 0x27, 0xBD, 0x24, 0x13, 0x8F, 0x4B, 0x1B, 0x6C, 0xB8,
    0x0C, 0xE5, 0xED, 0xFC, 0xC9, 0x97, 0x8B, 0xC9, 0x82, 0xD4, 0xDD, 0x0A,
    0xFD, 0x6B, 0x17, 0x7D, 0x71, 0x4C, 0x0A, 0x0C, 0xE1, 0xB0, 0x18, 0x5D,
    0x3E, 0x45, 0x28, 0x1B, 0x9D, 0xB4, 0x11, 0x67, 0x11, 0xCD, 0xB6, 0xDC,
    0x45, 0xA1, 0x54, 0x70, 0xD6, 0xCA, 0x50, 0xD1,
    };

    static ubyte k_s[] =
    {
    0x86, 0x67, 0xF1, 0x8B, 0xC2, 0x58, 0x8D, 0x87, 0x7C, 0x7A, 0xEA, 0x15,
    0xEB, 0xA3, 0x9E, 0xA2, 0x5A, 0x8A, 0x20, 0x56, 0xAB, 0x06, 0x1F, 0x6D,
    0xA7, 0xDC, 0x1F, 0x40, 0xF4, 0xCF, 0x64, 0xF3, 0x74, 0x4D, 0x42, 0xC9,
    0xDB, 0x45, 0x25, 0xB7, 0x3E, 0x7C, 0x1A, 0x07, 0xDF, 0x7E, 0xB2, 0xB1,
    0xAB, 0x79, 0x6F, 0x8E, 0x90, 0x60, 0x5C, 0xDB, 0x56, 0xD9, 0x2F, 0x36,
    0x60, 0xF9, 0xD6, 0xAE, 0xCC, 0xCA, 0xB8, 0x6F, 0x10, 0xB3, 0x99, 0x13,
    0x65, 0xFA, 0x2F, 0x78, 0xE8, 0xD8, 0xAA, 0x46, 0x9D, 0x74, 0xBD, 0x88,
    0x1A, 0x55, 0x34, 0xA3, 0xFC, 0x12, 0x29, 0x7E, 0x70, 0xE7, 0xBE, 0x59,
    0x56, 0xB4, 0xB5, 0x0A, 0x9F, 0xB4, 0xE6, 0x63, 0x7B, 0x1E, 0x75, 0xA8,
    0x05, 0x2B, 0x67, 0xB3, 0x48, 0xAA, 0x0D, 0x66, 0xC5, 0x78, 0x76, 0xB4,
    0x23, 0xE6, 0xC6, 0xE4, 0xC9, 0x19, 0xF6, 0x85,
    };

    /* client */

    ubyte y_c[] =
    {
    0xE8, 0xBE, 0xCB, 0xE8, 0x89, 0xFD, 0xC0, 0x06, 0xDA, 0x2E, 0xFB, 0x27,
    0x8C, 0x8F, 0xE2, 0x23, 0xD9, 0x1B, 0x0B, 0xBA, 0xCF, 0x35, 0x45, 0xA4,
    };

    static ubyte* f_c = e_s;

    static ubyte* e_c = f_s;

    static ubyte* k_c = k_s;

#if 0
    /* for reference, invalid k computed by the client with an old version of the PowerPC
        assembly language -- was missing one carry in the main loop */
    ubyte k_c[] =
    {
    0xD2, 0x64, 0x31, 0xCF, 0x5C, 0x04, 0x94, 0x99, 0x06, 0xFB, 0x63, 0x1B,
    0x89, 0x57, 0x29, 0x7C, 0xF0, 0x06, 0x0B, 0xBF, 0xB3, 0xB2, 0xBB, 0x4A,
    0xCC, 0x58, 0x8D, 0xFA, 0x6A, 0xAF, 0x36, 0x0C, 0x80, 0x68, 0xAF, 0xEC,
    0x94, 0x1B, 0xC0, 0x69, 0x9B, 0x2C, 0x78, 0x71, 0x48, 0x2D, 0x04, 0x2D,
    0x52, 0x24, 0x54, 0xCE, 0x08, 0x70, 0xB7, 0x8D, 0x26, 0x00, 0x20, 0xA9,
    0x18, 0x4A, 0x0A, 0xD6, 0xB5, 0x15, 0x66, 0xCB, 0xCE, 0x40, 0xFA, 0xDD,
    0x7C, 0xC9, 0xF9, 0x1D, 0x8D, 0xEC, 0x19, 0x0C, 0x60, 0x3F, 0x99, 0x6C,
    0xFF, 0xF2, 0xC8, 0x53, 0x26, 0x15, 0x15, 0xC5, 0x0D, 0x99, 0xDF, 0xC3,
    0x95, 0x2E, 0x48, 0x40, 0x9B, 0xB3, 0x2B, 0xC5, 0x11, 0xDA, 0xC5, 0x02,
    0xDE, 0x04, 0xE1, 0xB3, 0x46, 0x94, 0x6A, 0xFD, 0x24, 0xFA, 0x94, 0xDB,
    0x31, 0xA1, 0x03, 0xD8, 0xB8, 0x66, 0x65, 0x57,
    };
#endif
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal += DH_test(MOC_MOD(hwAccelCtx) 0, g, COUNTOF(g), p, COUNTOF(p),
                        y_s, COUNTOF( y_s), e_s, COUNTOF(e_s),
                        f_s, COUNTOF( f_s), k_s, COUNTOF(k_s));

    retVal += DH_test(MOC_MOD(hwAccelCtx) 0, g, COUNTOF(g), p, COUNTOF(p),
                        y_c, COUNTOF( y_c), f_s, COUNTOF(f_s),
                        e_s, COUNTOF( e_s), k_s, COUNTOF(k_s));

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;

}


/*------------------------------------------------------------------*/

int DH_test_aux(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const ubyte* gBytes, sbyte4 gLen,
                 const ubyte* pBytes, sbyte4 pLen,
                 const ubyte* xBytes, sbyte4 xLen,
                 const ubyte* yBytes, sbyte4 yLen)
{
    vlong* g = 0;
    vlong* p = 0;
    vlong* x = 0;
    vlong* y = 0;

    vlong* X= 0;
    vlong* Y= 0;
    vlong* kx= 0;
    vlong* ky= 0;

    int retVal = 0;

    VLONG_vlongFromByteString( gBytes, gLen, &g, NULL);
    VLONG_vlongFromByteString( pBytes, pLen, &p, NULL);
    VLONG_vlongFromByteString( xBytes, xLen, &x, NULL);
    VLONG_vlongFromByteString( yBytes, yLen, &y, NULL);

    /* X = g ^ x mod p */
    VLONG_modexp(MOC_MOD(hwAccelCtx) g, x, p, &X, NULL);
    /* Y = g ^ y mod p */
    VLONG_modexp(MOC_MOD(hwAccelCtx) g, y, p, &Y, NULL);
    /* kx= X ^y mod p */
    VLONG_modexp(MOC_MOD(hwAccelCtx) X, y, p, &kx, NULL);
    /* ky= Y ^x mod p */
    VLONG_modexp(MOC_MOD(hwAccelCtx) Y, x, p, &ky, NULL);

    /* test kx== ky */
    retVal += UNITTEST_INT(hint, VLONG_compareSignedVlongs( kx, ky), 0);

    if ( retVal)
    {
        print_vlong("x = ", x);
        print_vlong("y = ", y);
        print_vlong("X = ", X);
        print_vlong("Y = ", Y);
        print_vlong("kx = ", kx);
        print_vlong("ky = ", ky);
    }

    VLONG_freeVlong( &g, NULL);
    VLONG_freeVlong( &p, NULL);
    VLONG_freeVlong( &x, NULL);
    VLONG_freeVlong( &y, NULL);

    VLONG_freeVlong( &X, NULL);
    VLONG_freeVlong( &Y, NULL);
    VLONG_freeVlong( &kx, NULL);
    VLONG_freeVlong( &ky, NULL);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int vlong_test_dh_random1()
{
    int i, retVal = 0;

    randomContext* pRandomContext;

    ubyte x[COUNTOF(p)];
    ubyte y[COUNTOF(p)];
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    RANDOM_acquireContext( &pRandomContext);

    for (i = 0; i < 100; ++i)
    {
        RANDOM_rngFun( pRandomContext, COUNTOF(p), x);
        RANDOM_rngFun( pRandomContext, COUNTOF(p), y);

        retVal += DH_test_aux(MOC_MOD(hwAccelCtx) i + 1, g, COUNTOF(g), p, COUNTOF(p),
                               x, COUNTOF(p), y, COUNTOF(p));

    }

    RANDOM_releaseContext( &pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/*---------------------------------------------------------------------------*/

int vlong_test_dh_random2()
{
    int i, retVal = 0;

    randomContext* pRandomContext;

    ubyte x[COUNTOF(p)];
    ubyte y[COUNTOF(p)];
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    RANDOM_acquireContext( &pRandomContext);

    for (i = 101; i < 200; ++i)
    {
        RANDOM_rngFun( pRandomContext, COUNTOF(p), x);
        RANDOM_rngFun( pRandomContext, COUNTOF(p), y);

        retVal += DH_test_aux(MOC_MOD(hwAccelCtx) i + 1, g, COUNTOF(g), p, COUNTOF(p),
                               x, COUNTOF(p), y, COUNTOF(p));

    }

    RANDOM_releaseContext( &pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/*---------------------------------------------------------------------------*/

typedef struct bitlength_test 
{
    ubyte4 bitlen;
    sbyte* str;
} bitlength_test;


static const bitlength_test bitlength_tests[] = 
{
    { 0, "00" },
    { 1, "01" },
    { 2, "02" },
    { 31, "70000000" },
    { 32, "80000000" },
    { 32, "F0000000" },
    { 33, "0100000000" },
    { 63, "7000000000000000"},
    { 64, "8000000000000000"},
    { 65, "010000000000000000"},
};


/*--------------------------------------------------------------------------*/

int vlong_test_bitlength()
{
    int retVal = 0;
    vlong* test = 0;
    int i;
    ubyte4 bitLen;

    for (i = 0; i < COUNTOF(bitlength_tests); ++i)
    {
        MakeVlongFromString( bitlength_tests[i].str, &test, NULL);
        bitLen = VLONG_bitLength( test);
        retVal += UNITTEST_INT( i, bitLen, bitlength_tests[i].bitlen);
        VLONG_freeVlong( &test, NULL);
    }
    
    return retVal;
}


/*--------------------------------------------------------------------------*/

int perf_init_monty_aux(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const ubyte* modulus, ubyte4 modulusLen)
{
    int retVal = 0;

    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)

    struct tms tstart, tend;
    double diffTime;
    int i;
    int iter = 1000;
    vlong* m = 0;
    vlong* pQueue = 0;

    VLONG_vlongFromByteString( modulus, modulusLen, &m, &pQueue);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    for (i = 0; i < iter && ALARM_OFF; ++i)
    {
        MontgomeryCtx me;
        VLONG_initMontgomeryCtx(MOC_MOD(hwAccelCtx) &me, m, &pQueue);
    }
    times(&tend);
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("%d initMonty in %g seconds of CPU time\n", i, diffTime);
    printf("%d bits: %g initMonty/second (CPU time)\n",
           hint, i/diffTime);


    VLONG_freeVlong( &m, 0);
    VLONG_freeVlongQueue(&pQueue);

#endif

    return retVal;
}


/*---------------------------------------------------------------------------*/

int vlong_test_perf_init_monty()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal += perf_init_monty_aux(MOC_MOD(hwAccelCtx) 1024, modulus1, sizeof(modulus1));
    retVal += perf_init_monty_aux(MOC_MOD(hwAccelCtx) 2048, modulus2, sizeof(modulus2));
    retVal += perf_init_monty_aux(MOC_MOD(hwAccelCtx) 3072, modulus3, sizeof(modulus3));

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int perf_modexp_aux(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const ubyte* modulus, ubyte4 modulusLen)
{
    int retVal = 0;

    /* performance test on linux machines comparing the speed of
    modexp monty vs. modexp classic depending on exponent size */
#if (TEST_RUN_LEVEL > 1) && (defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))

    struct tms tstart, tend;
    double diffTime1, diffTime2, diffTime3;
    int i, j,remaining;
    int iter = 1000;
    vlong* m = 0;
    vlong* pQueue = 0;
    vlong* x = 0;
    vlong* e = 0;
    vlong* result = 0;
    ubyte* buffer = 0;
    randomContext* pRandomContext;

    RANDOM_acquireContext( &pRandomContext);

    VLONG_vlongFromByteString( modulus, modulusLen, &m, &pQueue);

    /* generate a number to exponentiate */
    buffer = MALLOC(modulusLen);
    RANDOM_numberGenerator( pRandomContext, buffer, modulusLen);
    VLONG_vlongFromByteString( buffer, modulusLen, &x, &pQueue);

    /* generate exponents */
    VLONG_allocVlong( &e, &pQueue);

    remaining = 10;
    for (j = 0; j < m->numUnitsUsed && remaining > 0; ++j)
    {
        VLONG_setVlongUnit( e, j, 0x55555555); /* half bit sets, odd value */

        times(&tstart);
        for (i = 0; i < iter; ++i)
        {
            VLONG_modexp_montgomery(MOC_MOD(hwAccelCtx) x, e, m, &result, &pQueue);
            if (0 == i)
            {
                print_vlong("monty = ", result);
            }
            VLONG_freeVlong( &result, &pQueue);
        }
        times(&tend);
        diffTime1 = tend.tms_utime-tstart.tms_utime;
        diffTime1 /= sysconf(_SC_CLK_TCK);
        printf("exponent %d bits, modulus %d bits : %g modexp/second (Montgomery) (CPU time)\n",
               ((j+1) * 32), hint, iter/diffTime1);

        times(&tstart);
        for (i = 0; i < iter; ++i)
        {
            VLONG_modexp_barrett( x, e, m, &result, &pQueue);
            if (0 == i)
            {
                print_vlong("barrett = ", result);
            }

            VLONG_freeVlong( &result, &pQueue);
        }
        times(&tend);
        diffTime2 = tend.tms_utime-tstart.tms_utime;
        diffTime2 /= sysconf(_SC_CLK_TCK);
        printf("exponent %d bits, modulus %d bits : %g modexp/second (Barrett) (CPU time)\n",
               ((j+1) * 32), hint, iter/diffTime2);

        times(&tstart);
        for (i = 0; i < iter; ++i)
        {
            VLONG_modexp_classic( x, e, m, &result, &pQueue);
            if (0 == i)
            {
                print_vlong("classic = ", result);
            }

            VLONG_freeVlong( &result, &pQueue);
        }
        times(&tend);
        diffTime3 = tend.tms_utime-tstart.tms_utime;
        diffTime3 /= sysconf(_SC_CLK_TCK);
        printf("exponent %d bits, modulus %d bits : %g modexp/second (Classic) (CPU time)\n",
               ((j+1) * 32), hint, iter/diffTime3);

        if ( diffTime1 < diffTime3)
        {
            --remaining;
        }
    }
cleanup:

    VLONG_freeVlong( &m, 0);
    VLONG_freeVlong( &x, 0);
    VLONG_freeVlong( &e, 0);
    VLONG_freeVlongQueue(&pQueue);

    if (buffer)
    {
        FREE(buffer);
    }
    RANDOM_releaseContext( &pRandomContext);

#endif

    return retVal;
}


/*---------------------------------------------------------------------------*/

int vlong_test_perf_modexp()
{
   int retVal = 0;
   hwAccelDescr hwAccelCtx = 0;

   if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
      return retVal;

   retVal += perf_modexp_aux(MOC_MOD(hwAccelCtx) 1024, modulus1, sizeof(modulus1));
   retVal += perf_modexp_aux(MOC_MOD(hwAccelCtx) 2048, modulus2, sizeof(modulus2));
   retVal += perf_modexp_aux(MOC_MOD(hwAccelCtx) 3072, modulus3, sizeof(modulus3));

   HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
   return retVal;
}




/*************************************************************
 Barrett tests
**************************************************************/
#if !defined(__DISABLE_DIGICERT_BARRETT__)

typedef struct BarrettMuTest
{
    sbyte* modulusStr;
    sbyte* muStr;
} BarrettMuTest;

BarrettMuTest gMuTests[] = {
    {"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
     "1000000000000000000000000662107C9EB94364E4B2DD7CF" },
    {"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
#ifdef __ENABLE_DIGICERT_64_BIT__
    "010000000000000000000000000000E95D1F470FC1EC22D6BAA3A3D5C3D4BAA4CF1822BC47"
#else
    "010000000000000000000000000000E95D1F470FC1EC22D6BAA3A3D5C3"
#endif
    },
    {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     "0000000100000000FFFFFFFFFFFFFFFEFFFFFFFF43190552DF1A6C21012FFD85EEDF9BFE"},
    {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
     "00000001000000000000000000000000000000000000000000000000389CB27E0BC8D220A7E5F24DB74F58851313E695"
     "333AD68D" },
    {"000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148"
     "F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
#ifdef __ENABLE_DIGICERT_64_BIT__
     "008000000000000000000000000000000000000000000000000000000000000000016B9E5E1F10341A65200CFFADC23D"
     "968BF1128D91DD98EE14512412385BB1E6FDC408F501C8D1CD2DAD1D7F46221C"
#else
     "008000000000000000000000000000000000000000000000000000000000000000016B9E5E1F10341A65200CFFADC23D"
     "968BF1128D91DD98EE14512412385BB1E6FDC408F501C8D1"
#endif
    },
    {"E28D3A137CD0B42938B2B2FD4561704620594E64A50DDFAD94A4503F9F1F370C754F5D491DB5D6B1DEA1D6965E087B6B"
     "9BBCF610EFC90EB10D4D3F2F8627C57607D2709B9C7DDFBB95141BCAC15BDC7843C095AE3342C5F00F3713ACCC2B18ED"
     "75210C33AAA7C5E9B4003E9D8A81CAC630F66CED692FD05AA3210B044DBDE72F",
     "000000012146B3771186C3FAD6CCF630315632350EA53BA30EE3483AA9F43BCF7BB90C6B17286484BEC18D228B86F6EF"
     "99C46D32DF73BE8A8A39B60E9E9BD50FF34032ECCC58F52D1DD42B5B376934AD0144847D2C31C96F4682C1970E8AAE90"
     "D770D49AE57006AEC7137FCA4C93EE429112F0D50E9DB02354F6742E5AD7672AD5FF1018"},
    {"00000092CE7AC1AE833E5AAA898357AC2501760CADAE8E2C37CEEB3578645403E5844051C9BF8F08E28A8208D2168637"
     "55E9B12102AD7668819A05A24BC94B256622566C88078FF781596D840765701371763E9B774CE35089569848B91DA729"
     "1A132E4A11599C1E15D549542C733A6982B197399C6D706748E5DD2DD6C81E7B",
     "01BE691AEF55F405FC9FD001A4C258B495EB46CF0C8F2CB179CF9C97B8B397142D965BEB5061A5F1B7A95E36DA742568"
     "6D97B36CFBF1CC806269B811D49C1BBB807167E52DC466128D07E4815FEEDA05AA49F112B53FD29C909F85051A968929"
     "AF6AEAB659BDA1A20A8ABA3B0B636D64EC1823A65D84E50E1891AC3F7FF407620231F497" },
};

int DoBarrettMuTest( int hint, const BarrettMuTest* pMuTest)
{
    int retVal = 0;
    vlong* pModulus;
    vlong* pMu;
    vlong* pExpectedMu;

   	MakeVlongFromString( pMuTest->modulusStr, &pModulus, NULL);
	MakeVlongFromString( pMuTest->muStr, &pExpectedMu, NULL);

    retVal += UNITTEST_STATUS( hint, VLONG_newBarrettMu(&pMu, pModulus, NULL));
    if ( retVal) goto exit;

    retVal += UNITTEST_INT(hint, VLONG_compareSignedVlongs( pMu, pExpectedMu), 0);

exit:

    VLONG_freeVlong( &pModulus, NULL);
    VLONG_freeVlong( &pMu, NULL);
    VLONG_freeVlong( &pExpectedMu, NULL);

    return retVal;
}
#endif /* __DISABLE_DIGICERT_BARRETT__ */


int vlong_test_barrett_mu()
{
#if !defined(__DISABLE_DIGICERT_BARRETT__)
    int retVal = 0;
    sbyte4 i;

    for ( i = 0; i < COUNTOF(gMuTests); ++i)
    {
        retVal += DoBarrettMuTest(i, gMuTests+i);
    }
    return retVal;
#else
    return 0;
#endif /* __DISABLE_DIGICERT_BARRETT__ */
}

#if !defined(__DISABLE_DIGICERT_BARRETT__)

typedef struct BarrettReductionTest
{
    char* xStr;
    char* mStr;
    char* resStr;
} BarrettReductionTest;

BarrettReductionTest gBarrettReductionTests[] = {
    {
        "814FEB478400",
        "067CE4FDF9",
        "2CF89EB82"
    }
};

int DoBarrettReductionTest( int hint, const BarrettReductionTest* pReductionTest)
{
    int retVal = 0;
    vlong* pX = 0;
    vlong* pModulus = 0;
    vlong* pMu = 0;
    vlong* pExpectedRes = 0;
    vlong* pRes = 0;

    retVal += UNITTEST_STATUS(hint, VLONG_allocVlong(&pRes, NULL));

    MakeVlongFromString( pReductionTest->xStr, &pX, NULL);
   	MakeVlongFromString( pReductionTest->mStr, &pModulus, NULL);
    MakeVlongFromString( pReductionTest->resStr, &pExpectedRes, NULL);

    retVal += UNITTEST_STATUS( hint, VLONG_newBarrettMu(&pMu, pModulus, NULL));
    if ( retVal) goto exit;

    /* fill res with garbage */
    retVal += UNITTEST_STATUS(hint, expandVlong(pRes, 2 * pMu->numUnitsAllocated));
    if (retVal) goto exit;

    DIGI_MEMSET((ubyte*)pRes->pUnits, 0xCC, pRes->numUnitsAllocated * sizeof(vlong_unit));

    retVal += UNITTEST_STATUS( hint, VLONG_barrettReduction(pRes, pX, pModulus, pMu, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_INT(hint, VLONG_compareSignedVlongs( pRes, pExpectedRes), 0);
    if (retVal) goto exit;

exit:
    VLONG_freeVlong( &pRes, NULL);
    VLONG_freeVlong( &pX, NULL);
    VLONG_freeVlong( &pModulus, NULL);
    VLONG_freeVlong( &pExpectedRes, NULL);
    VLONG_freeVlong( &pMu, NULL);
    return retVal;
}
#endif /* __DISABLE_DIGICERT_BARRETT__ */


int vlong_test_barrett_reduction()
{
#if !defined(__DISABLE_DIGICERT_BARRETT__)
    int retVal = 0;
    sbyte4 i;

    for ( i = 0; i < COUNTOF(gBarrettReductionTests); ++i)
    {
        retVal += DoBarrettReductionTest(i, gBarrettReductionTests+i);
    }
    return retVal;
#else
    return 0;
#endif /* __DISABLE_DIGICERT_BARRETT__ */
}

#if !defined(__DISABLE_DIGICERT_BARRETT__)

int DoBarrettMulTest(MOC_MOD(hwAccelDescr hwAccelCtx) const vlong* pModulus, randomContext* pRandomContext)
{
    int i, retVal = 0;
    ubyte a[128]; /* 1024 bits */
    vlong* pX = 0;
    vlong* pY = 0;
    vlong* pMu = 0;
    vlong* pProduct = 0;
    vlong* pRes1 = 0;
    vlong* pRes2 = 0;

    retVal += UNITTEST_STATUS(0, VLONG_newBarrettMu(&pMu, pModulus, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, VLONG_allocVlong(&pProduct, NULL));
    if ( retVal) goto exit;

    retVal += UNITTEST_STATUS(0, VLONG_allocVlong(&pRes2, NULL));
    if ( retVal) goto exit;

    for (i = 0; i < 200; ++i)
    {
        RANDOM_rngFun( pRandomContext, 128, a);
        VLONG_vlongFromByteString(a, 128, &pX, NULL);
        RANDOM_rngFun( pRandomContext, 128, a);
        VLONG_vlongFromByteString(a, 128, &pY, NULL);

        /* compute it the classic way */
        retVal += UNITTEST_STATUS( i, VLONG_unsignedMultiply( pProduct, pX,
                                                                 pY));
        if ( retVal) goto exit;

        retVal += UNITTEST_STATUS( i, VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pProduct,
                                                                     pModulus,
                                                                     &pRes1,
                                                                     NULL));
        if ( retVal) goto exit;

        /* compute it with barrett */
        retVal += UNITTEST_STATUS( i, VLONG_barrettMultiply( pRes2, pX, pY,
                                                             pModulus, pMu,
                                                             NULL));
        if ( retVal) goto exit;

        retVal += UNITTEST_INT( i, VLONG_compareSignedVlongs( pRes1, pRes2),
                                0);
        /* if there is an error, no need to keep doing the test */
        if ( retVal)
        {
            print_vlong("modulus =", pModulus);
            print_vlong("mu =", pMu);
            print_vlong("X =", pX);
            print_vlong("Y =", pY);
            print_vlong("res1 =", pRes1);
            print_vlong("res2 = ", pRes2);
            goto exit;
        }

        VLONG_freeVlong( &pRes1, NULL);
        VLONG_freeVlong( &pX, NULL);
        VLONG_freeVlong( &pY, NULL);
    }


exit:

    VLONG_freeVlong( &pMu, NULL);
    VLONG_freeVlong( &pX, NULL);
    VLONG_freeVlong( &pY, NULL);
    VLONG_freeVlong( &pProduct, NULL);
    VLONG_freeVlong( &pRes1, NULL);
    VLONG_freeVlong( &pRes2, NULL);

    return retVal;
}
#endif /* __DISABLE_DIGICERT_BARRETT__ */

int vlong_test_barrett_mult()
{

#if !defined(__DISABLE_DIGICERT_BARRETT__)
    int i, retVal = 0;
    randomContext* pRandomContext;
    ubyte m[128];
    vlong* pModulus = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    RANDOM_acquireContext( &pRandomContext);

    for ( i = 0; i < 50; ++i)
    {
        RANDOM_rngFun(pRandomContext, 128, m);
        VLONG_vlongFromByteString(m, 128, &pModulus, NULL);
        retVal += DoBarrettMulTest(MOC_MOD(hwAccelCtx) pModulus, pRandomContext);
        VLONG_freeVlong(&pModulus, NULL);
    }

    VLONG_freeVlong(&pModulus, NULL);

    RANDOM_releaseContext( &pRandomContext);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
#else
    return 0;
#endif  /* __DISABLE_DIGICERT_BARRETT__ */
}


/********************************************************************************/

int vlong_test_doublediv()
{
    int i;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_64_BIT__
    vlong_unit tests[] = {
        0x0000000000000001, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF, 0x0000000000000001,
        0xEFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xF000000000000000,
        0xDFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xE000000000000000,                                                                      
        0xDFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x000000000000000F, 0xEEEEEEEEEEEEEEEE,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000,
        0xFFFFFFFFFFFFFFFF, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF, 0x0000000000000000,
        0xFFFFFFFFFFFFFFE0, 0x0000000000000001, 0x000FFFFFFFFFFFFF, 0x0000000000FE0000,
        0xFFFFFFFFFFFFFE00, 0x0000000000000001, 0x000FFFFFFFFFFFFF, 0x0000000000E00000,
    };
#else
    vlong_unit tests[] = {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001,
        0xEFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xF0000000,
        0xDFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xE0000000,
        0xDFFFFFFF, 0xFFFFFFFF, 0x0000000F, 0xEEEEEEEE,
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF,
        0x00000000, 0x00000000, 0x00000001, 0x00000000,
        0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000,
        0xFFFFFFE0, 0x00000001, 0x000FFFFF, 0x00FE000F,
        0xC32DE9F9, 0x0000000E, 0xC0000000, 0x043D37F6
    };
#endif

    for (i = 0; i < COUNTOF(tests); i += 4)
    {
        vlong_unit res = VLONG_DoubleDiv( tests[i], tests[i+1], tests[i+2]);
        retVal += UNITTEST_TRUE(i, res == tests[i+3]);
    }

    return retVal;
}


/********************************************************************************/

int vlong_test_shift()
{
    int     i, sum;
    int     retVal = 0;
    vlong*  pOrigValue = NULL;
    vlong*  pShiftThis = NULL;
    vlong*  pReference = NULL;
    ubyte   tests[] = {
        0xc6, 0x63, 0x63, 0xa5, 0xf8, 0x7c, 0x7c, 0x84, 0xee, 0x77, 0x77, 0x99, 0xf6, 0x7b, 0x7b, 0x8d,
        0xff, 0xf2, 0xf2, 0x0d, 0xd6, 0x6b, 0x6b, 0xbd, 0xde, 0x6f, 0x6f, 0xb1, 0x91, 0xc5, 0xc5, 0x54,
        0x60, 0x30, 0x30, 0x50, 0x02, 0x01, 0x01, 0x03, 0xce, 0x67, 0x67, 0xa9, 0x56, 0x2b, 0x2b, 0x7d,
        0xe7, 0xfe, 0xfe, 0x19, 0xb5, 0xd7, 0xd7, 0x62, 0x4d, 0xab, 0xab, 0xe6, 0xec, 0x76, 0x76, 0x9a,
        0x8f, 0xca, 0xca, 0x45, 0x1f, 0x82, 0x82, 0x9d, 0x89, 0xc9, 0xc9, 0x40, 0xfa, 0x7d, 0x7d, 0x87,
        0xef, 0xfa, 0xfa, 0x15, 0xb2, 0x59, 0x59, 0xeb, 0x8e, 0x47, 0x47, 0xc9, 0xfb, 0xf0, 0xf0, 0x0b,
        0x41, 0xad, 0xad, 0xec, 0xb3, 0xd4, 0xd4, 0x67, 0x5f, 0xa2, 0xa2, 0xfd, 0x45, 0xaf, 0xaf, 0xea,
        0x23, 0x9c, 0x9c, 0xbf, 0x53, 0xa4, 0xa4, 0xf7, 0xe4, 0x72, 0x72, 0x96, 0x9b, 0xc0, 0xc0, 0x5b,
        0x75, 0xb7, 0xb7, 0xc2, 0xe1, 0xfd, 0xfd, 0x1c, 0x3d, 0x93, 0x93, 0xae, 0x4c, 0x26, 0x26, 0x6a,
        0x6c, 0x36, 0x36, 0x5a, 0x7e, 0x3f, 0x3f, 0x41, 0xf5, 0xf7, 0xf7, 0x02, 0x83, 0xcc, 0xcc, 0x4f
    };

    retVal += UNITTEST_STATUS(0, VLONG_vlongFromByteString(tests, 
                                                           sizeof(tests), 
                                                           &pShiftThis, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, VLONG_vlongFromByteString(tests, 
                                                           sizeof(tests), 
                                                           &pOrigValue, NULL));
    if (retVal) goto exit;

    /* make sure we parsed the test vectors correctly */

    retVal += UNITTEST_TRUE(0, 0x4f == (0xff & pShiftThis->pUnits[0]));
    if (retVal) goto exit;


    /* simple shift left test */
    for (i = 0; i < 66; i++)
    {
        retVal += UNITTEST_STATUS(i, VLONG_shlVlong(pShiftThis));
        if(retVal) goto exit;
    }

    retVal += UNITTEST_STATUS( 0, VLONG_makeVlongFromVlong( pShiftThis, 
                                                            &pReference, 
                                                            NULL));
    if (retVal) goto exit;

    /* shift back and forth */
    for (i = 1024; i >= 0; i--)
    {
        retVal += UNITTEST_STATUS(i, VLONG_shlXvlong(pShiftThis, i));
        if (retVal) goto exit;


        retVal += UNITTEST_STATUS(i, VLONG_shrXvlong(pShiftThis, i));
        if (retVal) goto exit;

        retVal += UNITTEST_TRUE(i, 0==VLONG_compareSignedVlongs( pShiftThis,
                                                                 pReference));
        if (retVal) 
        {
            print_vlong("ref = ", pReference);
            print_vlong("res = ", pShiftThis);
            goto exit;
        }
    }

    /* shift left only --- a little nastier test */
    sum = 0;
    for (i = 67; i >= 53; i--)
    {
        sum += i;
        retVal += UNITTEST_STATUS(i, VLONG_shlXvlong(pShiftThis, 2 * i));
        if (retVal) goto exit;
    }

    /* shift right only */
    retVal += UNITTEST_STATUS(0, VLONG_shrXvlong(pShiftThis, sum));
    if (retVal) goto exit;

    for (i = 67; i >= 53; i--)
    {
        retVal += UNITTEST_STATUS(i, VLONG_shrXvlong(pShiftThis, i));
        if (retVal) goto exit;
    }

    /* simple shift right test */
    for (i = 0; i < 66; i++)
    {
        retVal += UNITTEST_STATUS(i, VLONG_shrVlong(pShiftThis));
        if (retVal) goto exit;
    }

    retVal += UNITTEST_TRUE(0,0 == VLONG_compareSignedVlongs(pShiftThis, 
                                                             pOrigValue));
    if (retVal) goto exit;

exit:
    VLONG_freeVlong(&pOrigValue, NULL);
    VLONG_freeVlong(&pShiftThis, NULL);
    VLONG_freeVlong(&pReference, NULL);

    return retVal;
}


/*--------------------------------------------------------------------------*/

int vlong_test_shift_bug()
{
    vlong* pTest = 0;
    int retVal = 0;

    retVal += UNITTEST_STATUS( 0, VLONG_makeVlongFromUnsignedValue( 0, &pTest, 
                                                                    NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( 0, VLONG_shrXvlong( pTest, 512));
    if (retVal) goto exit;

    retVal += UNITTEST_TRUE( 0, pTest->numUnitsUsed == 0 );
    if (retVal) goto exit;

exit:
    
    VLONG_freeVlong( &pTest, NULL);
    
    return retVal;
}


/*--------------------------------------------------------------------------*/

int vlong_test_cmp()
{
    vlong* pA = 0;
    vlong* pB = 0;
    vlong* pC = 0;
    int retVal = 0;
    sbyte4 resCmp;

    retVal += UNITTEST_STATUS( 0, VLONG_makeVlongFromUnsignedValue( 123456, &pA, 
                                                                    NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( 0, VLONG_makeVlongFromUnsignedValue( 24, &pB, 
                                                                    NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( 0, VLONG_makeVlongFromUnsignedValue( 12, &pC, 
                                                                    NULL));
    if (retVal) goto exit;

    resCmp = compareUnsignedVlongs( pB, pC);
    retVal += UNITTEST_TRUE( 0, resCmp > 0 );
    
    resCmp = VLONG_compareSignedVlongs( pB, pC);
    retVal += UNITTEST_TRUE( 0, resCmp > 0 );

    /* subtract a big number to make them negative */
    VLONG_subtractSignedVlongs( pB, pA, NULL);
    VLONG_subtractSignedVlongs( pC, pA, NULL);

    resCmp = VLONG_compareSignedVlongs( pB, pC);
    retVal += UNITTEST_TRUE( 0, resCmp > 0 );

exit:
    
    VLONG_freeVlong( &pA, NULL);
    VLONG_freeVlong( &pB, NULL);
    VLONG_freeVlong( &pC, NULL);
    
    return retVal;
}


/*--------------------------------------------------------------------------*/

int vlong_test_blinding_factors()
{

    const sbyte* n = (sbyte*) 
"400F06FC034A993FC049AB92F8D65109D59B1BA042254B0FF29A16650A827553B078DF"
"222F1905E0ECEF6C9344094FA6AA2DBBBFE2505AD70F42D72E9DEF11DB987AA6D5B422"
"501F588C7E8496330686F3E69E69ABA975C2714A3B48F1DD9A0121DB68C41239595DBF"
"6AE8ADF742DABCA89AB04158E9A3D1BD8A801EB8608F75";

    const sbyte* p = (sbyte*)
"8014B803DDAB2FD1C9DEAB96EAF7ACB19D63877E2EA91A0B291DE33AB6811682D3E4C7"
"C7B99ED8697E71724005C649E51AB5DA69DCD7DDC6688EE08CBC6DE6B7";

    const sbyte* q = (sbyte*)
"800954718D80883FFD86A16C4E8311F37F96A390C42EA9B1EDD348F0935D7ECA304038"
"90AB3B8113B4A898035D75B015C37D6B3E54A1BCEFF1C16AFCE7E02F33";
    
    const sbyte* r = (sbyte*)
"7878787878787878787878787878787878787878787878787878787878787878787878"
"7878787878787878787878787878787878787878787878787878787878787878787878"
"7878787878787878787878787878787878787878787878787878787878787878787878"
"787878787878787878787878787878";

    const sbyte* re = (sbyte*)
"04175B89C710F18A56E74330AB2140AF3330D3C6F932EB58C614725666487A774793A8"
"E071D70108778A7E102D394FD51C151FD5771B2D9E8128EDC4B903004F0F53AF10D6E0"
"642423F3700475781FE4EDC0151C7ED6A2FB39A78DA5AB902971477055C5242EFB6D7D"
"0A5E8443105F74DA5EF093BA67C51D74245C138D5CE786";
    
    const sbyte* r1 = (sbyte*)
"0FD4C14557AB90C82F0A13B70E2FE097CC7AC2344B71F7E62588AD55C5AA9B6CDA06A1"
"8A8FAAF7BBE48EDC4FE128A6C60008991D5998828B073E939CBE9B8CAEA1A29C0F0631"
"069542BAFC18B57EF5C182E609572FB407D7CFD2AC999A301EFE76531DB0D2094DF45A"
"E9BE0F16C8CD887145D045CCC60E02ABDF911D02E3748A";

    int cmpRes, retVal = 0;
    vlong *pE = 0, *pN = 0, *pR = 0, *pR1 = 0, *pRE = 0;
    vlong *pER1 = 0, *pERE = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    VLONG_makeVlongFromUnsignedValue( 0x010001, &pE, NULL);
    MakeVlongFromString( n, &pN, NULL);
    MakeVlongFromString( r, &pR, NULL);
    MakeVlongFromString( re, &pERE, NULL);
    MakeVlongFromString( r1, &pER1, NULL);

    /* RE modular E exponent of R */
    retVal += UNITTEST_STATUS(0, 
            VLONG_modexp(MOC_MOD(hwAccelCtx) pR, pE, pN, &pRE, NULL));
    if (retVal) goto exit;
    
    /* R1 = modular inverse of r */
    retVal += UNITTEST_STATUS(0, 
            VLONG_modularInverse(MOC_MOD(hwAccelCtx) pR, pN, &pR1, NULL));
    if ( retVal) goto exit;
    
    retVal += UNITTEST_INT(0, 0,
            cmpRes = VLONG_compareSignedVlongs( pERE, pRE));

    if (cmpRes) print_vlong( "pRE = ", pRE); 

    retVal += UNITTEST_INT(0, 0,
            cmpRes = VLONG_compareSignedVlongs( pER1, pR1));

    if ( cmpRes) print_vlong( "pR1 = ", pR1); 

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    VLONG_freeVlong( &pE, NULL);
    VLONG_freeVlong( &pN, NULL);
    VLONG_freeVlong( &pR, NULL);
    VLONG_freeVlong( &pRE, NULL);
    VLONG_freeVlong( &pR1, NULL);
    VLONG_freeVlong( &pERE, NULL);
    VLONG_freeVlong( &pER1, NULL);

    return retVal;

}


/*--------------------------------------------------------------------------*/

static int
mpint_serialize_aux( int hint, const vlong* pTest) 
{
    vlong* pRead = 0;
    ubyte* pBuffer = 0;
    ubyte4 buffLen, read;
    int retVal = 0;

    retVal += UNITTEST_STATUS(  hint,
                                VLONG_mpintByteStringFromVlong( pTest, &pBuffer, 
                                                                &buffLen));
    if ( retVal) goto exit;

    retVal += UNITTEST_STATUS( hint,
                               VLONG_newFromMpintBytes( pBuffer, buffLen, 
                                                        &pRead, &read, NULL));
    if ( retVal) goto exit;

    retVal += UNITTEST_INT( hint, buffLen, read);
    retVal += UNITTEST_INT( hint, 0, VLONG_compareSignedVlongs( pTest, pRead));

exit:   

    VLONG_freeVlong( &pRead, NULL);

    if (pBuffer)
    {
        FREE( pBuffer);
    }
    return retVal;
    
}


/*--------------------------------------------------------------------------*/

int vlong_test_mpint_serialize()
{
    /* test the mpint routines -- also tested with the old
       RSA key blobs which uses this format internally */
    int i, k, retVal = 0;
    vlong* pTest = 0;
    
    retVal += UNITTEST_STATUS( 0, VLONG_allocVlong(&pTest, 0));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS( 0, VLONG_setVlongUnit( pTest, 0, FULL_MASK));
    if (retVal) goto exit;

    for (k = 0; k < 2; ++k)
    {
        pTest->negative = k ? TRUE : FALSE;

        for (i = 0; i <= 0xFF; ++i)
        {
            retVal += UNITTEST_STATUS( i, VLONG_setVlongUnit( pTest, 1, i));
            if (retVal) goto exit;

            retVal += mpint_serialize_aux( ((k << 16) | i), pTest);
        }
    }
    
exit:   

    VLONG_freeVlong( &pTest, NULL);

    return retVal;
}


/*--------------------------------------------------------------------------*/

typedef struct mpint_test
{
    ubyte4  representation_length;
    ubyte*  representation;
    ubyte   negative;
    ubyte*  data;
} mpint_test;

int vlong_test_mpint_serialize_2()
{
    /* test the mpint routines -- also tested with the old
       RSA key blobs which uses this format internally */
    int retVal = 0;
    vlong* pTest = 0;
    vlong* pBack = 0;
    ubyte* pBuffer = 0;
    ubyte4 buffLen, bytesUsed;
    sbyte4 cmpRes;
    int i;
    MSTATUS status;

    /* http://tools.ietf.org/html/rfc4251#section-5
    value (hex)        representation (hex)
     -----------        --------------------
     0                  00 00 00 00
     9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
     80                 00 00 00 02 00 80
     -1234              00 00 00 02 ed cc
     -deadbeef          00 00 00 05 ff 21 52 41 11
    */
    
    static const mpint_test mpint_tests[] =
    {
        {4, "\x000\x000\x000\x000", 0, "0" },
        {12, "\x000\x000\x000\x008\x009\x0a3\x078\x0f9\x0b2\x0e3\x032\x0a7", 
        0, "9a378f9b2e332a7" },
        {6, "\x000\x000\x000\x002\x000\x080", 0, "80"},
        {6, "\x000\x000\x000\x002\x0ed\x0cc", 1, "1234"},
        {9, "\x000\x000\x000\x005\x0ff\x021\x052\x041\x011", 1, "deadbeef"},        
    };

    for (i = 0; i < COUNTOF(mpint_tests); ++i)
    {
        MakeVlongFromString( mpint_tests[i].data, &pTest, NULL);
        pTest->negative = (mpint_tests[i].negative)? TRUE : FALSE;

        if ( pBuffer)
        {
            FREE(pBuffer);
            pBuffer = 0;
        }
        retVal += UNITTEST_STATUS( i,
                                   status = VLONG_mpintByteStringFromVlong( 
                                       pTest, &pBuffer, &buffLen));
        if ( OK > status ) continue;

        retVal += UNITTEST_INT( i, buffLen, mpint_tests[i].representation_length);
        DIGI_MEMCMP(pBuffer, mpint_tests[i].representation, buffLen, &cmpRes);
        retVal += UNITTEST_INT( i, cmpRes, 0);

        /* convert back */
        retVal += UNITTEST_STATUS(i, 
                                  status = VLONG_newFromMpintBytes( 
                                      mpint_tests[i].representation,
                                      mpint_tests[i].representation_length,
                                      &pBack, &bytesUsed, NULL));
        if (OK > status) continue;

        retVal += UNITTEST_INT(i, bytesUsed, mpint_tests[i].representation_length);
        retVal += UNITTEST_INT(i, VLONG_compareSignedVlongs( pTest, pBack), 0);

        VLONG_freeVlong( &pBack, NULL);
        VLONG_freeVlong( &pTest, NULL);
    }

    VLONG_freeVlong( &pBack, NULL);
    VLONG_freeVlong( &pTest, NULL);

    if ( pBuffer)
    {
        FREE( pBuffer);
    }
    
    return retVal;
}


int vlong_test_vlongFromUByte4String()
{
    int retval = 0;

    ubyte4 a[] = { 0xffff4455 };
    ubyte4 b[] = { 0x12345678 };
    ubyte4 ab[] = { 0x1234491F, 0x9BE095D8 }; /* a*b */
    ubyte4 abb[] = { 0x14B65E9, 0x2C745956, 0x237CCD40 }; /* a*b*b */
    ubyte4 abba[] = { 0x14B64F6, 0x3BA5F31C, 0x748334CA, 0x21B52640 }; /* a*b*b*a */
    ubyte4 babba[] = { 0x1790D9, 0xC177D443, 0x176E68D7, 0xA0AA3B8E, 0xECC36E00 }; /* b*a*b*b*a */

    vlong *pa, *pb, *pab, *pabb, *pabba, *pbabba, *pr;

    pa = pb = pab = pabb = pabba = pbabba = pr = (vlong*) 0;


    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( a, 1, &pa));
    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( b, 1, &pb));
    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( ab, 2, &pab));
    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( abb, 3, &pabb));
    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( abba, 4, &pabba));
    retval += UNITTEST_STATUS(0, VLONG_vlongFromUByte4String( babba, 5, &pbabba));

    retval += UNITTEST_STATUS(0, VLONG_allocVlong( &pr, NULL));

    retval += UNITTEST_STATUS(0, VLONG_unsignedMultiply( pr, pa, pb));
    retval += UNITTEST_INT(0, VLONG_compareSignedVlongs( pr, pab), 0);

    retval += UNITTEST_STATUS(0, VLONG_unsignedMultiply( pr, pab, pb));
    retval += UNITTEST_INT(0, VLONG_compareSignedVlongs( pr, pabb), 0);

    retval += UNITTEST_STATUS(0, VLONG_unsignedMultiply( pr, pabb, pa));
    retval += UNITTEST_INT(0, VLONG_compareSignedVlongs( pr, pabba), 0);

    retval += UNITTEST_STATUS(0, VLONG_unsignedMultiply( pr, pabba, pb));
    retval += UNITTEST_INT(0, VLONG_compareSignedVlongs( pr, pbabba), 0);

    VLONG_freeVlong(&pa, NULL);
    VLONG_freeVlong(&pb,  NULL);
    VLONG_freeVlong(&pab,  NULL);
    VLONG_freeVlong(&pabb,  NULL);
    VLONG_freeVlong(&pabba,  NULL);
    VLONG_freeVlong(&pbabba, NULL);
    VLONG_freeVlong(&pr, NULL);
 
    return retval;
}

int test_bad_vlong_input()
{
    int retval = 0;

    ubyte   a[] = { 0xff, 0xff, 0xff, 0xfe, 0x00 };
    ubyte   b[] = { 0x80, 0x00, 0x00, 0x00, 0x00 };
    ubyte   c[] = { 0x00, 0x00, 0x00, 0x01, 0xff };
    ubyte   d[] = { 0x00, 0x00, 0x00, 0x01, 0x00 };
    ubyte   e[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
    ubyte4  length = 0;
    vlong*  pTest = NULL;

    UNITTEST_GOTO((OK <= VLONG_newFromMpintBytes(a, sizeof(a), &pTest, &length, NULL)),
                  retval, exit);
    VLONG_freeVlong(&pTest, NULL);

    UNITTEST_GOTO((OK <= VLONG_newFromMpintBytes(b, sizeof(b), &pTest, &length, NULL)),
                  retval, exit);
    VLONG_freeVlong(&pTest, NULL);

    UNITTEST_GOTO((OK > VLONG_newFromMpintBytes(c, sizeof(c), &pTest, &length, NULL)),
                  retval, exit);
    VLONG_freeVlong(&pTest, NULL);

    UNITTEST_GOTO((OK > VLONG_newFromMpintBytes(d, sizeof(d), &pTest, &length, NULL)),
                  retval, exit);
    VLONG_freeVlong(&pTest, NULL);

    UNITTEST_GOTO((OK > VLONG_newFromMpintBytes(e, sizeof(e), &pTest, &length, NULL)),
                  retval, exit);

exit:
    VLONG_freeVlong(&pTest, NULL);

    return retval;
}


/*--------------------------------------------------------------------------*/

int vlong_test_modular_inverse()
{
    const sbyte* e = (sbyte*)
"0000000000000000000000000000000000000000000000000000000000000000000000"
"0000000000000000000000000000000000000000000000000000000000000000000000"
"0000000000000000000000000000000000000000000000000000000000000000000000"
"0000000000000000000000000000000000000000010001";

    const sbyte* p = (sbyte*)
"F312951AD08ABC360C6B995AA6C8464F18C0AF5C5CF83B5BAF49AF1295B54FC11DA046"
"F8663F68BDBD52C8361DDDDFCDD77617C6DD74E2BEDD4F98A85863EA71";

    const sbyte* q = (sbyte*)
"C8D1D88C8318DF27E59E88BAC570FFCD60621600A2499FE8A16B19196B349084012BBE"
"04A3264D11C178DF8C653AAD002CE92A35071BD86065F08307D8EB8523";

    const sbyte* d = (sbyte*)
"7211b6071fd24edde33bd9683515f5c5c8841b27a0af0aa90e015e552bd248dd2e0a90"
"82e90f7fd7758c4c06fe7f7351af7163a8fde0e88bcbacb4d2e20516ca9c1245270ee3"
"1706e482143ea0080af2f2d6800452c133eb866bad47ec1df50d775da893390be79c5a"
"ddea712fcc02568be1838e594e760cdeca2e98fab92d41";

    int cmpRes, retVal = 0;
    vlong *pE = 0, *pP = 0, *pQ = 0, *pP_1_N_1 = 0, *pD_answer = 0, *pD = 0;
    vlong *pQueue = 0;
    vlong* vModulus = 0;
    vlong* vA = 0;
    vlong* vInv = 0;

    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    VLONG_allocVlong(&pP_1_N_1, &pQueue);
    MakeVlongFromString(e, &pE, &pQueue);
    MakeVlongFromString(p, &pP, &pQueue);
    MakeVlongFromString(q, &pQ, &pQueue);
    MakeVlongFromString(d, &pD_answer, &pQueue);

    /* calculate ((p-1) * (n-1))*/
    VLONG_decrement(pP, &pQueue); 
    VLONG_decrement(pQ, &pQueue); 
    VLONG_vlongSignedMultiply(pP_1_N_1, pP, pQ);
    
    /* d = e^-1 mod ((p-1)(q-1)) */
    retVal += UNITTEST_STATUS(0, 
            VLONG_modularInverse(MOC_MOD(hwAccelCtx) pE, pP_1_N_1, &pD, &pQueue));
    if ( retVal) goto exit;
    
    retVal += UNITTEST_INT(0, 0,
            cmpRes = VLONG_compareSignedVlongs( pD, pD_answer));

    if (cmpRes) print_vlong( "pD = ", pD); 
    if (cmpRes) print_vlong( "pD_answer = ", pD_answer); 


#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if ( 0 == retVal)
    {
        struct tms tstart, tend;
        double diffTime;
        int i;
        randomContext* pRandomContext;
        ubyte buffer[512];
        
        RANDOM_acquireContext( &pRandomContext);

        RANDOM_numberGenerator(pRandomContext, buffer, 512);
        VLONG_vlongFromByteString(buffer, 512, &vModulus, &pQueue);

        RANDOM_numberGenerator(pRandomContext, buffer, 512);
        VLONG_vlongFromByteString(buffer, 512, &vA, &pQueue);
        
        RANDOM_releaseContext( &pRandomContext);

        if ( VLONG_compareSignedVlongs( vA, vModulus) > 0)
        {
            VLONG_subtractSignedVlongs(vA, vModulus, &pQueue);
        }

        vModulus->pUnits[0] |= 1; /* make sure it's odd */

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            VLONG_modularInverse(MOC_MOD(hwAccelCtx) vA, vModulus, &vInv, &pQueue);
            VLONG_freeVlong(&vInv, &pQueue);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\t%d modular inversions (odd) in %g seconds of CPU time\n", i, diffTime);
        printf("vlong: %g modular inversions/second (CPU time)\n", i/diffTime);

        vModulus->pUnits[0] -= (vlong_unit) 1; /* make sure it's even */

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            VLONG_modularInverse(MOC_MOD(hwAccelCtx) vA, vModulus, &vInv, &pQueue);
            VLONG_freeVlong(&vInv, &pQueue);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\t%d modular inversions (even) in %g seconds of CPU time\n", i, diffTime);
        printf("vlong: %g modular inversions/second (CPU time)\n", i/diffTime);


    }
#endif


exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    VLONG_freeVlong( &pP_1_N_1, 0);
    VLONG_freeVlong( &pE, 0);
    VLONG_freeVlong( &pP, 0);
    VLONG_freeVlong( &pQ, 0);
    VLONG_freeVlong( &pD, 0);
    VLONG_freeVlong( &pD_answer, 0);
    VLONG_freeVlong( &vInv, 0);
    VLONG_freeVlong( &vModulus, 0);
    VLONG_freeVlong( &vA, 0);
    VLONG_freeVlongQueue( &pQueue);    

    return retVal;
}


/*--------------------------------------------------------------------------*/

typedef struct ModExpTestVector
{
    const char* x;
    const char* e;
    const char* n;
    const char* res;  /* res = x ^^ e mod n */
} ModExpTestVector;

const ModExpTestVector gModExpTestVectors[] = 
{
    {
        "FFCE117833BE916D",
        "DC65385C4C011E0F",
        "7194E1713004783D",
        "06D3CC9455DCE7C9",
    },
    {
        "0E7C94C71189E0A4D050E6546D",
        "0583DF1E7ADC65385C4C011E0F",
        "160F7C79EB7194E1713004783D",
        "01",
    },
    {
        "0E223261E1FFCE117833BE916D",
        "0583DF1E7ADC65385C4C011E0F",
        "160F7C79EB7194E1713004783D",
        "126E213D7A52782D573E8264B9",
    },
    {
        "09E34EE9A24146F1FFA1A328D7",
        "0583DF1E7ADC65385C4C011E0F",
        "160F7C79EB7194E1713004783D",
        "160F7C79EB7194E1713004783C",
    },
    {
        "40E3FF41CAD6C1F2B10718EB8EF764D019C58807F390079B"
        "C9CEE87B00406B86104896A3C47DC13D1BF24494E85EF8C8"
        "AAAF7E496726B4E6E25626F1FA8662EF",
        "16558FFF21B9BE491FEDEAB372BF878F6A4F55689429BA98"
        "1CC44D983F897B0A0E414EBD0D2985FA8F7DBBE01CFA4F93"
        "91C576F17437AE0E7D328570DD0447C9",
        "B2AC7FF90DCDF248FF6F559B95FC3C7B527AAB44A14DD4C0"
        "E6226CC1FC4BD850720A75E8694C2FD47BEDDF00E7D27C9C"
        "8E2BB78BA1BD7073E9942B86E8223E49",
        "4F283C4DF4054105BC0C71425CF76BE2D7FE85AFFE2C9B38"
        "8CC3E33AC1DDD5D9E61540485461911439CA5463ACA38F42"
        "675541C514AB3116FA0DE3CFCE59747F"
    },
    {
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF0041747461636B206174"
        "206461776E2100",
        "7C61500F3307AB56E3A99F2C158A20BB048978F9172E99FE"
        "ECDF6B69501471BF6D72D24EC8B802B5F4F7931E173F8A9F"
        "7B198B8416D0C378EFFE328BB80730C49AB32A69703B2B67"
        "7B3784ACD14467A9DA14ADE834D0F4731E1CA74A41123D5B"
        "E85E5024FE0BF00693F424F4BAF06C2D3C2AE656572CFABF"
        "A7E31367C8E4DD3890989FCE5CB71C2CAAB8C22F8B654A38"
        "36CEBE88D6ED16421C5235583759D940B2A7045BF7ABBEB8"
        "651D6B204587D1F3A9200BA3A29D0489994C5740A0897008"
        "B2BEB6786891C15BE46BB1764E721543E5ED140CEFBA13CB"
        "08EFDC6D09A9B641B1D8841E79EC626A11DD32F463C3D00A"
        "D77DF2508FD97069A221602EB7DBCC29",
        "D4EBFEEEFB868E3BBF4648D8420DE5A951E76DDE75AFD1A8"
        "275C77C7B17456427D23C27DD71F2F0903018671A39931FC"
        "06B1980B247D3F3734049E172084832436671E7151E7A170"
        "4DAAFEEEAE3DBD47B8BC243FAD5BAC0A49C49A6EBCA736F4"
        "22BBA9E52FDB80E9B1460EC53C308394F57D38BD5AFD867D"
        "91FAAC2A7342590D47659DC6CA686D95377BD8CA4D39BB59"
        "6C743A0A0A41D55BF2C31B6EAF87DABB26C152F6BEDE350A"
        "8993084D927167E239515EF38CFD81BE221DB180AE3F2E6B"
        "CF954926007142FC9695E0EECCFEC486E1CF0309331B99A5"
        "171A38BCC5559E3BEA3E0A5F0C22BF499C63363A4D08B7E8"
        "15ABB43DBF6439795EC951202D6F1BEF",
        "C19E4D01382E2C4A21093CB7E8E03D1D3D30BDCC46F4E4B3"
        "310FC44698D44BF8A82ACB37F37840426BA1EAA2844A574E"
        "0CF10DCEA6679E9D9D5B0B33BC4DD0DE91BA46D4B27C475A"
        "B8D76FAE7878E9D9E80C2241CA20BF786B50B94DE9A561AA"
        "168616FBEF9ABCC85AFB303C7BF5261AC677E9FD0B731A0F"
        "0092047EFC9105A41220B10F57F9B1B01C832872D9C1D5E1"
        "D15237F31C4D01206AE8EC2582E42B5C42EA9C9238C3CA45"
        "6E6A492E7A502D523109F3437525C42AEBA5F4B783BC9109"
        "D91AA629A722413D1C0DEB83C2A6FA7656BF647B6DB5F46E"
        "E07E3FD4EF2EAE923B0023F83D084BAABB447554CEDF5576"
        "CA1934BA47A08C8FEDB189119B5A49CB",
    }
};


/*--------------------------------------------------------------------------*/

int mod_exp_test_vector(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const ModExpTestVector* pTestVector, vlong** ppQueue)
{
    int retVal = 0;
    vlong* e = 0;
    vlong* x = 0;
    vlong* n = 0;
    vlong* exp_res = 0;
    vlong* res = 0;
    vlong* res2 = 0;


    MakeVlongFromString( pTestVector->e, &e, ppQueue);
	MakeVlongFromString( pTestVector->n, &n, ppQueue);
	MakeVlongFromString( pTestVector->x, &x, ppQueue);
    MakeVlongFromString( pTestVector->res, &exp_res, ppQueue);

    retVal = UNITTEST_STATUS( hint, VLONG_modexp_montgomery( MOC_MOD(hwAccelCtx) x, e, n, &res2, ppQueue));
    if (0 == retVal)
    {
        retVal = UNITTEST_TRUE( hint, 0 == VLONG_compareSignedVlongs( res2, exp_res));
    }

    VLONG_freeVlong(&e, ppQueue);
    VLONG_freeVlong(&n, ppQueue);
    VLONG_freeVlong(&x, ppQueue);
    VLONG_freeVlong(&res, ppQueue);
    VLONG_freeVlong(&res2, ppQueue);
    VLONG_freeVlong(&exp_res, ppQueue);

    return retVal;

}


/*--------------------------------------------------------------------------*/

int vlong_test_mod_exp()
{
    int retVal = 0, i;
    vlong *pQueue = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for (i = 0; i < COUNTOF(gModExpTestVectors); ++i)
    {
        retVal += mod_exp_test_vector(MOC_MOD(hwAccelCtx) i, gModExpTestVectors + i, &pQueue);
    }

    VLONG_freeVlongQueue( &pQueue);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return retVal;
}

static vlong_unit gRhoTestVectors[] = 
{
    FULL_MASK,
#ifdef __ENABLE_DIGICERT_64_BIT__
    0x5123456789ABCDEFULL,
    0x8789454523442341ULL,
#else
    0x12345679,
    0x9ABCDEF1,
    0x43565645,
    0x34282427,
    0x2324FFAB,
    0xFFABFFAB,
    0x4FFBB237,
#endif
};


/*--------------------------------------------------------------------------*/

int vlong_test_rho()
{
    int retVal = 0;
#ifndef __ALTIVEC__
    int i;
    vlong *pQueue = 0;
    vlong *pA = 0;
    vlong *pModInv = 0;
    vlong *pRho = 0;
    vlong *pBeta = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    VLONG_allocVlong( &pBeta, &pQueue);
    VLONG_setVlongUnit( pBeta, 0, 0);
    VLONG_setVlongUnit( pBeta, 1, 1);
    
    VLONG_makeVlongFromUnsignedValue(gRhoTestVectors[0], &pA, &pQueue);


    for (i = 0; i < COUNTOF(gRhoTestVectors); ++i)
    {
        vlong_unit rho;

        VLONG_setVlongUnit( pA, 0, gRhoTestVectors[i]);
        rho = VLONG_rho( pA);
        
        VLONG_modularInverse(MOC_MOD(hwAccelCtx) pA, pBeta, &pModInv, &pQueue);
        VLONG_makeVlongFromVlong( pBeta, &pRho, &pQueue);
        subtractUnsignedVlongs( pRho, pModInv);

        retVal += UNITTEST_TRUE( i, 0 == VLONG_getVlongUnit(pRho, 1));
        retVal += UNITTEST_TRUE( i, rho == VLONG_getVlongUnit(pRho, 0));

        VLONG_freeVlong(&pRho, &pQueue);
        VLONG_freeVlong(&pModInv, &pQueue);
    }

    VLONG_freeVlong(&pA, 0);
    VLONG_freeVlong(&pBeta, 0);
 
    VLONG_freeVlongQueue( &pQueue);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

#endif
    
    return retVal;
}


/*--------------------------------------------------------------------------*/

typedef struct MontyMultVector
{
    const char* modulus;
    const char* exp_r;
    const char* exp_r1;
    const char* x;
    const char* y;
    const char* result;
} MontyMultVector;

const MontyMultVector gMontyMultVectors[] = 
{
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "26006623378A6066",
        "26006623378A6066",
        "0E5B3EFB0DC73813"
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "63D3C0E639CFD944",
        "0E5B3EFB0DC73813",
        "68F81A85FB53A486",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "68F81A85FB53A486",
        "0E5B3EFB0DC73813",
        "62E16C129E925690",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "8E6B1E8ECFFB87C3",
        "8E6B1E8ECFFB87C3",
        "1CD63D1D9FF70F86",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "1CD63D1D9FF70F86",
        "1CD63D1D9FF70F86",
        "1CD63D1D9FF70F86",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "1CD63D1D9FF70F86",
        "63D3C0E639CFD944",
        "63D3C0E639CFD944",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "63D3C0E639CFD944",
        "63D3C0E639CFD944",
        "2284BC3299FD5FBC",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "2284BC3299FD5FBC",
        "2284BC3299FD5FBC",
        "5862AEBAFB7E199D",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "5862AEBAFB7E199D",
        "5862AEBAFB7E199D",
        "402A72DEE291950C",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "402A72DEE291950C",
        "402A72DEE291950C",
        "174C83EB56F262D7",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "174C83EB56F262D7",
        "62E16C129E925690",
        "70D73088F51A5AC2",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "70D73088F51A5AC2",
        "70D73088F51A5AC2",
        "6186EB3144DDA0BA",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "6186EB3144DDA0BA",
        "6186EB3144DDA0BA",
        "66106C17436F42A7",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "66106C17436F42A7",
        "66106C17436F42A7",
        "696DBF27CDA0E306",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "696DBF27CDA0E306",
        "696DBF27CDA0E306",
        "08862580E3950612",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "08862580E3950612",
        "08862580E3950612",
        "6C3345EE5F4DB2F0",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "6C3345EE5F4DB2F0",
        "63D3C0E639CFD944",
        "546F38502F296532",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "546F38502F296532",
        "546F38502F296532",
        "461496EE5EB7134C",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "461496EE5EB7134C",
        "461496EE5EB7134C",
        "5327DB5B5D2169C7",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "5327DB5B5D2169C7",
        "5327DB5B5D2169C7",
        "6CB3431D52B163BF",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "6CB3431D52B163BF",
        "6CB3431D52B163BF",
        "01FB3D9E84639488",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "01FB3D9E84639488",
        "01FB3D9E84639488",
        "16382FDE089B4519",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "16382FDE089B4519",
        "68F81A85FB53A486",
        "6EA0000AB72B96BC",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "6EA0000AB72B96BC",
        "6EA0000AB72B96BC",
        "210AA5050029A0B1",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "210AA5050029A0B1",
        "210AA5050029A0B1",
        "5F40A5D62C90CC17",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "5F40A5D62C90CC17",
        "5F40A5D62C90CC17",
        "5824090955B954EE",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "5824090955B954EE",
        "5824090955B954EE",
        "64A196749CA8A6D9",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "64A196749CA8A6D9",
        "64A196749CA8A6D9",
        "31BD9E15338F25C3",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "31BD9E15338F25C3",
        "62E16C129E925690",
        "224EA233ADFFE302",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "224EA233ADFFE302",
        "224EA233ADFFE302",
        "370F6AADA208EF0A",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "370F6AADA208EF0A",
        "370F6AADA208EF0A",
        "3F6A406F0697DDDE",
    },
    {
        "7194E1713004783D",
        "010000000000000000",
        "08E3B9AB208F9BFD",
        "26006623378A6066",
        "0E5B3EFB0DC73813",
        "63D3C0E639CFD944",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "F4CE7BB74F1960690F642FE4",
        "F4CE7BB74F1960690F642FE4",
        "067DB7047A222FFD7EC3840D0F",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "01937350118F7347F750B2B244",
        "0C06DEF7101F0CD7C7D0A526F5",
        "0700A4564CF643417BABD6D783",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "0700A4564CF643417BABD6D783",
        "0C06DEF7101F0CD7C7D0A526F5",
        "01094F86256204C1E4E72450DB",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "01094F86256204C1E4E72450DB",
        "0C06DEF7101F0CD7C7D0A526F5",
        "03DBA70285584FBA5C518A7507",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "03DBA70285584FBA5C518A7507",
        "0C06DEF7101F0CD7C7D0A526F5",
        "02FCD94F4E315CD2751FDA468E",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "02FCD94F4E315CD2751FDA468E",
        "0C06DEF7101F0CD7C7D0A526F5",
        "020364819BECFED4B3482CC22D",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "020364819BECFED4B3482CC22D",
        "0C06DEF7101F0CD7C7D0A526F5",
        "0648A208611DA928E3B36A3277",
    },
    {
        "160F7C79EB7194E1713004783D",
        "0100000000000000000000000000000000",
        "0714208ED5B1E8B74AB3E77147",
        "0648A208611DA928E3B36A3277",
        "0C06DEF7101F0CD7C7D0A526F5",
        "091645621025C69204BB2C8730",
    },
    {
        "B2AC7FF90DCDF248FF6F559B95FC3C7B527AAB44A14DD4C0"
        "E6226CC1FC4BD850720A75E8694C2FD47BEDDF00E7D27C9C"
        "8E2BB78BA1BD7073E9942B86E8223E49",
        "010000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000",
        "3695E6196F2597EF28EA2A1FAABAD0ED1F8B3DAF2F81F635"
        "A2DE1787455A85479939977E7F95AF6D865CE230FA2EC8BE"
        "54E3D0ECAFE75CF1886FBEA43A355CB0",
        "A494167BB50470DB64A7E0AB434B25941DD7A251E8CB8543"
        "62904B89267B5BFCD057EC579539516DB1EF9374E5731939"
        "D4FE52AD15DEAC4D54CD76DC23D3716D",
        "A494167BB50470DB64A7E0AB434B25941DD7A251E8CB8543"
        "62904B89267B5BFCD057EC579539516DB1EF9374E5731939"
        "D4FE52AD15DEAC4D54CD76DC23D3716D",
        "5EEEF52B85852F64957AE57A094A12D105A3E5B70438DFB6"
        "3197B7251E897A2A6C9166C01648856327CA71782D6DEC38"
        "9D23F0E7C69A95FDB940CF569CDDBB9E"
    }
};


/*--------------------------------------------------------------------------*/

int montgomery_mult_vector_test(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const MontyMultVector* pVector,
                                  vlong** ppVlongQueue)
{
    int retVal = 0;
    MontgomeryCtx me = {0};
    MontgomeryWork mw = {{0}};
    vlong* pModulus = 0;
    vlong* pR1 = 0;
    vlong* pR = 0;
    vlong* pX = 0;
    vlong* pY = 0;
    vlong* pExpRes = 0;
    int doSquare = 0;
    MSTATUS status;

    MakeVlongFromString( pVector->modulus, &pModulus, ppVlongQueue);
    MakeVlongFromString( pVector->exp_r, &pR, ppVlongQueue);
    MakeVlongFromString( pVector->exp_r1, &pR1, ppVlongQueue);
    MakeVlongFromString( pVector->x, &pX, ppVlongQueue);
    MakeVlongFromString( pVector->y, &pY, ppVlongQueue);
    MakeVlongFromString( pVector->result, &pExpRes, ppVlongQueue);

    doSquare = ( 0 == VLONG_compareSignedVlongs(pX, pY));

    retVal = UNITTEST_STATUS( hint, VLONG_initMontgomeryCtx(MOC_MOD(hwAccelCtx) &me, pModulus, ppVlongQueue));
    if (retVal) goto exit;

    retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( MONTY_N(&me), pModulus));
    retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( MONTY_R(&me), pR));
    retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( MONTY_R1(&me), pR1));

    if (OK > ( status = VLONG_initMontgomeryWork(&mw, &me, ppVlongQueue)))
    {
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }


    if (UNITTEST_STATUS( hint, VLONG_montyMultiply( &me, pX, pY, &mw)))
    {
        retVal++; goto exit;
    }

    retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( pX, pExpRes));

    if ( doSquare)
    {
        if (UNITTEST_STATUS( hint, VLONG_montySqr( &me, pY, &mw)))
        {
            retVal++; goto exit;
        }
        retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( pY, pExpRes));
    }

exit:

    VLONG_cleanMontgomeryCtx(&me, ppVlongQueue);
    VLONG_cleanMontgomeryWork(&mw, ppVlongQueue);
    VLONG_freeVlong(&pModulus, ppVlongQueue);
    VLONG_freeVlong(&pR1, ppVlongQueue);
    VLONG_freeVlong(&pR, ppVlongQueue);
    VLONG_freeVlong(&pX, ppVlongQueue);
    VLONG_freeVlong(&pY, ppVlongQueue);
    VLONG_freeVlong(&pExpRes, ppVlongQueue);

    return retVal;
}


/*--------------------------------------------------------------------------*/

int vlong_test_montgomery_mult_vectors()
{
    int retVal = 0, i;
    vlong *pQueue = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;
    
    for (i = 0; i < COUNTOF(gMontyMultVectors); ++i)
    {
        retVal += montgomery_mult_vector_test(MOC_MOD(hwAccelCtx) i, gMontyMultVectors + i, &pQueue);
    }

    VLONG_freeVlongQueue( &pQueue);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*--------------------------------------------------------------------------*/

static MultTest mModInvTests[] =
{
    {
        "B2AC7FF90DCDF248FF6F559B95FC3C7B527AAB44A14DD4C0"
        "E6226CC1FC4BD850720A75E8694C2FD47BEDDF00E7D27C9C"
        "8E2BB78BA1BD7073E9942B86E8223E49",
        "010000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000",
        "3695E6196F2597EF28EA2A1FAABAD0ED1F8B3DAF2F81F635"
        "A2DE1787455A85479939977E7F95AF6D865CE230FA2EC8BE"
        "54E3D0ECAFE75CF1886FBEA43A355CB0",
    }
};


/*--------------------------------------------------------------------------*/

int modular_inverse_vector_test(MOC_MOD(hwAccelDescr hwAccelCtx) int hint, const MultTest* pVector,
                                  vlong** ppVlongQueue)
{
    int retVal = 0;
    vlong* pModulus = 0;
    vlong* pR1 = 0;
    vlong* pR = 0;
    vlong* pExpRes = 0;

    MakeVlongFromString( pVector->mul1, &pModulus, ppVlongQueue);
    MakeVlongFromString( pVector->mul2, &pR, ppVlongQueue);
    MakeVlongFromString( pVector->res, &pR1, ppVlongQueue);

    retVal = UNITTEST_STATUS( hint, VLONG_modularInverse(MOC_MOD(hwAccelCtx) pR, pModulus, &pExpRes, ppVlongQueue));
    if (retVal) goto exit;

    retVal += UNITTEST_TRUE(hint, 0 == VLONG_compareSignedVlongs( pExpRes, pR1));


exit:

    VLONG_freeVlong(&pModulus, ppVlongQueue);
    VLONG_freeVlong(&pR1, ppVlongQueue);
    VLONG_freeVlong(&pR, ppVlongQueue);
    VLONG_freeVlong(&pExpRes, ppVlongQueue);

    return retVal;
}


/*--------------------------------------------------------------------------*/

int vlong_test_modular_inverse2()
{

    int retVal = 0, i;
    vlong *pQueue = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for (i = 0; i < COUNTOF(mModInvTests); ++i)
    {
        retVal += modular_inverse_vector_test(MOC_MOD(hwAccelCtx) i, mModInvTests + i, &pQueue);
    }

    VLONG_freeVlongQueue( &pQueue);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}
