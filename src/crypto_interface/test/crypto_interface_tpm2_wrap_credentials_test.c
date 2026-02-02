/*
 * crypto_interface_tpm2_wrap_credentials_test.c
 *
 * Wraps secret using data from CSR request
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

#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs7.h"
#include "../../smp/smp_tpm2/tpm2_lib/tools/tpm2_server_helpers.h"
#include <stdio.h>
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)

static const sbyte *gpRSASampleCSR =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIMfQYJKoZIhvcNAQcCoIIMbjCCDGoCAQMxDzANBglghkgBZQMEAgEFADCCCsEG\n"
    "CCsGAQUFBwwCoIIKswSCCq8wggqrMDYwHgIBZQYKKwYBBAHwVRQBATENEwtUUE0y\n"
    "LUFUVEVTVDAUAgFmBggrBgEFBQcHHDEFMAMCAWcwggP2oIID8gIBATCCA+swggLT\n"
    "AgEAMIGTMSUwIwYDVQQDExwzSEUxNjczMUFBLUZYMlNCUjMwMjAtSURFVklEMREw\n"
    "DwYDVQQKEwhEaWdpQ2VydDETMBEGA1UEBRMKRlgyU0JSMzAyMDEUMBIGA1UECxML\n"
    "RW5naW5lZXJpbmcxEjAQBgNVBAcTCVN1bm55dmFsZTELMAkGA1UECBMCQ0ExCzAJ\n"
    "BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWsUIsuk\n"
    "jyCnek16E1EDsmlgPHHXOUiMiwm8Y+onzzdizhr1HVEFYLKDRrCfSMKotCJ1ZxV0\n"
    "F2+hlp+ueVZd92SixJTKbEAH9hGsyFoA/3odBnoYrKzI4dr8YsByyaDpX7pQaIkF\n"
    "aBS/BLSbCyYQW7pwmXeWQNMCI6Ob8/cWunCLnmBSWFRhDfuHSTzSm38CDd6Xcvqg\n"
    "pCoqrSQmhLvB9m4ytYb2Tjbduj8vzo9R9kKmZ5BdvkYultIcN9nOAk3r7ZM+0J+p\n"
    "K3nw/1mEZ86D3latBO81aXyDtgFdKJR9nZTXw3ueotmED6ybkpe/y++Wl4MXmoIy\n"
    "IlG+q/3FFX81LwIDAQABoIIBEDCCAQwGCSqGSIb3DQEJDjGB/jCB+zCBugYDVR0R\n"
    "BIGyMIGvoFcGCCsGAQUFBwgDoEswSQxAZDk1MmRlYzQ2MDE4MzJlOWM4NGYyMWNj\n"
    "ZGJmMzcyOGQ4OTQzODNlNmU5ZGQ4MDY3M2Q4MjQ4Zjg0NjM0OTRkMQYFZ4EFDAGg\n"
    "VAYIKwYBBQUHCASgSDBGBgVngQUBAgQ9aWQ6NDk0NjU4MDA6MzJjNmU1NzY2NjNm\n"
    "ZWU4MGQ2NGNkZDdiMThlNTYwMzg2M2IzYmM4YTo3ZDY3NzI4NTAdBgNVHSAEFjAU\n"
    "MAgGBmeBBQsBATAIBgZngQULAQMwHQYDVR0OBBYEFPoI7gfBqW6c/vrIjXvcvGfO\n"
    "w5aWMA0GCSqGSIb3DQEBCwUAA4IBAQBAbBP7R6TShnVogfO1DKO1NckT8AJIMnTQ\n"
    "OxczuZdm/z4Awu9ad4E86+6GwkJeZSv1HqqigcFrKOZ+bF1/kT7wxDtcON+KFhR8\n"
    "ha/2HbuyoFUv+WCGZWduTEXfAfqQQQHT+2wukmxc6Qh9Z/MF+usKt3KDiqQL4OU+\n"
    "wVcZMXH5Xe9x27DGnSfMvfCXDTevQjD3gD/HG3jeQ0U5YcWHnyYRfoL30Xj/FaiG\n"
    "oa6bEqp9krBkED3zAjnlOHbdSoMpa6Sy9PceYNQ2HOa7cIKBUZQzfa8FJ8wPMppL\n"
    "Rl/ubdEwm02Ky4zr6c3cchfqN7UhGLVgBxbp/7dJlj544uu23W3zMIIE2jCCBNYC\n"
    "AWcwggTPMIIEywYJKoZIhvcNAQcCoIIEvDCCBLgCAQExADALBgkqhkiG9w0BBwGg\n"
    "ggSgMIIEnDCCA4SgAwIBAgIEfWdyhTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE\n"
    "BhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UE\n"
    "CwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShU\n"
    "TSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDIwMB4XDTE3MDIyMzA0NDE1OVoXDTMy\n"
    "MDIyMzA0NDE1OVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJo0\n"
    "099ClzIVl14Aem2SnX+7MsRGw3/+RsNodJ6JYIinEZfVtmEtXFYoUERS3em2RzRH\n"
    "lr9lpfdaJ5UY+MkbxTMA92g40oivbmHQVnBuXF8C422wAHGYHnQXoOczfhpYJsG3\n"
    "TAlp5vswDH+TU8WWp8jpbXqhmWXIjtXRGbm3zOFRC3KEfJ3OUwCkzZVaW2bgL8Ds\n"
    "2X/L2z7E94IYRaWmorqxha0uYRlK2bUW2+nMn5FLmf69SOzZCFsbu5WcMtijClwI\n"
    "mWPOAsOb1qQdNHaXR1nzWDS2+HZEvTY9x8mfpkuAM5KyMR5IEH7nodFQ1NpPzT+E\n"
    "OOLQEA9DrFepy4EHb68CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggr\n"
    "BgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0Ew\n"
    "MjAvT3B0aWdhUnNhTWZyQ0EwMjAuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREB\n"
    "Af8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9T\n"
    "TEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDczRDAMBgNVHRMBAf8EAjAA\n"
    "MFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGln\n"
    "YVJzYU1mckNBMDIwL09wdGlnYVJzYU1mckNBMDIwLmNybDAVBgNVHSAEDjAMMAoG\n"
    "CCqCFABEARQBMB8GA1UdIwQYMBaAFDLG5XZmP+6A1kzdexjlYDhjs7yKMBAGA1Ud\n"
    "JQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQw\n"
    "DQYJKoZIhvcNAQELBQADggEBADUbMGmZFt1ki7JAJBqowNW4wNBTJovNqPc0UG+R\n"
    "uDFMRhyX8pXdpdCo+VHYmlQUqGmBcwBFjthpitieTcOr4qfbPKwnhv2GUlAUEjtq\n"
    "Y5Q9f9FJSatuODtvfyhV+hIUeNtBAX/TToZ7nQ9CGoALp5wrUv91WWd4BLjOppc/\n"
    "U2jc9VvmITgc6n89Sekj1++SmT8pm6jniSI0DaieiXYQXQB5f3OqUhQj2bFjOqPT\n"
    "lh2yTZUozPkPluomi/Y8CjLsaVwXufDH7OhzeZazQCD7Dvfh8iaZnbQBsHh3snwU\n"
    "wNwxG44zZxOACINcTQl/Rpln492d+bZyzB3Af8chr1WmVOgxADCCAZcwggGTAgFo\n"
    "BgorBgEEAfBVFAIBBIIBgEFBTUFzZ0FMQUFFQUN3QUZBSElBQUFBUUFCUUFDd2dB\n"
    "QUFBQUFBRUFyV3NVSXN1a2p5Q25lazE2RTFFRHNtbGdQSEhYT1VpTWl3bThZK29u\n"
    "enpkaXpocjFIVkVGWUxLRFJyQ2ZTTUtvdENKMVp4VjBGMitobHArdWVWWmQ5MlNp\n"
    "eEpUS2JFQUg5aEdzeUZvQS8zb2RCbm9Zckt6STRkcjhZc0J5eWFEcFg3cFFhSWtG\n"
    "YUJTL0JMU2JDeVlRVzdwd21YZVdRTk1DSTZPYjgvY1d1bkNMbm1CU1dGUmhEZnVI\n"
    "U1R6U20zOENEZDZYY3ZxZ3BDb3FyU1FtaEx2QjltNHl0WWIyVGpiZHVqOHZ6bzlS\n"
    "OWtLbVo1QmR2a1l1bHRJY045bk9BazNyN1pNKzBKK3BLM253LzFtRVo4NkQzbGF0\n"
    "Qk84MWFYeUR0Z0ZkS0pSOW5aVFh3M3Vlb3RtRUQ2eWJrcGUveSsrV2w0TVhtb0l5\n"
    "SWxHK3EvM0ZGWDgxTHc9PTGCAY0wggGJAgEDoBYEFPoI7gfBqW6c/vrIjXvcvGfO\n"
    "w5aWMA0GCWCGSAFlAwQCAQUAoEowFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMC8G\n"
    "CSqGSIb3DQEJBDEiBCAOxlqJzpX1D2SQhO1mB3UfurZeKnoucXAQz+KMxpSVLTAN\n"
    "BgkqhkiG9w0BAQEFAASCAQCdCCe0/qGJX1JY+5WdHFRZqH4b/TDp/9aEY8fSw1ae\n"
    "HQl7X9Z9S5dcUAw5W8U2w7ze1fBZuGcBXSngupR94oOCj000QYVfjUX8dZq0xlr4\n"
    "j7OGZqZUzlg9r+/PYZiwVW3w5842aeja6NzWroZ87+f6una0aqZu8CZTbFYqWBNg\n"
    "mN1r7iGtb7c1pA5geZikph7yvg/b0/4pc+gCyTFZ7BJlX58rqE8l8kxlFBJlPERk\n"
    "lhH+5uiWf53k47lvxg4YP2PbgI68hdJE/lYziDU3GzSLNAl5qQcfli5ZQmF2fkDW\n"
    "cYgHrTZSUlyDV47regIFC9OequeBraa1bgd84EPB0Fxo\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const sbyte *gpRSA4kSampleCSR =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIRYwYJKoZIhvcNAQcCoIIRVDCCEVACAQMxDzANBglghkgBZQMEAgEFADCCDqcG\n"
    "CCsGAQUFBwwCoIIOmQSCDpUwgg6RMDYwHgIBZQYKKwYBBAHwVRQBATENEwtUUE0y\n"
    "LUFUVEVTVDAUAgFmBggrBgEFBQcHHDEFMAMCAWcwggYVoIIGEQIBATCCBgowggPy\n"
    "AgEAMIGQMSIwIAYDVQQDExkzSEUxNjczMUFBLUZYMlNCUjMwMjQtSUFLMREwDwYD\n"
    "VQQKEwhEaWdpQ2VydDETMBEGA1UEBRMKRlgyU0JSMzAyNDEUMBIGA1UECxMLRW5n\n"
    "aW5lZXJpbmcxEjAQBgNVBAcTCVN1bm55dmFsZTELMAkGA1UECBMCQ0ExCzAJBgNV\n"
    "BAYTAlVTMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSfbMnDyKc8s\n"
    "BCslzrfraYnUFGD1eXPBh3TaxZSY/aV3fFMfR3XUZLuWy6s9Hgj91FU83GoIB7pd\n"
    "dvyfBvAq+jEpGw6FY2AoFRdy4FrmpGDcQeB/k6HM7JSEhvBHa93HO01AO+2Hzia7\n"
    "aTPIiTbKirJRa4H9Ryu4DJyhUiG0NwEWpajB4dEnzCFVGw/kTnN32wzE5xLyJTsr\n"
    "vepyIw4MsvqWBijZq8GZa02vqijZdPcdqicGu0o/ZHPN/o8mL8c4PCRr6UCHyGM8\n"
    "sr4dxxqcKM3DoUTN9gKcY4aPHX9Cpa8RKf3UyECiDkKtkO+B5cusdPSoXjmpB+na\n"
    "/MDHvdoAGYiVqgMjjITCsWAz0U3X3T8XgTzPZm5FTbGXQ+BkzpU/gCoLugrCMxUK\n"
    "0rq3DqY955kugqvoDq29dbTEwDtZlWIYtbdUow0pCqC2Ia6Wu5zldFR9tGFOY9xG\n"
    "HxtsGLcGrwLittaiNqQcftCqH3/I2i/2b5I7LXSjxIElGVdsbS/scu9DBuvTOz+8\n"
    "IzgfOnw5xCvvuyOmmkZVhdLppzLaxrQi13kK2nb9/PYEkvWUkLuIZUna8kp4ASqV\n"
    "cUSlFjz0pHUcR4WNSJgW6+TUCVHNoTux5DV/2O9Xhx86C5G0LbbXnCYaTmB/zOgG\n"
    "JxMTUU1+0z7DFH91CB9BxGYWp2uFfEMCAwEAAaCCATIwggEuBgkqhkiG9w0BCQ4x\n"
    "ggEfMIIBGzCB2gYDVR0RBIHSMIHPoFcGCCsGAQUFBwgDoEswSQxAZGU3NmYyZWZj\n"
    "NTAyNjdkMmYzZWRkYTRlYzI2ZWE5MmQ4YWM3NzhmNWYzZjk1MDNjMmVjY2FlYWM4\n"
    "NDk3YTk3NwYFZ4EFDAGgdAYIKwYBBQUHCASgaDBmBgVngQUBAgRdaWQ6NTM1NDRE\n"
    "MjA6NjU3MDYyYTcxMDU2OTE2ZjhjN2Y3OThhOTJkZGU2ZDgxZDBhOThkYTo3YzNm\n"
    "ZDJlNTVmYzNkYzc0N2NiMWYyZjljMzUwM2Y1MDEyZDdkNmVhMB0GA1UdIAQWMBQw\n"
    "CAYGZ4EFCwEBMAgGBmeBBQsBAzAdBgNVHQ4EFgQUywpxJhq2rN0HY5EzEIU9KdHx\n"
    "pnMwDQYJKoZIhvcNAQELBQADggIBAJmzGJLAsBi7QEhRJSahHc7oA5z3r7qv0934\n"
    "T3NxjALwIjV9XBiOgD5aPr3QcycaWvZ6of+PpBycrSWfHcrNQlOcLoNFcPuDyBzR\n"
    "hhF+VfR+7qSy8uSrQArTqT6S614L9psUHHlrUzjexJT+l9I3Ka0DRmVZyqVZhwCL\n"
    "o2WVlhyVeA2JZVTFHPK+KLE1C6rB1SksOzPYAhla9J+8V7feaRVHKj92ncOnwSQn\n"
    "Gvcci8k7qLsWM/VYLKTyKakr+dYy/C2vYGRSSBE64B2TadaK9PZP6yOkOI2gQoC1\n"
    "DrRPWbD8d3iepBHdbUEuQ8W5kjDKkyOR00KKmh6nK9pWFKgY6Zg6kPkhmh/ogTU1\n"
    "jo+UErKxWw+zn6mg6tR9Pc5jTkIEcIBOSj2zzFg2FTgbwsYind4d8H/p10svbhKG\n"
    "J7hPj3Ti36QAQrNI05sUylIwVHz6iEEYiEt7Vw32Ifh6fnLAoeAS8zj643CxacDN\n"
    "rEdsSsuqdcJm+v0HSdY9zuZybRapZ0msQdlxZwB41edTu0C6/pP1xD8dH2k5EBfE\n"
    "nwOIoLmu1bKyRFPzJ5Px3peJJBhOQ80UWqu770J/yDMA4lWjhFSLY/DPDhWm4DXb\n"
    "Os7hnci/5QgmONPMIJE+hNtA4k0cXbzmcSWnMxnwEX6Q6T2Z2PoZ19Livzyeovnc\n"
    "arY+O6ulMIIFTTCCBUkCAWcwggVCMIIFPgYJKoZIhvcNAQcCoIIFLzCCBSsCAQEx\n"
    "ADALBgkqhkiG9w0BBwGgggUTMIIFDzCCAvegAwIBAgIUfD/S5V/D3HR8sfL5w1A/\n"
    "UBLX1uowDQYJKoZIhvcNAQEMBQAwWTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNU\n"
    "TWljcm9lbGVjdHJvbmljcyBOVjEqMCgGA1UEAxMhU1RTQUZFIFRQTSBSU0EgSW50\n"
    "ZXJtZWRpYXRlIENBIDEwMCAXDTIzMDQxMjE2MjU1MloYDzk5OTkxMjMxMjM1OTU5\n"
    "WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl1GMDIb8LR6Z4GBV\n"
    "s+TKxPA+jbLlELTxUFrQG/T4mWp6lYM7WIHrxbzmYsmG9299xMn6RM1zimNbGXKS\n"
    "fuM3Z1UWXTPFQTJFrEssMvrLU67ekLCQdGBZGUJxDABjKgMbK2xGbcqesSZQxDGp\n"
    "VrMpGpCE++/k50AIkFxdHf+TTVEgPNzfHTT/aj/43y2NeDlkjbsh/e0jSTbO+7AQ\n"
    "gX/1SpZEOVtAUw7qhMlGSFVp+HdbNxBjrDsc2cktEA07qTLMgTbzdZ9PO6uozc4k\n"
    "n/trxN1DNRkqT1OitN184Rb9S/34p/AheB5ZtJKwW7XOwjT2S5Ryag9WpmVTvgWK\n"
    "eAtN6QIDAQABo4IBJDCCASAwHwYDVR0jBBgwFoAUZXBipxBWkW+Mf3mKkt3m2B0K\n"
    "mNowVwYDVR0RAQH/BE0wS6RJMEcxFjAUBgVngQUCAQwLaWQ6NTM1NDREMjAxFTAT\n"
    "BgVngQUCAgwKU1QzM0tUUE0yWDEWMBQGBWeBBQIDDAtpZDowMDA5MDEwMTAiBgNV\n"
    "HQkEGzAZMBcGBWeBBQIQMQ4wDAwDMi4wAgEAAgIAnzAMBgNVHRMBAf8EAjAAMBAG\n"
    "A1UdJQQJMAcGBWeBBQgBMA4GA1UdDwEB/wQEAwIFIDBQBggrBgEFBQcBAQREMEIw\n"
    "QAYIKwYBBQUHMAKGNGh0dHA6Ly9zdy1jZW50ZXIuc3QuY29tL1NUU0FGRS9zdHNh\n"
    "ZmV0cG1yc2FpbnQxMC5jcnQwDQYJKoZIhvcNAQEMBQADggIBAGJaG0W8FDuQB9QJ\n"
    "mnidRapzh8ThJiSFKRy7cGoNaPpqAah4ZRl/rlLHw6ethDrDBR1uL2LYxCf9elSs\n"
    "wHZKhPxuZjC4LYKLwpdWXFNRMCsMC57s0ll4O4rgjw9pxLYFKAIT8dmroJP2p04e\n"
    "TkRstawrguJodJnQ+Qb4obUy+gI0KmVWj3hZOr5clOc1O6nPW7YKFohVuOiyLs63\n"
    "ZcZVHMOqRTF3zy8lOFBRWZpZ8tmoHpn5h8dQG9/hZOXIPn8BVK+b3f+B7em2YpD9\n"
    "HFNwIalBD+P/su/FQ089EMWF/F3jiIjusw6TuD7MyIpt0ZqWeQeeDjYNykSno5Tx\n"
    "TBtM71j+ejyoD+5MvGY/BoEM7PDNVJHlOv13iXqZWwhesBlnp9Wgy4UG1+tnkhnW\n"
    "ZKM2N2aPir+M9uKKmxGEFgnL/lw121oiEGoC5AjZM73DxDnwKNelnqDYM3EQO35y\n"
    "w9UbIc0cdeVaOhHrcemA7VncDB9VfGoTcjn4HEoVep1N4/syWMdxloVj3CGoP9rs\n"
    "jS4uw0LE23Ga6t6Ch5LwPTz+AnuJdo+1KXa9lUcDg+kp2U4jPiQtJUp+++WwaYZn\n"
    "Q+ltp1zmJfCIt1/hj5EP6MA7p4L4BQ3djNLfqnmpYTcWqk8wCU3ui0vrUWy5Mf6s\n"
    "iuorSsN5vokcMGwQHCA8RjbMMPu6MQAwggLrMIIC5wIBaAYKKwYBBAHwVRQCAQSC\n"
    "AtRBQU1Bc2dBTEFBRUFDd0FGQUhJQUFBQVFBQlFBQ3hBQUFBQUFBQUlBdVNmYk1u\n"
    "RHlLYzhzQkNzbHpyZnJhWW5VRkdEMWVYUEJoM1RheFpTWS9hVjNmRk1mUjNYVVpM\n"
    "dVd5NnM5SGdqOTFGVTgzR29JQjdwZGR2eWZCdkFxK2pFcEd3NkZZMkFvRlJkeTRG\n"
    "cm1wR0RjUWVCL2s2SE03SlNFaHZCSGE5M0hPMDFBTysySHppYTdhVFBJaVRiS2ly\n"
    "SlJhNEg5Unl1NERKeWhVaUcwTndFV3BhakI0ZEVuekNGVkd3L2tUbk4zMnd6RTV4\n"
    "THlKVHNydmVweUl3NE1zdnFXQmlqWnE4R1phMDJ2cWlqWmRQY2RxaWNHdTBvL1pI\n"
    "UE4vbzhtTDhjNFBDUnI2VUNIeUdNOHNyNGR4eHFjS00zRG9VVE45Z0tjWTRhUEhY\n"
    "OUNwYThSS2YzVXlFQ2lEa0t0a08rQjVjdXNkUFNvWGptcEIrbmEvTURIdmRvQUdZ\n"
    "aVZxZ01qaklUQ3NXQXowVTNYM1Q4WGdUelBabTVGVGJHWFErQmt6cFUvZ0NvTHVn\n"
    "ckNNeFVLMHJxM0RxWTk1NWt1Z3F2b0RxMjlkYlRFd0R0WmxXSVl0YmRVb3cwcENx\n"
    "QzJJYTZXdTV6bGRGUjl0R0ZPWTl4R0h4dHNHTGNHcndMaXR0YWlOcVFjZnRDcUgz\n"
    "L0kyaS8yYjVJN0xYU2p4SUVsR1Zkc2JTL3NjdTlEQnV2VE96KzhJemdmT253NXhD\n"
    "dnZ1eU9tbWtaVmhkTHBwekxheHJRaTEza0sybmI5L1BZRWt2V1VrTHVJWlVuYThr\n"
    "cDRBU3FWY1VTbEZqejBwSFVjUjRXTlNKZ1c2K1RVQ1ZITm9UdXg1RFYvMk85WGh4\n"
    "ODZDNUcwTGJiWG5DWWFUbUIvek9nR0p4TVRVVTErMHo3REZIOTFDQjlCeEdZV3Ay\n"
    "dUZmRU09MYICjTCCAokCAQOgFgQUywpxJhq2rN0HY5EzEIU9KdHxpnMwDQYJYIZI\n"
    "AWUDBAIBBQCgSjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwLwYJKoZIhvcNAQkE\n"
    "MSIEIMcJKQu66KRbW783IAcF9oNLO9gqYoLWVFjPOfYC+lzzMA0GCSqGSIb3DQEB\n"
    "AQUABIICAF8+5hKnw8jGcoaox3EK6owfj0u3azKK0FiXXyD3nth+l0iS1jOArrv1\n"
    "L+/so0lXLPYZhyT3lJ4aFVZC80N+JFV5YZ4HB6jZd0uKnJCNZ11Aiq7tFNPhOfIP\n"
    "xKTQCP8nNDbUnF+iFaXN/JwxGCt/fn8QzwhYGUZ30rhFOFXAKydloar10y9gRAIu\n"
    "VyBupBJXYWJYkkq2vdid0vOwBLutTSlhv0gFYWBGWIx1XYsmKV7oy+emFqrx5WDB\n"
    "vORKuHljVhVbp+yj5DnpomZUxcw0XY45lFfrJ2ZbsEbhYyu9hZ0aKi8mAYXQGxQV\n"
    "boO4VaKA+CbBMIGNvo74fcy+kDCpZGzCmg/814AB8qiSIwg/ytOOSpLu47+8tE0+\n"
    "rffpcW4uCjoH+yLfoR+CFl6DN3AqGHLS/foUl6iioSgfEDOtmwkwUhoiuSRV4llq\n"
    "MCg7uirMqa4RcwVwG2UzYtjHlc0XjaRDbyuBVh0k9QoIaXUztKNyym/V5gFpot0d\n"
    "+HO0KBCBXlxfKUI6AWiRLVs+21fGoR/zpkHK39oZRCQokBeWhLsEcV/06dFHlayN\n"
    "crL2AIbmqopaUg4+iP9FRpmNcI1JbJXnPInlP+e+oz2iHaSxptO76/lqtpF1MlPr\n"
    "5hUqqKXLbhqj0JsYxBtRlqGcYEFQL+56h8OzYEGOspKtTRI9sKcT\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const sbyte *gpECCSampleCSR =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIJuwYJKoZIhvcNAQcCoIIJrDCCCagCAQMxDzANBglghkgBZQMEAgEFADCCCL8G\n"
    "CCsGAQUFBwwCoIIIsQSCCK0wggipMDYwHgIBZQYKKwYBBAHwVRQBATENEwtUUE0y\n"
    "LUFUVEVTVDAUAgFmBggrBgEFBQcHHDEFMAMCAWcwggL+oIIC+gIBATCCAvMwggKZ\n"
    "AgEAMIGQMSEwHwYDVQQDExhycGk0LTY0LWlvdC1hdHRlc3QtMjU1ODAxCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUx\n"
    "ETAPBgNVBAoTCERCQSBJbmMuMRMwEQYDVQQLEwpPcGVyYXRpb25zMQ0wCwYDVQQF\n"
    "EwRhYmNkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEywAANkgPiBRR/EMhuphw\n"
    "dScZr+RSmRcSObtAVSwatdIr98Ug3wgER14+FsERr0JAAma/3DIAmYDyKBYEbyVT\n"
    "RKCCAaQwTwYJKoZIhvcNAQkHMUITQEpRaWNCUFFraVBiSnZMNmFpMWJsclBpUmNk\n"
    "ZGtEZHc5ckErRElUcXJTQ3liVm9DTWtLbW9QcDFZamhkdkp6ZGkwggFPBgkqhkiG\n"
    "9w0BCQ4xggFAMIIBPDAMBgNVHRMEBTADAQEAMA4GA1UdDwEB/wQEAwIFoDCBugYD\n"
    "VR0RBIGyMIGvoFQGCCsGAQUFBwgEoEgwRgYFZ4EFAQIEPWlkOjQ5NDY1ODAwOjcw\n"
    "MjZkMDllZDkzNWRjZGM0NGQ4NGQ3ZGE3NWNjZjBhYmMxZmRlMGE6MWFmMGU3YmSg\n"
    "VwYIKwYBBQUHCAOgSzBJDEA0MzY2YWQwMzU3YWQxYjMzNzk4NjhhMmU3MTAzYTY3\n"
    "MTY4Yzk0ZmQ3NDMzMWU2NTA0NDE4NmRlMjVmNWFlMGJkBgVngQUMATAdBgNVHSAE\n"
    "FjAUMAgGBmeBBQsBATAIBgZngQULAQMwHQYDVR0OBBYEFCfKjaVjqx+Hxuh/WdtB\n"
    "urtvV+akMCEGCSsGAQQBgjcUAgQUHhIAVwBlAGIAUwBlAHIAdgBlAHIwCgYIKoZI\n"
    "zj0EAwIDSAAwRQIhAKeDJSPrYDAt+bOlg+tKkU6t9vwnphDDzVgui35DU8bhAiBu\n"
    "QuTbodhDveuJC96W4oRze82VI7mmkKDhZUJQRzSpyzCCBNMwggTPAgFnMIIEyDCC\n"
    "BMQGCSqGSIb3DQEHAqCCBLUwggSxAgEBMQAwCwYJKoZIhvcNAQcBoIIEmTCCBJUw\n"
    "ggN9oAMCAQICBBrw570wDQYJKoZIhvcNAQELBQAwgYMxCzAJBgNVBAYTAkRFMSEw\n"
    "HwYDVQQKDBhJbmZpbmVvbiBUZWNobm9sb2dpZXMgQUcxGjAYBgNVBAsMEU9QVElH\n"
    "QShUTSkgVFBNMi4wMTUwMwYDVQQDDCxJbmZpbmVvbiBPUFRJR0EoVE0pIFJTQSBN\n"
    "YW51ZmFjdHVyaW5nIENBIDAyMjAeFw0xNzA0MjYxNTU4NDBaFw0zMjA0MjYxNTU4\n"
    "NDBaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX1pMxaen8g8zi\n"
    "s40ZGiD0J4sWxwGxUna64u/tyL3/uP2SeQ9vL32HHNrZzk0rpHa+b87u6AAsMK7X\n"
    "z0wyHYuDsUqvPbvRTrumOIetU4Zwy1XaSS/i2B4m4JvjGRyawo464J5n1GKZLNCf\n"
    "v563tR2Mut9gvTCCTcy477gqcMElPFFSDUR7kqm8Hh4agCKKIh6RL9PdlvAcGvM2\n"
    "RlxoJR276gLxxmU4BfaTgNCNlhT5s7yx/+yI8EoHJduUBPY28Na3MTwvTiLWZlDG\n"
    "rSe/iO2m1yxkaHrjJ7FHqkM3VSOOCNv0ac8Ed3bDv1q1m/EYU6rJ8cfBBGv/VXEq\n"
    "xQ1WPimfAgMBAAGjggGRMIIBjTBbBggrBgEFBQcBAQRPME0wSwYIKwYBBQUHMAKG\n"
    "P2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDIyL09wdGln\n"
    "YVJzYU1mckNBMDIyLmNydDAOBgNVHQ8BAf8EBAMCACAwUQYDVR0RAQH/BEcwRaRD\n"
    "MEExFjAUBgVngQUCAQwLaWQ6NDk0NjU4MDAxEzARBgVngQUCAgwIU0xCIDk2NjUx\n"
    "EjAQBgVngQUCAwwHaWQ6MDUzRDAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBD\n"
    "oEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDIyL09w\n"
    "dGlnYVJzYU1mckNBMDIyLmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1Ud\n"
    "IwQYMBaAFHAm0J7ZNdzcRNhNfadczwq8H94KMBAGA1UdJQQJMAcGBWeBBQgBMCEG\n"
    "A1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQAD\n"
    "ggEBACSdy+BUyH/mIchekmUVc3US8sLo+v5RkQhROy9y5vZoRhNwZmoN06y3MhEa\n"
    "Dw7CJyBzreHLVfoZQXCuUqS25NG43POCmeA/2zfnFvZH38p1b8pl/L/k72nChU2T\n"
    "xl9mAFsIvea3EUxIobIwAhPbgqwWYrIJg5Z1vDPNJodtHzRCECZYoRGXQKjcphLe\n"
    "Y949OXBeEoJmc6v1hzBGo2oO2W5/As4CgSYv/ZkpK40XGKVn5GH2+IqHNeQF4Av2\n"
    "Cm8JHiEANbcfGblK6wYOISJlBVDt0TCax0l+D0ULf0xfw6of8ktCNWglQu7evVEf\n"
    "lFiykAJP3vEifK5hi5pC4KKFH98xADCBlTCBkgIBaAYKKwYBBAHwVRQCAQSBgEFB\n"
    "TUFzZ0FMQUNNQUN3QUZBSElBQUFBUUFCZ0FDd0FEQUJBQUlNc0FBRFpJRDRnVVVm\n"
    "eERJYnFZY0hVbkdhL2tVcGtYRWptN1FGVXNHclhTQUNBcjk4VWczd2dFUjE0K0Zz\n"
    "RVJyMEpBQW1hLzNESUFtWUR5S0JZRWJ5VlRSQT09MYHOMIHLAgEDoBYEFCfKjaVj\n"
    "qx+Hxuh/WdtBurtvV+akMA0GCWCGSAFlAwQCAQUAoEowFwYJKoZIhvcNAQkDMQoG\n"
    "CCsGAQUFBwwCMC8GCSqGSIb3DQEJBDEiBCAYfOA+x0Os0IxSA36rcNPGMk5bw9ND\n"
    "5RERtmC3VXp8iTAKBggqhkjOPQQDAgRHMEUCIQDQl9DhWLiqpCoTmbBHfiHSnpEf\n"
    "52KzfYlRhRpvWRYeCwIgLbYQp7A+IqTk+84jnNRlNiwV9wvMv8iDJbQmgNin07A=\n"
    "-----END CERTIFICATE REQUEST-----\n";

/* id-cmc-batchRequests 1.3.6.1.5.5.7.7.28 */
static ubyte gIdCmcBatchRequests_OID[]  = {0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x07, 0x1C};
const ubyte PKIData_OID[] =
{ 8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0C, 0x02 }; /* 1.3.6.1.5.5.7.12.2 */

static MSTATUS extractPublicKey(ubyte *pCertificate, ubyte4 certificateLen, AsymmetricKey *pPubKey)
{
    MSTATUS status = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pRoot = NULL;

    /* Input parameter check */
    if (NULL == pCertificate || NULL == pPubKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    MF_attach(&mf, certificateLen, pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    if (NULL == pRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
        ASN1_FIRST_CHILD(pRoot),
        cs, pPubKey)))
    {
        goto exit;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem *)pRoot);
    return status;
}

static MSTATUS extractPublicKey2(ubyte *pCertificate, ubyte4 certificateLen, AsymmetricKey *pPubKey)
{
    MSTATUS status = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pRoot = NULL;
    ASN1_ITEMPTR  pPKCS10 = NULL;
	static WalkerStep fullCMCWalkInstructions[] =
	{
		{ GoFirstChild, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyOID, 0, (ubyte*)pkcs7_signedData_OID },
		{ GoNextSibling, 0, 0 },
		{ VerifyTag, 0, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, INTEGER, 0 },
		{ GoNextSibling, 0, 0 },
		{ GoNextSibling, 0, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyOID, 0, (ubyte*)PKIData_OID },
		{ GoNextSibling, 0, 0 },
		{ VerifyTag, 0, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, OCTETSTRING, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ GoNextSibling, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyTag, 0, 0 },
		{ GoFirstChild, 0, 0 },
		{ VerifyType, INTEGER, 0 },
		{ GoNextSibling, 0, 0 },
		{ VerifyType, SEQUENCE, 0 },
		{ Complete, 0, 0 }
	};

    /* Input parameter check */
    if (NULL == pCertificate || NULL == pPubKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    MF_attach(&mf, certificateLen, pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    if (NULL == pRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

			if (OK > (status = ASN1_WalkTree(pRoot, cs, fullCMCWalkInstructions, &pPKCS10)))
			{
				
				goto exit;
			}

    ubyte *pCSR = (ubyte *) CS_memaccess(cs, pPKCS10->dataOffset - pPKCS10->headerSize, pPKCS10->length + pPKCS10->headerSize);
    ubyte4 csrLen = pPKCS10->length + pPKCS10->headerSize;

    status = DIGICERT_writeFile("./csr.der", pCSR, csrLen);
    if (OK != status)
    {
        goto exit;
    }

    system("openssl req -in csr.der -noout -pubkey -out csr-pub-key.pem -inform DER");

    status = DIGICERT_readFile("./csr-pub-key.pem", &pCSR, &csrLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(pCSR, csrLen, NULL, pPubKey);
    if (OK != status)
    {
        goto exit;
    }


exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem *)pRoot);
    return status;
}

MSTATUS writeKey(AsymmetricKey *pAsymKey, sbyte *pName)
{
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    status = CRYPTO_serializeAsymKey(pAsymKey, publicKeyPem, &pKey, &keyLen);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile(pName, pKey, keyLen);

exit:

    return status;
}


static int tpm2_wrap_test(
    ubyte *pData,
    ubyte4 dataLen,
    sbyte *pBlobFile,
    sbyte *pCsrKeyFile,
    sbyte *pEkKeyFile,
    sbyte *pSymKeyFile)
{
    MSTATUS status;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = NULL, pPKIDataItem = NULL;
    byteBoolean attestFlow = FALSE;
    ubyte4 *pBodyPartsList = NULL;
    ubyte4 numBodyParts = 0;
    ASN1_ITEMPTR *pCmsDataItems = NULL, pEkCertItem = NULL;
    ubyte4 numCmsData = 0;
    ubyte *pBuff;
    ubyte4 ekCertDataLen = 0, otherMsgDataLen = 0;
    ubyte *pEkCertData = NULL, *pOtherMsgData = NULL;
    AsymmetricKey csrKey = { 0 }, ekKey = { 0 };
    ubyte pSymKey[24] = { 0 };
    int retVal = 0;

    status = CA_MGMT_decodeCertificate(pData, dataLen, &pDecoded, &decodedLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, decodedLen, pDecoded);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRootItem);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CMC_getPKIData(pRootItem, cs, &pPKIDataItem);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CMC_verifyAttestationReqType(
        pPKIDataItem, cs, &attestFlow, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CMC_processControlSequence(
        pPKIDataItem, cs, gIdCmcBatchRequests_OID,
        &pBodyPartsList, &numBodyParts);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CMC_processCmsSequence(
        pPKIDataItem, cs, pBodyPartsList, numBodyParts, FALSE,
        &pCmsDataItems, &numCmsData);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = PKCS7_GetCertificates(pCmsDataItems[0], cs, &pEkCertItem);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    ekCertDataLen = pEkCertItem->length + pEkCertItem->headerSize;

    status = DIGI_MALLOC((void **) &pEkCertData, ekCertDataLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pBuff = (ubyte *) CS_memaccess(cs, pEkCertItem->dataOffset - pEkCertItem->headerSize, pEkCertItem->length + pEkCertItem->headerSize);
    status = DIGI_MEMCPY(pEkCertData, pBuff, ekCertDataLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CMC_processOtherMsgSequence(
        pPKIDataItem, cs, &pOtherMsgData, &otherMsgDataLen, FALSE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile(pBlobFile, pOtherMsgData, otherMsgDataLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = extractPublicKey2(pDecoded, decodedLen, &csrKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = writeKey(&csrKey, pCsrKeyFile);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = extractPublicKey(pEkCertData, ekCertDataLen, &ekKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = writeKey(&ekKey, pEkKeyFile);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile(pSymKeyFile, pSymKey, sizeof(pSymKey));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    ubyte *pOut = NULL;
    ubyte4 outLen = 0;

    status = SMP_TPM2_wrapCredentialSecret(
        &csrKey, &ekKey, pOtherMsgData, otherMsgDataLen, pSymKey, sizeof(pSymKey),
        &pOut, &outLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    ubyte4 i;
    printf("\nOUTPUT: ");
    for (i = 0; i < outLen; i++)
    {
        printf("0x%02X ", pOut[i]);
    }
    printf("\n");

exit:

    return retVal;
}

#endif

/*--------------------------------------------------------------------------*/

int crypto_interface_tpm2_wrap_credentials_test_all()
{
    MSTATUS status;
    int retVal = 0;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)
    retVal += tpm2_wrap_test(
        gpRSASampleCSR, DIGI_STRLEN(gpRSASampleCSR),
        "1-blob.bin",
        "1-csr-key.pem",
        "1-ek-key.pem",
        "1-sym-key.bin");
    retVal += tpm2_wrap_test(
        gpECCSampleCSR, DIGI_STRLEN(gpECCSampleCSR),
        "2-blob.bin",
        "2-csr-key.pem",
        "2-ek-key.pem",
        "2-sym-key.bin");
    retVal += tpm2_wrap_test(
        gpRSA4kSampleCSR, DIGI_STRLEN(gpRSA4kSampleCSR),
        "3-blob.bin",
        "3-csr-key.pem",
        "3-ek-key.pem",
        "3-sym-key.bin");
#endif

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
