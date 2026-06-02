
/*------------------------------------------------------------------*/

static void
printr(ubyte *data, sbyte4 len, sbyte4 br)
{
    sbyte4 i;

    for (i=0; i < len; i++)
    {
        printf("%02x%s", (ubyte4)data[i], (br ? " " : ""));
        if (br)
        {
            if (len == (i+1)) break;
            if (15 == (i%16)) printf("\n");
        }
    }
    if (br) printf("\n");
} /* printr */


/*------------------------------------------------------------------*/

static void
printk(sbyte *label, ubyte *data, sbyte4 len)
{
    printf("%s (%d bytes): ", label, len);
    printr(data, len, 0);
    printf("\n");
} /* printk */


/*------------------------------------------------------------------*/

static void
print_ip(ubyte4 dwIpAddr)
{
    printf("%d.%d.%d.%d",
        (dwIpAddr >> 24),
        ((dwIpAddr & 0x00ff0000) >> 16),
        ((dwIpAddr & 0x0000ff00) >> 8),
        (dwIpAddr & 0x000000ff));
} /* print_ip */


/*------------------------------------------------------------------*/

static sbyte4
get_netmask(ubyte4 dwIpAddr, ubyte4 dwIpAddrEnd)
{
    sbyte4 i, plen = sizeof(ubyte4) * 8;

    ubyte4 dwMask = ~(dwIpAddrEnd ^ dwIpAddr);

    for (i = (sizeof(ubyte4) * 8) - 1; i >= 0; i--)
    {
        if (!(dwMask & (((ubyte4)1) << i)))
            break;
    }

    if (0 > i) goto exit;
    plen -= i + 1;

    if ((0 == (dwMask << plen)) && /* valid netmask? */
        (dwIpAddr == (dwIpAddr & dwMask)) &&
        (dwIpAddrEnd == (dwIpAddr | ~(dwMask))))
        goto exit;

    plen = -1;

exit:
    return plen;
} /* get_netmask */


#ifdef __ENABLE_DIGICERT_IPV6__

/*------------------------------------------------------------------*/

static sbyte4
get_netmask6(const ubyte *ipAddr, const ubyte *ipAddrEnd)
{
    sbyte4 i, plen = 128;
    ubyte4 dwIpAddr, dwIpAddrEnd;

    for (i=3; 0 <= i; i--)
    {
        dwIpAddr = DIGI_NTOHL(ipAddr + (4 * i));
        dwIpAddrEnd = DIGI_NTOHL(ipAddrEnd + (4 * i));

        if ((0 == dwIpAddr) && ((ubyte4)(-1) == dwIpAddrEnd))
        {
            plen -= 32;
            continue;
        }

        if (dwIpAddrEnd != dwIpAddr)
        {
            sbyte4 plen0 = get_netmask(dwIpAddr, dwIpAddrEnd);
            if (0 > plen0)
            {
                plen = -1;
                goto exit;
            }
            plen -= (32 - plen0);
        }

        /* !!! */
        i--;
        break;
    }

    for (; 0 <= i; i--)
    {
        dwIpAddr = DIGI_NTOHL(ipAddr + (4 * i));
        dwIpAddrEnd = DIGI_NTOHL(ipAddrEnd + (4 * i));

        if (dwIpAddrEnd != dwIpAddr)
        {
            plen = -1;
            break;
        }
    }

exit:
    return plen;
} /* get_netmask6 */


/*------------------------------------------------------------------*/

static void
print_ip6(const ubyte* ipAddr6)
{
    sbyte4 i, zeros=0;
    for (i=0; i < 16; i += 2)
    {
        if (i && (0 >= zeros)) printf(":");

        if (ipAddr6[i])
        {
            if (0 < zeros) zeros = -1;
            printf("%x%02x", (int) ipAddr6[i], (int) ipAddr6[i+1]);
        }
        else if (ipAddr6[i+1])
        {
            if (0 < zeros) zeros = -1;
            printf("%x", (int) ipAddr6[i+1]);
        }
        else if (i && (0 > zeros) && (14 > i))
        {
            printf("0");
        }
        else if (i && (0 <= zeros))
        {
            if ((0 == zeros++) && (14 > i))
                printf(":");
        }
    }
} /* print_ip6 */


/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_IPV6__ */


/*------------------------------------------------------------------*/

static sbyte4
any_ip_range(MOC_IP_ADDRESS ipAddr, MOC_IP_ADDRESS ipAddrEnd)
{
    sbyte4 res;

#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte4 dwIP6[4] = { 0 };
    ubyte4 dwIPEnd6[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
#endif

    TEST_MOC_IPADDR6(ipAddr,
    {
        const ubyte *poIP = GET_MOC_IPADDR6(ipAddr);
        const ubyte *poIPEnd = GET_MOC_IPADDR6(ipAddrEnd);
        res = ((0 == CmpIpAddr6(poIP, (ubyte *)dwIP6)) &&
               (0 == CmpIpAddr6(poIPEnd, (ubyte *)dwIPEnd6)));
    })
    {
        ubyte4 dwIP = GET_MOC_IPADDR4(ipAddr);
        ubyte4 dwIPEnd = GET_MOC_IPADDR4(ipAddrEnd);
        res = ((0 == dwIP) && (~((ubyte4)0) == dwIPEnd));
    }

    return res;
} /* any_ip_range */


/*------------------------------------------------------------------*/

static void
print_proto(ubyte oProto)
{
    sbyte *pStr = NULL;

    switch (oProto)
    {
    case IPPROTO_TCP :
        pStr = "tcp";
        break;
    case IPPROTO_UDP :
        pStr = "udp";
        break;
    case IPPROTO_ICMP :
        pStr = "icmp";
        break;
    case 50/*IPPROTO_ESP*/ :
        pStr = "esp";
        break;
    case 51/*IPPROTO_AH*/ :
        pStr = "ah";
        break;
    case 4/*IPPROTO_IPIP*/ :
        pStr = "ipip";
        break;
    case 58/*IPPROTO_ICMPV6*/ :
        pStr = "icmp6";
        break;
    }

    if (NULL != pStr)
        printf("%s", pStr);
    else
        printf("\"%d\"", (sbyte4)oProto);
} /* print_proto */


/*------------------------------------------------------------------*/

static void
print_port(ubyte2 wPort)
{
    sbyte *pStr = NULL;

    switch (wPort)
    {
    case 80 :
        pStr = "http";
        break;
    case 23 :
        pStr = "telnet";
        break;
    }

    if (NULL != pStr)
        printf("%s", pStr);
    else
        printf("%d", (sbyte4)wPort);
} /* print_port */


/*------------------------------------------------------------------*/

static void
print_auth(ubyte oAuth)
{
    sbyte *pStr = NULL;

    switch (oAuth)
    {
    case 0 :
        pStr = "any";
        break;
    case IPSEC_AUTHALG_MD5 :
        pStr = "md5";
        break;
    case IPSEC_AUTHALG_SHA1 :
        pStr = "sha1";
        break;
    case IPSEC_AUTHALG_AES :
        pStr = "aes-xcbc";
        break;
    case IPSEC_AUTHALG_SHA256 :
        pStr = "sha2-256";
        break;
    case IPSEC_AUTHALG_SHA384 :
        pStr = "sha2-384";
        break;
    case IPSEC_AUTHALG_SHA512 :
        pStr = "sha2-512";
        break;
    case IPSEC_AUTHALG_BLAKE2_2B :
        pStr = "blake2b";
        break;
    case IPSEC_AUTHALG_BLAKE2_2S :
        pStr = "blake2s";
        break;
    }

    if (NULL != pStr)
        printf("%s", pStr);
    else
        printf("%d", (sbyte4)oAuth);
} /* print_auth */


/*------------------------------------------------------------------*/

static void
print_encr(ubyte oEncr)
{
    sbyte *pStr = NULL;

    switch (oEncr)
    {
    case 0 :
        pStr = "any";
        break;
    case IPSEC_ENCALG_DES :
        pStr = "des";
        break;
    case IPSEC_ENCALG_3DES :
        pStr = "3des";
        break;
    case IPSEC_ENCALG_BLOWFISH :
        pStr = "blowfish";
        break;
    case IPSEC_ENCALG_AES :
        pStr = "aes";
        break;
    case IPSEC_ENCALG_AES_GCM :
        pStr = "gcm";
        break;
    case IPSEC_ENCALG_AES_GMAC :
        pStr = "gmac";
        break;
    case IPSEC_ENCALG_AES_CTR :
        pStr = "ctr";
        break;
    case IPSEC_ENCALG_AES_CCM :
        pStr = "ccm";
        break;
    case IPSEC_ENCALG_CHACHA20_POLY1305 :
        pStr = "chacha-poly";
        break;
    }

    if (NULL != pStr)
        printf("%s", pStr);
    else
        printf("%d", (sbyte4)oEncr);
} /* print_encr */


/*------------------------------------------------------------------*/

static sbyte4
print_sadb( SADB pxSa, ubyte4 index )
{
    ubyte4 i = index;
    int ipCount = 0;
    time_t clock;
    time(&clock);

    if (0 == pxSa->saFlags)
        return -1;

    printf("\n");

    /* */
    printf("%3d %s spi=%08x ", i+1,
           ((51/*IPPROTO_AH*/ == pxSa->oSaProto) ? "AH " :
            ((50/*IPPROTO_ESP*/ == pxSa->oSaProto) ? "ESP" : "*  ")),
           pxSa->dwSaSpi);

    /* */
 #ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
     if ((IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) || (pxSa->inbound) )
 #else
    if (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)
 #endif
    {
        MOC_IP_ADDRESS destAddr = REF_MOC_IPADDR(pxSa->dwSaDestAddr);

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (0 != pxSa->dwSaDestIPCount)
        {
	        for (ipCount = 0; ipCount < pxSa->dwSaDestIPCount; ipCount++)
	        {
	            if (!ISZERO_MOC_IPADDR(pxSa->dwSaDestIPList[ipCount]))
	            {
	                TEST_MOC_IPADDR6(pxSa->dwSaDestIPList[ipCount],
	                    print_ip6(GET_MOC_IPADDR6(pxSa->dwSaDestIPList[ipCount]));
	                )
	                print_ip(GET_MOC_IPADDR4(pxSa->dwSaDestIPList[ipCount]));
	            }
	            if (ipCount < pxSa->dwSaDestIPCount - 1)
	            {
	                printf(",");
	            }
	        }
        }
        else
#endif
        {
            if (!ISZERO_MOC_IPADDR(pxSa->dwSaDestAddr))
            {
                TEST_MOC_IPADDR6(destAddr,
                        print_ip6(GET_MOC_IPADDR6(destAddr));
                )
                print_ip(GET_MOC_IPADDR4(destAddr));
            }
        }

 #ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
	if ((0 != destAddr) && (0 != pxSa->dwSaDestIPEnd) && (!SAME_MOC_IPADDR(destAddr, pxSa->dwSaDestIPEnd)))
	{
	    int plen;
            MOC_IP_ADDRESS destIPEnd = REF_MOC_IPADDR(pxSa->dwSaDestIPEnd);

            plen = get_netmask(GET_MOC_IPADDR4(destAddr), GET_MOC_IPADDR4(destIPEnd));

	    if (0 <= plen) printf("/%d", plen);
	    else
	    {
               if (!ISZERO_MOC_IPADDR(pxSa->dwSaDestIPEnd))
	       {
		 printf("-");
		 TEST_MOC_IPADDR6(pxSa->dwSaDestIPEnd,
			print_ip6(GET_MOC_IPADDR6(pxSa->dwSaDestIPEnd));
			)
		  	print_ip(GET_MOC_IPADDR4(pxSa->dwSaDestIPEnd));
                 }
	     }

	}
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT == pxSa->oSaMode)
#endif
        {
            if (0 != pxSa->wSaDestPort)
                printf("[%d]", (int)pxSa->wSaDestPort);
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
            printf(" << ");
        else if (IPSEC_MODE_TRANSPORT != pxSa->oSaMode)
            printf(" <? ");
        else
#endif
            printf(" < ");

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if ((ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)) && (pxSa->dwSaSrcIPCount == 0))
#else
        if (ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))
#endif
            printf("*");
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        else if(0 != pxSa->dwSaSrcIPCount)
        {
            if (0 != pxSa->fqdn[0])
            {
                printf(" %s",pxSa->fqdn);
                if(pxSa->dwSaSrcIPCount != 0)
                {
                    printf(" [ ");
                    ubyte4 ipListCount = 0;
                    while (ipListCount < pxSa->dwSaSrcIPCount)
                    {
                        if(!ISZERO_MOC_IPADDR(pxSa->dwSaSrcIPList[ipListCount]))
                        {
                            TEST_MOC_IPADDR6(pxSa->dwSaSrcIPList[ipListCount],
                                    print_ip6(GET_MOC_IPADDR6(pxSa->dwSaSrcIPList[ipListCount]));
                            )
                            print_ip(GET_MOC_IPADDR4(pxSa->dwSaSrcIPList[ipListCount]));
                            printf(" ");
                        }
                        ipListCount++;
                    }
                    printf("]");
                }
            }
        }
#endif
        else
        {
            MOC_IP_ADDRESS srcAddr = REF_MOC_IPADDR(pxSa->dwSaSrcAddr);
            TEST_MOC_IPADDR6(srcAddr,
                print_ip6(GET_MOC_IPADDR6(srcAddr));
            )
                print_ip(GET_MOC_IPADDR4(srcAddr));
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT == pxSa->oSaMode)
#endif
        {
            if (0 != pxSa->wSaSrcPort)
                printf("[%d]", (int)pxSa->wSaSrcPort);
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
        {
            MOC_IP_ADDRESS destIP = REF_MOC_IPADDR(pxSa->dwSaDestIP);
            MOC_IP_ADDRESS srcIP = REF_MOC_IPADDR(pxSa->dwSaSrcIP);

            printf(" ");

            TEST_MOC_IPADDR6(destIP,
                print_ip6(GET_MOC_IPADDR6(destIP));
            )
                print_ip(GET_MOC_IPADDR4(destIP));

            printf("mode=%s", ((int)(pxSa->oSaMode) == 1) ? "transport" : (((int)(pxSa->oSaMode) == 2) ? "tunnel" : "dontcare"));
            if (!SAME_MOC_IPADDR(destIP, pxSa->dwSaDestIPEnd))
            {
                sbyte4 plen;
                MOC_IP_ADDRESS destIPEnd = REF_MOC_IPADDR(pxSa->dwSaDestIPEnd);

                TEST_MOC_IPADDR6(destIPEnd, {
                plen = get_netmask6(GET_MOC_IPADDR6(destIP), GET_MOC_IPADDR6(destIPEnd));
                })
                plen = get_netmask(GET_MOC_IPADDR4(destIP), GET_MOC_IPADDR4(destIPEnd));

                if (0 <= plen) printf("/%d", plen);
                else
                {
                    printf("-");
                    TEST_MOC_IPADDR6(destIPEnd,
                        print_ip6(GET_MOC_IPADDR6(destIPEnd));
                    )
                        print_ip(GET_MOC_IPADDR4(destIPEnd));
                }
            }
            if (0 != pxSa->wSaDestPort)
                printf("[%d]", (int)pxSa->wSaDestPort);

            printf(" < ");

            TEST_MOC_IPADDR6(srcIP,
                print_ip6(GET_MOC_IPADDR6(srcIP));
            )
                print_ip(GET_MOC_IPADDR4(srcIP));
                printf("mode=%s", ((int)(pxSa->oSaMode) == 1) ? "transport" : (((int)(pxSa->oSaMode)== 2) ? "tunnel" : "dontcare"));
            if (!SAME_MOC_IPADDR(srcIP, pxSa->dwSaSrcIPEnd))
            {
                sbyte4 plen;
                MOC_IP_ADDRESS srcIPEnd = REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd);

                TEST_MOC_IPADDR6(srcIPEnd, {
                plen = get_netmask6(GET_MOC_IPADDR6(srcIP), GET_MOC_IPADDR6(srcIPEnd));
                })
                plen = get_netmask(GET_MOC_IPADDR4(srcIP), GET_MOC_IPADDR4(srcIPEnd));

                if (0 <= plen) printf("/%d", plen);
                else
                {
                    printf("-");
                    TEST_MOC_IPADDR6(srcIPEnd,
                        print_ip6(GET_MOC_IPADDR6(srcIPEnd));
                    )
                        print_ip(GET_MOC_IPADDR4(srcIPEnd));
                }
            }
            if (0 != pxSa->wSaSrcPort)
                printf("[%d]", (int)pxSa->wSaSrcPort);
        }
#endif
    }
    else
    {
        MOC_IP_ADDRESS destAddr = REF_MOC_IPADDR(pxSa->dwSaDestAddr);

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if ((ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)) && (0 == pxSa->dwSaSrcIPCount))
#else
        if (ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))
#endif
            printf("*");
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        else if(0 != pxSa->dwSaSrcIPCount)
        {
                for (ipCount = 0; ipCount < pxSa->dwSaSrcIPCount; ipCount++)
                {
                    if (!ISZERO_MOC_IPADDR(pxSa->dwSaSrcIPList[ipCount]))
                    {
                        TEST_MOC_IPADDR6(pxSa->dwSaSrcIPList[ipCount],
                            print_ip6(GET_MOC_IPADDR6(pxSa->dwSaSrcIPList[ipCount]));
                        )
                        print_ip(GET_MOC_IPADDR4(pxSa->dwSaSrcIPList[ipCount]));
                    }
                    if (ipCount < pxSa->dwSaSrcIPCount - 1)
                    {
                        printf(",");
                    }
                }
        }
#endif
        else
        {
            MOC_IP_ADDRESS srcAddr = REF_MOC_IPADDR(pxSa->dwSaSrcAddr);
            TEST_MOC_IPADDR6(srcAddr,
                    print_ip6(GET_MOC_IPADDR6(srcAddr));
            )
            print_ip(GET_MOC_IPADDR4(srcAddr));
        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT == pxSa->oSaMode)
#endif
        {
            if (0 != pxSa->wSaSrcPort)
                printf("[%d]", (int)pxSa->wSaSrcPort);
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
            printf(" >> ");
        else if (IPSEC_MODE_TRANSPORT != pxSa->oSaMode)
            printf(" ?> ");
        else
#endif
            printf(" > ");

#ifdef __ENABLE_DIGICERT_IPV6__
	if (!ISZERO_MOC_IPADDR(*destAddr))
#else
	if (!ISZERO_MOC_IPADDR(destAddr))
#endif
	{
		TEST_MOC_IPADDR6(destAddr,
			print_ip6(GET_MOC_IPADDR6(destAddr));
		)
		print_ip(GET_MOC_IPADDR4(destAddr));
	}
 #ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
 #ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if (0 != pxSa->fqdn[0])
    {
        printf(" %s",pxSa->fqdn);
        if(pxSa->dwSaDestIPCount != 0)
        {
            printf(" [ ");
            ubyte4 ipListCount = 0;
            while (ipListCount < pxSa->dwSaDestIPCount)
            {
                if(!ISZERO_MOC_IPADDR(pxSa->dwSaDestIPList[ipListCount]))
                {
                    TEST_MOC_IPADDR6(pxSa->dwSaDestIPList[ipListCount],
                            print_ip6(GET_MOC_IPADDR6(pxSa->dwSaDestIPList[ipListCount]));
                    )
                    print_ip(GET_MOC_IPADDR4(pxSa->dwSaDestIPList[ipListCount]));
                    printf(" ");
                }
                ipListCount++;
            }
            printf("]");
        }
    }
#endif
            if ((0 != destAddr) && (0 != pxSa->dwSaDestIPEnd) && (!SAME_MOC_IPADDR(destAddr, pxSa->dwSaDestIPEnd)))
            {
                int plen;
                MOC_IP_ADDRESS destIPEnd = REF_MOC_IPADDR(pxSa->dwSaDestIPEnd);

                plen = get_netmask(GET_MOC_IPADDR4(destAddr), GET_MOC_IPADDR4(destIPEnd));

                if (0 <= plen) printf("/%d", plen);
                else
                {
                   if (!ISZERO_MOC_IPADDR(pxSa->dwSaDestIPEnd))
	           {
		     printf("-");
 	             TEST_MOC_IPADDR6(pxSa->dwSaDestIPEnd,
		 	 print_ip6(GET_MOC_IPADDR6(pxSa->dwSaDestIPEnd));
		 	 )
		  	 print_ip(GET_MOC_IPADDR4(pxSa->dwSaDestIPEnd));
                    }
                 }
            }
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT == pxSa->oSaMode)
#endif
        {
            if (0 != pxSa->wSaDestPort)
                printf("[%d]", (int)pxSa->wSaDestPort);
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
        {
            MOC_IP_ADDRESS srcIP = REF_MOC_IPADDR(pxSa->dwSaSrcIP);
            MOC_IP_ADDRESS destIP = REF_MOC_IPADDR(pxSa->dwSaDestIP);

            printf(" ");

            TEST_MOC_IPADDR6(srcIP,
                print_ip6(GET_MOC_IPADDR6(srcIP));
            )
                print_ip(GET_MOC_IPADDR4(srcIP));

            if (!SAME_MOC_IPADDR(srcIP, pxSa->dwSaSrcIPEnd))
            {
                sbyte4 plen;
                MOC_IP_ADDRESS srcIPEnd = REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd);

                TEST_MOC_IPADDR6(srcIPEnd, {
                plen = get_netmask6(GET_MOC_IPADDR6(srcIP), GET_MOC_IPADDR6(srcIPEnd));
                })
                plen = get_netmask(GET_MOC_IPADDR4(srcIP), GET_MOC_IPADDR4(srcIPEnd));

                if (0 <= plen) printf("/%d", plen);
                else
                {
                    printf("-");
                    TEST_MOC_IPADDR6(srcIPEnd,
                        print_ip6(GET_MOC_IPADDR6(srcIPEnd));
                    )
                        print_ip(GET_MOC_IPADDR4(srcIPEnd));
                }
            }
            if (0 != pxSa->wSaSrcPort)
                printf("[%d]", (int)pxSa->wSaSrcPort);

            printf(" > ");

            TEST_MOC_IPADDR6(destIP,
                print_ip6(GET_MOC_IPADDR6(destIP));
            )
                print_ip(GET_MOC_IPADDR4(destIP));

            if (!SAME_MOC_IPADDR(destIP, pxSa->dwSaDestIPEnd))
            {
                sbyte4 plen;
                MOC_IP_ADDRESS destIPEnd = REF_MOC_IPADDR(pxSa->dwSaDestIPEnd);

                TEST_MOC_IPADDR6(destIPEnd, {
                plen = get_netmask6(GET_MOC_IPADDR6(destIP), GET_MOC_IPADDR6(destIPEnd));
                })
                plen = get_netmask(GET_MOC_IPADDR4(destIP), GET_MOC_IPADDR4(destIPEnd));

                if (0 <= plen) printf("/%d", plen);
                else
                {
                    printf("-");
                    TEST_MOC_IPADDR6(destIPEnd,
                        print_ip6(GET_MOC_IPADDR6(destIPEnd));
                    )
                        print_ip(GET_MOC_IPADDR4(destIPEnd));
                }
            }
            if (0 != pxSa->wSaDestPort)
                printf("[%d]", (int)pxSa->wSaDestPort);
        }
#endif
    }

    if (0 != pxSa->oSaUlp)
    {
        printf(" ");
        print_proto(pxSa->oSaUlp);
    }
#ifdef __ENABLE_IPSEC_NAT_T__
    if (0 != pxSa->wSaUdpEncPort)
    {
        printf(" udp-enc");
        if (4500 != pxSa->wSaUdpEncPort)
            printf("[%d]", (int) pxSa->wSaUdpEncPort);
        if (IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)
            printf("*");
    }
#endif
    printf("\n");

    /* */
    printf("    id=<%u", pxSa->dwId);
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (pxSa->pxSaM) printf("|%u", pxSa->dwIdM);
#endif
    clock -= pxSa->dwSaEstablished / 1000;
    printf(">, created at %s", ctime(&clock));

    /* */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (0 != pxSa->dwSpdId)
    {
        printf("    spd=%d[%d] ike=%d<%08lx> ",
               (int)(uintptr_t)(pxSa->pxSp), pxSa->iNest,
               pxSa->ikeSaLoc+1, (unsigned long)pxSa->dwIkeSaId);
        printf("%s %s",
            ((IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) ? "inbound" : "outbound"),
            ((IPSEC_SA_FLAG_INITIATOR & pxSa->saFlags) ? "initiator" : "responder"));
        if (IPSEC_SA_FLAG_MATURE & pxSa->saFlags) printf(" mature");
        printf("\n");
    }
#endif
    /* */
    printf("    usage=%lu", (unsigned long)(pxSa->dwSaEstablished / 1000));
    if (pxSa->dwSaLastUsed)
    {
        printf("(%lu", (unsigned long)
               ((pxSa->dwSaEstablished - pxSa->dwSaLastUsed) / 1000));
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (0 != pxSa->dwSpdId)
        {
            if (pxSa->dwSaFirstUsed)
            {
                if (!(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
                {
                    if (pxSa->dwSaFirstUsed != pxSa->dwSaLastUsed)
                        printf("-%lu", (unsigned long)
                               ((pxSa->dwSaEstablished - pxSa->dwSaFirstUsed) / 1000));
                }
            }
            else if (pxSa->dwIdM) printf("+");
        }
#endif
        printf(")");
    }
    if (pxSa->dwSaExpSecs)
        printf("/%lu", (unsigned long) pxSa->dwSaExpSecs);

    printf(" secs, %lu.%d", (unsigned long) pxSa->dwSaCurKBytes,
           (pxSa->wSaCurBytes * 1000) / 1024);

    if (pxSa->dwSaExpKBytes)
        printf("/%lu", (unsigned long) pxSa->dwSaExpKBytes);

    printf(" kbytes, %lu", (unsigned long) pxSa->dwSaCurPackets);

    if (pxSa->dwSaTotPackets &&
        (pxSa->dwSaCurPackets != pxSa->dwSaTotPackets))
        printf("/%lu", (unsigned long) pxSa->dwSaTotPackets);

    printf(" pkts");

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    if ((NULL != pxSa->pxSp) && /* auto key */
        (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
    {
        int j;
#ifndef __ENABLE_IPSEC_ESN__
        ubyte4 dwSeqNbr = pxSa->u.d.seq;
#else
        ubyte8 seq = pxSa->u.d.seq;
        ubyte4 dwSeqNbrHi = HI_U8(seq);
        ubyte4 dwSeqNbr = LOW_U8(seq);

        if ((IPSEC_SA_FLAG_ESN & pxSa->saFlags) && (0 != dwSeqNbrHi))
            printf(" seq=[%lu]%lu",
                   (unsigned long)dwSeqNbrHi, (unsigned long)dwSeqNbr);
        else
#endif
        printf(" seq=%lu", (unsigned long)dwSeqNbr);

        printf("\n    replay=");
        for (j = (IPSEC_REPLAY_SIZE / 8) - 1; j >= 0; j--)
        {
            int k = pxSa->u.i.poReplayWindow[j];
            printf("%02x ", k & 0xff);
        }
    }
    else
#endif
    {
#ifndef __ENABLE_IPSEC_ESN__
        ubyte4 dwSeqNbr = pxSa->u.d.seq;
#else
        ubyte8 seq = pxSa->u.d.seq;
        ubyte4 dwSeqNbrHi = HI_U8(seq);
        ubyte4 dwSeqNbr = LOW_U8(seq);

        if (!(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) &&
            (IPSEC_SA_FLAG_ESN & pxSa->saFlags) && (0 != dwSeqNbrHi))
            printf(" (seq=[%lu]%lu)", (unsigned long)dwSeqNbrHi, (unsigned long)dwSeqNbr);
        else
#endif
        if (dwSeqNbr && (dwSeqNbr != pxSa->dwSaCurPackets))
            printf(" (seq=%lu)", (unsigned long)dwSeqNbr);
    }
    printf("\n");

    /* */
    if (NULL != pxSa->pHmacSuite)
    {
        int keylen = 0;
        ubyte auth = pxSa->pHmacSuite->oAuthAlgo;
                  /* pxSa->pHmacSuite->oAuthAlgo; */
        switch (auth)
        {
        case IPSEC_AUTHALG_MD5 :
            keylen = 16;
            break;
        case IPSEC_AUTHALG_SHA1 :
            keylen = 20;
            break;
        case IPSEC_AUTHALG_AES :
            keylen = 16;
            break;
        case IPSEC_AUTHALG_SHA256 :
            keylen = 32;
            break;
        case IPSEC_AUTHALG_SHA384 :
            keylen = 48;
            break;
        case IPSEC_AUTHALG_SHA512 :
            keylen = 64;
            break;
        case IPSEC_AUTHALG_BLAKE2_2B :
        case IPSEC_AUTHALG_BLAKE2_2S :
            keylen = 32;
            break;
        }
        printf("    auth=");
        print_auth(auth);
        printk("", (unsigned char *) &(pxSa->poAuthKey[0]), keylen);
    }

    /* */
    if (NULL != pxSa->pCipherSuite)
    {
        ubyte encr = pxSa->pCipherSuite->oEncrAlgo;
        /* pxSa->pCipherSuite->oEncrAlgo; */
        printf("    encr=");
        print_encr(encr);

        printk("", (unsigned char *) &(pxSa->poEncrKey[0]), pxSa->wEncrKeyLen);
    }
    /* pxSa->dwId; */

    return 0;
} /* print_sadb */


/*------------------------------------------------------------------*/

static sbyte4
print_spd( SPD pxSp, sbyte4 *pIndex, sbyte4 *pMirrored )
{
    sbyte4 mirrored = *pMirrored;
    sbyte4 i;
    int ipCount = 0;
    byteBoolean raddrFinished = 0;

    if (0 == pxSp->flags)
        return -1;

    if (*pIndex == pxSp->index)
    {
        if (mirrored)
            goto stats;
        printf("  ");
    }
    else
    {
        if (IPSEC_SP_FLAG_MIRRORED & pxSp->flags)
            mirrored = 1;
        else mirrored = 0;

        *pIndex = pxSp->index;
        printf("%2d", *pIndex);
    }

    printf(" {");
    for (i=0; i<2; i++)
    {
        if ((!i && (IPSEC_SP_FLAG_INBOUND & pxSp->flags) &&
                    (IPSEC_ACTION_DROP != pxSp->oAction)) || /* should process raddr first */
            (i && !(IPSEC_SP_FLAG_INBOUND & pxSp->flags)) ||
            ((IPSEC_ACTION_DROP == pxSp->oAction) && raddrFinished))
        {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            if (pxSp->isUnicastGDOI)
            {
                if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
                {
                    printf(" laddr ");
                    if(0 != pxSp->fqdn[0])
                    {
                        if(pxSp->dwSrcIPCount != 0)
                        {
                            if (IPSEC_ACTION_DROP != pxSp->oAction)
                            {
                                printf("%s ",pxSp->fqdn);
                                printf(" [ ");
                                ubyte4 ipListCount = 0;
                                while (ipListCount < pxSp->dwSrcIPCount)
                                {
                                    if(!ISZERO_MOC_IPADDR(pxSp->dwSrcIPList[ipListCount]))
                                    {
                                        TEST_MOC_IPADDR6(pxSp->dwSrcIPList[ipListCount],
                                        print_ip6(GET_MOC_IPADDR6(pxSp->dwSrcIPList[ipListCount]));
                                        )
                                        print_ip(GET_MOC_IPADDR4(pxSp->dwSrcIPList[ipListCount]));
                                        printf(" ");
                                    }
                                    ipListCount++;
                                }
                                printf("]");
                            }
                            else
                            {
                                /* in unicast DROP case pxSp->dwDestIP holds laddr IP
                                 * and pxSp->dwSrcIPList[] holds unicast group (as raddr_list) */
                                if(!ISZERO_MOC_IPADDR(pxSp->dwDestIP))
                                {
                                    TEST_MOC_IPADDR6(pxSp->dwDestIP,
                                    print_ip6(GET_MOC_IPADDR6(pxSp->dwDestIP));
                                    )
                                    print_ip(GET_MOC_IPADDR4(pxSp->dwDestIP));
                                    printf(" ");
                                }

                                raddrFinished = 0;
                            }
                            if (pxSp->wPortCount)
			    {
			        printf(" port_list ");
			        for (i = 0; i < pxSp->wPortCount; i++)
			        {
			            if (i > 0)
			            {
			                printf(",");
			            }
			            print_port(pxSp->wPortList[i]);
			        }
			    }
                            if (0 != pxSp->wSrcPort)
                            {
                                if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
                                    printf(" rport ");
                                else
                                    printf(" lport ");
                                print_port(pxSp->wSrcPort);
                            }
                            if (0 != pxSp->wDestPort)
                            {
                                if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
                                    printf(" lport ");
                                else
                                    printf(" rport ");
                                print_port(pxSp->wDestPort);
                            }
                            else if(pxSp->wDestPortCount)
                            {
                                printf(" lport_list ");
                                for(i = 0; i < pxSp->wDestPortCount; i++)
                                {
                                    if(i > 0)
                                    {
                                        printf(",");
                                    }
                                    print_port(pxSp->wDestPortList[i]);
                                }
                            }
			    break;
                        }
                    }
                }
            }
            else
#endif
            {
                if (!any_ip_range(REF_MOC_IPADDR(pxSp->dwDestIP), REF_MOC_IPADDR(pxSp->dwDestIPEnd)))
                {
                    MOC_IP_ADDRESS destIP = REF_MOC_IPADDR(pxSp->dwDestIP);

                    if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
                        printf(" laddr ");
                    else
                        printf(" raddr ");

                    TEST_MOC_IPADDR6(destIP,
                            print_ip6(GET_MOC_IPADDR6(destIP));
                            )
                        print_ip(GET_MOC_IPADDR4(destIP));

                    if (!SAME_MOC_IPADDR(destIP, pxSp->dwDestIPEnd))
                    {
                        MOC_IP_ADDRESS destIPEnd = REF_MOC_IPADDR(pxSp->dwDestIPEnd);
                        int plen;

                        TEST_MOC_IPADDR6(destIPEnd, {
                                plen = get_netmask6(GET_MOC_IPADDR6(destIP), GET_MOC_IPADDR6(destIPEnd));
                                })
                        plen = get_netmask(GET_MOC_IPADDR4(destIP), GET_MOC_IPADDR4(destIPEnd));

                        if (0 <= plen) printf("/%d", plen);
                        else
                        {
                            printf("-");
                            TEST_MOC_IPADDR6(destIPEnd,
                                    print_ip6(GET_MOC_IPADDR6(destIPEnd));
                                    )
                                print_ip(GET_MOC_IPADDR4(destIPEnd));
                        }
                    }
                }
            }
            if (pxSp->wPortCount)
            {
                printf(" port_list ");
                for (i = 0; i < pxSp->wPortCount; i++)
                {
                    if (i > 0)
                    {
                        printf(",");
                    }
                    print_port(pxSp->wPortList[i]);
                }
            }
	    if (0 != pxSp->wDestPort)
	    {
	        if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
	            printf(" lport ");
	        else
	            printf(" rport ");
	        print_port(pxSp->wDestPort);
	    }
	    else if(pxSp->wDestPortCount)
            {
                printf(" lport_list ");
                for(i = 0; i < pxSp->wDestPortCount; i++)
                {
                    if(i > 0)
                    {
                        printf(",");
                    }
                    print_port(pxSp->wDestPortList[i]);
                }
            }
    }
    else
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxSp->isUnicastGDOI)
        {
            printf(" raddr ");
            if(0 != pxSp->fqdn[0])
            {
                printf("%s ",pxSp->fqdn);
                if(pxSp->dwDestIPCount != 0)
                {
                    printf(" [ ");
                    ubyte4 ipListCount = 0;
                    while (ipListCount < pxSp->dwDestIPCount)
                    {
                        if(!ISZERO_MOC_IPADDR(pxSp->dwDestIPList[ipListCount]))
                        {
                            TEST_MOC_IPADDR6(pxSp->dwDestIPList[ipListCount],
                                    print_ip6(GET_MOC_IPADDR6(pxSp->dwDestIPList[ipListCount]));
                                    )
                                print_ip(GET_MOC_IPADDR4(pxSp->dwDestIPList[ipListCount]));
                            printf(" ");
                        }
                        ipListCount++;
                    }
                    printf("]");
                }
            }

            /* in DROP case, unicast group is always stored in pxSp->dwSrcIPList */
            if (IPSEC_ACTION_DROP != pxSp->oAction)
            {
                if (pxSp->dwSrcIPCount > 1)
                {
                    printf(" laddr_ex ");
                }
                else
                {
                    printf(" laddr ");
                }
            }

            printf(" [ ");
            for (ipCount = 0; ipCount < pxSp->dwSrcIPCount; ipCount++)
            {
                TEST_MOC_IPADDR6(pxSp->dwSrcIPList[ipCount],
                    print_ip6(GET_MOC_IPADDR6(pxSp->dwSrcIPList[ipCount]));
                )
                print_ip(GET_MOC_IPADDR4(pxSp->dwSrcIPList[ipCount]));
                if (ipCount < pxSp->dwSrcIPCount - 1)
                {
                    printf(",");
                }
            }
            printf(" ] ");
        }
        else
#endif
        {

    if (!any_ip_range(REF_MOC_IPADDR(pxSp->dwSrcIP), REF_MOC_IPADDR(pxSp->dwSrcIPEnd)))
    {
        MOC_IP_ADDRESS srcIP = REF_MOC_IPADDR(pxSp->dwSrcIP);

        if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
            printf(" raddr ");
        else
            printf(" laddr ");

        TEST_MOC_IPADDR6(srcIP,
            print_ip6(GET_MOC_IPADDR6(srcIP));
        )
            print_ip(GET_MOC_IPADDR4(srcIP));

        if (!SAME_MOC_IPADDR(srcIP, pxSp->dwSrcIPEnd))
        {
            MOC_IP_ADDRESS srcIPEnd = REF_MOC_IPADDR(pxSp->dwSrcIPEnd);

            int plen;

            TEST_MOC_IPADDR6(srcIPEnd, {
            plen = get_netmask6(GET_MOC_IPADDR6(srcIP), GET_MOC_IPADDR6(srcIPEnd));
            })
            plen = get_netmask(GET_MOC_IPADDR4(srcIP), GET_MOC_IPADDR4(srcIPEnd));

            if (0 <= plen) printf("/%d", plen);
            else
            {
                printf("-");
                TEST_MOC_IPADDR6(srcIPEnd,
                    print_ip6(GET_MOC_IPADDR6(srcIPEnd));
                )
                    print_ip(GET_MOC_IPADDR4(srcIPEnd));
            }
        }
    }
        }
    if (0 != pxSp->wSrcPort)
    {
        if (mirrored || (IPSEC_SP_FLAG_INBOUND & pxSp->flags))
            printf(" rport ");
        else
            printf(" lport ");
        print_port(pxSp->wSrcPort);
    }

        if (IPSEC_ACTION_DROP == pxSp->oAction)
            raddrFinished = 1;
        }
    } /* for */

    if (0 != pxSp->oProto)
    {
        printf(" ulp ");
        print_proto(pxSp->oProto);
    }

    switch (pxSp->oAction)
    {
    case IPSEC_ACTION_APPLY :
    case IPSEC_ACTION_PERMIT :
        /* if (mirrored) printf(" dir mirrored"); */
        break;
    case IPSEC_ACTION_DROP :
    case IPSEC_ACTION_BYPASS :
    default :
        if (!mirrored)
        {
            printf(" dir ");
            if (IPSEC_SP_FLAG_INBOUND & pxSp->flags)
                printf("in");
            else
                printf("out");
        }
        break;
    }
    printf(" } ");

    switch (pxSp->oAction)
    {
    case IPSEC_ACTION_DROP :
        printf("drop"); break;
    case IPSEC_ACTION_BYPASS :
        printf("bypass"); break;
    case IPSEC_ACTION_APPLY :
        printf("apply"); break;
    case IPSEC_ACTION_PERMIT :
        if (mirrored) printf("ipsec"); else
        printf("permit"); break;
    default : printf("?"); break;
    }

    if ((IPSEC_ACTION_APPLY == pxSp->oAction) ||
        (IPSEC_ACTION_PERMIT == pxSp->oAction))
    {
        int k;
        printf(" {");

        for (k = pxSp->oSaLen - 1; k >= 0; k--)
        {
            struct sainfo *si = &(pxSp->pxSa[k]);

            switch (si->oSecuProto)
            {
            case IPSEC_PROTO_AH :
                printf(" auth_algs ");
                print_auth(si->oAuthAlgo);
                break;
            case IPSEC_PROTO_ESP :
            case IPSEC_PROTO_ESP_AUTH :
                printf(" encr_algs ");
                print_encr(si->oEncrAlgo);
                if (0 != si->aeadTag)
                    printf(" tag %d", (int) si->aeadTag);
                if (0 != si->oEncrKeyLen)
                    printf(" keylength %d", (int) si->oEncrKeyLen);
                break;
            }

            switch (si->oSecuProto)
            {
            case IPSEC_PROTO_ESP_NULL :
            case IPSEC_PROTO_ESP_AUTH :
                printf(" encr_auth_algs ");
                print_auth(si->oAuthAlgo);
                break;
            }
        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT != pxSp->oMode)
        {
            if (IPSEC_MODE_TUNNEL != pxSp->oMode)
                printf(" *");
            else
            {
                if (mirrored) printf(" tladdr ");
                else printf(" tdst ");

                if (ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP))
                    printf(" 0 ");
                else
                {
                    MOC_IP_ADDRESS tunlDestIP = REF_MOC_IPADDR(pxSp->dwTunlDestIP);
                    TEST_MOC_IPADDR6(tunlDestIP,
                        print_ip6(GET_MOC_IPADDR6(tunlDestIP));
                    )
                        print_ip(GET_MOC_IPADDR4(tunlDestIP));
                }
                if (mirrored) printf(" traddr ");
                else printf(" tsrc ");

                if (ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP))
                    printf(" 0 ");
                else
                {
                    MOC_IP_ADDRESS tunlSrcIP = REF_MOC_IPADDR(pxSp->dwTunlSrcIP);
                    TEST_MOC_IPADDR6(tunlSrcIP,
                        print_ip6(GET_MOC_IPADDR6(tunlSrcIP));
                    )
                        print_ip(GET_MOC_IPADDR4(tunlSrcIP));
                }
            }
        }
#endif
        printf(" }");
    }
    printf("\n");
stats:
    if (0 != pxSp->dwTotPackets)
    {
        switch (pxSp->oAction)
        {
        case IPSEC_ACTION_APPLY :
        case IPSEC_ACTION_PERMIT :
            printf("     %lu", (unsigned long) pxSp->dwCurPackets);
            if (pxSp->dwTotPackets != pxSp->dwCurPackets)
                printf("/%lu", (unsigned long) pxSp->dwTotPackets);
            printf(" pkts, %lu.%d kbytes",
                    (unsigned long) pxSp->dwCurKBytes,
                    (pxSp->wCurBytes * 1000) / 1024);
            break;
        default :
            printf("     %lu pkts", (unsigned long) pxSp->dwTotPackets);
            break;
        }
        if (IPSEC_SP_FLAG_INBOUND & pxSp->flags)
            printf(" received\n");
        else printf(" sent\n");
    }

    *pMirrored = mirrored;

    return 0;
} /* print_spd() */

