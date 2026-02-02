/*
 * hash_value.c
 *
 * Generate Hash Value Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/*
 * -------------------------------------------------------------------------------
 * http://www.burtleburtle.net/bob/c/lookup3.c
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  You can use this free for any purpose.
 * It's in the public domain.  It has no warranty.
 *
 * You probably want to use hashlittle().  hashlittle() and hashbig()
 * hash byte arrays.  hashlittle() is is faster than hashbig() on
 * little-endian machines.  Intel and AMD are little-endian machines.
 * On second thought, you probably want hashlittle2(), which is identical to
 * hashlittle() except it returns two 32-bit hashes for the price of one.
 * You could implement hashbig2() if you wanted but I haven't bothered here.
 *
 * If you want to find a hash of, say, exactly 7 integers, do
 *   a = i1;  b = i2;  c = i3;
 *   mix(a,b,c);
 *   a += i4; b += i5; c += i6;
 *   mix(a,b,c);
 *   a += i7;
 *   final(a,b,c);
 * then use c as the hash value.  If you have a variable length array of
 * 4-byte integers to hash, use hashword().  If you have a byte array (like
 * a character string), use hashlittle().  If you have several byte arrays, or
 * a mix of things, see the comments above hashlittle().
 *
 * Why is this so big?  I read 12 bytes at a time into 3 4-byte integers,
 * then mix those integers.  This is fast (you can do a lot more thorough
 * mixing with 12*3 instructions on 3 integers than you can with 3 instructions
 * on 1 byte), but shoehorning those bytes into integers efficiently is messy.
 * -------------------------------------------------------------------------------
 */

#include "../common/moptions.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/hash_value.h"

#ifdef __ENABLE_FSANITIZE__
#undef MOC_LITTLE_ENDIAN
#undef MOC_BIG_ENDIAN
#endif

#if ((!defined(__DISABLE_DIGICERT_COMMON_HASH_VALUE_GENERATE__)) && \
     (!defined(__DISABLE_DIGICERT_COMMON_HASH_TABLE_FACTORY__)))

#if ((defined(MOC_LITTLE_ENDIAN)) && (defined(MOC_BIG_ENDIAN)))
#error Pick either MOC_LITTLE_ENDIAN or MOC_BIG_ENDIAN or pick neither.
#endif


/*--------------------------------------------------------------------------*/

#define hashsize(n) ((ubyte4)1<<(n))
#define hashmask(n) (hashsize(n)-1)
#define rot(x,pHashKey) (((x)<<(pHashKey)) ^ ((x)>>(32-(pHashKey))))


/*--------------------------------------------------------------------------*/


/*
 * -------------------------------------------------------------------------------
 * mix -- mix 3 32-bit values reversibly.
 *
 * This is reversible, so any information in (a,b,c) before mix() is
 * still in (a,b,c) after mix().
 *
 * If four pairs of (a,b,c) inputs are run through mix(), or through
 * mix() in reverse, there are at least 32 bits of the output that
 * are sometimes the same for one pair and different for another pair.
 * This was tested for:
 * + pairs that differed by one bit, by two bits, in any combination
 *   of top bits of (a,b,c), or in any combination of bottom bits of
 *   (a,b,c).
 * + "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
 *   the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
 *   is commonly produced by subtraction) look like a single 1-bit
 *   difference.
 * + the base values were pseudorandom, all zero but one bit set, or
 *   all zero plus a counter that starts at zero.
 *
 * Some pHashKey values for my "a-=c; a^=rot(c,pHashKey); c+=b;" arrangement that
 * satisfy this are
 *     4  6  8 16 19  4
 *     9 15  3 18 27 15
 *    14  9  3  7 17  3
 * Well, "9 15 3 18 27 15" didn't quite get 32 bits diffing
 * for "differ" defined as + with a one-bit base and a two-bit delta.  I
 * used http://burtleburtle.net/bob/hash/avalanche.html to choose
 * the operations, constants, and arrangements of the variables.
 *
 * This does not achieve avalanche.  There are input bits of (a,b,c)
 * that fail to affect some output bits of (a,b,c), especially of a.  The
 * most thoroughly mixed value is c, but it doesn't really even achieve
 * avalanche in c.
 *
 * This allows some parallelism.  Read-after-writes are good at doubling
 * the number of bits affected, so the goal of mixing pulls in the opposite
 * direction as the goal of parallelism.  I did what I could.  Rotates
 * seem to cost as much as shifts on every machine I could lay my hands
 * on, and rotates are much kinder to the top and bottom bits, so I used
 * rotates.
 * -------------------------------------------------------------------------------
 */

#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

/*
 * -------------------------------------------------------------------------------
 * final -- final mixing of 3 32-bit values (a,b,c) into c
 *
 * Pairs of (a,b,c) values differing in only a few bits will usually
 * produce values of c that look totally different.  This was tested for
 * + pairs that differed by one bit, by two bits, in any combination
 *   of top bits of (a,b,c), or in any combination of bottom bits of
 *   (a,b,c).
 * + "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
 *   the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
 *   is commonly produced by subtraction) look like a single 1-bit
 *   difference.
 * + the base values were pseudorandom, all zero but one bit set, or
 *   all zero plus a counter that starts at zero.
 *
 * These constants passed:
 *  14 11 25 16 4 14 24
 *  12 14 25 16 4 14 24
 * and these came close:
 *   4  8 15 26 3 22 24
 *  10  8 15 26 3 22 24
 *  11  8 15 26 3 22 24
 * -------------------------------------------------------------------------------
 */

#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}


/*--------------------------------------------------------------------------*/

/*
 * --------------------------------------------------------------------
 *  This works on all machines.  To be useful, it requires
 *  -- that the key be an array of ubyte4's, and
 *  -- that the length be the number of ubyte4's in the key
 *
 *  The function hashword() is identical to hashlittle() on little-endian
 *  machines, and identical to hashbig() on big-endian machines,
 *  except that the length has to be measured in uint32_ts rather than in
 *  bytes.  hashlittle() is more complicated than hashword() only because
 *  hashlittle() has to dance around fitting the key bytes into registers.
 * --------------------------------------------------------------------
 */

extern MSTATUS
HASH_VALUE_hashWord(const ubyte4 *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue)
{
    ubyte4  a;
    ubyte4  b;
    ubyte4  c;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + (((ubyte4)hashKeyDataLength)<<2) + initialHashValue;

    while (hashKeyDataLength > 3)
    {
        a += pHashKeyData[0];
        b += pHashKeyData[1];
        c += pHashKeyData[2];
        mix(a,b,c);
        hashKeyDataLength -= 3;
        pHashKeyData += 3;
    }

    switch(hashKeyDataLength)
    {
        case 3 : c+=pHashKeyData[2];
        case 2 : b+=pHashKeyData[1];
        case 1 : a+=pHashKeyData[0];
        {
            final(a,b,c);
            /* FALL THROUGH */
        }

        case 0:
            /* case 0: nothing left to add */
            break;
    }

    *pRetHashValue = c;

    return OK;
}


/*
 * -------------------------------------------------------------------------------
 * hashlittle() -- hash a variable-length key into a 32-bit value
 *   pHashKeyData        : the key (the unaligned variable-length array of bytes)
 *   hashKeyDataLength   : the length of the key, counting by bytes
 *   initialHashValue    : can be any 4-byte value
 *   *pRetHashValue      : Every bit of the key affects every bit of
 * hash value.  Two keys differing by one or two bits will have
 * totally different hash values.
 *
 * The best hash table sizes are powers of 2.  There is no need to do
 * mod a prime (mod is sooo slow!).  If you need less than 32 bits,
 * use a bitmask.  For example, if you need only 10 bits, do
 *   h = (h & hashmask(10));
 * In which case, the hash table should have hashsize(10) elements.
 *
 * If you are hashing n strings (ubyte **)pHashKey, do it like this:
 *   for (i=0, h=0; i<n; ++i) h = hashlittle( pHashKey[i], len[i], h);
 *
 * By Bob Jenkins, 2006.  bob_jenkins@burtleburtle.net.  You may use this
 * code any way you wish, private, educational, or commercial.  It's free.
 *
 * Use for hash table lookup, or anything where one collision in 2^^32 is
 * acceptable.  Do NOT use for cryptographic purposes.
 * -------------------------------------------------------------------------------
 */

#if (defined(MOC_LITTLE_ENDIAN))
extern void
HASH_VALUE_hashGen(const void *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue)
{
    ubyte4  a;
    ubyte4  b;
    ubyte4  c;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + ((ubyte4)hashKeyDataLength) + initialHashValue;

    if (0 == (((uintptr)(pHashKeyData)) & 0x3))
    {
        const ubyte4 *pHashKey = (const ubyte4*) pHashKeyData;  /* read 32-bit chunks */

        /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
        while (hashKeyDataLength > 12)
        {
            a += pHashKey[0];
            b += pHashKey[1];
            c += pHashKey[2];
            mix(a,b,c);

            hashKeyDataLength -= 12;
            pHashKey += 3;
        }

        /*----------------------------- handle the last (probably partial) block */
        /*
        * "pHashKey[2]&0xffffff" actually reads beyond the end of the string, but
        * then masks off the part it's not allowed to read.  Because the
        * string is aligned, the masked-off tail is in the same word as the
        * rest of the string.  Every machine with memory protection I've seen
        * does it on word boundaries, so is OK with this.  But VALGRIND will
        * still catch it and complain.  The masking trick does make the hash
        * noticably faster for short strings (like English words).
        */
        switch(hashKeyDataLength)
        {
            case 12: c+=pHashKey[2]; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 11: c+=pHashKey[2]&0xffffff; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 10: c+=pHashKey[2]&0xffff; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 9 : c+=pHashKey[2]&0xff; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 8 : b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 7 : b+=pHashKey[1]&0xffffff; a+=pHashKey[0]; break;
            case 6 : b+=pHashKey[1]&0xffff; a+=pHashKey[0]; break;
            case 5 : b+=pHashKey[1]&0xff; a+=pHashKey[0]; break;
            case 4 : a+=pHashKey[0]; break;
            case 3 : a+=pHashKey[0]&0xffffff; break;
            case 2 : a+=pHashKey[0]&0xffff; break;
            case 1 : a+=pHashKey[0]&0xff; break;
            case 0 : goto exit;              /* zero length strings require no mixing */
        }

    }
    else if (0 == (((uintptr)(pHashKeyData)) & 0x1))
    {
        const ubyte2 *pHashKey = (const ubyte2*) pHashKeyData;     /* read 16-bit chunks */
        const ubyte  *k8;

        /*--------------- all but last block: aligned reads and different mixing */
        while (hashKeyDataLength > 12)
        {
            a += pHashKey[0] + (((ubyte4)pHashKey[1])<<16);
            b += pHashKey[2] + (((ubyte4)pHashKey[3])<<16);
            c += pHashKey[4] + (((ubyte4)pHashKey[5])<<16);
            mix(a,b,c);

            hashKeyDataLength -= 12;
            pHashKey += 6;
        }

        /*----------------------------- handle the last (probably partial) block */
        k8 = (const ubyte *)pHashKey;
        switch(hashKeyDataLength)
        {
            case 12: c+=pHashKey[4]+(((ubyte4)pHashKey[5])<<16);
                b+=pHashKey[2]+(((ubyte4)pHashKey[3])<<16);
                a+=pHashKey[0]+(((ubyte4)pHashKey[1])<<16);
                break;
            case 11: c+=((ubyte4)k8[10])<<16;       /* fall through */
            case 10: c+=pHashKey[4];
                b+=pHashKey[2]+(((ubyte4)pHashKey[3])<<16);
                a+=pHashKey[0]+(((ubyte4)pHashKey[1])<<16);
                break;
            case 9 : c+=k8[8];                      /* fall through */
            case 8 : b+=pHashKey[2]+(((ubyte4)pHashKey[3])<<16);
                a+=pHashKey[0]+(((ubyte4)pHashKey[1])<<16);
                break;
            case 7 : b+=((ubyte4)k8[6])<<16;        /* fall through */
            case 6 : b+=pHashKey[2];
                a+=pHashKey[0]+(((ubyte4)pHashKey[1])<<16);
                break;
            case 5 : b+=k8[4];                      /* fall through */
            case 4 : a+=pHashKey[0]+(((ubyte4)pHashKey[1])<<16);
                break;
            case 3 : a+=((ubyte4)k8[2])<<16;        /* fall through */
            case 2 : a+=pHashKey[0];
                break;
            case 1 : a+=k8[0];
                break;
            case 0 : goto exit;                      /* zero length requires no mixing */
        }

    }
    else
    {
        /* need to read the key one byte at a time */
        const ubyte *pHashKey = (const ubyte*) pHashKeyData;

        /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
        while (hashKeyDataLength > 12)
        {
            a += pHashKey[0];
            a += ((ubyte4)pHashKey[1])<<8;
            a += ((ubyte4)pHashKey[2])<<16;
            a += ((ubyte4)pHashKey[3])<<24;
            b += pHashKey[4];
            b += ((ubyte4)pHashKey[5])<<8;
            b += ((ubyte4)pHashKey[6])<<16;
            b += ((ubyte4)pHashKey[7])<<24;
            c += pHashKey[8];
            c += ((ubyte4)pHashKey[9])<<8;
            c += ((ubyte4)pHashKey[10])<<16;
            c += ((ubyte4)pHashKey[11])<<24;
            mix(a,b,c);

            hashKeyDataLength -= 12;
            pHashKey += 12;
        }

        /*-------------------------------- last block: affect all 32 bits of (c) */
        switch(hashKeyDataLength)                   /* all the case statements fall through */
        {
            case 12: c+=((ubyte4)pHashKey[11])<<24;
            case 11: c+=((ubyte4)pHashKey[10])<<16;
            case 10: c+=((ubyte4)pHashKey[9])<<8;
            case 9 : c+=pHashKey[8];
            case 8 : b+=((ubyte4)pHashKey[7])<<24;
            case 7 : b+=((ubyte4)pHashKey[6])<<16;
            case 6 : b+=((ubyte4)pHashKey[5])<<8;
            case 5 : b+=pHashKey[4];
            case 4 : a+=((ubyte4)pHashKey[3])<<24;
            case 3 : a+=((ubyte4)pHashKey[2])<<16;
            case 2 : a+=((ubyte4)pHashKey[1])<<8;
            case 1 : a+=pHashKey[0];
                break;
            case 0 : goto exit;
        }
    }

    final(a,b,c);

exit:
    *pRetHashValue = c;
}
#endif /* (defined(MOC_LITTLE_ENDIAN)) */


/*------------------------------------------------------------------*/

/*
 * hashbig():
 * This is the same as hashword() on big-endian machines.  It is different
 * from hashlittle() on all machines.  hashbig() takes advantage of
 * big-endian byte ordering.
 */
#if (defined(MOC_BIG_ENDIAN))
extern void
HASH_VALUE_hashGen(const void *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue)
{
    ubyte4 a,b,c;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + ((ubyte4)hashKeyDataLength) + initialHashValue;

    if (0 == (((uintptr)(pHashKeyData)) & 0x03))
    {
        /* read 32-bit chunks */
        const ubyte4 *pHashKey = pHashKeyData;

        /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
        while (hashKeyDataLength > 12)
        {
            a += pHashKey[0];
            b += pHashKey[1];
            c += pHashKey[2];
            mix(a,b,c);

            hashKeyDataLength -= 12;
            pHashKey += 3;
        }

        /*----------------------------- handle the last (probably partial) block */
        /*
         * "pHashKey[2]<<8" actually reads beyond the end of the string, but
         * then shifts out the part it's not allowed to read.  Because the
         * string is aligned, the illegal read is in the same word as the
         * rest of the string.  Every machine with memory protection I've seen
         * does it on word boundaries, so is OK with this.  But VALGRIND will
         * still catch it and complain.  The masking trick does make the hash
         * noticably faster for short strings (like English words).
         */
        switch(hashKeyDataLength)
        {
            case 12: c+=pHashKey[2]; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 11: c+=pHashKey[2]&0xffffff00; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 10: c+=pHashKey[2]&0xffff0000; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 9 : c+=pHashKey[2]&0xff000000; b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 8 : b+=pHashKey[1]; a+=pHashKey[0]; break;
            case 7 : b+=pHashKey[1]&0xffffff00; a+=pHashKey[0]; break;
            case 6 : b+=pHashKey[1]&0xffff0000; a+=pHashKey[0]; break;
            case 5 : b+=pHashKey[1]&0xff000000; a+=pHashKey[0]; break;
            case 4 : a+=pHashKey[0]; break;
            case 3 : a+=pHashKey[0]&0xffffff00; break;
            case 2 : a+=pHashKey[0]&0xffff0000; break;
            case 1 : a+=pHashKey[0]&0xff000000; break;
            case 0 : goto exit;              /* zero hashKeyDataLength strings require no mixing */
        }
    }
    else
    {
        /* need to read the pHashKeyData one byte at a time */
        const ubyte *pHashKey = (const ubyte*) pHashKeyData;

        /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
        while (hashKeyDataLength > 12)
        {
            a += ((ubyte4)pHashKey[0])<<24;
            a += ((ubyte4)pHashKey[1])<<16;
            a += ((ubyte4)pHashKey[2])<<8;
            a += ((ubyte4)pHashKey[3]);
            b += ((ubyte4)pHashKey[4])<<24;
            b += ((ubyte4)pHashKey[5])<<16;
            b += ((ubyte4)pHashKey[6])<<8;
            b += ((ubyte4)pHashKey[7]);
            c += ((ubyte4)pHashKey[8])<<24;
            c += ((ubyte4)pHashKey[9])<<16;
            c += ((ubyte4)pHashKey[10])<<8;
            c += ((ubyte4)pHashKey[11]);
            mix(a,b,c);

            hashKeyDataLength -= 12;
            pHashKey += 12;
        }

        /*-------------------------------- last block: affect all 32 bits of (c) */
        switch(hashKeyDataLength)                   /* all the case statements fall through */
        {
            case 12: c+=pHashKey[11];
            case 11: c+=((ubyte4)pHashKey[10])<<8;
            case 10: c+=((ubyte4)pHashKey[9])<<16;
            case 9 : c+=((ubyte4)pHashKey[8])<<24;
            case 8 : b+=pHashKey[7];
            case 7 : b+=((ubyte4)pHashKey[6])<<8;
            case 6 : b+=((ubyte4)pHashKey[5])<<16;
            case 5 : b+=((ubyte4)pHashKey[4])<<24;
            case 4 : a+=pHashKey[3];
            case 3 : a+=((ubyte4)pHashKey[2])<<8;
            case 2 : a+=((ubyte4)pHashKey[1])<<16;
            case 1 : a+=((ubyte4)pHashKey[0])<<24;
                break;
            case 0 : goto exit;
        }
    }

    final(a,b,c);

exit:
    *pRetHashValue = c;
}
#endif /* (defined(MOC_BIG_ENDIAN)) */


/*------------------------------------------------------------------*/

#if ((!defined(MOC_LITTLE_ENDIAN)) && (!defined(MOC_BIG_ENDIAN)))
extern void
HASH_VALUE_hashGen(const void *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue)
{
    /* not optimized for little or big endian --- safe but slower */
    ubyte4          a;
    ubyte4          b;
    ubyte4          c;
    const ubyte*    pHashKey = ( const ubyte*) pHashKeyData;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + ((ubyte4)hashKeyDataLength) + initialHashValue;

    /* need to read the key one byte at a time */
    /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
    while (hashKeyDataLength > 12)
    {
        a += pHashKey[0];
        a += ((ubyte4)pHashKey[1])<<8;
        a += ((ubyte4)pHashKey[2])<<16;
        a += ((ubyte4)pHashKey[3])<<24;
        b += pHashKey[4];
        b += ((ubyte4)pHashKey[5])<<8;
        b += ((ubyte4)pHashKey[6])<<16;
        b += ((ubyte4)pHashKey[7])<<24;
        c += pHashKey[8];
        c += ((ubyte4)pHashKey[9])<<8;
        c += ((ubyte4)pHashKey[10])<<16;
        c += ((ubyte4)pHashKey[11])<<24;
        mix(a,b,c);

        hashKeyDataLength -= 12;
        pHashKey += 12;
    }

    /*-------------------------------- last block: affect all 32 bits of (c) */
    switch(hashKeyDataLength)                   /* all the case statements fall through */
    {
        case 12: c+=((ubyte4)pHashKey[11])<<24;
        case 11: c+=((ubyte4)pHashKey[10])<<16;
        case 10: c+=((ubyte4)pHashKey[9])<<8;
        case 9 : c+=pHashKey[8];
        case 8 : b+=((ubyte4)pHashKey[7])<<24;
        case 7 : b+=((ubyte4)pHashKey[6])<<16;
        case 6 : b+=((ubyte4)pHashKey[5])<<8;
        case 5 : b+=pHashKey[4];
        case 4 : a+=((ubyte4)pHashKey[3])<<24;
        case 3 : a+=((ubyte4)pHashKey[2])<<16;
        case 2 : a+=((ubyte4)pHashKey[1])<<8;
        case 1 : a+=pHashKey[0];
            break;
        case 0 : goto exit;
    }

    final(a,b,c);

exit:
    *pRetHashValue = c;
}
#endif /* ((!defined(MOC_LITTLE_ENDIAN)) && (!defined(MOC_BIG_ENDIAN))) */

#endif /* __DISABLE_DIGICERT_COMMON_HASH_VALUE_GENERATE__ etc */
