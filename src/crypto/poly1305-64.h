/*
	poly1305 implementation using 64 bit * 64 bit = 128 bit multiplication and 128 bit addition
*/
#ifndef __POLY1305_HARDWARE_ACCELERATOR__

#if defined(_MSC_VER)

    #include <intrin.h>

	typedef struct uint128_t {
		unsigned long long lo;
		unsigned long long hi;
	} uint128_t;

	#define MUL(out, x, y) out.lo = _umul128((x), (y), &out.hi)
	#define ADD(out, in) { unsigned long long t = out.lo; out.lo += in.lo; out.hi += (out.lo < t) + in.hi; }
	#define ADDLO(out, in) { unsigned long long t = out.lo; out.lo += in; out.hi += (out.lo < t); }
	#define SHR(in, shift) (__shiftright128(in.lo, in.hi, (shift)))
	#define LO(in) (in.lo)

	#define POLY1305_NOINLINE __declspec(noinline)

#elif defined(__GNUC__)

    #if defined(__SIZEOF_INT128__)
		typedef unsigned __int128 uint128_t;
	#else
		typedef unsigned uint128_t __attribute__((mode(TI)));
	#endif

	#define MUL(out, x, y) out = ((uint128_t)x * y)
	#define ADD(out, in) out += in
	#define ADDLO(out, in) out += in
	#define SHR(in, shift) (unsigned long long)(in >> (shift))
	#define LO(in) (unsigned long long)(in)

	#define POLY1305_NOINLINE __attribute__((noinline))

#endif

/* 17 + sizeof(size_t) + 8*sizeof(unsigned long long) */
typedef struct poly1305_state_internal_t {
	unsigned long long r[3];
	unsigned long long h[3];
	unsigned long long pad[2];
	size_t leftover;
	unsigned char buffer[POLY1305_BLOCK_SIZE];
	unsigned char final;
} poly1305_state_internal_t;

/* interpret eight 8 bit unsigned integers as a 64 bit unsigned integer in little endian */
static unsigned long long
U8TO64(const unsigned char *p) {
	return
		(((unsigned long long)(p[0] & 0xff)      ) |
		 ((unsigned long long)(p[1] & 0xff) <<  8) |
		 ((unsigned long long)(p[2] & 0xff) << 16) |
		 ((unsigned long long)(p[3] & 0xff) << 24) |
		 ((unsigned long long)(p[4] & 0xff) << 32) |
		 ((unsigned long long)(p[5] & 0xff) << 40) |
		 ((unsigned long long)(p[6] & 0xff) << 48) |
		 ((unsigned long long)(p[7] & 0xff) << 56));
}

/* store a 64 bit unsigned integer as eight 8 bit unsigned integers in little endian */
static void
U64TO8(unsigned char *p, unsigned long long v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
	p[4] = (v >> 32) & 0xff;
	p[5] = (v >> 40) & 0xff;
	p[6] = (v >> 48) & 0xff;
	p[7] = (v >> 56) & 0xff;
}

MSTATUS
Poly1305Init(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, const unsigned char key[32]) {
	MSTATUS status;
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long long t0,t1;

	status = ERR_NULL_POINTER;
	if ( (NULL == key) || (NULL == st) )
		goto exit;

	status = OK;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	t0 = U8TO64(&key[0]);
	t1 = U8TO64(&key[8]);

	st->r[0] = ( t0                    ) & 0xffc0fffffff;
	st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	st->r[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;

	/* save pad for later */
	st->pad[0] = U8TO64(&key[16]);
	st->pad[1] = U8TO64(&key[24]);

	st->leftover = 0;
	st->final = 0;

	ctx->state = MOC_POLY1305_STATE_INIT;

exit:

	return status;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const unsigned long long hibit = (st->final) ? 0 : ((unsigned long long)1 << 40); /* 1 << 128 */
	unsigned long long r0,r1,r2;
	unsigned long long s1,s2;
	unsigned long long h0,h1,h2;
	unsigned long long c;
	uint128_t d0,d1,d2,d;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	s1 = r1 * (5 << 2);
	s2 = r2 * (5 << 2);

	while (bytes >= POLY1305_BLOCK_SIZE) {
		unsigned long long t0,t1;

		/* h += m[i] */
		t0 = U8TO64(&m[0]);
		t1 = U8TO64(&m[8]);

		h0 += (( t0                    ) & 0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;

		/* h *= r */
		MUL(d0, h0, r0); MUL(d, h1, s2); ADD(d0, d); MUL(d, h2, s1); ADD(d0, d);
		MUL(d1, h0, r1); MUL(d, h1, r0); ADD(d1, d); MUL(d, h2, s2); ADD(d1, d);
		MUL(d2, h0, r2); MUL(d, h1, r1); ADD(d2, d); MUL(d, h2, r0); ADD(d2, d);

		/* (partial) h %= p */
		              c = SHR(d0, 44); h0 = LO(d0) & 0xfffffffffff;
		ADDLO(d1, c); c = SHR(d1, 44); h1 = LO(d1) & 0xfffffffffff;
		ADDLO(d2, c); c = SHR(d2, 42); h2 = LO(d2) & 0x3ffffffffff;
		h0  += c * 5; c = (h0 >> 44);  h0 =    h0  & 0xfffffffffff;
		h1  += c;

		m += POLY1305_BLOCK_SIZE;
		bytes -= POLY1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
}


#ifdef __KERNEL__
noinline MSTATUS
#else
POLY1305_NOINLINE MSTATUS
#endif
Poly1305Final(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, unsigned char mac[16]) {
	MSTATUS status;
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long long h0,h1,h2,c;
	unsigned long long g0,g1,g2;
	unsigned long long t0,t1;

	status = ERR_NULL_POINTER;
	if ( (NULL == mac) || (NULL == st) )
		goto exit;

	status = ERR_CRYPTO_CTX_STATE;
	if ( (MOC_POLY1305_STATE_INIT != ctx->state) &&
			 (MOC_POLY1305_STATE_UPDATE != ctx->state) )
		goto exit;

	status = OK;

	/* process the remaining block */
	if (st->leftover)
	{
		size_t i = st->leftover;
		st->buffer[i] = 1;
		for (i = i + 1; i < POLY1305_BLOCK_SIZE; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	             c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
	g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
	g2 = h2 + c - ((unsigned long long)1 << 42);

	/* select h if h < p, or h + -p if h >= p */
	c = (g2 >> ((sizeof(unsigned long long) * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;

	/* h = (h + pad) */
	t0 = st->pad[0];
	t1 = st->pad[1];

	h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

	/* mac = h % (2^128) */
	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	U64TO8(&mac[0], h0);
	U64TO8(&mac[8], h1);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;

	ctx->state = MOC_POLY1305_STATE_FINAL;

exit:

	return status;
}
#endif /* __POLY1305_HARDWARE_ACCELERATOR__ */
