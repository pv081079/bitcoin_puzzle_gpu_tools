/* secp256k1_device.cuh
 *
 * Device-side secp256k1 field/scalar arithmetic and point operations.
 * 256-bit values represented as 8x32-bit limbs (little-endian limb
 * order: v[0] is least significant).
 *
 * UNTESTED until validate_scalar_mult (see below) passes - do not
 * trust results from any kernel using this file until that check
 * passes on real hardware.
 */




#include <cstdint>
#include <cstring>
#include <cstdio>

struct u256 { uint32_t v[8]; };

static inline u256 u256_from_be_bytes(const unsigned char *b){
    u256 r;
    for(int i=0;i<8;++i){
        int off = (7-i)*4;
        r.v[i] = ((uint32_t)b[off]<<24)|((uint32_t)b[off+1]<<16)|
                 ((uint32_t)b[off+2]<<8)|((uint32_t)b[off+3]);
    }
    return r;
}

static inline void u256_to_be_bytes(const u256 &a, unsigned char *out){
    for(int i=0;i<8;++i){
        int off = (7-i)*4;
        out[off]   = (unsigned char)(a.v[i]>>24);
        out[off+1] = (unsigned char)(a.v[i]>>16);
        out[off+2] = (unsigned char)(a.v[i]>>8);
        out[off+3] = (unsigned char)(a.v[i]);
    }
}

static inline bool u256_is_zero(const u256 &a){
    uint32_t r = 0;
    for(int i=0;i<8;++i) r |= a.v[i];
    return r == 0;
}

static inline int u256_cmp(const u256 &a, const u256 &b){
    for(int i=7;i>=0;--i){
        if(a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
    }
    return 0;
}

/* c = a + b, returns carry (0 or 1) */
static inline uint32_t u256_add(u256 &c, const u256 &a, const u256 &b){
    uint64_t carry = 0;
    for(int i=0;i<8;++i){
        uint64_t s = (uint64_t)a.v[i] + b.v[i] + carry;
        c.v[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (uint32_t)carry;
}

/* c = a - b, returns borrow (0 or 1) */
static inline uint32_t u256_sub(u256 &c, const u256 &a, const u256 &b){
    int64_t borrow = 0;
    for(int i=0;i<8;++i){
        int64_t d = (int64_t)a.v[i] - b.v[i] - borrow;
        if(d < 0){ d += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
        c.v[i] = (uint32_t)d;
    }
    return (uint32_t)borrow;
}

/* Field modulus P = 2^256 - 2^32 - 977 (secp256k1) */
static const u256 FIELD_P = {{
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

/* Curve order N */
static const u256 CURVE_N = {{
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

static inline u256 mod_add(const u256 &a, const u256 &b, const u256 &m){
    u256 c;
    uint32_t carry = u256_add(c, a, b);
    if(carry || u256_cmp(c, m) >= 0){
        u256 t;
        u256_sub(t, c, m);
        c = t;
    }
    return c;
}

static inline u256 mod_sub(const u256 &a, const u256 &b, const u256 &m){
    u256 c;
    uint32_t borrow = u256_sub(c, a, b);
    if(borrow){
        u256 t;
        u256_add(t, c, m);
        c = t;
    }
    return c;
}

/* 512-bit product of two 256-bit numbers, as 16x32-bit limbs */
static inline void u256_mul_512(uint32_t r[16], const u256 &a, const u256 &b){
    for(int i=0;i<16;++i) r[i]=0;
    for(int i=0;i<8;++i){
        uint64_t carry = 0;
        for(int j=0;j<8;++j){
            uint64_t p = (uint64_t)a.v[i]*b.v[j] + r[i+j] + carry;
            r[i+j] = (uint32_t)p;
            carry = p >> 32;
        }
        r[i+8] += (uint32_t)carry;
    }
}

/* Reduce a 512-bit value mod m via shift-and-subtract long division,
 * operating on full 512-bit (16-limb) representations throughout to
 * avoid the bit-serial approach's carry bug found during validation
 * (confirmed via (P-1)^2 mod P test - see project notes). Iterates
 * k from 256 down to 0, subtracting (m << k) whenever the current
 * value is >= that shifted modulus. */

static inline void u512_shift_mod(uint32_t dst[16], const u256 &m, int k){
    for(int i=0;i<16;++i) dst[i]=0;
    int limb_shift = k / 32;
    int bit_shift = k % 32;

    for(int i=0;i<8;++i){
        int dst_idx = i + limb_shift;
        if(dst_idx >= 16) continue;
        uint64_t val = ((uint64_t)m.v[i]) << bit_shift;
        dst[dst_idx] |= (uint32_t)val;
        if(bit_shift > 0 && dst_idx+1 < 16){
            dst[dst_idx+1] |= (uint32_t)(val >> 32);
        }
    }
}

static inline int u512_cmp(const uint32_t a[16], const uint32_t b[16]){
    for(int i=15;i>=0;--i){
        if(a[i]!=b[i]) return a[i]<b[i] ? -1 : 1;
    }
    return 0;
}

static inline void u512_sub_inplace(uint32_t a[16], const uint32_t b[16]){
    int64_t borrow=0;
    for(int i=0;i<16;++i){
        int64_t d = (int64_t)a[i] - b[i] - borrow;
        if(d<0){ d += ((int64_t)1<<32); borrow=1; } else borrow=0;
        a[i]=(uint32_t)d;
    }
}

static inline u256 reduce_512_mod(const uint32_t r[16], const u256 &m){
    uint32_t val[16];
    for(int i=0;i<16;++i) val[i]=r[i];

    for(int k = 512-256; k >= 0; --k){
        uint32_t shifted[16];
        u512_shift_mod(shifted, m, k);
        if(u512_cmp(val, shifted) >= 0){
            u512_sub_inplace(val, shifted);
        }
    }

    u256 result;
    for(int i=0;i<8;++i) result.v[i]=val[i];
    return result;
}

static inline u256 mod_mul(const u256 &a, const u256 &b, const u256 &m){
    uint32_t r[16];
    u256_mul_512(r, a, b);
    return reduce_512_mod(r, m);
}

/* Modular exponentiation (square-and-multiply): base^exp mod m.
 * exp given as a u256. Used for modular inverse via Fermat
 * (a^(m-2) mod m) since m (both P and N here) is prime. */
static inline u256 mod_pow(u256 base, u256 exp, const u256 &m){
    u256 result; result.v[0]=1; for(int i=1;i<8;++i) result.v[i]=0;

    for(int limb=0; limb<8; ++limb){
        for(int bit=0; bit<32; ++bit){
            if((exp.v[limb] >> bit) & 1){
                result = mod_mul(result, base, m);
            }
            base = mod_mul(base, base, m);
        }
    }
    return result;
}

static inline u256 mod_inverse(const u256 &a, const u256 &m){
    /* m - 2 */
    u256 two; two.v[0]=2; for(int i=1;i<8;++i) two.v[i]=0;
    u256 exp;
    u256_sub(exp, m, two);
    return mod_pow(a, exp, m);
}

/* ============ EC point operations (affine, over F_P) ============ */

struct ECPoint {
    u256 x, y;
    bool infinity;
};

static inline ECPoint point_double(const ECPoint &p){
    if(p.infinity) return p;

    u256 two_y = mod_add(p.y, p.y, FIELD_P);
    u256 inv_two_y = mod_inverse(two_y, FIELD_P);

    u256 x_sq = mod_mul(p.x, p.x, FIELD_P);
    u256 three_x_sq = mod_add(mod_add(x_sq, x_sq, FIELD_P), x_sq, FIELD_P);
    u256 lam = mod_mul(three_x_sq, inv_two_y, FIELD_P);

    u256 lam_sq = mod_mul(lam, lam, FIELD_P);
    u256 x3 = mod_sub(mod_sub(lam_sq, p.x, FIELD_P), p.x, FIELD_P);
    u256 y3 = mod_sub(mod_mul(lam, mod_sub(p.x, x3, FIELD_P), FIELD_P), p.y, FIELD_P);

    ECPoint r; r.x=x3; r.y=y3; r.infinity=false;
    return r;
}

static inline ECPoint point_add(const ECPoint &p1, const ECPoint &p2){
    if(p1.infinity) return p2;
    if(p2.infinity) return p1;

    if(u256_cmp(p1.x, p2.x) == 0){
        u256 ysum = mod_add(p1.y, p2.y, FIELD_P);
        if(u256_is_zero(ysum)){
            ECPoint r; r.infinity = true; return r;
        }
        return point_double(p1);
    }

    u256 dx = mod_sub(p2.x, p1.x, FIELD_P);
    u256 dy = mod_sub(p2.y, p1.y, FIELD_P);
    u256 inv_dx = mod_inverse(dx, FIELD_P);
    u256 lam = mod_mul(dy, inv_dx, FIELD_P);

    u256 lam_sq = mod_mul(lam, lam, FIELD_P);
    u256 x3 = mod_sub(mod_sub(lam_sq, p1.x, FIELD_P), p2.x, FIELD_P);
    u256 y3 = mod_sub(mod_mul(lam, mod_sub(p1.x, x3, FIELD_P), FIELD_P), p1.y, FIELD_P);

    ECPoint r; r.x=x3; r.y=y3; r.infinity=false;
    return r;
}

static inline ECPoint scalar_mul(const u256 &k, const ECPoint &p){
    ECPoint result; result.infinity = true;
    ECPoint addend = p;

    for(int limb=0; limb<8; ++limb){
        for(int bit=0; bit<32; ++bit){
            if((k.v[limb] >> bit) & 1){
                result = point_add(result, addend);
            }
            addend = point_double(addend);
        }
    }
    return result;
}


