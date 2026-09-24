#include <stdint.h>
#include <string.h>
#include <stdio.h>

static const uint64_t SHA512_K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, int n){ return (x>>n)|(x<<(64-n)); }

/* processa UM bloco de 128 bytes */
static void sha512_block(uint64_t h[8], const unsigned char block[128]){
    uint64_t w[80];
    for(int i=0;i<16;++i){
        w[i]=0;
        for(int j=0;j<8;++j) w[i] = (w[i]<<8) | block[i*8+j];
    }
    for(int i=16;i<80;++i){
        uint64_t s0 = rotr64(w[i-15],1)^rotr64(w[i-15],8)^(w[i-15]>>7);
        uint64_t s1 = rotr64(w[i-2],19)^rotr64(w[i-2],61)^(w[i-2]>>6);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<80;++i){
        uint64_t S1 = rotr64(e,14)^rotr64(e,18)^rotr64(e,41);
        uint64_t ch = (e&f)^((~e)&g);
        uint64_t t1 = hh+S1+ch+SHA512_K[i]+w[i];
        uint64_t S0 = rotr64(a,28)^rotr64(a,34)^rotr64(a,39);
        uint64_t maj = (a&b)^(a&c)^(b&c);
        uint64_t t2 = S0+maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void sha512(const unsigned char *msg, uint64_t msg_len, unsigned char out[64]){
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };

    uint64_t total_len = msg_len;
    uint64_t nblocks = (total_len + 16 + 1) / 128 + 1; /* +16 for 128-bit length, +1 for 0x80 */
    /* correcting: standard padded length calc */
    uint64_t padded_len = ((total_len + 1 + 16 + 127) / 128) * 128;
    nblocks = padded_len / 128;

    unsigned char *buf = (unsigned char*)calloc(nblocks*128, 1);
    memcpy(buf, msg, msg_len);
    buf[msg_len] = 0x80;
    /* 128-bit length in bits, big-endian, in the LAST 16 bytes */
    unsigned __int128 bitlen = (unsigned __int128)msg_len * 8;
    for(int i=0;i<16;++i){
        buf[padded_len-1-i] = (unsigned char)(bitlen & 0xFF);
        bitlen >>= 8;
    }

    for(uint64_t b=0;b<nblocks;++b){
        sha512_block(h, buf+b*128);
    }
    free(buf);

    for(int i=0;i<8;++i){
        for(int j=0;j<8;++j){
            out[i*8+j] = (unsigned char)(h[i] >> (56-8*j));
        }
    }
}

#include <stdlib.h>

int main(){
    unsigned char out[64];

    /* vetor de teste oficial NIST: SHA512("abc") */
    sha512((const unsigned char*)"abc", 3, out);
    printf("SHA512(\"abc\") = ");
    for(int i=0;i<64;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado        = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49\n");

    /* vetor de teste vazio */
    sha512((const unsigned char*)"", 0, out);
    printf("\nSHA512(\"\")    = ");
    for(int i=0;i<64;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado        = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3\n");

    return 0;
}
