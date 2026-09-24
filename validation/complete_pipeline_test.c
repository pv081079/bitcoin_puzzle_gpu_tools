#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac_base.h"
#include "secp256k1_test_base.h"

/* SHA-256, reaproveitado */
static uint32_t rotr32b(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
static const uint32_t SHA256_K2[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static void sha256b(const unsigned char *msg, int msg_len, unsigned char *out32){
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    int total_len = ((msg_len + 9 + 63) / 64) * 64;
    unsigned char *block = (unsigned char*)calloc(total_len,1);
    memcpy(block, msg, msg_len);
    block[msg_len] = 0x80;
    uint64_t bitlen = (uint64_t)msg_len*8;
    for(int i=0;i<8;++i) block[total_len-1-i] = (unsigned char)(bitlen>>(8*i));
    int nblocks = total_len/64;
    for(int b=0;b<nblocks;++b){
        uint32_t w[64];
        unsigned char *blk = block+b*64;
        for(int i=0;i<16;++i) w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|blk[i*4+3];
        for(int i=16;i<64;++i){
            uint32_t s0=rotr32b(w[i-15],7)^rotr32b(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rotr32b(w[i-2],17)^rotr32b(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;++i){
            uint32_t S1=rotr32b(e,6)^rotr32b(e,11)^rotr32b(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=hh+S1+ch+SHA256_K2[i]+w[i];
            uint32_t S0=rotr32b(a,2)^rotr32b(a,13)^rotr32b(a,22);
            uint32_t maj=(a&bb)^(a&c)^(bb&c);
            uint32_t t2=S0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    free(block);
    for(int i=0;i<8;++i){
        out32[i*4]=(unsigned char)(h[i]>>24); out32[i*4+1]=(unsigned char)(h[i]>>16);
        out32[i*4+2]=(unsigned char)(h[i]>>8); out32[i*4+3]=(unsigned char)(h[i]);
    }
}

void pbkdf2_hmac_sha512(const unsigned char *password, int password_len,
                          const unsigned char *salt, int salt_len,
                          int iterations, unsigned char *out, int dklen){
    int hlen = 64;
    int nblocks = (dklen + hlen - 1) / hlen;
    for(int block_idx = 1; block_idx <= nblocks; ++block_idx){
        unsigned char *salt_block = (unsigned char*)malloc(salt_len + 4);
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len]   = (unsigned char)(block_idx >> 24);
        salt_block[salt_len+1] = (unsigned char)(block_idx >> 16);
        salt_block[salt_len+2] = (unsigned char)(block_idx >> 8);
        salt_block[salt_len+3] = (unsigned char)(block_idx);
        unsigned char u[64];
        hmac_sha512(password, password_len, salt_block, salt_len+4, u);
        free(salt_block);
        unsigned char t[64];
        memcpy(t, u, 64);
        for(int iter = 1; iter < iterations; ++iter){
            unsigned char u_next[64];
            hmac_sha512(password, password_len, u, 64, u_next);
            memcpy(u, u_next, 64);
            for(int i=0;i<64;++i) t[i] ^= u[i];
        }
        int copy_len = (block_idx == nblocks) ? (dklen - (block_idx-1)*hlen) : hlen;
        memcpy(out + (block_idx-1)*hlen, t, copy_len);
    }
}

void entropy_to_indices(const unsigned char *entropy, int ent_bits, int *indices, int *num_words){
    int cs_bits = ent_bits / 32;
    unsigned char hash[32];
    sha256b(entropy, ent_bits/8, hash);
    int ent_bytes = ent_bits/8;
    unsigned char bits_buf[64];
    memcpy(bits_buf, entropy, ent_bytes);
    memcpy(bits_buf+ent_bytes, hash, (cs_bits+7)/8);
    *num_words = (ent_bits+cs_bits)/11;
    for(int w=0; w<*num_words; ++w){
        int idx = 0;
        for(int b=0; b<11; ++b){
            int bit_pos = w*11+b;
            int byte_idx = bit_pos/8;
            int bit_in_byte = 7 - (bit_pos%8);
            int bit = (bits_buf[byte_idx] >> bit_in_byte) & 1;
            idx = (idx<<1) | bit;
        }
        indices[w] = idx;
    }
}

void bip32_derive_child(const u256 &priv, const unsigned char chain[32],
                          uint32_t index, u256 &child_priv, unsigned char child_chain[32],
                          const ECPoint &G){
    ECPoint pub = scalar_mul(priv, G);
    unsigned char pub33[33];
    pub33[0] = (pub.y.v[0]&1) ? 0x03 : 0x02;
    u256_to_be_bytes(pub.x, pub33+1);
    unsigned char data[37];
    memcpy(data, pub33, 33);
    data[33] = (unsigned char)(index>>24);
    data[34] = (unsigned char)(index>>16);
    data[35] = (unsigned char)(index>>8);
    data[36] = (unsigned char)(index);
    unsigned char I[64];
    hmac_sha512(chain, 32, data, 37, I);
    u256 il = u256_from_be_bytes(I);
    child_priv = mod_add(priv, il, CURVE_N);
    memcpy(child_chain, I+32, 32);
}

int main(){
    /* carregar wordlist */
    char words[2048][16];
    FILE *f = fopen("english.txt", "r");
    for(int i=0;i<2048;++i){ fscanf(f, "%s", words[i]); }
    fclose(f);

    ECPoint G;
    unsigned char gx_bytes[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    unsigned char gy_bytes[32] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
    };
    G.x = u256_from_be_bytes(gx_bytes);
    G.y = u256_from_be_bytes(gy_bytes);
    G.infinity = false;

    /* teste: entropia todos 1s (256 bits) -> deve dar zoo*23+vote ->
       mesmo seed/chave que ja validamos */
    unsigned char entropy[32];
    memset(entropy, 0xFF, 32);

    int indices[24], num_words;
    entropy_to_indices(entropy, 256, indices, &num_words);

    char mnemonic[512] = {0};
    for(int i=0;i<num_words;++i){
        strcat(mnemonic, words[indices[i]]);
        if(i<num_words-1) strcat(mnemonic, " ");
    }
    printf("mnemonic gerada: %s\n", mnemonic);

    unsigned char seed[64];
    pbkdf2_hmac_sha512((const unsigned char*)mnemonic, strlen(mnemonic),
                        (const unsigned char*)"mnemonic", 8, 2048, seed, 64);

    unsigned char I[64];
    hmac_sha512((const unsigned char*)"Bitcoin seed", 12, seed, 64, I);
    u256 master_priv = u256_from_be_bytes(I);
    unsigned char master_chain[32];
    memcpy(master_chain, I+32, 32);

    u256 priv0; unsigned char chain0[32];
    bip32_derive_child(master_priv, master_chain, 0, priv0, chain0, G);
    u256 priv1; unsigned char chain1[32];
    bip32_derive_child(priv0, chain0, 1, priv1, chain1, G);

    unsigned char out[32];
    u256_to_be_bytes(priv1, out);
    printf("m/0/1 privkey = ");
    for(int i=0;i<32;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado      = c95674095f8a6c10b0736f5844c051c43b724ab94b990c16285198afc84fd2da\n");

    return 0;
}
