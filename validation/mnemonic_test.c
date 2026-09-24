#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha512_base.h"

/* SHA-256 (para checksum BIP39) - reaproveitando a implementacao ja
   validada do trabalho Electrum anterior nesta sessao */
static uint32_t rotr32(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
static const uint32_t SHA256_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static void sha256(const unsigned char *msg, int msg_len, unsigned char *out32){
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
            uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;++i){
            uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=hh+S1+ch+SHA256_K[i]+w[i];
            uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
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

/* entropia (ENT bits, ENT/8 bytes) -> indices de palavras (ENT+CS)/11 palavras */
void entropy_to_indices(const unsigned char *entropy, int ent_bits, int *indices, int *num_words){
    int cs_bits = ent_bits / 32;
    int total_bits = ent_bits + cs_bits;
    *num_words = total_bits / 11;

    unsigned char hash[32];
    sha256(entropy, ent_bits/8, hash);

    /* concatenar entropy + hash num buffer de bits, depois extrair grupos de 11 */
    int ent_bytes = ent_bits/8;
    unsigned char bits_buf[64]; /* suficiente para ate 32+32=64 bytes */
    memcpy(bits_buf, entropy, ent_bytes);
    memcpy(bits_buf+ent_bytes, hash, (cs_bits+7)/8);

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

int main(){
    unsigned char entropy[32];
    memset(entropy, 0xFF, 32); /* 256 bits todos 1 */

    int indices[24], num_words;
    entropy_to_indices(entropy, 256, indices, &num_words);

    printf("num_words = %d\n", num_words);
    printf("indices: ");
    for(int i=0;i<num_words;++i) printf("%d ", indices[i]);
    printf("\n");
    printf("esperado: primeiros 23 = 2047 (zoo), ultimo = 1967 (vote)\n");

    return 0;
}
