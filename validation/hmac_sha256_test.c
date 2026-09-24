#include <stdint.h>
#include <string.h>
#include <stdio.h>

static uint32_t rotr32c(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
static const uint32_t SHA256_K3[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static void sha256c(const unsigned char *msg, int msg_len, unsigned char *out32){
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned char block[256];
    memset(block,0,sizeof(block));
    memcpy(block, msg, msg_len);
    block[msg_len]=0x80;
    int total_len = ((msg_len+9+63)/64)*64;
    uint64_t bitlen = (uint64_t)msg_len*8;
    for(int i=0;i<8;++i) block[total_len-1-i]=(unsigned char)(bitlen>>(8*i));
    int nblocks = total_len/64;
    for(int b=0;b<nblocks;++b){
        uint32_t w[64];
        unsigned char *blk = block+b*64;
        for(int i=0;i<16;++i) w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|blk[i*4+3];
        for(int i=16;i<64;++i){
            uint32_t s0=rotr32c(w[i-15],7)^rotr32c(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rotr32c(w[i-2],17)^rotr32c(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;++i){
            uint32_t S1=rotr32c(e,6)^rotr32c(e,11)^rotr32c(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=hh+S1+ch+SHA256_K3[i]+w[i];
            uint32_t S0=rotr32c(a,2)^rotr32c(a,13)^rotr32c(a,22);
            uint32_t maj=(a&bb)^(a&c)^(bb&c);
            uint32_t t2=S0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;++i){
        out32[i*4]=(unsigned char)(h[i]>>24); out32[i*4+1]=(unsigned char)(h[i]>>16);
        out32[i*4+2]=(unsigned char)(h[i]>>8); out32[i*4+3]=(unsigned char)(h[i]);
    }
}

void hmac_sha256(const unsigned char *key, int key_len,
                  const unsigned char *msg, int msg_len,
                  unsigned char out32[32]){
    unsigned char key_block[64];
    memset(key_block,0,64);
    if(key_len>64){
        sha256c(key,key_len,key_block);
    } else {
        memcpy(key_block,key,key_len);
    }
    unsigned char k_ipad[64], k_opad[64];
    for(int i=0;i<64;++i){
        k_ipad[i]=key_block[i]^0x36;
        k_opad[i]=key_block[i]^0x5c;
    }
    unsigned char inner_buf[64+256];
    memcpy(inner_buf,k_ipad,64);
    memcpy(inner_buf+64,msg,msg_len);
    unsigned char inner_hash[32];
    sha256c(inner_buf,64+msg_len,inner_hash);

    unsigned char outer_buf[64+32];
    memcpy(outer_buf,k_opad,64);
    memcpy(outer_buf+64,inner_hash,32);
    sha256c(outer_buf,64+32,out32);
}

int main(){
    /* vetor de teste RFC 4231, HMAC-SHA256, Test Case 1 */
    unsigned char key[20];
    for(int i=0;i<20;++i) key[i]=0x0b;
    const char *data = "Hi There";
    unsigned char out[32];
    hmac_sha256(key, 20, (const unsigned char*)data, strlen(data), out);
    printf("HMAC-SHA256 = ");
    for(int i=0;i<32;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado    = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7\n");
    return 0;
}
