#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha512_base.h"

/* HMAC-SHA512(key, message) */
void hmac_sha512(const unsigned char *key, int key_len,
                  const unsigned char *msg, uint64_t msg_len,
                  unsigned char out[64]){
    unsigned char k_ipad[128], k_opad[128];
    unsigned char key_block[128];
    memset(key_block, 0, 128);

    if(key_len > 128){
        sha512(key, key_len, key_block);
        /* resto ja e zero */
    } else {
        memcpy(key_block, key, key_len);
    }

    for(int i=0;i<128;++i){
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5c;
    }

    /* inner = SHA512(k_ipad || msg) */
    unsigned char *inner_buf = (unsigned char*)malloc(128+msg_len);
    memcpy(inner_buf, k_ipad, 128);
    memcpy(inner_buf+128, msg, msg_len);
    unsigned char inner_hash[64];
    sha512(inner_buf, 128+msg_len, inner_hash);
    free(inner_buf);

    /* outer = SHA512(k_opad || inner_hash) */
    unsigned char outer_buf[128+64];
    memcpy(outer_buf, k_opad, 128);
    memcpy(outer_buf+128, inner_hash, 64);
    sha512(outer_buf, 128+64, out);
}

int main(){
    unsigned char out[64];

    /* vetor de teste RFC 4231 (HMAC-SHA512, Test Case 1) */
    unsigned char key[20];
    for(int i=0;i<20;++i) key[i]=0x0b;
    const char *data = "Hi There";

    hmac_sha512(key, 20, (const unsigned char*)data, strlen(data), out);
    printf("HMAC-SHA512 test1 = ");
    for(int i=0;i<64;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado (RFC4231) = 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854\n");

    return 0;
}
