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

