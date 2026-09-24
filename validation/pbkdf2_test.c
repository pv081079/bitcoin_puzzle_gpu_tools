#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac_base.h"

/* PBKDF2-HMAC-SHA512(password, salt, iterations, dklen) */
void pbkdf2_hmac_sha512(const unsigned char *password, int password_len,
                          const unsigned char *salt, int salt_len,
                          int iterations, unsigned char *out, int dklen){
    int hlen = 64; /* SHA512 output size */
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

int main(){
    unsigned char out[64];

    /* vetor de teste BIP39 oficial: mnemonic "zoo zoo ... vote", sem
       passphrase - ja calculamos este valor em Python nesta sessao */
    const char *mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    const char *salt = "mnemonic"; /* sem passphrase extra */

    pbkdf2_hmac_sha512((const unsigned char*)mnemonic, strlen(mnemonic),
                        (const unsigned char*)salt, strlen(salt),
                        2048, out, 64);

    printf("PBKDF2 seed = ");
    for(int i=0;i<64;++i) printf("%02x", out[i]);
    printf("\n");
    printf("esperado    = e28a37058c7f5112ec9e16a3437cf363a2572d70b6ceb3b6965447623d620f14d06bb321a26b33ec15fcd84a3b5ddfd5520e230c924c87aaa0d559749e044fef\n");

    return 0;
}
