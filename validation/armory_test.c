#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hmac_sha256_base.h"
#include "secp256k1_test_base.h"

/* SHA256 generico ja esta em hmac_sha256_base.h como sha256c() */

/* Deriva o chaincode Armory a partir do root privkey */
void armory_chaincode(const unsigned char root[32], unsigned char chaincode[32]){
    unsigned char hash1[32], hash2[32];
    sha256c(root, 32, hash1);
    sha256c(hash1, 32, hash2);
    hmac_sha256(hash2, 32, (const unsigned char*)"Derive Chaincode from Root Key", 30, chaincode);
}

/* Avanca UM passo: novo_priv = (A * priv) mod N, A = SHA256(SHA256(pubkey_nao_comprimida)) XOR chaincode */
void armory_advance(const u256 &priv, const unsigned char chaincode[32], u256 &new_priv, const ECPoint &G){
    ECPoint pub = scalar_mul(priv, G);

    unsigned char pub_uncompressed[65];
    pub_uncompressed[0] = 0x04;
    u256_to_be_bytes(pub.x, pub_uncompressed+1);
    u256_to_be_bytes(pub.y, pub_uncompressed+33);

    unsigned char h1[32], h2[32];
    sha256c(pub_uncompressed, 65, h1);
    sha256c(h1, 32, h2);

    unsigned char A_bytes[32];
    for(int i=0;i<32;++i) A_bytes[i] = h2[i] ^ chaincode[i];

    u256 A = u256_from_be_bytes(A_bytes);
    new_priv = mod_mul(priv, A, CURVE_N);
}

int main(){
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

    /* seed de teste: SHA256("teste_armory") como root privkey, para
       cross-validar depois com vuke no mesmo seed */
    unsigned char root_hash[32];
    const char *test_seed = "teste_armory";
    sha256c((const unsigned char*)test_seed, strlen(test_seed), root_hash);

    u256 root_priv = u256_from_be_bytes(root_hash);

    unsigned char chaincode[32];
    armory_chaincode(root_hash, chaincode);

    printf("root (SHA256(seed)) = ");
    for(int i=0;i<32;++i) printf("%02x", root_hash[i]);
    printf("\n");

    printf("chaincode = ");
    for(int i=0;i<32;++i) printf("%02x", chaincode[i]);
    printf("\n");

    u256 cur = root_priv;
    for(int step=0; step<5; ++step){
        u256 next;
        armory_advance(cur, chaincode, next, G);
        cur = next;
        unsigned char out[32];
        u256_to_be_bytes(cur, out);
        printf("P%d = ", step+1);
        for(int i=0;i<32;++i) printf("%02x", out[i]);
        printf("\n");
    }

    return 0;
}
