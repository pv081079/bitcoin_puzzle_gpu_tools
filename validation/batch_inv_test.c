#include <cstring>
#include "secp256k1_test_base.h"
#include <stdio.h>

/* Simulacao de N "threads" fazendo inversao em lote (Montgomery),
 * comparada com N inversoes individuais - para validar a LOGICA antes
 * de portar para CUDA com threads/shared memory reais. */

int main(){
    const int N = 16;
    u256 z_values[16];

    /* gerar N valores "aleatorios" (deterministicos para reprodutibilidade) */
    unsigned int seed = 42;
    for(int i=0;i<N;++i){
        for(int j=0;j<8;++j){
            seed = seed*1103515245 + 12345;
            z_values[i].v[j] = seed;
        }
        /* garantir < FIELD_P reduzindo se necessario */
        while(u256_cmp(z_values[i], FIELD_P) >= 0){
            u256 t; u256_sub(t, z_values[i], FIELD_P); z_values[i]=t;
        }
    }

    /* metodo 1: N inversoes individuais (referencia, ja validada) */
    u256 individual_inv[16];
    for(int i=0;i<N;++i){
        individual_inv[i] = mod_inverse(z_values[i], FIELD_P);
    }

    /* metodo 2: inversao em lote (Montgomery) */
    u256 prefix[17]; /* prefix[0]=1, prefix[i]=z0*z1*...*z(i-1) */
    prefix[0].v[0]=1; for(int j=1;j<8;++j) prefix[0].v[j]=0;
    for(int i=0;i<N;++i){
        prefix[i+1] = mod_mul(prefix[i], z_values[i], FIELD_P);
    }

    u256 total_inv = mod_inverse(prefix[N], FIELD_P); /* UNICA inversao */

    u256 batch_inv[16];
    u256 running = total_inv;
    for(int i=N-1;i>=0;--i){
        /* 1/z_i = prefix[i] * running_suffix_product */
        batch_inv[i] = mod_mul(prefix[i], running, FIELD_P);
        running = mod_mul(running, z_values[i], FIELD_P);
    }

    /* comparar */
    int all_match = 1;
    for(int i=0;i<N;++i){
        if(u256_cmp(individual_inv[i], batch_inv[i]) != 0){
            printf("MISMATCH no indice %d\n", i);
            all_match = 0;
        }
    }
    printf("%s\n", all_match ? "TODOS OS 16 VALORES BATEM CERTO" : "FALHOU");

    return 0;
}
