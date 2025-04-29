// dpf.h
#ifndef DPF_H
#define DPF_H

#include <stdint.h>
#include <openssl/evp.h>
#include "bitmap.h"

#ifdef __SIZEOF_INT128__
    typedef unsigned __int128 uint128_t;
#else
    typedef struct {
        uint64_t low;
        uint64_t high;
    } uint128_t;
#endif


void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, 
            Bitmap* data, unsigned char** k0, unsigned char **k1);

Bitmap* evalDPF(EVP_CIPHER_CTX *ctx, int domainSize, 
                unsigned char* k, uint128_t x);


#endif // DPF_H