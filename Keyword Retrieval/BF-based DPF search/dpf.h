// From SabaEskandarian/OlivKeyValCode
#pragma once
#ifndef _DPF
#define _DPF

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "params.h"

typedef struct {
    uint8_t domainSize;
    uint128_t seed[2];
    uint8_t control_bits[2];
    struct {
        uint128_t correction_word;
        uint8_t tCW[2];
    } layers[];
} DPFKey;
typedef __uint128_t uint128_t;

void print_block(uint128_t input);

uint128_t getRandomBlock(void);

//DPF functions

void dpfPRG(uint128_t input, uint128_t* output1, uint128_t* output2, 
           int* bit1, int* bit2, const unsigned char* key);
void genDPF(int domainSize, uint128_t index, int dataSize, uint8_t* data, unsigned char** k0, unsigned char** k1); // 改为二级指针

uint128_t evalDPF(int domainSize, const unsigned char* k, uint128_t x, int dataSize, uint8_t* dataShare);
void evalAllDPF(EVP_CIPHER_CTX *ctx, int domainSize, unsigned char* k, int dataSize, uint8_t **dataShare);
void handle_openssl_error(const char* msg);

uint8_t getBitFromDPFResult(const uint8_t* dataShare, uint32_t index);

#endif
