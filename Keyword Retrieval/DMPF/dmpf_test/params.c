// params.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>
#include <math.h>
#include "params.h"


#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0')

static uint32_t min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}


int hashOnce(EVP_MD_CTX *ctx, uint8_t *bytes_out, 
    const uint8_t *bytes_in, int inlen, uint16_t counter) 
{
    int success = 1;
    success &= EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    success &= EVP_DigestUpdate(ctx, &counter, sizeof(counter));
    success &= EVP_DigestUpdate(ctx, bytes_in, inlen);
    success &= EVP_DigestFinal_ex(ctx, bytes_out, NULL);
    return success ? 0 : -1;
}

int hashToBytes(uint8_t *bytesOut, int outLen, const uint8_t *bytesIn, int inLen) {
    uint16_t counter = 0;
    uint8_t buf[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) return -1;

    int bytesFilled = 0;
    do {
        const int toCopy = min(SHA256_DIGEST_LENGTH, outLen - bytesFilled);
        if (hashOnce(ctx, buf, bytesIn, inLen, counter) != 0) {
            EVP_MD_CTX_destroy(ctx);
            return -1;
        }
        memcpy(bytesOut + bytesFilled, buf, toCopy);
        counter++;
        bytesFilled += SHA256_DIGEST_LENGTH;
    } while (bytesFilled < outLen);

    EVP_MD_CTX_destroy(ctx);
    return 0;
}


void printBuffer(char *label, uint8_t *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void printByteBinary(char byte) {
    printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(byte));
}


void convertBignumsToBytes(BIGNUM **src, uint8_t **dst, uint8_t *lens, int sz) {
    for (int i = 0; i < sz; i++) {
        lens[i] = BN_num_bytes(src[i]);
        dst[i] = malloc(lens[i]);
        BN_bn2bin(src[i], dst[i]);
    }
}

BIGNUM *convertBytesToBignum(uint8_t *src, int len) {
    return BN_bin2bn(src, len, NULL);
}

void freeBignums(BIGNUM **bns, int len) {
    for (int i = 0; i < len; i++) {
        if(bns[i]) BN_free(bns[i]);
    }
}


uint32_t getBit32(uint32_t x, uint32_t i) {
    return (x >> i) & 1;
}

void xorByteArray(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

int prg(const uint8_t *seed, EVP_CIPHER_CTX *ctx, uint8_t *output, uint32_t outLen) {
    int len;
    uint8_t *zeros = (uint8_t *)calloc(outLen + 16, 1);
    if (!zeros) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, NULL)) {
        free(zeros);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, output, &len, zeros, outLen)) {
        free(zeros);
        return -1;
    }

    free(zeros);
    return 0;
}

uint8_t* randBytes(size_t len) {
    uint8_t *bytes = (uint8_t*)malloc(len);
    if (!bytes) return NULL;
    
    if (RAND_bytes(bytes, len) != 1) {
        free(bytes);
        return NULL;
    }
    return bytes;
}

uint32_t divideNumber(uint8_t totalBits, uint8_t rightBits, uint32_t number) {
    (void)totalBits;  
    uint32_t rightMask = (1 << rightBits) - 1;
    uint32_t right = number & rightMask;
    uint32_t left = number >> rightBits;
    return left + right;
}

uint8_t randUInt8(uint8_t max) {
    uint8_t r;
    RAND_bytes(&r, 1);
    return r % (max + 1);
}

void handleError(const char* msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(1);
}