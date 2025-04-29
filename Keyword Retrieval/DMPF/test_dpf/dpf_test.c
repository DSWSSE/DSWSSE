// dpf_test.c
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "dpf.h"
#include "bitmap.h"
#include "params.h"

int testBasicDPF(EVP_CIPHER_CTX *ctx) {
    int domainSize = 8;  
    uint128_t index = 42;  
    
    Bitmap* data = createBitmap(8);
    setBit(data, 0, true);

    unsigned char *k0 = NULL, *k1 = NULL;
    genDPF(ctx, domainSize, index, data, &k0, &k1);
    
    if (!k0 || !k1) {
        freeBitmap(data);
        return 0;
    }

    Bitmap* result0 = evalDPF(ctx, domainSize, k0, index);
    Bitmap* result1 = evalDPF(ctx, domainSize, k1, index);
    
    if (!result0 || !result1) {
        free(k0);
        free(k1);
        freeBitmap(data);
        return 0;
    }

    xorBitmaps(result0, result1);
    
    int success = 1;
    for (uint32_t i = 0; i < data->bitSize; i++) {
        if (getBit(result0, i) != getBit(data, i)) {
            success = 0;
            break;
        }
    }

    uint128_t wrongIndex = (index + 1) % (1 << domainSize);
    
    freeBitmap(result0);
    freeBitmap(result1);
    
    result0 = evalDPF(ctx, domainSize, k0, wrongIndex);
    result1 = evalDPF(ctx, domainSize, k1, wrongIndex);
    
    if (!result0 || !result1) {
        free(k0);
        free(k1);
        freeBitmap(data);
        return 0;
    }

    xorBitmaps(result0, result1);
    
    success = 1;
    for (uint32_t i = 0; i < data->bitSize; i++) {
        if (getBit(result0, i) != 0) {
            success = 0;
            break;
        }
    }
    
    free(k0);
    free(k1);
    freeBitmap(data);
    freeBitmap(result0);
    freeBitmap(result1);
    
    return success;
}

int testMultipleEvals(EVP_CIPHER_CTX *ctx) {
    int domainSize = 5;  
    uint128_t index = 17;  
    
    Bitmap* data = createBitmap(8);
    setBit(data, 0, true);
    setBit(data, 2, true);
    setBit(data, 5, true);

    unsigned char *k0 = NULL, *k1 = NULL;
    genDPF(ctx, domainSize, index, data, &k0, &k1);
    
    if (!k0 || !k1) {
        freeBitmap(data);
        return 0;
    }
    
    int domainSize_val = 1 << domainSize;
    
    int correct = 0, zero = 0;
    
    for (uint128_t x = 0; x < domainSize_val; x++) {
        Bitmap* r0 = evalDPF(ctx, domainSize, k0, x);
        Bitmap* r1 = evalDPF(ctx, domainSize, k1, x);
        
        if (!r0 || !r1) {
            free(k0);
            free(k1);
            freeBitmap(data);
            return 0;
        }
        
        xorBitmaps(r0, r1);
        
        int isZero = 1;
        for (uint32_t i = 0; i < data->bitSize; i++) {
            if (getBit(r0, i) != 0) {
                isZero = 0;
                break;
            }
        }
        
        int isCorrect = 1;
        if (x == index) {
            for (uint32_t i = 0; i < data->bitSize; i++) {
                if (getBit(r0, i) != getBit(data, i)) {
                    isCorrect = 0;
                    break;
                }
            }
        } else {
            isCorrect = isZero;
        }
        
        if (isZero) zero++;
        if (isCorrect) correct++;
        
        freeBitmap(r0);
        freeBitmap(r1);
    }

    free(k0);
    free(k1);
    freeBitmap(data);
    
    return correct == domainSize_val;
}

int testDifferentDomainSizes(EVP_CIPHER_CTX *ctx) {
    int domainSizes[] = {3, 6, 10};
    int numTests = sizeof(domainSizes) / sizeof(domainSizes[0]);
    int allPassed = 1;
    
    for (int t = 0; t < numTests; t++) {
        int domainSize = domainSizes[t];
        int domainSize_val = 1 << domainSize;

        uint128_t index = rand() % domainSize_val;
        
        Bitmap* data = createBitmap(8);
        for (uint32_t i = 0; i < data->bitSize; i++) {
            setBit(data, i, rand() % 2);
        }
        
        unsigned char *k0 = NULL, *k1 = NULL;
        genDPF(ctx, domainSize, index, data, &k0, &k1);
        
        if (!k0 || !k1) {
            freeBitmap(data);
            allPassed = 0;
            continue;
        }
        
        Bitmap* r0 = evalDPF(ctx, domainSize, k0, index);
        Bitmap* r1 = evalDPF(ctx, domainSize, k1, index);
        
        if (!r0 || !r1) {
            free(k0);
            free(k1);
            freeBitmap(data);
            allPassed = 0;
            continue;
        }
        
        xorBitmaps(r0, r1);
        
        int isCorrect = 1;
        for (uint32_t i = 0; i < data->bitSize; i++) {
            if (getBit(r0, i) != getBit(data, i)) {
                isCorrect = 0;
                break;
            }
        }

        free(k0);
        free(k1);
        freeBitmap(data);
        freeBitmap(r0);
        freeBitmap(r1);
        
        if (!isCorrect) {
            allPassed = 0;
        }
    }
    
    return allPassed;
}

int testFullDomainEval(EVP_CIPHER_CTX *ctx) {
    int domainSize = 4;  
    int domainSize_val = 1 << domainSize;
    uint128_t index = 7;  
    
    Bitmap* data = createBitmap(8);
    for (uint32_t i = 0; i < data->bitSize; i++) {
        setBit(data, i, rand() % 2 == 0);  
    }

    unsigned char *k0 = NULL, *k1 = NULL;
    genDPF(ctx, domainSize, index, data, &k0, &k1);
    
    if (!k0 || !k1) {
        freeBitmap(data);
        return 0;
    }
    
    Bitmap** results0 = (Bitmap**)malloc(domainSize_val * sizeof(Bitmap*));
    Bitmap** results1 = (Bitmap**)malloc(domainSize_val * sizeof(Bitmap*));
    Bitmap** combined = (Bitmap**)malloc(domainSize_val * sizeof(Bitmap*));
    
    if (!results0 || !results1 || !combined) {
        free(k0);
        free(k1);
        freeBitmap(data);
        free(results0);
        free(results1);
        free(combined);
        return 0;
    }

    for (uint128_t x = 0; x < domainSize_val; x++) {
        results0[x] = evalDPF(ctx, domainSize, k0, x);
        results1[x] = evalDPF(ctx, domainSize, k1, x);
        
        if (!results0[x] || !results1[x]) {
            for (uint128_t j = 0; j < x; j++) {
                if (results0[j]) freeBitmap(results0[j]);
                if (results1[j]) freeBitmap(results1[j]);
                if (combined[j]) freeBitmap(combined[j]);
            }
            free(results0);
            free(results1);
            free(combined);
            free(k0);
            free(k1);
            freeBitmap(data);
            return 0;
        }
        
        combined[x] = createBitmap(data->bitSize);
        if (!combined[x]) {
            for (uint128_t j = 0; j <= x; j++) {
                if (results0[j]) freeBitmap(results0[j]);
                if (results1[j]) freeBitmap(results1[j]);
            }
            free(results0);
            free(results1);
            free(combined);
            free(k0);
            free(k1);
            freeBitmap(data);
            return 0;
        }

        for (uint32_t i = 0; i < data->bitSize; i++) {
            setBit(combined[x], i, getBit(results0[x], i));
        }
        
        xorBitmaps(combined[x], results1[x]);
    }

    int correct = 0;
    
    for (uint128_t x = 0; x < domainSize_val; x++) {
        int isCorrect = 1;
        
        if (x == index) {
            for (uint32_t i = 0; i < data->bitSize; i++) {
                if (getBit(combined[x], i) != getBit(data, i)) {
                    isCorrect = 0;
                    break;
                }
            }
        } else {
            for (uint32_t i = 0; i < data->bitSize; i++) {
                if (getBit(combined[x], i) != 0) {
                    isCorrect = 0;
                    break;
                }
            }
        }

        if (isCorrect) correct++;
    }
    
    for (int x = 0; x < domainSize_val; x++) {
        freeBitmap(results0[x]);
        freeBitmap(results1[x]);
        freeBitmap(combined[x]);
    }
    free(results0);
    free(results1);
    free(combined);
    free(k0);
    free(k1);
    freeBitmap(data);
    
    return correct == domainSize_val;
}

int main() {
    OpenSSL_add_all_algorithms();
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 1;
    }
    
    srand(time(NULL));
    
    int tests_passed = 0;
    int total_tests = 4;
    
    if (testBasicDPF(ctx)) tests_passed++;
    if (testMultipleEvals(ctx)) tests_passed++;
    if (testDifferentDomainSizes(ctx)) tests_passed++;
    if (testFullDomainEval(ctx)) tests_passed++;
    
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    
    return tests_passed == total_tests ? 0 : 1;
}
