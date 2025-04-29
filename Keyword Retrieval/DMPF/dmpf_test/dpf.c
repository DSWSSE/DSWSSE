// dpf.c
#include "dpf.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <math.h>
#include <time.h>


uint128_t dpf_reverse_lsb(uint128_t input) {
    uint128_t xor = 1;
    return input ^ xor;
}

uint128_t dpf_lsb(uint128_t input) {
    return input & 1;
}

uint128_t dpf_set_lsb_zero(uint128_t input) {
    int lsb = input & 1;
    if(lsb == 1) {
        return dpf_reverse_lsb(input);
    } else {
        return input;
    }
}


uint128_t getRandomBlock() {
    static uint8_t* randKey = NULL;
    static EVP_CIPHER_CTX* randCtx = NULL;
    static uint128_t counter = 0;

    int len = 0;
    uint128_t output = 0;
    if(!randKey) {
        randKey = (uint8_t*)malloc(16);
        if (!randKey) {
            return 0;
        }
        
        if(!(randCtx = EVP_CIPHER_CTX_new())) {
            free(randKey);
            randKey = NULL;
            return 0;
        }
        
        if(!RAND_bytes(randKey, 16)) {
            EVP_CIPHER_CTX_free(randCtx);
            free(randKey);
            randKey = NULL;
            randCtx = NULL;
            return 0;
        }
        
        if(1 != EVP_EncryptInit_ex(randCtx, EVP_aes_128_ecb(), NULL, randKey, NULL)) {
            EVP_CIPHER_CTX_free(randCtx);
            free(randKey);
            randKey = NULL;
            randCtx = NULL;
            return 0;
        }
        
        EVP_CIPHER_CTX_set_padding(randCtx, 0);
    }

    if(1 != EVP_EncryptUpdate(randCtx, (uint8_t*)&output, &len, (uint8_t*)&counter, 16)) {
        return 0;
    }
    counter++;
    return output;
}


void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t* output1, uint128_t* output2, int* bit1, int* bit2) {
    if (!ctx || !output1 || !output2 || !bit1 || !bit2) {
        return;
    }
    
    input = dpf_set_lsb_zero(input);
    
    uint128_t stashin[2] = {input, dpf_reverse_lsb(input)};
    uint128_t stash[2];
    
    int len;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Create new context to avoid state issues
    EVP_CIPHER_CTX *local_ctx = EVP_CIPHER_CTX_new();
    if (!local_ctx) {
        return;
    }
    
    if (1 != EVP_EncryptInit_ex(local_ctx, EVP_aes_128_ecb(), NULL, (uint8_t*)&input, NULL)) {
        EVP_CIPHER_CTX_free(local_ctx);
        return;
    }
    
    EVP_CIPHER_CTX_set_padding(local_ctx, 0);
    
    if(!EVP_EncryptUpdate(local_ctx, (uint8_t*)&stash, &len, (uint8_t*)&stashin, 32)) {
        EVP_CIPHER_CTX_free(local_ctx);
        return;
    }
    
    EVP_CIPHER_CTX_free(local_ctx);
    
    stash[0] = stash[0] ^ input;
    stash[1] = stash[1] ^ input;
    stash[1] = dpf_reverse_lsb(stash[1]);
    
    *bit1 = dpf_lsb(stash[0]);
    *bit2 = dpf_lsb(stash[1]);
    
    *output1 = dpf_set_lsb_zero(stash[0]);
    *output2 = dpf_set_lsb_zero(stash[1]);
}


static int getbit(uint128_t x, int n, int b) {
    if (b <= 0 || b > n) {
        return 0;
    }
    return ((uint128_t)(x) >> (n - b)) & 1;
}


void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, 
            Bitmap* data, unsigned char** k0, unsigned char **k1) {
    
    if (!ctx || !data || !k0 || !k1) {
        return;
    }
    
    if (index >= (1ULL << domainSize)) {
        return;
    }
    
    int maxLayer = domainSize;
    size_t dataSize = (data->bitSize + 7) / 8;
    
    
    size_t key_size = 1 + 16 + 1 + (18 * maxLayer) + dataSize;
    
    
    *k0 = (unsigned char*)calloc(key_size, 1);
    *k1 = (unsigned char*)calloc(key_size, 1);
    if (!*k0 || !*k1) {
        free(*k0);
        free(*k1);
        *k0 = *k1 = NULL;
        return;
    }
    
    
    uint128_t **s = (uint128_t**)malloc((maxLayer + 1) * sizeof(uint128_t*));
    int **t = (int**)malloc((maxLayer + 1) * sizeof(int*));
    uint128_t *sCW = (uint128_t*)malloc(maxLayer * sizeof(uint128_t));
    int **tCW = (int**)malloc(maxLayer * sizeof(int*));
    
    if (!s || !t || !sCW || !tCW) {
        free(s);
        free(t);
        free(sCW);
        free(tCW);
        free(*k0);
        free(*k1);
        *k0 = *k1 = NULL;
        return;
    }
    
    for (int i = 0; i <= maxLayer; i++) {
        s[i] = (uint128_t*)malloc(2 * sizeof(uint128_t));
        t[i] = (int*)malloc(2 * sizeof(int));
        if (!s[i] || !t[i]) {
            for (int j = 0; j <= i; j++) {
                free(s[j]);
                free(t[j]);
            }
            free(s);
            free(t);
            free(sCW);
            free(tCW);
            free(*k0);
            free(*k1);
            *k0 = *k1 = NULL;
            return;
        }
    }
    
    for (int i = 0; i < maxLayer; i++) {
        tCW[i] = (int*)malloc(2 * sizeof(int));
        if (!tCW[i]) {
            for (int j = 0; j <= maxLayer; j++) {
                free(s[j]);
                free(t[j]);
            }
            for (int j = 0; j < i; j++) {
                free(tCW[j]);
            }
            free(s);
            free(t);
            free(sCW);
            free(tCW);
            free(*k0);
            free(*k1);
            *k0 = *k1 = NULL;
            return;
        }
    }
    
    
    s[0][0] = getRandomBlock();
    s[0][1] = getRandomBlock();
    t[0][0] = 0;
    t[0][1] = 1;  
    
    
    (*k0)[0] = domainSize;
    memcpy(&(*k0)[1], &s[0][0], 16);
    (*k0)[17] = t[0][0];
    (*k1)[0] = domainSize;
    memcpy(&(*k1)[1], &s[0][1], 16);
    (*k1)[17] = t[0][1];
    
    
    for (int i = 1; i <= maxLayer; i++) {
        uint128_t s0[2], s1[2]; 
        int t0[2], t1[2];
        
        
        dpfPRG(ctx, s[i-1][0], &s0[0], &s0[1], &t0[0], &t0[1]);
        dpfPRG(ctx, s[i-1][1], &s1[0], &s1[1], &t1[0], &t1[1]);
        
        
        int keep, lose;
        int indexBit = getbit(index, domainSize, i);
        if(indexBit == 0) {
            keep = 0; 
            lose = 1; 
        } else {
            keep = 1; 
            lose = 0; 
        }
        
        
        sCW[i-1] = s0[lose] ^ s1[lose];
        
        tCW[i-1][0] = t0[0] ^ t1[0] ^ indexBit ^ 1; 
        tCW[i-1][1] = t0[1] ^ t1[1] ^ indexBit;
        
        
        if(t[i-1][0] == 1) {
            s[i][0] = s0[keep] ^ sCW[i-1];
            t[i][0] = t0[keep] ^ tCW[i-1][keep];
        } else {
            s[i][0] = s0[keep];
            t[i][0] = t0[keep];
        }
        
        if(t[i-1][1] == 1) {
            s[i][1] = s1[keep] ^ sCW[i-1];
            t[i][1] = t1[keep] ^ tCW[i-1][keep];
        } else {
            s[i][1] = s1[keep];
            t[i][1] = t1[keep];
        }
        
        
        size_t offset = 18 + (18 * (i-1));
        memcpy(&(*k0)[offset], &sCW[i-1], 16);
        (*k0)[offset + 16] = tCW[i-1][0];
        (*k0)[offset + 17] = tCW[i-1][1];
        memcpy(&(*k1)[offset], &sCW[i-1], 16);
        (*k1)[offset + 16] = tCW[i-1][0];
        (*k1)[offset + 17] = tCW[i-1][1];
    }
    
    
    uint8_t* originalData = (uint8_t*)malloc(dataSize);
    uint8_t* lastCW = (uint8_t*)malloc(dataSize);
    if (!originalData || !lastCW) {
        
        free(originalData);
        free(lastCW);
        for (int i = 0; i <= maxLayer; i++) {
            free(s[i]);
            free(t[i]);
        }
        for (int i = 0; i < maxLayer; i++) {
            free(tCW[i]);
        }
        free(s);
        free(t);
        free(sCW);
        free(tCW);
        free(*k0);
        free(*k1);
        *k0 = *k1 = NULL;
        return;
    }
    
    
    memcpy(originalData, data->data, dataSize);
    
    
    uint8_t* convert0 = (uint8_t*)malloc(dataSize);
    uint8_t* convert1 = (uint8_t*)malloc(dataSize);
    uint8_t* zeros = (uint8_t*)calloc(dataSize, 1);
    
    if (!convert0 || !convert1 || !zeros) {
        free(originalData);
        free(lastCW);
        free(convert0);
        free(convert1);
        free(zeros);
        for (int i = 0; i <= maxLayer; i++) {
            free(s[i]);
            free(t[i]);
        }
        for (int i = 0; i < maxLayer; i++) {
            free(tCW[i]);
        }
        free(s);
        free(t);
        free(sCW);
        free(tCW);
        free(*k0);
        free(*k1);
        *k0 = *k1 = NULL;
        return;
    }
    
    
    EVP_CIPHER_CTX *seedCtx0 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *seedCtx1 = EVP_CIPHER_CTX_new();
    
    if (!seedCtx0 || !seedCtx1) {
        free(originalData);
        free(lastCW);
        free(convert0);
        free(convert1);
        free(zeros);
        if (seedCtx0) EVP_CIPHER_CTX_free(seedCtx0);
        if (seedCtx1) EVP_CIPHER_CTX_free(seedCtx1);
        for (int i = 0; i <= maxLayer; i++) {
            free(s[i]);
            free(t[i]);
        }
        for (int i = 0; i < maxLayer; i++) {
            free(tCW[i]);
        }
        free(s);
        free(t);
        free(sCW);
        free(tCW);
        free(*k0);
        free(*k1);
        *k0 = *k1 = NULL;
        return;
    }
    
    int len;
    EVP_EncryptInit_ex(seedCtx0, EVP_aes_128_ctr(), NULL, (uint8_t*)&s[maxLayer][0], NULL);
    EVP_EncryptInit_ex(seedCtx1, EVP_aes_128_ctr(), NULL, (uint8_t*)&s[maxLayer][1], NULL);
    EVP_EncryptUpdate(seedCtx0, convert0, &len, zeros, dataSize);
    EVP_EncryptUpdate(seedCtx1, convert1, &len, zeros, dataSize);
    
    
    for(size_t i = 0; i < dataSize; i++) {
        lastCW[i] = originalData[i] ^ convert0[i] ^ convert1[i];
    }
    
    
    size_t final_offset = 18 + (18 * maxLayer);
    memcpy(&(*k0)[final_offset], lastCW, dataSize);
    memcpy(&(*k1)[final_offset], lastCW, dataSize);
    
    
    free(originalData);
    free(lastCW);
    free(convert0);
    free(convert1);
    free(zeros);
    EVP_CIPHER_CTX_free(seedCtx0);
    EVP_CIPHER_CTX_free(seedCtx1);
    
    for (int i = 0; i <= maxLayer; i++) {
        free(s[i]);
        free(t[i]);
    }
    for (int i = 0; i < maxLayer; i++) {
        free(tCW[i]);
    }
    free(s);
    free(t);
    free(sCW);
    free(tCW);
}


Bitmap* evalDPF(EVP_CIPHER_CTX *ctx, int domainSize, unsigned char* k, uint128_t x) {
    if (!ctx || !k) {
        return NULL;
    }
    
    
    if (x >= (1ULL << domainSize)) {
        return NULL;
    }
    
    
    Bitmap* result = createBitmap(8);
    if (!result) {
        return NULL;
    }
    
    int maxLayer = domainSize;
    
    
    uint128_t s;
    int t;
    memcpy(&s, &k[1], 16);
    t = k[17];
    
    
    for (int i = 1; i <= maxLayer; i++) {
        uint128_t sL, sR;
        int tL, tR;
        
        dpfPRG(ctx, s, &sL, &sR, &tL, &tR);
        
        size_t offset = 18 + (18 * (i-1));
        uint128_t sCW = 0;
        memcpy(&sCW, &k[offset], 16);
        int tCW[2] = {k[offset + 16], k[offset + 17]};
        
        if (t) {
            sL ^= sCW;
            sR ^= sCW;
            tL ^= tCW[0];
            tR ^= tCW[1];
        }
        
        int bit = (x >> (maxLayer - i)) & 1;
        
        if (bit == 0) {
            s = sL;
            t = tL;
        } else {
            s = sR;
            t = tR;
        }
    }
    
    
    size_t dataSize = (result->bitSize + 7) / 8;
    
    
    uint8_t* dataShare = (uint8_t*)calloc(dataSize, 1);
    if (!dataShare) {
        freeBitmap(result);
        return NULL;
    }
    
    
    uint8_t* zeros = (uint8_t*)calloc(dataSize, 1);
    if (!zeros) {
        free(dataShare);
        freeBitmap(result);
        return NULL;
    }
    
    EVP_CIPHER_CTX *seedCtx = EVP_CIPHER_CTX_new();
    if (!seedCtx) {
        free(dataShare);
        free(zeros);
        freeBitmap(result);
        return NULL;
    }
    
    int len;
    if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL, (uint8_t*)&s, NULL)) {
        free(dataShare);
        free(zeros);
        EVP_CIPHER_CTX_free(seedCtx);
        freeBitmap(result);
        return NULL;
    }
    
    if (1 != EVP_EncryptUpdate(seedCtx, dataShare, &len, zeros, dataSize)) {
        free(dataShare);
        free(zeros);
        EVP_CIPHER_CTX_free(seedCtx);
        freeBitmap(result);
        return NULL;
    }
    
    
    if (t == 1) {
        size_t final_offset = 18 + (18 * maxLayer);
        
        for (size_t i = 0; i < dataSize; i++) {
            dataShare[i] ^= k[final_offset + i];
        }
    }
    
    
    memcpy(result->data, dataShare, dataSize);
    
    // Clean up resources
    free(dataShare);
    free(zeros);
    EVP_CIPHER_CTX_free(seedCtx);
    
    return result;
}