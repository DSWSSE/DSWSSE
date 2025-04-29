// dmpf.c 
#include "dmpf.h"
#include <stdio.h>
#define MAX_BUCKETS 8 


DMPFKey* genDMPFKey(int party, uint32_t* alphas, uint8_t** betas, 
                    int numPoints, int domainSize, uint8_t kappa, uint32_t numBuckets) {
    if (!alphas || !betas || numPoints <= 0 || domainSize <= 0) {
        return NULL;
    }

    if (party != 0 && party != 1) {
        return NULL;
    }

    srand(0x12345678);

    DMPFKey* key = (DMPFKey*)malloc(sizeof(DMPFKey));
    if (!key) {
        return NULL;
    }

    key->domainSize = domainSize;
    key->ctx = EVP_CIPHER_CTX_new();
    key->dpfKeys = NULL;
    key->keyLengths = NULL;
    key->defaultBitmap = NULL;

    if (!key->ctx) {
        freeDMPFKey(key);
        return NULL;
    }

    uint8_t fixed_key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
                             0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    EVP_EncryptInit_ex(key->ctx, EVP_aes_128_ecb(), NULL, fixed_key, NULL);

    key->cht = initCuckooHashTable(kappa, numBuckets, 1 << domainSize);
    if (!key->cht) {
        freeDMPFKey(key);
        return NULL;
    }

    for (int i = 0; i < numPoints; i++) {
        if (!insert(key->cht, alphas[i], betas[i])) {
            freeDMPFKey(key);
            return NULL;
        }
    }
    
    key->dpfKeys = (unsigned char**)malloc(numBuckets * sizeof(unsigned char*));
    key->keyLengths = (size_t*)malloc(numBuckets * sizeof(size_t));
    
    if (!key->dpfKeys || !key->keyLengths) {
        freeDMPFKey(key);
        return NULL;
    }
    
    for (uint32_t i = 0; i < numBuckets; i++) {
        key->dpfKeys[i] = NULL;
        key->keyLengths[i] = 0;
    }

    for (uint32_t i = 0; i < numBuckets; i++) {
        Bitmap* data = createBitmap(8);  
        if (!data) {
            freeDMPFKey(key);
            return NULL;
        }
        
        unsigned char *k0 = NULL, *k1 = NULL;
        uint32_t index;
        
        if (key->cht->buckets[i].isUsed) {
            uint8_t betaValue = key->cht->buckets[i].beta[0];
            index = key->cht->buckets[i].alpha;
            data->data[0] = betaValue;
        } else {
            index = 0;  
            memset(data->data, 0, (data->bitSize + 7) / 8);
        }
        
        genDPF(key->ctx, domainSize, index, data, &k0, &k1);
        
        size_t key_size = 1 + 16 + 1 + (18 * domainSize) + ((data->bitSize + 7) / 8);
        
        key->dpfKeys[i] = (party == 0) ? k0 : k1;
        key->keyLengths[i] = key_size;
        
        if (party == 0) {
            free(k1);
        } else {
            free(k0);
        }
        
        freeBitmap(data);
    }
    
    return key;
}


Bitmap* evalDMPF(DMPFKey* key, uint32_t x) {
    if (!key || !key->cht || !key->dpfKeys) {
        return NULL;
    }
    
    if (x >= (1ULL << key->domainSize)) {
        return NULL;
    }
    
    Bitmap* result = createBitmap(8);  
    if (!result) {
        return NULL;
    }
    
    memset(result->data, 0, (result->bitSize + 7) / 8);
    
    CandidateBucket candidates[MAX_KAPPA];
    getCandidateBuckets(key->cht, x, candidates);
    
    int numCandidates = key->cht->kappa;
    
    bool processed[MAX_BUCKETS] = {false};
    
    for (int i = 0; i < numCandidates; i++) {
        uint32_t bucketIndex = candidates[i].position;
        
        if (bucketIndex >= key->cht->numBuckets || processed[bucketIndex]) {
            continue;
        }
        
        processed[bucketIndex] = true;
        
        Bitmap* partialResult = evalDPF(key->ctx, key->domainSize, 
                                     key->dpfKeys[bucketIndex], x);
        
        if (partialResult) {
            for (size_t j = 0; j < (result->bitSize + 7) / 8; j++) {
                result->data[j] ^= partialResult->data[j];
            }
            
            freeBitmap(partialResult);
        }
    }
    
    return result;
}

void freeDMPFKey(DMPFKey* key) {
    if (!key) return;
    
    if (key->ctx) {
        EVP_CIPHER_CTX_free(key->ctx);
        key->ctx = NULL;  
    }
    
    if (key->cht) {
        freeCuckooHashTable(key->cht);
        key->cht = NULL;
    }
    
    if (key->dpfKeys && key->keyLengths) {
        uint32_t numBuckets = key->cht ? key->cht->numBuckets : 0;
        for (uint32_t i = 0; i < numBuckets; i++) {
            if (key->dpfKeys[i]) {
                free(key->dpfKeys[i]);
                key->dpfKeys[i] = NULL;
            }
        }
        free(key->dpfKeys);
        free(key->keyLengths);
    }
    
    if (key->defaultBitmap) {
        if (key->defaultBitmap[0]) {
            freeBitmap(key->defaultBitmap[0]);
            key->defaultBitmap[0] = NULL;
        }
        free(key->defaultBitmap);
    }
    
    free(key);
}