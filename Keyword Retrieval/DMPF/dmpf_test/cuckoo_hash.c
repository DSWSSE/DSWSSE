#include "cuckoo_hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include <math.h>
#include <stdbool.h>

#define MAX_HISTORY 1024
typedef struct {
    uint32_t alpha;
    uint8_t beta[16];
} InsertedEntry;

InsertedEntry history[MAX_HISTORY];
int insertedCount = 0;


CuckooHashTable* initCuckooHashTable(uint8_t kappa, uint32_t numBuckets, uint32_t inputDomain) {
    CuckooHashTable* cht = (CuckooHashTable*)malloc(sizeof(CuckooHashTable));
    if (!cht) return NULL;
    
    cht->kappa = kappa;
    cht->numBuckets = numBuckets;
    cht->n = inputDomain;
    cht->nu = inputDomain / numBuckets;
    
    
    cht->domainSize = (uint32_t)ceil(log2(inputDomain));
    cht->maxEvictions = kappa * numBuckets * 10;

    
    cht->buckets = (Bucket*)calloc(numBuckets, sizeof(Bucket));

    
    srand((unsigned)time(NULL));
    for (int i = 0; i < 16; i++) {
        cht->aesRawKey[i] = rand() % 256;
    }
    cht->cipherCtx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cht->cipherCtx, EVP_aes_128_ecb(), NULL, cht->aesRawKey, NULL);

    insertedCount = 0;

    return cht;
}


void regenerateAESKey(CuckooHashTable* cht) {
    for (int i = 0; i < 16; i++) {
        cht->aesRawKey[i] = rand() % 256;
    }
    EVP_EncryptInit_ex(cht->cipherCtx, EVP_aes_128_ecb(), NULL, cht->aesRawKey, NULL);
}


void hash(CuckooHashTable* cht, uint32_t left, uint32_t right, uint32_t* hashes) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};

    
    memcpy(plaintext, &right, sizeof(right));
    int outLen;
    EVP_EncryptUpdate(cht->cipherCtx, ciphertext, &outLen, plaintext, sizeof(plaintext));

    for (uint8_t i = 0; i < cht->kappa; i++) {
        uint32_t hashValue;
        memcpy(&hashValue, ciphertext + (i * 4), 4);
        hashes[i] = ((hashValue + i * 2654435761U) % cht->numBuckets) ^ left;
    }
}


int findAlpha(CuckooHashTable* cht, uint32_t alpha, uint32_t* bucket_pos) {
    uint32_t left = alpha / cht->numBuckets;
    uint32_t right = alpha % cht->numBuckets;
    
    uint32_t hashes[MAX_KAPPA];
    hash(cht, left, right, hashes);
    
    for (uint8_t i = 0; i < cht->kappa; i++) {
        uint32_t h = hashes[i];
        if (h < cht->numBuckets && cht->buckets[h].isUsed && cht->buckets[h].alpha == alpha) {
            if (bucket_pos) *bucket_pos = h;
            return 1; 
        }
    }
    
    return 0; 
}


int updateBeta(CuckooHashTable* cht, uint32_t alpha, uint8_t* beta) {
    uint32_t bucket_pos;
    if (findAlpha(cht, alpha, &bucket_pos)) {
        memcpy(cht->buckets[bucket_pos].beta, beta, 16);
        return 1;
    }
    return 0;
}


int insert(CuckooHashTable* cht, uint32_t alpha, uint8_t* beta) {
    // If the entry already exists, just update beta
    if (updateBeta(cht, alpha, beta)) {
        return 1; 
    }
    
    // Keep track of insertion history for rehashing
    if (insertedCount < MAX_HISTORY) {
        history[insertedCount].alpha = alpha;
        memcpy(history[insertedCount].beta, beta, 16);
        insertedCount++;
    }
    
    uint32_t left = alpha / cht->numBuckets;
    uint32_t right = alpha % cht->numBuckets;

    Bucket tmpBucket;
    tmpBucket.alpha = alpha;
    memcpy(tmpBucket.beta, beta, 16);
    tmpBucket.isUsed = 1;

    uint32_t evictionCount = 0;
    uint8_t retryCount = 0;

    // Start cuckoo insertion process
    while (retryCount < 3) {
        while (evictionCount < cht->maxEvictions) {
            left = tmpBucket.alpha / cht->numBuckets;
            right = tmpBucket.alpha % cht->numBuckets;

            uint32_t hashes[MAX_KAPPA];
            hash(cht, left, right, hashes);

            // Try to find an empty bucket
            for (uint8_t i = 0; i < cht->kappa; i++) {
                uint32_t h = hashes[i];
                if (!cht->buckets[h].isUsed) {
                    cht->buckets[h] = tmpBucket;
                    return 1;
                }
            }

            // All buckets are occupied, choose one randomly for eviction
            uint8_t j = rand() % cht->kappa;
            uint32_t h = hashes[j];
            
            // Avoid evicting the same element we're trying to insert
            if (cht->buckets[h].alpha == alpha) {
                continue; 
            }

            Bucket evicted = cht->buckets[h];
            cht->buckets[h] = tmpBucket;
            tmpBucket = evicted;

            evictionCount++;
        }

        // Max evictions reached, regenerate hash functions and retry
        regenerateAESKey(cht);
        memset(cht->buckets, 0, sizeof(Bucket) * cht->numBuckets);
        evictionCount = 0;
        retryCount++;

        // Reinsert all previous entries
        int oldCount = insertedCount;
        insertedCount = 0;
        for (int i = 0; i < oldCount; i++) {
            if (!insert(cht, history[i].alpha, history[i].beta)) {
                return 0;
            }
        }
    }

    return 0;
}


void getCandidateBuckets(CuckooHashTable* cht, uint32_t x, CandidateBucket* candidates) {
    if (!cht || !candidates) {
        return;
    }
    
    uint32_t left = x / cht->numBuckets;
    uint32_t right = x % cht->numBuckets;
    
    uint32_t hashes[MAX_KAPPA];
    hash(cht, left, right, hashes);
    
    for (uint8_t i = 0; i < cht->kappa; i++) {
        uint32_t position = hashes[i];
        candidates[i].position = position;
        
        if (position < cht->numBuckets && cht->buckets[position].isUsed) {
            uint32_t stored_alpha = cht->buckets[position].alpha;
            candidates[i].alpha = stored_alpha;
        } else {
            candidates[i].alpha = 0;
        }
    }
}


void freeCuckooHashTable(CuckooHashTable* cht) {
    EVP_CIPHER_CTX_free(cht->cipherCtx);
    free(cht->buckets);
    free(cht);
}