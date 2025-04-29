#include "cuckoo_hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include <math.h>

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
    uint8_t ciphertext[32] = {0}; 

    memcpy(plaintext, &left, sizeof(left));
    memcpy(plaintext + 4, &right, sizeof(right));

    for (uint8_t i = 0; i < cht->kappa; i++) {
        plaintext[8 + i] = i * 37 + 41; 
    }
    
    int outLen;
    EVP_EncryptUpdate(cht->cipherCtx, ciphertext, &outLen, plaintext, sizeof(plaintext));

    for (uint8_t i = 0; i < cht->kappa; i++) {
        uint32_t hashValue;
        memcpy(&hashValue, ciphertext + (i * 3 % 12), 4);
        hashes[i] = (hashValue + (i + 1) * 2654435761U) % cht->numBuckets;

        for (uint8_t j = 0; j < i; j++) {
            if (hashes[i] == hashes[j]) {
                hashes[i] = (hashes[i] + 7919) % cht->numBuckets; 
                j = -1; 
            }
        }
    }
}

int insert(CuckooHashTable* cht, uint32_t alpha, uint8_t* beta) {
    int alreadyInHistory = 0;
    for (int i = 0; i < insertedCount; i++) {
        if (history[i].alpha == alpha) {
            alreadyInHistory = 1;
            break;
        }
    }

    if (!alreadyInHistory && insertedCount < MAX_HISTORY) {
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
    uint32_t initialAlpha = alpha;

    while (evictionCount < cht->maxEvictions) {
        left = tmpBucket.alpha / cht->numBuckets;
        right = tmpBucket.alpha % cht->numBuckets;

        uint32_t hashes[MAX_KAPPA];
        hash(cht, left, right, hashes);

        int inserted = 0;
        for (uint8_t i = 0; i < cht->kappa; i++) {
            uint32_t h = hashes[i];
            if (!cht->buckets[h].isUsed) {
                cht->buckets[h] = tmpBucket;
                inserted = 1;
                break;
            }
        }

        if (inserted) {
            return 1;
        }

        uint8_t j = 0;
        uint32_t minAlpha = UINT32_MAX;
        
        for (uint8_t i = 0; i < cht->kappa; i++) {
            uint32_t h = hashes[i];
            if (cht->buckets[h].alpha < minAlpha) {
                minAlpha = cht->buckets[h].alpha;
                j = i;
            }
        }
        
        uint32_t h = hashes[j];
        Bucket evicted = cht->buckets[h];
        cht->buckets[h] = tmpBucket;
        tmpBucket = evicted;

        evictionCount++;
    }

    InsertedEntry currentEntry;
    currentEntry.alpha = initialAlpha;
    memcpy(currentEntry.beta, beta, 16);

    regenerateAESKey(cht);

    memset(cht->buckets, 0, sizeof(Bucket) * cht->numBuckets);

    int success = 1;
    int oldCount = insertedCount;
    insertedCount = 0;

    for (int i = 0; i < oldCount; i++) {
        if (history[i].alpha != currentEntry.alpha) { 
            if (!insert(cht, history[i].alpha, history[i].beta)) {
                success = 0;
            }
        }
    }

    return insert(cht, currentEntry.alpha, currentEntry.beta) && success;
}

void getCandidateBuckets(CuckooHashTable* cht, uint32_t x, CandidateBucket* candidates) {
    uint32_t left = x / cht->numBuckets;
    uint32_t right = x % cht->numBuckets;
    uint32_t hashes[MAX_KAPPA];

    hash(cht, left, right, hashes);

    for (uint8_t i = 0; i < cht->kappa; i++) {
        candidates[i].position = hashes[i];
    }
}

void freeCuckooHashTable(CuckooHashTable* cht) {
    EVP_CIPHER_CTX_free(cht->cipherCtx);
    free(cht->buckets);
    free(cht);
}
