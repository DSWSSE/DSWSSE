#ifndef CUCKOO_HASH_H
#define CUCKOO_HASH_H
#include <stdint.h>
#include <openssl/evp.h>

// 定义桶结构
typedef struct {
    uint32_t alpha;
    uint8_t beta[16];
    int isUsed; 
} Bucket;


typedef struct {
    uint32_t position; 
    uint32_t alpha;    
} CandidateBucket;


typedef struct {
    uint8_t kappa;             
    uint32_t maxEvictions;     
    uint32_t numBuckets;       
    uint32_t n;                
    uint32_t nu;              
    uint32_t domainSize;       
    Bucket* buckets;           
    EVP_CIPHER_CTX* cipherCtx; 
    uint8_t aesRawKey[16];     
} CuckooHashTable;


#define MAX_KAPPA 3


CuckooHashTable* initCuckooHashTable(uint8_t kappa, uint32_t numBuckets, uint32_t inputDomain);

int insert(CuckooHashTable* cht, uint32_t alpha, uint8_t* beta);

void getCandidateBuckets(CuckooHashTable* cht, uint32_t x, CandidateBucket* candidates);

void freeCuckooHashTable(CuckooHashTable* cht);

#endif // CUCKOO_HASH_H