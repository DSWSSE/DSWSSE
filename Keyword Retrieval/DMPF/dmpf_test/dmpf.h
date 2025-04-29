// dmpf.h 
#ifndef DMPF_H
#define DMPF_H

#include "dpf.h"
#include "cuckoo_hash.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>


typedef struct {
    CuckooHashTable* cht;       
    unsigned char** dpfKeys;    
    size_t* keyLengths;         
    int domainSize;             
    EVP_CIPHER_CTX* ctx;        
    Bitmap** defaultBitmap;     
} DMPFKey;


DMPFKey* genDMPFKey(int party,                
                    uint32_t* alphas,         
                    uint8_t** betas,          
                    int numPoints,            
                    int domainSize,           
                    uint8_t kappa,            
                    uint32_t numBuckets);     

Bitmap* evalDMPF(DMPFKey* key,               
                 uint32_t x);                

void freeDMPFKey(DMPFKey* key);              



#endif // DMPF_H
