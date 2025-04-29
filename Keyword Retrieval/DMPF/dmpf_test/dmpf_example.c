// dmpf_example.c 
#include "dmpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void testDMPF() {
    printf("====== DMPF Test Start ======\n");
    
    const int domainSize = 5;         
    const uint8_t kappa = 3;          
    const uint32_t numBuckets = 8;    
    const int numPoints = 3;          
    
    uint32_t alphas[3] = {1, 2, 3};
    uint8_t* betas[3];
    
    for (int i = 0; i < numPoints; i++) {
        betas[i] = (uint8_t*)malloc(16);
        if (!betas[i]) {
            printf("Error: Failed to allocate memory for beta values\n");
            for (int j = 0; j < i; j++) {
                free(betas[j]);
            }
            return;
        }
        
        for (int j = 0; j < 16; j++) {
            betas[i][j] = (i + 1) * 10 + j;  
        }
        
        printf("Alpha=%d, Beta[0]=%d\n", alphas[i], betas[i][0]);
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to create cipher context\n");
        for (int i = 0; i < numPoints; i++) {
            free(betas[i]);
        }
        return;
    }
    
    uint8_t key[16] = {0};
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    
    printf("\nGenerating DMPF keys...\n");
    
    // Measure key generation time
    clock_t key_start, key_end;
    double key_generation_time;
    
    key_start = clock();
    
    DMPFKey* keyParty0 = genDMPFKey(0, alphas, betas, numPoints, domainSize, kappa, numBuckets);
    DMPFKey* keyParty1 = genDMPFKey(1, alphas, betas, numPoints, domainSize, kappa, numBuckets);
    
    key_end = clock();
    key_generation_time = ((double) (key_end - key_start)) / CLOCKS_PER_SEC * 1000.0;
    
    printf("DMPF key generation time: %.2f ms\n", key_generation_time);
    
    if (!keyParty0 || !keyParty1) {
        printf("Error: Failed to generate DMPF keys\n");
        if (keyParty0) freeDMPFKey(keyParty0);
        if (keyParty1) freeDMPFKey(keyParty1);
        for (int i = 0; i < numPoints; i++) {
            free(betas[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    printf("\nTesting DMPF evaluation...\n");
            
    uint32_t testPoints[] = {1, 2, 3, 4, 5};
    int numTestPoints = sizeof(testPoints) / sizeof(testPoints[0]);
            
    double total_share_eval_time = 0.0;
    double total_combine_time = 0.0;

    for (int i = 0; i < numTestPoints; i++) {
        uint32_t x = testPoints[i];
                
        
        clock_t eval_share_start, eval_share_end;
        double eval_share_time;
                
        eval_share_start = clock();
        Bitmap* share0 = evalDMPF(keyParty0, x);
        eval_share_end = clock();
        eval_share_time = ((double) (eval_share_end - eval_share_start)) / CLOCKS_PER_SEC * 1000.0;
        
        total_share_eval_time += eval_share_time;
        printf("Share evaluation time for point x=%d: %.2f ms\n", x, eval_share_time);
        
        
        Bitmap* share1 = evalDMPF(keyParty1, x);
                
        if (!share0 || !share1) {
            printf("Error: DMPF evaluation failed\n");
            if (share0) freeBitmap(share0);
            if (share1) freeBitmap(share1);
            continue;
        }
        
        
        clock_t combine_start, combine_end;
        double combine_time;
        
        combine_start = clock();
        
        
        Bitmap* result = createBitmap(share0->bitSize);
        if (result) {
            for (size_t j = 0; j < (result->bitSize + 7) / 8; j++) {
                result->data[j] = share0->data[j] ^ share1->data[j];
            }
            
            freeBitmap(result);
        }
        
        combine_end = clock();
        combine_time = ((double) (combine_end - combine_start)) / CLOCKS_PER_SEC * 1000.0;
        
        total_combine_time += combine_time;
        printf("Result combining time for point x=%d: %.2f ms\n", x, combine_time);
        
        freeBitmap(share0);
        freeBitmap(share1);
    }
            
    printf("\nTotal single share evaluation time for all points: %.2f ms\n", total_share_eval_time);
    printf("Average single share evaluation time per point: %.2f ms\n", total_share_eval_time / numTestPoints);

    printf("\nTotal result combining time for all points: %.2f ms\n", total_combine_time);
    printf("Average result combining time per point: %.2f ms\n", total_combine_time / numTestPoints);

    printf("\nEstimated total time (max(party0,party1) + combine): %.2f ms\n", total_share_eval_time + total_combine_time);
    printf("Estimated average time per point: %.2f ms\n", (total_share_eval_time + total_combine_time) / numTestPoints);
    
    freeDMPFKey(keyParty0);
    freeDMPFKey(keyParty1);
    EVP_CIPHER_CTX_free(ctx);
    
    for (int i = 0; i < numPoints; i++) {
        free(betas[i]);
    }
    
    printf("\n====== DMPF Test End ======\n");
}

int main() {
    
    srand((unsigned)time(NULL));
    
    testDMPF();
    
    return 0;
}