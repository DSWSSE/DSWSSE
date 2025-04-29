#include "cuckoo_hash.h"
#include <stdio.h>
#include <string.h>
#include <time.h>  
#include <sys/time.h> 

long long current_timestamp_micro() {
    struct timeval te; 
    gettimeofday(&te, NULL);
    long long microseconds = te.tv_sec * 1000000LL + te.tv_usec;
    return microseconds;
}

int main() {
    uint8_t kappa = 3;
    uint32_t numBuckets = 64;
    uint32_t inputDomain = 64;
    
    printf("Initializing Cuckoo Hash Table: kappa=%u, numBuckets=%u, inputDomain=%u\n", 
           kappa, numBuckets, inputDomain);
    
    CuckooHashTable* cht = initCuckooHashTable(kappa, numBuckets, inputDomain);
    printf("Hash table initialization complete\n\n");
    
    printf("Starting element insertion...\n");
    long long insert_start_time = current_timestamp_micro();
    int total_success = 0;
    
    for (uint32_t i = 0; i < 8; i++) {
        uint8_t beta[16];
        snprintf((char*)beta, sizeof(beta), "value_%02u", i);
        int success = insert(cht, i, beta);
        total_success += success;
        
        printf("Inserting element alpha=%u, beta=%s, %s\n", 
               i, beta, success ? "success" : "failed");
    }
    
    long long insert_end_time = current_timestamp_micro();
    double insert_time_ms = (insert_end_time - insert_start_time) / 1000.0;
    printf("\nSuccessfully inserted %d/8 elements\n", total_success);
    printf("Total insertion time: %.3f ms, average per insertion: %.3f ms\n\n", 
           insert_time_ms, insert_time_ms / 8);
    
    printf("Starting element queries...\n");
    CandidateBucket candidates[MAX_KAPPA];
    double query_times[8] = {0};
    
    for (uint32_t i = 0; i < 8; i++) {
        long long query_start_time = current_timestamp_micro();
        getCandidateBuckets(cht, i, candidates);
        long long query_end_time = current_timestamp_micro();
        query_times[i] = (query_end_time - query_start_time) / 1000.0;
        
        printf("Query for alpha=%u, candidate buckets: ", i);
        for (uint8_t j = 0; j < kappa; j++) {
            printf("%u ", candidates[j].position);
        }
        printf("time: %.3f ms\n", query_times[i]);
    }
    
    double total_query_time = 0;
    for (int i = 0; i < 8; i++) {
        total_query_time += query_times[i];
    }
    double avg_query_time = total_query_time / 8;
    printf("\nAverage query time: %.3f ms\n\n", avg_query_time);
    
    // Batch query performance test
    int num_repeat = 1000;
    printf("Starting batch query test (%d iterations)...\n", num_repeat);
    
    long long batch_query_start = current_timestamp_micro();
    for (int repeat = 0; repeat < num_repeat; repeat++) {
        for (uint32_t i = 0; i < 8; i++) {
            getCandidateBuckets(cht, i, candidates);
        }
    }
    long long batch_query_end = current_timestamp_micro();
    double batch_query_time = (batch_query_end - batch_query_start) / 1000.0;
    
    printf("Batch query total time: %.3f ms\n", batch_query_time);
    printf("Average time per query: %.6f ms\n\n", batch_query_time / (num_repeat * 8));
    
    // Output hash table contents
    printf("Hash table contents:\n");
    int used_buckets = 0;
    for (uint32_t i = 0; i < numBuckets; i++) {
        if (cht->buckets[i].isUsed) {
            used_buckets++;
            printf("Bucket %u: alpha=%u, beta=%s\n", 
                   i, cht->buckets[i].alpha, cht->buckets[i].beta);
        }
    }
    printf("Used %d/%u buckets, utilization: %.2f%%\n\n", 
           used_buckets, numBuckets, (float)used_buckets / numBuckets * 100);
    
    printf("Freeing hash table resources\n");
    freeCuckooHashTable(cht);
    printf("Test completed\n");
    
    return 0;
}