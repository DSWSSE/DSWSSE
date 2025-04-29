#include <math.h>  // 添加在文件顶部
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "bloom_filter.h"

#define OKAY 0
#define GET_BIT(array, index) (((array)[(index)/8] >> (7 - ((index) % 8))) & 1)
// 测试文档结构体
typedef struct {
    DocumentBloomFilter dbf;
    const char **keywords;  // 改为二级指针，指向关键词数组
} TestCase;

// 打印加密后的布隆过滤器（调试用）
void printEncryptedBloomFilter(const DocumentBloomFilter *dbf) {
    printf("Encrypted Bloom Filter (%u bytes):\n", dbf->bloomFilterSz / 8);
    for (size_t i = 0; i < dbf->bloomFilterSz / 8; i++) {
        printf("%02x ", dbf->encrypted_bf[i]);
    }
    printf("\n");
}

// 全局关键词数组
const char *generate_keywords[] = {
    "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", 
    "honeydew", "kiwi", "lemon", "mango", "nectarine", "orange", "pear",
    "quince", "raspberry", "strawberry", "tangerine", "ugli", "vanilla",
    "watermelon", "xigua", "yam", "zucchini", "almond", "basil", "cinnamon",
    "dill", "eggplant", "fennel", "ginger", "horseradish", "iceberg", "jicama",
    "kale", "lettuce", "mushroom", "nutmeg", "olive", "pepper", "quinoa",
    "rosemary", "sage", "thyme", "udon", "vinegar", "wasabi", "xylitol",
    "yeast", "zest", "avocado", "blueberry", "cantaloupe", "dragonfruit",
    "elderflower", "fraise", "guava", "huckleberry", "ilama", "jackfruit",
    "kumquat", "lychee", "mulberry", "nance", "olallieberry", "papaya",
    "queen", "rambutan", "soursop", "tamarind", "ugni", "voavanga", "wolfberry"
};

int main() {
    // 测试配置
    const size_t DOCUMENT_COUNT = 1; // 测试文档数量
    const size_t KEYWORDS_PER_DOC = sizeof(generate_keywords) / sizeof(generate_keywords[0]);  // 动态计算关键词个数
    
    TestCase test_cases[DOCUMENT_COUNT];
    
    // 初始化测试用例
    for (size_t i = 0; i < DOCUMENT_COUNT; i++) {
        test_cases[i].dbf.docId = i;
        test_cases[i].dbf.bloomFilterSz = getOptimalBloomFilterSize(DOCUMENT_COUNT);
        
        size_t original_bf_bytes = test_cases[i].dbf.bloomFilterSz / 8;
        size_t padded_bf_bytes = ((original_bf_bytes + 15) / 16) * 16;
        
        test_cases[i].dbf.encrypted_bf = malloc(padded_bf_bytes);
        if (!test_cases[i].dbf.encrypted_bf) {
            fprintf(stderr, "Memory allocation failed for doc %zu\n", i);
            exit(EXIT_FAILURE);
        }

        test_cases[i].keywords = generate_keywords;
    }

    // 创建并加密每个文档的布隆过滤器
    for (size_t d = 0; d < DOCUMENT_COUNT; d++) {
        printf("Initializing document %zu...\n", d);
        
        // 生成密钥（仅 maskKey）
        if (generateBloomKeys(&test_cases[d].dbf) != OKAY) {
            fprintf(stderr, "Failed to generate keys for doc %zu\n", d);
            continue;
        }
        
        // 加密布隆过滤器
        if (encryptBloomFilter(&test_cases[d].dbf, 
                             test_cases[d].keywords, 
                             KEYWORDS_PER_DOC) != OKAY) {
            fprintf(stderr, "Failed to encrypt BF for doc %zu\n", d);
            continue;
        }
        
        // 打印加密结果（调试）
        printEncryptedBloomFilter(&test_cases[d].dbf);
    }

    // 执行跨文档查询测试
    const char *search_keywords[] = {"apple", "zucchini", "nonexist"};
    for (size_t d = 0; d < DOCUMENT_COUNT; d++) {
        printf("=== Document %zu Query Results ===\n", d);
        size_t original_bf_bytes = test_cases[d].dbf.bloomFilterSz / 8;
        size_t padded_bf_bytes = ((original_bf_bytes + 15) / 16) * 16;
        uint8_t decrypted_bf[padded_bf_bytes];
        
        if (decryptBloomFilter(&test_cases[d].dbf, decrypted_bf, original_bf_bytes, padded_bf_bytes) != OKAY) {
            fprintf(stderr, "Decryption failed for doc %zu\n", d);
            continue;
        }

        for (size_t i = 0; i < sizeof(search_keywords)/sizeof(char *); i++) {
            int found = checkKeyword(decrypted_bf, test_cases[d].dbf.bloomFilterSz, search_keywords[i]);
            printf("Keyword '%s' in doc %zu: %s\n", search_keywords[i], d, found ? "Found" : "Not Found");
        }
        // 在main函数中找到DPF查询测试部分，修改如下：

        printf("\n=== DPF Query Simulation ===\n");
        for (size_t i = 0; i < sizeof(search_keywords)/sizeof(char *); i++) {
            const char *keyword = search_keywords[i];
            printf("\nTesting keyword: '%s'\n", keyword);
            
            // 客户端生成查询上下文
            QueryContext ctx = {0};
            
            // 生成DPF密钥
            if (generateDPFKeys(&ctx, &test_cases[d].dbf, keyword) != OKAY) {
                fprintf(stderr, "DPF key generation failed\n");
                continue;
            }
            
            // 为每个索引分配完整的结果缓冲区
            uint8_t **resp0 = malloc(BLOOM_FILTER_K * sizeof(uint8_t*));
            uint8_t **resp1 = malloc(BLOOM_FILTER_K * sizeof(uint8_t*));
            int domain_size = (int)log2(test_cases[d].dbf.bloomFilterSz);
            size_t bf_bytes = test_cases[d].dbf.bloomFilterSz / 8;

            for (int k = 0; k < BLOOM_FILTER_K; k++) {
                resp0[k] = malloc(bf_bytes);
                resp1[k] = malloc(bf_bytes);
                if (!resp0[k] || !resp1[k]) {
                    fprintf(stderr, "Memory allocation failed\n");
                    // 释放已分配的内存
                    for (int j = 0; j <= k; j++) {
                        if (resp0[j]) free(resp0[j]);
                        if (resp1[j]) free(resp1[j]);
                    }
                    free(resp0); free(resp1);
                    freeDPFContext(&ctx);
                    continue;
                }
                
                // 评估两个密钥分支
                memset(resp0[k], 0, bf_bytes);  // 确保初始化为0
                memset(resp1[k], 0, bf_bytes);  // 确保初始化为0
                
                if (evalDPF(domain_size, ctx.dpf_keys[0][k], ctx.indexes[k], 
                        bf_bytes, resp0[k]) == 0 ||
                    evalDPF(domain_size, ctx.dpf_keys[1][k], ctx.indexes[k],
                        bf_bytes, resp1[k]) == 0) {
                    fprintf(stderr, "DPF evaluation failed\n");
                    // 清理内存
                    for (int j=0; j<=k; j++) { 
                        free(resp0[j]); free(resp1[j]);
                    }
                    free(resp0); free(resp1);
                    freeDPFContext(&ctx);
                    continue;
                }
            }

            // 使用clientProcessResponses处理响应
            // 修改主函数中的调用方式
            int dpf_found = clientProcessResponses(resp0, resp1, &ctx, &test_cases[d].dbf);
            
            // 释放响应内存
            for (int k=0; k<BLOOM_FILTER_K; k++) {
                free(resp0[k]);
                free(resp1[k]);
            }
            free(resp0);
            free(resp1);
            
            printf("DPF Query result for '%s': %s\n", 
                keyword, 
                dpf_found ? "Found" : "Not Found");
            
            freeDPFContext(&ctx);
        }
    }
        

    // 清理资源
    for (size_t d = 0; d < DOCUMENT_COUNT; d++) {
        free(test_cases[d].dbf.encrypted_bf);
    }
    
    return EXIT_SUCCESS;
}