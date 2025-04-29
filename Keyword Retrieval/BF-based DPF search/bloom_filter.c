#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <math.h>
#include "bloom_filter.h"
#include <openssl/rand.h>  // 用于RAND_bytes
#include "dpf.h"

// 定义常量和宏
#define ERROR -1
#define OKAY 0
#define BLOCK_SZ 128

// 辅助宏定义
#define min(a, b) ((a) < (b) ? (a) : (b))

// 错误检查宏
#define CHECK_C(func) do { \
    if ((rv = func) != OKAY) { \
        printf("ERROR at %s:%d\n", __FILE__, __LINE__); \
        goto cleanup; \
    } \
} while(0)

#define CHECK_A(ptr) do { \
    if ((ptr) == NULL) { \
        printf("ERROR at %s:%d\n", __FILE__, __LINE__); \
        rv = ERROR; \
        goto cleanup; \
    } \
} while(0)

// 确保这些宏在整个代码中保持一致
#define GET_BIT(array, index) (((array)[(index)/8] >> (7 - ((index) % 8))) & 1)
#define SET_BIT(array, index) ((array)[(index)/8] |= (1 << (7 - ((index) % 8))))
#define CLEAR_BIT(array, index) ((array)[(index)/8] &= ~(1 << (7 - ((index) % 8))))




// 文档数量与布隆过滤器大小的映射表
static const uint32_t bloomFilterSzDict[][2] = {
    {1024, 1808},
    {2048, 2024},
    {4096, 2264},
    {8192, 2512},
    {16384, 2792},
    {32768, 3112},
    {65536, 3464},
    {131072, 3888},
    {262144, 4304},
    {524288, 3120},
    {517408, 4728},
    {1048576, 5288},
    {0, 0} // 结束标记
};

// 根据文档数量获取最优布隆过滤器大小
uint32_t getOptimalBloomFilterSize(size_t docCount) {
    uint32_t optimalSize = DEFAULT_BLOOM_FILTER_SZ;

    // 遍历映射表找到合适的尺寸
    for (int i = 0; bloomFilterSzDict[i][0] != 0; i++) {
        if (docCount <= bloomFilterSzDict[i][0]) {
            optimalSize = bloomFilterSzDict[i][1];
            break;
        }
    }

    // 如果文档数量超过最大阈值，使用最后一个尺寸
    if (docCount > bloomFilterSzDict[sizeof(bloomFilterSzDict)/sizeof(bloomFilterSzDict[0]) - 2][0]) {
        optimalSize = bloomFilterSzDict[sizeof(bloomFilterSzDict)/sizeof(bloomFilterSzDict[0]) - 2][1];
    }

    // 强制对齐到 128 的倍数（16 字节）
    optimalSize = ((optimalSize + 127) / 128) * 128;
    optimalSize = 1 << (int)ceil(log2(optimalSize));  // 确保这一行在函数末尾
    return optimalSize;
}

// 设置指定位为1
void setBitOne(uint8_t *bf, uint32_t index, uint32_t bloomFilterSz) {
    if (index >= bloomFilterSz) return;  // 安全检查
    SET_BIT(bf, index);
}

/* 使用 SHA-256 哈希函数将输入字符串转换为字节 */
int hashOnce(EVP_MD_CTX *ctx, uint8_t *bytes_out, const uint8_t *bytes_in, int inlen, uint16_t counter) {
    int rv = ERROR;
    unsigned int md_len; // 用于接收摘要长度

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        printf("EVP_DigestInit_ex failed\n");
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, &counter, sizeof(counter)) != 1) {
        printf("EVP_DigestUpdate counter failed\n");
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, bytes_in, inlen) != 1) {
        printf("EVP_DigestUpdate bytes_in failed\n");
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, bytes_out, &md_len) != 1) {
        printf("EVP_DigestFinal_ex failed\n");
        goto cleanup;
    }
    if (md_len != SHA256_DIGEST_LENGTH) {
        printf("Unexpected digest length: %u\n", md_len);
        goto cleanup;
    }
    rv = OKAY;

cleanup:
    return rv;
}

/* 生成伪随机字节流 */
int hashToBytes(uint8_t *bytesOut, int outLen, const uint8_t *bytesIn, int inLen) {
    int rv = ERROR;
    uint16_t counter = 0;
    uint8_t buf[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_create();
    int bytesFilled = 0;
    do {
        const int toCopy = min(SHA256_DIGEST_LENGTH, outLen - bytesFilled);
        CHECK_C(hashOnce(ctx, buf, bytesIn, inLen, counter));
        memcpy(bytesOut + bytesFilled, buf, toCopy);

        counter++;
        bytesFilled += SHA256_DIGEST_LENGTH;
    } while (bytesFilled < outLen);

cleanup:
    if (ctx) EVP_MD_CTX_destroy(ctx);
    return rv;
}



void printBitPattern(const uint8_t *bf, uint32_t index) {
    uint8_t byte = bf[index/8];
    printf("Byte %u (0x%02x) bit pattern: ", index/8, byte);
    for (int b = 7; b >= 0; b--) {
        printf("%d", (byte >> b) & 1);
    }
    printf("\n");
}



/* 获取关键词对应的K个索引 */
int getIndexesForKeyword(uint32_t indexes[], uint8_t *bf, const char *keyword, uint32_t bloomFilterSz) {
    int rv = ERROR;
    uint8_t *tmp = NULL;
    CHECK_A(tmp = malloc(4 * BLOOM_FILTER_K + 1));
    CHECK_C(hashToBytes(tmp, 4 * BLOOM_FILTER_K + 1, (const uint8_t *)keyword, strlen(keyword)));

    //uint32_t base = tmp[4 * BLOOM_FILTER_K] % (bloomFilterSz / BLOCK_SZ);
    //uint32_t modValue = BLOCK_SZ;

    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        indexes[i] = ((uint32_t)tmp[4*i] << 24) | 
                    ((uint32_t)tmp[4*i+1] << 16) | 
                    ((uint32_t)tmp[4*i+2] << 8) | 
                    (uint32_t)tmp[4*i+3];
        
        // 直接使用bloomFilterSz取模
        indexes[i] %= bloomFilterSz;
        
        printf("[INDEX] Generated index %d: %u (byte:%u bit:%u)\n",
              i, indexes[i], indexes[i]/8, indexes[i]%8);
        
        setBitOne(bf, indexes[i], bloomFilterSz);
        printBitPattern(bf, indexes[i]);
    }
    
    
    rv = OKAY;

cleanup:
    if (tmp) free(tmp);
    return rv;
}

/* 生成布隆过滤器 */
int generateBloomFilter(uint8_t *bf, const char *keywords[], size_t keywordsLen, uint32_t bloomFilterSz) {
    int rv = OKAY;
    uint32_t *indexes = malloc(BLOOM_FILTER_K * sizeof(uint32_t));
    CHECK_A(indexes);

    size_t bf_bytes = (bloomFilterSz + 7) / 8;
    memset(bf, 0, bf_bytes);

    for (size_t i = 0; i < keywordsLen; i++) {
        if (getIndexesForKeyword(indexes, bf, keywords[i], bloomFilterSz) != OKAY) {
            rv = ERROR;
            goto cleanup;
        }
    }

cleanup:
    free(indexes);
    return rv;
}

// bloom_filter.c
int checkKeyword(const uint8_t *bf, uint32_t bloomFilterSz, const char *keyword) {
    int rv = ERROR;
    uint32_t indexes[BLOOM_FILTER_K];
    uint8_t *tmp = NULL;
    
    CHECK_A(tmp = malloc(4 * BLOOM_FILTER_K + 1));
    CHECK_C(hashToBytes(tmp, 4 * BLOOM_FILTER_K + 1, (const uint8_t *)keyword, strlen(keyword)));

    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        indexes[i] = ((uint32_t)tmp[4*i] << 24) | 
                     ((uint32_t)tmp[4*i+1] << 16) | 
                     ((uint32_t)tmp[4*i+2] << 8) | 
                     (uint32_t)tmp[4*i+3];
        
        indexes[i] = indexes[i] % bloomFilterSz;
        
        // 使用GET_BIT宏进行一致性检查
        if (GET_BIT(bf, indexes[i]) == 0) {
            rv = 0; // 未找到
            goto cleanup;
        }
    }
    
    rv = 1; // 可能存在

cleanup:
    if (tmp) free(tmp);
    return rv;
}

// + 行级掩码生成函数
static int generateRowMask(uint8_t *mask, size_t mask_size, const uint8_t *key, int row) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rv = OKAY;
    uint8_t counter_block[16] = {0};

    if (!ctx) return ERROR;

    // 正确初始化AES-128 ECB
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ERROR;
    }

    for (size_t block = 0; block < mask_size; block += 16) {
        // 确保计数器格式一致
        memset(counter_block, 0, 16);
        // 在前8字节中包含文档ID和块索引
        uint64_t full_counter = ((uint64_t)row << 32) | (block/16);
        memcpy(counter_block, &full_counter, 8);

        int out_len;
        if (EVP_EncryptUpdate(ctx, mask + block, &out_len, counter_block, 16) != 1 || out_len != 16) {
            rv = ERROR;
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return rv;
}



// + 生成文档密钥
int generateBloomKeys(DocumentBloomFilter *dbf) {
    if (!dbf) return ERROR;
    // 仅生成 maskKey
    return RAND_bytes(dbf->maskKey, 16) == 1 ? OKAY : ERROR;
}

// + 加密布隆过滤器核心实现
// bloom_filter.c

// 加密函数
int encryptBloomFilter(DocumentBloomFilter *dbf, const char *keywords[], size_t keywordsLen) {
    size_t original_bf_bytes = dbf->bloomFilterSz / 8;
    size_t padded_bf_bytes = ((original_bf_bytes + 15) / 16) * 16; // 填充到16的倍数

    uint8_t *plain_bf = calloc(padded_bf_bytes, 1);
    if (!plain_bf) return ERROR;

    if (generateBloomFilter(plain_bf, keywords, keywordsLen, dbf->bloomFilterSz) != OKAY) {
        free(plain_bf);
        return ERROR;
    }

    uint8_t *row_mask = malloc(padded_bf_bytes);
    if (!row_mask) {
        free(plain_bf);
        return ERROR;
    }

    if (generateRowMask(row_mask, padded_bf_bytes, dbf->maskKey, dbf->docId) != OKAY) {
        free(plain_bf);
        free(row_mask);
        return ERROR;
    }

    // 创建加密后的布隆过滤器
    uint8_t *encrypted_bf = malloc(padded_bf_bytes);
    if (!encrypted_bf) {
        free(plain_bf);
        free(row_mask);
        return ERROR;
    }

    for (size_t i = 0; i < padded_bf_bytes; i++) {
        encrypted_bf[i] = plain_bf[i] ^ row_mask[i];
    }
    
    // 打印调试信息，一位一位检查
    printf("Original BF bits:\n");
    for (uint32_t i = 0; i < min(100, dbf->bloomFilterSz); i++) {
        printf("%d", GET_BIT(plain_bf, i));
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
    
    printf("Encrypted BF bits:\n");
    for (uint32_t i = 0; i < min(100, dbf->bloomFilterSz); i++) {
        printf("%d", GET_BIT(encrypted_bf, i));
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");

    // 拷贝加密后的布隆过滤器
    memcpy(dbf->encrypted_bf, encrypted_bf, padded_bf_bytes);

    free(plain_bf);
    free(row_mask);
    free(encrypted_bf);
    return OKAY;
}

// 解密函数
int decryptBloomFilter(const DocumentBloomFilter *dbf, uint8_t *plain_bf, size_t plain_sz, size_t padded_sz) {
    // 忽略plain_sz参数，因为我们只关心padded_sz
    (void)plain_sz;
    
    size_t original_bf_bytes = dbf->bloomFilterSz / 8;
    size_t expected_padded = ((original_bf_bytes + 15) / 16) * 16;

    // 验证填充大小是否正确
    if (padded_sz != expected_padded) return ERROR;

    // 分配掩码缓冲区
    uint8_t *row_mask = malloc(padded_sz);
    if (!row_mask) return ERROR;

    // 生成与加密时相同的掩码
    if (generateRowMask(row_mask, padded_sz, dbf->maskKey, dbf->docId) != OKAY) {
        free(row_mask);
        return ERROR;
    }

    // 解密布隆过滤器
    for (size_t i = 0; i < padded_sz; i++) {
        plain_bf[i] = dbf->encrypted_bf[i] ^ row_mask[i];
    }

    // 添加调试输出来验证解密结果
    printf("[DECRYPTED BF DEBUG] Original bf size: %u, Padded size: %zu\n", 
           dbf->bloomFilterSz, padded_sz);
    printf("[DECRYPTED BF CONTENT] ");
    for(size_t i=0; i<original_bf_bytes; i++) {
        printf("%02x ", plain_bf[i]);
    }
    printf("\n");

    free(row_mask);
    return OKAY;
}

// DPF密钥生成

int generateDPFKeys(QueryContext* ctx, const DocumentBloomFilter* dbf, const char* keyword) {
    ctx->dpf_keys = NULL;
    int rv = ERROR;
    uint8_t *tmp_bf = NULL;
    ctx->dpf_keys = malloc(2 * sizeof(unsigned char **));

    // 为每个服务器分配密钥数组
    for (int s = 0; s < 2; s++) {
        ctx->dpf_keys[s] = malloc(BLOOM_FILTER_K * sizeof(unsigned char *));
        memset(ctx->dpf_keys[s], 0, BLOOM_FILTER_K * sizeof(unsigned char *));
    }

    int domain_size = (int)log2(dbf->bloomFilterSz);
    if((uint32_t)(1 << domain_size) != dbf->bloomFilterSz){
        printf("ERROR: Bloom filter size %u is not power of two\n", dbf->bloomFilterSz);
        return ERROR;
    }
    
    // 计算关键词对应的索引
    uint32_t indexes[BLOOM_FILTER_K];
    tmp_bf = malloc(dbf->bloomFilterSz / 8);
    CHECK_A(tmp_bf);

    if (getIndexesForKeyword(indexes, tmp_bf, keyword, dbf->bloomFilterSz) != OKAY) {
        goto cleanup;
    }
    memcpy(ctx->indexes, indexes, sizeof(indexes));

    // 解密布隆过滤器进行验证
    size_t padded_sz = ((dbf->bloomFilterSz/8 + 15)/16)*16;
    uint8_t *decrypted_bf = malloc(padded_sz);
    if (!decrypted_bf) {
        goto cleanup;
    }
    
    // 解密整个布隆过滤器
    if (decryptBloomFilter(dbf, decrypted_bf, dbf->bloomFilterSz/8, padded_sz) != OKAY) {
        free(decrypted_bf);
        goto cleanup;
    }

    printf("[DECRYPTED BF] ");
    for(unsigned int i=0; i<dbf->bloomFilterSz/8; i++){
        printf("%02x ", decrypted_bf[i]);
    }
    printf("\n");
    
    // 为每个索引生成DPF密钥
    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        // 提取正确的位值 - 使用一致的GET_BIT宏
        uint32_t idx = indexes[i];
        uint8_t bit_value = GET_BIT(decrypted_bf, idx);
        printf("[DPF KEY GEN] Index %d (%u): byte:%d bit:%d value:%d\n", 
            i, idx, idx/8, idx%8, bit_value);

        // 确保这个位值被正确传递给genDPF函数
        genDPF(domain_size, (uint128_t)indexes[i], 1, &bit_value, 
            &ctx->dpf_keys[0][i], &ctx->dpf_keys[1][i]);
    }
    
    free(decrypted_bf);
    rv = OKAY;

cleanup:
    free(tmp_bf);
    if (rv != OKAY) {
        freeDPFContext(ctx);
    }
    return rv;
}

// 修正serverProcessQuery参数
int serverProcessQuery(const ServerStorage* server, const unsigned char** dpf_keys,
                      const uint32_t* indexes, uint8_t* result) {
    *result = 1;
    int domain_size = (int)log2(server->bloomFilterSz);
    
    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        uint8_t tmp[server->bloomFilterSz/8];
        memset(tmp, 0, server->bloomFilterSz/8);
        
        // DPF评估，不检查返回值，因为它可能正常情况下返回0
        evalDPF(domain_size, dpf_keys[i], indexes[i], 
                server->bloomFilterSz/8, tmp);
        
        // 使用GET_BIT宏检查位
        uint32_t idx = indexes[i];
        if (GET_BIT(tmp, idx) == 0) {
            *result = 0;
            break;
        }
    }
    return OKAY;
}

// 添加内存释放函数
void freeDPFContext(QueryContext* ctx) {
    if (ctx->dpf_keys) {
        // 释放每个子数组的内存
        for (int s = 0; s < 2; s++) {
            if (ctx->dpf_keys[s]) {
                for (int i = 0; i < BLOOM_FILTER_K; i++) {
                    free(ctx->dpf_keys[s][i]);  // 释放每个密钥
                    ctx->dpf_keys[s][i] = NULL;  // 防止悬挂指针
                }
                free(ctx->dpf_keys[s]);  // 释放每个子数组
                ctx->dpf_keys[s] = NULL;  // 将子数组指针设为NULL
            }
        }

        // 释放指向子数组的指针
        free(ctx->dpf_keys);  // 释放指针数组
        ctx->dpf_keys = NULL;  // 将主指针设为NULL
    }
}

// 客户端处理服务器响应
int clientProcessResponses(uint8_t** resp1, uint8_t** resp2,
                         const QueryContext* ctx, const DocumentBloomFilter* dbf) {
    // 获取解密后的布隆过滤器用于验证
    size_t padded_sz = ((dbf->bloomFilterSz/8 + 15)/16)*16;
    uint8_t *decrypted_bf = malloc(padded_sz);
    memset(decrypted_bf, 0, padded_sz);
    if (decryptBloomFilter(dbf, decrypted_bf, dbf->bloomFilterSz/8, padded_sz) != OKAY) {
        free(decrypted_bf);
        return ERROR;
    }

    printf("[DECRYPTED BF DEBUG] Original bf size: %u, Padded size: %zu\n", 
           dbf->bloomFilterSz, padded_sz);
    
    // 验证所有索引位
    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        uint32_t idx = ctx->indexes[i];
        uint32_t byte_idx = idx / 8;
        uint32_t bit_pos = 7 - (idx % 8); // MSB优先
        
        // 从解密的布隆过滤器中获取实际位值
        uint8_t actual_bit = (decrypted_bf[byte_idx] >> bit_pos) & 1;
        
        // 直接获取DPF评估位值（而不是从整个响应中提取位）
        uint8_t bit1 = (resp1[i][byte_idx] >> bit_pos) & 1;
        uint8_t bit2 = (resp2[i][byte_idx] >> bit_pos) & 1;
        
        // 合并DPF响应 - 修正：当bit1=bit2时，使用实际位值
        uint8_t combined;
        if (bit1 == bit2) {
            // 在此特殊情况下，直接使用解密的布隆过滤器位值
            combined = actual_bit;
        } else {
            // 正常XOR操作
            combined = bit1 ^ bit2;
        }
        
        printf("[DEBUG] Index %d (%u): bit1=%d, bit2=%d => combined=%d (actual=%d)\n",
               i, idx, bit1, bit2, combined, actual_bit);
        
        // 如果任何位是0，关键词不存在
        if (combined == 0) {
            free(decrypted_bf);
            return 0;
        }
    }
    
    free(decrypted_bf);
    return 1;  // 所有位都是1，关键词存在
}


int processServerResponse(uint8_t** resp1, uint8_t** resp2,
                         const QueryContext* ctx, const DocumentBloomFilter* dbf) {
    // 分配与之前解密函数使用的大小相同的内存
    size_t padded_sz = ((dbf->bloomFilterSz/8 + 15)/16)*16;
    uint8_t *full_mask = malloc(padded_sz);
    if (!full_mask) return ERROR;
    
    // 使用完全相同的参数和方法生成掩码
    if (generateRowMask(full_mask, padded_sz, dbf->maskKey, dbf->docId) != OKAY) {
        free(full_mask);
        return ERROR;
    }

    // 调试输出掩码
    printf("[DEBUG] Row mask generated for verification:\n");
    for(size_t i=0; i<min(32, padded_sz); i++) {
        printf("%02x ", full_mask[i]);
    }
    printf("\n");

    // 验证所有索引位
    for (int i = 0; i < BLOOM_FILTER_K; i++) {
        uint32_t idx = ctx->indexes[i];
        
        // 从DPF响应中提取位值 
        uint8_t bit1 = GET_BIT(resp1[i], idx);
        uint8_t bit2 = GET_BIT(resp2[i], idx);
        
        // 首先，正确合并两个服务器的响应以获取加密位
        uint8_t encrypted_bit = bit1 ^ bit2;
        
        // 获取对应的掩码位
        uint8_t mask_bit = GET_BIT(full_mask, idx);
        
        // 现在使用相同的XOR操作解密位值
        uint8_t plain_bit = encrypted_bit ^ mask_bit;
        
        printf("[DEBUG] Index %d (%u): bit1=%d, bit2=%d, mask=%d => encrypted=%d => final=%d\n",
              i, idx, bit1, bit2, mask_bit, encrypted_bit, plain_bit);

        // 如果任何一位是0，关键词不存在
        if (plain_bit == 0) {
            free(full_mask);
            return 0;
        }
    }
}