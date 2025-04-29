#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <stdint.h>
#include "dpf.h"
#define BLOOM_FILTER_K 7
#define DEFAULT_BLOOM_FILTER_SZ 1024

// + 新增加密相关结构体
// bloom_filter.h
typedef struct {
    uint8_t maskKey[16];   // 统一使用一个密钥
    uint8_t *encrypted_bf;
    uint32_t bloomFilterSz;
    uint32_t docId;
} DocumentBloomFilter;

// 新增服务器数据结构
typedef struct {
    uint8_t* encrypted_bf;          // 加密的布隆过滤器
    uint32_t bloomFilterSz;         // 过滤器大小
} ServerStorage;




// 在现有内容后添加以下声明
typedef struct {
    unsigned char ***dpf_keys;  // 三维数组[2][K][key_size]
    uint32_t indexes[BLOOM_FILTER_K];
} QueryContext;


int generateDPFKeys(QueryContext* ctx, const DocumentBloomFilter* dbf, const char* keyword);
// 在 bloom_filter.h 中更新声明
int serverProcessQuery(const ServerStorage* server, const unsigned char** dpf_keys,
                      const uint32_t* indexes, uint8_t* result);


void freeDPFContext(QueryContext* ctx);

int processServerResponse(uint8_t** resp1, uint8_t** resp2, const QueryContext* ctx, const DocumentBloomFilter* dbf);


// + 新增加密功能函数声明
int generateBloomKeys(DocumentBloomFilter *dbf);
int encryptBloomFilter(DocumentBloomFilter *dbf, const char *keywords[], size_t keywordsLen);
// 修改decryptBloomFilter函数声明，添加填充处理
int decryptBloomFilter(const DocumentBloomFilter *dbf, uint8_t *plain_bf, size_t plain_sz, size_t padded_sz);
// 原有函数声明保持不变
int hashToBytes(uint8_t *bytesOut, int outLen, const uint8_t *bytesIn, int inLen);
void setBitOne(uint8_t *bf, uint32_t index, uint32_t bloomFilterSz);
int getIndexesForKeyword(uint32_t indexes[], uint8_t *bf, const char *keyword, uint32_t bloomFilterSz);
int generateBloomFilter(uint8_t *bf, const char *keywords[], size_t keywordsLen, uint32_t bloomFilterSz);
int checkKeyword(const uint8_t *bf, uint32_t bloomFilterSz, const char *keyword);
uint32_t getOptimalBloomFilterSize(size_t docCount);
void handle_openssl_error(const char* msg);

// 在 bloom_filter.h 中更新声明
int clientProcessResponses(uint8_t** resp1, uint8_t** resp2, 
                          const QueryContext* ctx, const DocumentBloomFilter* dbf);
#endif // BLOOM_FILTER_H