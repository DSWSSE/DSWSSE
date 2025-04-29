#ifndef _PARAMS
#define _PARAMS

#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// 系统常量定义
#define MAX_THREADS 128
#define MALICIOUS true
#define BLOOM_FILTER_K 7
#define BLOCK_BYTES 16
#define BLOCK_SZ 128
#define FIRST_TERM 1
#define SECOND_TERM 2
#define CT_LEN 32
#define IV_LEN 16
#define TAG_LEN 16
#define AAD_LEN 16
#define MAC_BYTES 16

/* // 性能测试相关参数
#define MAX_NUM_KEYWORDS 1000  // 添加这行
#define DEFAULT_NUM_TRIALS 5   // 添加这行：默认测试次数
#define MIN_BLOOM_FILTER_SIZE 1120  // 添加这行：最小布隆过滤器大小
#define MAX_BLOOM_FILTER_SIZE 3480 // 添加这行：最大布隆过滤器大小 */

// 外部变量声明
extern int NUM_DOCS;
extern int NUM_DOCS_BYTES;
extern int MAX_DOCS;
extern int MAX_DOCS_BYTES;
extern int BLOOM_FILTER_SZ;
extern int LOG_BLOOM_FILTER_SZ;
extern int BLOOM_FILTER_BYTES;
extern int MALICIOUS_DPF_LEN;

// 类型定义
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

// 函数声明
void setSystemParams(int bloomFilterSz, int numDocs);
int hashToBytes(uint8_t *bytesOut, int outLen, const uint8_t *bytesIn, int inLen);
int prf(EVP_CIPHER_CTX *ctx, uint8_t *bytesOut, int outLen, const uint8_t *bytesIn, int inLen, uint8_t startCounter);
int blockPrf(EVP_CIPHER_CTX *ctx, uint8_t *bytesOut, const uint8_t *bytesIn, int len);
bool isBitOne(const uint8_t *buf, int bitIndex);
//void setBitOne(uint8_t *buf, int bitIndex);
void getBitColumn(const uint8_t **table, int column, uint8_t *result);
void setBitColumn(uint8_t **table, int column, uint8_t *in, int inBytes);
void copyBit(uint8_t *dst, int dstBitIndex, uint8_t *src, int srcBitIndex);
void xorIn(uint8_t *out, uint8_t *in, int len);
void flipTable(uint8_t **tableOut, const uint8_t **tableIn, int rows, int cols);
void convertBignumsToBytes(BIGNUM **src, uint8_t **dst, uint8_t *lens, int sz);
BIGNUM *convertBytesToBignum(uint8_t *src, int len);
void freeBignums(BIGNUM **bns, int len);
int getDPFKeyLen();
int getDPFKeyLen_malicious();
void printBuffer(char *label, uint8_t *buf, int len);
void printByteBinary(char byte);

/* 在 params.h 中添加声明 */
int min(int a, int b);

#endif
