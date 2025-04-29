// params.h
#ifndef PARAMS_H
#define PARAMS_H

#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "bitmap.h"  // 使用bitmap.h中的Bitmap定义

// 保留原有的uint128_t定义
#ifdef __SIZEOF_INT128__
    typedef unsigned __int128 uint128_t;
#else
    typedef struct {
        uint64_t low;
        uint64_t high;
    } uint128_t;
#endif

// 移除重复的Bitmap结构体定义和位图操作函数声明，因为它们已经在bitmap.h中定义

// 保留原有的辅助函数声明
void printBuffer(char *label, uint8_t *buf, int len);
void printByteBinary(char byte);

// 添加新的必要函数声明
// 位操作辅助函数
uint32_t getBit32(uint32_t x, uint32_t i);
void xorByteArray(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t len);

// PRF相关函数
int prg(const uint8_t *seed, EVP_CIPHER_CTX *ctx, uint8_t *output, uint32_t outLen);
uint8_t* randBytes(size_t len);

// 数值操作辅助函数
uint32_t divideNumber(uint8_t totalBits, uint8_t rightBits, uint32_t number);
uint8_t randUInt8(uint8_t max);

// 错误处理函数
void handleError(const char* msg);

#endif // PARAMS_H