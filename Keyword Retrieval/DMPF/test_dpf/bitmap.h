// bitmap.h
#ifndef BITMAP_H
#define BITMAP_H
#include <stdint.h>
#include <stdbool.h>
typedef struct {
    uint8_t* data;    
    int bitSize;      
} Bitmap;

Bitmap* createBitmap(uint32_t bitSize);  
void freeBitmap(Bitmap* bm);
bool isBitOne(const uint8_t *buf, uint32_t bitIndex);  
void setBitOne(uint8_t *buf, uint32_t bitIndex);  
void setBit(Bitmap* bm, uint32_t index, bool value);  
bool getBit(const Bitmap* bm, uint32_t index);  
void xorBitmaps(Bitmap* dst, const Bitmap* src);

void copyBit(uint8_t *dst, uint32_t dstBitIndex, uint8_t *src, uint32_t srcBitIndex);  
void xorIn(uint8_t *out, uint8_t *in, uint32_t len);  

void andStrings(uint8_t *result, const uint8_t *str1, const uint8_t *str2, uint32_t len);  
void orStrings(uint8_t *result, const uint8_t *str1, const uint8_t *str2, uint32_t len);  
void notString(uint8_t *result, const uint8_t *str, uint32_t len);  
Bitmap* reverseBitOrder(Bitmap* input);
#endif 