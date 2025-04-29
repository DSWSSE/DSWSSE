// bitmap.c
#include <stdlib.h>
#include <string.h>
#include "bitmap.h"

Bitmap* createBitmap(uint32_t bitSize) {
    Bitmap* bm = (Bitmap*)malloc(sizeof(Bitmap));
    if (!bm) return NULL;
    bm->bitSize = bitSize;
    bm->data = (uint8_t*)malloc((bitSize + 7) / 8);
    if (!bm->data) {
        free(bm);
        return NULL;
    }
    memset(bm->data, 0, (bitSize + 7) / 8);
    return bm;
}

void freeBitmap(Bitmap* bm) {
    if(bm) {
        if(bm->data) free(bm->data);
        free(bm);
    }
}

bool isBitOne(const uint8_t *buf, uint32_t bitIndex) {
    uint32_t byteIndex = bitIndex / 8;
    return buf[byteIndex] & (1 << (bitIndex % 8));
}

void setBitOne(uint8_t *buf, uint32_t bitIndex) {
    uint32_t byteIndex = bitIndex / 8;
    buf[byteIndex] |= 1 << (bitIndex % 8);
}

void setBit(Bitmap* bm, uint32_t index, bool value) {
    if (index >= bm->bitSize) return;
    uint32_t byteIndex = index / 8;
    uint32_t bitOffset = index % 8;
    if (value) {
        bm->data[byteIndex] |= (1 << bitOffset);
    } else {
        bm->data[byteIndex] &= ~(1 << bitOffset);
    }
}

bool getBit(const Bitmap* bm, uint32_t index) {
    if (index >= bm->bitSize) return false;
    uint32_t byteIndex = index / 8;
    uint32_t bitOffset = index % 8;
    return (bm->data[byteIndex] & (1 << bitOffset)) != 0;
}

void xorBitmaps(Bitmap* dst, const Bitmap* src) {
    uint32_t minBytes = ((dst->bitSize < src->bitSize ? dst->bitSize : src->bitSize) + 7) / 8;
    for(uint32_t i = 0; i < minBytes; i++) {
        dst->data[i] ^= src->data[i];
    }
}

void copyBit(uint8_t *dst, uint32_t dstBitIndex, uint8_t *src, uint32_t srcBitIndex) {
    uint8_t srcBit = src[srcBitIndex / 8] & (1 << (srcBitIndex % 8));
    srcBit = srcBit >> (srcBitIndex % 8);
    dst[dstBitIndex / 8] |= srcBit << (dstBitIndex % 8);
}

void xorIn(uint8_t *out, uint8_t *in, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        out[i] = out[i] ^ in[i];
    }
}

// AND operation
void andStrings(uint8_t *result, const uint8_t *str1, const uint8_t *str2, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        result[i] = str1[i] & str2[i];
    }
}

// OR operation
void orStrings(uint8_t *result, const uint8_t *str1, const uint8_t *str2, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        result[i] = str1[i] | str2[i];
    }
}


void notString(uint8_t *result, const uint8_t *str, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        result[i] = ~str[i];  
    }
}


Bitmap* reverseBitOrder(Bitmap* input) {
    if (!input) return NULL;
    
    Bitmap* output = createBitmap(input->bitSize);
    if (!output) return NULL;
    
    for (uint32_t i = 0; i < input->bitSize; i++) {
        
        setBit(output, i, getBit(input, input->bitSize - 1 - i));
    }
    
    return output;
}
