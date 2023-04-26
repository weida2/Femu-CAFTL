// #ifndef _CRC32_H
// #define _CRC32_H

typedef unsigned int u32;
typedef unsigned char u8;

#include <stdint.h> 
#include "../nvme.h"

u32 crc32(u32 seed, const void *buf, unsigned int size);
// u32 crc32 ( u32 seed, const void *data, size_t len );
u32 crc32_v1 (void *pStart, u32 uSize);


// #endif
