#ifndef _CRC32_H
#define _CRC32_H

typedef unsigned int u32;
typedef unsigned char u8;

#include <stdint.h>

u32 crc32 ( u32 seed, const void *data, size_t len );

#endif
