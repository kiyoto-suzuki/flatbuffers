/**********************************************************\
|                                                          |
| xxtea.h                                                  |
|                                                          |
| XXTEA encryption algorithm library for C.                |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Authors: Chen fei <cf850118@163.com>                |
|               Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Mar 3, 2015                                |
|                                                          |
\**********************************************************/

#ifndef XXTEA_INCLUDED
#define XXTEA_INCLUDED

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t xxtea_to_key_array(const char * key, size_t len, uint32_t* key_array, size_t key_array_size);
size_t xxtea_ubyte_encrypt(const uint8_t * data, size_t len, uint8_t* out, size_t out_size, const uint32_t * key_array);
size_t xxtea_ubyte_decrypt(const uint8_t * data, size_t len, uint8_t* out, size_t out_size, const uint32_t * key_array);

size_t xxtea_encrypt(const void * data, size_t len, uint8_t * out, size_t out_size, const char * key);
size_t xxtea_decrypt(const void * data, size_t len, uint8_t * out, size_t out_size, const char * key);

#ifdef __cplusplus
}
#endif

#endif
