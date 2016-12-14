#include "flatbuffers/aes.h"

#include <iostream>
#include <iomanip>
#include <cassert>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <zlib.h>

namespace flatbuffers {
namespace crypto {

size_t Aes::KEY_SIZE = 32;  // AES-CBC-256

// Make a Key of exactly 32 bytes, truncates or adds values if it's necessary
std::string Aes::normalizeKey(const std::string& key) {
  std::string dest = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  dest.assign(key, 0, key.size() < KEY_SIZE ? key.size() : KEY_SIZE);
  return dest;
}

std::string Aes::encrypt(const unsigned char* data,
                         size_t size,
                         const std::string& key,
                         const std::string& iv,
                         bool withCompress) {
  if (size == 0) return std::string();

  // encrypt key
  AES_KEY encryptedKey;
  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()), KEY_SIZE * 8, &encryptedKey);

  // initial vector
  unsigned char initialVector[AES_BLOCK_SIZE] = {0};
  std::memcpy(initialVector, iv.data(), iv.size() < AES_BLOCK_SIZE ? iv.size() : AES_BLOCK_SIZE);

  // setup buf + compress
  std::string buf;
  size_t bufSize = size + AES_BLOCK_SIZE;
  if (withCompress) {
    int ret;
    do {
      bufSize *= 2;
      buf.resize(bufSize);
      ret = compress((Bytef*)buf.data(), (unsigned long*)&bufSize, (Bytef*)data, (unsigned long)size);
      if (ret == Z_DATA_ERROR) return std::string();
      assert(ret == Z_OK || ret == Z_BUF_ERROR);
    } while (ret != Z_OK);
    size = bufSize;  // overwrite encryption data size
  } else {
    bufSize = size + AES_BLOCK_SIZE;
    buf.resize(bufSize);
    std::memcpy((unsigned char*)buf.data(), data, size);
  }

  // padding
  unsigned char padding = (size % AES_BLOCK_SIZE > 0) ? AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE) : 0;
  size_t encSize = size + padding;
  std::memset((unsigned char*)buf.data() + size, padding, padding);

  // encrypt data
  std::string dest;
  dest.resize(encSize);
  AES_cbc_encrypt((const unsigned char*)buf.data(), (unsigned char*)dest.data(), encSize, &encryptedKey,
                  initialVector, AES_ENCRYPT);
  return dest;
}

std::string Aes::decrypt(const unsigned char* data,
                         size_t size,
                         const std::string& key,
                         const std::string& iv,
                         bool withUncompress,
                         bool unpad) {
  if (size == 0) {
    return std::string();
  }

  // decrypt key
  AES_KEY decryptedKey;
  AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(normalizeKey(key).data()), KEY_SIZE * 8,
                      &decryptedKey);

  // initial vector
  unsigned char initialVector[AES_BLOCK_SIZE] = {0};
  std::memcpy(initialVector, iv.data(), iv.size() < AES_BLOCK_SIZE ? iv.size() : AES_BLOCK_SIZE);

  // decrypt data
  std::string dest;
  dest.resize(size);
  AES_cbc_encrypt(data, (unsigned char*)dest.data(), size, &decryptedKey, initialVector, AES_DECRYPT);

  if (withUncompress) {
    // uncompress
    std::string dest2;
    unsigned long uncompSize = size;
    int ret;
    do {
      uncompSize *= 2;
      dest2.resize(uncompSize);
      ret = uncompress((Bytef*)dest2.data(), &uncompSize, (Bytef*)dest.data(), size);
      if (ret == Z_DATA_ERROR) return std::string();
      assert(ret == Z_OK || ret == Z_BUF_ERROR);
    } while (ret != Z_OK);
    dest2.resize(uncompSize);
    return dest2;
  } else if (unpad && dest.back() <= (unsigned char)0x10) {
    // unpad (just for string not binary)
    std::size_t last = dest.find_last_not_of(dest.back());
    dest = dest.substr(0, last + 1);
    dest.resize(last + 1);
  }
  return dest;
}

std::string Aes::encrypt(const std::string& str,
                         const std::string& key,
                         const std::string& iv,
                         bool withCompress) {
  return encrypt(reinterpret_cast<const unsigned char*>(str.data()), str.size(), key, iv, withCompress);
}

std::string Aes::decrypt(
    const std::string& str, const std::string& key, const std::string& iv, bool withUncompress, bool unpad) {
  return decrypt(reinterpret_cast<const unsigned char*>(str.data()), str.size(), key, iv, withUncompress,
                 unpad);
}

std::string Aes::generateIv() {
  std::string dest;
  dest.resize(AES_BLOCK_SIZE);
  RAND_bytes((unsigned char*)dest.data(), AES_BLOCK_SIZE);
  return dest;
}

void Aes::dump(const unsigned char* data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(*(data + i)) << " ";
    if (((i + 1) % AES_BLOCK_SIZE == 0) && ((i + 1) != size)) {
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;
}

void Aes::dump(const std::string& str) {
  dump(reinterpret_cast<const unsigned char*>(str.data()), str.size());
}
}
}
