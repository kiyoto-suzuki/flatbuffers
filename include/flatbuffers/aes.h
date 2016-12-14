#pragma once
#include <cstddef>
#include <string>
#include <openssl/aes.h>

namespace flatbuffers {
namespace crypto {

/**
 * AES-CBC-256
 */
class Aes {
 public:
  static size_t KEY_SIZE;

  static std::string encrypt(const unsigned char* src,
                             size_t size,
                             const std::string& key,
                             const std::string& iv,
                             bool withCompress = true);
  static std::string decrypt(const unsigned char* src,
                             size_t size,
                             const std::string& key,
                             const std::string& iv,
                             bool withUncompress = true,
                             bool unpad = true);

  static std::string encrypt(const std::string& str,
                             const std::string& key,
                             const std::string& iv,
                             bool withCompress = true);
  static std::string decrypt(const std::string& str,
                             const std::string& key,
                             const std::string& iv,
                             bool withUncompress = true,
                             bool unpad = true);

  static void dump(const unsigned char* data, size_t size);
  static void dump(const std::string& data);

  static std::string generateIv();

 private:
  static std::string normalizeKey(const std::string& key);
};
}
}
