#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace depotkit {

/** AES-256: ECB decrypt one 16-byte block, CBC decrypt with PKCS7. */
std::vector<uint8_t> aesDecryptEcbBlock(const uint8_t key[32], const uint8_t block[16]);
std::vector<uint8_t> aesDecryptCbcPkcs7(const uint8_t key[32], const uint8_t iv[16],
                                        const uint8_t *data, size_t len);

/** Steam SymmetricDecrypt: ECB-IV prefix + CBC body. */
std::vector<uint8_t> steamSymmetricDecrypt(const uint8_t key[32], const uint8_t *data, size_t len);

/** Decrypt base64 filename blob used in encrypted manifests. */
std::string decryptDepotFilename(const uint8_t key[32], const std::string &b64);

/** Decrypt + decompress a depot chunk into `out` (size >= uncompressedLength). */
size_t processDepotChunk(const uint8_t key[32], const uint8_t *encrypted, size_t encryptedLen,
                         uint8_t *out, size_t outCap, uint32_t expectedUncompressed,
                         uint32_t expectedAdler);

} // namespace depotkit
