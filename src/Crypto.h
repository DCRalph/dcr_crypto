#pragma once

#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h> // For hashing

namespace Crypto
{
  // Initialize the crypto system with null-terminated PEM key material and DRBG
  // personalization. The pointers must remain valid for as long as crypto
  // operations may run (and until deinit). privateKeyPem may be null when
  // INCLUDE_PRIVATE_KEYS is not defined.
  bool init(const char *publicKeyPem,
            const char *privateKeyPem,
            const char *personalization);
  // Deinitialize the crypto system (returns true if successful, false if not initialized)
  bool deinit();

  // Encrypt data using the private key (DEBUG only, automatically loads/frees key)
  void encrypt(unsigned char *data,
               size_t dataLen,
               unsigned char *encryptedData,
               size_t bufferSize,
               size_t *encryptedDataLen);

  // Encrypt data using the public key (automatically loads/frees key)
  void encryptPublic(unsigned char *data,
                     size_t dataLen,
                     unsigned char *encryptedData,
                     size_t bufferSize,
                     size_t *encryptedDataLen);

  // Decrypt data using the private key (DEBUG only, automatically loads/frees key)
  void decrypt(unsigned char *encryptedData,
               size_t encryptedDataLen,
               unsigned char *decryptedData,
               size_t bufferSize,
               size_t *decryptedDataLen);

  // Sign data using the private key (DEBUG only, automatically loads/frees key)
  void sign(const unsigned char *data,
            size_t dataLen,
            unsigned char *signature,
            size_t *signatureLen);

  // Verify signature using the public key (automatically loads/frees key)
  bool verify(const unsigned char *data,
              size_t dataLen,
              const unsigned char *signature,
              size_t signatureLen);
}
