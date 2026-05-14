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


  bool init();
  bool deinit();

  bool setKeys(const char *publicKeyPem, const char *privateKeyPem);

  bool setPersonalization(const char *personalization);
  bool hasPrivateKey();

  // Encrypt data using the configured public key.
  // This is the standard RSA confidentiality path and works on public-only
  // devices configured with setKeys(publicPem, nullptr).
  bool encrypt(const unsigned char *data,
               size_t dataLen,
               unsigned char *encryptedData,
               size_t bufferSize,
               size_t *encryptedDataLen);

  // Decrypt data using the configured private key.
  // This remains the standard RSA private-key decryption path and fails
  // safely when no private key is configured.
  bool decrypt(const unsigned char *encryptedData,
               size_t encryptedDataLen,
               unsigned char *decryptedData,
               size_t bufferSize,
               size_t *decryptedDataLen);

  // Sign data using the private key.
  // `signatureLen` is input capacity and output actual length.
  bool sign(const unsigned char *data,
            size_t dataLen,
            unsigned char *signature,
            size_t *signatureLen);

  // Verify a SHA-256 signature using the configured public key.
  bool verify(const unsigned char *data,
              size_t dataLen,
              const unsigned char *signature,
              size_t signatureLen);
}
