#include "dcr_Crypto.h"
#include <dcr_Logger.h>
#include <cstring>
#include <memory>

#undef LOG_TAG
#define LOG_TAG "CRYPTO"

namespace Crypto
{
  static bool initialized = false;

  static const char *g_publicKeyPem = nullptr;
  static const char *g_privateKeyPem = nullptr;
  static const char *g_personalization = nullptr;

  static mbedtls_entropy_context cryptoEntropy;
  static mbedtls_ctr_drbg_context cryptoCtrDrbg;
  static mbedtls_pk_context cryptoPublicKey;
  static mbedtls_pk_context cryptoPrivateKey;
  static bool publicKeyLoaded = false;
  static bool privateKeyLoaded = false;

  static constexpr size_t SHA256_HASH_LEN = 32;
  static bool hasText(const char *value)
  {
    return value && value[0] != '\0';
  }

  static void clearOutputLength(size_t *value)
  {
    if (value)
      *value = 0;
  }

  static void logMbedtlsError(const char *action, int rc)
  {
    debugE("%s failed: %d (-0x%x): %s",
           action, rc, -rc, mbedtls_high_level_strerr(rc));
  }

  static bool validateInputBuffer(const char *operation,
                                  const unsigned char *data,
                                  size_t dataLen)
  {
    if (!data)
    {
      debugE("%s: data buffer is required.", operation);
      return false;
    }

    if (dataLen == 0)
    {
      debugE("%s: data length must be greater than zero.", operation);
      return false;
    }

    return true;
  }

  static bool validateOutputBuffer(const char *operation,
                                   unsigned char *output,
                                   size_t bufferSize,
                                   size_t *outputLen)
  {
    clearOutputLength(outputLen);

    if (!outputLen)
    {
      debugE("%s: output length pointer is required.", operation);
      return false;
    }

    if (!output)
    {
      debugE("%s: output buffer is required.", operation);
      return false;
    }

    if (bufferSize == 0)
    {
      debugE("%s: output buffer size must be greater than zero.", operation);
      return false;
    }

    return true;
  }

  static void freePersistentState()
  {
    mbedtls_pk_free(&cryptoPublicKey);
    mbedtls_pk_free(&cryptoPrivateKey);
    publicKeyLoaded = false;
    privateKeyLoaded = false;

    mbedtls_ctr_drbg_free(&cryptoCtrDrbg);
    mbedtls_entropy_free(&cryptoEntropy);
  }

  // Tear down mbedtls contexts when present (no warning — used after each op).
  static void releaseSession()
  {
    if (!initialized)
      return;
    freePersistentState();
    initialized = false;
  }

  // Loads keys/RNG for one operation; always releases RAM in the destructor.
  struct SessionScope
  {
    const bool ok;
    SessionScope() : ok(init()) {}
    ~SessionScope() { releaseSession(); }
    SessionScope(const SessionScope &) = delete;
    SessionScope &operator=(const SessionScope &) = delete;
  };

  static bool requirePrivateKey(const char *operation)
  {
    if (hasPrivateKey())
      return true;

    debugE("%s: private key not configured. Customer devices should use public-key operations only.",
           operation);
    return false;
  }

  static mbedtls_pk_context *getPublicKeyContext(const char *operation)
  {
    if (!publicKeyLoaded)
    {
      debugE("%s: public key not loaded. Check setKeys() and init().", operation);
      return nullptr;
    }

    return &cryptoPublicKey;
  }

  static mbedtls_pk_context *getPrivateKeyContext(const char *operation)
  {
    if (!privateKeyLoaded)
    {
      debugE("%s: private key not loaded.", operation);
      return nullptr;
    }

    return &cryptoPrivateKey;
  }

  static bool computeSha256(const char *operation,
                            const unsigned char *data,
                            size_t dataLen,
                            unsigned char hash[SHA256_HASH_LEN])
  {
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mdInfo)
    {
      debugE("%s: failed to get SHA-256 digest info.", operation);
      return false;
    }

    const int rc = mbedtls_md(mdInfo, data, dataLen, hash);
    if (rc != 0)
    {
      logMbedtlsError(operation, rc);
      return false;
    }

    return true;
  }

  static bool encryptWithPublicKey(const char *operation,
                                   const unsigned char *data,
                                   size_t dataLen,
                                   unsigned char *encryptedData,
                                   size_t bufferSize,
                                   size_t *encryptedDataLen)
  {
    mbedtls_pk_context *pk = getPublicKeyContext(operation);
    if (!pk)
      return false;

    const size_t requiredLen = mbedtls_pk_get_len(pk);
    if (bufferSize < requiredLen)
    {
      *encryptedDataLen = requiredLen;
      debugE("%s: output buffer too small. Need %lu bytes.",
             operation,
             static_cast<unsigned long>(requiredLen));
      return false;
    }

    const int rc = mbedtls_pk_encrypt(pk,
                                      data,
                                      dataLen,
                                      encryptedData,
                                      encryptedDataLen,
                                      bufferSize,
                                      mbedtls_ctr_drbg_random,
                                      &cryptoCtrDrbg);
    if (rc != 0)
    {
      logMbedtlsError(operation, rc);
      clearOutputLength(encryptedDataLen);
      return false;
    }

    return true;
  }

  bool init()
  {
    if (initialized)
      return true;

    if (!hasText(g_publicKeyPem))
    {
      debugE("init: public key PEM is required.");
      return false;
    }

    if (!hasText(g_personalization))
    {
      debugE("init: personalization string is required.");
      return false;
    }

    mbedtls_entropy_init(&cryptoEntropy);
    mbedtls_ctr_drbg_init(&cryptoCtrDrbg);
    mbedtls_pk_init(&cryptoPublicKey);
    mbedtls_pk_init(&cryptoPrivateKey);

    int rc = mbedtls_ctr_drbg_seed(&cryptoCtrDrbg,
                                   mbedtls_entropy_func,
                                   &cryptoEntropy,
                                   reinterpret_cast<const unsigned char *>(g_personalization),
                                   strlen(g_personalization));
    if (rc != 0)
    {
      logMbedtlsError("init", rc);
      freePersistentState();
      return false;
    }

    rc = mbedtls_pk_parse_public_key(&cryptoPublicKey,
                                     reinterpret_cast<const unsigned char *>(g_publicKeyPem),
                                     strlen(g_publicKeyPem) + 1);
    if (rc != 0)
    {
      logMbedtlsError("init", rc);
      freePersistentState();
      return false;
    }
    publicKeyLoaded = true;

    if (hasPrivateKey())
    {
      rc = mbedtls_pk_parse_key(&cryptoPrivateKey,
                                reinterpret_cast<const unsigned char *>(g_privateKeyPem),
                                strlen(g_privateKeyPem) + 1,
                                nullptr,
                                0);
      if (rc != 0)
      {
        logMbedtlsError("init", rc);
        freePersistentState();
        return false;
      }
      privateKeyLoaded = true;
    }

    initialized = true;
    debugD("Crypto initialised.");
    return true;
  }

  bool deinit()
  {
    if (!initialized)
    {
      debugW("Crypto not initialised.");
      return false;
    }

    releaseSession();
    debugD("Crypto deinitialised.");
    return true;
  }

  bool setKeys(const char *publicKeyPem, const char *privateKeyPem)
  {
    if (initialized)
    {
      debugE("setKeys: call deinit() before changing keys.");
      return false;
    }

    if (!hasText(publicKeyPem))
    {
      debugE("setKeys: public key PEM is required.");
      return false;
    }

    g_publicKeyPem = publicKeyPem;
    g_privateKeyPem = hasText(privateKeyPem) ? privateKeyPem : nullptr;
    return true;
  }

  bool setPersonalization(const char *personalization)
  {
    if (initialized)
    {
      debugE("setPersonalization: call deinit() before changing personalization.");
      return false;
    }

    if (!hasText(personalization))
    {
      debugE("setPersonalization: personalization is required.");
      return false;
    }

    g_personalization = personalization;
    return true;
  }

  bool hasPrivateKey()
  {
    return hasText(g_privateKeyPem);
  }

  bool encrypt(const unsigned char *data,
               size_t dataLen,
               unsigned char *encryptedData,
               size_t bufferSize,
               size_t *encryptedDataLen)
  {
    if (!validateOutputBuffer("encrypt", encryptedData, bufferSize, encryptedDataLen) ||
        !validateInputBuffer("encrypt", data, dataLen))
    {
      return false;
    }

    SessionScope session;
    if (!session.ok)
    {
      debugE("encrypt: crypto subsystem is not ready.");
      return false;
    }

    return encryptWithPublicKey("encrypt",
                                data,
                                dataLen,
                                encryptedData,
                                bufferSize,
                                encryptedDataLen);
  }

  bool decrypt(const unsigned char *encryptedData,
               size_t encryptedDataLen,
               unsigned char *decryptedData,
               size_t bufferSize,
               size_t *decryptedDataLen)
  {
    if (!validateOutputBuffer("decrypt", decryptedData, bufferSize, decryptedDataLen) ||
        !validateInputBuffer("decrypt", encryptedData, encryptedDataLen))
    {
      return false;
    }

    if (!requirePrivateKey("decrypt"))
      return false;

    SessionScope session;
    if (!session.ok)
    {
      debugE("decrypt: crypto subsystem is not ready.");
      return false;
    }

    mbedtls_pk_context *pk = getPrivateKeyContext("decrypt");
    if (!pk)
      return false;

    const size_t keyLen = mbedtls_pk_get_len(pk);
    if (encryptedDataLen != keyLen)
    {
      debugE("decrypt: ciphertext length must match RSA key size (%lu bytes).",
             static_cast<unsigned long>(keyLen));
      return false;
    }

    std::unique_ptr<unsigned char[]> plaintext(new (std::nothrow) unsigned char[keyLen]);
    if (!plaintext)
    {
      debugE("decrypt: failed to allocate plaintext buffer.");
      return false;
    }

    size_t plaintextLen = 0;
    const int rc = mbedtls_pk_decrypt(pk,
                                      encryptedData,
                                      encryptedDataLen,
                                      plaintext.get(),
                                      &plaintextLen,
                                      keyLen,
                                      mbedtls_ctr_drbg_random,
                                      &cryptoCtrDrbg);
    if (rc != 0)
    {
      logMbedtlsError("decrypt", rc);
      clearOutputLength(decryptedDataLen);
      return false;
    }

    if (bufferSize < plaintextLen)
    {
      *decryptedDataLen = plaintextLen;
      debugE("decrypt: output buffer too small. Need %lu bytes.",
             static_cast<unsigned long>(plaintextLen));
      return false;
    }

    memcpy(decryptedData, plaintext.get(), plaintextLen);
    *decryptedDataLen = plaintextLen;
    return true;
  }

  bool sign(const unsigned char *data,
            size_t dataLen,
            unsigned char *signature,
            size_t *signatureLen)
  {
    if (!signatureLen)
    {
      debugE("sign: signature length pointer is required.");
      return false;
    }

    const size_t signatureCapacity = *signatureLen;
    *signatureLen = 0;

    if (!signature)
    {
      debugE("sign: signature buffer is required.");
      return false;
    }

    if (!validateInputBuffer("sign", data, dataLen))
    {
      return false;
    }

    if (!requirePrivateKey("sign"))
      return false;

    SessionScope session;
    if (!session.ok)
    {
      debugE("sign: crypto subsystem is not ready.");
      return false;
    }

    mbedtls_pk_context *pk = getPrivateKeyContext("sign");
    if (!pk)
      return false;

    const size_t requiredLen = mbedtls_pk_get_len(pk);
    if (signatureCapacity < requiredLen)
    {
      *signatureLen = requiredLen;
      debugE("sign: signature buffer too small. Need %lu bytes.",
             static_cast<unsigned long>(requiredLen));
      return false;
    }

    unsigned char hash[SHA256_HASH_LEN] = {0};
    if (!computeSha256("sign", data, dataLen, hash))
    {
      return false;
    }

    size_t actualLen = 0;
    const int rc = mbedtls_pk_sign(pk,
                                   MBEDTLS_MD_SHA256,
                                   hash,
                                   SHA256_HASH_LEN,
                                   signature,
                                   &actualLen,
                                   mbedtls_ctr_drbg_random,
                                   &cryptoCtrDrbg);
    if (rc != 0)
    {
      logMbedtlsError("sign", rc);
      return false;
    }

    *signatureLen = actualLen;
    return true;
  }

  bool verify(const unsigned char *data,
              size_t dataLen,
              const unsigned char *signature,
              size_t signatureLen)
  {
    if (!validateInputBuffer("verify", data, dataLen) ||
        !validateInputBuffer("verify", signature, signatureLen))
    {
      return false;
    }

    SessionScope session;
    if (!session.ok)
    {
      debugE("verify: crypto subsystem is not ready.");
      return false;
    }

    mbedtls_pk_context *pk = getPublicKeyContext("verify");
    if (!pk)
      return false;

    unsigned char hash[SHA256_HASH_LEN] = {0};
    if (!computeSha256("verify", data, dataLen, hash))
    {
      return false;
    }

    const int rc = mbedtls_pk_verify(pk,
                                     MBEDTLS_MD_SHA256,
                                     hash,
                                     SHA256_HASH_LEN,
                                     signature,
                                     signatureLen);
    if (rc != 0)
    {
      logMbedtlsError("verify", rc);
      return false;
    }

    return true;
  }
}
