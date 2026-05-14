#include "Crypto.h"
#include <Logger.h>
#include <cstring>

#undef LOG_TAG
#define LOG_TAG "CRYPTO"

namespace Crypto
{

  static bool initialized = false;

  static const char *g_publicKeyPem = nullptr;
  static const char *g_privateKeyPem = nullptr;
  static const char *g_personalization = nullptr;

  // Global mbedTLS contexts (persistent for entropy and RNG)
  static mbedtls_entropy_context cryptoEntropy;
  static mbedtls_ctr_drbg_context cryptoCtrDrbg;

  // ----------------------
  // init()
  // ----------------------
  bool init(const char *publicKeyPem, const char *privateKeyPem, const char *personalization)
  {
    if (initialized)
    {
      debugW("Crypto already initialised.");
      return true;
    }

    if (!publicKeyPem || !personalization)
    {
      debugE("Crypto init: publicKeyPem and personalization are required.");
      return false;
    }
#ifdef INCLUDE_PRIVATE_KEYS
    if (!privateKeyPem)
    {
      debugE("Crypto init: privateKeyPem is required when INCLUDE_PRIVATE_KEYS is set.");
      return false;
    }
#endif

    g_publicKeyPem = publicKeyPem;
    g_privateKeyPem = privateKeyPem;
    g_personalization = personalization;

    // Initialize contexts (these don't return errors, they always succeed)
    mbedtls_entropy_init(&cryptoEntropy);
    mbedtls_ctr_drbg_init(&cryptoCtrDrbg);

    // Seed the RNG (can fail, but contexts are still initialized and need cleanup)
    int ret = mbedtls_ctr_drbg_seed(&cryptoCtrDrbg,
                                    mbedtls_entropy_func,
                                    &cryptoEntropy,
                                    reinterpret_cast<const unsigned char *>(g_personalization),
                                    strlen(g_personalization));
    if (ret != 0)
    {
      debugE("Failed to seed RNG: %d (-0x%x): %s",
                       ret, -ret, mbedtls_high_level_strerr(ret));
      // Free the contexts since initialization failed
      mbedtls_ctr_drbg_free(&cryptoCtrDrbg);
      mbedtls_entropy_free(&cryptoEntropy);
      g_publicKeyPem = nullptr;
      g_privateKeyPem = nullptr;
      g_personalization = nullptr;
      debugE("Crypto initialization failed.");
      return false;
    }

    debugD("Crypto initialised.");
    initialized = true;
    return true;
  }

  // ----------------------
  // deinit()
  // ----------------------
  bool deinit()
  {
    if (!initialized)
    {
      debugW("Crypto not initialised.");
      return false;
    }

    mbedtls_ctr_drbg_free(&cryptoCtrDrbg);
    mbedtls_entropy_free(&cryptoEntropy);
    g_publicKeyPem = nullptr;
    g_privateKeyPem = nullptr;
    g_personalization = nullptr;
    initialized = false;
    debugD("Crypto deinitialised.");
    return true;
  }

  // Internal helper functions to load/free keys
  static bool loadPrivateKey(mbedtls_pk_context *pk)
  {
#ifdef INCLUDE_PRIVATE_KEYS
    if (!g_privateKeyPem)
    {
      debugE("Private key PEM not configured.");
      return false;
    }

    mbedtls_pk_init(pk);

    int rc = mbedtls_pk_parse_key(pk,
                                  reinterpret_cast<const unsigned char *>(g_privateKeyPem),
                                  strlen(g_privateKeyPem) + 1,
                                  nullptr,
                                  0);

    if (rc != 0)
    {
      debugE("Failed to parse RSA private key: %d (-0x%x): %s",
                       rc, -rc, mbedtls_high_level_strerr(rc));
      mbedtls_pk_free(pk); // Free the initialized context on failure
      return false;
    }

    return true;
#else
    return false;
#endif
  }

  static bool loadPublicKey(mbedtls_pk_context *pk)
  {
    if (!g_publicKeyPem)
    {
      debugE("Public key PEM not configured.");
      return false;
    }

    mbedtls_pk_init(pk);

    int rc = mbedtls_pk_parse_public_key(pk,
                                         reinterpret_cast<const unsigned char *>(g_publicKeyPem),
                                         strlen(g_publicKeyPem) + 1);

    if (rc != 0)
    {
      debugE("Failed to parse RSA public key: %d (-0x%x): %s",
                       rc, -rc, mbedtls_high_level_strerr(rc));
      mbedtls_pk_free(pk); // Free the initialized context on failure
      return false;
    }

    return true;
  }

  static void freeKey(mbedtls_pk_context *pk)
  {
    // Always free the key context, even if crypto system isn't initialized
    // This ensures cleanup if pk was initialized but crypto init failed
    mbedtls_pk_free(pk);
  }

  // ----------------------
  // encrypt() - Dynamically loads/frees private key
  // ----------------------
  void encrypt(unsigned char *data,
               size_t dataLen,
               unsigned char *encryptedData,
               size_t bufferSize,
               size_t *encryptedDataLen)
  {
#ifdef INCLUDE_PRIVATE_KEYS
    if (!init())
    {
      debugE("Cannot encrypt: Failed to initialize crypto system.");
      return;
    }

    mbedtls_pk_context pk;
    if (!loadPrivateKey(&pk))
    {
      debugE("Cannot encrypt: Failed to load private key.");
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    int rc = mbedtls_pk_encrypt(&pk,
                                data, dataLen,
                                encryptedData, encryptedDataLen,
                                bufferSize,
                                mbedtls_ctr_drbg_random, &cryptoCtrDrbg);

    freeKey(&pk);
    if (!deinit())
    {
      debugW("Warning: Failed to deinitialize crypto system after encryption.");
    }

    if (rc != 0)
    {
      debugE("Failed to encrypt data.");
      debugE("mbedtls_pk_encrypt returned %d (-0x%x): %s",
                       rc, -rc, mbedtls_high_level_strerr(rc));
    }
#else
    debugW("Encryption not available in non-DEBUG builds.");
#endif
  }

  // ----------------------
  // encryptPublic() - Dynamically loads/frees public key
  // ----------------------
  void encryptPublic(unsigned char *data,
                     size_t dataLen,
                     unsigned char *encryptedData,
                     size_t bufferSize,
                     size_t *encryptedDataLen)
  {
    if (!init())
    {
      debugE("Cannot encrypt: Failed to initialize crypto system.");
      return;
    }

    mbedtls_pk_context pk;
    if (!loadPublicKey(&pk))
    {
      debugE("Cannot encrypt: Failed to load public key.");
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    int rc = mbedtls_pk_encrypt(&pk,
                                data, dataLen,
                                encryptedData, encryptedDataLen,
                                bufferSize,
                                mbedtls_ctr_drbg_random, &cryptoCtrDrbg);

    freeKey(&pk);
    if (!deinit())
    {
      debugW("Warning: Failed to deinitialize crypto system after encryption.");
    }

    if (rc != 0)
    {
      debugE("Failed to encrypt data.");
      debugE("mbedtls_pk_encrypt returned %d (-0x%x): %s",
                       rc, -rc, mbedtls_high_level_strerr(rc));
    }
  }

  // ----------------------
  // decrypt() - Dynamically loads/frees private key
  // ----------------------
  void decrypt(unsigned char *encryptedData,
               size_t encryptedDataLen,
               unsigned char *decryptedData,
               size_t bufferSize,
               size_t *decryptedDataLen)
  {
#ifdef INCLUDE_PRIVATE_KEYS
    if (!init())
    {
      debugE("Cannot decrypt: Failed to initialize crypto system.");
      return;
    }

    mbedtls_pk_context pk;
    if (!loadPrivateKey(&pk))
    {
      debugE("Cannot decrypt: Failed to load private key.");
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    int rc = mbedtls_pk_decrypt(&pk,
                                encryptedData, encryptedDataLen,
                                decryptedData, decryptedDataLen,
                                bufferSize,
                                mbedtls_ctr_drbg_random, &cryptoCtrDrbg);

    freeKey(&pk);
    if (!deinit())
    {
      debugW("Warning: Failed to deinitialize crypto system after decryption.");
    }

    if (rc != 0)
    {
      debugE("Failed to decrypt data.");
      debugE("mbedtls_pk_decrypt returned %d (-0x%x): %s",
                       rc, -rc, mbedtls_high_level_strerr(rc));
    }
#else
    debugW("Decryption not available in non-DEBUG builds.");
#endif
  }

  // ----------------------
  // sign() - Dynamically loads/frees private key
  // ----------------------
  void sign(const unsigned char *data,
            size_t dataLen,
            unsigned char *signature,
            size_t *signatureLen)
  {
#ifdef INCLUDE_PRIVATE_KEYS
    if (!init())
    {
      debugE("Cannot sign: Failed to initialize crypto system.");
      return;
    }

    mbedtls_pk_context pk;
    if (!loadPrivateKey(&pk))
    {
      debugE("Cannot sign: Failed to load private key.");
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    // Initialize a message digest context for SHA-256
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
    {
      debugE("Failed to get md info.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    if (mbedtls_md_setup(&md_ctx, md_info, 0) != 0)
    {
      debugE("Failed to setup md context.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }

    // Compute the hash of the data
    unsigned char hash[32] = {0};
    if (mbedtls_md(md_info, data, dataLen, hash) != 0)
    {
      debugE("Failed to compute hash.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return;
    }
    mbedtls_md_free(&md_ctx);

    int ret = mbedtls_pk_sign(&pk,
                              MBEDTLS_MD_SHA256,
                              hash, 0,
                              signature, signatureLen,
                              mbedtls_ctr_drbg_random, &cryptoCtrDrbg);

    freeKey(&pk);
    if (!deinit())
    {
      debugW("Warning: Failed to deinitialize crypto system after signing.");
    }

    if (ret != 0)
    {
      debugE("Failed to sign data: -0x%x", -ret);
    }
#else
    debugW("Signing not available in non-DEBUG builds.");
#endif
  }

  // ----------------------
  // verify() - Dynamically loads/frees public key
  // ----------------------
  bool verify(const unsigned char *data,
              size_t dataLen,
              const unsigned char *signature,
              size_t signatureLen)
  {
    if (!init())
    {
      debugE("Cannot verify: Failed to initialize crypto system.");
      return false;
    }

    mbedtls_pk_context pk;
    if (!loadPublicKey(&pk))
    {
      debugE("Cannot verify: Failed to load public key.");
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return false;
    }

    // Initialize a message digest context for SHA-256
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
    {
      debugE("Failed to get md info.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return false;
    }

    if (mbedtls_md_setup(&md_ctx, md_info, 0) != 0)
    {
      debugE("Failed to setup md context.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return false;
    }

    // Compute the hash of the data
    unsigned char hash[32] = {0};
    if (mbedtls_md(md_info, data, dataLen, hash) != 0)
    {
      debugE("Failed to compute hash.");
      mbedtls_md_free(&md_ctx);
      freeKey(&pk);
      if (!deinit())
      {
        debugW("Warning: Failed to deinitialize crypto system.");
      }
      return false;
    }
    mbedtls_md_free(&md_ctx);

    int ret = mbedtls_pk_verify(&pk,
                                MBEDTLS_MD_SHA256,
                                hash, 0,
                                signature, signatureLen);

    freeKey(&pk);
    if (!deinit())
    {
      debugW("Warning: Failed to deinitialize crypto system after verification.");
    }

    if (ret != 0)
    {
      debugE("Signature verification failed: -0x%x", ret);
      return false;
    }

    return true;
  }
}

