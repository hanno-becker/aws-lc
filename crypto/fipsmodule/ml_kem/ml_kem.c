// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

/*
 * mlkem-native source code
 *
 * We include three copies of mlkem-native, one per security level.
 */

#define MLKEM_NATIVE_MULTILEVEL_BUILD

/* Include level-independent code */
#define MLKEM_NATIVE_MULTILEVEL_BUILD_WITH_SHARED
#define MLKEM_NATIVE_MONOBUILD_KEEP_SHARED_HEADERS

#define MLKEM_NATIVE_CONFIG_FILE "../config_512.h"
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE

/* Exclude level-independent code */
#undef MLKEM_NATIVE_MULTILEVEL_BUILD_WITH_SHARED
#define MLKEM_NATIVE_MULTILEVEL_BUILD_NO_SHARED

#define MLKEM_NATIVE_CONFIG_FILE "../config_1024.h"
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE

#define MLKEM_NATIVE_CONFIG_FILE "../config_768.h"
#undef MLKEM_NATIVE_MONOBUILD_KEEP_SHARED_HEADERS
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE

/* End of mlkem-native import */

#include "./ml_kem.h"
#include "openssl/rand.h"

void randombytes(uint8_t *out, size_t outlen)
{
    RAND_bytes(out, outlen);
}

int ml_kem_512_keypair_deterministic(uint8_t *public_key  /* OUT */,
                                         uint8_t *secret_key  /* OUT */,
                                         const uint8_t *seed  /* IN */) {
  return ml_kem_512_keypair_deterministic_no_self_test(public_key, secret_key, seed);
}

int ml_kem_512_keypair_deterministic_no_self_test(uint8_t *public_key  /* OUT */,
                                                  uint8_t *secret_key  /* OUT */,
                                                  const uint8_t *seed  /* IN */) {
  return mlkem512_keypair_derand(public_key, secret_key, seed);
}

int ml_kem_512_keypair(uint8_t *public_key /* OUT */,
                       uint8_t *secret_key /* OUT */) {
  return mlkem512_keypair(public_key, secret_key);
}

int ml_kem_512_encapsulate_deterministic(uint8_t *ciphertext       /* OUT */,
                                             uint8_t *shared_secret    /* OUT */,
                                             const uint8_t *public_key /* IN  */,
                                             const uint8_t *seed       /* IN */) {
  return mlkem512_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_512_encapsulate_deterministic_no_self_test(uint8_t *ciphertext       /* OUT */,
                                                      uint8_t *shared_secret    /* OUT */,
                                                      const uint8_t *public_key /* IN  */,
                                                      const uint8_t *seed       /* IN */) {
  return mlkem512_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_512_encapsulate(uint8_t *ciphertext       /* OUT */,
                               uint8_t *shared_secret    /* OUT */,
                               const uint8_t *public_key /* IN  */) {
  return mlkem512_enc(ciphertext, shared_secret, public_key);
}

int ml_kem_512_decapsulate(uint8_t *shared_secret    /* OUT */,
                               const uint8_t *ciphertext /* IN  */,
                               const uint8_t *secret_key /* IN  */) {
  return mlkem512_dec(shared_secret, ciphertext, secret_key);
}

int ml_kem_512_decapsulate_no_self_test(uint8_t *shared_secret    /* OUT */,
                                        const uint8_t *ciphertext /* IN  */,
                                        const uint8_t *secret_key /* IN  */) {
  return mlkem512_dec(shared_secret, ciphertext, secret_key);
}

int ml_kem_768_keypair_deterministic(uint8_t *public_key  /* OUT */,
                                         uint8_t *secret_key  /* OUT */,
                                         const uint8_t *seed  /* IN */) {
  return ml_kem_768_keypair_deterministic_no_self_test(public_key, secret_key, seed);
}

int ml_kem_768_keypair_deterministic_no_self_test(uint8_t *public_key  /* OUT */,
                                                  uint8_t *secret_key  /* OUT */,
                                                  const uint8_t *seed  /* IN */) {
  return mlkem768_keypair_derand(public_key, secret_key, seed);
}

int ml_kem_768_keypair(uint8_t *public_key /* OUT */,
                       uint8_t *secret_key /* OUT */) {
  return mlkem768_keypair(public_key, secret_key);
}

int ml_kem_768_encapsulate_deterministic(uint8_t *ciphertext       /* OUT */,
                                             uint8_t *shared_secret    /* OUT */,
                                             const uint8_t *public_key /* IN  */,
                                             const uint8_t *seed       /* IN */) {
  return mlkem768_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_768_encapsulate_deterministic_no_self_test(uint8_t *ciphertext       /* OUT */,
                                                      uint8_t *shared_secret    /* OUT */,
                                                      const uint8_t *public_key /* IN  */,
                                                      const uint8_t *seed       /* IN */) {
  return mlkem768_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_768_encapsulate(uint8_t *ciphertext       /* OUT */,
                               uint8_t *shared_secret    /* OUT */,
                               const uint8_t *public_key /* IN  */) {
  return mlkem768_enc(ciphertext, shared_secret, public_key);
}

int ml_kem_768_decapsulate(uint8_t *shared_secret    /* OUT */,
                               const uint8_t *ciphertext /* IN  */,
                               const uint8_t *secret_key /* IN  */) {
  return mlkem768_dec(shared_secret, ciphertext, secret_key);
}

int ml_kem_768_decapsulate_no_self_test(uint8_t *shared_secret    /* OUT */,
                                        const uint8_t *ciphertext /* IN  */,
                                        const uint8_t *secret_key /* IN  */) {
  return mlkem768_dec(shared_secret, ciphertext, secret_key);
}


int ml_kem_1024_keypair_deterministic(uint8_t *public_key  /* OUT */,
                                         uint8_t *secret_key  /* OUT */,
                                         const uint8_t *seed  /* IN */) {
  return ml_kem_1024_keypair_deterministic_no_self_test(public_key, secret_key, seed);
}

int ml_kem_1024_keypair_deterministic_no_self_test(uint8_t *public_key  /* OUT */,
                                                  uint8_t *secret_key  /* OUT */,
                                                  const uint8_t *seed  /* IN */) {
  return mlkem1024_keypair_derand(public_key, secret_key, seed);
}

int ml_kem_1024_keypair(uint8_t *public_key /* OUT */,
                       uint8_t *secret_key /* OUT */) {
  return mlkem1024_keypair(public_key, secret_key);
}

int ml_kem_1024_encapsulate_deterministic(uint8_t *ciphertext       /* OUT */,
                                             uint8_t *shared_secret    /* OUT */,
                                             const uint8_t *public_key /* IN  */,
                                             const uint8_t *seed       /* IN */) {
  return mlkem1024_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_1024_encapsulate_deterministic_no_self_test(uint8_t *ciphertext       /* OUT */,
                                                      uint8_t *shared_secret    /* OUT */,
                                                      const uint8_t *public_key /* IN  */,
                                                      const uint8_t *seed       /* IN */) {
  return mlkem1024_enc_derand(ciphertext, shared_secret, public_key, seed);
}

int ml_kem_1024_encapsulate(uint8_t *ciphertext       /* OUT */,
                               uint8_t *shared_secret    /* OUT */,
                               const uint8_t *public_key /* IN  */) {
  return mlkem1024_enc(ciphertext, shared_secret, public_key);
}

int ml_kem_1024_decapsulate(uint8_t *shared_secret    /* OUT */,
                               const uint8_t *ciphertext /* IN  */,
                               const uint8_t *secret_key /* IN  */) {
  return mlkem1024_dec(shared_secret, ciphertext, secret_key);
}

int ml_kem_1024_decapsulate_no_self_test(uint8_t *shared_secret    /* OUT */,
                                        const uint8_t *ciphertext /* IN  */,
                                        const uint8_t *secret_key /* IN  */) {
  return mlkem1024_dec(shared_secret, ciphertext, secret_key);
}
