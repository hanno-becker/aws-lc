/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLK_CONFIG_H
#define MLK_CONFIG_H

#if defined(__ASSEMBLER__)
/* No ASM functionality depends on MLKEM_K, so pick a default value.
 * Some ASM functions, however, are only needed for a specific MLKEM_K.
 * Set MLKEM_MULTILEVEL_BUILD_WITH_SHARED to force their inclusion in the
 * build. */
#define MLKEM_K 2
#define MLK_MULTILEVEL_BUILD_WITH_SHARED
#endif

/* Namespacing: All symbols are of the form mlkem*. Level-specific
 * symbols are further prefixed with their security level, e.g.
 * mlkem512*, mlkem768*, mlkem1024*. */
#define MLK_NAMESPACE_PREFIX mlkem
#define MLK_NAMESPACE_PREFIX_ADD_LEVEL

/* Register custom backend; for now, we only use the AArch64 arithmetic
 * and FIPS-202 backends on Unix-like systems. */
#define MLK_USE_NATIVE_BACKEND_ARITH
#define MLK_USE_NATIVE_BACKEND_FIPS202
#define MLK_ARITH_BACKEND_FILE "../mlkem_native_arith_meta.h"
#define MLK_FIPS202_BACKEND_FILE "../mlkem_native_fips202_meta.h"

#endif /* MLkEM_NATIVE_CONFIG_H */
