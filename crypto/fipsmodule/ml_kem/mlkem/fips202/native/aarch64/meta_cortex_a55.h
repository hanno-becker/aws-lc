/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLK_FIPS202_NATIVE_AARCH64_META_CORTEX_A55_H
#define MLK_FIPS202_NATIVE_AARCH64_META_CORTEX_A55_H
/* FIPS202 assembly profile targeting Cortex-A55 */

#ifdef MLK_FIPS202_NATIVE_PROFILE_H
#error Only one FIPS202 assembly profile can be defined -- did you include multiple profiles?
#else
#define MLK_FIPS202_NATIVE_PROFILE_H

/* Identifier for this backend so that source and assembly files
 * in the build can be appropriately guarded. */
#define MLK_FIPS202_BACKEND_AARCH64_A55

#define MLK_FIPS202_BACKEND_NAME AARCH64_A55

/* Filename of the C backend implementation.
 * This is not inlined here because this header is included in assembly
 * files as well. */
#define MLK_FIPS202_BACKEND_IMPL "native/aarch64/src/cortex_a55_impl.h"

#endif /* MLK_FIPS202_NATIVE_PROFILE_H */

#endif /* MLK_FIPS202_NATIVE_AARCH64_META_CORTEX_A55_H */
