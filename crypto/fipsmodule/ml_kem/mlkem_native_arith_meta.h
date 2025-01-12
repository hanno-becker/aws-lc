/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MLKEM_NATIVE_ARITH_BACKEND_META_H
#define MLKEM_NATIVE_ARITH_BACKEND_META_H

#include "mlkem/sys.h"

/* For now, use AArch64 backend only for Unix-like systems */
#if defined(MLK_SYS_AARCH64) && defined(MLK_SYS_UNIX_LIKE)
#include "mlkem/native/aarch64/meta.h"
#endif /* SYS_AARCH64 && SYS_UNIX */

#endif /* MLKEM_NATIVE_ARITH_BACKEND_META_H */
