// Copyright (c) 2022, ARM Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// Author: Hanno Becker <hannobecker@posteo.de>
//
// This file was derived from the assembly generated from aesv8-gcm-armv8.pl,
// written by Fangming Fang <fangming.fang@arm.com> for the OpenSSL project,
// and derived from https://github.com/ARM-software/AArch64cryptolib, original
// author Samuel Lee <Samuel.Lee@arm.com>.
//
// The code below is a 'clean' AArch64 implementation of AES-GCM emphasizing
// the logic of the computation. It is meant as the input to manual audits /
// formal verification, as well as automated micro-optimization such as done
// by the SLOTHY superoptimizer (https://github.com/slothy-optimizer/slothy).

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#if __has_feature(memory_sanitizer) && !defined(OPENSSL_NO_ASM)
#define OPENSSL_NO_ASM
#endif

#include <openssl/asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(__AARCH64EL__)
#if defined(__ELF__)
#include <openssl/boringssl_prefix_symbols_asm.h>
#include <openssl/arm_arch.h>
.arch   armv8-a+crypto
.text
.globl  aes_gcm_dec_kernel_slothy_base_192
.hidden aes_gcm_dec_kernel_slothy_base_192
.type   aes_gcm_dec_kernel_slothy_base_192,%function
#elif defined(__APPLE__)
#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif
#include <openssl/arm_arch.h>
.text
.globl	_aes_gcm_dec_kernel_slothy_base_192
.private_extern	_aes_gcm_dec_kernel_slothy_base_192
#else
#error Unknown configuration
#endif

#if __ARM_MAX_ARCH__ >= 8

.align	4
_aes_gcm_dec_kernel_slothy_base_192:
aes_gcm_dec_kernel_slothy_base_192:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29, x30, [sp, #-128]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	mov	x16, x4
	mov	x8, x5
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	d8, d9, [sp, #64]
	stp	d10, d11, [sp, #80]
	stp	d12, d13, [sp, #96]
	stp	d14, d15, [sp, #112]
	ldr	w17, [x8, #240]
	add	x19, x8, x17, lsl #4                   // borrow input_l1 for last key
	ldp	x13, x14, [x19]                       // load round N keys
	ldr	q31, [x19, #-16]                        // load round N-1 keys
	lsr	x5, x1, #3              // byte_len
	mov	x15, x5
	ldp	x10, x11, [x16]              // ctr96_b64, ctr96_t32
	ldr	q26, [x8, #128]                                // load rk8
	sub	x5, x5, #1      // byte_len - 1
	ldr	q25, [x8, #112]                                // load rk7
	and	x5, x5, #0xffffffffffffffc0 // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
	add	x4, x0, x1, lsr #3   // end_input_ptr
	ldr	q24, [x8, #96]                                 // load rk6
	lsr	x12, x11, #32
	ldr	q23, [x8, #80]                                 // load rk5
	orr	w11, w11, w11
	ldr	q21, [x8, #48]                                 // load rk3
	add	x5, x5, x0
	rev	w12, w12                                // rev_ctr32
	add	w12, w12, #1                            // increment rev_ctr32
	fmov	d3, x10                               // CTR block 3
	rev	w9, w12                                 // CTR block 1
	add	w12, w12, #1                            // CTR block 1
	fmov	d1, x10                               // CTR block 1
	orr	x9, x11, x9, lsl #32            // CTR block 1
	ld1	{ v0.16b}, [x16]                             // special case vector load initial counter so we can start first AES block as quickly as possible
	fmov	v1.d[1], x9                               // CTR block 1
	rev	w9, w12                                 // CTR block 2
	add	w12, w12, #1                            // CTR block 2
	fmov	d2, x10                               // CTR block 2
	orr	x9, x11, x9, lsl #32            // CTR block 2
	fmov	v2.d[1], x9                               // CTR block 2
	rev	w9, w12                                 // CTR block 3
	orr	x9, x11, x9, lsl #32            // CTR block 3
	ldr	q18, [x8, #0]                                  // load rk0
	fmov	v3.d[1], x9                               // CTR block 3
	add	w12, w12, #1                            // CTR block 3
	ldr	q22, [x8, #64]                                 // load rk4
	ldr	q19, [x8, #16]                                 // load rk1
	aese	v0.16b, v18.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 0
	ldr	q14, [x6, #48]                              // load h3l | h3h
	aese	v3.16b, v18.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 0
	ldr	q15, [x6, #80]                              // load h4l | h4h
	aese	v1.16b, v18.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 0
	ldr	q13, [x6, #32]                              // load h2l | h2h
	aese	v2.16b, v18.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 0
	ldr	q20, [x8, #32]                                 // load rk2
	aese	v0.16b, v19.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 1
	aese	v1.16b, v19.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 1
	ld1	{ v11.16b}, [x3]
	ext	v11.16b, v11.16b, v11.16b, #8
	rev64	v11.16b, v11.16b
	aese	v2.16b, v19.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 1
	ldr	q27, [x8, #144]                                // load rk9
	aese	v3.16b, v19.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 1
	ldr	q30, [x8, #192]                               // load rk12
	aese	v0.16b, v20.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 2
	ldr	q12, [x6]                                   // load h1l | h1h
	aese	v2.16b, v20.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 2
	ldr	q28, [x8, #160]                               // load rk10
	aese	v3.16b, v20.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 2
	aese	v0.16b, v21.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 3
	aese	v1.16b, v20.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 2
	aese	v3.16b, v21.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 3
	aese	v0.16b, v22.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 4
	aese	v2.16b, v21.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 3
	aese	v1.16b, v21.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 3
	aese	v3.16b, v22.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 4
	aese	v2.16b, v22.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 4
	aese	v1.16b, v22.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 4
	aese	v3.16b, v23.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 5
	aese	v0.16b, v23.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 5
	aese	v1.16b, v23.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 5
	aese	v2.16b, v23.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 5
	aese	v0.16b, v24.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 6
	aese	v3.16b, v24.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 6
	cmp	x17, #12                                      // setup flags for AES-128/192/256 check
	aese	v1.16b, v24.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 6
	aese	v2.16b, v24.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 6
	aese	v0.16b, v25.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 7
	aese	v1.16b, v25.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 7
	aese	v3.16b, v25.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 7
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 8
	aese	v2.16b, v25.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 7
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 8
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 8
	ldr	q29, [x8, #176]                               // load rk11
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 8
	b.lt	Ldec_finish_first_blocks                         // branch if AES-128

	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 9
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 9
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 9
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 9
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 10
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 10
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 10
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 10
	b.eq	Ldec_finish_first_blocks                         // branch if AES-192

	aese	v0.16b, v29.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 11
	aese	v3.16b, v29.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 11
	aese	v1.16b, v29.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 11
	aese	v2.16b, v29.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 11
	aese	v1.16b, v30.16b
	aesmc	v1.16b, v1.16b          // AES block 1 - round 12
	aese	v0.16b, v30.16b
	aesmc	v0.16b, v0.16b          // AES block 0 - round 12
	aese	v2.16b, v30.16b
	aesmc	v2.16b, v2.16b          // AES block 2 - round 12
	aese	v3.16b, v30.16b
	aesmc	v3.16b, v3.16b          // AES block 3 - round 12

Ldec_finish_first_blocks:
	cmp	x0, x5                   // check if we have <= 4 blocks
	ldr	q16, [x6, #16]				  // load h2k | h1k
	ldr	q17, [x6, #64]				  // load h4k | h3k
	aese	v1.16b, v31.16b                                    // AES block 1 - round N-1
	aese	v2.16b, v31.16b                                    // AES block 2 - round N-1
	aese	v3.16b, v31.16b                                    // AES block 3 - round N-1
	aese	v0.16b, v31.16b                                    // AES block 0 - round N-1
	b.ge	Ldec_tail                                        // handle tail

	ldr	q4, [x0, #0]                          // AES block 0 - load ciphertext
	ldr	q5, [x0, #16]                         // AES block 1 - load ciphertext
	rev	w9, w12                                 // CTR block 4
	eor	v0.16b, v4.16b, v0.16b                            // AES block 0 - result
	eor	v1.16b, v5.16b, v1.16b                            // AES block 1 - result
	rev64	v5.16b, v5.16b                                    // GHASH block 1
	ldr	q7, [x0, #48]                         // AES block 3 - load ciphertext
	mov	x7, v0.d[1]                            // AES block 0 - mov high
	mov	x6, v0.d[0]                            // AES block 0 - mov low
	rev64	v4.16b, v4.16b                                    // GHASH block 0
	add	w12, w12, #1                            // CTR block 4
	fmov	d0, x10                               // CTR block 4
	orr	x9, x11, x9, lsl #32            // CTR block 4
	fmov	v0.d[1], x9                               // CTR block 4
	rev	w9, w12                                 // CTR block 5
	add	w12, w12, #1                            // CTR block 5
	mov	x19, v1.d[0]                            // AES block 1 - mov low
	orr	x9, x11, x9, lsl #32            // CTR block 5
	mov	x20, v1.d[1]                            // AES block 1 - mov high
	eor	x7, x7, x14                    // AES block 0 - round N high
	eor	x6, x6, x13                    // AES block 0 - round N low
	stp	x6, x7, [x2], #16        // AES block 0 - store result
	fmov	d1, x10                               // CTR block 5
	ldr	q6, [x0, #32]                         // AES block 2 - load ciphertext
	add	x0, x0, #64                       // AES input_ptr update
	fmov	v1.d[1], x9                               // CTR block 5
	rev	w9, w12                                 // CTR block 6
	add	w12, w12, #1                            // CTR block 6
	eor	x19, x19, x13                    // AES block 1 - round N low
	orr	x9, x11, x9, lsl #32            // CTR block 6
	eor	x20, x20, x14                    // AES block 1 - round N high
	stp	x19, x20, [x2], #16        // AES block 1 - store result
	eor	v2.16b, v6.16b, v2.16b                            // AES block 2 - result
	cmp	x0, x5                   // check if we have <= 8 blocks
	b.ge	Ldec_prepretail                                  // do prepretail

Ldec_main_loop:	//	main loop start
	mov	x21, v2.d[0]                            // AES block 4k+2 - mov low
	ext	v11.16b, v11.16b, v11.16b, #8                     // PRE 0
	eor	v3.16b, v7.16b, v3.16b                            // AES block 4k+3 - result
	aese	v0.16b, v18.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 0
	mov	x22, v2.d[1]                            // AES block 4k+2 - mov high
	aese	v1.16b, v18.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 0
	fmov	d2, x10                               // CTR block 4k+6
	fmov	v2.d[1], x9                               // CTR block 4k+6
	eor	v4.16b, v4.16b, v11.16b                           // PRE 1
	rev	w9, w12                                 // CTR block 4k+7
	aese	v0.16b, v19.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 1
	mov	x24, v3.d[1]                            // AES block 4k+3 - mov high
	aese	v1.16b, v19.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 1
	mov	x23, v3.d[0]                            // AES block 4k+3 - mov low
	pmull2	v9.1q, v4.2d, v15.2d                       // GHASH block 4k - high
	mov	d8, v4.d[1]                                  // GHASH block 4k - mid
	fmov	d3, x10                               // CTR block 4k+7
	aese	v0.16b, v20.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 2
	orr	x9, x11, x9, lsl #32            // CTR block 4k+7
	aese	v2.16b, v18.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 0
	fmov	v3.d[1], x9                               // CTR block 4k+7
	aese	v1.16b, v20.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 2
	eor	v8.8b, v8.8b, v4.8b                          // GHASH block 4k - mid
	aese	v0.16b, v21.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 3
	eor	x22, x22, x14                    // AES block 4k+2 - round N high
	aese	v2.16b, v19.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 1
	mov	d10, v17.d[1]                               // GHASH block 4k - mid
	aese	v1.16b, v21.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 3
	rev64	v6.16b, v6.16b                                    // GHASH block 4k+2
	aese	v3.16b, v18.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 0
	eor	x21, x21, x13                    // AES block 4k+2 - round N low
	aese	v2.16b, v20.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 2
	stp	x21, x22, [x2], #16        // AES block 4k+2 - store result
	pmull	v11.1q, v4.1d, v15.1d                       // GHASH block 4k - low
	pmull2	v4.1q, v5.2d, v14.2d                          // GHASH block 4k+1 - high
	aese	v2.16b, v21.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 3
	rev64	v7.16b, v7.16b                                    // GHASH block 4k+3
	pmull	v10.1q, v8.1d, v10.1d                      // GHASH block 4k - mid
	eor	x23, x23, x13                    // AES block 4k+3 - round N low
	pmull	v8.1q, v5.1d, v14.1d                          // GHASH block 4k+1 - low
	eor	x24, x24, x14                    // AES block 4k+3 - round N high
	eor	v9.16b, v9.16b, v4.16b                         // GHASH block 4k+1 - high
	aese	v2.16b, v22.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 4
	aese	v3.16b, v19.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 1
	mov	d4, v5.d[1]                                  // GHASH block 4k+1 - mid
	aese	v0.16b, v22.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 4
	eor	v11.16b, v11.16b, v8.16b                         // GHASH block 4k+1 - low
	aese	v2.16b, v23.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 5
	add	w12, w12, #1                            // CTR block 4k+7
	aese	v3.16b, v20.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 2
	mov	d8, v6.d[1]                                  // GHASH block 4k+2 - mid
	aese	v1.16b, v22.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 4
	eor	v4.8b, v4.8b, v5.8b                          // GHASH block 4k+1 - mid
	pmull	v5.1q, v6.1d, v13.1d                          // GHASH block 4k+2 - low
	aese	v3.16b, v21.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 3
	eor	v8.8b, v8.8b, v6.8b                          // GHASH block 4k+2 - mid
	aese	v1.16b, v23.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 5
	aese	v0.16b, v23.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 5
	eor	v11.16b, v11.16b, v5.16b                         // GHASH block 4k+2 - low
	pmull	v4.1q, v4.1d, v17.1d                          // GHASH block 4k+1 - mid
	rev	w9, w12                                 // CTR block 4k+8
	aese	v1.16b, v24.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 6
	ins	v8.d[1], v8.d[0]                                // GHASH block 4k+2 - mid
	aese	v0.16b, v24.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 6
	add	w12, w12, #1                            // CTR block 4k+8
	aese	v3.16b, v22.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 4
	aese	v1.16b, v25.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 7
	eor	v10.16b, v10.16b, v4.16b                         // GHASH block 4k+1 - mid
	aese	v0.16b, v25.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 7
	pmull2	v4.1q, v6.2d, v13.2d                          // GHASH block 4k+2 - high
	mov	d6, v7.d[1]                                  // GHASH block 4k+3 - mid
	aese	v3.16b, v23.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 5
	pmull2	v8.1q, v8.2d, v16.2d                          // GHASH block 4k+2 - mid
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 8
	eor	v9.16b, v9.16b, v4.16b                         // GHASH block 4k+2 - high
	aese	v3.16b, v24.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 6
	pmull	v4.1q, v7.1d, v12.1d                          // GHASH block 4k+3 - low
	orr	x9, x11, x9, lsl #32            // CTR block 4k+8
	eor	v10.16b, v10.16b, v8.16b                         // GHASH block 4k+2 - mid
	pmull2	v5.1q, v7.2d, v12.2d                          // GHASH block 4k+3 - high
	cmp	x17, #12                                      // setup flags for AES-128/192/256 check
	eor	v6.8b, v6.8b, v7.8b                          // GHASH block 4k+3 - mid
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 8
	aese	v2.16b, v24.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 6
	eor	v9.16b, v9.16b, v5.16b                         // GHASH block 4k+3 - high
	pmull	v6.1q, v6.1d, v16.1d                          // GHASH block 4k+3 - mid
	movi	v8.8b, #0xc2
	aese	v2.16b, v25.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 7
	eor	v11.16b, v11.16b, v4.16b                         // GHASH block 4k+3 - low
	aese	v3.16b, v25.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 7
	shl	d8, d8, #56               // mod_constant
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 8
	eor	v10.16b, v10.16b, v6.16b                         // GHASH block 4k+3 - mid
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 8
	b.lt	Ldec_main_loop_continue                          // branch if AES-128

	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 9
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 9
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 9
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 9
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 10
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 10
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 10
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 10
	b.eq	Ldec_main_loop_continue                          // branch if AES-192

	aese	v0.16b, v29.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 11
	aese	v1.16b, v29.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 11
	aese	v2.16b, v29.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 11
	aese	v3.16b, v29.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 11
	aese	v0.16b, v30.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 12
	aese	v1.16b, v30.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 12
	aese	v2.16b, v30.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 12
	aese	v3.16b, v30.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 12

Ldec_main_loop_continue:
	pmull	v7.1q, v9.1d, v8.1d            // MODULO - top 64b align with mid
	eor	v6.16b, v11.16b, v9.16b                         // MODULO - karatsuba tidy up
	ldr	q4, [x0, #0]                          // AES block 4k+4 - load ciphertext
	aese	v0.16b, v31.16b                                    // AES block 4k+4 - round N-1
	ext	v9.16b, v9.16b, v9.16b, #8                     // MODULO - other top alignment
	eor	v10.16b, v10.16b, v6.16b                         // MODULO - karatsuba tidy up
	ldr	q5, [x0, #16]                         // AES block 4k+5 - load ciphertext
	eor	v0.16b, v4.16b, v0.16b                            // AES block 4k+4 - result
	stp	x23, x24, [x2], #16        // AES block 4k+3 - store result
	eor	v10.16b, v10.16b, v7.16b                      // MODULO - fold into mid
	ldr	q7, [x0, #48]                         // AES block 4k+7 - load ciphertext
	ldr	q6, [x0, #32]                         // AES block 4k+6 - load ciphertext
	mov	x7, v0.d[1]                            // AES block 4k+4 - mov high
	eor	v10.16b, v10.16b, v9.16b                         // MODULO - fold into mid
	aese	v1.16b, v31.16b                                    // AES block 4k+5 - round N-1
	add	x0, x0, #64                       // AES input_ptr update
	mov	x6, v0.d[0]                            // AES block 4k+4 - mov low
	fmov	d0, x10                               // CTR block 4k+8
	fmov	v0.d[1], x9                               // CTR block 4k+8
	pmull	v8.1q, v10.1d, v8.1d     // MODULO - mid 64b align with low
	eor	v1.16b, v5.16b, v1.16b                            // AES block 4k+5 - result
	rev	w9, w12                                 // CTR block 4k+9
	aese	v2.16b, v31.16b                                    // AES block 4k+6 - round N-1
	orr	x9, x11, x9, lsl #32            // CTR block 4k+9
	cmp	x0, x5                   // LOOP CONTROL
	add	w12, w12, #1                            // CTR block 4k+9
	eor	x6, x6, x13                    // AES block 4k+4 - round N low
	eor	x7, x7, x14                    // AES block 4k+4 - round N high
	mov	x20, v1.d[1]                            // AES block 4k+5 - mov high
	eor	v2.16b, v6.16b, v2.16b                            // AES block 4k+6 - result
	eor	v11.16b, v11.16b, v8.16b               // MODULO - fold into low
	mov	x19, v1.d[0]                            // AES block 4k+5 - mov low
	fmov	d1, x10                               // CTR block 4k+9
	ext	v10.16b, v10.16b, v10.16b, #8                     // MODULO - other mid alignment
	fmov	v1.d[1], x9                               // CTR block 4k+9
	rev	w9, w12                                 // CTR block 4k+10
	add	w12, w12, #1                            // CTR block 4k+10
	aese	v3.16b, v31.16b                                    // AES block 4k+7 - round N-1
	orr	x9, x11, x9, lsl #32            // CTR block 4k+10
	rev64	v5.16b, v5.16b                                    // GHASH block 4k+5
	eor	x20, x20, x14                    // AES block 4k+5 - round N high
	stp	x6, x7, [x2], #16        // AES block 4k+4 - store result
	eor	x19, x19, x13                    // AES block 4k+5 - round N low
	stp	x19, x20, [x2], #16        // AES block 4k+5 - store result
	rev64	v4.16b, v4.16b                                    // GHASH block 4k+4
	eor	v11.16b, v11.16b, v10.16b                         // MODULO - fold into low
	b.lt	Ldec_main_loop

Ldec_prepretail:	//	PREPRETAIL
	ext	v11.16b, v11.16b, v11.16b, #8                     // PRE 0
	mov	x21, v2.d[0]                            // AES block 4k+2 - mov low
	eor	v3.16b, v7.16b, v3.16b                            // AES block 4k+3 - result
	aese	v0.16b, v18.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 0
	mov	x22, v2.d[1]                            // AES block 4k+2 - mov high
	aese	v1.16b, v18.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 0
	fmov	d2, x10                               // CTR block 4k+6
	fmov	v2.d[1], x9                               // CTR block 4k+6
	rev	w9, w12                                 // CTR block 4k+7
	eor	v4.16b, v4.16b, v11.16b                           // PRE 1
	rev64	v6.16b, v6.16b                                    // GHASH block 4k+2
	orr	x9, x11, x9, lsl #32            // CTR block 4k+7
	mov	x23, v3.d[0]                            // AES block 4k+3 - mov low
	aese	v1.16b, v19.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 1
	mov	x24, v3.d[1]                            // AES block 4k+3 - mov high
	pmull	v11.1q, v4.1d, v15.1d                       // GHASH block 4k - low
	mov	d8, v4.d[1]                                  // GHASH block 4k - mid
	fmov	d3, x10                               // CTR block 4k+7
	pmull2	v9.1q, v4.2d, v15.2d                       // GHASH block 4k - high
	fmov	v3.d[1], x9                               // CTR block 4k+7
	aese	v2.16b, v18.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 0
	mov	d10, v17.d[1]                               // GHASH block 4k - mid
	aese	v0.16b, v19.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 1
	eor	v8.8b, v8.8b, v4.8b                          // GHASH block 4k - mid
	pmull2	v4.1q, v5.2d, v14.2d                          // GHASH block 4k+1 - high
	aese	v2.16b, v19.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 1
	rev64	v7.16b, v7.16b                                    // GHASH block 4k+3
	aese	v3.16b, v18.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 0
	pmull	v10.1q, v8.1d, v10.1d                      // GHASH block 4k - mid
	eor	v9.16b, v9.16b, v4.16b                         // GHASH block 4k+1 - high
	pmull	v8.1q, v5.1d, v14.1d                          // GHASH block 4k+1 - low
	aese	v3.16b, v19.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 1
	mov	d4, v5.d[1]                                  // GHASH block 4k+1 - mid
	aese	v0.16b, v20.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 2
	aese	v1.16b, v20.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 2
	eor	v11.16b, v11.16b, v8.16b                         // GHASH block 4k+1 - low
	aese	v2.16b, v20.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 2
	aese	v0.16b, v21.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 3
	mov	d8, v6.d[1]                                  // GHASH block 4k+2 - mid
	aese	v3.16b, v20.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 2
	eor	v4.8b, v4.8b, v5.8b                          // GHASH block 4k+1 - mid
	pmull	v5.1q, v6.1d, v13.1d                          // GHASH block 4k+2 - low
	aese	v0.16b, v22.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 4
	aese	v3.16b, v21.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 3
	eor	v8.8b, v8.8b, v6.8b                          // GHASH block 4k+2 - mid
	pmull	v4.1q, v4.1d, v17.1d                          // GHASH block 4k+1 - mid
	aese	v0.16b, v23.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 5
	eor	v11.16b, v11.16b, v5.16b                         // GHASH block 4k+2 - low
	aese	v3.16b, v22.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 4
	pmull2	v5.1q, v7.2d, v12.2d                          // GHASH block 4k+3 - high
	eor	v10.16b, v10.16b, v4.16b                         // GHASH block 4k+1 - mid
	pmull2	v4.1q, v6.2d, v13.2d                          // GHASH block 4k+2 - high
	aese	v3.16b, v23.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 5
	ins	v8.d[1], v8.d[0]                                // GHASH block 4k+2 - mid
	aese	v2.16b, v21.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 3
	aese	v1.16b, v21.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 3
	eor	v9.16b, v9.16b, v4.16b                         // GHASH block 4k+2 - high
	pmull	v4.1q, v7.1d, v12.1d                          // GHASH block 4k+3 - low
	aese	v2.16b, v22.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 4
	mov	d6, v7.d[1]                                  // GHASH block 4k+3 - mid
	aese	v1.16b, v22.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 4
	pmull2	v8.1q, v8.2d, v16.2d                          // GHASH block 4k+2 - mid
	aese	v2.16b, v23.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 5
	eor	v6.8b, v6.8b, v7.8b                          // GHASH block 4k+3 - mid
	aese	v1.16b, v23.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 5
	aese	v3.16b, v24.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 6
	eor	v10.16b, v10.16b, v8.16b                         // GHASH block 4k+2 - mid
	aese	v2.16b, v24.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 6
	aese	v0.16b, v24.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 6
	movi	v8.8b, #0xc2
	aese	v1.16b, v24.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 6
	eor	v11.16b, v11.16b, v4.16b                         // GHASH block 4k+3 - low
	pmull	v6.1q, v6.1d, v16.1d                          // GHASH block 4k+3 - mid
	aese	v3.16b, v25.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 7
	cmp	x17, #12                                      // setup flags for AES-128/192/256 check
	eor	v9.16b, v9.16b, v5.16b                         // GHASH block 4k+3 - high
	aese	v1.16b, v25.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 7
	aese	v0.16b, v25.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 7
	eor	v10.16b, v10.16b, v6.16b                         // GHASH block 4k+3 - mid
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 8
	aese	v2.16b, v25.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 7
	eor	v6.16b, v11.16b, v9.16b                         // MODULO - karatsuba tidy up
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 8
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 8
	shl	d8, d8, #56               // mod_constant
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 8
	b.lt	Ldec_finish_prepretail                           // branch if AES-128

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 9
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 9
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 9
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 9
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 10
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 10
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 10
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 10
	b.eq	Ldec_finish_prepretail                           // branch if AES-192

	aese	v2.16b, v29.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 11
	aese	v0.16b, v29.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 11
	aese	v1.16b, v29.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 11
	aese	v2.16b, v30.16b
	aesmc	v2.16b, v2.16b          // AES block 4k+6 - round 12
	aese	v3.16b, v29.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 11
	aese	v1.16b, v30.16b
	aesmc	v1.16b, v1.16b          // AES block 4k+5 - round 12
	aese	v0.16b, v30.16b
	aesmc	v0.16b, v0.16b          // AES block 4k+4 - round 12
	aese	v3.16b, v30.16b
	aesmc	v3.16b, v3.16b          // AES block 4k+7 - round 12

Ldec_finish_prepretail:
	eor	v10.16b, v10.16b, v6.16b                         // MODULO - karatsuba tidy up
	pmull	v7.1q, v9.1d, v8.1d            // MODULO - top 64b align with mid
	ext	v9.16b, v9.16b, v9.16b, #8                     // MODULO - other top alignment
	eor	v10.16b, v10.16b, v7.16b                      // MODULO - fold into mid
	eor	x22, x22, x14                    // AES block 4k+2 - round N high
	eor	x23, x23, x13                    // AES block 4k+3 - round N low
	eor	v10.16b, v10.16b, v9.16b                         // MODULO - fold into mid
	add	w12, w12, #1                            // CTR block 4k+7
	eor	x21, x21, x13                    // AES block 4k+2 - round N low
	pmull	v8.1q, v10.1d, v8.1d     // MODULO - mid 64b align with low
	eor	x24, x24, x14                    // AES block 4k+3 - round N high
	stp	x21, x22, [x2], #16        // AES block 4k+2 - store result
	ext	v10.16b, v10.16b, v10.16b, #8                     // MODULO - other mid alignment
	stp	x23, x24, [x2], #16        // AES block 4k+3 - store result

	eor	v11.16b, v11.16b, v8.16b               // MODULO - fold into low
	aese	v1.16b, v31.16b                                    // AES block 4k+5 - round N-1
	aese	v0.16b, v31.16b                                    // AES block 4k+4 - round N-1
	aese	v3.16b, v31.16b                                    // AES block 4k+7 - round N-1
	aese	v2.16b, v31.16b                                    // AES block 4k+6 - round N-1
	eor	v11.16b, v11.16b, v10.16b                         // MODULO - fold into low

Ldec_tail:	//	TAIL
	sub	x5, x4, x0   // main_end_input_ptr is number of bytes left to process
	ld1	{ v5.16b}, [x0], #16                      // AES block 4k+4 - load ciphertext
	eor	v0.16b, v5.16b, v0.16b                            // AES block 4k+4 - result
	mov	x6, v0.d[0]                            // AES block 4k+4 - mov low
	mov	x7, v0.d[1]                            // AES block 4k+4 - mov high
	ext	v8.16b, v11.16b, v11.16b, #8                     // prepare final partial tag
	cmp	x5, #48
	eor	x6, x6, x13                    // AES block 4k+4 - round N low
	eor	x7, x7, x14                    // AES block 4k+4 - round N high
	b.gt	Ldec_blocks_more_than_3
	sub	w12, w12, #1
	mov	v3.16b, v2.16b
	movi	v10.8b, #0
	movi	v11.8b, #0
	cmp	x5, #32
	movi	v9.8b, #0
	mov	v2.16b, v1.16b
	b.gt	Ldec_blocks_more_than_2
	sub	w12, w12, #1
	mov	v3.16b, v1.16b
	cmp	x5, #16
	b.gt	Ldec_blocks_more_than_1
	sub	w12, w12, #1
	b	Ldec_blocks_less_than_1
Ldec_blocks_more_than_3:	//	blocks left >  3
	rev64	v4.16b, v5.16b                                   // GHASH final-3 block
	ld1	{ v5.16b}, [x0], #16                     // AES final-2 block - load ciphertext
	stp	x6, x7, [x2], #16       // AES final-3 block  - store result
	mov	d10, v17.d[1]                              // GHASH final-3 block - mid
	eor	v4.16b, v4.16b, v8.16b                          // feed in partial tag
	eor	v0.16b, v5.16b, v1.16b                           // AES final-2 block - result
	mov	d22, v4.d[1]                                // GHASH final-3 block - mid
	mov	x6, v0.d[0]                           // AES final-2 block - mov low
	mov	x7, v0.d[1]                           // AES final-2 block - mov high
	eor	v22.8b, v22.8b, v4.8b                     // GHASH final-3 block - mid
	movi	v8.8b, #0                                       // suppress further partial tag feed in
	pmull2	v9.1q, v4.2d, v15.2d                      // GHASH final-3 block - high
	pmull	v10.1q, v22.1d, v10.1d                   // GHASH final-3 block - mid
	eor	x6, x6, x13                   // AES final-2 block - round N low
	pmull	v11.1q, v4.1d, v15.1d                      // GHASH final-3 block - low
	eor	x7, x7, x14                   // AES final-2 block - round N high
Ldec_blocks_more_than_2:	//	blocks left >  2
	rev64	v4.16b, v5.16b                                   // GHASH final-2 block
	ld1	{ v5.16b}, [x0], #16                     // AES final-1 block - load ciphertext
	eor	v4.16b, v4.16b, v8.16b                          // feed in partial tag
	stp	x6, x7, [x2], #16       // AES final-2 block  - store result
	eor	v0.16b, v5.16b, v2.16b                           // AES final-1 block - result
	mov	d22, v4.d[1]                                // GHASH final-2 block - mid
	pmull	v21.1q, v4.1d, v14.1d                         // GHASH final-2 block - low
	pmull2	v20.1q, v4.2d, v14.2d                         // GHASH final-2 block - high
	eor	v22.8b, v22.8b, v4.8b                     // GHASH final-2 block - mid
	mov	x6, v0.d[0]                           // AES final-1 block - mov low
	mov	x7, v0.d[1]                           // AES final-1 block - mov high
	eor	v11.16b, v11.16b, v21.16b                           // GHASH final-2 block - low
	movi	v8.8b, #0                                       // suppress further partial tag feed in
	pmull	v22.1q, v22.1d, v17.1d                     // GHASH final-2 block - mid
	eor	v9.16b, v9.16b, v20.16b                           // GHASH final-2 block - high
	eor	x6, x6, x13                   // AES final-1 block - round N low
	eor	v10.16b, v10.16b, v22.16b                      // GHASH final-2 block - mid
	eor	x7, x7, x14                   // AES final-1 block - round N high
Ldec_blocks_more_than_1:	//	blocks left >  1
	stp	x6, x7, [x2], #16       // AES final-1 block  - store result
	rev64	v4.16b, v5.16b                                   // GHASH final-1 block
	ld1	{ v5.16b}, [x0], #16                     // AES final block - load ciphertext
	eor	v4.16b, v4.16b, v8.16b                          // feed in partial tag
	movi	v8.8b, #0                                       // suppress further partial tag feed in
	mov	d22, v4.d[1]                                // GHASH final-1 block - mid
	eor	v0.16b, v5.16b, v3.16b                           // AES final block - result
	pmull2	v20.1q, v4.2d, v13.2d                         // GHASH final-1 block - high
	eor	v22.8b, v22.8b, v4.8b                     // GHASH final-1 block - mid
	pmull	v21.1q, v4.1d, v13.1d                         // GHASH final-1 block - low
	mov	x6, v0.d[0]                           // AES final block - mov low
	ins	v22.d[1], v22.d[0]                           // GHASH final-1 block - mid
	mov	x7, v0.d[1]                           // AES final block - mov high
	pmull2	v22.1q, v22.2d, v16.2d                     // GHASH final-1 block - mid
	eor	x6, x6, x13                   // AES final block - round N low
	eor	v11.16b, v11.16b, v21.16b                           // GHASH final-1 block - low
	eor	v9.16b, v9.16b, v20.16b                           // GHASH final-1 block - high
	eor	v10.16b, v10.16b, v22.16b                      // GHASH final-1 block - mid
	eor	x7, x7, x14                   // AES final block - round N high
Ldec_blocks_less_than_1:	//	blocks left <= 1
	and	x1, x1, #127                   // bit_length %= 128
	mvn	x14, xzr                                      // rkN_h = 0xffffffffffffffff
	sub	x1, x1, #128                   // bit_length -= 128
	mvn	x13, xzr                                      // rkN_l = 0xffffffffffffffff
	ldp	x4, x5, [x2] // load existing bytes we need to not overwrite
	neg	x1, x1                         // bit_length = 128 - #bits in input (in range [1,128])
	and	x1, x1, #127                   // bit_length %= 128
	lsr	x14, x14, x1                      // rkN_h is mask for top 64b of last block
	cmp	x1, #64
	csel	x9, x13, x14, lt
	csel	x10, x14, xzr, lt
	fmov	d0, x9                                  // ctr0b is mask for last block
	and	x6, x6, x9
	mov	v0.d[1], x10
	bic	x4, x4, x9          // mask out low existing bytes
	rev	w9, w12
	bic	x5, x5, x10      // mask out high existing bytes
	orr	x6, x6, x4
	and	x7, x7, x10
	orr	x7, x7, x5
	and	v5.16b, v5.16b, v0.16b                            // possibly partial last block has zeroes in highest bits
	rev64	v4.16b, v5.16b                                    // GHASH final block
	eor	v4.16b, v4.16b, v8.16b                           // feed in partial tag
	pmull	v21.1q, v4.1d, v12.1d                          // GHASH final block - low
	mov	d8, v4.d[1]                                  // GHASH final block - mid
	eor	v8.8b, v8.8b, v4.8b                          // GHASH final block - mid
	pmull2	v20.1q, v4.2d, v12.2d                          // GHASH final block - high
	pmull	v8.1q, v8.1d, v16.1d                          // GHASH final block - mid
	eor	v9.16b, v9.16b, v20.16b                            // GHASH final block - high
	eor	v11.16b, v11.16b, v21.16b                            // GHASH final block - low
	eor	v10.16b, v10.16b, v8.16b                         // GHASH final block - mid
	movi	v8.8b, #0xc2
	eor	v6.16b, v11.16b, v9.16b                         // MODULO - karatsuba tidy up
	shl	d8, d8, #56               // mod_constant
	eor	v10.16b, v10.16b, v6.16b                         // MODULO - karatsuba tidy up
	pmull	v7.1q, v9.1d, v8.1d            // MODULO - top 64b align with mid
	ext	v9.16b, v9.16b, v9.16b, #8                     // MODULO - other top alignment
	eor	v10.16b, v10.16b, v7.16b                      // MODULO - fold into mid
	eor	v10.16b, v10.16b, v9.16b                         // MODULO - fold into mid
	pmull	v8.1q, v10.1d, v8.1d     // MODULO - mid 64b align with low
	ext	v10.16b, v10.16b, v10.16b, #8                     // MODULO - other mid alignment
	eor	v11.16b, v11.16b, v8.16b               // MODULO - fold into low
	stp	x6, x7, [x2]
	str	w9, [x16, #12]                          // store the updated counter
	eor	v11.16b, v11.16b, v10.16b                         // MODULO - fold into low
	ext	v11.16b, v11.16b, v11.16b, #8
	rev64	v11.16b, v11.16b
	mov	x0, x15
	st1	{ v11.16b }, [x3]
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	d8, d9, [sp, #64]
	ldp	d10, d11, [sp, #80]
	ldp	d12, d13, [sp, #96]
	ldp	d14, d15, [sp, #112]
	ldp	x29, x30, [sp], #128
	AARCH64_VALIDATE_LINK_REGISTER
	ret

#endif
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__APPLE__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
