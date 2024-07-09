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
.globl  aes_gcm_enc_kernel_slothy_base_128
.hidden aes_gcm_enc_kernel_slothy_base_128
.type   aes_gcm_enc_kernel_slothy_base_128,%function
#elif defined(__APPLE__)
#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif
#include <openssl/arm_arch.h>
.text
.globl	_aes_gcm_enc_kernel_slothy_base_128
.private_extern	_aes_gcm_enc_kernel_slothy_base_128
#else
#error Unknown configuration
#endif

#if __ARM_MAX_ARCH__ >= 8

// Arguments
input    .req x0
len_bits .req x1
output   .req x2
tag_ptr  .req x3
ivec     .req x4
key      .req x5
Htable   .req x6

byte_len .req x15

constant_temp .req x25

count           .req x1
full_blocks     .req x7
remainder       .req x9
unroll          .req x10

aes_st0   .req v0
aes_st0_q .req q0
aes_st1   .req v1
aes_st1_q .req q1
aes_st2   .req v2
aes_st2_q .req q2
aes_st3   .req v3
aes_st3_q .req q3

res0      .req v0
res0_q    .req q0
res1      .req v1
res1_q    .req q1
res2      .req v2
res2_q    .req q2
res3      .req v3
res3_q    .req q3

ghash_hi    .req v9
ghash_lo    .req v8
ghash_mid   .req v10
ghash_mid_d .req d10

ghash_tmp   .req v11
ghash_tmp_d .req d11

ghash_mod   .req v7
ghash_mod_d .req d7

modulo_tmp0 .req v0
modulo_tmp1 .req v1

Ht1q    .req q12
Ht2q    .req q13
Ht12q   .req q14

Ht1    .req v12
Ht2    .req v13
Ht12   .req v14

Ht3q    .req Ht1q
Ht4q    .req Ht2q
Ht34q   .req Ht12q

Ht3    .req Ht1
Ht4    .req Ht2
Ht34   .req Ht12

Ht5q    .req Ht1q
Ht6q    .req Ht2q
Ht56q   .req Ht12q

Ht5    .req Ht1
Ht6    .req Ht2
Ht56   .req Ht12

Ht7q    .req Ht1q
Ht8q    .req Ht2q
Ht78q   .req Ht12q

Ht7    .req Ht1
Ht8    .req Ht2
Ht78   .req Ht12

rk0q   .req q18
rk1q   .req q19
rk2q   .req q20
rk3q   .req q21
rk4q   .req q22
rk5q   .req q23
rk6q   .req q24
rk7q   .req q25
rk8q   .req q26
rk9q   .req q27
rk10q  .req q28

rk0    .req v18
rk1    .req v19
rk2    .req v20
rk3    .req v21
rk4    .req v22
rk5    .req v23
rk6    .req v24
rk7    .req v25
rk8    .req v26
rk9    .req v27
rk10   .req v28

plain0   .req v29
plain0_q .req q29

plain1   .req v4
plain1_q .req q4

plain2   .req v5
plain2_q .req q5

plain3   .req v6
plain3_q .req q6


rctr_inc   .req v30
rtmp_ctr   .req v31
rtmp_ctr_q .req q31

tag    .req v11
tag_q  .req q11

#define UNROLL 8

#define STACK_SIZE_GPRS  (6*16)
#define STACK_SIZE_VREGS (4*16)
#define STACK_SIZE  (STACK_SIZE_GPRS + STACK_SIZE_VREGS)

#define STACK_BASE_GPRS  (0)
#define STACK_BASE_VREGS (STACK_SIZE_GPRS)

/********************************************************************/
/*                 Generic preamble/postamble macros                */
/********************************************************************/

.macro save_vregs
        stp  d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
        stp d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
        stp d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
        stp d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm

.macro restore_vregs
        ldp  d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
        ldp d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
        ldp d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
        ldp d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm

.macro save_gprs
        stp x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
        stp x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
        stp x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
        stp x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
        stp x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
        stp x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

.macro restore_gprs
        ldp x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
        ldp x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
        ldp x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
        ldp x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
        ldp x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
        ldp x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

/********************************************************************/
/*                       AES related macros                         */
/********************************************************************/

.macro load_iv
        ldr     rtmp_ctr_q, [ivec]

	mov	constant_temp, #0x100000000   // set up counter increment
	movi	rctr_inc.16b,  #0x0
	fmov	rctr_inc.d[1], constant_temp

        rev32   rtmp_ctr.16b, rtmp_ctr.16b
.endm

.macro aes_ctr_inc
        add    rtmp_ctr.4s, rtmp_ctr.4s, rctr_inc.4s
.endm

.macro next_ctr_init_aes aes_st
        rev32  \aes_st\().16b, rtmp_ctr.16b
        aes_ctr_inc
.endm

.macro next_ctr_init_aes_x4 aes_st
        next_ctr_init_aes \aes_st\()0
        next_ctr_init_aes \aes_st\()1
        next_ctr_init_aes \aes_st\()2
        next_ctr_init_aes \aes_st\()3
.endm

// A single AES round
// Prevent SLOTHY from unfolding because uArchs tend to fuse AESMC+AESE
.macro aesr data, key // @slothy:no-unfold
        aese  \data, \key
        aesmc \data, \data
.endm

.macro aesr_x2 data0, data1, key // @slothy:no-unfold
        aesr \data0\(), \key\()
        aesr \data1\(), \key\()
.endm

.macro aesr_x4 data0, data1, data2, data3, key
        aesr \data0\(), \key\()
        aesr \data1\(), \key\()
        aesr \data2\(), \key\()
        aesr \data3\(), \key\()
.endm

.macro aese_x4 data0, data1, data2, data3, key
        aese \data0\(), \key\()
        aese \data1\(), \key\()
        aese \data2\(), \key\()
        aese \data3\(), \key\()
.endm

.macro aesr_0_8 data, key
        aesr \data\().16b, \key\()0.16b
        aesr \data\().16b, \key\()1.16b
        aesr \data\().16b, \key\()2.16b
        aesr \data\().16b, \key\()3.16b
        aesr \data\().16b, \key\()4.16b
        aesr \data\().16b, \key\()5.16b
        aesr \data\().16b, \key\()6.16b
        aesr \data\().16b, \key\()7.16b
        aesr \data\().16b, \key\()8.16b
.endm

.macro aesr_0_8_x2 data0, data1, key
        aesr_x2 \data0\().16b, \data1\().16b, \key\()0.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()1.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()2.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()3.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()4.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()5.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()6.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()7.16b
        aesr_x2 \data0\().16b, \data1\().16b, \key\()8.16b
.endm

.macro aesr_0_8_x4 data, key
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()0.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()1.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()2.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()3.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()4.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()5.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()6.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()7.16b
        aesr_x4 \data\()0.16b, \data\()1.16b, \data\()2.16b, \data\()3.16b, \key\()8.16b
.endm

.macro aesr_9_10 data, key
        aesr \data\().16b, \key\()9.16b
        aesr \data\().16b, \key\()10.16b
.endm

.macro aesr_11_12 data, key
        aesr \data\().16b, \key\()11.16b
        aesr \data\().16b, \key\()12.16b
.endm

// .macro eor3 out, inA, inB, inC // @slothy:no-unfold
//         eor \out, \inA, \inB
//         eor \out, \out, \inC
// .endm

.macro aesr_final aes_st, plain, out
        aese \aes_st\().16b, rk9.16b
        eor3 \out\().16b, \plain\().16b, rk10.16b, \aes_st\().16b
.endm

.macro aesr_final_x4 aes_st, plain, out
        aese_x4 \aes_st\()0.16b, \aes_st\()1.16b, \aes_st\()2.16b, \aes_st\()3.16b, rk9.16b
        eor3 \out\()0.16b, \plain\()0.16b, rk10.16b, \aes_st\()0.16b
        eor3 \out\()1.16b, \plain\()1.16b, rk10.16b, \aes_st\()1.16b
        eor3 \out\()2.16b, \plain\()2.16b, rk10.16b, \aes_st\()2.16b
        eor3 \out\()3.16b, \plain\()3.16b, rk10.16b, \aes_st\()3.16b
.endm

.macro aes_full_block aes_st, input, output
        aesr_0_8 \aes_st\(), rk
        aesr_final \aes_st, \input, \output
.endm

.macro load_round_key i
        ldr rk\()\i\()q, [key, #((\i)*16)]
.endm

.macro load_round_key_pair i, j
        ldp rk\()\i\()q, rk\()\j\()q, [key, #((\i)*16)]
.endm

.macro load_round_keys
        load_round_key 0
        load_round_key 1
        load_round_key 2
        load_round_key 3
        load_round_key 4
        load_round_key 5
        load_round_key 6
        load_round_key 7
        load_round_key 8
        load_round_key 9
        load_round_key 10
.endm

/********************************************************************/
/*       Loading of H-table (precomputed H-powers for GHASH)        */
/********************************************************************/

// This has to be synchronized with the H-table generation

.macro load_h1 dst, dst_q
        ldr \dst_q, [Htable]
.endm

.macro load_h2 dst, dst_q
        ldr \dst_q, [Htable, #32]
.endm

.macro load_h3 dst, dst_q
        ldr \dst_q, [Htable, #48]
.endm

.macro load_h4 dst, dst_q
        ldr \dst_q, [Htable, #80]
.endm

.macro load_h5 dst, dst_q
        ldr \dst_q, [Htable, #96]
.endm

.macro load_h6 dst, dst_q
        ldr \dst_q, [Htable, #128]
.endm

.macro load_h7 dst, dst_q
        ldr \dst_q, [Htable, #144]
.endm

.macro load_h8 dst, dst_q
        ldr \dst_q, [Htable, #176]
.endm

.macro load_h12 dst, dst_q
        ldr \dst_q, [Htable, #16]
.endm

.macro load_h34 dst, dst_q
        ldr \dst_q, [Htable, #64]
.endm

.macro load_h56 dst, dst_q
        ldr \dst_q, [Htable, #112]
.endm

.macro load_h78 dst, dst_q
        ldr \dst_q, [Htable, #160]
.endm

.macro load_full_htable
        load_h1  Ht1,  Ht1q
        load_h2  Ht2,  Ht2q
        load_h3  Ht3,  Ht3q
        load_h4  Ht4,  Ht4q
        load_h5  Ht5,  Ht5q
        load_h6  Ht6,  Ht6q
        load_h12 Ht12, Ht12q
        load_h34 Ht34, Ht34q
        load_h56 Ht56, Ht56q
.endm

.macro load_htable_12
        load_h1  Ht1,  Ht1q
        load_h2  Ht2,  Ht2q
        load_h12 Ht12, Ht12q
.endm

.macro load_htable_34
        load_h3  Ht3,  Ht3q
        load_h4  Ht4,  Ht4q
        load_h34 Ht34, Ht34q
.endm

.macro load_htable_56
        load_h5  Ht5,  Ht5q
        load_h6  Ht6,  Ht6q
        load_h56 Ht56, Ht56q
.endm

.macro load_htable_78
        load_h7  Ht7,  Ht7q
        load_h8  Ht8,  Ht8q
        load_h78 Ht78, Ht78q
.endm

/********************************************************************/
/*                    Macros for GHASH udpate                       */
/********************************************************************/

.macro ghash_init_pair inputa, inputb, Ha, Hb, Hk_mid, tag
        rev64 \inputa\().16b, \inputa\().16b
        rev64 \inputb\().16b, \inputb\().16b
        eor   \inputa\().16b, \inputa\().16b, \tag\().16b
        // Low product
        pmull   ghash_lo.1q,  \inputa\().1d, \Ha\().1d
        pmull   ghash_tmp.1q, \inputb\().1d, \Hb\().1d
        eor     ghash_lo.16b, ghash_lo.16b, ghash_tmp.16b
        // High product
        pmull2  ghash_hi.1q, \inputa\().2d, \Ha\().2d
        pmull2  ghash_tmp.1q, \inputb\().2d, \Hb\().2d
        eor     ghash_hi.16b, ghash_hi.16b, ghash_tmp.16b
        // Middle product
        trn1    ghash_tmp.2d,  \inputb\().2d, \inputa\().2d
        trn2    \inputb\().2d, \inputb\().2d, \inputa\().2d
        eor     ghash_tmp.16b, ghash_tmp.16b, \inputb\().16b
        pmull2  ghash_mid.1q, ghash_tmp.2d, \Hk_mid\().2d
        pmull   ghash_tmp.1q, ghash_tmp.1d, \Hk_mid\().1d
        eor     ghash_mid.16b, ghash_mid.16b, ghash_tmp.16b
.endm

.macro ghash_acc_pair inputa, inputb, Ha, Hb, Hk_mid
        rev64 \inputa\().16b, \inputa\().16b
        rev64 \inputb\().16b, \inputb\().16b
        // Low product
        pmull   ghash_tmp.1q, \inputa\().1d, \Ha\().1d
        eor     ghash_lo.16b, ghash_lo.16b, ghash_tmp.16b
        pmull   ghash_tmp.1q, \inputb\().1d, \Hb\().1d
        eor     ghash_lo.16b, ghash_lo.16b, ghash_tmp.16b
        // High product
        pmull2  ghash_tmp.1q, \inputa\().2d, \Ha\().2d
        eor     ghash_hi.16b, ghash_hi.16b, ghash_tmp.16b
        pmull2  ghash_tmp.1q, \inputb\().2d, \Hb\().2d
        eor     ghash_hi.16b, ghash_hi.16b, ghash_tmp.16b
        // Middle product
        trn1    ghash_tmp.2d,  \inputb\().2d, \inputa\().2d
        trn2    \inputb\().2d, \inputb\().2d, \inputa\().2d
        eor     ghash_tmp.16b, ghash_tmp.16b, \inputb\().16b
        pmull2  \inputa\().1q, ghash_tmp.2d, \Hk_mid\().2d
        eor     ghash_mid.16b, ghash_mid.16b, \inputa\().16b
        pmull   ghash_tmp.1q, ghash_tmp.1d, \Hk_mid\().1d
        eor     ghash_mid.16b, ghash_mid.16b, ghash_tmp.16b
.endm

.macro ghash_init_0 input, Hk, Hk_mid, tag
        rev64 \input\().16b, \input\().16b
        eor   \input\().16b, \input\().16b, \tag\().16b
        // Low product
        pmull   ghash_lo.1q, \input\().1d, \Hk\().1d
        // High product
        pmull2  ghash_hi.1q, \input\().2d, \Hk\().2d
        // Middle product
        mov     ghash_tmp_d, \input\().d[1]
        eor     ghash_tmp.8b, ghash_tmp.8b, \input\().8b
        pmull   ghash_mid.1q, ghash_tmp.1d, \Hk_mid\().1d
.endm

.macro ghash_init_1 input, Hk, Hk_mid, tag
        rev64 \input\().16b, \input\().16b
        eor   \input\().16b, \input\().16b, \tag\().16b
        // Low product
        pmull   ghash_lo.1q, \input\().1d, \Hk\().1d
        // High product
        pmull2  ghash_hi.1q, \input\().2d, \Hk\().2d
        // Middle product
        ext     ghash_tmp.16b, \input\().16b, \input\().16b, #8
        eor     ghash_tmp.16b, ghash_tmp.16b, \input\().16b
        pmull2  ghash_mid.1q, ghash_tmp.2d, \Hk_mid\().2d
.endm

.macro ghash_acc_0 input, Hk, Hk_mid
        rev64   \input\().16b, \input\().16b

        // Low product
        pmull   ghash_tmp.1q, \input\().1d, \Hk\().1d
        eor     ghash_lo.16b, ghash_lo.16b, ghash_tmp.16b
        // High product
        pmull2  ghash_tmp.1q, \input\().2d, \Hk\().2d
        eor     ghash_hi.16b, ghash_hi.16b, ghash_tmp.16b
        // Middle product
        mov     ghash_tmp_d, \input\().d[1]
        eor     ghash_tmp.8b, ghash_tmp.8b, \input\().8b
        pmull   ghash_tmp.1q, ghash_tmp.1d, \Hk_mid\().1d
        eor     ghash_mid.16b, ghash_mid.16b, ghash_tmp.16b
.endm

.macro ghash_acc_1 input, Hk, Hk_mid
        rev64   \input\().16b, \input\().16b

        // Low product
        pmull   ghash_tmp.1q, \input\().1d, \Hk\().1d
        eor     ghash_lo.16b, ghash_lo.16b, ghash_tmp.16b
        // High product
        pmull2  ghash_tmp.1q, \input\().2d, \Hk\().2d
        eor     ghash_hi.16b, ghash_hi.16b, ghash_tmp.16b
        // Middle product
        ext     ghash_tmp.16b, \input\().16b, \input\().16b, #8
        eor     ghash_tmp.16b, ghash_tmp.16b, \input\().16b
        pmull2  ghash_tmp.1q, ghash_tmp.2d, \Hk_mid\().2d
        eor     ghash_mid.16b, ghash_mid.16b, ghash_tmp.16b
.endm

.macro ghash_finalize tag
        eor        modulo_tmp0.16b, ghash_lo.16b,  ghash_hi.16b
        pmull      modulo_tmp1.1q,  ghash_hi.1d,   ghash_mod.1d
        ext        ghash_hi.16b,    ghash_hi.16b,  ghash_hi.16b, #8
        eor        ghash_mid.16b,   ghash_mid.16b, modulo_tmp0.16b
        eor        modulo_tmp1.16b, ghash_hi.16b,  modulo_tmp1.16b
        eor        ghash_mid.16b,   ghash_mid.16b, modulo_tmp1.16b
        pmull      ghash_hi.1q,     ghash_mid.1d,  ghash_mod.1d
        eor        ghash_lo.16b,    ghash_lo.16b,  ghash_hi.16b
        ext        ghash_mid.16b,   ghash_mid.16b, ghash_mid.16b, #8
        eor        \tag\().16b,     ghash_lo.16b,  ghash_mid.16b
        ext        \tag\().16b, \tag\().16b, \tag\().16b, #8
.endm

.macro prepare_loop_counts
        mov  unroll, #UNROLL
        lsr  full_blocks, byte_len, #4
        udiv count, full_blocks, unroll
        msub remainder, count, unroll, full_blocks
.endm

.macro load_tag
        ldr      tag_q, [tag_ptr]
        rev64    tag.16b, tag.16b
.endm

.macro prepare_ghash
        // Prepare constant for modular reduction
        movi ghash_mod.8b, #0xc2
        shl  ghash_mod_d, ghash_mod_d, #56
.endm

/********************************************************************/
/*                            Core routine                          */
/********************************************************************/

.align        4
_aes_gcm_enc_kernel_slothy_base_128:
aes_gcm_enc_kernel_slothy_base_128:
#ifdef BORINGSSL_DISPATCH_TEST
        adrp  x9,_BORINGSSL_function_hit@PAGE
        add   x9, x9, _BORINGSSL_function_hit@PAGEOFF
        mov   w10, #1
        strb  w10, [x9,#2] // kFlag_aes_gcm_enc_kernel
#endif

        AARCH64_SIGN_LINK_REGISTER
        sub sp, sp, #STACK_SIZE

Lenc_preamble_start:
        save_gprs
        save_vregs

        lsr byte_len, len_bits, #3

        load_round_keys
        load_tag
        load_iv

        prepare_loop_counts
        prepare_ghash

Lenc_preamble_end:

        cbz count, Lloop_unrolled_end
Lloop_unrolled_start:

        load_round_key_pair 0, 1
        load_round_key_pair 2, 3
        load_round_key_pair 4, 5
        load_round_key_pair 6, 7
        load_round_key_pair 8, 9

        next_ctr_init_aes_x4 aes_st
        aesr_0_8_x4 aes_st, rk

        ldp plain0_q, plain1_q, [input], #(8*16)
        ldp plain2_q, plain3_q, [input, #(-6*16)]
        aesr_final_x4 aes_st, plain, res
        stp res0_q, res1_q, [output], #(8*16)
        stp res2_q, res3_q, [output, #(-6*16)]

        load_htable_78
        ghash_init_pair res0, res1, Ht8, Ht7, Ht78, tag
        load_htable_56
        ghash_acc_pair res2, res3, Ht6, Ht5, Ht56

        next_ctr_init_aes_x4 aes_st
        aesr_0_8_x4 aes_st, rk

        ldp plain0_q, plain1_q, [input, #(-4*16)]
        ldp plain2_q, plain3_q, [input, #(-2*16)]
        aesr_final_x4 aes_st, plain, res
        stp res0_q, res1_q, [output, #(-4*16)]
        stp res2_q, res3_q, [output, #(-2*16)]

        load_htable_34
        ghash_acc_pair res0, res1, Ht4, Ht3, Ht34
        load_htable_12
        ghash_acc_pair res2, res3, Ht2, Ht1, Ht12

        ghash_finalize tag

        sub count, count, #1
        cbnz count, Lloop_unrolled_start
Lloop_unrolled_end:

        load_round_key_pair 0, 1
        load_round_key_pair 2, 3
        load_round_key_pair 4, 5
        load_round_key_pair 6, 7
        load_round_key_pair 8, 9

        load_htable_12

        cbz remainder, Lloop_1x_end
Lloop_1x_start:

        ldr plain0_q, [input], #16
        next_ctr_init_aes aes_st0
        aesr_0_8 aes_st0, rk
        aesr_final aes_st0, plain0, res0
        str res0_q, [output], #16
        ghash_init_0 res0, Ht1, Ht12, tag

        ghash_finalize tag

        sub remainder, remainder, #1
        cbnz remainder, Lloop_1x_start
Lloop_1x_end:

        // Return number of bytes processed
        mov x0, byte_len
        // Store new authentication tag
        rev64 tag.16b, tag.16b
        str tag_q, [tag_ptr]
        // Store updated counter
        rev32 rtmp_ctr.16b, rtmp_ctr.16b
        str rtmp_ctr_q, [ivec]

        restore_vregs
        restore_gprs

Lenc_postamble_end:
        add sp, sp, #STACK_SIZE

        AARCH64_VALIDATE_LINK_REGISTER
        ret

#endif
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__APPLE__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
