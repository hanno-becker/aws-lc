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
aes_st4   .req v20
aes_st4_q .req q20
aes_st5   .req v21
aes_st5_q .req q21
aes_st6   .req v22
aes_st6_q .req q22
aes_st7   .req v23
aes_st7_q .req q23

res0      .req v4
res0_q    .req q4
res1      .req v5
res1_q    .req q5
res2      .req v6
res2_q    .req q6
res3      .req v24
res3_q    .req q24
res4      .req v25
res4_q    .req q25
res5      .req v26
res5_q    .req q26
res6      .req v27
res6_q    .req q27
res7      .req v28
res7_q    .req q28

ghash_hi    .req v9
ghash_lo    .req v8
ghash_mid   .req v10

ghash_hi0   .req ghash_hi
ghash_lo0   .req ghash_lo
ghash_mid0  .req ghash_mid

ghash_hi1    .req v15
ghash_lo1    .req v16
ghash_mid1   .req v17

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
rk2q   .req q18 //q20
rk3q   .req q19 //q21
rk4q   .req q18 //q22
rk5q   .req q19 //q23
rk6q   .req q18 //q24
rk7q   .req q19 //q25
rk8q   .req q18 //q26
rk9q   .req q19 //q27
rk10q  .req q18 //q28

rk0    .req v18
rk1    .req v19
rk2    .req v18 //v20
rk3    .req v19 //v21
rk4    .req v18 //v22
rk5    .req v19 //v23
rk6    .req v18 //v24
rk7    .req v19 //v25
rk8    .req v18 //v26
rk9    .req v19 //v27
rk10   .req v18 //v28

plain0   .req res0
plain0_q .req res0_q
plain1   .req res1
plain1_q .req res1_q
plain2   .req res2
plain2_q .req res2_q
plain3   .req res3
plain3_q .req res3_q
plain4   .req res4
plain4_q .req res4_q
plain5   .req res5
plain5_q .req res5_q
plain6   .req res6
plain6_q .req res6_q
plain7   .req res7
plain7_q .req res7_q

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

.macro prepare_loop_counts
        mov  unroll, #UNROLL
        lsr  full_blocks, byte_len, #4
        udiv count, full_blocks, unroll
        msub remainder, count, unroll, full_blocks
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

.macro next_ctr_init_aes_x8 aes_st
        next_ctr_init_aes \aes_st\()0
        next_ctr_init_aes \aes_st\()1
        next_ctr_init_aes \aes_st\()2
        next_ctr_init_aes \aes_st\()3
        next_ctr_init_aes \aes_st\()4
        next_ctr_init_aes \aes_st\()5
        next_ctr_init_aes \aes_st\()6
        next_ctr_init_aes \aes_st\()7
.endm

// Prevent SLOTHY from unfolding because uArchs tend to fuse AESMC+AESE
.macro aesr data, key // @slothy:no-unfold
        aese  \data, \key
        aesmc \data, \data
.endm

.macro aesr_x8 i
        load_round_key \i
        aesr aes_st0.16b, rk\i\().16b
        aesr aes_st1.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st2.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st3.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st4.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st5.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st6.16b, rk\i\().16b // @slothy:after_last
        aesr aes_st7.16b, rk\i\().16b // @slothy:after_last
.endm

.macro aese_x8 i
        load_round_key \i
        aese aes_st0.16b, rk\i\().16b
        aese aes_st1.16b, rk\i\().16b // @slothy:after_last
        aese aes_st2.16b, rk\i\().16b // @slothy:after_last
        aese aes_st3.16b, rk\i\().16b // @slothy:after_last
        aese aes_st4.16b, rk\i\().16b // @slothy:after_last
        aese aes_st5.16b, rk\i\().16b // @slothy:after_last
        aese aes_st6.16b, rk\i\().16b // @slothy:after_last
        aese aes_st7.16b, rk\i\().16b // @slothy:after_last
.endm

.macro aesr_final aes_st, plain, out
        aese \aes_st\().16b, rk9.16b
        eor3 \out\().16b, \plain\().16b, rk10.16b, \aes_st\().16b
.endm

// Load i-th round key
.macro load_round_key i
        ldr rk\()\i\()q, [key, #((\i)*16)]
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

.macro ghash_init_pair inputa, inputb, Ha, Hb, Hk_mid, i
        // Low product
        pmull   ghash_lo\()\i\().1q,  \inputa\().1d, \Ha\().1d
        pmull   ghash_tmp.1q, \inputb\().1d, \Hb\().1d
        eor     ghash_lo\()\i\().16b, ghash_lo\()\i\().16b, ghash_tmp.16b
        // High product
        pmull2  ghash_hi\()\i\().1q, \inputa\().2d, \Ha\().2d
        pmull2  ghash_tmp.1q, \inputb\().2d, \Hb\().2d
        eor     ghash_hi\()\i\().16b, ghash_hi\()\i\().16b, ghash_tmp.16b
        // Middle product
        trn1    ghash_tmp.2d,  \inputb\().2d, \inputa\().2d
        trn2    \inputb\().2d, \inputb\().2d, \inputa\().2d
        eor     ghash_tmp.16b, ghash_tmp.16b, \inputb\().16b
        pmull2  ghash_mid\()\i\().1q, ghash_tmp.2d, \Hk_mid\().2d
        pmull   ghash_tmp.1q, ghash_tmp.1d, \Hk_mid\().1d
        eor     ghash_mid\()\i\().16b, ghash_mid\()\i\().16b, ghash_tmp.16b
.endm

.macro ghash_acc_pair inputa, inputb, Ha, Hb, Hk_mid, i
        // Low product
        pmull   ghash_tmp.1q, \inputa\().1d, \Ha\().1d
        eor     ghash_lo\()\i\().16b, ghash_lo\()\i\().16b, ghash_tmp.16b
        pmull   ghash_tmp.1q, \inputb\().1d, \Hb\().1d
        eor     ghash_lo\()\i\().16b, ghash_lo\()\i\().16b, ghash_tmp.16b
        // High product
        pmull2  ghash_tmp.1q, \inputa\().2d, \Ha\().2d
        eor     ghash_hi\()\i\().16b, ghash_hi\()\i\().16b, ghash_tmp.16b
        pmull2  ghash_tmp.1q, \inputb\().2d, \Hb\().2d
        eor     ghash_hi\()\i\().16b, ghash_hi\()\i\().16b, ghash_tmp.16b
        // Middle product
        trn1    ghash_tmp.2d,  \inputb\().2d, \inputa\().2d
        trn2    \inputb\().2d, \inputb\().2d, \inputa\().2d
        eor     ghash_tmp.16b, ghash_tmp.16b, \inputb\().16b
        pmull2  \inputa\().1q, ghash_tmp.2d, \Hk_mid\().2d
        eor     ghash_mid\()\i\().16b, ghash_mid\()\i\().16b, \inputa\().16b
        pmull   ghash_tmp.1q, ghash_tmp.1d, \Hk_mid\().1d
        eor     ghash_mid\()\i\().16b, ghash_mid\()\i\().16b, ghash_tmp.16b
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

.macro store_0_8 res
        stp \res\()0_q, \res\()1_q, [output], #(8*16)
        stp \res\()2_q, \res\()3_q, [output, #(-6*16)]
        stp \res\()4_q, \res\()5_q, [output, #(-4*16)]
        stp \res\()6_q, \res\()7_q, [output, #(-2*16)]
        rev64 \res\()0.16b, \res\()0.16b
        rev64 \res\()1.16b, \res\()1.16b
        rev64 \res\()2.16b, \res\()2.16b
        rev64 \res\()3.16b, \res\()3.16b
        rev64 \res\()4.16b, \res\()4.16b
        rev64 \res\()5.16b, \res\()5.16b
        rev64 \res\()6.16b, \res\()6.16b
        rev64 \res\()7.16b, \res\()7.16b
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

        load_tag
        load_iv

        prepare_loop_counts
        prepare_ghash

Lenc_preamble_end:

        cbz count, Lloop_unrolled_end
Lloop_unrolled_start:

        next_ctr_init_aes aes_st0 // @slothy:pre=true
        next_ctr_init_aes aes_st1 // @slothy:pre=true
        next_ctr_init_aes aes_st2 // @slothy:pre=true
        next_ctr_init_aes aes_st3 // @slothy:pre=true
        next_ctr_init_aes aes_st4 // @slothy:pre=true
        next_ctr_init_aes aes_st5 // @slothy:pre=true
        next_ctr_init_aes aes_st6 // @slothy:pre=true
        next_ctr_init_aes aes_st7

        aesr_x8 0 // @slothy:core=true
        aesr_x8 1 // @slothy:core=true
        aesr_x8 2 // @slothy:core=true
        aesr_x8 3 // @slothy:core=true
        aesr_x8 4 // @slothy:core=true
        aesr_x8 5 // @slothy:core=true
        aesr_x8 6 // @slothy:core=true
        aesr_x8 7 // @slothy:core=true
        aesr_x8 8 // @slothy:core=true
        aese_x8 9 // @slothy:core=true

        load_round_key 10
        ldp plain0_q, plain1_q, [input], #(8*16)
        eor3 res0.16b, plain0.16b, rk10.16b, aes_st0.16b // @slothy:core=true
        eor3 res1.16b, plain1.16b, rk10.16b, aes_st1.16b // @slothy:core=true
        ldp plain2_q, plain3_q, [input, #(-6*16)]
        eor3 res2.16b, plain2.16b, rk10.16b, aes_st2.16b // @slothy:core=true
        eor3 res3.16b, plain3.16b, rk10.16b, aes_st3.16b // @slothy:core=true
        ldp plain4_q, plain5_q, [input, #(-4*16)]
        eor3 res4.16b, plain4.16b, rk10.16b, aes_st4.16b // @slothy:core=true
        eor3 res5.16b, plain5.16b, rk10.16b, aes_st5.16b // @slothy:core=true
        ldp plain6_q, plain7_q, [input, #(-2*16)]
        eor3 res6.16b, plain6.16b, rk10.16b, aes_st6.16b // @slothy:core=true
        eor3 res7.16b, plain7.16b, rk10.16b, aes_st7.16b // @slothy:core=true
        store_0_8 res

        eor   res0.16b, res0.16b, tag.16b

        load_htable_78
        ghash_init_pair res0, res1, Ht8, Ht7, Ht78, 0  // @slothy:post=true
        load_htable_56
        ghash_init_pair res2, res3, Ht6, Ht5, Ht56, 1  // @slothy:post=true
        load_htable_34
        ghash_acc_pair res4, res5, Ht4, Ht3, Ht34, 0   // @slothy:post=true
        load_htable_12
        ghash_acc_pair res6, res7, Ht2, Ht1, Ht12, 1   // @slothy:post=true

        eor ghash_lo.16b,  ghash_lo0.16b,  ghash_lo1.16b
        eor ghash_hi.16b,  ghash_hi0.16b,  ghash_hi1.16b
        eor ghash_mid.16b, ghash_mid0.16b, ghash_mid1.16b

        ghash_finalize tag                             // @slothy:post=true

        sub count, count, #1
        cbnz count, Lloop_unrolled_start
Lloop_unrolled_end:

        load_htable_12

        cbz remainder, Lloop_1x_end
Lloop_1x_start:

        next_ctr_init_aes aes_st0

        load_round_key 0
        aesr aes_st0.16b, rk0.16b

        load_round_key 1
        aesr aes_st0.16b, rk1.16b

        load_round_key 2
        aesr aes_st0.16b, rk2.16b

        load_round_key 3
        aesr aes_st0.16b, rk3.16b

        load_round_key 4
        aesr aes_st0.16b, rk4.16b

        load_round_key 5
        aesr aes_st0.16b, rk5.16b

        load_round_key 6
        aesr aes_st0.16b, rk6.16b

        load_round_key 7
        aesr aes_st0.16b, rk7.16b

        load_round_key 8
        aesr aes_st0.16b, rk8.16b

        load_round_key 9
        aese aes_st0.16b, rk9.16b

        load_round_key 10
        ldr plain0_q, [input], #16
        eor3 res0.16b, plain0.16b, rk10.16b, aes_st0.16b
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
