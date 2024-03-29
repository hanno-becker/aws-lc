// Copyright (c) 2022, ARM Inc.

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.

// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// Author: Hanno Becker <hannobecker@posteo.de>

// This file was derived from the assembly generated from aesv8-gcm-armv8.pl,
// written by Fangming Fang <fangming.fang@arm.com> for the OpenSSL project,
// and derived from https: // github.com/ARM-software/AArch64cryptolib, original
// author Samuel Lee <Samuel.Lee@arm.com>.

// The code below is a 'clean' AArch64 implementation of AES-GCM emphasizing
// the logic of the computation. It is meant as the input to manual audits /
// formal verification, as well as automated micro-optimization such as done
// by the SLOTHY superoptimizer (https: // github.com/slothy-optimizer/slothy).

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
remainder       .req x16
unroll          .req x10

ctr_tmp   .req x14
ctr_tmp_w .req w14

ivec_0_63    .req x11
ivec_64_96   .req x12
ivec_64_96_w .req w12

ctr      .req w13
ctr_x    .req x13

aes_st    .req v0
aes_st_q  .req q0
aes_st_d  .req d0

res       .req v0
res_q     .req q0

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

Ht1q   .req q12
Ht2q   .req q13
Ht12q  .req q14

Ht1    .req v12
Ht2    .req v13
Ht12   .req v14

Ht3q   .req q15
Ht4q   .req q16
Ht34q  .req q17

Ht3    .req v15
Ht4    .req v16
Ht34   .req v17

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

rk10_lo .req x20
rk10_hi .req x21

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

plain   .req v29
plain_q .req q29

plain_lo .req x22
plain_hi .req x23

tag    .req v30
tag_q  .req q30

#define UNROLL 4

#define STACK_SIZE_GPRS  (6*16)
#define STACK_SIZE_VREGS (4*16)
#define STACK_SIZE  (STACK_SIZE_GPRS + STACK_SIZE_VREGS + UNROLL*16)

#define STACK_BASE_GPRS  (0)
#define STACK_BASE_VREGS (STACK_SIZE_GPRS)
#define STACK_BASE_AES_ST (STACK_SIZE_GPRS + STACK_SIZE_VREGS)

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

// Derive number of iterations of unrolled loop and single-block loop
.macro prepare_loop_counts
        mov  unroll, #UNROLL
        // Number of AES Blocks (16b each)
        lsr  full_blocks, byte_len, #4
        // Number of iterations of the unrolled loop
        udiv count, full_blocks, unroll
        // Number of iterations for the tail loop handling 1 block each
        msub remainder, count, unroll, full_blocks
.endm

/********************************************************************/
/*                       AES related macros                         */
/********************************************************************/

.macro load_iv
        ldp        ivec_0_63, ivec_64_96, [ivec]
        lsr        ctr_x, ivec_64_96, #32
        rev        ctr, ctr
        orr        ivec_64_96_w, ivec_64_96_w, ivec_64_96_w // clear top 32 bit
.endm

.macro next_ctr_init_aes aes_st, loc
        add        ctr_tmp_w, ctr, #\loc
        rev        ctr_tmp_w, ctr_tmp_w
        orr        ctr_tmp, ivec_64_96, ctr_tmp, lsl #32
        stp        ivec_0_63, ctr_tmp, [sp, #(STACK_BASE_AES_ST + \loc*16)] // @slothy:writes=stack_\loc
        ldr        \aes_st\()_q, [sp, #(STACK_BASE_AES_ST + \loc*16)]       // @slothy:reads=stack_\loc
.endm

// A single AES round
// Prevent SLOTHY from unfolding because uArchs tend to fuse AESMC+AESE
.macro aesr data, key // @slothy:no-unfold
        aese  \data, \key
        aesmc \data, \data
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

.macro aesr_9_10 data, key
        aesr \data\().16b, \key\()9.16b
        aesr \data\().16b, \key\()10.16b
.endm

.macro aesr_11_12 data, key
        aesr \data\().16b, \key\()11.16b
        aesr \data\().16b, \key\()12.16b
.endm

// Destructs inA
.macro eor3 out, inA, inB, inC
        eor \inA, \inA, \inB
        eor \out, \inA, \inC
.endm

.macro aesr_final aes_st, plain, out, loc
        aese \aes_st\().16b, rk9.16b
        eor \plain\()_lo, \plain\()_lo, rk10_lo
        eor \plain\()_hi, \plain\()_hi, rk10_hi
        stp \plain\()_lo, \plain\()_hi, [sp, #(STACK_BASE_AES_ST + \loc*16)] // @slothy:writes=stack_\loc
        ldr \plain\()_q, [sp, #(STACK_BASE_AES_ST + \loc*16)]       // @slothy:reads=stack_\loc
        eor \out\().16b, \plain\().16b, \aes_st\().16b
.endm

.macro aes_full_block aes_st, input, output, loc
        next_ctr_init_aes \aes_st, \loc
        aesr_0_8 \aes_st\(), rk
        aesr_final \aes_st, \input, \output, \loc
.endm

.macro load_round_key i
        ldr rk\i\()q, [key, #((\i)*16)]
.endm

.macro load_round_key_scalar i
        ldp rk\i\()_lo, rk\i\()_hi, [key, #((\i)*16)]
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
        load_round_key_scalar 10
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

.macro ghash_init_0 input, Hk, Hk_mid
        rev64 \input\().16b, \input\().16b
        // Low product
        pmull   ghash_lo.1q, \input\().1d, \Hk\().1d
        // High product
        pmull2  ghash_hi.1q, \input\().2d, \Hk\().2d
        // Middle product
        mov     ghash_tmp_d, \input\().d[1]
        eor     ghash_tmp.8b, ghash_tmp.8b, \input\().8b
        pmull   ghash_mid.1q, ghash_tmp.1d, \Hk_mid\().1d
.endm

.macro ghash_init_1 input, Hk, Hk_mid
        rev64 \input\().16b, \input\().16b
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

.macro ghash_init_with_tag_0 input, Hk, Hk_mid, tag
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

.macro ghash_init_with_tag_1 input, Hk, Hk_mid, tag
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

.macro ghash_acc_with_tag_0 input, Hk, Hk_mid, tag
        rev64   \input\().16b, \input\().16b
        eor   \input\().16b, \input\().16b, \tag\().16b
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

.macro ghash_acc_with_tag_1 input, Hk, Hk_mid, tag
        rev64   \input\().16b, \input\().16b
        eor   \input\().16b, \input\().16b, \tag\().16b
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

        AARCH64_VALID_CALL_TARGET
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

        load_htable_12
        load_htable_34

Lenc_preamble_end:

        cbz count, Lloop_unrolled_end
                                                           // Instructions:    98
                                                           // Expected cycles: 52
                                                           // Expected IPC:    1.88
                                                           // ---------------- cycle (expected) ----------------->
                                                           // 0                        25                       50
                                                           // |------------------------|------------------------|-
        add w7, w13, #0                                    // *...................................................
        add w27, w13, #1                                   // *...................................................
        add w23, w13, #2                                   // *...................................................
        add w29, w13, #3                                   // .*..................................................
        add w13, w13, #UNROLL                              // .*..................................................
        rev w7, w7                                         // .*..................................................
        rev w27, w27                                       // ..*.................................................
        rev w23, w23                                       // ..*.................................................
        orr x7, x12, x7, lsl #32                           // ..*.................................................
        orr x27, x12, x27, lsl #32                         // ...*................................................
        orr x23, x12, x23, lsl #32                         // ...*................................................
        stp x11, x7, [sp, #STACK_BASE_AES_ST]              // ...*................................................ // @slothy:writes=stack_0
        rev w7, w29                                        // ....*...............................................
        stp x11, x27, [sp, #STACK_BASE_AES_ST + 16]        // ....*............................................... // @slothy:writes=stack_1
        orr x7, x12, x7, lsl #32                           // .....*..............................................
        ldr q1, [sp, #STACK_BASE_AES_ST]                   // ......*............................................. // @slothy:reads=stack_0
        ldp x27, x29, [x0, #16]                            // ......*.............................................
        ldr q6, [sp, #STACK_BASE_AES_ST + 16]              // .......*............................................ // @slothy:reads=stack_1
        stp x11, x23, [sp, #STACK_BASE_AES_ST + 32]        // ........*........................................... // @slothy:writes=stack_2
        stp x11, x7, [sp, #STACK_BASE_AES_ST + 48]         // ........*........................................... // @slothy:writes=stack_3
        aesr v1.16b, v18.16b                               // .........*..........................................
        eor x7, x27, x20                                   // .........*..........................................
        eor x27, x29, x21                                  // .........*..........................................
        aesr v6.16b, v18.16b                               // ..........*.........................................
        stp x7, x27, [sp, #STACK_BASE_AES_ST + 16]         // ..........*......................................... // @slothy:writes=stack_1
        ldr q9, [sp, #STACK_BASE_AES_ST + 48]              // ...........*........................................ // @slothy:reads=stack_3
        aesr v1.16b, v19.16b                               // ...........*........................................
        ldr q11, [sp, #STACK_BASE_AES_ST + 32]             // ............*....................................... // @slothy:reads=stack_2
        aesr v6.16b, v19.16b                               // ............*.......................................
        ldp x7, x27, [x0, #48]                             // ............*.......................................
        ldr q10, [sp, #STACK_BASE_AES_ST + 16]             // .............*...................................... // @slothy:reads=stack_1
        aesr v1.16b, v20.16b                               // .............*......................................
        aesr v6.16b, v20.16b                               // ..............*.....................................
        ldp x23, x29, [x0, #32]                            // ..............*.....................................
        aesr v1.16b, v21.16b                               // ...............*....................................
        eor x7, x7, x20                                    // ...............*....................................
        eor x27, x27, x21                                  // ...............*....................................
        aesr v11.16b, v18.16b                              // ................*...................................
        stp x7, x27, [sp, #STACK_BASE_AES_ST + 48]         // ................*................................... // @slothy:writes=stack_3
        ldp x7, x27, [x0], #(4*16)                         // ................*...................................
        aesr v1.16b, v22.16b                               // .................*..................................
        eor x23, x23, x20                                  // .................*..................................
        eor x29, x29, x21                                  // .................*..................................
        aesr v11.16b, v19.16b                              // ..................*.................................
        stp x23, x29, [sp, #STACK_BASE_AES_ST + 32]        // ..................*................................. // @slothy:writes=stack_2
        ldr q28, [sp, #STACK_BASE_AES_ST + 48]             // ...................*................................ // @slothy:reads=stack_3
        aesr v1.16b, v23.16b                               // ...................*................................
        eor x7, x7, x20                                    // ...................*................................
        aesr v11.16b, v20.16b                              // ....................*...............................
        eor x27, x27, x21                                  // ....................*...............................
        ldr q0, [sp, #STACK_BASE_AES_ST + 32]              // .....................*.............................. // @slothy:reads=stack_2
        aesr v1.16b, v24.16b                               // .....................*..............................
        stp x7, x27, [sp, #STACK_BASE_AES_ST]              // .....................*.............................. // @slothy:writes=stack_0
        aesr v9.16b, v18.16b                               // ......................*.............................
        aesr v1.16b, v25.16b                               // .......................*............................
        aesr v11.16b, v21.16b                              // ........................*...........................
        ldr q31, [sp, #STACK_BASE_AES_ST]                  // ........................*........................... // @slothy:reads=stack_0
        aesr v1.16b, v26.16b                               // .........................*..........................
        aesr v11.16b, v22.16b                              // ..........................*.........................
        aese v1.16b, v27.16b                               // ...........................*........................
        aesr v11.16b, v23.16b                              // ............................*.......................
        aesr v9.16b, v19.16b                               // .............................*......................
        eor v1.16B, v31.16B, v1.16B                        // .............................*......................
        aesr v11.16b, v24.16b                              // ..............................*.....................
        aesr v9.16b, v20.16b                               // ...............................*....................
        rev64 v31.16B, v1.16B                              // ...............................*....................
        str q1, [x2], #(4*16)                              // ................................*...................
        aesr v11.16b, v25.16b                              // ................................*...................
        eor v31.16B, v31.16B, v30.16B                      // .................................*..................
        aesr v9.16b, v21.16b                               // .................................*..................
        aesr v11.16b, v26.16b                              // ..................................*.................
        aesr v6.16b, v21.16b                               // ...................................*................
        ext v1.16B, v31.16B, v31.16B, #8                   // ...................................*................
        aese v11.16b, v27.16b                              // ....................................*...............
        aesr v9.16b, v22.16b                               // .....................................*..............
        eor v5.16B, v1.16B, v31.16B                        // .....................................*..............
        eor v1.16B, v0.16B, v11.16B                        // ......................................*.............
        aesr v6.16b, v22.16b                               // ......................................*.............
        aesr v9.16b, v23.16b                               // .......................................*............
        aesr v6.16b, v23.16b                               // ........................................*...........
        rev64 v29.16B, v1.16B                              // ........................................*...........
        str q1, [x2, #-32]                                 // .........................................*..........
        aesr v9.16b, v24.16b                               // .........................................*..........
        aesr v6.16b, v24.16b                               // ..........................................*.........
        ext v1.16B, v29.16B, v29.16B, #8                   // ..........................................*.........
        aesr v9.16b, v25.16b                               // ...........................................*........
        aesr v6.16b, v25.16b                               // ............................................*.......
        eor v2.16B, v1.16B, v29.16B                        // ............................................*.......
        aesr v9.16b, v26.16b                               // .............................................*......
        aesr v6.16b, v26.16b                               // ..............................................*.....
        aese v9.16b, v27.16b                               // ...............................................*....
        aese v6.16b, v27.16b                               // ................................................*...
        eor v0.16B, v28.16B, v9.16B                        // .................................................*..
        pmull v28.1q, v31.1d, v16.1d                       // .................................................*..
        eor v1.16B, v10.16B, v6.16B                        // ..................................................*.
        pmull2 v10.1q, v31.2d, v16.2d                      // ..................................................*.
        pmull v11.1q, v29.1d, v13.1d                       // ...................................................*
        rev64 v8.16B, v0.16B                               // ...................................................*

                                                                        // ---------------- cycle (expected) ----------------->
                                                                        // 0                        25                       50
                                                                        // |------------------------|------------------------|-
        // ldp X<ssa_2>, X<ssa_3>, [x0, #16]                            // ......*.............................................
        // add W<ssa_4>, w13, #1                                        // *...................................................
        // rev W<ssa_6>, W<ssa_4>                                       // ..*.................................................
        // add W<ssa_7>, w13, #2                                        // *...................................................
        // orr X<ssa_10>, x12, X<ssa_6>, lsl #32                        // ...*................................................
        // rev W<ssa_11>, W<ssa_7>                                      // ..*.................................................
        // stp x11, X<ssa_10>, [sp, #STACK_BASE_AES_ST + 16]            // ....*...............................................
        // orr X<ssa_15>, x12, X<ssa_11>, lsl #32                       // ...*................................................
        // stp x11, X<ssa_15>, [sp, #STACK_BASE_AES_ST + 32]            // ........*...........................................
        // add W<ssa_19>, w13, #0                                       // *...................................................
        // add W<ssa_22>, w13, #3                                       // .*..................................................
        // rev W<ssa_23>, W<ssa_19>                                     // .*..................................................
        // ldr Q<ssa_25>, [sp, #STACK_BASE_AES_ST + 16]                 // .......*............................................
        // orr X<ssa_26>, x12, X<ssa_23>, lsl #32                       // ..*.................................................
        // rev W<ssa_27>, W<ssa_22>                                     // ....*...............................................
        // ldr Q<ssa_29>, [sp, #STACK_BASE_AES_ST + 32]                 // ............*.......................................
        // orr X<ssa_30>, x12, X<ssa_27>, lsl #32                       // .....*..............................................
        // add w13, w13, #UNROLL                                        // .*..................................................
        // eor X<ssa_32>, X<ssa_3>, x21                                 // .........*..........................................
        // stp x11, X<ssa_30>, [sp, #STACK_BASE_AES_ST + 48]            // ........*...........................................
        // aesr V<ssa_25>.16b, v18.16b                                  // ..........*.........................................
        // stp x11, X<ssa_26>, [sp, #STACK_BASE_AES_ST]                 // ...*................................................
        // aesr V<ssa_29>.16b, v18.16b                                  // ................*...................................
        // eor X<ssa_37>, X<ssa_2>, x20                                 // .........*..........................................
        // ldp X<ssa_38>, X<ssa_39>, [x0, #48]                          // ............*.......................................
        // aesr V<ssa_25>.16b, v19.16b                                  // ............*.......................................
        // ldr Q<ssa_40>, [sp, #STACK_BASE_AES_ST + 48]                 // ...........*........................................
        // aesr V<ssa_29>.16b, v19.16b                                  // ..................*.................................
        // ldp X<ssa_42>, X<ssa_43>, [x0, #32]                          // ..............*.....................................
        // ldr Q<ssa_44>, [sp, #STACK_BASE_AES_ST]                      // ......*.............................................
        // aesr V<ssa_25>.16b, v20.16b                                  // ..............*.....................................
        // eor X<ssa_45>, X<ssa_39>, x21                                // ...............*....................................
        // aesr V<ssa_29>.16b, v20.16b                                  // ....................*...............................
        // eor X<ssa_47>, X<ssa_38>, x20                                // ...............*....................................
        // aesr V<ssa_40>.16b, v18.16b                                  // ......................*.............................
        // eor X<ssa_49>, X<ssa_43>, x21                                // .................*..................................
        // aesr V<ssa_29>.16b, v21.16b                                  // ........................*...........................
        // ldp X<ssa_51>, X<ssa_52>, [x0], #(4*16)                      // ................*...................................
        // aesr V<ssa_44>.16b, v18.16b                                  // .........*..........................................
        // aesr V<ssa_29>.16b, v22.16b                                  // ..........................*.........................
        // aesr V<ssa_44>.16b, v19.16b                                  // ...........*........................................
        // eor X<ssa_56>, X<ssa_42>, x20                                // .................*..................................
        // aesr V<ssa_29>.16b, v23.16b                                  // ............................*.......................
        // stp X<ssa_56>, X<ssa_49>, [sp, #STACK_BASE_AES_ST + 32]      // ..................*.................................
        // aesr V<ssa_44>.16b, v20.16b                                  // .............*......................................
        // eor X<ssa_58>, X<ssa_51>, x20                                // ...................*................................
        // aesr V<ssa_29>.16b, v24.16b                                  // ..............................*.....................
        // stp X<ssa_47>, X<ssa_45>, [sp, #STACK_BASE_AES_ST + 48]      // ................*...................................
        // aesr V<ssa_44>.16b, v21.16b                                  // ...............*....................................
        // stp X<ssa_37>, X<ssa_32>, [sp, #STACK_BASE_AES_ST + 16]      // ..........*.........................................
        // aesr V<ssa_29>.16b, v25.16b                                  // ................................*...................
        // aesr V<ssa_44>.16b, v22.16b                                  // .................*..................................
        // aesr V<ssa_29>.16b, v26.16b                                  // ..................................*.................
        // ldr Q<ssa_66>, [sp, #STACK_BASE_AES_ST + 32]                 // .....................*..............................
        // aesr V<ssa_44>.16b, v23.16b                                  // ...................*................................
        // aesr V<ssa_40>.16b, v19.16b                                  // .............................*......................
        // ldr Q<ssa_68>, [sp, #STACK_BASE_AES_ST + 48]                 // ...................*................................
        // aesr V<ssa_44>.16b, v24.16b                                  // .....................*..............................
        // aese V<ssa_29>.16b, v27.16b                                  // ....................................*...............
        // aesr V<ssa_40>.16b, v20.16b                                  // ...............................*....................
        // eor V<ssa_72>.16B, V<ssa_66>.16B, V<ssa_29>.16B              // ......................................*.............
        // aesr V<ssa_44>.16b, v25.16b                                  // .......................*............................
        // eor X<ssa_73>, X<ssa_52>, x21                                // ....................*...............................
        // aesr V<ssa_40>.16b, v21.16b                                  // .................................*..................
        // stp X<ssa_58>, X<ssa_73>, [sp, #STACK_BASE_AES_ST]           // .....................*..............................
        // aesr V<ssa_44>.16b, v26.16b                                  // .........................*..........................
        // rev64 v29.16B, V<ssa_72>.16B                                 // ........................................*...........
        // aesr V<ssa_25>.16b, v21.16b                                  // ...................................*................
        // ldr Q<ssa_77>, [sp, #STACK_BASE_AES_ST]                      // ........................*...........................
        // aesr V<ssa_40>.16b, v22.16b                                  // .....................................*..............
        // aese V<ssa_44>.16b, v27.16b                                  // ...........................*........................
        // ext V<ssa_78>.16B, v29.16B, v29.16B, #8                      // ..........................................*.........
        // str Q<ssa_72>, [x2, #32]                                     // .........................................*..........
        // aesr V<ssa_25>.16b, v22.16b                                  // ......................................*.............
        // eor V<ssa_79>.16B, V<ssa_77>.16B, V<ssa_44>.16B              // .............................*......................
        // aesr V<ssa_40>.16b, v23.16b                                  // .......................................*............
        // ldr Q<ssa_80>, [sp, #STACK_BASE_AES_ST + 16]                 // .............*......................................
        // aesr V<ssa_25>.16b, v23.16b                                  // ........................................*...........
        // aesr V<ssa_40>.16b, v24.16b                                  // .........................................*..........
        // str Q<ssa_79>, [x2], #(4*16)                                 // ................................*...................
        // rev64 V<ssa_81>.16B, V<ssa_79>.16B                           // ...............................*....................
        // aesr V<ssa_25>.16b, v24.16b                                  // ..........................................*.........
        // eor v2.16B, V<ssa_78>.16B, v29.16B                           // ............................................*.......
        // aesr V<ssa_40>.16b, v25.16b                                  // ...........................................*........
        // eor V<ssa_82>.16B, V<ssa_81>.16B, v30.16B                    // .................................*..................
        // aesr V<ssa_25>.16b, v25.16b                                  // ............................................*.......
        // aesr V<ssa_40>.16b, v26.16b                                  // .............................................*......
        // aesr V<ssa_25>.16b, v26.16b                                  // ..............................................*.....
        // ext V<ssa_83>.16B, V<ssa_82>.16B, V<ssa_82>.16B, #8          // ...................................*................
        // aese V<ssa_40>.16b, v27.16b                                  // ...............................................*....
        // eor v5.16B, V<ssa_83>.16B, V<ssa_82>.16B                     // .....................................*..............
        // aese V<ssa_25>.16b, v27.16b                                  // ................................................*...
        // eor v0.16B, V<ssa_68>.16B, V<ssa_40>.16B                     // .................................................*..
        // pmull v28.1q, V<ssa_82>.1d, v16.1d                           // .................................................*..
        // pmull2 v10.1q, V<ssa_82>.2d, v16.2d                          // ..................................................*.
        // eor v1.16B, V<ssa_80>.16B, V<ssa_25>.16B                     // ..................................................*.
        // pmull v11.1q, v29.1d, v13.1d                                 // ...................................................*
        // rev64 v8.16B, v0.16B                                         // ...................................................*

        //
        // LLVM MCA STATISTICS (PREAMBLE) BEGIN
        //
        //
        // [0] Code Region
        //
        // Iterations:        100
        // Instructions:      13400
        // Total Cycles:      7914
        // Total uOps:        17000
        //
        // Dispatch Width:    8
        // uOps Per Cycle:    2.15
        // IPC:               1.69
        // Block RThroughput: 79.0
        //
        //
        // Cycles with backend pressure increase [ 39.01% ]
        // Throughput Bottlenecks:
        //   Resource Pressure       [ 39.01% ]
        //   - N1UnitL  [ 1.39% ]
        //   - N1UnitM  [ 1.33% ]
        //   - N1UnitS  [ 1.33% ]
        //   - N1UnitV0  [ 38.84% ]
        //   - N1UnitV1  [ 1.25% ]
        //   Data Dependencies:      [ 2.68% ]
        //   - Register Dependencies [ 2.68% ]
        //   - Memory Dependencies   [ 0.00% ]
        //
        // Critical sequence based on the simulation:
        //
        //               Instruction                                 Dependency Information
        //  +----< 132.  pmull.1q	v11, v29, v13
        //  |
        //  |    < loop carried >
        //  |
        //  |      0.    add	w7, w13, #0
        //  |      1.    add	w27, w13, #1
        //  |      2.    add	w23, w13, #2
        //  |      3.    add	w29, w13, #3
        //  |      4.    add	w13, w13, #4
        //  |      5.    rev	w7, w7
        //  |      6.    rev	w27, w27
        //  |      7.    rev	w23, w23
        //  |      8.    orr	x7, x12, x7, lsl #32
        //  |      9.    orr	x27, x12, x27, lsl #32
        //  |      10.   orr	x23, x12, x23, lsl #32
        //  |      11.   stp	x11, x7, [sp, #160]
        //  |      12.   rev	w7, w29
        //  |      13.   stp	x11, x27, [sp, #176]
        //  |      14.   orr	x7, x12, x7, lsl #32
        //  |      15.   ldr	q1, [sp, #160]
        //  |      16.   ldp	x27, x29, [x0, #16]
        //  |      17.   ldr	q6, [sp, #176]
        //  |      18.   stp	x11, x23, [sp, #192]
        //  |      19.   stp	x11, x7, [sp, #208]
        //  +----> 20.   aese.16b	v1, v18                           ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  +----> 21.   aesmc.16b	v1, v1                            ## REGISTER dependency:  q1
        //  |      22.   eor	x7, x27, x20
        //  |      23.   eor	x27, x29, x21
        //  |      24.   aese.16b	v6, v18
        //  |      25.   aesmc.16b	v6, v6
        //  |      26.   stp	x7, x27, [sp, #176]
        //  |      27.   ldr	q9, [sp, #208]
        //  +----> 28.   aese.16b	v1, v19                           ## REGISTER dependency:  q1
        //  +----> 29.   aesmc.16b	v1, v1                            ## REGISTER dependency:  q1
        //  |      30.   ldr	q11, [sp, #192]
        //  |      31.   aese.16b	v6, v19
        //  |      32.   aesmc.16b	v6, v6
        //  |      33.   ldp	x7, x27, [x0, #48]
        //  |      34.   ldr	q10, [sp, #176]
        //  +----> 35.   aese.16b	v1, v20                           ## REGISTER dependency:  q1
        //  +----> 36.   aesmc.16b	v1, v1                            ## REGISTER dependency:  q1
        //  |      37.   aese.16b	v6, v20
        //  |      38.   aesmc.16b	v6, v6
        //  |      39.   ldp	x23, x29, [x0, #32]
        //  +----> 40.   aese.16b	v1, v21                           ## REGISTER dependency:  q1
        //  |      41.   aesmc.16b	v1, v1
        //  |      42.   eor	x7, x7, x20
        //  |      43.   eor	x27, x27, x21
        //  +----> 44.   aese.16b	v11, v18                          ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 45.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      46.   stp	x7, x27, [sp, #208]
        //  |      47.   ldp	x7, x27, [x0], #64
        //  |      48.   aese.16b	v1, v22
        //  |      49.   aesmc.16b	v1, v1
        //  |      50.   eor	x23, x23, x20
        //  |      51.   eor	x29, x29, x21
        //  +----> 52.   aese.16b	v11, v19                          ## REGISTER dependency:  q11
        //  +----> 53.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      54.   stp	x23, x29, [sp, #192]
        //  |      55.   ldr	q28, [sp, #208]
        //  |      56.   aese.16b	v1, v23
        //  |      57.   aesmc.16b	v1, v1
        //  |      58.   eor	x7, x7, x20
        //  +----> 59.   aese.16b	v11, v20                          ## REGISTER dependency:  q11
        //  +----> 60.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      61.   eor	x27, x27, x21
        //  |      62.   ldr	q0, [sp, #192]
        //  |      63.   aese.16b	v1, v24
        //  |      64.   aesmc.16b	v1, v1
        //  |      65.   stp	x7, x27, [sp, #160]
        //  |      66.   aese.16b	v9, v18
        //  |      67.   aesmc.16b	v9, v9
        //  |      68.   aese.16b	v1, v25
        //  |      69.   aesmc.16b	v1, v1
        //  +----> 70.   aese.16b	v11, v21                          ## REGISTER dependency:  q11
        //  +----> 71.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      72.   ldr	q31, [sp, #160]
        //  |      73.   aese.16b	v1, v26
        //  |      74.   aesmc.16b	v1, v1
        //  +----> 75.   aese.16b	v11, v22                          ## REGISTER dependency:  q11
        //  +----> 76.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      77.   aese.16b	v1, v27
        //  +----> 78.   aese.16b	v11, v23                          ## REGISTER dependency:  q11
        //  +----> 79.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      80.   aese.16b	v9, v19
        //  |      81.   aesmc.16b	v9, v9
        //  |      82.   eor.16b	v1, v31, v1
        //  +----> 83.   aese.16b	v11, v24                          ## REGISTER dependency:  q11
        //  +----> 84.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      85.   aese.16b	v9, v20
        //  |      86.   aesmc.16b	v9, v9
        //  |      87.   rev64.16b	v31, v1
        //  |      88.   str	q1, [x2], #64
        //  +----> 89.   aese.16b	v11, v25                          ## REGISTER dependency:  q11
        //  +----> 90.   aesmc.16b	v11, v11                          ## REGISTER dependency:  q11
        //  |      91.   eor.16b	v31, v31, v30
        //  |      92.   aese.16b	v9, v21
        //  |      93.   aesmc.16b	v9, v9
        //  +----> 94.   aese.16b	v11, v26                          ## REGISTER dependency:  q11
        //  |      95.   aesmc.16b	v11, v11
        //  +----> 96.   aese.16b	v6, v21                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 97.   aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      98.   ext.16b	v1, v31, v31, #8
        //  |      99.   aese.16b	v11, v27
        //  |      100.  aese.16b	v9, v22
        //  |      101.  aesmc.16b	v9, v9
        //  |      102.  eor.16b	v5, v1, v31
        //  |      103.  eor.16b	v1, v0, v11
        //  +----> 104.  aese.16b	v6, v22                           ## REGISTER dependency:  q6
        //  +----> 105.  aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      106.  aese.16b	v9, v23
        //  |      107.  aesmc.16b	v9, v9
        //  +----> 108.  aese.16b	v6, v23                           ## REGISTER dependency:  q6
        //  +----> 109.  aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      110.  rev64.16b	v29, v1
        //  |      111.  stur	q1, [x2, #-32]
        //  |      112.  aese.16b	v9, v24
        //  |      113.  aesmc.16b	v9, v9
        //  +----> 114.  aese.16b	v6, v24                           ## REGISTER dependency:  q6
        //  +----> 115.  aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      116.  ext.16b	v1, v29, v29, #8
        //  |      117.  aese.16b	v9, v25
        //  |      118.  aesmc.16b	v9, v9
        //  +----> 119.  aese.16b	v6, v25                           ## REGISTER dependency:  q6
        //  +----> 120.  aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      121.  eor.16b	v2, v1, v29
        //  |      122.  aese.16b	v9, v26
        //  |      123.  aesmc.16b	v9, v9
        //  +----> 124.  aese.16b	v6, v26                           ## REGISTER dependency:  q6
        //  +----> 125.  aesmc.16b	v6, v6                            ## REGISTER dependency:  q6
        //  |      126.  aese.16b	v9, v27
        //  +----> 127.  aese.16b	v6, v27                           ## REGISTER dependency:  q6
        //  |      128.  eor.16b	v0, v28, v9
        //  +----> 129.  pmull.1q	v28, v31, v16                     ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      130.  eor.16b	v1, v10, v6
        //  +----> 131.  pmull2.1q	v10, v31, v16                     ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 132.  pmull.1q	v11, v29, v13                     ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      133.  rev64.16b	v8, v0
        //  |
        //  |    < loop carried >
        //  |
        //  +----> 20.   aese.16b	v1, v18                           ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //
        //
        // Instruction Info:
        // [1]: #uOps
        // [2]: Latency
        // [3]: RThroughput
        // [4]: MayLoad
        // [5]: MayStore
        // [6]: HasSideEffects (U)
        //
        // [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
        //  1      1     0.33                        add	w7, w13, #0
        //  1      1     0.33                        add	w27, w13, #1
        //  1      1     0.33                        add	w23, w13, #2
        //  1      1     0.33                        add	w29, w13, #3
        //  1      1     0.33                        add	w13, w13, #4
        //  1      1     0.33                        rev	w7, w7
        //  1      1     0.33                        rev	w27, w27
        //  1      1     0.33                        rev	w23, w23
        //  1      1     0.33                        orr	x7, x12, x7, lsl #32
        //  1      1     0.33                        orr	x27, x12, x27, lsl #32
        //  1      1     0.33                        orr	x23, x12, x23, lsl #32
        //  3      1     1.00           *            stp	x11, x7, [sp, #160]
        //  1      1     0.33                        rev	w7, w29
        //  3      1     1.00           *            stp	x11, x27, [sp, #176]
        //  1      1     0.33                        orr	x7, x12, x7, lsl #32
        //  2      5     0.50    *                   ldr	q1, [sp, #160]
        //  2      4     1.00    *                   ldp	x27, x29, [x0, #16]
        //  2      5     0.50    *                   ldr	q6, [sp, #176]
        //  3      1     1.00           *            stp	x11, x23, [sp, #192]
        //  3      1     1.00           *            stp	x11, x7, [sp, #208]
        //  1      2     1.00                        aese.16b	v1, v18
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      1     0.33                        eor	x7, x27, x20
        //  1      1     0.33                        eor	x27, x29, x21
        //  1      2     1.00                        aese.16b	v6, v18
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  3      1     1.00           *            stp	x7, x27, [sp, #176]
        //  2      5     0.50    *                   ldr	q9, [sp, #208]
        //  1      2     1.00                        aese.16b	v1, v19
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  2      5     0.50    *                   ldr	q11, [sp, #192]
        //  1      2     1.00                        aese.16b	v6, v19
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  2      4     1.00    *                   ldp	x7, x27, [x0, #48]
        //  2      5     0.50    *                   ldr	q10, [sp, #176]
        //  1      2     1.00                        aese.16b	v1, v20
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      2     1.00                        aese.16b	v6, v20
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  2      4     1.00    *                   ldp	x23, x29, [x0, #32]
        //  1      2     1.00                        aese.16b	v1, v21
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      1     0.33                        eor	x7, x7, x20
        //  1      1     0.33                        eor	x27, x27, x21
        //  1      2     1.00                        aese.16b	v11, v18
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  3      1     1.00           *            stp	x7, x27, [sp, #208]
        //  3      4     1.00    *                   ldp	x7, x27, [x0], #64
        //  1      2     1.00                        aese.16b	v1, v22
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      1     0.33                        eor	x23, x23, x20
        //  1      1     0.33                        eor	x29, x29, x21
        //  1      2     1.00                        aese.16b	v11, v19
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  3      1     1.00           *            stp	x23, x29, [sp, #192]
        //  2      5     0.50    *                   ldr	q28, [sp, #208]
        //  1      2     1.00                        aese.16b	v1, v23
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      1     0.33                        eor	x7, x7, x20
        //  1      2     1.00                        aese.16b	v11, v20
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      1     0.33                        eor	x27, x27, x21
        //  2      5     0.50    *                   ldr	q0, [sp, #192]
        //  1      2     1.00                        aese.16b	v1, v24
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  3      1     1.00           *            stp	x7, x27, [sp, #160]
        //  1      2     1.00                        aese.16b	v9, v18
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v1, v25
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      2     1.00                        aese.16b	v11, v21
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  2      5     0.50    *                   ldr	q31, [sp, #160]
        //  1      2     1.00                        aese.16b	v1, v26
        //  1      2     1.00                        aesmc.16b	v1, v1
        //  1      2     1.00                        aese.16b	v11, v22
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      2     1.00                        aese.16b	v1, v27
        //  1      2     1.00                        aese.16b	v11, v23
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      2     1.00                        aese.16b	v9, v19
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     0.50                        eor.16b	v1, v31, v1
        //  1      2     1.00                        aese.16b	v11, v24
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      2     1.00                        aese.16b	v9, v20
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     0.50                        rev64.16b	v31, v1
        //  5      2     1.00           *            str	q1, [x2], #64
        //  1      2     1.00                        aese.16b	v11, v25
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      2     0.50                        eor.16b	v31, v31, v30
        //  1      2     1.00                        aese.16b	v9, v21
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v11, v26
        //  1      2     1.00                        aesmc.16b	v11, v11
        //  1      2     1.00                        aese.16b	v6, v21
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     0.50                        ext.16b	v1, v31, v31, #8
        //  1      2     1.00                        aese.16b	v11, v27
        //  1      2     1.00                        aese.16b	v9, v22
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     0.50                        eor.16b	v5, v1, v31
        //  1      2     0.50                        eor.16b	v1, v0, v11
        //  1      2     1.00                        aese.16b	v6, v22
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     1.00                        aese.16b	v9, v23
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v6, v23
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     0.50                        rev64.16b	v29, v1
        //  4      2     1.00           *            stur	q1, [x2, #-32]
        //  1      2     1.00                        aese.16b	v9, v24
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v6, v24
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     0.50                        ext.16b	v1, v29, v29, #8
        //  1      2     1.00                        aese.16b	v9, v25
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v6, v25
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     0.50                        eor.16b	v2, v1, v29
        //  1      2     1.00                        aese.16b	v9, v26
        //  1      2     1.00                        aesmc.16b	v9, v9
        //  1      2     1.00                        aese.16b	v6, v26
        //  1      2     1.00                        aesmc.16b	v6, v6
        //  1      2     1.00                        aese.16b	v9, v27
        //  1      2     1.00                        aese.16b	v6, v27
        //  1      2     0.50                        eor.16b	v0, v28, v9
        //  1      2     1.00                        pmull.1q	v28, v31, v16
        //  1      2     0.50                        eor.16b	v1, v10, v6
        //  1      2     1.00                        pmull2.1q	v10, v31, v16
        //  1      2     1.00                        pmull.1q	v11, v29, v13
        //  1      2     0.50                        rev64.16b	v8, v0
        //
        //
        // Dynamic Dispatch Stall Cycles:
        // RAT     - Register unavailable:                      0
        // RCU     - Retire tokens unavailable:                 7222  (91.3%)
        // SCHEDQ  - Scheduler full:                            0
        // LQ      - Load queue full:                           0
        // SQ      - Store queue full:                          0
        // GROUP   - Static restrictions on the dispatch group: 0
        // USH     - Uncategorised Structural Hazard:           0
        //
        //
        // Dispatch Logic - number of cycles where we saw N micro opcodes dispatched:
        // [# dispatched], [# cycles]
        //  0,              2646  (33.4%)
        //  1,              1682  (21.3%)
        //  2,              990  (12.5%)
        //  3,              594  (7.5%)
        //  4,              495  (6.3%)
        //  5,              594  (7.5%)
        //  6,              298  (3.8%)
        //  7,              102  (1.3%)
        //  8,              513  (6.5%)
        //
        //
        // Schedulers - number of cycles where we saw N micro opcodes issued:
        // [# issued], [# cycles]
        //  0,          4  (0.1%)
        //  1,          4515  (57.1%)
        //  2,          1198  (15.1%)
        //  3,          896  (11.3%)
        //  4,          499  (6.3%)
        //  5,          201  (2.5%)
        //  6,          203  (2.6%)
        //  7,          101  (1.3%)
        //  8,          198  (2.5%)
        //  9,          99  (1.3%)
        //
        // Scheduler's queue usage:
        // No scheduler resources used.
        //
        //
        // Retire Control Unit - number of cycles where we saw N instructions retired:
        // [# retired], [# cycles]
        //  0,           1807  (22.8%)
        //  1,           2700  (34.1%)
        //  2,           1803  (22.8%)
        //  3,           1104  (13.9%)
        //  4,           401  (5.1%)
        //  22,          99  (1.3%)
        //
        // Total ROB Entries:                128
        // Max Used ROB Entries:             128  ( 100.0% )
        // Average Used ROB Entries per cy:  125  ( 97.7% )
        //
        //
        // Register File statistics:
        // Total number of mappings created:    13000
        // Max number of mappings used:         108
        //
        //
        // Resources:
        // [0]   - N1UnitB
        // [1.0] - N1UnitD
        // [1.1] - N1UnitD
        // [2.0] - N1UnitL
        // [2.1] - N1UnitL
        // [3]   - N1UnitM
        // [4.0] - N1UnitS
        // [4.1] - N1UnitS
        // [5]   - N1UnitV0
        // [6]   - N1UnitV1
        //
        //
        // Resource pressure per iteration:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]
        //  -     4.00   4.00   17.00  19.00  5.03   13.98  13.99  79.00  14.00
        //
        // Resource pressure by instruction:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]    Instructions:
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     add	w7, w13, #0
        //  -      -      -      -      -      -     0.51   0.49    -      -     add	w27, w13, #1
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     add	w23, w13, #2
        //  -      -      -      -      -     0.99    -     0.01    -      -     add	w29, w13, #3
        //  -      -      -      -      -      -     0.51   0.49    -      -     add	w13, w13, #4
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     rev	w7, w7
        //  -      -      -      -      -     0.99    -     0.01    -      -     rev	w27, w27
        //  -      -      -      -      -      -     0.51   0.49    -      -     rev	w23, w23
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     orr	x7, x12, x7, lsl #32
        //  -      -      -      -      -     0.99    -     0.01    -      -     orr	x27, x12, x27, lsl #32
        //  -      -      -      -      -      -     0.51   0.49    -      -     orr	x23, x12, x23, lsl #32
        //  -      -     1.00   0.02   1.98    -      -      -      -      -     stp	x11, x7, [sp, #160]
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     rev	w7, w29
        //  -     1.00    -     1.98   0.02    -      -      -      -      -     stp	x11, x27, [sp, #176]
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     orr	x7, x12, x7, lsl #32
        //  -      -      -     1.00    -      -     0.51   0.49    -      -     ldr	q1, [sp, #160]
        //  -      -      -      -     2.00    -      -      -      -      -     ldp	x27, x29, [x0, #16]
        //  -      -      -     0.99   0.01   0.98    -     0.02    -      -     ldr	q6, [sp, #176]
        //  -      -     1.00   0.02   1.98    -      -      -      -      -     stp	x11, x23, [sp, #192]
        //  -     1.00    -     1.98   0.02    -      -      -      -      -     stp	x11, x7, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -     0.51   0.49    -      -     eor	x7, x27, x20
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     eor	x27, x29, x21
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -     1.00   0.02   1.98    -      -      -      -      -     stp	x7, x27, [sp, #176]
        //  -      -      -      -     1.00   0.99    -     0.01    -      -     ldr	q9, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -     1.00    -      -     0.51   0.49    -      -     ldr	q11, [sp, #192]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -     2.00    -      -      -      -      -     ldp	x7, x27, [x0, #48]
        //  -      -      -     1.00    -      -     0.49   0.51    -      -     ldr	q10, [sp, #176]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -     2.00    -      -      -      -      -     ldp	x23, x29, [x0, #32]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x7, x7, x20
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x27, x27, x21
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -     1.00    -     2.00    -      -      -      -      -      -     stp	x7, x27, [sp, #208]
        //  -      -      -     0.02   1.98    -     0.50   0.50    -      -     ldp	x7, x27, [x0], #64
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -     0.51   0.49    -      -     eor	x23, x23, x20
        //  -      -      -      -      -      -     0.49   0.51    -      -     eor	x29, x29, x21
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -     1.00   0.02   1.98    -      -      -      -      -     stp	x23, x29, [sp, #192]
        //  -      -      -     0.99   0.01   0.01   0.50   0.49    -      -     ldr	q28, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     eor	x7, x7, x20
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -     0.51   0.49    -      -     eor	x27, x27, x21
        //  -      -      -      -     1.00    -     0.49   0.51    -      -     ldr	q0, [sp, #192]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -     1.00    -     1.98   0.02    -      -      -      -      -     stp	x7, x27, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -     1.00    -     0.49   0.51    -      -     ldr	q31, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v1, v1
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v1, v27
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v1, v31, v1
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v31, v1
        //  -      -      -     2.00    -      -     0.51   0.49    -     2.00   str	q1, [x2], #64
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v31, v31, v30
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v11, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v1, v31, v31, #8
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v11, v27
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v5, v1, v31
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v1, v0, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v29, v1
        //  -      -      -     1.98   0.02    -     1.00   1.00    -      -     stur	q1, [x2, #-32]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v1, v29, v29, #8
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v2, v1, v29
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v6, v6
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v9, v27
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v6, v27
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v28, v9
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v28, v31, v16
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v1, v10, v6
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v10, v31, v16
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v29, v13
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v8, v0
        //
        //
        // Timeline view:
        //                     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0
        // Index     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789
        //
        // [0,0]     DeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w7, w13, #0
        // [0,1]     DeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w27, w13, #1
        // [0,2]     DeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w23, w13, #2
        // [0,3]     D=eER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w29, w13, #3
        // [0,4]     D=eER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w13, w13, #4
        // [0,5]     D=eER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w7
        // [0,6]     D==eER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w27, w27
        // [0,7]     D==eER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w23, w23
        // [0,8]     .D=eER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [0,9]     .D==eER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x27, x12, x27, lsl #32
        // [0,10]    .D==eER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x23, x12, x23, lsl #32
        // [0,11]    .D==eER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #160]
        // [0,12]    .D==eER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w29
        // [0,13]    . D==eER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x27, [sp, #176]
        // [0,14]    . D==eER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [0,15]    . D===eeeeeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q1, [sp, #160]
        // [0,16]    . DeeeeE----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x27, x29, [x0, #16]
        // [0,17]    .  D===eeeeeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q6, [sp, #176]
        // [0,18]    .  D===eE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x23, [sp, #192]
        // [0,19]    .  D====eE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #208]
        // [0,20]    .   D======eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v18
        // [0,21]    .   D========eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,22]    .   D==eE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x27, x20
        // [0,23]    .   D==eE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x29, x21
        // [0,24]    .   D=======eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v18
        // [0,25]    .   D=========eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,26]    .    D===eE------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #176]
        // [0,27]    .    D====eeeeeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q9, [sp, #208]
        // [0,28]    .    D=========eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v19
        // [0,29]    .    D===========eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,30]    .    .D====eeeeeE---R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q11, [sp, #192]
        // [0,31]    .    .D=========eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v19
        // [0,32]    .    .D===========eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,33]    .    .D====eeeeE-----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0, #48]
        // [0,34]    .    .D=====eeeeeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q10, [sp, #176]
        // [0,35]    .    . D===========eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v20
        // [0,36]    .    . D=============eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,37]    .    . D============eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v20
        // [0,38]    .    . D==============eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,39]    .    . D=====eeeeE-------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x23, x29, [x0, #32]
        // [0,40]    .    . D===============eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v21
        // [0,41]    .    . D=================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,42]    .    .  D======eE-----------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [0,43]    .    .  D======eE-----------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [0,44]    .    .  D===============eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v18
        // [0,45]    .    .  D=================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,46]    .    .  D=======eE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #208]
        // [0,47]    .    .   D===eeeeE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0], #64
        // [0,48]    .    .   D=================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v22
        // [0,49]    .    .   D===================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,50]    .    .   D=======eE-------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x23, x23, x20
        // [0,51]    .    .   D=======eE-------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x29, x29, x21
        // [0,52]    .    .   D==================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v19
        // [0,53]    .    .    D===================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,54]    .    .    D=======eE-------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x23, x29, [sp, #192]
        // [0,55]    .    .    D====eeeeeE------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q28, [sp, #208]
        // [0,56]    .    .    D====================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v23
        // [0,57]    .    .    D======================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,58]    .    .    .D=====eE-----------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [0,59]    .    .    .D====================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v20
        // [0,60]    .    .    .D======================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,61]    .    .    .D======eE-----------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [0,62]    .    .    .D====eeeeeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q0, [sp, #192]
        // [0,63]    .    .    .D=======================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v24
        // [0,64]    .    .    .D=========================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,65]    .    .    . D======eE-------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #160]
        // [0,66]    .    .    . D=======================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v18
        // [0,67]    .    .    . D=========================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,68]    .    .    . D==========================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v25
        // [0,69]    .    .    . D============================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,70]    .    .    . D===========================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v21
        // [0,71]    .    .    .  D============================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,72]    .    .    .  D====eeeeeE---------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q31, [sp, #160]
        // [0,73]    .    .    .  D=============================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v26
        // [0,74]    .    .    .  D===============================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [0,75]    .    .    .  D==============================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v22
        // [0,76]    .    .    .  D================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,77]    .    .    .  D=================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v27
        // [0,78]    .    .    .   D=================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v23
        // [0,79]    .    .    .   D===================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,80]    .    .    .   D==================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v19
        // [0,81]    .    .    .   D====================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,82]    .    .    .   D==================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v31, v1
        // [0,83]    .    .    .   D=====================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v24
        // [0,84]    .    .    .   D=======================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,85]    .    .    .   D======================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v20
        // [0,86]    .    .    .    D=======================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,87]    .    .    .    D===================================eeE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v31, v1
        // [0,88]    .    .    .    D====================================eeE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   str	q1, [x2], #64
        // [0,89]    .    .    .    D========================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v25
        // [0,90]    .    .    .    .D=========================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,91]    .    .    .    .D=====================================eeE----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v31, v31, v30
        // [0,92]    .    .    .    .D========================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v21
        // [0,93]    .    .    .    .D==========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,94]    .    .    .    .D===========================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v26
        // [0,95]    .    .    .    .D=============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [0,96]    .    .    .    .D============================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v21
        // [0,97]    .    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,98]    .    .    .    . D======================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ext.16b	v1, v31, v31, #8
        // [0,99]    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v27
        // [0,100]   .    .    .    . D===============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v22
        // [0,101]   .    .    .    . D=================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,102]   .    .    .    . D========================================eeE---------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v5, v1, v31
        // [0,103]   .    .    .    . D================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v0, v11
        // [0,104]   .    .    .    . D================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v22
        // [0,105]   .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,106]   .    .    .    .  D==================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v23
        // [0,107]   .    .    .    .  D====================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,108]   .    .    .    .  D===================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v23
        // [0,109]   .    .    .    .  D=====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,110]   .    .    .    .  D=================================================eeE----R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v29, v1
        // [0,111]   .    .    .    .   D================================================eeE----R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stur	q1, [x2, #-32]
        // [0,112]   .    .    .    .   D=====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v24
        // [0,113]   .    .    .    .   D=======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,114]   .    .    .    .   D======================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v24
        // [0,115]   .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,116]   .    .    .    .    D=================================================eeE------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ext.16b	v1, v29, v29, #8
        // [0,117]   .    .    .    .    D========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v25
        // [0,118]   .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,119]   .    .    .    .    D=========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v25
        // [0,120]   .    .    .    .    D===========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,121]   .    .    .    .    D===================================================eeE--------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v2, v1, v29
        // [0,122]   .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v26
        // [0,123]   .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [0,124]   .    .    .    .    .D============================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v26
        // [0,125]   .    .    .    .    .D==============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [0,126]   .    .    .    .    .D===============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v27
        // [0,127]   .    .    .    .    .D================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v27
        // [0,128]   .    .    .    .    .D=================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v0, v28, v9
        // [0,129]   .    .    .    .    .D=================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull.1q	v28, v31, v16
        // [0,130]   .    .    .    .    .D==================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v10, v6
        // [0,131]   .    .    .    .    .D==================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull2.1q	v10, v31, v16
        // [0,132]   .    .    .    .    . D==================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull.1q	v11, v29, v13
        // [0,133]   .    .    .    .    . D==================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v8, v0
        // [1,0]     .    .    .    .    . DeE-------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w7, w13, #0
        // [1,1]     .    .    .    .    . DeE-------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w27, w13, #1
        // [1,2]     .    .    .    .    . DeE-------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w23, w13, #2
        // [1,3]     .    .    .    .    . D=eE------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w29, w13, #3
        // [1,4]     .    .    .    .    . D=eE------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w13, w13, #4
        // [1,5]     .    .    .    .    . D=eE------------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w7
        // [1,6]     .    .    .    .    .  D=eE-----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w27, w27
        // [1,7]     .    .    .    .    .  D=eE-----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w23, w23
        // [1,8]     .    .    .    .    .  D=eE-----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [1,9]     .    .    .    .    .  D==eE----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x27, x12, x27, lsl #32
        // [1,10]    .    .    .    .    .  D==eE----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x23, x12, x23, lsl #32
        // [1,11]    .    .    .    .    .    D==========================================eE----------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #160]
        // [1,12]    .    .    .    .    .    DeE----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w29
        // [1,13]    .    .    .    .    .    .  D=========================================eE--------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x27, [sp, #176]
        // [1,14]    .    .    .    .    .    .  DeE-------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [1,15]    .    .    .    .    .    .  DeeeeeE---------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q1, [sp, #160]
        // [1,16]    .    .    .    .    .    .   DeeeeE---------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x27, x29, [x0, #16]
        // [1,17]    .    .    .    .    .    .   DeeeeeE--------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q6, [sp, #176]
        // [1,18]    .    .    .    .    .    .   D========================================eE--------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x23, [sp, #192]
        // [1,19]    .    .    .    .    .    .    . D=======================================eE------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #208]
        // [1,20]    .    .    .    .    .    .    . D=========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v18
        // [1,21]    .    .    .    .    .    .    . D===========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,22]    .    .    .    .    .    .    .  DeE-----------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x27, x20
        // [1,23]    .    .    .    .    .    .    .  DeE-----------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x29, x21
        // [1,24]    .    .    .    .    .    .    .  D=========================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v18
        // [1,25]    .    .    .    .    .    .    .  D===========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,26]    .    .    .    .    .    .    .   D=====================================eE----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #176]
        // [1,27]    .    .    .    .    .    .    .    .DeeeeeE-----------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q9, [sp, #208]
        // [1,28]    .    .    .    .    .    .    .    .D=========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v19
        // [1,29]    .    .    .    .    .    .    .    . D==========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,30]    .    .    .    .    .    .    .    . DeeeeeE-------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q11, [sp, #192]
        // [1,31]    .    .    .    .    .    .    .    . D=========================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v19
        // [1,32]    .    .    .    .    .    .    .    .  D==========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,33]    .    .    .    .    .    .    .    .    DeeeeE------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0, #48]
        // [1,34]    .    .    .    .    .    .    .    .    DeeeeeE-----------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q10, [sp, #176]
        // [1,35]    .    .    .    .    .    .    .    .    D=========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v20
        // [1,36]    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,37]    .    .    .    .    .    .    .    .    . D========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v20
        // [1,38]    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,39]    .    .    .    .    .    .    .    .    .    DeeeeE-----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x23, x29, [x0, #32]
        // [1,40]    .    .    .    .    .    .    .    .    .    D========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v21
        // [1,41]    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,42]    .    .    .    .    .    .    .    .    .    .DeE----------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [1,43]    .    .    .    .    .    .    .    .    .    .  DeE--------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [1,44]    .    .    .    .    .    .    .    .    .    .  D======================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v18
        // [1,45]    .    .    .    .    .    .    .    .    .    .   D=======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,46]    .    .    .    .    .    .    .    .    .    .    .  D====================eE--------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #208]
        // [1,47]    .    .    .    .    .    .    .    .    .    .    .   DeeeeE------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0], #64
        // [1,48]    .    .    .    .    .    .    .    .    .    .    .    D==================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v22
        // [1,49]    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,50]    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x23, x23, x20
        // [1,51]    .    .    .    .    .    .    .    .    .    .    .    .  DeE--------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x29, x29, x21
        // [1,52]    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v19
        // [1,53]    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,54]    .    .    .    .    .    .    .    .    .    .    .    .  D===============eE------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x23, x29, [sp, #192]
        // [1,55]    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE----------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q28, [sp, #208]
        // [1,56]    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v23
        // [1,57]    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,58]    .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [1,59]    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v20
        // [1,60]    .    .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [1,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE-------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q0, [sp, #192]
        // [1,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v24
        // [1,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====eE-----------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #160]
        // [1,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v18
        // [1,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v25
        // [1,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v21
        // [1,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q31, [sp, #160]
        // [1,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v26
        // [1,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [1,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v22
        // [1,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v27
        // [1,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v23
        // [1,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v19
        // [1,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================eeE--R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v31, v1
        // [1,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v24
        // [1,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v20
        // [1,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeE----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v31, v1
        // [1,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================eeE---R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   str	q1, [x2], #64
        // [1,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v25
        // [1,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================eeE----R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v31, v31, v30
        // [1,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v21
        // [1,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v26
        // [1,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [1,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v21
        // [1,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==========================================eeE-------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ext.16b	v1, v31, v31, #8
        // [1,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v27
        // [1,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v22
        // [1,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================eeE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v5, v1, v31
        // [1,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v0, v11
        // [1,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v22
        // [1,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v23
        // [1,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v23
        // [1,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeE----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v29, v1
        // [1,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeE----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stur	q1, [x2, #-32]
        // [1,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v24
        // [1,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v24
        // [1,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================eeE------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ext.16b	v1, v29, v29, #8
        // [1,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v25
        // [1,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v25
        // [1,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=======================================================eeE--------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v2, v1, v29
        // [1,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v26
        // [1,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [1,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v26
        // [1,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [1,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v27
        // [1,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v27
        // [1,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v0, v28, v9
        // [1,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull.1q	v28, v31, v16
        // [1,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor.16b	v1, v10, v6
        // [1,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull2.1q	v10, v31, v16
        // [1,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   pmull.1q	v11, v29, v13
        // [1,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev64.16b	v8, v0
        // [2,0]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w7, w13, #0
        // [2,1]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE---------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w27, w13, #1
        // [2,2]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE---------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w23, w13, #2
        // [2,3]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE---------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w29, w13, #3
        // [2,4]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=eE--------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   add	w13, w13, #4
        // [2,5]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE--------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w7
        // [2,6]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE--------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w27, w27
        // [2,7]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=eE-------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w23, w23
        // [2,8]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=eE-------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [2,9]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=eE-------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x27, x12, x27, lsl #32
        // [2,10]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eE------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x23, x12, x23, lsl #32
        // [2,11]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================eE----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #160]
        // [2,12]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE----------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   rev	w7, w29
        // [2,13]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=========================================eE--------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x27, [sp, #176]
        // [2,14]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   orr	x7, x12, x7, lsl #32
        // [2,15]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q1, [sp, #160]
        // [2,16]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x27, x29, [x0, #16]
        // [2,17]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeeE--------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q6, [sp, #176]
        // [2,18]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eE--------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x23, [sp, #192]
        // [2,19]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================eE------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x11, x7, [sp, #208]
        // [2,20]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v18
        // [2,21]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,22]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x27, x20
        // [2,23]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x29, x21
        // [2,24]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=========================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v18
        // [2,25]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [2,26]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================eE----------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #176]
        // [2,27]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE-----------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q9, [sp, #208]
        // [2,28]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v19
        // [2,29]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,30]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE-------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q11, [sp, #192]
        // [2,31]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v19
        // [2,32]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [2,33]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeE------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0, #48]
        // [2,34]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE-----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldr	q10, [sp, #176]
        // [2,35]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v20
        // [2,36]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,37]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v6, v20
        // [2,38]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v6, v6
        // [2,39]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeE-----------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x23, x29, [x0, #32]
        // [2,40]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v21
        // [2,41]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,42]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [2,43]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE--------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [2,44]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v18
        // [2,45]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,46]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================eE--------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #208]
        // [2,47]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeE------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .   ldp	x7, x27, [x0], #64
        // [2,48]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v22
        // [2,49]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,50]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .   eor	x23, x23, x20
        // [2,51]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE--------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .   eor	x29, x29, x21
        // [2,52]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v19
        // [2,53]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,54]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============eE------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .   stp	x23, x29, [sp, #192]
        // [2,55]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeeE----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .   ldr	q28, [sp, #208]
        // [2,56]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v23
        // [2,57]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================eeER.    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,58]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE---------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .   eor	x7, x7, x20
        // [2,59]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v20
        // [2,60]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================================eeER    .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .   eor	x27, x27, x21
        // [2,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE-------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .   ldr	q0, [sp, #192]
        // [2,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================eeER   .    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v24
        // [2,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeER .    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====eE-----------------------------------------R .    .    .    .    .    .    .    .    .    .    .   stp	x7, x27, [sp, #160]
        // [2,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================eeE-R .    .    .    .    .    .    .    .    .    .    .   aese.16b	v9, v18
        // [2,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================eeER.    .    .    .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [2,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeER    .    .    .    .    .    .    .    .    .    .   aese.16b	v1, v25
        // [2,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================eeER  .    .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D============================================eeE-R  .    .    .    .    .    .    .    .    .    .   aese.16b	v11, v21
        // [2,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eeER .    .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE------------------------------------------R .    .    .    .    .    .    .    .    .    .   ldr	q31, [sp, #160]
        // [2,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================eeER.    .    .    .    .    .    .    .    .    .   aese.16b	v1, v26
        // [2,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================================eeER   .    .    .    .    .    .    .    .    .   aesmc.16b	v1, v1
        // [2,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeE-R   .    .    .    .    .    .    .    .    .   aese.16b	v11, v22
        // [2,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================eeER  .    .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================eeER .    .    .    .    .    .    .    .    .   aese.16b	v1, v27
        // [2,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .   aese.16b	v11, v23
        // [2,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .    .    .   aese.16b	v9, v19
        // [2,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================eeER  .    .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [2,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeE--R  .    .    .    .    .    .    .    .   eor.16b	v1, v31, v1
        // [2,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeER .    .    .    .    .    .    .    .   aese.16b	v11, v24
        // [2,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eeER    .    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeE-R    .    .    .    .    .    .    .   aese.16b	v9, v20
        // [2,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [2,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeE----R   .    .    .    .    .    .    .   rev64.16b	v31, v1
        // [2,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================eeE---R   .    .    .    .    .    .    .   str	q1, [x2], #64
        // [2,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================eeER  .    .    .    .    .    .    .   aese.16b	v11, v25
        // [2,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================eeER.    .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================================eeE----R.    .    .    .    .    .    .   eor.16b	v31, v31, v30
        // [2,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeE-R.    .    .    .    .    .    .   aese.16b	v9, v21
        // [2,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeER    .    .    .    .    .    .   aesmc.16b	v9, v9
        // [2,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================eeER   .    .    .    .    .    .   aese.16b	v11, v26
        // [2,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeER .    .    .    .    .    .   aesmc.16b	v11, v11
        // [2,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================eeE-R .    .    .    .    .    .   aese.16b	v6, v21
        // [2,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================eeER.    .    .    .    .    .   aesmc.16b	v6, v6
        // [2,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeE-------R.    .    .    .    .    .   ext.16b	v1, v31, v31, #8
        // [2,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eeER    .    .    .    .    .   aese.16b	v11, v27
        // [2,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================================eeER   .    .    .    .    .   aese.16b	v9, v22
        // [2,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .   aesmc.16b	v9, v9
        // [2,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================eeE---------R .    .    .    .    .   eor.16b	v5, v1, v31
        // [2,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================================eeE-R .    .    .    .    .   eor.16b	v1, v0, v11
        // [2,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================================eeE-R .    .    .    .    .   aese.16b	v6, v22
        // [2,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================================eeER.    .    .    .    .   aesmc.16b	v6, v6
        // [2,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeER    .    .    .    .   aese.16b	v9, v23
        // [2,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================================eeER  .    .    .    .   aesmc.16b	v9, v9
        // [2,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================================eeE-R  .    .    .    .   aese.16b	v6, v23
        // [2,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeER .    .    .    .   aesmc.16b	v6, v6
        // [2,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================eeE----R .    .    .    .   rev64.16b	v29, v1
        // [2,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================eeE----R .    .    .    .   stur	q1, [x2, #-32]
        // [2,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .   aese.16b	v9, v24
        // [2,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================================eeER   .    .    .   aesmc.16b	v9, v9
        // [2,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeE-R   .    .    .   aese.16b	v6, v24
        // [2,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeER  .    .    .   aesmc.16b	v6, v6
        // [2,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeE------R  .    .    .   ext.16b	v1, v29, v29, #8
        // [2,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .   aese.16b	v9, v25
        // [2,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER    .    .   aesmc.16b	v9, v9
        // [2,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================================eeE-R    .    .   aese.16b	v6, v25
        // [2,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================================eeER   .    .   aesmc.16b	v6, v6
        // [2,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeE--------R   .    .   eor.16b	v2, v1, v29
        // [2,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeER  .    .   aese.16b	v9, v26
        // [2,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================================eeER.    .   aesmc.16b	v9, v9
        // [2,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================================eeE-R.    .   aese.16b	v6, v26
        // [2,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================================eeER    .   aesmc.16b	v6, v6
        // [2,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===================================================================eeER   .   aese.16b	v9, v27
        // [2,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================================eeER  .   aese.16b	v6, v27
        // [2,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================================eeER .   eor.16b	v0, v28, v9
        // [2,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================================eeER .   pmull.1q	v28, v31, v16
        // [2,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================================eeER.   eor.16b	v1, v10, v6
        // [2,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================================eeER.   pmull2.1q	v10, v31, v16
        // [2,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================================eeER   pmull.1q	v11, v29, v13
        // [2,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================================eeER   rev64.16b	v8, v0
        //
        //
        // Average Wait times (based on the timeline view):
        // [0]: Executions
        // [1]: Average time spent waiting in a scheduler's queue
        // [2]: Average time spent waiting in a scheduler's queue while ready
        // [3]: Average time elapsed from WB until retire stage
        //
        //       [0]    [1]    [2]    [3]
        // 0.     3     1.0    1.0    46.0      add	w7, w13, #0
        // 1.     3     1.0    1.0    45.3      add	w27, w13, #1
        // 2.     3     1.0    1.0    45.3      add	w23, w13, #2
        // 3.     3     1.7    1.7    45.0      add	w29, w13, #3
        // 4.     3     2.0    2.0    44.7      add	w13, w13, #4
        // 5.     3     1.7    0.3    44.7      rev	w7, w7
        // 6.     3     2.0    0.7    44.3      rev	w27, w27
        // 7.     3     2.3    1.0    44.0      rev	w23, w23
        // 8.     3     2.0    0.0    44.0      orr	x7, x12, x7, lsl #32
        // 9.     3     2.7    0.0    43.7      orr	x27, x12, x27, lsl #32
        // 10.    3     2.7    0.0    43.3      orr	x23, x12, x23, lsl #32
        // 11.    3     29.7   0.0    14.7      stp	x11, x7, [sp, #160]
        // 12.    3     1.7    1.0    42.7      rev	w7, w29
        // 13.    3     29.0   1.3    13.3      stp	x11, x27, [sp, #176]
        // 14.    3     1.7    0.7    40.7      orr	x7, x12, x7, lsl #32
        // 15.    3     2.0    2.0    38.0      ldr	q1, [sp, #160]
        // 16.    3     1.0    1.0    39.3      ldp	x27, x29, [x0, #16]
        // 17.    3     2.0    2.0    37.3      ldr	q6, [sp, #176]
        // 18.    3     28.7   0.0    14.7      stp	x11, x23, [sp, #192]
        // 19.    3     28.3   1.7    13.0      stp	x11, x7, [sp, #208]
        // 20.    3     41.0   37.3   0.0       aese.16b	v1, v18
        // 21.    3     43.0   0.0    0.0       aesmc.16b	v1, v1
        // 22.    3     1.7    0.0    41.7      eor	x7, x27, x20
        // 23.    3     1.7    0.0    41.7      eor	x27, x29, x21
        // 24.    3     41.3   37.3   1.0       aese.16b	v6, v18
        // 25.    3     43.3   0.0    0.0       aesmc.16b	v6, v6
        // 26.    3     26.7   0.3    16.7      stp	x7, x27, [sp, #176]
        // 27.    3     2.3    2.3    35.7      ldr	q9, [sp, #208]
        // 28.    3     42.0   0.0    0.0       aese.16b	v1, v19
        // 29.    3     43.3   0.0    0.0       aesmc.16b	v1, v1
        // 30.    3     2.3    2.3    37.7      ldr	q11, [sp, #192]
        // 31.    3     42.0   0.0    1.0       aese.16b	v6, v19
        // 32.    3     43.3   0.0    0.0       aesmc.16b	v6, v6
        // 33.    3     2.3    2.3    37.7      ldp	x7, x27, [x0, #48]
        // 34.    3     2.7    2.7    36.3      ldr	q10, [sp, #176]
        // 35.    3     42.7   0.0    0.0       aese.16b	v1, v20
        // 36.    3     44.0   0.0    0.0       aesmc.16b	v1, v1
        // 37.    3     42.3   0.0    1.0       aese.16b	v6, v20
        // 38.    3     43.0   0.0    0.0       aesmc.16b	v6, v6
        // 39.    3     2.7    2.7    37.7      ldp	x23, x29, [x0, #32]
        // 40.    3     43.3   0.0    0.0       aese.16b	v1, v21
        // 41.    3     45.3   0.0    0.0       aesmc.16b	v1, v1
        // 42.    3     3.0    0.7    42.3      eor	x7, x7, x20
        // 43.    3     3.0    0.7    41.0      eor	x27, x27, x21
        // 44.    3     42.0   39.3   1.0       aese.16b	v11, v18
        // 45.    3     43.3   0.0    0.0       aesmc.16b	v11, v11
        // 46.    3     16.7   1.3    25.0      stp	x7, x27, [sp, #208]
        // 47.    3     2.0    2.0    35.7      ldp	x7, x27, [x0], #64
        // 48.    3     40.0   0.0    0.0       aese.16b	v1, v22
        // 49.    3     40.7   0.0    0.0       aesmc.16b	v1, v1
        // 50.    3     3.3    0.7    38.3      eor	x23, x23, x20
        // 51.    3     3.3    0.7    37.7      eor	x29, x29, x21
        // 52.    3     39.0   0.0    1.0       aese.16b	v11, v19
        // 53.    3     40.7   0.0    0.0       aesmc.16b	v11, v11
        // 54.    3     13.3   0.0    28.3      stp	x23, x29, [sp, #192]
        // 55.    3     2.3    2.3    34.7      ldr	q28, [sp, #208]
        // 56.    3     39.7   0.0    0.0       aese.16b	v1, v23
        // 57.    3     41.7   0.0    0.0       aesmc.16b	v1, v1
        // 58.    3     2.7    0.7    39.7      eor	x7, x7, x20
        // 59.    3     39.7   0.0    1.0       aese.16b	v11, v20
        // 60.    3     41.0   0.0    0.0       aesmc.16b	v11, v11
        // 61.    3     3.0    1.0    37.7      eor	x27, x27, x21
        // 62.    3     2.3    2.3    33.7      ldr	q0, [sp, #192]
        // 63.    3     40.0   0.0    0.0       aese.16b	v1, v24
        // 64.    3     41.3   0.0    0.0       aesmc.16b	v1, v1
        // 65.    3     6.3    1.3    33.7      stp	x7, x27, [sp, #160]
        // 66.    3     38.0   37.0   1.0       aese.16b	v9, v18
        // 67.    3     40.0   0.0    0.0       aesmc.16b	v9, v9
        // 68.    3     40.3   0.0    0.0       aese.16b	v1, v25
        // 69.    3     41.7   0.0    0.0       aesmc.16b	v1, v1
        // 70.    3     39.3   4.0    1.0       aese.16b	v11, v21
        // 71.    3     41.0   0.0    0.0       aesmc.16b	v11, v11
        // 72.    3     2.3    2.3    35.0      ldr	q31, [sp, #160]
        // 73.    3     41.3   0.0    0.0       aese.16b	v1, v26
        // 74.    3     43.3   0.0    0.0       aesmc.16b	v1, v1
        // 75.    3     42.3   0.0    1.0       aese.16b	v11, v22
        // 76.    3     44.3   0.0    0.0       aesmc.16b	v11, v11
        // 77.    3     44.7   0.0    0.0       aese.16b	v1, v27
        // 78.    3     44.0   0.0    0.0       aese.16b	v11, v23
        // 79.    3     46.0   0.0    0.0       aesmc.16b	v11, v11
        // 80.    3     44.3   9.0    1.0       aese.16b	v9, v19
        // 81.    3     46.3   0.0    0.0       aesmc.16b	v9, v9
        // 82.    3     43.7   0.0    2.0       eor.16b	v1, v31, v1
        // 83.    3     45.3   0.0    0.0       aese.16b	v11, v24
        // 84.    3     47.3   0.0    0.0       aesmc.16b	v11, v11
        // 85.    3     45.7   0.0    1.0       aese.16b	v9, v20
        // 86.    3     47.3   0.0    0.0       aesmc.16b	v9, v9
        // 87.    3     42.7   0.0    4.0       rev64.16b	v31, v1
        // 88.    3     40.3   1.0    3.0       str	q1, [x2], #64
        // 89.    3     43.7   0.0    0.0       aese.16b	v11, v25
        // 90.    3     45.3   0.0    0.0       aesmc.16b	v11, v11
        // 91.    3     40.7   1.0    4.0       eor.16b	v31, v31, v30
        // 92.    3     43.7   0.0    1.0       aese.16b	v9, v21
        // 93.    3     45.0   0.0    0.0       aesmc.16b	v9, v9
        // 94.    3     46.0   0.0    0.0       aese.16b	v11, v26
        // 95.    3     48.0   0.0    0.0       aesmc.16b	v11, v11
        // 96.    3     47.0   37.0   1.0       aese.16b	v6, v21
        // 97.    3     49.0   0.0    0.0       aesmc.16b	v6, v6
        // 98.    3     41.7   0.0    7.0       ext.16b	v1, v31, v31, #8
        // 99.    3     49.7   0.0    0.0       aese.16b	v11, v27
        // 100.   3     50.7   4.0    0.0       aese.16b	v9, v22
        // 101.   3     52.0   0.0    0.0       aesmc.16b	v9, v9
        // 102.   3     43.0   0.0    9.0       eor.16b	v5, v1, v31
        // 103.   3     51.0   0.0    1.0       eor.16b	v1, v0, v11
        // 104.   3     51.0   1.0    1.0       aese.16b	v6, v22
        // 105.   3     53.0   0.0    0.0       aesmc.16b	v6, v6
        // 106.   3     53.7   0.0    0.0       aese.16b	v9, v23
        // 107.   3     55.7   0.0    0.0       aesmc.16b	v9, v9
        // 108.   3     54.7   0.0    1.0       aese.16b	v6, v23
        // 109.   3     56.0   0.0    0.0       aesmc.16b	v6, v6
        // 110.   3     52.0   0.0    4.0       rev64.16b	v29, v1
        // 111.   3     51.7   0.0    4.0       stur	q1, [x2, #-32]
        // 112.   3     56.7   0.0    0.0       aese.16b	v9, v24
        // 113.   3     58.7   0.0    0.0       aesmc.16b	v9, v9
        // 114.   3     57.0   0.0    1.0       aese.16b	v6, v24
        // 115.   3     59.0   0.0    0.0       aesmc.16b	v6, v6
        // 116.   3     52.7   0.0    6.0       ext.16b	v1, v29, v29, #8
        // 117.   3     59.7   0.0    0.0       aese.16b	v9, v25
        // 118.   3     61.7   0.0    0.0       aesmc.16b	v9, v9
        // 119.   3     60.7   0.0    1.0       aese.16b	v6, v25
        // 120.   3     62.7   0.0    0.0       aesmc.16b	v6, v6
        // 121.   3     54.7   0.0    8.0       eor.16b	v2, v1, v29
        // 122.   3     63.0   0.0    0.0       aese.16b	v9, v26
        // 123.   3     65.0   0.0    0.0       aesmc.16b	v9, v9
        // 124.   3     63.7   0.0    1.0       aese.16b	v6, v26
        // 125.   3     65.7   0.0    0.0       aesmc.16b	v6, v6
        // 126.   3     66.7   0.0    0.0       aese.16b	v9, v27
        // 127.   3     67.7   0.0    0.0       aese.16b	v6, v27
        // 128.   3     68.7   0.0    0.0       eor.16b	v0, v28, v9
        // 129.   3     68.7   31.0   0.0       pmull.1q	v28, v31, v16
        // 130.   3     69.0   0.0    0.0       eor.16b	v1, v10, v6
        // 131.   3     69.0   32.0   0.0       pmull2.1q	v10, v31, v16
        // 132.   3     69.7   19.0   0.0       pmull.1q	v11, v29, v13
        // 133.   3     69.7   0.0    0.0       rev64.16b	v8, v0
        //        3     35.8   2.5    11.7      <total>
        //
        //
        // ORIGINAL LLVM MCA STATISTICS (PREAMBLE) END
        //
        sub count, count, #1
cbz count, Lloop_unrolled_start_postamble
Lloop_unrolled_start:
                                                           // Instructions:    134
                                                           // Expected cycles: 54
                                                           // Expected IPC:    2.48
                                                           // ----------------- cycle (expected) ------------------>
                                                           // 0                        25                       50
                                                           // |------------------------|------------------------|---
        rev64 v4.16B, v1.16B                               // *.....................................................
        pmull2 v6.1q, v5.2d, v17.2d                        // *.....................................................
        ldp x19, x29, [x0, #16]                            // e.....................................................
        add w26, w13, #1                                   // e.....................................................
        pmull v31.1q, v8.1d, v12.1d                        // .*....................................................
        str q0, [x2, #-16]                                 // .*....................................................
        rev w24, w26                                       // .e....................................................
        add w30, w13, #2                                   // .e....................................................
        mov d9, v8.d[1]                                    // ..*...................................................
        pmull2 v3.1q, v4.2d, v15.2d                        // ..*...................................................
        orr x22, x12, x24, lsl #32                         // ..e...................................................
        rev w17, w30                                       // ..e...................................................
        pmull2 v30.1q, v29.2d, v13.2d                      // ...*..................................................
        mov d0, v4.d[1]                                    // ...*..................................................
        stp x11, x22, [sp, #STACK_BASE_AES_ST + 16]        // ...e.................................................. // @slothy:writes=stack_1
        orr x22, x12, x17, lsl #32                         // ...e..................................................
        pmull v5.1q, v4.1d, v15.1d                         // ....*.................................................
        eor v9.8B, v9.8B, v8.8B                            // ....*.................................................
        stp x11, x22, [sp, #STACK_BASE_AES_ST + 32]        // ....e................................................. // @slothy:writes=stack_2
        add w25, w13, #0                                   // ....e.................................................
        eor v29.8B, v0.8B, v4.8B                           // .....*................................................
        pmull2 v4.1q, v8.2d, v12.2d                        // .....*................................................
        add w22, w13, #3                                   // .....e................................................
        rev w7, w25                                        // .....e................................................
        pmull v9.1q, v9.1d, v14.1d                         // ......*...............................................
        ldr q8, [sp, #STACK_BASE_AES_ST + 16]              // ......e............................................... // @slothy:reads=stack_1
        orr x14, x12, x7, lsl #32                          // ......e...............................................
        rev w17, w22                                       // ......e...............................................
        pmull2 v0.1q, v2.2d, v14.2d                        // .......*..............................................
        ldr q2, [sp, #STACK_BASE_AES_ST + 32]              // .......e.............................................. // @slothy:reads=stack_2
        orr x28, x12, x17, lsl #32                         // .......e..............................................
        pmull v29.1q, v29.1d, v17.1d                       // ........*.............................................
        add w13, w13, #UNROLL                              // ........e.............................................
        eor x8, x29, x21                                   // ........e.............................................
        stp x11, x28, [sp, #STACK_BASE_AES_ST + 48]        // ........e............................................. // @slothy:writes=stack_3
        eor v11.16B, v31.16B, v11.16B                      // .........*............................................
        aesr v8.16b, v18.16b                               // .........e............................................
        stp x11, x14, [sp, #STACK_BASE_AES_ST]             // .........e............................................ // @slothy:writes=stack_0
        aesr v2.16b, v18.16b                               // ..........e...........................................
        eor v30.16B, v4.16B, v30.16B                       // ..........*...........................................
        eor x30, x19, x20                                  // ..........e...........................................
        ldp x10, x29, [x0, #48]                            // ..........e...........................................
        aesr v8.16b, v19.16b                               // ...........e..........................................
        ldr q4, [sp, #STACK_BASE_AES_ST + 48]              // ...........e.......................................... // @slothy:reads=stack_3
        aesr v2.16b, v19.16b                               // ............e.........................................
        eor v11.16B, v11.16B, v5.16B                       // ............*.........................................
        ldp x22, x23, [x0, #32]                            // ............e.........................................
        ldr q5, [sp, #STACK_BASE_AES_ST]                   // .............e........................................ // @slothy:reads=stack_0
        aesr v8.16b, v20.16b                               // .............e........................................
        eor x19, x29, x21                                  // .............e........................................
        eor v30.16B, v30.16B, v3.16B                       // ..............*.......................................
        aesr v2.16b, v20.16b                               // ..............e.......................................
        eor x29, x10, x20                                  // ..............e.......................................
        aesr v4.16b, v18.16b                               // ...............e......................................
        eor v11.16B, v11.16B, v28.16B                      // ...............*......................................
        eor x27, x23, x21                                  // ...............e......................................
        eor v3.16B, v9.16B, v0.16B                         // ................*.....................................
        aesr v2.16b, v21.16b                               // ................e.....................................
        ldp x24, x7, [x0], #(4*16)                         // ................e.....................................
        eor v0.16B, v30.16B, v10.16B                       // .................*....................................
        aesr v5.16b, v18.16b                               // .................e....................................
        eor v30.16B, v3.16B, v29.16B                       // ..................*...................................
        aesr v2.16b, v22.16b                               // ..................e...................................
        aesr v5.16b, v19.16b                               // ...................e..................................
        eor v10.16B, v11.16B, v0.16B                       // ...................*..................................
        eor x25, x22, x20                                  // ...................e..................................
        aesr v2.16b, v23.16b                               // ....................e.................................
        stp x25, x27, [sp, #STACK_BASE_AES_ST + 32]        // ....................e................................. // @slothy:writes=stack_2
        str q1, [x2, #-48]                                 // .....................*................................
        aesr v5.16b, v20.16b                               // .....................e................................
        eor x26, x24, x20                                  // .....................e................................
        aesr v2.16b, v24.16b                               // ......................e...............................
        ext v28.16B, v0.16B, v0.16B, #8                    // ......................*...............................
        stp x29, x19, [sp, #STACK_BASE_AES_ST + 48]        // ......................e............................... // @slothy:writes=stack_3
        eor v29.16B, v30.16B, v6.16B                       // .......................*..............................
        aesr v5.16b, v21.16b                               // .......................e..............................
        pmull v30.1q, v0.1d, v7.1d                         // ........................*.............................
        stp x30, x8, [sp, #STACK_BASE_AES_ST + 16]         // ........................e............................. // @slothy:writes=stack_1
        eor v6.16B, v29.16B, v10.16B                       // .........................*............................
        aesr v2.16b, v25.16b                               // .........................e............................
        eor v3.16B, v28.16B, v30.16B                       // ..........................*...........................
        aesr v5.16b, v22.16b                               // ..........................e...........................
        aesr v2.16b, v26.16b                               // ...........................e..........................
        ldr q30, [sp, #STACK_BASE_AES_ST + 32]             // ...........................e.......................... // @slothy:reads=stack_2
        eor v6.16B, v6.16B, v3.16B                         // ............................*.........................
        aesr v5.16b, v23.16b                               // ............................e.........................
        aesr v4.16b, v19.16b                               // .............................e........................
        ldr q28, [sp, #STACK_BASE_AES_ST + 48]             // .............................e........................ // @slothy:reads=stack_3
        aesr v5.16b, v24.16b                               // ..............................e.......................
        ext v0.16B, v6.16B, v6.16B, #8                     // ..............................*.......................
        pmull v1.1q, v6.1d, v7.1d                          // ...............................*......................
        aese v2.16b, v27.16b                               // ................................e.....................
        eor v1.16B, v11.16B, v1.16B                        // .................................*....................
        aesr v4.16b, v20.16b                               // .................................e....................
        eor v3.16B, v30.16B, v2.16B                        // ..................................e...................
        aesr v5.16b, v25.16b                               // ..................................e...................
        eor x17, x7, x21                                   // ..................................e...................
        eor v6.16B, v1.16B, v0.16B                         // ...................................*..................
        aesr v4.16b, v21.16b                               // ...................................e..................
        stp x26, x17, [sp, #STACK_BASE_AES_ST]             // ...................................e.................. // @slothy:writes=stack_0
        aesr v5.16b, v26.16b                               // ....................................e.................
        rev64 v29.16B, v3.16B                              // ....................................e.................
        aesr v8.16b, v21.16b                               // .....................................e................
        ext v30.16B, v6.16B, v6.16B, #8                    // .....................................*................
        ldr q11, [sp, #STACK_BASE_AES_ST]                  // ......................................e............... // @slothy:reads=stack_0
        aesr v4.16b, v22.16b                               // ......................................e...............
        aese v5.16b, v27.16b                               // .......................................e..............
        ext v10.16B, v29.16B, v29.16B, #8                  // .......................................e..............
        str q3, [x2, #32]                                  // ........................................e.............
        aesr v8.16b, v22.16b                               // ........................................e.............
        eor v9.16B, v11.16B, v5.16B                        // .........................................e............
        aesr v4.16b, v23.16b                               // .........................................e............
        ldr q1, [sp, #STACK_BASE_AES_ST + 16]              // ..........................................e........... // @slothy:reads=stack_1
        aesr v8.16b, v23.16b                               // ..........................................e...........
        aesr v4.16b, v24.16b                               // ...........................................e..........
        str q9, [x2], #(4*16)                              // ...........................................e..........
        rev64 v9.16B, v9.16B                               // ............................................e.........
        aesr v8.16b, v24.16b                               // ............................................e.........
        eor v2.16B, v10.16B, v29.16B                       // .............................................e........
        aesr v4.16b, v25.16b                               // .............................................e........
        eor v30.16B, v9.16B, v30.16B                       // ..............................................e.......
        aesr v8.16b, v25.16b                               // ..............................................e.......
        aesr v4.16b, v26.16b                               // ...............................................e......
        aesr v8.16b, v26.16b                               // ................................................e.....
        ext v6.16B, v30.16B, v30.16B, #8                   // ................................................e.....
        aese v4.16b, v27.16b                               // .................................................e....
        eor v5.16B, v6.16B, v30.16B                        // ..................................................e...
        aese v8.16b, v27.16b                               // ..................................................e...
        eor v0.16B, v28.16B, v4.16B                        // ...................................................e..
        pmull v28.1q, v30.1d, v16.1d                       // ...................................................e..
        pmull2 v10.1q, v30.2d, v16.2d                      // ....................................................e.
        eor v1.16B, v1.16B, v8.16B                         // ....................................................e.
        pmull v11.1q, v29.1d, v13.1d                       // .....................................................e
        rev64 v8.16B, v0.16B                               // .....................................................e

                                                                        // ------------------------------------ cycle (expected) ------------------------------------->
                                                                        // 0                        25                       50                       75
                                                                        // |------------------------|------------------------|------------------------|----------------
        // ldp x22, x23, [x0, #(3*16)]                                  // ..........e...........................................'.........~...........................
        // add        w14, w13, #3                                      // .....e................................................'....~................................
        // rev        w14, w14                                          // ......e...............................................'.....~...............................
        // orr        x14, x12, x14, lsl #32                            // .......e..............................................'......~..............................
        // stp        x11, x14, [sp, #(STACK_BASE_AES_ST + 3*16)]       // ........e.............................................'.......~.............................
        // ldr        q0, [sp, #(STACK_BASE_AES_ST + 3*16)]             // ...........e..........................................'..........~..........................
        // aesr v0.16b, v18.16b                                         // ...............e......................................'..............~......................
        // aesr v0.16b, v19.16b                                         // .............................e........................'............................~........
        // aesr v0.16b, v20.16b                                         // .................................e....................'................................~....
        // aesr v0.16b, v21.16b                                         // ...................................e..................'..................................~..
        // aesr v0.16b, v22.16b                                         // ......................................e...............'.....................................
        // aesr v0.16b, v23.16b                                         // .........................................e............'.....................................
        // aesr v0.16b, v24.16b                                         // ...........................................e..........'.....................................
        // aesr v0.16b, v25.16b                                         // .............................................e........'.....................................
        // aesr v0.16b, v26.16b                                         // ...............................................e......'.....................................
        // aese v0.16b, v27.16b                                         // .................................................e....'.....................................
        // eor x22, x22, x20                                            // ..............e.......................................'.............~.......................
        // eor x23, x23, x21                                            // .............e........................................'............~........................
        // stp x22, x23, [sp, #(STACK_BASE_AES_ST + 3*16)]              // ......................e...............................'.....................~...............
        // ldr q29, [sp, #(STACK_BASE_AES_ST + 3*16)]                   // .............................e........................'............................~........
        // eor v0.16b, v29.16b, v0.16b                                  // ...................................................e..'.....................................
        // str q0, [x2, #(3*16)]                                        // .~....................................................'*....................................
        // rev64 v0.16b, v0.16b                                         // .....................................................e'.....................................
        // pmull   v8.1q, v0.1d, v12.1d                                 // .~....................................................'*....................................
        // pmull2  v9.1q, v0.2d, v12.2d                                 // .....~................................................'....*................................
        // mov     d11, v0.d[1]                                         // ..~...................................................'.*...................................
        // eor     v11.8b, v11.8b, v0.8b                                // ....~.................................................'...*.................................
        // pmull   v10.1q, v11.1d, v14.1d                               // ......~...............................................'.....*...............................
        // ldp x22, x23, [x0, #(2*16)]                                  // ............e.........................................'...........~.........................
        // add        w14, w13, #2                                      // .e....................................................'~....................................
        // rev        w14, w14                                          // ..e...................................................'.~...................................
        // orr        x14, x12, x14, lsl #32                            // ...e..................................................'..~..................................
        // stp        x11, x14, [sp, #(STACK_BASE_AES_ST + 2*16)]       // ....e.................................................'...~.................................
        // ldr        q0, [sp, #(STACK_BASE_AES_ST + 2*16)]             // .......e..............................................'......~..............................
        // aesr v0.16b, v18.16b                                         // ..........e...........................................'.........~...........................
        // aesr v0.16b, v19.16b                                         // ............e.........................................'...........~.........................
        // aesr v0.16b, v20.16b                                         // ..............e.......................................'.............~.......................
        // aesr v0.16b, v21.16b                                         // ................e.....................................'...............~.....................
        // aesr v0.16b, v22.16b                                         // ..................e...................................'.................~...................
        // aesr v0.16b, v23.16b                                         // ....................e.................................'...................~.................
        // aesr v0.16b, v24.16b                                         // ......................e...............................'.....................~...............
        // aesr v0.16b, v25.16b                                         // .........................e............................'........................~............
        // aesr v0.16b, v26.16b                                         // ...........................e..........................'..........................~..........
        // aese v0.16b, v27.16b                                         // ................................e.....................'...............................~.....
        // eor x22, x22, x20                                            // ...................e..................................'..................~..................
        // eor x23, x23, x21                                            // ...............e......................................'..............~......................
        // stp x22, x23, [sp, #(STACK_BASE_AES_ST + 2*16)]              // ....................e.................................'...................~.................
        // ldr q29, [sp, #(STACK_BASE_AES_ST + 2*16)]                   // ...........................e..........................'..........................~..........
        // eor v0.16b, v29.16b, v0.16b                                  // ..................................e...................'.................................~...
        // str q0, [x2, #(2*16)]                                        // ........................................e.............'.....................................
        // rev64   v0.16b, v0.16b                                       // ....................................e.................'...................................~.
        // pmull   v11.1q, v0.1d, v13.1d                                // .....................................................e'.....................................
        // eor     v8.16b, v8.16b, v11.16b                              // .........~............................................'........*............................
        // pmull2  v11.1q, v0.2d, v13.2d                                // ...~..................................................'..*..................................
        // eor     v9.16b, v9.16b, v11.16b                              // ..........~...........................................'.........*...........................
        // ext     v11.16b, v0.16b, v0.16b, #8                          // .......................................e..............'.....................................
        // eor     v11.16b, v11.16b, v0.16b                             // .............................................e........'.....................................
        // pmull2  v11.1q, v11.2d, v14.2d                               // .......~..............................................'......*..............................
        // eor     v10.16b, v10.16b, v11.16b                            // ................~.....................................'...............*.....................
        // ldp x22, x23, [x0, #(1*16)]                                  // e.....................................................~.....................................
        // add        w14, w13, #1                                      // e.....................................................~.....................................
        // rev        w14, w14                                          // .e....................................................'~....................................
        // orr        x14, x12, x14, lsl #32                            // ..e...................................................'.~...................................
        // stp        x11, x14, [sp, #(STACK_BASE_AES_ST + 1*16)]       // ...e..................................................'..~..................................
        // ldr        q0, [sp, #(STACK_BASE_AES_ST + 1*16)]             // ......e...............................................'.....~...............................
        // aesr v0.16b, v18.16b                                         // .........e............................................'........~............................
        // aesr v0.16b, v19.16b                                         // ...........e..........................................'..........~..........................
        // aesr v0.16b, v20.16b                                         // .............e........................................'............~........................
        // aesr v0.16b, v21.16b                                         // .....................................e................'.....................................
        // aesr v0.16b, v22.16b                                         // ........................................e.............'.....................................
        // aesr v0.16b, v23.16b                                         // ..........................................e...........'.....................................
        // aesr v0.16b, v24.16b                                         // ............................................e.........'.....................................
        // aesr v0.16b, v25.16b                                         // ..............................................e.......'.....................................
        // aesr v0.16b, v26.16b                                         // ................................................e.....'.....................................
        // aese v0.16b, v27.16b                                         // ..................................................e...'.....................................
        // eor x22, x22, x20                                            // ..........e...........................................'.........~...........................
        // eor x23, x23, x21                                            // ........e.............................................'.......~.............................
        // stp x22, x23, [sp, #(STACK_BASE_AES_ST + 1*16)]              // ........................e.............................'.......................~.............
        // ldr q29, [sp, #(STACK_BASE_AES_ST + 1*16)]                   // ..........................................e...........'.....................................
        // eor v0.16b, v29.16b, v0.16b                                  // ....................................................e.'.....................................
        // str q0, [x2, #(1*16)]                                        // .....................~................................'....................*................
        // rev64   v0.16b, v0.16b                                       // ~.....................................................*.....................................
        // pmull   v11.1q, v0.1d, v15.1d                                // ....~.................................................'...*.................................
        // eor     v8.16b, v8.16b, v11.16b                              // ............~.........................................'...........*.........................
        // pmull2  v11.1q, v0.2d, v15.2d                                // ..~...................................................'.*...................................
        // eor     v9.16b, v9.16b, v11.16b                              // ..............~.......................................'.............*.......................
        // mov     d11, v0.d[1]                                         // ...~..................................................'..*..................................
        // eor     v11.8b, v11.8b, v0.8b                                // .....~................................................'....*................................
        // pmull   v11.1q, v11.1d, v17.1d                               // ........~.............................................'.......*.............................
        // eor     v10.16b, v10.16b, v11.16b                            // ..................~...................................'.................*...................
        // ldp x22, x23, [x0], #(4*16)                                  // ................e.....................................'...............~.....................
        // add        w14, w13, #0                                      // ....e.................................................'...~.................................
        // rev        w14, w14                                          // .....e................................................'....~................................
        // orr        x14, x12, x14, lsl #32                            // ......e...............................................'.....~...............................
        // stp        x11, x14, [sp, #(STACK_BASE_AES_ST + 0*16)]       // .........e............................................'........~............................
        // ldr        q0, [sp, #(STACK_BASE_AES_ST + 0*16)]             // .............e........................................'............~........................
        // aesr v0.16b, v18.16b                                         // .................e....................................'................~....................
        // aesr v0.16b, v19.16b                                         // ...................e..................................'..................~..................
        // aesr v0.16b, v20.16b                                         // .....................e................................'....................~................
        // aesr v0.16b, v21.16b                                         // .......................e..............................'......................~..............
        // aesr v0.16b, v22.16b                                         // ..........................e...........................'.........................~...........
        // aesr v0.16b, v23.16b                                         // ............................e.........................'...........................~.........
        // aesr v0.16b, v24.16b                                         // ..............................e.......................'.............................~.......
        // aesr v0.16b, v25.16b                                         // ..................................e...................'.................................~...
        // aesr v0.16b, v26.16b                                         // ....................................e.................'...................................~.
        // aese v0.16b, v27.16b                                         // .......................................e..............'.....................................
        // eor x22, x22, x20                                            // .....................e................................'....................~................
        // eor x23, x23, x21                                            // ..................................e...................'.................................~...
        // stp x22, x23, [sp, #(STACK_BASE_AES_ST + 0*16)]              // ...................................e..................'..................................~..
        // ldr q29, [sp, #(STACK_BASE_AES_ST + 0*16)]                   // ......................................e...............'.....................................
        // eor v0.16b, v29.16b, v0.16b                                  // .........................................e............'.....................................
        // str q0, [x2], #(4*16)                                        // ...........................................e..........'.....................................
        // rev64   v0.16b, v0.16b                                       // ............................................e.........'.....................................
        // eor   v0.16b, v0.16b, v30.16b                                // ..............................................e.......'.....................................
        // pmull   v11.1q, v0.1d, v16.1d                                // ...................................................e..'.....................................
        // eor     v8.16b, v8.16b, v11.16b                              // ...............~......................................'..............*......................
        // pmull2  v11.1q, v0.2d, v16.2d                                // ....................................................e.'.....................................
        // eor     v9.16b, v9.16b, v11.16b                              // .................~....................................'................*....................
        // ext     v11.16b, v0.16b, v0.16b, #8                          // ................................................e.....'.....................................
        // eor     v11.16b, v11.16b, v0.16b                             // ..................................................e...'.....................................
        // pmull2  v11.1q, v11.2d, v17.2d                               // ~.....................................................*.....................................
        // eor     v10.16b, v10.16b, v11.16b                            // .......................~..............................'......................*..............
        // eor        v0.16b, v8.16b,  v9.16b                           // ...................~..................................'..................*..................
        // pmull      v1.1q,  v9.1d,   v7.1d                            // ........................~.............................'.......................*.............
        // ext        v9.16b,    v9.16b,  v9.16b, #8                    // ......................~...............................'.....................*...............
        // eor        v10.16b,   v10.16b, v0.16b                        // .........................~............................'........................*............
        // eor        v1.16b, v9.16b,  v1.16b                           // ..........................~...........................'.........................*...........
        // eor        v10.16b,   v10.16b, v1.16b                        // ............................~.........................'...........................*.........
        // pmull      v9.1q,     v10.1d,  v7.1d                         // ...............................~......................'..............................*......
        // eor        v8.16b,    v8.16b,  v9.16b                        // .................................~....................'................................*....
        // ext        v10.16b,   v10.16b, v10.16b, #8                   // ..............................~.......................'.............................*.......
        // eor        v30.16b,     v8.16b,  v10.16b                     // ...................................~..................'..................................*..
        // ext        v30.16b, v30.16b, v30.16b, #8                     // .....................................~................'....................................*
        // add w13, w13, #UNROLL                                        // ........e.............................................'.......~.............................

        //
        // LLVM MCA STATISTICS (ORIGINAL) BEGIN
        //
        //
        // [0] Code Region
        //
        // Iterations:        100
        // Instructions:      17000
        // Total Cycles:      10342
        // Total uOps:        21200
        //
        // Dispatch Width:    8
        // uOps Per Cycle:    2.05
        // IPC:               1.64
        // Block RThroughput: 90.0
        //
        //
        // Cycles with backend pressure increase [ 18.09% ]
        // Throughput Bottlenecks:
        //   Resource Pressure       [ 10.84% ]
        //   - N1UnitL  [ 1.97% ]
        //   - N1UnitV0  [ 10.84% ]
        //   - N1UnitV1  [ 0.46% ]
        //   Data Dependencies:      [ 12.72% ]
        //   - Register Dependencies [ 12.72% ]
        //   - Memory Dependencies   [ 0.00% ]
        //
        // Critical sequence based on the simulation:
        //
        //               Instruction                                 Dependency Information
        //  +----< 144.  stp	x22, x23, [sp, #160]
        //  |
        //  |    < loop carried >
        //  |
        //  |      0.    ldp	x22, x23, [x0, #48]
        //  |      1.    add	w14, w13, #3
        //  |      2.    rev	w14, w14
        //  |      3.    orr	x14, x12, x14, lsl #32
        //  |      4.    stp	x11, x14, [sp, #208]
        //  +----> 5.    ldr	q0, [sp, #208]                    ## RESOURCE interference:  N1UnitL [ probability: 48% ]
        //  +----> 6.    aese.16b	v0, v18                           ## REGISTER dependency:  q0
        //  +----> 7.    aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 8.    aese.16b	v0, v19                           ## REGISTER dependency:  q0
        //  +----> 9.    aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 10.   aese.16b	v0, v20                           ## REGISTER dependency:  q0
        //  +----> 11.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 12.   aese.16b	v0, v21                           ## REGISTER dependency:  q0
        //  +----> 13.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 14.   aese.16b	v0, v22                           ## REGISTER dependency:  q0
        //  +----> 15.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 16.   aese.16b	v0, v23                           ## REGISTER dependency:  q0
        //  +----> 17.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 18.   aese.16b	v0, v24                           ## REGISTER dependency:  q0
        //  +----> 19.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 20.   aese.16b	v0, v25                           ## REGISTER dependency:  q0
        //  +----> 21.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 22.   aese.16b	v0, v26                           ## REGISTER dependency:  q0
        //  +----> 23.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 24.   aese.16b	v0, v27                           ## REGISTER dependency:  q0
        //  |      25.   eor	x22, x22, x20
        //  |      26.   eor	x23, x23, x21
        //  |      27.   stp	x22, x23, [sp, #208]
        //  |      28.   ldr	q29, [sp, #208]
        //  +----> 29.   eor.16b	v0, v29, v0                       ## REGISTER dependency:  q0
        //  |      30.   str	q0, [x2, #48]
        //  +----> 31.   rev64.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 32.   pmull.1q	v8, v0, v12                       ## REGISTER dependency:  q0
        //  +----> 33.   pmull2.1q	v9, v0, v12                       ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  +----> 34.   mov	d11, v0[1]                        ## RESOURCE interference:  N1UnitV0 [ probability: 48% ]
        //  |      35.   eor.8b	v11, v11, v0
        //  |      36.   pmull.1q	v10, v11, v14
        //  |      37.   ldp	x22, x23, [x0, #32]
        //  |      38.   add	w14, w13, #2
        //  |      39.   rev	w14, w14
        //  |      40.   orr	x14, x12, x14, lsl #32
        //  |      41.   stp	x11, x14, [sp, #192]
        //  |      42.   ldr	q0, [sp, #192]
        //  |      43.   aese.16b	v0, v18
        //  |      44.   aesmc.16b	v0, v0
        //  +----> 45.   aese.16b	v0, v19                           ## RESOURCE interference:  N1UnitV0 [ probability: 48% ]
        //  +----> 46.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 47.   aese.16b	v0, v20                           ## REGISTER dependency:  q0
        //  +----> 48.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 49.   aese.16b	v0, v21                           ## REGISTER dependency:  q0
        //  +----> 50.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 51.   aese.16b	v0, v22                           ## REGISTER dependency:  q0
        //  +----> 52.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 53.   aese.16b	v0, v23                           ## REGISTER dependency:  q0
        //  +----> 54.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 55.   aese.16b	v0, v24                           ## REGISTER dependency:  q0
        //  +----> 56.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 57.   aese.16b	v0, v25                           ## REGISTER dependency:  q0
        //  +----> 58.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 59.   aese.16b	v0, v26                           ## REGISTER dependency:  q0
        //  +----> 60.   aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 61.   aese.16b	v0, v27                           ## REGISTER dependency:  q0
        //  |      62.   eor	x22, x22, x20
        //  |      63.   eor	x23, x23, x21
        //  |      64.   stp	x22, x23, [sp, #192]
        //  |      65.   ldr	q29, [sp, #192]
        //  +----> 66.   eor.16b	v0, v29, v0                       ## REGISTER dependency:  q0
        //  |      67.   str	q0, [x2, #32]
        //  +----> 68.   rev64.16b	v0, v0                            ## REGISTER dependency:  q0
        //  |      69.   pmull.1q	v11, v0, v13
        //  |      70.   eor.16b	v8, v8, v11
        //  |      71.   pmull2.1q	v11, v0, v13
        //  |      72.   eor.16b	v9, v9, v11
        //  |      73.   ext.16b	v11, v0, v0, #8
        //  +----> 74.   eor.16b	v11, v11, v0                      ## REGISTER dependency:  q0
        //  |      75.   pmull2.1q	v11, v11, v14
        //  |      76.   eor.16b	v10, v10, v11
        //  |      77.   ldp	x22, x23, [x0, #16]
        //  |      78.   add	w14, w13, #1
        //  |      79.   rev	w14, w14
        //  |      80.   orr	x14, x12, x14, lsl #32
        //  |      81.   stp	x11, x14, [sp, #176]
        //  |      82.   ldr	q0, [sp, #176]
        //  |      83.   aese.16b	v0, v18
        //  |      84.   aesmc.16b	v0, v0
        //  |      85.   aese.16b	v0, v19
        //  |      86.   aesmc.16b	v0, v0
        //  |      87.   aese.16b	v0, v20
        //  |      88.   aesmc.16b	v0, v0
        //  |      89.   aese.16b	v0, v21
        //  |      90.   aesmc.16b	v0, v0
        //  |      91.   aese.16b	v0, v22
        //  |      92.   aesmc.16b	v0, v0
        //  |      93.   aese.16b	v0, v23
        //  |      94.   aesmc.16b	v0, v0
        //  |      95.   aese.16b	v0, v24
        //  |      96.   aesmc.16b	v0, v0
        //  |      97.   aese.16b	v0, v25
        //  |      98.   aesmc.16b	v0, v0
        //  +----> 99.   aese.16b	v0, v26                           ## RESOURCE interference:  N1UnitV0 [ probability: 48% ]
        //  +----> 100.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 101.  aese.16b	v0, v27                           ## REGISTER dependency:  q0
        //  |      102.  eor	x22, x22, x20
        //  |      103.  eor	x23, x23, x21
        //  |      104.  stp	x22, x23, [sp, #176]
        //  |      105.  ldr	q29, [sp, #176]
        //  +----> 106.  eor.16b	v0, v29, v0                       ## REGISTER dependency:  q0
        //  |      107.  str	q0, [x2, #16]
        //  +----> 108.  rev64.16b	v0, v0                            ## REGISTER dependency:  q0
        //  |      109.  pmull.1q	v11, v0, v15
        //  |      110.  eor.16b	v8, v8, v11
        //  |      111.  pmull2.1q	v11, v0, v15
        //  |      112.  eor.16b	v9, v9, v11
        //  |      113.  mov	d11, v0[1]
        //  +----> 114.  eor.8b	v11, v11, v0                      ## REGISTER dependency:  q0
        //  |      115.  pmull.1q	v11, v11, v17
        //  |      116.  eor.16b	v10, v10, v11
        //  |      117.  ldp	x22, x23, [x0], #64
        //  |      118.  add	w14, w13, #0
        //  |      119.  rev	w14, w14
        //  |      120.  orr	x14, x12, x14, lsl #32
        //  |      121.  stp	x11, x14, [sp, #160]
        //  |      122.  ldr	q0, [sp, #160]
        //  |      123.  aese.16b	v0, v18
        //  |      124.  aesmc.16b	v0, v0
        //  +----> 125.  aese.16b	v0, v19                           ## RESOURCE interference:  N1UnitV0 [ probability: 48% ]
        //  +----> 126.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 127.  aese.16b	v0, v20                           ## REGISTER dependency:  q0
        //  +----> 128.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 129.  aese.16b	v0, v21                           ## REGISTER dependency:  q0
        //  +----> 130.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 131.  aese.16b	v0, v22                           ## REGISTER dependency:  q0
        //  +----> 132.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 133.  aese.16b	v0, v23                           ## REGISTER dependency:  q0
        //  +----> 134.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 135.  aese.16b	v0, v24                           ## REGISTER dependency:  q0
        //  +----> 136.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 137.  aese.16b	v0, v25                           ## REGISTER dependency:  q0
        //  +----> 138.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 139.  aese.16b	v0, v26                           ## REGISTER dependency:  q0
        //  +----> 140.  aesmc.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 141.  aese.16b	v0, v27                           ## REGISTER dependency:  q0
        //  |      142.  eor	x22, x22, x20
        //  |      143.  eor	x23, x23, x21
        //  |      144.  stp	x22, x23, [sp, #160]
        //  |      145.  ldr	q29, [sp, #160]
        //  +----> 146.  eor.16b	v0, v29, v0                       ## REGISTER dependency:  q0
        //  |      147.  str	q0, [x2], #64
        //  +----> 148.  rev64.16b	v0, v0                            ## REGISTER dependency:  q0
        //  +----> 149.  eor.16b	v0, v0, v30                       ## REGISTER dependency:  q0
        //  +----> 150.  pmull.1q	v11, v0, v16                      ## REGISTER dependency:  q0
        //  |      151.  eor.16b	v8, v8, v11
        //  +----> 152.  pmull2.1q	v11, v0, v16                      ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  +----> 153.  eor.16b	v9, v9, v11                       ## REGISTER dependency:  q11
        //  |      154.  ext.16b	v11, v0, v0, #8
        //  |      155.  eor.16b	v11, v11, v0
        //  |      156.  pmull2.1q	v11, v11, v17
        //  |      157.  eor.16b	v10, v10, v11
        //  +----> 158.  eor.16b	v0, v8, v9                        ## REGISTER dependency:  q9
        //  +----> 159.  pmull.1q	v1, v9, v7                        ## RESOURCE interference:  N1UnitV0 [ probability: 48% ]
        //  |      160.  ext.16b	v9, v9, v9, #8
        //  |      161.  eor.16b	v10, v10, v0
        //  +----> 162.  eor.16b	v1, v9, v1                        ## REGISTER dependency:  q1
        //  +----> 163.  eor.16b	v10, v10, v1                      ## REGISTER dependency:  q1
        //  |      164.  pmull.1q	v9, v10, v7
        //  |      165.  eor.16b	v8, v8, v9
        //  +----> 166.  ext.16b	v10, v10, v10, #8                 ## REGISTER dependency:  q10
        //  +----> 167.  eor.16b	v30, v8, v10                      ## REGISTER dependency:  q10
        //  +----> 168.  ext.16b	v30, v30, v30, #8                 ## REGISTER dependency:  q30
        //         169.  add	w13, w13, #4
        //
        //
        // Instruction Info:
        // [1]: #uOps
        // [2]: Latency
        // [3]: RThroughput
        // [4]: MayLoad
        // [5]: MayStore
        // [6]: HasSideEffects (U)
        //
        // [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
        //  2      4     1.00    *                   ldp	x22, x23, [x0, #48]
        //  1      1     0.33                        add	w14, w13, #3
        //  1      1     0.33                        rev	w14, w14
        //  1      1     0.33                        orr	x14, x12, x14, lsl #32
        //  3      1     1.00           *            stp	x11, x14, [sp, #208]
        //  2      5     0.50    *                   ldr	q0, [sp, #208]
        //  1      2     1.00                        aese.16b	v0, v18
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v19
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v20
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v21
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v22
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v23
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v24
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v25
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v26
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v27
        //  1      1     0.33                        eor	x22, x22, x20
        //  1      1     0.33                        eor	x23, x23, x21
        //  3      1     1.00           *            stp	x22, x23, [sp, #208]
        //  2      5     0.50    *                   ldr	q29, [sp, #208]
        //  1      2     0.50                        eor.16b	v0, v29, v0
        //  4      2     1.00           *            str	q0, [x2, #48]
        //  1      2     0.50                        rev64.16b	v0, v0
        //  1      2     1.00                        pmull.1q	v8, v0, v12
        //  1      2     1.00                        pmull2.1q	v9, v0, v12
        //  1      2     0.50                        mov	d11, v0[1]
        //  1      2     0.50                        eor.8b	v11, v11, v0
        //  1      2     1.00                        pmull.1q	v10, v11, v14
        //  2      4     1.00    *                   ldp	x22, x23, [x0, #32]
        //  1      1     0.33                        add	w14, w13, #2
        //  1      1     0.33                        rev	w14, w14
        //  1      1     0.33                        orr	x14, x12, x14, lsl #32
        //  3      1     1.00           *            stp	x11, x14, [sp, #192]
        //  2      5     0.50    *                   ldr	q0, [sp, #192]
        //  1      2     1.00                        aese.16b	v0, v18
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v19
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v20
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v21
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v22
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v23
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v24
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v25
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v26
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v27
        //  1      1     0.33                        eor	x22, x22, x20
        //  1      1     0.33                        eor	x23, x23, x21
        //  3      1     1.00           *            stp	x22, x23, [sp, #192]
        //  2      5     0.50    *                   ldr	q29, [sp, #192]
        //  1      2     0.50                        eor.16b	v0, v29, v0
        //  4      2     1.00           *            str	q0, [x2, #32]
        //  1      2     0.50                        rev64.16b	v0, v0
        //  1      2     1.00                        pmull.1q	v11, v0, v13
        //  1      2     0.50                        eor.16b	v8, v8, v11
        //  1      2     1.00                        pmull2.1q	v11, v0, v13
        //  1      2     0.50                        eor.16b	v9, v9, v11
        //  1      2     0.50                        ext.16b	v11, v0, v0, #8
        //  1      2     0.50                        eor.16b	v11, v11, v0
        //  1      2     1.00                        pmull2.1q	v11, v11, v14
        //  1      2     0.50                        eor.16b	v10, v10, v11
        //  2      4     1.00    *                   ldp	x22, x23, [x0, #16]
        //  1      1     0.33                        add	w14, w13, #1
        //  1      1     0.33                        rev	w14, w14
        //  1      1     0.33                        orr	x14, x12, x14, lsl #32
        //  3      1     1.00           *            stp	x11, x14, [sp, #176]
        //  2      5     0.50    *                   ldr	q0, [sp, #176]
        //  1      2     1.00                        aese.16b	v0, v18
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v19
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v20
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v21
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v22
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v23
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v24
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v25
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v26
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v27
        //  1      1     0.33                        eor	x22, x22, x20
        //  1      1     0.33                        eor	x23, x23, x21
        //  3      1     1.00           *            stp	x22, x23, [sp, #176]
        //  2      5     0.50    *                   ldr	q29, [sp, #176]
        //  1      2     0.50                        eor.16b	v0, v29, v0
        //  4      2     1.00           *            str	q0, [x2, #16]
        //  1      2     0.50                        rev64.16b	v0, v0
        //  1      2     1.00                        pmull.1q	v11, v0, v15
        //  1      2     0.50                        eor.16b	v8, v8, v11
        //  1      2     1.00                        pmull2.1q	v11, v0, v15
        //  1      2     0.50                        eor.16b	v9, v9, v11
        //  1      2     0.50                        mov	d11, v0[1]
        //  1      2     0.50                        eor.8b	v11, v11, v0
        //  1      2     1.00                        pmull.1q	v11, v11, v17
        //  1      2     0.50                        eor.16b	v10, v10, v11
        //  3      4     1.00    *                   ldp	x22, x23, [x0], #64
        //  1      1     0.33                        add	w14, w13, #0
        //  1      1     0.33                        rev	w14, w14
        //  1      1     0.33                        orr	x14, x12, x14, lsl #32
        //  3      1     1.00           *            stp	x11, x14, [sp, #160]
        //  2      5     0.50    *                   ldr	q0, [sp, #160]
        //  1      2     1.00                        aese.16b	v0, v18
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v19
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v20
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v21
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v22
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v23
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v24
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v25
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v26
        //  1      2     1.00                        aesmc.16b	v0, v0
        //  1      2     1.00                        aese.16b	v0, v27
        //  1      1     0.33                        eor	x22, x22, x20
        //  1      1     0.33                        eor	x23, x23, x21
        //  3      1     1.00           *            stp	x22, x23, [sp, #160]
        //  2      5     0.50    *                   ldr	q29, [sp, #160]
        //  1      2     0.50                        eor.16b	v0, v29, v0
        //  5      2     1.00           *            str	q0, [x2], #64
        //  1      2     0.50                        rev64.16b	v0, v0
        //  1      2     0.50                        eor.16b	v0, v0, v30
        //  1      2     1.00                        pmull.1q	v11, v0, v16
        //  1      2     0.50                        eor.16b	v8, v8, v11
        //  1      2     1.00                        pmull2.1q	v11, v0, v16
        //  1      2     0.50                        eor.16b	v9, v9, v11
        //  1      2     0.50                        ext.16b	v11, v0, v0, #8
        //  1      2     0.50                        eor.16b	v11, v11, v0
        //  1      2     1.00                        pmull2.1q	v11, v11, v17
        //  1      2     0.50                        eor.16b	v10, v10, v11
        //  1      2     0.50                        eor.16b	v0, v8, v9
        //  1      2     1.00                        pmull.1q	v1, v9, v7
        //  1      2     0.50                        ext.16b	v9, v9, v9, #8
        //  1      2     0.50                        eor.16b	v10, v10, v0
        //  1      2     0.50                        eor.16b	v1, v9, v1
        //  1      2     0.50                        eor.16b	v10, v10, v1
        //  1      2     1.00                        pmull.1q	v9, v10, v7
        //  1      2     0.50                        eor.16b	v8, v8, v9
        //  1      2     0.50                        ext.16b	v10, v10, v10, #8
        //  1      2     0.50                        eor.16b	v30, v8, v10
        //  1      2     0.50                        ext.16b	v30, v30, v30, #8
        //  1      1     0.33                        add	w13, w13, #4
        //
        //
        // Dynamic Dispatch Stall Cycles:
        // RAT     - Register unavailable:                      0
        // RCU     - Retire tokens unavailable:                 8613  (83.3%)
        // SCHEDQ  - Scheduler full:                            0
        // LQ      - Load queue full:                           0
        // SQ      - Store queue full:                          0
        // GROUP   - Static restrictions on the dispatch group: 0
        // USH     - Uncategorised Structural Hazard:           0
        //
        //
        // Dispatch Logic - number of cycles where we saw N micro opcodes dispatched:
        // [# dispatched], [# cycles]
        //  0,              4707  (45.5%)
        //  1,              2431  (23.5%)
        //  2,              352  (3.4%)
        //  3,              597  (5.8%)
        //  4,              200  (1.9%)
        //  5,              155  (1.5%)
        //  6,              248  (2.4%)
        //  7,              5  (0.0%)
        //  8,              1647  (15.9%)
        //
        //
        // Schedulers - number of cycles where we saw N micro opcodes issued:
        // [# issued], [# cycles]
        //  0,          183  (1.8%)
        //  1,          6107  (59.1%)
        //  2,          1852  (17.9%)
        //  3,          657  (6.4%)
        //  4,          348  (3.4%)
        //  5,          446  (4.3%)
        //  6,          148  (1.4%)
        //  7,          100  (1.0%)
        //  8,          401  (3.9%)
        //  9,          1  (0.0%)
        //  10,          98  (0.9%)
        //  11,          1  (0.0%)
        //
        // Scheduler's queue usage:
        // No scheduler resources used.
        //
        //
        // Retire Control Unit - number of cycles where we saw N instructions retired:
        // [# retired], [# cycles]
        //  0,           4719  (45.6%)
        //  1,           3904  (37.7%)
        //  2,           759  (7.3%)
        //  3,           349  (3.4%)
        //  4,           52  (0.5%)
        //  5,           256  (2.5%)
        //  11,          48  (0.5%)
        //  12,          1  (0.0%)
        //  13,          50  (0.5%)
        //  16,          2  (0.0%)
        //  18,          1  (0.0%)
        //  20,          2  (0.0%)
        //  21,          1  (0.0%)
        //  22,          1  (0.0%)
        //  25,          51  (0.5%)
        //  26,          1  (0.0%)
        //  31,          48  (0.5%)
        //  35,          1  (0.0%)
        //  50,          48  (0.5%)
        //  52,          48  (0.5%)
        //
        // Total ROB Entries:                128
        // Max Used ROB Entries:             128  ( 100.0% )
        // Average Used ROB Entries per cy:  123  ( 96.1% )
        //
        //
        // Register File statistics:
        // Total number of mappings created:    16400
        // Max number of mappings used:         104
        //
        //
        // Resources:
        // [0]   - N1UnitB
        // [1.0] - N1UnitD
        // [1.1] - N1UnitD
        // [2.0] - N1UnitL
        // [2.1] - N1UnitL
        // [3]   - N1UnitM
        // [4.0] - N1UnitS
        // [4.1] - N1UnitS
        // [5]   - N1UnitV0
        // [6]   - N1UnitV1
        //
        //
        // Resource pressure per iteration:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]
        //  -     4.00   4.00   19.98  20.02  7.44   11.78  11.78  102.03 30.97
        //
        // Resource pressure by instruction:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]    Instructions:
        //  -      -      -     1.00   1.00    -      -      -      -      -     ldp	x22, x23, [x0, #48]
        //  -      -      -      -      -      -     0.50   0.50    -      -     add	w14, w13, #3
        //  -      -      -      -      -      -     0.50   0.50    -      -     rev	w14, w14
        //  -      -      -      -      -     0.01   0.50   0.49    -      -     orr	x14, x12, x14, lsl #32
        //  -      -     1.00   1.02   0.98    -      -      -      -      -     stp	x11, x14, [sp, #208]
        //  -      -      -     0.50   0.50    -     0.49   0.51    -      -     ldr	q0, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v27
        //  -      -      -      -      -      -     0.51   0.49    -      -     eor	x22, x22, x20
        //  -      -      -      -      -      -     0.49   0.51    -      -     eor	x23, x23, x21
        //  -     1.00    -     0.96   1.04    -      -      -      -      -     stp	x22, x23, [sp, #208]
        //  -      -      -     0.51   0.49   0.99   0.01    -      -      -     ldr	q29, [sp, #208]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v29, v0
        //  -      -      -     1.00   1.00    -      -      -     1.04   0.96   str	q0, [x2, #48]
        //  -      -      -      -      -      -      -      -     0.48   0.52   rev64.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v8, v0, v12
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v9, v0, v12
        //  -      -      -      -      -      -      -      -     0.48   0.52   mov	d11, v0[1]
        //  -      -      -      -      -      -      -      -     0.48   0.52   eor.8b	v11, v11, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v10, v11, v14
        //  -      -      -     1.02   0.98    -      -      -      -      -     ldp	x22, x23, [x0, #32]
        //  -      -      -      -      -      -     0.50   0.50    -      -     add	w14, w13, #2
        //  -      -      -      -      -      -     0.50   0.50    -      -     rev	w14, w14
        //  -      -      -      -      -     0.49   0.25   0.26    -      -     orr	x14, x12, x14, lsl #32
        //  -      -     1.00   1.00   1.00    -      -      -      -      -     stp	x11, x14, [sp, #192]
        //  -      -      -     0.49   0.51    -     0.51   0.49    -      -     ldr	q0, [sp, #192]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v27
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x22, x22, x20
        //  -      -      -      -      -     0.01   0.50   0.49    -      -     eor	x23, x23, x21
        //  -     1.00    -     1.00   1.00    -      -      -      -      -     stp	x22, x23, [sp, #192]
        //  -      -      -     0.52   0.48   0.99    -     0.01    -      -     ldr	q29, [sp, #192]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v29, v0
        //  -      -      -     0.96   1.04    -      -      -     2.00    -     str	q0, [x2, #32]
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v0, v13
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v8, v8, v11
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v11, v0, v13
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v9, v9, v11
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v11, v0, v0, #8
        //  -      -      -      -      -      -      -      -     1.00    -     eor.16b	v11, v11, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v11, v11, v14
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v10, v11
        //  -      -      -     1.02   0.98    -      -      -      -      -     ldp	x22, x23, [x0, #16]
        //  -      -      -      -      -      -     0.50   0.50    -      -     add	w14, w13, #1
        //  -      -      -      -      -     0.98   0.01   0.01    -      -     rev	w14, w14
        //  -      -      -      -      -     0.02   0.49   0.49    -      -     orr	x14, x12, x14, lsl #32
        //  -      -     1.00   1.04   0.96    -      -      -      -      -     stp	x11, x14, [sp, #176]
        //  -      -      -     0.49   0.51    -     0.50   0.50    -      -     ldr	q0, [sp, #176]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v27
        //  -      -      -      -      -     0.98   0.01   0.01    -      -     eor	x22, x22, x20
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x23, x23, x21
        //  -     1.00    -     0.96   1.04    -      -      -      -      -     stp	x22, x23, [sp, #176]
        //  -      -      -     0.50   0.50   0.02   0.49   0.49    -      -     ldr	q29, [sp, #176]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v29, v0
        //  -      -      -     1.00   1.00    -      -      -     2.00    -     str	q0, [x2, #16]
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v0, v15
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v8, v8, v11
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v11, v0, v15
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v9, v9, v11
        //  -      -      -      -      -      -      -      -      -     1.00   mov	d11, v0[1]
        //  -      -      -      -      -      -      -      -     1.00    -     eor.8b	v11, v11, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v11, v17
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v10, v11
        //  -      -      -     1.02   0.98   0.98   0.01   0.01    -      -     ldp	x22, x23, [x0], #64
        //  -      -      -      -      -      -     0.50   0.50    -      -     add	w14, w13, #0
        //  -      -      -      -      -     0.97   0.02   0.01    -      -     rev	w14, w14
        //  -      -      -      -      -      -     0.50   0.50    -      -     orr	x14, x12, x14, lsl #32
        //  -      -     1.00   1.00   1.00    -      -      -      -      -     stp	x11, x14, [sp, #160]
        //  -      -      -     0.49   0.51    -     0.50   0.50    -      -     ldr	q0, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v0, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v0, v27
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     eor	x22, x22, x20
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x23, x23, x21
        //  -     1.00    -     1.00   1.00    -      -      -      -      -     stp	x22, x23, [sp, #160]
        //  -      -      -     0.52   0.48   0.99   0.01    -      -      -     ldr	q29, [sp, #160]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v29, v0
        //  -      -      -     0.96   1.04    -     0.50   0.50    -     2.00   str	q0, [x2], #64
        //  -      -      -      -      -      -      -      -     1.00    -     rev64.16b	v0, v0
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v0, v30
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v0, v16
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v8, v8, v11
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v11, v0, v16
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v9, v9, v11
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v11, v0, v0, #8
        //  -      -      -      -      -      -      -      -     1.00    -     eor.16b	v11, v11, v0
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v11, v11, v17
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v10, v11
        //  -      -      -      -      -      -      -      -     0.48   0.52   eor.16b	v0, v8, v9
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v1, v9, v7
        //  -      -      -      -      -      -      -      -     0.52   0.48   ext.16b	v9, v9, v9, #8
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v10, v0
        //  -      -      -      -      -      -      -      -     0.52   0.48   eor.16b	v1, v9, v1
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v10, v1
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v9, v10, v7
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v8, v8, v9
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v10, v10, v10, #8
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v8, v10
        //  -      -      -      -      -      -      -      -     0.02   0.98   ext.16b	v30, v30, v30, #8
        //  -      -      -      -      -      -     0.49   0.51    -      -     add	w13, w13, #4
        //
        //
        // Timeline view:
        //                     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789
        // Index     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          01234567
        //
        // [0,0]     DeeeeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #48]
        // [0,1]     DeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #3
        // [0,2]     D=eE--R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [0,3]     D==eE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [0,4]     D===eER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #208]
        // [0,5]     .DeeeeeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #208]
        // [0,6]     .D=====eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [0,7]     .D=======eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,8]     .D=========eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [0,9]     .D===========eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,10]    .D=============eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [0,11]    .D===============eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,12]    . D================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [0,13]    . D==================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,14]    . D====================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [0,15]    . D======================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,16]    . D========================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [0,17]    . D==========================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,18]    . D============================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [0,19]    . D==============================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,20]    .  D===============================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [0,21]    .  D=================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,22]    .  D===================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [0,23]    .  D=====================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,24]    .  D=======================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [0,25]    .  D=eE---------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [0,26]    .  D=eE---------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [0,27]    .   D=eE--------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #208]
        // [0,28]    .   DeeeeeE-----------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #208]
        // [0,29]    .   D========================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [0,30]    .    D=========================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #48]
        // [0,31]    .    D=========================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [0,32]    .    D===========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v8, v0, v12
        // [0,33]    .    D============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v9, v0, v12
        // [0,34]    .    D===========================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [0,35]    .    .D============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [0,36]    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v10, v11, v14
        // [0,37]    .    .DeeeeE--------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #32]
        // [0,38]    .    .DeE-----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #2
        // [0,39]    .    .D=eE----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [0,40]    .    .D==eE---------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [0,41]    .    . D=======================================eE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #192]
        // [0,42]    .    . DeeeeeE------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #192]
        // [0,43]    .    . D======eeE---------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [0,44]    .    . D========eeE-------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,45]    .    . D==========eeE-----------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [0,46]    .    .  D===========eeE---------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,47]    .    .  D=============eeE-------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [0,48]    .    .  D===============eeE-----------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,49]    .    .  D=================eeE---------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [0,50]    .    .  D===================eeE-------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,51]    .    .  D=====================eeE-----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [0,52]    .    .  D=======================eeE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,53]    .    .  D=========================eeE-------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [0,54]    .    .   D==========================eeE-----------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,55]    .    .   D============================eeE---------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [0,56]    .    .   D==============================eeE-------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,57]    .    .   D================================eeE-----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [0,58]    .    .   D==================================eeE---------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,59]    .    .   D====================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [0,60]    .    .   D=========================================eeE--R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,61]    .    .   D============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [0,62]    .    .    DeE--------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [0,63]    .    .    DeE--------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [0,64]    .    .    D======================================eE------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #192]
        // [0,65]    .    .    DeeeeeE----------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #192]
        // [0,66]    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [0,67]    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #32]
        // [0,68]    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [0,69]    .    .    .D================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v13
        // [0,70]    .    .    .D==================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [0,71]    .    .    .D=================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v13
        // [0,72]    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [0,73]    .    .    . D===============================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v11, v0, v0, #8
        // [0,74]    .    .    . D=================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v11, v11, v0
        // [0,75]    .    .    . D===================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v11, v14
        // [0,76]    .    .    . D=====================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [0,77]    .    .    . DeeeeE---------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #16]
        // [0,78]    .    .    . DeE------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #1
        // [0,79]    .    .    .  DeE-----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [0,80]    .    .    .  D=eE----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [0,81]    .    .    .  D============================================eE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #176]
        // [0,82]    .    .    .  DeeeeeE-------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #176]
        // [0,83]    .    .    .  D===============================eeE---------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [0,84]    .    .    .   D=====================================eeE--------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,85]    .    .    .   D========================================eeE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [0,86]    .    .    .   D==========================================eeE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,87]    .    .    .   D================================================eeE---R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [0,88]    .    .    .   D==================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,89]    .    .    .   D====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [0,90]    .    .    .   D======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,91]    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [0,92]    .    .    .    D=========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,93]    .    .    .    D===========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [0,94]    .    .    .    D=============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,95]    .    .    .    D===============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [0,96]    .    .    .    D=================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,97]    .    .    .    D===================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [0,98]    .    .    .    D=====================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,99]    .    .    .    D=======================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [0,100]   .    .    .    .D========================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,101]   .    .    .    .D==========================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [0,102]   .    .    .    .DeE---------------------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [0,103]   .    .    .    .DeE---------------------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [0,104]   .    .    .    .D===========================================eE--------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #176]
        // [0,105]   .    .    .    . DeeeeeE----------------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #176]
        // [0,106]   .    .    .    . D===========================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [0,107]   .    .    .    . D=============================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #16]
        // [0,108]   .    .    .    . D=============================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [0,109]   .    .    .    .  D==============================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v15
        // [0,110]   .    .    .    .  D================================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [0,111]   .    .    .    .  D===============================================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v15
        // [0,112]   .    .    .    .  D=================================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [0,113]   .    .    .    .    D============================================================================eeE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [0,114]   .    .    .    .    . D============================================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [0,115]   .    .    .    .    .   D============================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v11, v17
        // [0,116]   .    .    .    .    .    .D============================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [0,117]   .    .    .    .    .    .    . DeeeeE--------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0], #64
        // [0,118]   .    .    .    .    .    .    .   DeE---------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #0
        // [0,119]   .    .    .    .    .    .    .    .DeE-------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [0,120]   .    .    .    .    .    .    .    .  DeE-----------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [0,121]   .    .    .    .    .    .    .    .    .   D==================================================eE---------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #160]
        // [0,122]   .    .    .    .    .    .    .    .    .    .D==eeeeeE---------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #160]
        // [0,123]   .    .    .    .    .    .    .    .    .    .D=========eeE-----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [0,124]   .    .    .    .    .    .    .    .    .    .D===================eeE-------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,125]   .    .    .    .    .    .    .    .    .    .D=====================eeE-----------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [0,126]   .    .    .    .    .    .    .    .    .    .D=======================eeE---------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,127]   .    .    .    .    .    .    .    .    .    .D=========================eeE-------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [0,128]   .    .    .    .    .    .    .    .    .    .D===========================eeE-----------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,129]   .    .    .    .    .    .    .    .    .    .  D===========================eeE---------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [0,130]   .    .    .    .    .    .    .    .    .    .    D===========================eeE-------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,131]   .    .    .    .    .    .    .    .    .    .    D=============================eeE-----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [0,132]   .    .    .    .    .    .    .    .    .    .    D===============================eeE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,133]   .    .    .    .    .    .    .    .    .    .    D=================================eeE-------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [0,134]   .    .    .    .    .    .    .    .    .    .    D===================================eeE-----------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,135]   .    .    .    .    .    .    .    .    .    .    . D===================================eeE---------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [0,136]   .    .    .    .    .    .    .    .    .    .    .  D====================================eeE-------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,137]   .    .    .    .    .    .    .    .    .    .    .  D======================================eeE-----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [0,138]   .    .    .    .    .    .    .    .    .    .    .   D=======================================eeE---------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,139]   .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [0,140]   .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [0,141]   .    .    .    .    .    .    .    .    .    .    .    .D===============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [0,142]   .    .    .    .    .    .    .    .    .    .    .    .DeE------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [0,143]   .    .    .    .    .    .    .    .    .    .    .    .DeE------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [0,144]   .    .    .    .    .    .    .    .    .    .    .    .D========================================eE--------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #160]
        // [0,145]   .    .    .    .    .    .    .    .    .    .    .    . D==eeeeeE-----------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #160]
        // [0,146]   .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [0,147]   .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2], #64
        // [0,148]   .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [0,149]   .    .    .    .    .    .    .    .    .    .    .    .  D===================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v0, v30
        // [0,150]   .    .    .    .    .    .    .    .    .    .    .    .  D=====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v16
        // [0,151]   .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [0,152]   .    .    .    .    .    .    .    .    .    .    .    .  D======================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v16
        // [0,153]   .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [0,154]   .    .    .    .    .    .    .    .    .    .    .    .  D=====================================================eeE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v11, v0, v0, #8
        // [0,155]   .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v11, v11, v0
        // [0,156]   .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v11, v17
        // [0,157]   .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [0,158]   .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v8, v9
        // [0,159]   .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v1, v9, v7
        // [0,160]   .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v9, v9, v9, #8
        // [0,161]   .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v0
        // [0,162]   .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v1, v9, v1
        // [0,163]   .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v1
        // [0,164]   .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v9, v10, v7
        // [0,165]   .    .    .    .    .    .    .    .    .    .    .    .    D=================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v9
        // [0,166]   .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v10, v10, v10, #8
        // [0,167]   .    .    .    .    .    .    .    .    .    .    .    .    D===================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v30, v8, v10
        // [0,168]   .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v30, v30, v30, #8
        // [0,169]   .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w13, w13, #4
        // [1,0]     .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeE------------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #48]
        // [1,1]     .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #3
        // [1,2]     .    .    .    .    .    .    .    .    .    .    .    .    .D=eE--------------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [1,3]     .    .    .    .    .    .    .    .    .    .    .    .    .D==eE-------------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [1,4]     .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================eE-----------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #208]
        // [1,5]     .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #208]
        // [1,6]     .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================eeE-------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [1,7]     .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================eeE---------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,8]     .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================eeE-------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [1,9]     .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE-----------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,10]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================eeE---------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [1,11]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================eeE-------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,12]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeE---------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [1,13]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================eeE-----------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,14]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================================eeE---------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [1,15]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeE-------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,16]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================================eeE-----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [1,17]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================================eeE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,18]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [1,19]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,20]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [1,21]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,22]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [1,23]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,24]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [1,25]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE----------------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [1,26]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [1,27]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===============================eE--------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #208]
        // [1,28]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeeE-------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #208]
        // [1,29]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [1,30]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #48]
        // [1,31]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [1,32]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v8, v0, v12
        // [1,33]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v9, v0, v12
        // [1,34]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [1,35]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [1,36]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v10, v11, v14
        // [1,37]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==eeeeE----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #32]
        // [1,38]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #2
        // [1,39]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeE-----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [1,40]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=eE----------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [1,41]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eE-------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #192]
        // [1,42]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeeE---------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #192]
        // [1,43]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======eeE-----------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [1,44]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================eeE-----------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,45]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================eeE-------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [1,46]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================eeE-----------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,47]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================eeE---------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [1,48]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================eeE-------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,49]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================eeE-----------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [1,50]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================eeE---------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,51]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================eeE-------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [1,52]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================eeE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,53]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================eeE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [1,54]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================eeE-------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,55]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [1,56]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,57]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [1,58]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,59]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [1,60]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [1,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [1,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [1,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================================eE----------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #192]
        // [1,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=eeeeeE-------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #192]
        // [1,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [1,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #32]
        // [1,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [1,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v13
        // [1,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [1,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v13
        // [1,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [1,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================================================eeE---R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v11, v0, v0, #8
        // [1,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v11, v11, v0
        // [1,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v11, v14
        // [1,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [1,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeE-------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #16]
        // [1,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #1
        // [1,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [1,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eE--------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [1,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================eE---------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #176]
        // [1,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE-----------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #176]
        // [1,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================eeE-------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [1,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================eeE------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================eeE---------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [1,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================eeE-------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================================eeE-----------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [1,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==========================================eeE-------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [1,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================eeE-----------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeE---------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [1,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================eeE---R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [1,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [1,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=======================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [1,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [1,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [1,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeE--------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [1,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeE--------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [1,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================eE----------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #176]
        // [1,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeeE----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #176]
        // [1,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [1,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #16]
        // [1,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [1,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v15
        // [1,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [1,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v15
        // [1,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [1,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [1,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [1,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v11, v17
        // [1,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [1,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeE---------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0], #64
        // [1,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-----------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #0
        // [1,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eE----------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [1,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==eE---------------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [1,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #160]
        // [1,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==eeeeeE---------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #160]
        // [1,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================eeE-------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [1,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================eeE---------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================eeE-------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [1,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================eeE-----------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================eeE---------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [1,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE-------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================eeE-----------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [1,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================eeE---------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================eeE-------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [1,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================eeE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================eeE---------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [1,134]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeE---R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,135]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [1,136]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,137]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [1,138]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,139]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [1,140]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [1,141]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [1,142]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE----------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [1,143]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE----------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [1,144]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================eE------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #160]
        // [1,145]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE-----------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #160]
        // [1,146]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [1,147]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2], #64
        // [1,148]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [1,149]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v0, v30
        // [1,150]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v16
        // [1,151]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [1,152]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v16
        // [1,153]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [1,154]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v11, v0, v0, #8
        // [1,155]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v11, v11, v0
        // [1,156]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v11, v17
        // [1,157]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [1,158]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v8, v9
        // [1,159]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v1, v9, v7
        // [1,160]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v9, v9, v9, #8
        // [1,161]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v0
        // [1,162]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v1, v9, v1
        // [1,163]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v1
        // [1,164]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v9, v10, v7
        // [1,165]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v9
        // [1,166]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================================eeE--R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v10, v10, v10, #8
        // [1,167]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v30, v8, v10
        // [1,168]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v30, v30, v30, #8
        // [1,169]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w13, w13, #4
        // [2,0]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeE------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #48]
        // [2,1]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE---------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #3
        // [2,2]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=eE--------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [2,3]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==eE-------------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [2,4]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==========================================eE-----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #208]
        // [2,5]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #208]
        // [2,6]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================eeE-----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [2,7]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================eeE-------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,8]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=========================eeE-----------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [2,9]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================eeE---------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,10]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================eeE-------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [2,11]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================eeE-----------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,12]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================eeE---------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [2,13]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================eeE-------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,14]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================eeE-----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [2,15]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================eeE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,16]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeE-------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [2,17]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D============================================eeE---------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,18]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [2,19]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================eeE---------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,20]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [2,21]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================================================eeE-----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,22]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [2,23]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==========================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,24]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [2,25]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [2,26]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [2,27]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D======================================eE----------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #208]
        // [2,28]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE-------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #208]
        // [2,29]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [2,30]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #48]
        // [2,31]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [2,32]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v8, v0, v12
        // [2,33]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v9, v0, v12
        // [2,34]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [2,35]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [2,36]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v10, v11, v14
        // [2,37]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==eeeeE----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #32]
        // [2,38]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE-------------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #2
        // [2,39]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [2,40]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eE----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [2,41]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================eE-------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #192]
        // [2,42]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE---------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #192]
        // [2,43]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============eeE-----------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [2,44]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================eeE-------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,45]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================eeE-------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [2,46]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,47]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================eeE-------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [2,48]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================eeE-----------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,49]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================eeE---------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [2,50]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE-------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,51]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================eeE--R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [2,52]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,53]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [2,54]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,55]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [2,56]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,57]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [2,58]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,59]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [2,60]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [2,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE---------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [2,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE---------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [2,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================eE------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #192]
        // [2,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE----------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #192]
        // [2,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [2,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #32]
        // [2,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [2,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v13
        // [2,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [2,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v13
        // [2,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [2,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeE---R    .    .    .    .    .    .    .    .    .    .    .    .    . .   ext.16b	v11, v0, v0, #8
        // [2,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v11, v11, v0
        // [2,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v11, v14
        // [2,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [2,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==eeeeE------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0, #16]
        // [2,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE-----------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   add	w14, w13, #1
        // [2,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [2,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE-------------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [2,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eE---------R .    .    .    .    .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #176]
        // [2,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE---------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #176]
        // [2,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================eeE---------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [2,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================eeE--------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================eeE-----------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [2,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================eeE---------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================eeE-------------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [2,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================eeE-----------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================eeE---------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [2,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================eeE-------------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================eeE-----------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [2,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================eeE---------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE-------------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [2,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================eeE-----------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================eeE---------R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [2,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeE---R .    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [2,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================================eeER   .    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v26
        // [2,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================================eeER .    .    .    .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeER    .    .    .    .    .    .    .    .    .    .    . .   aese.16b	v0, v27
        // [2,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE----------------------------------------------R    .    .    .    .    .    .    .    .    .    .    . .   eor	x22, x22, x20
        // [2,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE----------------------------------------------R    .    .    .    .    .    .    .    .    .    .    . .   eor	x23, x23, x21
        // [2,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================eE--------------R    .    .    .    .    .    .    .    .    .    .    . .   stp	x22, x23, [sp, #176]
        // [2,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE------------------------------------------R    .    .    .    .    .    .    .    .    .    .    . .   ldr	q29, [sp, #176]
        // [2,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================================eeER  .    .    .    .    .    .    .    .    .    .    . .   eor.16b	v0, v29, v0
        // [2,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    . .   str	q0, [x2, #16]
        // [2,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeER.    .    .    .    .    .    .    .    .    .    . .   rev64.16b	v0, v0
        // [2,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==================================================eeER   .    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v0, v15
        // [2,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    . .   eor.16b	v8, v8, v11
        // [2,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================================eeE-R .    .    .    .    .    .    .    .    .    . .   pmull2.1q	v11, v0, v15
        // [2,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================eeER.    .    .    .    .    .    .    .    .    . .   eor.16b	v9, v9, v11
        // [2,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeE---R.    .    .    .    .    .    .    .    .    . .   mov	d11, v0[1]
        // [2,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===================================================eeE-R.    .    .    .    .    .    .    .    .    . .   eor.8b	v11, v11, v0
        // [2,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================================eeER    .    .    .    .    .    .    .    .    . .   pmull.1q	v11, v11, v17
        // [2,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    . .   eor.16b	v10, v10, v11
        // [2,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=eeeeE----------------------------------------------------R  .    .    .    .    .    .    .    .    . .   ldp	x22, x23, [x0], #64
        // [2,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE-------------------------------------------------------R  .    .    .    .    .    .    .    .    . .   add	w14, w13, #0
        // [2,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=eE------------------------------------------------------R  .    .    .    .    .    .    .    .    . .   rev	w14, w14
        // [2,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==eE-----------------------------------------------------R  .    .    .    .    .    .    .    .    . .   orr	x14, x12, x14, lsl #32
        // [2,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================eE---------R  .    .    .    .    .    .    .    .    . .   stp	x11, x14, [sp, #160]
        // [2,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==eeeeeE-------------------------------------------------R  .    .    .    .    .    .    .    .    . .   ldr	q0, [sp, #160]
        // [2,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================eeE-----------------------------R  .    .    .    .    .    .    .    .    . .   aese.16b	v0, v18
        // [2,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================eeE-------------------R  .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================eeE-----------------R  .    .    .    .    .    .    .    .    . .   aese.16b	v0, v19
        // [2,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================eeE---------------R  .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================eeE-------------R  .    .    .    .    .    .    .    .    . .   aese.16b	v0, v20
        // [2,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================eeE-----------R  .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeE---------R  .    .    .    .    .    .    .    .    . .   aese.16b	v0, v21
        // [2,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================eeE---R  .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================================eeE-R  .    .    .    .    .    .    .    .    . .   aese.16b	v0, v22
        // [2,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================================eeER .    .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    . .   aese.16b	v0, v23
        // [2,134]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================================eeER  .    .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,135]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .    .    .    .    . .   aese.16b	v0, v24
        // [2,136]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==========================================================eeER   .    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,137]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    . .   aese.16b	v0, v25
        // [2,138]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================================eeER    .    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,139]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================================================eeER  .    .    .    .    .    . .   aese.16b	v0, v26
        // [2,140]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================================================eeER.    .    .    .    .    . .   aesmc.16b	v0, v0
        // [2,141]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=================================================================eeER   .    .    .    .    . .   aese.16b	v0, v27
        // [2,142]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE------------------------------------------------------------------R   .    .    .    .    . .   eor	x22, x22, x20
        // [2,143]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE------------------------------------------------------------------R   .    .    .    .    . .   eor	x23, x23, x21
        // [2,144]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================eE--------------------------R   .    .    .    .    . .   stp	x22, x23, [sp, #160]
        // [2,145]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeeeeeE-------------------------------------------------------------R   .    .    .    .    . .   ldr	q29, [sp, #160]
        // [2,146]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==================================================================eeER .    .    .    .    . .   eor.16b	v0, v29, v0
        // [2,147]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================================eeER    .    .    .    . .   str	q0, [x2], #64
        // [2,148]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===================================================================eeER    .    .    .    . .   rev64.16b	v0, v0
        // [2,149]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================================eeER  .    .    .    . .   eor.16b	v0, v0, v30
        // [2,150]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================================eeER.    .    .    . .   pmull.1q	v11, v0, v16
        // [2,151]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=========================================================================eeER   .    .    . .   eor.16b	v8, v8, v11
        // [2,152]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================================================eeE-R   .    .    . .   pmull2.1q	v11, v0, v16
        // [2,153]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=========================================================================eeER  .    .    . .   eor.16b	v9, v9, v11
        // [2,154]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================================eeE---R  .    .    . .   ext.16b	v11, v0, v0, #8
        // [2,155]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================================eeE-R  .    .    . .   eor.16b	v11, v11, v0
        // [2,156]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================================eeER .    .    . .   pmull2.1q	v11, v11, v17
        // [2,157]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D====================================================================eeER    .    . .   eor.16b	v10, v10, v11
        // [2,158]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=================================================================eeE-R    .    . .   eor.16b	v0, v8, v9
        // [2,159]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===============================================================eeE-R    .    . .   pmull.1q	v1, v9, v7
        // [2,160]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER    .    . .   ext.16b	v9, v9, v9, #8
        // [2,161]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================================eeER  .    . .   eor.16b	v10, v10, v0
        // [2,162]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================================eeER  .    . .   eor.16b	v1, v9, v1
        // [2,163]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================================eeER.    . .   eor.16b	v10, v10, v1
        // [2,164]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================================eeER   . .   pmull.1q	v9, v10, v7
        // [2,165]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================================eeER . .   eor.16b	v8, v8, v9
        // [2,166]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================================eeE--R . .   ext.16b	v10, v10, v10, #8
        // [2,167]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================================eeER .   eor.16b	v30, v8, v10
        // [2,168]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================================eeER   ext.16b	v30, v30, v30, #8
        // [2,169]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeE-----------------------------------------------------------------------R   add	w13, w13, #4
        //
        //
        // Average Wait times (based on the timeline view):
        // [0]: Executions
        // [1]: Average time spent waiting in a scheduler's queue
        // [2]: Average time spent waiting in a scheduler's queue while ready
        // [3]: Average time elapsed from WB until retire stage
        //
        //       [0]    [1]    [2]    [3]
        // 0.     3     1.0    1.0    44.0      ldp	x22, x23, [x0, #48]
        // 1.     3     1.0    0.7    47.0      add	w14, w13, #3
        // 2.     3     2.0    0.0    46.0      rev	w14, w14
        // 3.     3     3.0    0.0    45.0      orr	x14, x12, x14, lsl #32
        // 4.     3     30.0   0.0    15.3      stp	x11, x14, [sp, #208]
        // 5.     3     1.0    1.0    40.0      ldr	q0, [sp, #208]
        // 6.     3     16.7   10.7   28.0      aese.16b	v0, v18
        // 7.     3     23.3   5.3    21.3      aesmc.16b	v0, v0
        // 8.     3     24.0   0.0    20.0      aese.16b	v0, v19
        // 9.     3     26.0   0.0    18.7      aesmc.16b	v0, v0
        // 10.    3     28.0   0.0    17.3      aese.16b	v0, v20
        // 11.    3     30.0   0.0    16.0      aesmc.16b	v0, v0
        // 12.    3     32.3   0.7    14.0      aese.16b	v0, v21
        // 13.    3     35.0   0.7    12.0      aesmc.16b	v0, v0
        // 14.    3     37.0   0.0    10.7      aese.16b	v0, v22
        // 15.    3     39.0   0.0    9.3       aesmc.16b	v0, v0
        // 16.    3     40.3   0.0    8.0       aese.16b	v0, v23
        // 17.    3     43.0   0.7    6.0       aesmc.16b	v0, v0
        // 18.    3     45.7   0.7    4.0       aese.16b	v0, v24
        // 19.    3     47.7   0.0    3.0       aesmc.16b	v0, v0
        // 20.    3     49.3   0.0    2.3       aese.16b	v0, v25
        // 21.    3     51.3   0.0    1.7       aesmc.16b	v0, v0
        // 22.    3     53.3   0.0    1.0       aese.16b	v0, v26
        // 23.    3     55.3   0.0    0.3       aesmc.16b	v0, v0
        // 24.    3     56.7   0.0    0.0       aese.16b	v0, v27
        // 25.    3     1.3    0.7    56.3      eor	x22, x22, x20
        // 26.    3     1.3    0.7    56.0      eor	x23, x23, x21
        // 27.    3     24.3   1.3    30.7      stp	x22, x23, [sp, #208]
        // 28.    3     1.0    1.0    48.3      ldr	q29, [sp, #208]
        // 29.    3     53.0   0.0    0.0       eor.16b	v0, v29, v0
        // 30.    3     49.3   0.0    0.0       str	q0, [x2, #48]
        // 31.    3     48.0   0.0    0.0       rev64.16b	v0, v0
        // 32.    3     50.0   0.0    0.0       pmull.1q	v8, v0, v12
        // 33.    3     51.0   1.0    0.0       pmull2.1q	v9, v0, v12
        // 34.    3     50.0   0.0    1.0       mov	d11, v0[1]
        // 35.    3     51.7   0.0    0.0       eor.8b	v11, v11, v0
        // 36.    3     53.7   0.0    0.0       pmull.1q	v10, v11, v14
        // 37.    3     2.3    2.3    49.3      ldp	x22, x23, [x0, #32]
        // 38.    3     1.0    1.0    52.3      add	w14, w13, #2
        // 39.    3     1.3    0.7    50.7      rev	w14, w14
        // 40.    3     2.3    0.0    49.7      orr	x14, x12, x14, lsl #32
        // 41.    3     44.7   0.0    7.0       stp	x11, x14, [sp, #192]
        // 42.    3     1.0    1.0    44.0      ldr	q0, [sp, #192]
        // 43.    3     9.7    3.7    38.3      aese.16b	v0, v18
        // 44.    3     15.0   4.0    32.3      aesmc.16b	v0, v0
        // 45.    3     21.0   4.0    26.3      aese.16b	v0, v19
        // 46.    3     23.3   0.7    23.7      aesmc.16b	v0, v0
        // 47.    3     24.7   0.0    21.7      aese.16b	v0, v20
        // 48.    3     25.3   0.0    19.7      aesmc.16b	v0, v0
        // 49.    3     27.3   0.0    17.7      aese.16b	v0, v21
        // 50.    3     29.3   0.0    15.7      aesmc.16b	v0, v0
        // 51.    3     32.3   1.0    12.7      aese.16b	v0, v22
        // 52.    3     34.7   0.3    10.7      aesmc.16b	v0, v0
        // 53.    3     36.7   0.0    9.3       aese.16b	v0, v23
        // 54.    3     38.3   0.0    8.0       aesmc.16b	v0, v0
        // 55.    3     41.3   1.0    5.7       aese.16b	v0, v24
        // 56.    3     43.0   0.3    4.3       aesmc.16b	v0, v0
        // 57.    3     45.0   0.0    3.7       aese.16b	v0, v25
        // 58.    3     47.0   0.0    3.0       aesmc.16b	v0, v0
        // 59.    3     49.0   0.0    2.3       aese.16b	v0, v26
        // 60.    3     52.0   1.0    0.7       aesmc.16b	v0, v0
        // 61.    3     54.3   0.3    0.0       aese.16b	v0, v27
        // 62.    3     1.0    0.7    54.0      eor	x22, x22, x20
        // 63.    3     1.0    0.7    54.0      eor	x23, x23, x21
        // 64.    3     39.0   2.0    15.3      stp	x22, x23, [sp, #192]
        // 65.    3     1.3    1.3    49.0      ldr	q29, [sp, #192]
        // 66.    3     55.3   0.0    0.0       eor.16b	v0, v29, v0
        // 67.    3     56.3   0.0    0.0       str	q0, [x2, #32]
        // 68.    3     56.3   0.0    0.0       rev64.16b	v0, v0
        // 69.    3     57.7   0.0    0.0       pmull.1q	v11, v0, v13
        // 70.    3     59.0   0.0    0.0       eor.16b	v8, v8, v11
        // 71.    3     57.3   1.0    1.0       pmull2.1q	v11, v0, v13
        // 72.    3     58.0   0.0    0.0       eor.16b	v9, v9, v11
        // 73.    3     55.0   0.0    3.0       ext.16b	v11, v0, v0, #8
        // 74.    3     57.0   0.0    1.0       eor.16b	v11, v11, v0
        // 75.    3     59.0   0.0    0.0       pmull2.1q	v11, v11, v14
        // 76.    3     61.0   0.0    0.0       eor.16b	v10, v10, v11
        // 77.    3     1.7    1.7    57.3      ldp	x22, x23, [x0, #16]
        // 78.    3     1.0    1.0    61.0      add	w14, w13, #1
        // 79.    3     1.0    0.3    59.7      rev	w14, w14
        // 80.    3     1.7    0.3    58.3      orr	x14, x12, x14, lsl #32
        // 81.    3     51.0   0.0    9.0       stp	x11, x14, [sp, #176]
        // 82.    3     1.0    1.0    55.0      ldr	q0, [sp, #176]
        // 83.    3     27.3   22.7   30.3      aese.16b	v0, v18
        // 84.    3     32.7   5.0    23.3      aesmc.16b	v0, v0
        // 85.    3     34.3   1.0    20.3      aese.16b	v0, v19
        // 86.    3     36.3   0.0    18.3      aesmc.16b	v0, v0
        // 87.    3     39.0   1.3    15.0      aese.16b	v0, v20
        // 88.    3     41.0   0.0    13.0      aesmc.16b	v0, v0
        // 89.    3     43.0   0.0    11.3      aese.16b	v0, v21
        // 90.    3     44.3   0.0    10.0      aesmc.16b	v0, v0
        // 91.    3     45.0   0.0    8.7       aese.16b	v0, v22
        // 92.    3     48.0   1.3    6.0       aesmc.16b	v0, v0
        // 93.    3     50.0   0.0    4.7       aese.16b	v0, v23
        // 94.    3     52.0   0.0    3.7       aesmc.16b	v0, v0
        // 95.    3     52.7   0.0    3.0       aese.16b	v0, v24
        // 96.    3     56.0   1.3    1.0       aesmc.16b	v0, v0
        // 97.    3     56.7   0.0    0.3       aese.16b	v0, v25
        // 98.    3     57.3   0.0    0.0       aesmc.16b	v0, v0
        // 99.    3     58.0   0.0    0.0       aese.16b	v0, v26
        // 100.   3     59.7   0.0    0.0       aesmc.16b	v0, v0
        // 101.   3     60.3   0.0    0.0       aese.16b	v0, v27
        // 102.   3     1.0    0.7    59.0      eor	x22, x22, x20
        // 103.   3     1.0    0.7    59.0      eor	x23, x23, x21
        // 104.   3     37.3   2.0    22.7      stp	x22, x23, [sp, #176]
        // 105.   3     1.0    1.0    54.7      ldr	q29, [sp, #176]
        // 106.   3     60.7   0.0    0.0       eor.16b	v0, v29, v0
        // 107.   3     62.0   0.0    0.0       str	q0, [x2, #16]
        // 108.   3     62.0   0.0    0.0       rev64.16b	v0, v0
        // 109.   3     63.7   0.0    0.0       pmull.1q	v11, v0, v15
        // 110.   3     65.7   0.0    0.0       eor.16b	v8, v8, v11
        // 111.   3     64.7   1.0    1.0       pmull2.1q	v11, v0, v15
        // 112.   3     66.0   0.0    0.0       eor.16b	v9, v9, v11
        // 113.   3     62.3   0.0    3.0       mov	d11, v0[1]
        // 114.   3     63.7   0.0    1.0       eor.8b	v11, v11, v0
        // 115.   3     65.0   0.0    0.0       pmull.1q	v11, v11, v17
        // 116.   3     66.3   0.0    0.0       eor.16b	v10, v10, v11
        // 117.   3     1.3    1.3    61.0      ldp	x22, x23, [x0], #64
        // 118.   3     1.0    1.0    63.0      add	w14, w13, #0
        // 119.   3     1.7    0.3    61.7      rev	w14, w14
        // 120.   3     2.3    0.3    60.3      orr	x14, x12, x14, lsl #32
        // 121.   3     49.7   0.0    9.0       stp	x11, x14, [sp, #160]
        // 122.   3     3.0    3.0    50.3      ldr	q0, [sp, #160]
        // 123.   3     18.3   10.7   37.7      aese.16b	v0, v18
        // 124.   3     28.3   8.0    27.7      aesmc.16b	v0, v0
        // 125.   3     30.3   0.0    25.7      aese.16b	v0, v19
        // 126.   3     32.3   0.0    23.7      aesmc.16b	v0, v0
        // 127.   3     34.3   0.0    21.7      aese.16b	v0, v20
        // 128.   3     36.3   0.0    19.7      aesmc.16b	v0, v0
        // 129.   3     37.0   0.0    17.7      aese.16b	v0, v21
        // 130.   3     38.7   1.3    14.3      aesmc.16b	v0, v0
        // 131.   3     40.7   0.0    12.3      aese.16b	v0, v22
        // 132.   3     42.7   0.0    10.7      aesmc.16b	v0, v0
        // 133.   3     44.7   0.0    9.3       aese.16b	v0, v23
        // 134.   3     48.0   1.3    6.7       aesmc.16b	v0, v0
        // 135.   3     48.0   0.0    5.3       aese.16b	v0, v24
        // 136.   3     49.0   0.0    4.3       aesmc.16b	v0, v0
        // 137.   3     51.0   0.0    3.7       aese.16b	v0, v25
        // 138.   3     52.0   0.0    3.0       aesmc.16b	v0, v0
        // 139.   3     53.3   1.3    1.0       aese.16b	v0, v26
        // 140.   3     55.3   0.0    0.3       aesmc.16b	v0, v0
        // 141.   3     57.3   0.0    0.0       aese.16b	v0, v27
        // 142.   3     1.0    1.0    57.3      eor	x22, x22, x20
        // 143.   3     1.0    1.0    57.3      eor	x23, x23, x21
        // 144.   3     41.0   2.0    17.3      stp	x22, x23, [sp, #160]
        // 145.   3     1.7    1.7    51.7      ldr	q29, [sp, #160]
        // 146.   3     58.3   0.0    0.0       eor.16b	v0, v29, v0
        // 147.   3     60.3   0.0    0.0       str	q0, [x2], #64
        // 148.   3     59.3   0.0    0.0       rev64.16b	v0, v0
        // 149.   3     61.3   0.0    0.0       eor.16b	v0, v0, v30
        // 150.   3     63.3   0.0    0.0       pmull.1q	v11, v0, v16
        // 151.   3     65.3   0.0    0.0       eor.16b	v8, v8, v11
        // 152.   3     64.3   1.0    1.0       pmull2.1q	v11, v0, v16
        // 153.   3     66.0   0.0    0.0       eor.16b	v9, v9, v11
        // 154.   3     62.3   0.0    3.0       ext.16b	v11, v0, v0, #8
        // 155.   3     63.7   0.0    1.0       eor.16b	v11, v11, v0
        // 156.   3     64.3   0.0    0.0       pmull2.1q	v11, v11, v17
        // 157.   3     65.7   0.0    0.0       eor.16b	v10, v10, v11
        // 158.   3     63.3   0.0    1.0       eor.16b	v0, v8, v9
        // 159.   3     62.0   0.0    1.0       pmull.1q	v1, v9, v7
        // 160.   3     61.7   1.0    0.0       ext.16b	v9, v9, v9, #8
        // 161.   3     62.3   0.0    0.0       eor.16b	v10, v10, v0
        // 162.   3     62.3   0.0    0.0       eor.16b	v1, v9, v1
        // 163.   3     64.3   0.0    0.0       eor.16b	v10, v10, v1
        // 164.   3     66.0   0.0    0.0       pmull.1q	v9, v10, v7
        // 165.   3     68.0   0.0    0.0       eor.16b	v8, v8, v9
        // 166.   3     66.0   0.0    2.0       ext.16b	v10, v10, v10, #8
        // 167.   3     70.0   0.0    0.0       eor.16b	v30, v8, v10
        // 168.   3     72.0   0.0    0.0       ext.16b	v30, v30, v30, #8
        // 169.   3     1.0    1.0    70.7      add	w13, w13, #4
        //        3     39.1   0.8    16.4      <total>
        //
        //
        // ORIGINAL LLVM MCA STATISTICS (ORIGINAL) END
        //
        //
        // LLVM MCA STATISTICS (OPTIMIZED) BEGIN
        //
        //
        // [0] Code Region
        //
        // Iterations:        100
        // Instructions:      17000
        // Total Cycles:      9005
        // Total uOps:        21200
        //
        // Dispatch Width:    8
        // uOps Per Cycle:    2.35
        // IPC:               1.89
        // Block RThroughput: 90.0
        //
        //
        // Cycles with backend pressure increase [ 32.12% ]
        // Throughput Bottlenecks:
        //   Resource Pressure       [ 32.10% ]
        //   - N1UnitL  [ 2.28% ]
        //   - N1UnitM  [ 0.02% ]
        //   - N1UnitS  [ 0.02% ]
        //   - N1UnitV0  [ 32.07% ]
        //   - N1UnitV1  [ 2.22% ]
        //   Data Dependencies:      [ 7.81% ]
        //   - Register Dependencies [ 7.81% ]
        //   - Memory Dependencies   [ 0.00% ]
        //
        // Critical sequence based on the simulation:
        //
        //               Instruction                                 Dependency Information
        //  +----< 167.  eor.16b	v1, v1, v8
        //  |
        //  |    < loop carried >
        //  |
        //  +----> 0.    rev64.16b	v4, v1                            ## REGISTER dependency:  q1
        //  |      1.    pmull2.1q	v6, v5, v17
        //  |      2.    ldp	x19, x29, [x0, #16]
        //  |      3.    add	w26, w13, #1
        //  |      4.    pmull.1q	v31, v8, v12
        //  |      5.    stur	q0, [x2, #-16]
        //  |      6.    rev	w24, w26
        //  |      7.    add	w30, w13, #2
        //  |      8.    mov	d9, v8[1]
        //  +----> 9.    pmull2.1q	v3, v4, v15                       ## REGISTER dependency:  q4
        //  |      10.   orr	x22, x12, x24, lsl #32
        //  |      11.   rev	w17, w30
        //  |      12.   pmull2.1q	v30, v29, v13
        //  |      13.   mov	d0, v4[1]
        //  |      14.   stp	x11, x22, [sp, #176]
        //  |      15.   orr	x22, x12, x17, lsl #32
        //  +----> 16.   pmull.1q	v5, v4, v15                       ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  |      17.   eor.8b	v9, v9, v8
        //  |      18.   stp	x11, x22, [sp, #192]
        //  |      19.   add	w25, w13, #0
        //  |      20.   eor.8b	v29, v0, v4
        //  +----> 21.   pmull2.1q	v4, v8, v12                       ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      22.   add	w22, w13, #3
        //  |      23.   rev	w7, w25
        //  +----> 24.   pmull.1q	v9, v9, v14                       ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      25.   ldr	q8, [sp, #176]
        //  |      26.   orr	x14, x12, x7, lsl #32
        //  |      27.   rev	w17, w22
        //  +----> 28.   pmull2.1q	v0, v2, v14                       ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      29.   ldr	q2, [sp, #192]
        //  |      30.   orr	x28, x12, x17, lsl #32
        //  +----> 31.   pmull.1q	v29, v29, v17                     ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      32.   add	w13, w13, #4
        //  |      33.   eor	x8, x29, x21
        //  |      34.   stp	x11, x28, [sp, #208]
        //  |      35.   eor.16b	v11, v31, v11
        //  +----> 36.   aese.16b	v8, v18                           ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  |      37.   aesmc.16b	v8, v8
        //  |      38.   stp	x11, x14, [sp, #160]
        //  +----> 39.   aese.16b	v2, v18                           ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  +----> 40.   aesmc.16b	v2, v2                            ## REGISTER dependency:  q2
        //  |      41.   eor.16b	v30, v4, v30
        //  |      42.   eor	x30, x19, x20
        //  |      43.   ldp	x10, x29, [x0, #48]
        //  |      44.   aese.16b	v8, v19
        //  |      45.   aesmc.16b	v8, v8
        //  |      46.   ldr	q4, [sp, #208]
        //  +----> 47.   aese.16b	v2, v19                           ## REGISTER dependency:  q2
        //  +----> 48.   aesmc.16b	v2, v2                            ## REGISTER dependency:  q2
        //  |      49.   eor.16b	v11, v11, v5
        //  |      50.   ldp	x22, x23, [x0, #32]
        //  |      51.   ldr	q5, [sp, #160]
        //  |      52.   aese.16b	v8, v20
        //  |      53.   aesmc.16b	v8, v8
        //  |      54.   eor	x19, x29, x21
        //  |      55.   eor.16b	v30, v30, v3
        //  +----> 56.   aese.16b	v2, v20                           ## REGISTER dependency:  q2
        //  +----> 57.   aesmc.16b	v2, v2                            ## REGISTER dependency:  q2
        //  |      58.   eor	x29, x10, x20
        //  |      59.   aese.16b	v4, v18
        //  |      60.   aesmc.16b	v4, v4
        //  |      61.   eor.16b	v11, v11, v28
        //  |      62.   eor	x27, x23, x21
        //  |      63.   eor.16b	v3, v9, v0
        //  +----> 64.   aese.16b	v2, v21                           ## REGISTER dependency:  q2
        //  +----> 65.   aesmc.16b	v2, v2                            ## REGISTER dependency:  q2
        //  |      66.   ldp	x24, x7, [x0], #64
        //  |      67.   eor.16b	v0, v30, v10
        //  +----> 68.   aese.16b	v5, v18                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 69.   aesmc.16b	v5, v5                            ## REGISTER dependency:  q5
        //  |      70.   eor.16b	v30, v3, v29
        //  |      71.   aese.16b	v2, v22
        //  |      72.   aesmc.16b	v2, v2
        //  +----> 73.   aese.16b	v5, v19                           ## REGISTER dependency:  q5
        //  +----> 74.   aesmc.16b	v5, v5                            ## REGISTER dependency:  q5
        //  |      75.   eor.16b	v10, v11, v0
        //  |      76.   eor	x25, x22, x20
        //  |      77.   aese.16b	v2, v23
        //  |      78.   aesmc.16b	v2, v2
        //  |      79.   stp	x25, x27, [sp, #192]
        //  |      80.   stur	q1, [x2, #-48]
        //  +----> 81.   aese.16b	v5, v20                           ## REGISTER dependency:  q5
        //  +----> 82.   aesmc.16b	v5, v5                            ## REGISTER dependency:  q5
        //  |      83.   eor	x26, x24, x20
        //  |      84.   aese.16b	v2, v24
        //  |      85.   aesmc.16b	v2, v2
        //  |      86.   ext.16b	v28, v0, v0, #8
        //  |      87.   stp	x29, x19, [sp, #208]
        //  |      88.   eor.16b	v29, v30, v6
        //  +----> 89.   aese.16b	v5, v21                           ## REGISTER dependency:  q5
        //  |      90.   aesmc.16b	v5, v5
        //  +----> 91.   pmull.1q	v30, v0, v7                       ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      92.   stp	x30, x8, [sp, #176]
        //  |      93.   eor.16b	v6, v29, v10
        //  |      94.   aese.16b	v2, v25
        //  |      95.   aesmc.16b	v2, v2
        //  +----> 96.   eor.16b	v3, v28, v30                      ## REGISTER dependency:  q30
        //  |      97.   aese.16b	v5, v22
        //  |      98.   aesmc.16b	v5, v5
        //  |      99.   aese.16b	v2, v26
        //  |      100.  aesmc.16b	v2, v2
        //  |      101.  ldr	q30, [sp, #192]
        //  +----> 102.  eor.16b	v6, v6, v3                        ## REGISTER dependency:  q3
        //  |      103.  aese.16b	v5, v23
        //  |      104.  aesmc.16b	v5, v5
        //  |      105.  aese.16b	v4, v19
        //  |      106.  aesmc.16b	v4, v4
        //  |      107.  ldr	q28, [sp, #208]
        //  |      108.  aese.16b	v5, v24
        //  |      109.  aesmc.16b	v5, v5
        //  |      110.  ext.16b	v0, v6, v6, #8
        //  +----> 111.  pmull.1q	v1, v6, v7                        ## REGISTER dependency:  q6
        //  +----> 112.  aese.16b	v2, v27                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      113.  eor.16b	v1, v11, v1
        //  +----> 114.  aese.16b	v4, v20                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      115.  aesmc.16b	v4, v4
        //  |      116.  eor.16b	v3, v30, v2
        //  +----> 117.  aese.16b	v5, v25                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 118.  aesmc.16b	v5, v5                            ## REGISTER dependency:  q5
        //  |      119.  eor	x17, x7, x21
        //  |      120.  eor.16b	v6, v1, v0
        //  |      121.  aese.16b	v4, v21
        //  |      122.  aesmc.16b	v4, v4
        //  |      123.  stp	x26, x17, [sp, #160]
        //  +----> 124.  aese.16b	v5, v26                           ## REGISTER dependency:  q5
        //  +----> 125.  aesmc.16b	v5, v5                            ## REGISTER dependency:  q5
        //  |      126.  rev64.16b	v29, v3
        //  +----> 127.  aese.16b	v8, v21                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      128.  aesmc.16b	v8, v8
        //  |      129.  ext.16b	v30, v6, v6, #8
        //  |      130.  ldr	q11, [sp, #160]
        //  +----> 131.  aese.16b	v4, v22                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 132.  aesmc.16b	v4, v4                            ## REGISTER dependency:  q4
        //  +----> 133.  aese.16b	v5, v27                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      134.  ext.16b	v10, v29, v29, #8
        //  |      135.  str	q3, [x2, #32]
        //  +----> 136.  aese.16b	v8, v22                           ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  +----> 137.  aesmc.16b	v8, v8                            ## REGISTER dependency:  q8
        //  |      138.  eor.16b	v9, v11, v5
        //  |      139.  aese.16b	v4, v23
        //  |      140.  aesmc.16b	v4, v4
        //  |      141.  ldr	q1, [sp, #176]
        //  +----> 142.  aese.16b	v8, v23                           ## REGISTER dependency:  q8
        //  +----> 143.  aesmc.16b	v8, v8                            ## REGISTER dependency:  q8
        //  |      144.  aese.16b	v4, v24
        //  |      145.  aesmc.16b	v4, v4
        //  |      146.  str	q9, [x2], #64
        //  |      147.  rev64.16b	v9, v9
        //  +----> 148.  aese.16b	v8, v24                           ## REGISTER dependency:  q8
        //  +----> 149.  aesmc.16b	v8, v8                            ## REGISTER dependency:  q8
        //  |      150.  eor.16b	v2, v10, v29
        //  |      151.  aese.16b	v4, v25
        //  |      152.  aesmc.16b	v4, v4
        //  |      153.  eor.16b	v30, v9, v30
        //  +----> 154.  aese.16b	v8, v25                           ## REGISTER dependency:  q8
        //  +----> 155.  aesmc.16b	v8, v8                            ## REGISTER dependency:  q8
        //  |      156.  aese.16b	v4, v26
        //  |      157.  aesmc.16b	v4, v4
        //  +----> 158.  aese.16b	v8, v26                           ## REGISTER dependency:  q8
        //  +----> 159.  aesmc.16b	v8, v8                            ## REGISTER dependency:  q8
        //  |      160.  ext.16b	v6, v30, v30, #8
        //  |      161.  aese.16b	v4, v27
        //  |      162.  eor.16b	v5, v6, v30
        //  +----> 163.  aese.16b	v8, v27                           ## REGISTER dependency:  q8
        //  |      164.  eor.16b	v0, v28, v4
        //  |      165.  pmull.1q	v28, v30, v16
        //  +----> 166.  pmull2.1q	v10, v30, v16                     ## RESOURCE interference:  N1UnitV0 [ probability: 100% ]
        //  |      167.  eor.16b	v1, v1, v8
        //  +----> 168.  pmull.1q	v11, v29, v13                     ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  |      169.  rev64.16b	v8, v0
        //  |
        //  |    < loop carried >
        //  |
        //  +----> 1.    pmull2.1q	v6, v5, v17                       ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //
        //
        // Instruction Info:
        // [1]: #uOps
        // [2]: Latency
        // [3]: RThroughput
        // [4]: MayLoad
        // [5]: MayStore
        // [6]: HasSideEffects (U)
        //
        // [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
        //  1      2     0.50                        rev64.16b	v4, v1
        //  1      2     1.00                        pmull2.1q	v6, v5, v17
        //  2      4     1.00    *                   ldp	x19, x29, [x0, #16]
        //  1      1     0.33                        add	w26, w13, #1
        //  1      2     1.00                        pmull.1q	v31, v8, v12
        //  4      2     1.00           *            stur	q0, [x2, #-16]
        //  1      1     0.33                        rev	w24, w26
        //  1      1     0.33                        add	w30, w13, #2
        //  1      2     0.50                        mov	d9, v8[1]
        //  1      2     1.00                        pmull2.1q	v3, v4, v15
        //  1      1     0.33                        orr	x22, x12, x24, lsl #32
        //  1      1     0.33                        rev	w17, w30
        //  1      2     1.00                        pmull2.1q	v30, v29, v13
        //  1      2     0.50                        mov	d0, v4[1]
        //  3      1     1.00           *            stp	x11, x22, [sp, #176]
        //  1      1     0.33                        orr	x22, x12, x17, lsl #32
        //  1      2     1.00                        pmull.1q	v5, v4, v15
        //  1      2     0.50                        eor.8b	v9, v9, v8
        //  3      1     1.00           *            stp	x11, x22, [sp, #192]
        //  1      1     0.33                        add	w25, w13, #0
        //  1      2     0.50                        eor.8b	v29, v0, v4
        //  1      2     1.00                        pmull2.1q	v4, v8, v12
        //  1      1     0.33                        add	w22, w13, #3
        //  1      1     0.33                        rev	w7, w25
        //  1      2     1.00                        pmull.1q	v9, v9, v14
        //  2      5     0.50    *                   ldr	q8, [sp, #176]
        //  1      1     0.33                        orr	x14, x12, x7, lsl #32
        //  1      1     0.33                        rev	w17, w22
        //  1      2     1.00                        pmull2.1q	v0, v2, v14
        //  2      5     0.50    *                   ldr	q2, [sp, #192]
        //  1      1     0.33                        orr	x28, x12, x17, lsl #32
        //  1      2     1.00                        pmull.1q	v29, v29, v17
        //  1      1     0.33                        add	w13, w13, #4
        //  1      1     0.33                        eor	x8, x29, x21
        //  3      1     1.00           *            stp	x11, x28, [sp, #208]
        //  1      2     0.50                        eor.16b	v11, v31, v11
        //  1      2     1.00                        aese.16b	v8, v18
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  3      1     1.00           *            stp	x11, x14, [sp, #160]
        //  1      2     1.00                        aese.16b	v2, v18
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      2     0.50                        eor.16b	v30, v4, v30
        //  1      1     0.33                        eor	x30, x19, x20
        //  2      4     1.00    *                   ldp	x10, x29, [x0, #48]
        //  1      2     1.00                        aese.16b	v8, v19
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  2      5     0.50    *                   ldr	q4, [sp, #208]
        //  1      2     1.00                        aese.16b	v2, v19
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      2     0.50                        eor.16b	v11, v11, v5
        //  2      4     1.00    *                   ldp	x22, x23, [x0, #32]
        //  2      5     0.50    *                   ldr	q5, [sp, #160]
        //  1      2     1.00                        aese.16b	v8, v20
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      1     0.33                        eor	x19, x29, x21
        //  1      2     0.50                        eor.16b	v30, v30, v3
        //  1      2     1.00                        aese.16b	v2, v20
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      1     0.33                        eor	x29, x10, x20
        //  1      2     1.00                        aese.16b	v4, v18
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  1      2     0.50                        eor.16b	v11, v11, v28
        //  1      1     0.33                        eor	x27, x23, x21
        //  1      2     0.50                        eor.16b	v3, v9, v0
        //  1      2     1.00                        aese.16b	v2, v21
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  3      4     1.00    *                   ldp	x24, x7, [x0], #64
        //  1      2     0.50                        eor.16b	v0, v30, v10
        //  1      2     1.00                        aese.16b	v5, v18
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     0.50                        eor.16b	v30, v3, v29
        //  1      2     1.00                        aese.16b	v2, v22
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      2     1.00                        aese.16b	v5, v19
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     0.50                        eor.16b	v10, v11, v0
        //  1      1     0.33                        eor	x25, x22, x20
        //  1      2     1.00                        aese.16b	v2, v23
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  3      1     1.00           *            stp	x25, x27, [sp, #192]
        //  4      2     1.00           *            stur	q1, [x2, #-48]
        //  1      2     1.00                        aese.16b	v5, v20
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      1     0.33                        eor	x26, x24, x20
        //  1      2     1.00                        aese.16b	v2, v24
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      2     0.50                        ext.16b	v28, v0, v0, #8
        //  3      1     1.00           *            stp	x29, x19, [sp, #208]
        //  1      2     0.50                        eor.16b	v29, v30, v6
        //  1      2     1.00                        aese.16b	v5, v21
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     1.00                        pmull.1q	v30, v0, v7
        //  3      1     1.00           *            stp	x30, x8, [sp, #176]
        //  1      2     0.50                        eor.16b	v6, v29, v10
        //  1      2     1.00                        aese.16b	v2, v25
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  1      2     0.50                        eor.16b	v3, v28, v30
        //  1      2     1.00                        aese.16b	v5, v22
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     1.00                        aese.16b	v2, v26
        //  1      2     1.00                        aesmc.16b	v2, v2
        //  2      5     0.50    *                   ldr	q30, [sp, #192]
        //  1      2     0.50                        eor.16b	v6, v6, v3
        //  1      2     1.00                        aese.16b	v5, v23
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     1.00                        aese.16b	v4, v19
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  2      5     0.50    *                   ldr	q28, [sp, #208]
        //  1      2     1.00                        aese.16b	v5, v24
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     0.50                        ext.16b	v0, v6, v6, #8
        //  1      2     1.00                        pmull.1q	v1, v6, v7
        //  1      2     1.00                        aese.16b	v2, v27
        //  1      2     0.50                        eor.16b	v1, v11, v1
        //  1      2     1.00                        aese.16b	v4, v20
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  1      2     0.50                        eor.16b	v3, v30, v2
        //  1      2     1.00                        aese.16b	v5, v25
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      1     0.33                        eor	x17, x7, x21
        //  1      2     0.50                        eor.16b	v6, v1, v0
        //  1      2     1.00                        aese.16b	v4, v21
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  3      1     1.00           *            stp	x26, x17, [sp, #160]
        //  1      2     1.00                        aese.16b	v5, v26
        //  1      2     1.00                        aesmc.16b	v5, v5
        //  1      2     0.50                        rev64.16b	v29, v3
        //  1      2     1.00                        aese.16b	v8, v21
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     0.50                        ext.16b	v30, v6, v6, #8
        //  2      5     0.50    *                   ldr	q11, [sp, #160]
        //  1      2     1.00                        aese.16b	v4, v22
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  1      2     1.00                        aese.16b	v5, v27
        //  1      2     0.50                        ext.16b	v10, v29, v29, #8
        //  4      2     1.00           *            str	q3, [x2, #32]
        //  1      2     1.00                        aese.16b	v8, v22
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     0.50                        eor.16b	v9, v11, v5
        //  1      2     1.00                        aese.16b	v4, v23
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  2      5     0.50    *                   ldr	q1, [sp, #176]
        //  1      2     1.00                        aese.16b	v8, v23
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     1.00                        aese.16b	v4, v24
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  5      2     1.00           *            str	q9, [x2], #64
        //  1      2     0.50                        rev64.16b	v9, v9
        //  1      2     1.00                        aese.16b	v8, v24
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     0.50                        eor.16b	v2, v10, v29
        //  1      2     1.00                        aese.16b	v4, v25
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  1      2     0.50                        eor.16b	v30, v9, v30
        //  1      2     1.00                        aese.16b	v8, v25
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     1.00                        aese.16b	v4, v26
        //  1      2     1.00                        aesmc.16b	v4, v4
        //  1      2     1.00                        aese.16b	v8, v26
        //  1      2     1.00                        aesmc.16b	v8, v8
        //  1      2     0.50                        ext.16b	v6, v30, v30, #8
        //  1      2     1.00                        aese.16b	v4, v27
        //  1      2     0.50                        eor.16b	v5, v6, v30
        //  1      2     1.00                        aese.16b	v8, v27
        //  1      2     0.50                        eor.16b	v0, v28, v4
        //  1      2     1.00                        pmull.1q	v28, v30, v16
        //  1      2     1.00                        pmull2.1q	v10, v30, v16
        //  1      2     0.50                        eor.16b	v1, v1, v8
        //  1      2     1.00                        pmull.1q	v11, v29, v13
        //  1      2     0.50                        rev64.16b	v8, v0
        //
        //
        // Dynamic Dispatch Stall Cycles:
        // RAT     - Register unavailable:                      0
        // RCU     - Retire tokens unavailable:                 8318  (92.4%)
        // SCHEDQ  - Scheduler full:                            0
        // LQ      - Load queue full:                           0
        // SQ      - Store queue full:                          0
        // GROUP   - Static restrictions on the dispatch group: 0
        // USH     - Uncategorised Structural Hazard:           0
        //
        //
        // Dispatch Logic - number of cycles where we saw N micro opcodes dispatched:
        // [# dispatched], [# cycles]
        //  0,              2838  (31.5%)
        //  1,              1981  (22.0%)
        //  2,              792  (8.8%)
        //  3,              693  (7.7%)
        //  4,              495  (5.5%)
        //  5,              893  (9.9%)
        //  6,              597  (6.6%)
        //  7,              199  (2.2%)
        //  8,              517  (5.7%)
        //
        //
        // Schedulers - number of cycles where we saw N micro opcodes issued:
        // [# issued], [# cycles]
        //  0,          4  (0.0%)
        //  1,          3911  (43.4%)
        //  2,          2692  (29.9%)
        //  3,          794  (8.8%)
        //  4,          698  (7.8%)
        //  5,          203  (2.3%)
        //  6,          4  (0.0%)
        //  7,          200  (2.2%)
        //  8,          200  (2.2%)
        //  9,          298  (3.3%)
        //  10,          1  (0.0%)
        //
        // Scheduler's queue usage:
        // No scheduler resources used.
        //
        //
        // Retire Control Unit - number of cycles where we saw N instructions retired:
        // [# retired], [# cycles]
        //  0,           2204  (24.5%)
        //  1,           2601  (28.9%)
        //  2,           801  (8.9%)
        //  3,           1800  (20.0%)
        //  4,           1199  (13.3%)
        //  5,           200  (2.2%)
        //  7,           100  (1.1%)
        //  9,           99  (1.1%)
        //  10,          1  (0.0%)
        //
        // Total ROB Entries:                128
        // Max Used ROB Entries:             128  ( 100.0% )
        // Average Used ROB Entries per cy:  126  ( 98.4% )
        //
        //
        // Register File statistics:
        // Total number of mappings created:    16400
        // Max number of mappings used:         104
        //
        //
        // Resources:
        // [0]   - N1UnitB
        // [1.0] - N1UnitD
        // [1.1] - N1UnitD
        // [2.0] - N1UnitL
        // [2.1] - N1UnitL
        // [3]   - N1UnitM
        // [4.0] - N1UnitS
        // [4.1] - N1UnitS
        // [5]   - N1UnitV0
        // [6]   - N1UnitV1
        //
        //
        // Resource pressure per iteration:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]
        //  -     4.00   4.00   19.01  20.99  6.02   14.49  14.49  90.00  39.00
        //
        // Resource pressure by instruction:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]    Instructions:
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v4, v1
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v6, v5, v17
        //  -      -      -     1.98   0.02    -      -      -      -      -     ldp	x19, x29, [x0, #16]
        //  -      -      -      -      -      -     0.50   0.50    -      -     add	w26, w13, #1
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v31, v8, v12
        //  -      -      -     0.02   1.98    -     1.02   0.98    -      -     stur	q0, [x2, #-16]
        //  -      -      -      -      -      -     0.49   0.51    -      -     rev	w24, w26
        //  -      -      -      -      -     0.01   0.50   0.49    -      -     add	w30, w13, #2
        //  -      -      -      -      -      -      -      -      -     1.00   mov	d9, v8[1]
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v3, v4, v15
        //  -      -      -      -      -     0.99    -     0.01    -      -     orr	x22, x12, x24, lsl #32
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     rev	w17, w30
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v30, v29, v13
        //  -      -      -      -      -      -      -      -      -     1.00   mov	d0, v4[1]
        //  -      -     1.00   1.98   0.02    -      -      -      -      -     stp	x11, x22, [sp, #176]
        //  -      -      -      -      -      -     0.51   0.49    -      -     orr	x22, x12, x17, lsl #32
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v5, v4, v15
        //  -      -      -      -      -      -      -      -      -     1.00   eor.8b	v9, v9, v8
        //  -     1.00    -     0.02   1.98    -      -      -      -      -     stp	x11, x22, [sp, #192]
        //  -      -      -      -      -      -     0.49   0.51    -      -     add	w25, w13, #0
        //  -      -      -      -      -      -      -      -      -     1.00   eor.8b	v29, v0, v4
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v4, v8, v12
        //  -      -      -      -      -     0.01   0.50   0.49    -      -     add	w22, w13, #3
        //  -      -      -      -      -     0.99   0.01    -      -      -     rev	w7, w25
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v9, v9, v14
        //  -      -      -      -     1.00    -     0.49   0.51    -      -     ldr	q8, [sp, #176]
        //  -      -      -      -      -      -     0.51   0.49    -      -     orr	x14, x12, x7, lsl #32
        //  -      -      -      -      -     1.00    -      -      -      -     rev	w17, w22
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v0, v2, v14
        //  -      -      -     1.00    -      -     0.49   0.51    -      -     ldr	q2, [sp, #192]
        //  -      -      -      -      -      -     0.51   0.49    -      -     orr	x28, x12, x17, lsl #32
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v29, v29, v17
        //  -      -      -      -      -     0.01   0.49   0.50    -      -     add	w13, w13, #4
        //  -      -      -      -      -     0.99    -     0.01    -      -     eor	x8, x29, x21
        //  -      -     1.00   1.98   0.02    -      -      -      -      -     stp	x11, x28, [sp, #208]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v11, v31, v11
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -     1.00    -     0.02   1.98    -      -      -      -      -     stp	x11, x14, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v4, v30
        //  -      -      -      -      -      -     0.51   0.49    -      -     eor	x30, x19, x20
        //  -      -      -      -     2.00    -      -      -      -      -     ldp	x10, x29, [x0, #48]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -     0.01   0.99   0.01   0.49   0.50    -      -     ldr	q4, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v11, v11, v5
        //  -      -      -     0.02   1.98    -      -      -      -      -     ldp	x22, x23, [x0, #32]
        //  -      -      -     0.99   0.01    -     0.50   0.50    -      -     ldr	q5, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -     0.49   0.51    -      -     eor	x19, x29, x21
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v30, v3
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -     0.99   0.01    -      -      -     eor	x29, x10, x20
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v11, v11, v28
        //  -      -      -      -      -     0.01   0.50   0.49    -      -     eor	x27, x23, x21
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v3, v9, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -     2.00    -      -     0.51   0.49    -      -     ldp	x24, x7, [x0], #64
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v30, v10
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v18
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v3, v29
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v10, v11, v0
        //  -      -      -      -      -     0.99    -     0.01    -      -     eor	x25, x22, x20
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -     1.00   1.98   0.02    -      -      -      -      -     stp	x25, x27, [sp, #192]
        //  -      -      -     0.02   1.98    -     1.00   1.00    -      -     stur	q1, [x2, #-48]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -     0.49   0.51    -      -     eor	x26, x24, x20
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v28, v0, v0, #8
        //  -     1.00    -     1.98   0.02    -      -      -      -      -     stp	x29, x19, [sp, #208]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v29, v30, v6
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v30, v0, v7
        //  -      -     1.00   0.02   1.98    -      -      -      -      -     stp	x30, x8, [sp, #176]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v6, v29, v10
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v3, v28, v30
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v2, v2
        //  -      -      -     0.99   0.01   0.01   0.50   0.49    -      -     ldr	q30, [sp, #192]
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v6, v6, v3
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v19
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -     1.00    -      -     0.50   0.50    -      -     ldr	q28, [sp, #208]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v0, v6, v6, #8
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v1, v6, v7
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v2, v27
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v1, v11, v1
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v20
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v3, v30, v2
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -     0.50   0.50    -      -     eor	x17, x7, x21
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v6, v1, v0
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -     1.00    -      -     2.00    -      -      -      -      -     stp	x26, x17, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v5, v5
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v29, v3
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v21
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v30, v6, v6, #8
        //  -      -      -     1.00    -      -     0.50   0.50    -      -     ldr	q11, [sp, #160]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v5, v27
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v10, v29, v29, #8
        //  -      -      -     2.00    -      -      -      -      -     2.00   str	q3, [x2, #32]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v22
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v9, v11, v5
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -     1.00    -     0.50   0.50    -      -     ldr	q1, [sp, #176]
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v23
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -     2.00    -     0.49   0.51    -     2.00   str	q9, [x2], #64
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v9, v9
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v24
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v2, v10, v29
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v9, v30
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v25
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v4, v4
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v26
        //  -      -      -      -      -      -      -      -     1.00    -     aesmc.16b	v8, v8
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v6, v30, v30, #8
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v4, v27
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v5, v6, v30
        //  -      -      -      -      -      -      -      -     1.00    -     aese.16b	v8, v27
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v0, v28, v4
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v28, v30, v16
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v10, v30, v16
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v1, v1, v8
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v29, v13
        //  -      -      -      -      -      -      -      -      -     1.00   rev64.16b	v8, v0
        //
        //
        // Timeline view:
        //                     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          01234
        // Index     0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789          0123456789
        //
        // [0,0]     DeeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v4, v1
        // [0,1]     DeeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v6, v5, v17
        // [0,2]     DeeeeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x19, x29, [x0, #16]
        // [0,3]     DeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w26, w13, #1
        // [0,4]     D=eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v31, v8, v12
        // [0,5]     .DeeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stur	q0, [x2, #-16]
        // [0,6]     .DeE--R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w24, w26
        // [0,7]     .DeE--R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w30, w13, #2
        // [0,8]     .DeeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d9, v8[1]
        // [0,9]     .D=eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v3, v4, v15
        // [0,10]    . DeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x24, lsl #32
        // [0,11]    . DeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w30
        // [0,12]    . D=eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v30, v29, v13
        // [0,13]    . DeeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d0, v4[1]
        // [0,14]    . D=eE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #176]
        // [0,15]    . D=eE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x17, lsl #32
        // [0,16]    .  D=eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v5, v4, v15
        // [0,17]    .  DeeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v9, v9, v8
        // [0,18]    .  D=eE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #192]
        // [0,19]    .  DeE--R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w25, w13, #0
        // [0,20]    .  D=eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v29, v0, v4
        // [0,21]    .  D==eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v4, v8, v12
        // [0,22]    .   DeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w22, w13, #3
        // [0,23]    .   DeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w7, w25
        // [0,24]    .   D==eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v9, v9, v14
        // [0,25]    .   D=eeeeeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q8, [sp, #176]
        // [0,26]    .   D=eE----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x14, x12, x7, lsl #32
        // [0,27]    .   D=eE----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w22
        // [0,28]    .   D===eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v0, v2, v14
        // [0,29]    .    D=eeeeeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q2, [sp, #192]
        // [0,30]    .    D=eE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x28, x12, x17, lsl #32
        // [0,31]    .    D===eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v29, v29, v17
        // [0,32]    .    D=eE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w13, w13, #4
        // [0,33]    .    D==eE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x8, x29, x21
        // [0,34]    .    .D=eE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x28, [sp, #208]
        // [0,35]    .    .DeeE---R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v31, v11
        // [0,36]    .    .D====eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v18
        // [0,37]    .    .D======eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,38]    .    . DeE------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x14, [sp, #160]
        // [0,39]    .    . D====eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v18
        // [0,40]    .    . D======eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,41]    .    . DeeE------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v4, v30
        // [0,42]    .    . DeE-------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x30, x19, x20
        // [0,43]    .    .  D=eeeeE--R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x10, x29, [x0, #48]
        // [0,44]    .    .  D======eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v19
        // [0,45]    .    .  D========eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,46]    .    .  D=eeeeeE----R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q4, [sp, #208]
        // [0,47]    .    .  D=======eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v19
        // [0,48]    .    .  D=========eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,49]    .    .   DeeE--------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v5
        // [0,50]    .    .   D=eeeeE-----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x22, x23, [x0, #32]
        // [0,51]    .    .   D==eeeeeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q5, [sp, #160]
        // [0,52]    .    .   D=========eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v20
        // [0,53]    .    .   D===========eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,54]    .    .   D====eE--------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x19, x29, x21
        // [0,55]    .    .    DeeE----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v30, v3
        // [0,56]    .    .    D=========eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v20
        // [0,57]    .    .    D===========eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,58]    .    .    D===eE---------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x29, x10, x20
        // [0,59]    .    .    D============eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v18
        // [0,60]    .    .    D==============eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,61]    .    .    D=eeE-------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v28
        // [0,62]    .    .    D====eE-----------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x27, x23, x21
        // [0,63]    .    .    .D=eeE------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v9, v0
        // [0,64]    .    .    .D============eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v21
        // [0,65]    .    .    .D==============eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,66]    .    .    .D=eeeeE-----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x24, x7, [x0], #64
        // [0,67]    .    .    .D==eeE------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v0, v30, v10
        // [0,68]    .    .    .D===============eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v18
        // [0,69]    .    .    . D================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,70]    .    .    . D==eeE--------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v3, v29
        // [0,71]    .    .    . D===============eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v22
        // [0,72]    .    .    . D=================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,73]    .    .    . D==================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v19
        // [0,74]    .    .    . D====================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,75]    .    .    . D===eeE-----------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v10, v11, v0
        // [0,76]    .    .    . D==eE-------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x25, x22, x20
        // [0,77]    .    .    .  D==================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v23
        // [0,78]    .    .    .  D====================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,79]    .    .    .  D==eE-------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x25, x27, [sp, #192]
        // [0,80]    .    .    .   D=eeE------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stur	q1, [x2, #-48]
        // [0,81]    .    .    .   D====================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v20
        // [0,82]    .    .    .   D======================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,83]    .    .    .   D==eE---------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x26, x24, x20
        // [0,84]    .    .    .   D=====================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v24
        // [0,85]    .    .    .    D======================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,86]    .    .    .    D=eeE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v28, v0, v0, #8
        // [0,87]    .    .    .    D==eE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x29, x19, [sp, #208]
        // [0,88]    .    .    .    D==eeE--------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v29, v30, v6
        // [0,89]    .    .    .    D=======================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v21
        // [0,90]    .    .    .    D=========================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,91]    .    .    .    .D=======================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v30, v0, v7
        // [0,92]    .    .    .    .D=eE------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x30, x8, [sp, #176]
        // [0,93]    .    .    .    .D===eeE---------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v29, v10
        // [0,94]    .    .    .    .D=========================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v25
        // [0,95]    .    .    .    .D===========================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,96]    .    .    .    .D=========================eeE--R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v28, v30
        // [0,97]    .    .    .    . D=========================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v22
        // [0,98]    .    .    .    . D===========================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,99]    .    .    .    . D============================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v26
        // [0,100]   .    .    .    . D==============================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [0,101]   .    .    .    . D==eeeeeE-------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q30, [sp, #192]
        // [0,102]   .    .    .    . D==========================eeE----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v3
        // [0,103]   .    .    .    . D=============================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v23
        // [0,104]   .    .    .    .  D==============================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,105]   .    .    .    .  D===============================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v19
        // [0,106]   .    .    .    .  D=================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,107]   .    .    .    .  D=eeeeeE-----------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q28, [sp, #208]
        // [0,108]   .    .    .    .  D================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v24
        // [0,109]   .    .    .    .  D==================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,110]   .    .    .    .  D===========================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v0, v6, v6, #8
        // [0,111]   .    .    .    .   D==================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v1, v6, v7
        // [0,112]   .    .    .    .   D===================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v27
        // [0,113]   .    .    .    .   D====================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v1, v11, v1
        // [0,114]   .    .    .    .   D====================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v20
        // [0,115]   .    .    .    .   D======================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,116]   .    .    .    .   D=====================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v30, v2
        // [0,117]   .    .    .    .   D=====================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v25
        // [0,118]   .    .    .    .   D=======================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,119]   .    .    .    .    DeE---------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x17, x7, x21
        // [0,120]   .    .    .    .    D=====================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v1, v0
        // [0,121]   .    .    .    .    D=======================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v21
        // [0,122]   .    .    .    .    D=========================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,123]   .    .    .    .    D=eE-----------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x26, x17, [sp, #160]
        // [0,124]   .    .    .    .    D========================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v26
        // [0,125]   .    .    .    .    .D=========================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [0,126]   .    .    .    .    .D=====================================eeE----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v29, v3
        // [0,127]   .    .    .    .    .D==========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v21
        // [0,128]   .    .    .    .    .D============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,129]   .    .    .    .    .D======================================eeE------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v30, v6, v6, #8
        // [0,130]   .    .    .    .    .DeeeeeE-----------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q11, [sp, #160]
        // [0,131]   .    .    .    .    .D===========================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v22
        // [0,132]   .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,133]   .    .    .    .    . D=============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v27
        // [0,134]   .    .    .    .    . D======================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v10, v29, v29, #8
        // [0,135]   .    .    .    .    . D=======================================eeE------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   str	q3, [x2, #32]
        // [0,136]   .    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v22
        // [0,137]   .    .    .    .    .  D===============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,138]   .    .    .    .    .  D==============================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v9, v11, v5
        // [0,139]   .    .    .    .    .  D==============================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v23
        // [0,140]   .    .    .    .    .  D================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,141]   .    .    .    .    .  DeeeeeE---------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q1, [sp, #176]
        // [0,142]   .    .    .    .    .  D=================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v23
        // [0,143]   .    .    .    .    .  D===================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,144]   .    .    .    .    .   D=================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v24
        // [0,145]   .    .    .    .    .   D===================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,146]   .    .    .    .    .   D===============================================eeE----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   str	q9, [x2], #64
        // [0,147]   .    .    .    .    .   D=================================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v9, v9
        // [0,148]   .    .    .    .    .    D===================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v24
        // [0,149]   .    .    .    .    .    D=====================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,150]   .    .    .    .    .    D======================================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v2, v10, v29
        // [0,151]   .    .    .    .    .    D====================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v25
        // [0,152]   .    .    .    .    .    D======================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,153]   .    .    .    .    .    D==================================================eeE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v9, v30
        // [0,154]   .    .    .    .    .    D=======================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v25
        // [0,155]   .    .    .    .    .    D=========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,156]   .    .    .    .    .    .D=======================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v26
        // [0,157]   .    .    .    .    .    .D=========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [0,158]   .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v26
        // [0,159]   .    .    .    .    .    .D============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [0,160]   .    .    .    .    .    .D===================================================eeE---------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v6, v30, v30, #8
        // [0,161]   .    .    .    .    .    .D===========================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v27
        // [0,162]   .    .    .    .    .    .D=====================================================eeE-------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v5, v6, v30
        // [0,163]   .    .    .    .    .    .D==============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v27
        // [0,164]   .    .    .    .    .    .  D===========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v0, v28, v4
        // [0,165]   .    .    .    .    .    .  D===========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v28, v30, v16
        // [0,166]   .    .    .    .    .    .  D=============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v10, v30, v16
        // [0,167]   .    .    .    .    .    .  D==============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v1, v1, v8
        // [0,168]   .    .    .    .    .    .  D==============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v11, v29, v13
        // [0,169]   .    .    .    .    .    .   D============================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v8, v0
        // [1,0]     .    .    .    .    .    .   D===============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v4, v1
        // [1,1]     .    .    .    .    .    .   D==============================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v6, v5, v17
        // [1,2]     .    .    .    .    .    .   DeeeeE-------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x19, x29, [x0, #16]
        // [1,3]     .    .    .    .    .    .    DeE---------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w26, w13, #1
        // [1,4]     .    .    .    .    .    .    . D============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v31, v8, v12
        // [1,5]     .    .    .    .    .    .    .   D=======================================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stur	q0, [x2, #-16]
        // [1,6]     .    .    .    .    .    .    .    .DeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w24, w26
        // [1,7]     .    .    .    .    .    .    .    .DeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w30, w13, #2
        // [1,8]     .    .    .    .    .    .    .    .D=======================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d9, v8[1]
        // [1,9]     .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v3, v4, v15
        // [1,10]    .    .    .    .    .    .    .    . DeE----------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x24, lsl #32
        // [1,11]    .    .    .    .    .    .    .    . DeE----------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w30
        // [1,12]    .    .    .    .    .    .    .    . D========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v30, v29, v13
        // [1,13]    .    .    .    .    .    .    .    . D=========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d0, v4[1]
        // [1,14]    .    .    .    .    .    .    .    . D====================================================eE------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #176]
        // [1,15]    .    .    .    .    .    .    .    . D=eE---------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x17, lsl #32
        // [1,16]    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v5, v4, v15
        // [1,17]    .    .    .    .    .    .    .    .    D=====================================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v9, v9, v8
        // [1,18]    .    .    .    .    .    .    .    .    .D==================================================eE-----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #192]
        // [1,19]    .    .    .    .    .    .    .    .    .DeE-------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w25, w13, #0
        // [1,20]    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v29, v0, v4
        // [1,21]    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v4, v8, v12
        // [1,22]    .    .    .    .    .    .    .    .    .DeE--------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w22, w13, #3
        // [1,23]    .    .    .    .    .    .    .    .    .D=eE-------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w7, w25
        // [1,24]    .    .    .    .    .    .    .    .    . D=======================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v9, v9, v14
        // [1,25]    .    .    .    .    .    .    .    .    .   DeeeeeE--------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q8, [sp, #176]
        // [1,26]    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x14, x12, x7, lsl #32
        // [1,27]    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w22
        // [1,28]    .    .    .    .    .    .    .    .    .   D======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v0, v2, v14
        // [1,29]    .    .    .    .    .    .    .    .    .    DeeeeeE--------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q2, [sp, #192]
        // [1,30]    .    .    .    .    .    .    .    .    .    . DeE----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x28, x12, x17, lsl #32
        // [1,31]    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v29, v29, v17
        // [1,32]    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w13, w13, #4
        // [1,33]    .    .    .    .    .    .    .    .    .    .  DeE----------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x8, x29, x21
        // [1,34]    .    .    .    .    .    .    .    .    .    .    .D========================================eE---------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x28, [sp, #208]
        // [1,35]    .    .    .    .    .    .    .    .    .    .    .D============================================eeE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v31, v11
        // [1,36]    .    .    .    .    .    .    .    .    .    .    .D=================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v18
        // [1,37]    .    .    .    .    .    .    .    .    .    .    .D===================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,38]    .    .    .    .    .    .    .    .    .    .    .    D======================================eE----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x14, [sp, #160]
        // [1,39]    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v18
        // [1,40]    .    .    .    .    .    .    .    .    .    .    .    D================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,41]    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeE-----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v4, v30
        // [1,42]    .    .    .    .    .    .    .    .    .    .    .    .DeE------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x30, x19, x20
        // [1,43]    .    .    .    .    .    .    .    .    .    .    .    . DeeeeE--------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x10, x29, [x0, #48]
        // [1,44]    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v19
        // [1,45]    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,46]    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q4, [sp, #208]
        // [1,47]    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v19
        // [1,48]    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,49]    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================eeE----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v5
        // [1,50]    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeE-------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x22, x23, [x0, #32]
        // [1,51]    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE---------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q5, [sp, #160]
        // [1,52]    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v20
        // [1,53]    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,54]    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x19, x29, x21
        // [1,55]    .    .    .    .    .    .    .    .    .    .    .    .    .    D===================================eeE----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v30, v3
        // [1,56]    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v20
        // [1,57]    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,58]    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x29, x10, x20
        // [1,59]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v18
        // [1,60]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================eeE---------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v28
        // [1,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE----------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x27, x23, x21
        // [1,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================eeE-------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v9, v0
        // [1,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v21
        // [1,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeE------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x24, x7, [x0], #64
        // [1,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================eeE-------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v0, v30, v10
        // [1,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v18
        // [1,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v3, v29
        // [1,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v22
        // [1,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v19
        // [1,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================eeE------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v10, v11, v0
        // [1,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x25, x22, x20
        // [1,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v23
        // [1,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============eE-------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x25, x27, [sp, #192]
        // [1,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================eeE----------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stur	q1, [x2, #-48]
        // [1,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v20
        // [1,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x26, x24, x20
        // [1,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v24
        // [1,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================eeE----------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v28, v0, v0, #8
        // [1,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========eE---------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x29, x19, [sp, #208]
        // [1,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================eeE---------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v29, v30, v6
        // [1,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v21
        // [1,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=======================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v30, v0, v7
        // [1,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====eE----------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x30, x8, [sp, #176]
        // [1,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================eeE----------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v29, v10
        // [1,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v25
        // [1,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE--R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v28, v30
        // [1,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D======================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v22
        // [1,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v26
        // [1,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [1,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eeeeeE-------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q30, [sp, #192]
        // [1,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================eeE----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v3
        // [1,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v23
        // [1,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v19
        // [1,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=eeeeeE----------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q28, [sp, #208]
        // [1,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v24
        // [1,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v0, v6, v6, #8
        // [1,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v1, v6, v7
        // [1,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v27
        // [1,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v1, v11, v1
        // [1,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v20
        // [1,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v30, v2
        // [1,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v25
        // [1,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE--------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x17, x7, x21
        // [1,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v1, v0
        // [1,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v21
        // [1,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x26, x17, [sp, #160]
        // [1,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v26
        // [1,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [1,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================eeE----R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v29, v3
        // [1,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v21
        // [1,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeE------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v30, v6, v6, #8
        // [1,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE---------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q11, [sp, #160]
        // [1,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v22
        // [1,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v27
        // [1,134]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeE-------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v10, v29, v29, #8
        // [1,135]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   str	q3, [x2, #32]
        // [1,136]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v22
        // [1,137]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,138]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v9, v11, v5
        // [1,139]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v23
        // [1,140]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,141]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE----------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q1, [sp, #176]
        // [1,142]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v23
        // [1,143]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,144]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v24
        // [1,145]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,146]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===================================================eeE----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   str	q9, [x2], #64
        // [1,147]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v9, v9
        // [1,148]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v24
        // [1,149]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,150]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v2, v10, v29
        // [1,151]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v25
        // [1,152]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,153]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================eeE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v9, v30
        // [1,154]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v25
        // [1,155]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,156]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v26
        // [1,157]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [1,158]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v26
        // [1,159]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [1,160]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeE---------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v6, v30, v30, #8
        // [1,161]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v27
        // [1,162]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================================eeE-------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v5, v6, v30
        // [1,163]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v27
        // [1,164]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v0, v28, v4
        // [1,165]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v28, v30, v16
        // [1,166]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v10, v30, v16
        // [1,167]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v1, v1, v8
        // [1,168]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v11, v29, v13
        // [1,169]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v8, v0
        // [2,0]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v4, v1
        // [2,1]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v6, v5, v17
        // [2,2]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeE-------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x19, x29, [x0, #16]
        // [2,3]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE---------------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w26, w13, #1
        // [2,4]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v31, v8, v12
        // [2,5]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeE---R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stur	q0, [x2, #-16]
        // [2,6]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w24, w26
        // [2,7]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE---------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w30, w13, #2
        // [2,8]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d9, v8[1]
        // [2,9]     .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v3, v4, v15
        // [2,10]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE----------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x24, lsl #32
        // [2,11]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE----------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w30
        // [2,12]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v30, v29, v13
        // [2,13]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=========================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d0, v4[1]
        // [2,14]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eE------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #176]
        // [2,15]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=eE---------------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x22, x12, x17, lsl #32
        // [2,16]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v5, v4, v15
        // [2,17]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================eeE--R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v9, v9, v8
        // [2,18]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==================================================eE-----R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x22, [sp, #192]
        // [2,19]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-------------------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w25, w13, #0
        // [2,20]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v29, v0, v4
        // [2,21]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v4, v8, v12
        // [2,22]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE--------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w22, w13, #3
        // [2,23]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eE-------------------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w7, w25
        // [2,24]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v9, v9, v14
        // [2,25]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeeeeeE--------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q8, [sp, #176]
        // [2,26]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x14, x12, x7, lsl #32
        // [2,27]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE------------------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev	w17, w22
        // [2,28]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D======================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v0, v2, v14
        // [2,29]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE--------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q2, [sp, #192]
        // [2,30]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE----------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   orr	x28, x12, x17, lsl #32
        // [2,31]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v29, v29, v17
        // [2,32]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE-----------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   add	w13, w13, #4
        // [2,33]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  DeE----------------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x8, x29, x21
        // [2,34]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================eE---------R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x28, [sp, #208]
        // [2,35]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeE----R .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v31, v11
        // [2,36]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=================================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v18
        // [2,37]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===================================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [2,38]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================eE----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   stp	x11, x14, [sp, #160]
        // [2,39]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==============================================eeE-R   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v18
        // [2,40]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,41]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeE-----R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v4, v30
        // [2,42]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE------------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x30, x19, x20
        // [2,43]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeE--------------------------------------------R  .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x10, x29, [x0, #48]
        // [2,44]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v19
        // [2,45]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [2,46]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q4, [sp, #208]
        // [2,47]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeE-R    .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v19
        // [2,48]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,49]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================================eeE----------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v5
        // [2,50]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeeeeE-------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x22, x23, [x0, #32]
        // [2,51]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeeeeeE---------------------------------------R   .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   ldr	q5, [sp, #160]
        // [2,52]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeER  .    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v8, v20
        // [2,53]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v8, v8
        // [2,54]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x19, x29, x21
        // [2,55]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===================================eeE----------R.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v30, v3
        // [2,56]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeE-R.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v20
        // [2,57]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,58]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------R    .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x29, x10, x20
        // [2,59]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================eeER   .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v4, v18
        // [2,60]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeER .    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [2,61]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================eeE---------------R .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v11, v11, v28
        // [2,62]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE----------------------------------------------R .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor	x27, x23, x21
        // [2,63]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================eeE-------------R .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v9, v0
        // [2,64]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===========================================eeE-R .    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v21
        // [2,65]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D============================================eeER.    .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,66]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeE------------------------------------------R.    .    .    .    .    .    .    .    .    .    .    .    .   .   ldp	x24, x7, [x0], #64
        // [2,67]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===============================eeE-------------R.    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v0, v30, v10
        // [2,68]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================eeER    .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v18
        // [2,69]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==============================================eeER  .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,70]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================eeE---------------R  .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v3, v29
        // [2,71]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================eeE-R  .    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v22
        // [2,72]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=============================================eeER .    .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,73]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================================eeER.    .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v19
        // [2,74]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===============================================eeER   .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,75]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=============================eeE------------------R   .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v10, v11, v0
        // [2,76]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeE-----------------------------------------------R   .    .    .    .    .    .    .    .    .    .    .   .   eor	x25, x22, x20
        // [2,77]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================eeE-R   .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v23
        // [2,78]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeER  .    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,79]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============eE-------------------------------R  .    .    .    .    .    .    .    .    .    .    .   .   stp	x25, x27, [sp, #192]
        // [2,80]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================eeE----------------------------R  .    .    .    .    .    .    .    .    .    .    .   .   stur	q1, [x2, #-48]
        // [2,81]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================eeER .    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v20
        // [2,82]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,83]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . DeE---------------------------------------------R    .    .    .    .    .    .    .    .    .    .   .   eor	x26, x24, x20
        // [2,84]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================eeE-R    .    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v24
        // [2,85]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D============================================eeER   .    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,86]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D======================eeE----------------------R   .    .    .    .    .    .    .    .    .    .   .   ext.16b	v28, v0, v0, #8
        // [2,87]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========eE---------------------------------R   .    .    .    .    .    .    .    .    .    .   .   stp	x29, x19, [sp, #208]
        // [2,88]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===================eeE---------------------R   .    .    .    .    .    .    .    .    .    .   .   eor.16b	v29, v30, v6
        // [2,89]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeER  .    .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v21
        // [2,90]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================eeER.    .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,91]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=======================================eeE-R.    .    .    .    .    .    .    .    .    .   .   pmull.1q	v30, v0, v7
        // [2,92]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=====eE----------------------------------R.    .    .    .    .    .    .    .    .    .   .   stp	x30, x8, [sp, #176]
        // [2,93]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================eeE----------------------R.    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v29, v10
        // [2,94]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================eeER    .    .    .    .    .    .    .    .    .   .   aese.16b	v2, v25
        // [2,95]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================eeER  .    .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,96]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================eeE--R  .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v28, v30
        // [2,97]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D======================================eeE-R  .    .    .    .    .    .    .    .    .   .   aese.16b	v5, v22
        // [2,98]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D========================================eeER .    .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,99]    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================eeER.    .    .    .    .    .    .    .    .   .   aese.16b	v2, v26
        // [2,100]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=========================================eeER   .    .    .    .    .    .    .    .   .   aesmc.16b	v2, v2
        // [2,101]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=eeeeeE-------------------------------------R   .    .    .    .    .    .    .    .   .   ldr	q30, [sp, #192]
        // [2,102]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=====================================eeE----R   .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v3
        // [2,103]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================eeE-R   .    .    .    .    .    .    .    .   .   aese.16b	v5, v23
        // [2,104]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeER  .    .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,105]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================eeER .    .    .    .    .    .    .    .   .   aese.16b	v4, v19
        // [2,106]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D============================================eeER    .    .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [2,107]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=eeeeeE----------------------------------------R    .    .    .    .    .    .    .   .   ldr	q28, [sp, #208]
        // [2,108]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================eeE-R    .    .    .    .    .    .    .   .   aese.16b	v5, v24
        // [2,109]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=============================================eeER   .    .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,110]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=====================================eeE-------R   .    .    .    .    .    .    .   .   ext.16b	v0, v6, v6, #8
        // [2,111]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================eeER  .    .    .    .    .    .    .   .   pmull.1q	v1, v6, v7
        // [2,112]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================eeER .    .    .    .    .    .    .   .   aese.16b	v2, v27
        // [2,113]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===============================================eeER.    .    .    .    .    .    .   .   eor.16b	v1, v11, v1
        // [2,114]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===============================================eeER.    .    .    .    .    .    .   .   aese.16b	v4, v20
        // [2,115]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=================================================eeER   .    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [2,116]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .   .   eor.16b	v3, v30, v2
        // [2,117]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE-R   .    .    .    .    .    .   .   aese.16b	v5, v25
        // [2,118]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=================================================eeER  .    .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,119]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   DeE--------------------------------------------------R  .    .    .    .    .    .   .   eor	x17, x7, x21
        // [2,120]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D================================================eeE-R  .    .    .    .    .    .   .   eor.16b	v6, v1, v0
        // [2,121]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==================================================eeER .    .    .    .    .    .   .   aese.16b	v4, v21
        // [2,122]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D====================================================eeER    .    .    .    .    .   .   aesmc.16b	v4, v4
        // [2,123]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    DeE----------------------------------------------------R    .    .    .    .    .   .   stp	x26, x17, [sp, #160]
        // [2,124]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==================================================eeE-R    .    .    .    .    .   .   aese.16b	v5, v26
        // [2,125]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D====================================================eeER   .    .    .    .    .   .   aesmc.16b	v5, v5
        // [2,126]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D================================================eeE----R   .    .    .    .    .   .   rev64.16b	v29, v3
        // [2,127]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D====================================================eeER  .    .    .    .    .   .   aese.16b	v8, v21
        // [2,128]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================eeER.    .    .    .    .   .   aesmc.16b	v8, v8
        // [2,129]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D================================================eeE------R.    .    .    .    .   .   ext.16b	v30, v6, v6, #8
        // [2,130]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE---------------------------------------------------R.    .    .    .    .   .   ldr	q11, [sp, #160]
        // [2,131]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D====================================================eeE-R.    .    .    .    .   .   aese.16b	v4, v22
        // [2,132]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D======================================================eeER    .    .    .    .   .   aesmc.16b	v4, v4
        // [2,133]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D=======================================================eeER   .    .    .    .   .   aese.16b	v5, v27
        // [2,134]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D================================================eeE-------R   .    .    .    .   .   ext.16b	v10, v29, v29, #8
        // [2,135]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D================================================eeE------R   .    .    .    .   .   str	q3, [x2, #32]
        // [2,136]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=======================================================eeER  .    .    .    .   .   aese.16b	v8, v22
        // [2,137]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=========================================================eeER.    .    .    .   .   aesmc.16b	v8, v8
        // [2,138]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D========================================================eeE-R.    .    .    .   .   eor.16b	v9, v11, v5
        // [2,139]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=======================================================eeE-R.    .    .    .   .   aese.16b	v4, v23
        // [2,140]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=======================================================eeER    .    .    .   .   aesmc.16b	v4, v4
        // [2,141]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .DeeeeeE----------------------------------------------------R    .    .    .   .   ldr	q1, [sp, #176]
        // [2,142]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================eeER   .    .    .   .   aese.16b	v8, v23
        // [2,143]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .    .   .   aesmc.16b	v8, v8
        // [2,144]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D========================================================eeE-R .    .    .   .   aese.16b	v4, v24
        // [2,145]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D==========================================================eeER.    .    .   .   aesmc.16b	v4, v4
        // [2,146]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D===================================================eeE----R.    .    .   .   str	q9, [x2], #64
        // [2,147]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D=====================================================eeE--R.    .    .   .   rev64.16b	v9, v9
        // [2,148]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D========================================================eeER    .    .   .   aese.16b	v8, v24
        // [2,149]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D==========================================================eeER  .    .   .   aesmc.16b	v8, v8
        // [2,150]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================eeE---------------R  .    .   .   eor.16b	v2, v10, v29
        // [2,151]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D========================================================eeE-R  .    .   .   aese.16b	v4, v25
        // [2,152]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==========================================================eeER .    .   .   aesmc.16b	v4, v4
        // [2,153]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D======================================================eeE----R .    .   .   eor.16b	v30, v9, v30
        // [2,154]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D===========================================================eeER.    .   .   aese.16b	v8, v25
        // [2,155]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D=============================================================eeER   .   .   aesmc.16b	v8, v8
        // [2,156]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    . D===========================================================eeE-R   .   .   aese.16b	v4, v26
        // [2,157]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D===========================================================eeER  .   .   aesmc.16b	v4, v4
        // [2,158]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeER .   .   aese.16b	v8, v26
        // [2,159]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D==============================================================eeER   .   aesmc.16b	v8, v8
        // [2,160]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D=====================================================eeE---------R   .   ext.16b	v6, v30, v30, #8
        // [2,161]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D============================================================eeE-R   .   aese.16b	v4, v27
        // [2,162]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    D======================================================eeE-------R   .   eor.16b	v5, v6, v30
        // [2,163]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .D==============================================================eeER .   aese.16b	v8, v27
        // [2,164]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================================eeE-R .   eor.16b	v0, v28, v4
        // [2,165]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D===========================================================eeE-R .   pmull.1q	v28, v30, v16
        // [2,166]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D=============================================================eeER.   pmull2.1q	v10, v30, v16
        // [2,167]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================================eeER   eor.16b	v1, v1, v8
        // [2,168]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .  D==============================================================eeER   pmull.1q	v11, v29, v13
        // [2,169]   .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .   D============================================================eeE-R   rev64.16b	v8, v0
        //
        //
        // Average Wait times (based on the timeline view):
        // [0]: Executions
        // [1]: Average time spent waiting in a scheduler's queue
        // [2]: Average time spent waiting in a scheduler's queue while ready
        // [3]: Average time elapsed from WB until retire stage
        //
        //       [0]    [1]    [2]    [3]
        // 0.     3     43.0   0.3    0.0       rev64.16b	v4, v1
        // 1.     3     42.3   7.0    0.7       pmull2.1q	v6, v5, v17
        // 2.     3     1.0    1.0    40.7      ldp	x19, x29, [x0, #16]
        // 3.     3     1.0    1.0    43.0      add	w26, w13, #1
        // 4.     3     41.3   1.3    0.3       pmull.1q	v31, v8, v12
        // 5.     3     37.7   0.3    2.3       stur	q0, [x2, #-16]
        // 6.     3     1.0    0.7    38.7      rev	w24, w26
        // 7.     3     1.0    1.0    38.7      add	w30, w13, #2
        // 8.     3     37.7   0.3    1.0       mov	d9, v8[1]
        // 9.     3     40.0   0.0    0.0       pmull2.1q	v3, v4, v15
        // 10.    3     1.0    0.0    39.0      orr	x22, x12, x24, lsl #32
        // 11.    3     1.0    0.0    39.0      rev	w17, w30
        // 12.    3     38.7   22.7   0.7       pmull2.1q	v30, v29, v13
        // 13.    3     39.0   0.0    0.3       mov	d0, v4[1]
        // 14.    3     36.0   0.0    4.3       stp	x11, x22, [sp, #176]
        // 15.    3     2.0    0.0    38.3      orr	x22, x12, x17, lsl #32
        // 16.    3     39.3   1.3    0.0       pmull.1q	v5, v4, v15
        // 17.    3     36.3   0.0    1.7       eor.8b	v9, v9, v8
        // 18.    3     34.7   1.3    3.7       stp	x11, x22, [sp, #192]
        // 19.    3     1.0    1.0    37.3      add	w25, w13, #0
        // 20.    3     38.0   0.0    0.0       eor.8b	v29, v0, v4
        // 21.    3     38.3   4.3    0.0       pmull2.1q	v4, v8, v12
        // 22.    3     1.0    1.0    38.0      add	w22, w13, #3
        // 23.    3     1.7    0.0    37.3      rev	w7, w25
        // 24.    3     38.3   1.7    0.0       pmull.1q	v9, v9, v14
        // 25.    3     1.3    1.3    33.3      ldr	q8, [sp, #176]
        // 26.    3     1.3    0.7    37.3      orr	x14, x12, x7, lsl #32
        // 27.    3     1.3    0.7    37.3      rev	w17, w22
        // 28.    3     38.0   23.3   0.3       pmull2.1q	v0, v2, v14
        // 29.    3     1.3    1.3    33.3      ldr	q2, [sp, #192]
        // 30.    3     1.3    0.7    36.0      orr	x28, x12, x17, lsl #32
        // 31.    3     36.7   1.3    0.3       pmull.1q	v29, v29, v17
        // 32.    3     1.3    1.3    36.7      add	w13, w13, #4
        // 33.    3     1.7    1.7    35.7      eor	x8, x29, x21
        // 34.    3     28.0   0.0    7.0       stp	x11, x28, [sp, #208]
        // 35.    3     30.3   1.0    3.7       eor.16b	v11, v31, v11
        // 36.    3     35.0   33.3   0.0       aese.16b	v8, v18
        // 37.    3     37.0   0.0    0.0       aesmc.16b	v8, v8
        // 38.    3     26.3   1.3    8.7       stp	x11, x14, [sp, #160]
        // 39.    3     33.0   31.3   1.0       aese.16b	v2, v18
        // 40.    3     35.0   0.0    0.0       aesmc.16b	v2, v2
        // 41.    3     29.7   0.0    5.3       eor.16b	v30, v4, v30
        // 42.    3     1.0    1.0    34.3      eor	x30, x19, x20
        // 43.    3     1.3    1.3    30.0      ldp	x10, x29, [x0, #48]
        // 44.    3     33.7   0.0    0.0       aese.16b	v8, v19
        // 45.    3     35.0   0.0    0.0       aesmc.16b	v8, v8
        // 46.    3     1.3    1.3    29.3      ldr	q4, [sp, #208]
        // 47.    3     32.7   0.0    1.0       aese.16b	v2, v19
        // 48.    3     34.7   0.0    0.0       aesmc.16b	v2, v2
        // 49.    3     24.3   0.3    9.3       eor.16b	v11, v11, v5
        // 50.    3     1.3    1.3    30.3      ldp	x22, x23, [x0, #32]
        // 51.    3     1.7    1.7    27.0      ldr	q5, [sp, #160]
        // 52.    3     32.7   0.0    0.0       aese.16b	v8, v20
        // 53.    3     34.7   0.0    0.0       aesmc.16b	v8, v8
        // 54.    3     2.3    0.7    33.3      eor	x19, x29, x21
        // 55.    3     24.3   0.3    10.0      eor.16b	v30, v30, v3
        // 56.    3     32.7   0.0    1.0       aese.16b	v2, v20
        // 57.    3     34.7   0.0    0.0       aesmc.16b	v2, v2
        // 58.    3     2.0    0.7    33.0      eor	x29, x10, x20
        // 59.    3     33.7   32.0   0.0       aese.16b	v4, v18
        // 60.    3     35.7   0.0    0.0       aesmc.16b	v4, v4
        // 61.    3     21.3   0.0    14.3      eor.16b	v11, v11, v28
        // 62.    3     2.3    0.7    34.3      eor	x27, x23, x21
        // 63.    3     22.7   1.3    12.7      eor.16b	v3, v9, v0
        // 64.    3     33.7   0.0    1.0       aese.16b	v2, v21
        // 65.    3     35.0   0.0    0.0       aesmc.16b	v2, v2
        // 66.    3     1.3    1.3    31.7      ldp	x24, x7, [x0], #64
        // 67.    3     22.3   0.3    12.7      eor.16b	v0, v30, v10
        // 68.    3     36.0   34.0   0.0       aese.16b	v5, v18
        // 69.    3     37.0   0.0    0.0       aesmc.16b	v5, v5
        // 70.    3     21.0   0.0    14.7      eor.16b	v30, v3, v29
        // 71.    3     34.7   0.0    1.0       aese.16b	v2, v22
        // 72.    3     36.7   0.0    0.0       aesmc.16b	v2, v2
        // 73.    3     37.0   0.0    0.0       aese.16b	v5, v19
        // 74.    3     39.0   0.0    0.0       aesmc.16b	v5, v5
        // 75.    3     21.3   0.0    17.7      eor.16b	v10, v11, v0
        // 76.    3     1.7    0.7    37.7      eor	x25, x22, x20
        // 77.    3     35.7   0.0    1.0       aese.16b	v2, v23
        // 78.    3     37.7   0.0    0.0       aesmc.16b	v2, v2
        // 79.    3     11.0   0.0    27.0      stp	x25, x27, [sp, #192]
        // 80.    3     12.0   1.3    24.7      stur	q1, [x2, #-48]
        // 81.    3     37.0   0.0    0.0       aese.16b	v5, v20
        // 82.    3     37.7   0.0    0.0       aesmc.16b	v5, v5
        // 83.    3     1.7    0.7    37.0      eor	x26, x24, x20
        // 84.    3     36.7   0.0    1.0       aese.16b	v2, v24
        // 85.    3     37.7   0.0    0.0       aesmc.16b	v2, v2
        // 86.    3     16.0   1.0    21.7      ext.16b	v28, v0, v0, #8
        // 87.    3     7.7    0.7    29.0      stp	x29, x19, [sp, #208]
        // 88.    3     14.3   1.0    20.7      eor.16b	v29, v30, v6
        // 89.    3     35.3   0.0    0.0       aese.16b	v5, v21
        // 90.    3     36.0   0.0    0.0       aesmc.16b	v5, v5
        // 91.    3     34.7   24.7   1.0       pmull.1q	v30, v0, v7
        // 92.    3     4.7    1.3    30.7      stp	x30, x8, [sp, #176]
        // 93.    3     12.7   0.0    21.7      eor.16b	v6, v29, v10
        // 94.    3     35.3   2.0    0.0       aese.16b	v2, v25
        // 95.    3     36.7   0.0    0.0       aesmc.16b	v2, v2
        // 96.    3     34.0   0.0    2.0       eor.16b	v3, v28, v30
        // 97.    3     34.7   0.0    1.0       aese.16b	v5, v22
        // 98.    3     36.7   0.0    0.0       aesmc.16b	v5, v5
        // 99.    3     36.3   0.0    0.0       aese.16b	v2, v26
        // 100.   3     38.3   0.0    0.0       aesmc.16b	v2, v2
        // 101.   3     2.3    2.3    33.0      ldr	q30, [sp, #192]
        // 102.   3     34.3   0.0    4.0       eor.16b	v6, v6, v3
        // 103.   3     37.3   0.0    1.0       aese.16b	v5, v23
        // 104.   3     39.0   0.0    0.0       aesmc.16b	v5, v5
        // 105.   3     40.0   23.0   0.0       aese.16b	v4, v19
        // 106.   3     41.3   0.0    0.0       aesmc.16b	v4, v4
        // 107.   3     2.0    2.0    36.3      ldr	q28, [sp, #208]
        // 108.   3     40.3   0.0    1.0       aese.16b	v5, v24
        // 109.   3     42.3   0.0    0.0       aesmc.16b	v5, v5
        // 110.   3     34.7   0.0    7.0       ext.16b	v0, v6, v6, #8
        // 111.   3     42.3   8.0    0.0       pmull.1q	v1, v6, v7
        // 112.   3     43.3   5.0    0.0       aese.16b	v2, v27
        // 113.   3     44.3   0.0    0.0       eor.16b	v1, v11, v1
        // 114.   3     44.3   2.0    0.0       aese.16b	v4, v20
        // 115.   3     46.3   0.0    0.0       aesmc.16b	v4, v4
        // 116.   3     45.3   0.0    1.0       eor.16b	v3, v30, v2
        // 117.   3     45.3   2.0    1.0       aese.16b	v5, v25
        // 118.   3     46.7   0.0    0.0       aesmc.16b	v5, v5
        // 119.   3     1.0    1.0    46.3      eor	x17, x7, x21
        // 120.   3     45.3   0.0    1.0       eor.16b	v6, v1, v0
        // 121.   3     47.3   0.0    0.0       aese.16b	v4, v21
        // 122.   3     49.3   0.0    0.0       aesmc.16b	v4, v4
        // 123.   3     1.3    0.0    48.3      stp	x26, x17, [sp, #160]
        // 124.   3     47.7   0.0    1.0       aese.16b	v5, v26
        // 125.   3     49.3   0.0    0.0       aesmc.16b	v5, v5
        // 126.   3     45.3   0.0    4.0       rev64.16b	v29, v3
        // 127.   3     49.7   41.0   0.0       aese.16b	v8, v21
        // 128.   3     51.7   0.0    0.0       aesmc.16b	v8, v8
        // 129.   3     45.7   0.0    6.0       ext.16b	v30, v6, v6, #8
        // 130.   3     1.0    1.0    47.7      ldr	q11, [sp, #160]
        // 131.   3     50.0   1.0    1.0       aese.16b	v4, v22
        // 132.   3     51.7   0.0    0.0       aesmc.16b	v4, v4
        // 133.   3     52.7   3.0    0.0       aese.16b	v5, v27
        // 134.   3     45.7   0.0    7.0       ext.16b	v10, v29, v29, #8
        // 135.   3     46.0   3.0    6.0       str	q3, [x2, #32]
        // 136.   3     53.0   1.0    0.0       aese.16b	v8, v22
        // 137.   3     54.7   0.0    0.0       aesmc.16b	v8, v8
        // 138.   3     53.7   0.0    1.0       eor.16b	v9, v11, v5
        // 139.   3     53.0   1.0    1.0       aese.16b	v4, v23
        // 140.   3     53.7   0.0    0.0       aesmc.16b	v4, v4
        // 141.   3     1.0    1.0    49.7      ldr	q1, [sp, #176]
        // 142.   3     54.7   0.0    0.0       aese.16b	v8, v23
        // 143.   3     56.7   0.0    0.0       aesmc.16b	v8, v8
        // 144.   3     54.7   0.0    1.0       aese.16b	v4, v24
        // 145.   3     56.7   0.0    0.0       aesmc.16b	v4, v4
        // 146.   3     50.7   0.0    4.0       str	q9, [x2], #64
        // 147.   3     52.7   2.0    2.0       rev64.16b	v9, v9
        // 148.   3     55.3   0.0    0.0       aese.16b	v8, v24
        // 149.   3     57.3   0.0    0.0       aesmc.16b	v8, v8
        // 150.   3     41.7   1.0    15.0      eor.16b	v2, v10, v29
        // 151.   3     55.7   0.0    1.0       aese.16b	v4, v25
        // 152.   3     57.7   0.0    0.0       aesmc.16b	v4, v4
        // 153.   3     53.7   0.0    4.0       eor.16b	v30, v9, v30
        // 154.   3     58.7   0.0    0.0       aese.16b	v8, v25
        // 155.   3     60.7   0.0    0.0       aesmc.16b	v8, v8
        // 156.   3     58.7   0.0    1.0       aese.16b	v4, v26
        // 157.   3     59.3   0.0    0.0       aesmc.16b	v4, v4
        // 158.   3     60.3   0.0    0.0       aese.16b	v8, v26
        // 159.   3     62.3   0.0    0.0       aesmc.16b	v8, v8
        // 160.   3     53.3   0.0    9.0       ext.16b	v6, v30, v30, #8
        // 161.   3     60.7   0.0    1.0       aese.16b	v4, v27
        // 162.   3     54.7   0.0    7.0       eor.16b	v5, v6, v30
        // 163.   3     63.0   0.0    0.0       aese.16b	v8, v27
        // 164.   3     60.0   0.0    1.0       eor.16b	v0, v28, v4
        // 165.   3     60.0   10.0   1.0       pmull.1q	v28, v30, v16
        // 166.   3     62.0   12.0   0.0       pmull2.1q	v10, v30, v16
        // 167.   3     63.0   0.0    0.0       eor.16b	v1, v1, v8
        // 168.   3     63.0   30.0   0.0       pmull.1q	v11, v29, v13
        // 169.   3     61.0   0.0    1.0       rev64.16b	v8, v0
        //        3     33.1   2.4    9.8       <total>
        //
        //
        // ORIGINAL LLVM MCA STATISTICS (OPTIMIZED) END
        //
        sub count, count, #1
        cbnz count, Lloop_unrolled_start
Lloop_unrolled_start_postamble:// end of loop kernel
                                                 // Instructions:    36
                                                 // Expected cycles: 25
                                                 // Expected IPC:    1.44
                                                 // ----- cycle (expected) ------>
                                                 // 0                        25
                                                 // |------------------------|----
        rev64 v30.16B, v1.16B                    // *.............................
        pmull2 v31.1q, v2.2d, v14.2d             // *.............................
        pmull2 v2.1q, v29.2d, v13.2d             // .*............................
        mov d6, v8.d[1]                          // .*............................
        pmull2 v3.1q, v30.2d, v15.2d             // ..*...........................
        mov d4, v30.d[1]                         // ..*...........................
        eor v9.8B, v6.8B, v8.8B                  // ...*..........................
        pmull2 v6.1q, v8.2d, v12.2d              // ...*..........................
        eor v29.8B, v4.8B, v30.8B                // ....*.........................
        pmull v4.1q, v8.1d, v12.1d               // ....*.........................
        eor v6.16B, v6.16B, v2.16B               // .....*........................
        pmull v2.1q, v9.1d, v14.1d               // .....*........................
        eor v9.16B, v4.16B, v11.16B              // ......*.......................
        pmull v8.1q, v30.1d, v15.1d              // ......*.......................
        pmull v11.1q, v29.1d, v17.1d             // .......*......................
        eor v29.16B, v6.16B, v3.16B              // .......*......................
        eor v6.16B, v2.16B, v31.16B              // ........*.....................
        eor v9.16B, v9.16B, v8.16B               // ........*.....................
        pmull2 v2.1q, v5.2d, v17.2d              // .........*....................
        eor v31.16B, v29.16B, v10.16B            // .........*....................
        eor v6.16B, v6.16B, v11.16B              // ..........*...................
        eor v3.16B, v9.16B, v28.16B              // ..........*...................
        ext v11.16B, v31.16B, v31.16B, #8        // ...........*..................
        pmull v10.1q, v31.1d, v7.1d              // ...........*..................
        eor v30.16B, v3.16B, v31.16B             // ............*.................
        eor v9.16B, v6.16B, v2.16B               // ............*.................
        eor v2.16B, v11.16B, v10.16B             // .............*................
        str q1, [x2, #-48]                       // .............*................
        str q0, [x2, #-16]                       // ..............*...............
        eor v29.16B, v9.16B, v30.16B             // ..............*...............
        eor v5.16B, v29.16B, v2.16B              // ................*.............
        pmull v1.1q, v5.1d, v7.1d                // ..................*...........
        ext v4.16B, v5.16B, v5.16B, #8           // ..................*...........
        eor v8.16B, v3.16B, v1.16B               // ....................*.........
        eor v3.16B, v8.16B, v4.16B               // ......................*.......
        ext v30.16B, v3.16B, v3.16B, #8          // ........................*.....

                                                                    // ------ cycle (expected) ------>
                                                                    // 0                        25
                                                                    // |------------------------|-----
        // rev64 V<ssa_0>.16B, v1.16B                               // *..............................
        // pmull2 V<ssa_1>.1q, v5.2d, v17.2d                        // .........*.....................
        // pmull V<ssa_5>.1q, v8.1d, v12.1d                         // ....*..........................
        // str q0, [x2, #-16]                                       // ..............*................
        // mov D<ssa_8>, v8.d[1]                                    // .*.............................
        // pmull2 V<ssa_9>.1q, V<ssa_0>.2d, v15.2d                  // ..*............................
        // pmull2 V<ssa_12>.1q, v29.2d, v13.2d                      // .*.............................
        // mov D<ssa_13>, V<ssa_0>.d[1]                             // ..*............................
        // pmull V<ssa_16>.1q, V<ssa_0>.1d, v15.1d                  // ......*........................
        // eor V<ssa_17>.8B, V<ssa_8>.8B, v8.8B                     // ...*...........................
        // eor V<ssa_20>.8B, V<ssa_13>.8B, V<ssa_0>.8B              // ....*..........................
        // pmull2 V<ssa_21>.1q, v8.2d, v12.2d                       // ...*...........................
        // pmull V<ssa_24>.1q, V<ssa_17>.1d, v14.1d                 // .....*.........................
        // pmull2 V<ssa_28>.1q, v2.2d, v14.2d                       // *..............................
        // pmull V<ssa_31>.1q, V<ssa_20>.1d, v17.1d                 // .......*.......................
        // eor V<ssa_34>.16B, V<ssa_5>.16B, v11.16B                 // ......*........................
        // eor V<ssa_36>.16B, V<ssa_21>.16B, V<ssa_12>.16B          // .....*.........................
        // eor V<ssa_41>.16B, V<ssa_34>.16B, V<ssa_16>.16B          // ........*......................
        // eor V<ssa_46>.16B, V<ssa_36>.16B, V<ssa_9>.16B           // .......*.......................
        // eor V<ssa_48>.16B, V<ssa_41>.16B, v28.16B                // ..........*....................
        // eor V<ssa_50>.16B, V<ssa_24>.16B, V<ssa_28>.16B          // ........*......................
        // eor V<ssa_53>.16B, V<ssa_46>.16B, v10.16B                // .........*.....................
        // eor V<ssa_54>.16B, V<ssa_50>.16B, V<ssa_31>.16B          // ..........*....................
        // eor V<ssa_55>.16B, V<ssa_48>.16B, V<ssa_53>.16B          // ............*..................
        // str q1, [x2, #-48]                                       // .............*.................
        // ext V<ssa_59>.16B, V<ssa_53>.16B, V<ssa_53>.16B, #8      // ...........*...................
        // eor V<ssa_61>.16B, V<ssa_54>.16B, V<ssa_1>.16B           // ............*..................
        // pmull V<ssa_62>.1q, V<ssa_53>.1d, v7.1d                  // ...........*...................
        // eor V<ssa_64>.16B, V<ssa_61>.16B, V<ssa_55>.16B          // ..............*................
        // eor V<ssa_65>.16B, V<ssa_59>.16B, V<ssa_62>.16B          // .............*.................
        // eor V<ssa_67>.16B, V<ssa_64>.16B, V<ssa_65>.16B          // ................*..............
        // ext V<ssa_69>.16B, V<ssa_67>.16B, V<ssa_67>.16B, #8      // ..................*............
        // pmull V<ssa_70>.1q, V<ssa_67>.1d, v7.1d                  // ..................*............
        // eor V<ssa_71>.16B, V<ssa_48>.16B, V<ssa_70>.16B          // ....................*..........
        // eor V<ssa_74>.16B, V<ssa_71>.16B, V<ssa_69>.16B          // ......................*........
        // ext v30.16B, V<ssa_74>.16B, V<ssa_74>.16B, #8            // ........................*......

        //
        // LLVM MCA STATISTICS (POSTAMBLE) BEGIN
        //
        //
        // [0] Code Region
        //
        // Iterations:        100
        // Instructions:      3600
        // Total Cycles:      2306
        // Total uOps:        4200
        //
        // Dispatch Width:    8
        // uOps Per Cycle:    1.82
        // IPC:               1.56
        // Block RThroughput: 11.5
        //
        //
        // Cycles with backend pressure increase [ 29.84% ]
        // Throughput Bottlenecks:
        //   Resource Pressure       [ 8.76% ]
        //   - N1UnitV0  [ 8.76% ]
        //   - N1UnitV1  [ 0.09% ]
        //   Data Dependencies:      [ 25.28% ]
        //   - Register Dependencies [ 25.28% ]
        //   - Memory Dependencies   [ 0.00% ]
        //
        // Critical sequence based on the simulation:
        //
        //               Instruction                                 Dependency Information
        //  +----< 23.   pmull.1q	v10, v31, v7
        //  |
        //  |    < loop carried >
        //  |
        //  |      0.    rev64.16b	v30, v1
        //  |      1.    pmull2.1q	v31, v2, v14
        //  |      2.    pmull2.1q	v2, v29, v13
        //  |      3.    mov	d6, v8[1]
        //  |      4.    pmull2.1q	v3, v30, v15
        //  |      5.    mov	d4, v30[1]
        //  |      6.    eor.8b	v9, v6, v8
        //  |      7.    pmull2.1q	v6, v8, v12
        //  |      8.    eor.8b	v29, v4, v30
        //  |      9.    pmull.1q	v4, v8, v12
        //  |      10.   eor.16b	v6, v6, v2
        //  |      11.   pmull.1q	v2, v9, v14
        //  |      12.   eor.16b	v9, v4, v11
        //  |      13.   pmull.1q	v8, v30, v15
        //  |      14.   pmull.1q	v11, v29, v17
        //  |      15.   eor.16b	v29, v6, v3
        //  |      16.   eor.16b	v6, v2, v31
        //  |      17.   eor.16b	v9, v9, v8
        //  |      18.   pmull2.1q	v2, v5, v17
        //  +----> 19.   eor.16b	v31, v29, v10                     ## REGISTER dependency:  q10
        //  |      20.   eor.16b	v6, v6, v11
        //  |      21.   eor.16b	v3, v9, v28
        //  +----> 22.   ext.16b	v11, v31, v31, #8                 ## REGISTER dependency:  q31
        //  +----> 23.   pmull.1q	v10, v31, v7                      ## RESOURCE interference:  N1UnitV0 [ probability: 99% ]
        //  |      24.   eor.16b	v30, v3, v31
        //  |      25.   eor.16b	v9, v6, v2
        //  +----> 26.   eor.16b	v2, v11, v10                      ## REGISTER dependency:  q10
        //  |      27.   stur	q1, [x2, #-48]
        //  |      28.   stur	q0, [x2, #-16]
        //  |      29.   eor.16b	v29, v9, v30
        //  +----> 30.   eor.16b	v5, v29, v2                       ## REGISTER dependency:  q2
        //  |      31.   pmull.1q	v1, v5, v7
        //  +----> 32.   ext.16b	v4, v5, v5, #8                    ## REGISTER dependency:  q5
        //  |      33.   eor.16b	v8, v3, v1
        //  +----> 34.   eor.16b	v3, v8, v4                        ## REGISTER dependency:  q4
        //  +----> 35.   ext.16b	v30, v3, v3, #8                   ## REGISTER dependency:  q3
        //
        //
        // Instruction Info:
        // [1]: #uOps
        // [2]: Latency
        // [3]: RThroughput
        // [4]: MayLoad
        // [5]: MayStore
        // [6]: HasSideEffects (U)
        //
        // [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
        //  1      2     0.50                        rev64.16b	v30, v1
        //  1      2     1.00                        pmull2.1q	v31, v2, v14
        //  1      2     1.00                        pmull2.1q	v2, v29, v13
        //  1      2     0.50                        mov	d6, v8[1]
        //  1      2     1.00                        pmull2.1q	v3, v30, v15
        //  1      2     0.50                        mov	d4, v30[1]
        //  1      2     0.50                        eor.8b	v9, v6, v8
        //  1      2     1.00                        pmull2.1q	v6, v8, v12
        //  1      2     0.50                        eor.8b	v29, v4, v30
        //  1      2     1.00                        pmull.1q	v4, v8, v12
        //  1      2     0.50                        eor.16b	v6, v6, v2
        //  1      2     1.00                        pmull.1q	v2, v9, v14
        //  1      2     0.50                        eor.16b	v9, v4, v11
        //  1      2     1.00                        pmull.1q	v8, v30, v15
        //  1      2     1.00                        pmull.1q	v11, v29, v17
        //  1      2     0.50                        eor.16b	v29, v6, v3
        //  1      2     0.50                        eor.16b	v6, v2, v31
        //  1      2     0.50                        eor.16b	v9, v9, v8
        //  1      2     1.00                        pmull2.1q	v2, v5, v17
        //  1      2     0.50                        eor.16b	v31, v29, v10
        //  1      2     0.50                        eor.16b	v6, v6, v11
        //  1      2     0.50                        eor.16b	v3, v9, v28
        //  1      2     0.50                        ext.16b	v11, v31, v31, #8
        //  1      2     1.00                        pmull.1q	v10, v31, v7
        //  1      2     0.50                        eor.16b	v30, v3, v31
        //  1      2     0.50                        eor.16b	v9, v6, v2
        //  1      2     0.50                        eor.16b	v2, v11, v10
        //  4      2     1.00           *            stur	q1, [x2, #-48]
        //  4      2     1.00           *            stur	q0, [x2, #-16]
        //  1      2     0.50                        eor.16b	v29, v9, v30
        //  1      2     0.50                        eor.16b	v5, v29, v2
        //  1      2     1.00                        pmull.1q	v1, v5, v7
        //  1      2     0.50                        ext.16b	v4, v5, v5, #8
        //  1      2     0.50                        eor.16b	v8, v3, v1
        //  1      2     0.50                        eor.16b	v3, v8, v4
        //  1      2     0.50                        ext.16b	v30, v3, v3, #8
        //
        //
        // Dynamic Dispatch Stall Cycles:
        // RAT     - Register unavailable:                      0
        // RCU     - Retire tokens unavailable:                 2019  (87.6%)
        // SCHEDQ  - Scheduler full:                            0
        // LQ      - Load queue full:                           0
        // SQ      - Store queue full:                          0
        // GROUP   - Static restrictions on the dispatch group: 0
        // USH     - Uncategorised Structural Hazard:           0
        //
        //
        // Dispatch Logic - number of cycles where we saw N micro opcodes dispatched:
        // [# dispatched], [# cycles]
        //  0,              650  (28.2%)
        //  1,              577  (25.0%)
        //  2,              673  (29.2%)
        //  3,              192  (8.3%)
        //  4,              1  (0.0%)
        //  6,              3  (0.1%)
        //  7,              1  (0.0%)
        //  8,              209  (9.1%)
        //
        //
        // Schedulers - number of cycles where we saw N micro opcodes issued:
        // [# issued], [# cycles]
        //  0,          207  (9.0%)
        //  1,          798  (34.6%)
        //  2,          1200  (52.0%)
        //  6,          2  (0.1%)
        //  10,          99  (4.3%)
        //
        // Scheduler's queue usage:
        // No scheduler resources used.
        //
        //
        // Retire Control Unit - number of cycles where we saw N instructions retired:
        // [# retired], [# cycles]
        //  0,           504  (21.9%)
        //  1,           797  (34.6%)
        //  2,           707  (30.7%)
        //  3,           199  (8.6%)
        //  8,           99  (4.3%)
        //
        // Total ROB Entries:                128
        // Max Used ROB Entries:             128  ( 100.0% )
        // Average Used ROB Entries per cy:  125  ( 97.7% )
        //
        //
        // Register File statistics:
        // Total number of mappings created:    3400
        // Max number of mappings used:         104
        //
        //
        // Resources:
        // [0]   - N1UnitB
        // [1.0] - N1UnitD
        // [1.1] - N1UnitD
        // [2.0] - N1UnitL
        // [2.1] - N1UnitL
        // [3]   - N1UnitM
        // [4.0] - N1UnitS
        // [4.1] - N1UnitS
        // [5]   - N1UnitV0
        // [6]   - N1UnitV1
        //
        //
        // Resource pressure per iteration:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]
        //  -      -      -     2.00   2.00   1.00   1.50   1.50   17.99  16.01
        //
        // Resource pressure by instruction:
        // [0]    [1.0]  [1.1]  [2.0]  [2.1]  [3]    [4.0]  [4.1]  [5]    [6]    Instructions:
        //  -      -      -      -      -      -      -      -     0.99   0.01   rev64.16b	v30, v1
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v31, v2, v14
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v2, v29, v13
        //  -      -      -      -      -      -      -      -     0.99   0.01   mov	d6, v8[1]
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v3, v30, v15
        //  -      -      -      -      -      -      -      -      -     1.00   mov	d4, v30[1]
        //  -      -      -      -      -      -      -      -     0.99   0.01   eor.8b	v9, v6, v8
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v6, v8, v12
        //  -      -      -      -      -      -      -      -      -     1.00   eor.8b	v29, v4, v30
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v4, v8, v12
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v6, v6, v2
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v2, v9, v14
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v9, v4, v11
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v8, v30, v15
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v11, v29, v17
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v29, v6, v3
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v6, v2, v31
        //  -      -      -      -      -      -      -      -     1.00    -     eor.16b	v9, v9, v8
        //  -      -      -      -      -      -      -      -     1.00    -     pmull2.1q	v2, v5, v17
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v31, v29, v10
        //  -      -      -      -      -      -      -      -     0.99   0.01   eor.16b	v6, v6, v11
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v3, v9, v28
        //  -      -      -      -      -      -      -      -     0.99   0.01   ext.16b	v11, v31, v31, #8
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v10, v31, v7
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v30, v3, v31
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v9, v6, v2
        //  -      -      -      -      -      -      -      -     0.99   0.01   eor.16b	v2, v11, v10
        //  -      -      -      -     2.00   1.00   0.50   0.50    -      -     stur	q1, [x2, #-48]
        //  -      -      -     2.00    -      -     1.00   1.00    -      -     stur	q0, [x2, #-16]
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v29, v9, v30
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v5, v29, v2
        //  -      -      -      -      -      -      -      -     1.00    -     pmull.1q	v1, v5, v7
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v4, v5, v5, #8
        //  -      -      -      -      -      -      -      -      -     1.00   eor.16b	v8, v3, v1
        //  -      -      -      -      -      -      -      -     0.01   0.99   eor.16b	v3, v8, v4
        //  -      -      -      -      -      -      -      -      -     1.00   ext.16b	v30, v3, v3, #8
        //
        //
        // Timeline view:
        //                     0123456789          0123456789          0123456789          01234
        // Index     0123456789          0123456789          0123456789          0123456789
        //
        // [0,0]     DeeER.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   rev64.16b	v30, v1
        // [0,1]     DeeER.    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v31, v2, v14
        // [0,2]     D=eeER    .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v2, v29, v13
        // [0,3]     D=eeER    .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d6, v8[1]
        // [0,4]     D==eeER   .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v3, v30, v15
        // [0,5]     D==eeER   .    .    .    .    .    .    .    .    .    .    .    .    .   .   mov	d4, v30[1]
        // [0,6]     D===eeER  .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v9, v6, v8
        // [0,7]     D===eeER  .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v6, v8, v12
        // [0,8]     .D===eeER .    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.8b	v29, v4, v30
        // [0,9]     .D===eeER .    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v4, v8, v12
        // [0,10]    .D====eeER.    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v2
        // [0,11]    .D====eeER.    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v2, v9, v14
        // [0,12]    .D=====eeER    .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v9, v4, v11
        // [0,13]    .D=====eeER    .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v8, v30, v15
        // [0,14]    .D======eeER   .    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v11, v29, v17
        // [0,15]    .D======eeER   .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v29, v6, v3
        // [0,16]    . D======eeER  .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v2, v31
        // [0,17]    . D======eeER  .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v9, v9, v8
        // [0,18]    . D=======eeER .    .    .    .    .    .    .    .    .    .    .    .   .   pmull2.1q	v2, v5, v17
        // [0,19]    . D=======eeER .    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v31, v29, v10
        // [0,20]    . D========eeER.    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v11
        // [0,21]    . D========eeER.    .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v9, v28
        // [0,22]    . D=========eeER    .    .    .    .    .    .    .    .    .    .    .   .   ext.16b	v11, v31, v31, #8
        // [0,23]    . D=========eeER    .    .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v10, v31, v7
        // [0,24]    .  D=========eeER   .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v30, v3, v31
        // [0,25]    .  D=========eeER   .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v9, v6, v2
        // [0,26]    .  D==========eeER  .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v2, v11, v10
        // [0,27]    .  DeeE----------R  .    .    .    .    .    .    .    .    .    .    .   .   stur	q1, [x2, #-48]
        // [0,28]    .   DeeE---------R  .    .    .    .    .    .    .    .    .    .    .   .   stur	q0, [x2, #-16]
        // [0,29]    .   D==========eeER .    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v29, v9, v30
        // [0,30]    .   D============eeER    .    .    .    .    .    .    .    .    .    .   .   eor.16b	v5, v29, v2
        // [0,31]    .   D==============eeER  .    .    .    .    .    .    .    .    .    .   .   pmull.1q	v1, v5, v7
        // [0,32]    .   D==============eeER  .    .    .    .    .    .    .    .    .    .   .   ext.16b	v4, v5, v5, #8
        // [0,33]    .    D===============eeER.    .    .    .    .    .    .    .    .    .   .   eor.16b	v8, v3, v1
        // [0,34]    .    D=================eeER   .    .    .    .    .    .    .    .    .   .   eor.16b	v3, v8, v4
        // [0,35]    .    D===================eeER .    .    .    .    .    .    .    .    .   .   ext.16b	v30, v3, v3, #8
        // [1,0]     .    D===============eeE----R .    .    .    .    .    .    .    .    .   .   rev64.16b	v30, v1
        // [1,1]     .    D==========eeE---------R .    .    .    .    .    .    .    .    .   .   pmull2.1q	v31, v2, v14
        // [1,2]     .    D===========eeE--------R .    .    .    .    .    .    .    .    .   .   pmull2.1q	v2, v29, v13
        // [1,3]     .    D=================eeE--R .    .    .    .    .    .    .    .    .   .   mov	d6, v8[1]
        // [1,4]     .    D==================eeE-R .    .    .    .    .    .    .    .    .   .   pmull2.1q	v3, v30, v15
        // [1,5]     .    .D=================eeE-R .    .    .    .    .    .    .    .    .   .   mov	d4, v30[1]
        // [1,6]     .    .D==================eeER .    .    .    .    .    .    .    .    .   .   eor.8b	v9, v6, v8
        // [1,7]     .    .D===================eeER.    .    .    .    .    .    .    .    .   .   pmull2.1q	v6, v8, v12
        // [1,8]     .    .D===================eeER.    .    .    .    .    .    .    .    .   .   eor.8b	v29, v4, v30
        // [1,9]     .    .D====================eeER    .    .    .    .    .    .    .    .   .   pmull.1q	v4, v8, v12
        // [1,10]    .    .D=====================eeER   .    .    .    .    .    .    .    .   .   eor.16b	v6, v6, v2
        // [1,11]    .    .D=====================eeER   .    .    .    .    .    .    .    .   .   pmull.1q	v2, v9, v14
        // [1,12]    .    .D======================eeER  .    .    .    .    .    .    .    .   .   eor.16b	v9, v4, v11
        // [1,13]    .    . D=====================eeER  .    .    .    .    .    .    .    .   .   pmull.1q	v8, v30, v15
        // [1,14]    .    . D======================eeER .    .    .    .    .    .    .    .   .   pmull.1q	v11, v29, v17
        // [1,15]    .    . D======================eeER .    .    .    .    .    .    .    .   .   eor.16b	v29, v6, v3
        // [1,16]    .    . D=======================eeER.    .    .    .    .    .    .    .   .   eor.16b	v6, v2, v31
        // [1,17]    .    . D=======================eeER.    .    .    .    .    .    .    .   .   eor.16b	v9, v9, v8
        // [1,18]    .    . D============eeE-----------R.    .    .    .    .    .    .    .   .   pmull2.1q	v2, v5, v17
        // [1,19]    .    . D========================eeER    .    .    .    .    .    .    .   .   eor.16b	v31, v29, v10
        // [1,20]    .    . D=========================eeER   .    .    .    .    .    .    .   .   eor.16b	v6, v6, v11
        // [1,21]    .    .  D========================eeER   .    .    .    .    .    .    .   .   eor.16b	v3, v9, v28
        // [1,22]    .    .  D=========================eeER  .    .    .    .    .    .    .   .   ext.16b	v11, v31, v31, #8
        // [1,23]    .    .  D==========================eeER .    .    .    .    .    .    .   .   pmull.1q	v10, v31, v7
        // [1,24]    .    .  D==========================eeER .    .    .    .    .    .    .   .   eor.16b	v30, v3, v31
        // [1,25]    .    .  D===========================eeER.    .    .    .    .    .    .   .   eor.16b	v9, v6, v2
        // [1,26]    .    .  D============================eeER    .    .    .    .    .    .   .   eor.16b	v2, v11, v10
        // [1,27]    .    .   D===========eeE----------------R    .    .    .    .    .    .   .   stur	q1, [x2, #-48]
        // [1,28]    .    .   D===========eeE----------------R    .    .    .    .    .    .   .   stur	q0, [x2, #-16]
        // [1,29]    .    .    D===========================eeER   .    .    .    .    .    .   .   eor.16b	v29, v9, v30
        // [1,30]    .    .    D=============================eeER .    .    .    .    .    .   .   eor.16b	v5, v29, v2
        // [1,31]    .    .    D===============================eeER    .    .    .    .    .   .   pmull.1q	v1, v5, v7
        // [1,32]    .    .    D===============================eeER    .    .    .    .    .   .   ext.16b	v4, v5, v5, #8
        // [1,33]    .    .    D=================================eeER  .    .    .    .    .   .   eor.16b	v8, v3, v1
        // [1,34]    .    .    D===================================eeER.    .    .    .    .   .   eor.16b	v3, v8, v4
        // [1,35]    .    .    D=====================================eeER   .    .    .    .   .   ext.16b	v30, v3, v3, #8
        // [2,0]     .    .    D=================================eeE----R   .    .    .    .   .   rev64.16b	v30, v1
        // [2,1]     .    .    .D===========================eeE---------R   .    .    .    .   .   pmull2.1q	v31, v2, v14
        // [2,2]     .    .    .D============================eeE--------R   .    .    .    .   .   pmull2.1q	v2, v29, v13
        // [2,3]     .    .    .D==================================eeE--R   .    .    .    .   .   mov	d6, v8[1]
        // [2,4]     .    .    .D===================================eeE-R   .    .    .    .   .   pmull2.1q	v3, v30, v15
        // [2,5]     .    .    .D===================================eeE-R   .    .    .    .   .   mov	d4, v30[1]
        // [2,6]     .    .    .D====================================eeER   .    .    .    .   .   eor.8b	v9, v6, v8
        // [2,7]     .    .    .D=====================================eeER  .    .    .    .   .   pmull2.1q	v6, v8, v12
        // [2,8]     .    .    .D=====================================eeER  .    .    .    .   .   eor.8b	v29, v4, v30
        // [2,9]     .    .    . D=====================================eeER .    .    .    .   .   pmull.1q	v4, v8, v12
        // [2,10]    .    .    . D======================================eeER.    .    .    .   .   eor.16b	v6, v6, v2
        // [2,11]    .    .    . D======================================eeER.    .    .    .   .   pmull.1q	v2, v9, v14
        // [2,12]    .    .    . D=======================================eeER    .    .    .   .   eor.16b	v9, v4, v11
        // [2,13]    .    .    . D=======================================eeER    .    .    .   .   pmull.1q	v8, v30, v15
        // [2,14]    .    .    . D========================================eeER   .    .    .   .   pmull.1q	v11, v29, v17
        // [2,15]    .    .    . D========================================eeER   .    .    .   .   eor.16b	v29, v6, v3
        // [2,16]    .    .    . D=========================================eeER  .    .    .   .   eor.16b	v6, v2, v31
        // [2,17]    .    .    .  D========================================eeER  .    .    .   .   eor.16b	v9, v9, v8
        // [2,18]    .    .    .  D=============================eeE-----------R  .    .    .   .   pmull2.1q	v2, v5, v17
        // [2,19]    .    .    .  D=========================================eeER .    .    .   .   eor.16b	v31, v29, v10
        // [2,20]    .    .    .  D==========================================eeER.    .    .   .   eor.16b	v6, v6, v11
        // [2,21]    .    .    .  D==========================================eeER.    .    .   .   eor.16b	v3, v9, v28
        // [2,22]    .    .    .  D===========================================eeER    .    .   .   ext.16b	v11, v31, v31, #8
        // [2,23]    .    .    .  D============================================eeER   .    .   .   pmull.1q	v10, v31, v7
        // [2,24]    .    .    .  D============================================eeER   .    .   .   eor.16b	v30, v3, v31
        // [2,25]    .    .    .   D============================================eeER  .    .   .   eor.16b	v9, v6, v2
        // [2,26]    .    .    .   D=============================================eeER .    .   .   eor.16b	v2, v11, v10
        // [2,27]    .    .    .   D=============================eeE----------------R .    .   .   stur	q1, [x2, #-48]
        // [2,28]    .    .    .    D============================eeE----------------R .    .   .   stur	q0, [x2, #-16]
        // [2,29]    .    .    .    D=============================================eeER.    .   .   eor.16b	v29, v9, v30
        // [2,30]    .    .    .    D===============================================eeER   .   .   eor.16b	v5, v29, v2
        // [2,31]    .    .    .    D=================================================eeER .   .   pmull.1q	v1, v5, v7
        // [2,32]    .    .    .    D=================================================eeER .   .   ext.16b	v4, v5, v5, #8
        // [2,33]    .    .    .    .D==================================================eeER   .   eor.16b	v8, v3, v1
        // [2,34]    .    .    .    .D====================================================eeER .   eor.16b	v3, v8, v4
        // [2,35]    .    .    .    .D======================================================eeER   ext.16b	v30, v3, v3, #8
        //
        //
        // Average Wait times (based on the timeline view):
        // [0]: Executions
        // [1]: Average time spent waiting in a scheduler's queue
        // [2]: Average time spent waiting in a scheduler's queue while ready
        // [3]: Average time elapsed from WB until retire stage
        //
        //       [0]    [1]    [2]    [3]
        // 0.     3     17.0   0.3    2.7       rev64.16b	v30, v1
        // 1.     3     13.3   0.3    6.0       pmull2.1q	v31, v2, v14
        // 2.     3     14.3   0.7    5.3       pmull2.1q	v2, v29, v13
        // 3.     3     18.3   0.7    1.3       mov	d6, v8[1]
        // 4.     3     19.3   0.7    0.7       pmull2.1q	v3, v30, v15
        // 5.     3     19.0   0.7    0.7       mov	d4, v30[1]
        // 6.     3     20.0   0.0    0.0       eor.8b	v9, v6, v8
        // 7.     3     20.7   3.3    0.0       pmull2.1q	v6, v8, v12
        // 8.     3     20.7   0.0    0.0       eor.8b	v29, v4, v30
        // 9.     3     21.0   4.0    0.0       pmull.1q	v4, v8, v12
        // 10.    3     22.0   0.0    0.0       eor.16b	v6, v6, v2
        // 11.    3     22.0   0.7    0.0       pmull.1q	v2, v9, v14
        // 12.    3     23.0   0.0    0.0       eor.16b	v9, v4, v11
        // 13.    3     22.7   5.3    0.0       pmull.1q	v8, v30, v15
        // 14.    3     23.7   1.7    0.0       pmull.1q	v11, v29, v17
        // 15.    3     23.7   0.0    0.0       eor.16b	v29, v6, v3
        // 16.    3     24.3   1.0    0.0       eor.16b	v6, v2, v31
        // 17.    3     24.0   0.0    0.0       eor.16b	v9, v9, v8
        // 18.    3     17.0   3.3    7.3       pmull2.1q	v2, v5, v17
        // 19.    3     25.0   0.0    0.0       eor.16b	v31, v29, v10
        // 20.    3     26.0   0.0    0.0       eor.16b	v6, v6, v11
        // 21.    3     25.7   0.0    0.0       eor.16b	v3, v9, v28
        // 22.    3     26.7   0.0    0.0       ext.16b	v11, v31, v31, #8
        // 23.    3     27.3   0.7    0.0       pmull.1q	v10, v31, v7
        // 24.    3     27.3   0.0    0.0       eor.16b	v30, v3, v31
        // 25.    3     27.7   0.7    0.0       eor.16b	v9, v6, v2
        // 26.    3     28.7   0.0    0.0       eor.16b	v2, v11, v10
        // 27.    3     14.3   0.3    14.0      stur	q1, [x2, #-48]
        // 28.    3     14.0   0.3    13.7      stur	q0, [x2, #-16]
        // 29.    3     28.3   0.0    0.0       eor.16b	v29, v9, v30
        // 30.    3     30.3   0.0    0.0       eor.16b	v5, v29, v2
        // 31.    3     32.3   0.0    0.0       pmull.1q	v1, v5, v7
        // 32.    3     32.3   0.0    0.0       ext.16b	v4, v5, v5, #8
        // 33.    3     33.7   0.0    0.0       eor.16b	v8, v3, v1
        // 34.    3     35.7   0.0    0.0       eor.16b	v3, v8, v4
        // 35.    3     37.7   0.0    0.0       ext.16b	v30, v3, v3, #8
        //        3     23.9   0.7    1.4       <total>
        //
        //
        // ORIGINAL LLVM MCA STATISTICS (POSTAMBLE) END
        //
        b Lloop_unrolled_start_end
Lloop_unrolled_start_end:
Lloop_unrolled_end:

        cbz remainder, Lloop_1x_end
Lloop_1x_start:

        ldp plain_lo, plain_hi, [input], #16
        aes_full_block aes_st, plain, res, 0
        str res_q, [output], #16
        ghash_init_with_tag_0 res, Ht1, Ht12, tag

        ghash_finalize tag

        add ctr, ctr, #1
        sub remainder, remainder, #1
        cbnz remainder, Lloop_1x_start
Lloop_1x_end:

        // Return number of bytes processed
        mov x0, byte_len
        // Store new authentication tag
        rev64 tag.16b, tag.16b
        str tag_q, [tag_ptr]

        // Store updated counter
        // rev32 rtmp_ctr.16b, rtmp_ctr.16b
        // str rtmp_ctr_q, [ivec]
        rev ctr_tmp_w, ctr
        str ctr_tmp_w, [ivec, #12]

        restore_vregs
        restore_gprs

Lenc_postamble_end:
        add sp, sp, #STACK_SIZE

        ret

#endif
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__APPLE__)
#if defined(__ELF__)
// See https: // www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif