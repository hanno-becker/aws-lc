#!/usr/bin/env sh
set -e

# Optimize AES-GCM variant via SLOTHY
#
# Usage:
# > [SZ=128/192/256] [SLOTHY_FLAGS=...] [UARCH={N1,V1}] optimize.sh variant
#
# SLOTHY_FLAGS is passed to slothy-cli unmodified.
#
# SZ defaults to 128 (for AES-GCM-128)
#
# Use
# > optimize.sh --help
# to list all available examples.

CLEAN_DIR=./clean
OPT_DIR=./opt
TMP_DIR=./tmp
ASM_DIR=../

if [ "$SZ" = "" ]; then
    SZ=128
    echo "No keysize specified -- defaulting to 128 bit"
fi

if [ "$AWS_LC_BASE" = "" ]; then
    # Oof... bit gross
    AWS_LC_BASE=$(dirname $(dirname $(dirname $(dirname $(dirname $(pwd))))))
    echo "Environment variable AWS_LC_BASE not set. Defaulting to $AWS_LC_BASE."
fi

BUILD_DIR=build_release

CLEAN_STEM=aesv8-gcm-armv8-base-${SZ}
OPT_STEM=aesv8-gcm-armv8-opt-${SZ}
TMP_STEM=aesv8-gcm-armv8-tmp-${SZ}

UARCH=${UARCH:=N1}
if [ $UARCH = "N1" ]; then
    MODEL=Arm_Neoverse_N1_experimental
elif [ $UARCH = "V1" ]; then
    MODEL=Arm_Big_experimental
else
    echo "Unknown microarchitecture: Choose from {N1, V1}"
    exit 1
fi

if [ $SZ = "128" ]; then
    VARIANTS_ALL="
    x4_basic
    x4_late_tag
    x4_ilp
    x4_dual_acc
    x4_dual_acc_keep_htable
    x4_keep_htable
    x4_keep_htable_rotate
    x4_reload_round_keys_partial
    x4_reload_round_keys_full
    x4_scalar_iv
    x4_scalar_iv_mem
    x4_scalar_iv_mem_late_tag
    x4_scalar_iv_mem_late_tag_keep_htable
    x6_basic
    x8_basic
    x6_ilp
    x8_ilp
    x8_ilp_dual_acc
    x8_ilp_rotate
    x8_ilp_rotate_dual_acc
    x8_ilp_rotate_manual_eor3
    x8_reload
    x8_reload_ldp_stp
    x8_reload_ldp_stp_dual_acc
    x8_reload_ldp_stp_simpler
    x8_reload_ldp_stp_simpler_manual_rotate
    "
elif [ $SZ = "192" ]; then
    VARIANTS_ALL="
    x4_basic
    x4_reload_round_keys_partial
    "
else
    VARIANTS_ALL="
    x4_basic
    x4_reload_round_keys_partial
    "
fi

VERBOSE=${VERBOSE:=0}
TIMEOUT=${TIMEOUT:=1200} # 20min timeout by default

if [ "$1" = "--help" ]; then
    echo "Usage: optimize.sh variant"
    echo "Known variants:"
    for var in $VARIANTS_ALL; do
        echo "- $var"
    done
    exit 1
fi

TODO=$@
if [ "$TODO" = "" ]; then
    echo "No variant provided -- optimizing all."
    echo "WARNING: This will take a long time."
    TODO=$VARIANTS_ALL
fi

if [ "$DRY_RUN" = "1" ]; then
    echo "NOTE: Performing dry run -- no renaming/rescheduling allowed, but checking that SLOTHY understands the code and commands."
    DRY_RUN_FLAGS=" -c /constraints.allow_reordering -c /constraints.allow_renaming -c constraints.stalls_first_attempt=256"
else
    DRY_RUN_FLAGS=""
fi

if [ "$LLVM_MCA" = "1" ]; then
    LLVM_MCA_FLAGS="-c with_llvm_mca -c llvm_mca_full"
else
    LLVM_MCA_FLAGS=""
fi

optimize_x4() {
            slothy-cli Arm_AArch64 $MODEL                      \
                  ${INFILE}                                    \
               -l Lloop_unrolled_start                         \
               -c compiler_binary=clang                        \
               -c compiler_include_paths="${AWS_LC_BASE}/include"\
               -c inputs_are_outputs                           \
               -c variable_size                                \
               -c constraints.stalls_first_attempt=48          \
               -c sw_pipelining.enabled                        \
               -c timeout=$TIMEOUT                             \
               -c visualize_expected_performance               \
               -c sw_pipelining.allow_post                     \
               ${LLVM_MCA_FLAGS}                               \
               -c /sw_pipelining.minimize_overlapping          \
               -c sw_pipelining.unknown_iteration_count        \
               -c reserved_regs=[sp,x1,x3,x4,x5,x6,x9,x15,x16,x18]\
               -o $OUTFILE                                     \
               ${SLOTHY_FLAGS} ${DRY_RUN_FLAGS}
}

optimize_x8() {
    slothy-cli Arm_AArch64 $MODEL ${INFILE} -l Lloop_unrolled_start               \
                 -c compiler_binary=clang                        \
                 -c inputs_are_outputs                           \
                 -c visualize_expected_performance               \
                 -c variable_size                                \
                 -c constraints.stalls_first_attempt=16          \
                 -c split_heuristic                              \
                 -c timeout=$TIMEOUT                             \
                 -c split_heuristic_preprocess_naive_interleaving \
                 -c split_heuristic_repeat=3                     \
                 -c split_heuristic_factor=2                     \
                 -c constraints.move_stalls_to_bottom            \
                 -c constraints.stalls_precision=3               \
                 -c objective_precision=0.1 \
                 -c retry_timeout=60\
                 -c reserved_regs=[sp,x1,x3,x4,x5,x6,x9,x15,x16,x18]\
                 -o $OUTFILE                                        \
                 ${SLOTHY_FLAGS} ${DRY_RUN_FLAGS}
}

optimize_generic() {
            slothy-cli Arm_AArch64 $MODEL                      \
                  ${INFILE}                                    \
               -l Lloop_unrolled_start                         \
               -c compiler_binary=clang                        \
               -c inputs_are_outputs                           \
               -c visualize_expected_performance               \
               -c variable_size                                \
               -c constraints.stalls_first_attempt=36          \
               -c sw_pipelining.enabled                        \
               -c timeout=$TIMEOUT                             \
               -c /sw_pipelining.minimize_overlapping          \
               -c sw_pipelining.unknown_iteration_count        \
               -c reserved_regs=[sp,x1,x3,x4,x5,x15,x16,x18]   \
               -o $OUTFILE                                     \
               ${SLOTHY_FLAGS} ${DRY_RUN_FLAGS}
}

optimize_variant() {
    echo "Optimizing variant $1 ..."
    INFILE=$CLEAN_DIR/${CLEAN_STEM}_$1.S
    OUTFILE=$OPT_DIR/${OPT_STEM}_$1.S
    TMP0=$TMP_DIR/${TMP_STEM}_$1_0.S
    TMP1=$TMP_DIR/${TMP_STEM}_$1_1.S
    TMP2=$TMP_DIR/${TMP_STEM}_$1_2.S
    case $1 in                            \
        x4_*)

            optimize_x4
            ;;

        x8_*)

            optimize_x8
            ;;

        *)
            echo "NOTE: No dedicated optimization command for $1 registered -- trying default optimization via software pipelining..."

            optimize_generic
    esac
}

for v in $TODO
do
    optimize_variant $v
done
