#!/usr/bin/env sh
#
# Build and test AES-GCM variants
#
# Usage:
# > [BENCH=0/1] [AWS_LC_BASE=PATH] [BUILD_DIR=DIRNAME] [VERBOSE=0/1] [OPT=0/1] test.sh [variant]
#
# This script tests that the assembly files in clean/ or opt/ can be used as drop-in
# replacements for the default aesv8-gcm-armv8-base-{128,192,256}
#
# If BENCH=1, it also runs OpenSSL's `bssl speed` to benchmark performance.

set -e

if [ "$AWS_LC_BASE" = "" ]; then
    # Oof... bit gross
    AWS_LC_BASE=$(dirname $(dirname $(dirname $(dirname $(dirname $(pwd))))))
    echo "Environment variable AWS_LC_BASE not set. Defaulting to $AWS_LC_BASE."
fi

if [ "$BUILD_DIR" = "" ]; then
    BUILD_DIR="build_release"
    echo "Environment variable BUILD_DIR not set. Defaulting to $BUILD_DIR."
fi

if [ "$OPT" = "" ]; then
    OPT=0
    echo "Environment variable OPT not set. Defaulting to OPT=0 (testing clean variants)."
fi

if [ "$VERBOSE" = "" ]; then
    VERBOSE=0
    echo "Environment variable VERBOSE not set. Defaulting to VERBOSE=0 (silent mode)."
fi

if [ "$SZ" = "" ]; then
    SZ=128
    echo "No keysize specified -- defaulting to 128 bit"
fi

TIMEOUT=5 # Run tests for 5 seconds -- they often hang upon a bug
KEEP_GOING=${KEEP_GOING:=0}

ASM_DIR=../
AES_SLOTHY_ASM=aesv8-gcm-armv8-slothy-${SZ}.S

if [ "$OPT" = "0" ]; then
    DIR=./clean
    FILE_STEM=aesv8-gcm-armv8-base-${SZ}
else
    DIR=./opt
    FILE_STEM=aesv8-gcm-armv8-opt-${SZ}
fi

set_variant() {
    cp $DIR/${FILE_STEM}_$1.S $ASM_DIR/$AES_SLOTHY_ASM
}

build_variant() {
    if [ $VERBOSE -eq 1 ]; then
        ninja -C $AWS_LC_BASE/$BUILD_DIR
    else
        ninja -C $AWS_LC_BASE/$BUILD_DIR > /dev/null 2>&1
    fi
}

test_variant() {
    if [ $VERBOSE -eq 1 ]; then
        timeout --foreground $TIMEOUT ${AWS_LC_BASE}/${BUILD_DIR}/crypto/crypto_test --gtest_filter="*AES*"
    else
        timeout --foreground $TIMEOUT ${AWS_LC_BASE}/${BUILD_DIR}/crypto/crypto_test --gtest_filter="*AES*" > /dev/null
    fi
}

BENCH_TIMEOUT=7
bench_variant() {
    timeout --foreground $BENCH_TIMEOUT ${AWS_LC_BASE}/${BUILD_DIR}/tool/bssl speed -filter "AES-${SZ}-GCM"
}

do_variant() {
    echo "* Testing variant: $1"
    printf " - Copy... "
    set_variant $1
    printf "OK!\n"
    printf " - Build... "
    build_variant
    printf "OK!\n"
    printf " - Test... "

    test_variant && res=$? || res=$?

    if [ "$res" = "0" ]; then
        printf "OK!\n"
    elif [ "$res" = "124" ]; then # TIMEOUT
        printf "FAIL (timeout after ${TIMEOUT}s) -- likely a bug causing tests to hang\n"
        if [ "$KEEP_GOING" = "0" ]; then
            exit 1
        fi
    else
        printf "FAIL\n"
        if [ "$KEEP_GOING" = "0" ]; then
            exit 1
        fi
    fi

    if [ "$BENCH" = "1" ]; then
        printf " - Bench...\n"
        bench_variant && res=$? || res=$?
    fi
}


if [ $SZ = "128" ]; then
    VARIANTS="
    x4_basic
    x4_keep_htable
    x6_basic
    x8_basic
    x4_ilp
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
    VARIANTS="
    x4_basic
    x4_reload_round_keys_partial
    "
else
    VARIANTS="
    x4_basic
    x4_reload_round_keys_partial
    "
fi

if [ "$1" = "--help" ]; then
    echo "Usage: [VERBOSE=0/1] [OPT=0/1] test.sh [variant]"
    echo "Valid values for 'variant' are:"
    for var in $VARIANTS; do
        echo "* $var"
    done
    exit 0
fi

TODO=$@
if [ "$TODO" = "" ]; then
    TODO=$VARIANTS
fi

for var in $TODO; do
    do_variant $var
done
