#!/usr/bin/env sh
set -e

# This script processes a benchmark file like benchmarks_g2.md
# Every line in the output describes the performance of one AES-GCM
# variant. The legend of every individual line is:
#
# - {NAME}
# - {MB/s (16b)}
# - {MB/s (256b)}
# - {MB/s (1350b)}
# - {MB/s (8192b)}
# - {MB/s (16384b)
# - Expected cycles (SLOTHY-optimized code only)
# - Expected IPC    (SLOTHY-optimized code only)
# - Cycle bound     (SLOTHY-optimized code only)
# - IPC bound       (SLOTHY-optimized code only)
# - Wall time       (SLOTHY-optimized code only)
# - User time       (SLOTHY-optimized code only)

BENCHMARKS=${BENCHMARKS:=benchmarks_g2.md}
if [ ! -f ${BENCHMARKS} ]; then
   echo "Benchmark file not found: ${BENCHMARKS}"
   exit 1
fi

SZ_ARG=$1
if [ "$SZ" = "" ]; then
    SZ_ARG=128
    echo "No keysize specified via SZ_ARG -- defaulting to ${SZ_ARG} bit"
fi

UNROLL_ARG=$2
if [ "$UNROLL_ARG" = "" ]; then
    UNROLL_ARG="x4"
    echo "No unrolling level specified UNROLL_ARG -- defaulting to ${UNROLL_ARG}"
fi

LOOP_LABEL="Lloop_unrolled_start:"

list_variants() {
    SZ=$1
    UNROLL=$2
    DIR=$3
    VARIANTS=$(ls -1 ./${DIR}/*${SZ}*${UNROLL}*.S | sed -n 's/.*'"${UNROLL}"'_\(.*\)\.S/\1/p' | tr '\n' ' ' )
    echo $VARIANTS
}

get_benchmark_for() {
    # Extracts and prints, separated by spaces, the throughputs (in MB/s)
    # for 16, 256, 1350, 8k, 16k data sizes.
    SZ=$1
    UNROLL=$2
    DIR=$3
    VARIANT=$4
    ID="${DIR}/${SZ}_${UNROLL}_${VARIANT}"
    cat $BENCHMARKS                                                                            \
        | grep "Testing variant: ${ID}" -A 10                                                  \
        | grep "MB/s"                                                                          \
        | sed -n 's/.*(\([0-9][0-9]*\) bytes).*[^0-9]\([0-9][0-9]*\.[0-9]\) MB.*/\2/p'         \
        | head -n 5 | tr '\n' ' '
}

get_slothy_stats_for() {
    # Extracts and prints, separated by spaces, the following SLOTHY statistics:
    # - Expected cycles
    # - Expected IPC
    # - Cycle bound
    # - IPC bound
    # - Wall time
    # - User time
    SZ=$1
    UNROLL=$2
    DIR=$3
    VARIANT=$4
    if [ "${DIR}" = "opt" ]; then
        TY="opt"
    else
        TY="base"
    fi
    FILEBASE="aesv8-gcm-armv8"
    FILE="${DIR}/${FILEBASE}-${TY}-${SZ}_${UNROLL}_${VARIANT}.S"
    cat $FILE                                        \
        | grep "${LOOP_LABEL}" -A 10                 \
        | sed -n 's/[^0-9]*\([0-9][0-9.]*\).*/\1/p'  \
        | tr '\n' ' '
}

get_stats_for() {
    SZ=$1
    UNROLL=$2
    DIR=$3
    VARIANT=$4
    ID="${DIR}/${SZ}_${UNROLL}_${VARIANT}"
    BENCH=$(get_benchmark_for $1 $2 $3 $4)
    if [ "$DIR" = "opt" ]; then
        SLOTHY=$(get_slothy_stats_for $1 $2 $3 $4)
    else
        SLOTHY="- - - - - - -"
    fi
    echo "${ID} ${BENCH} ${SLOTHY}"
}

get_all_stats() {
    for VARIANT in $(list_variants $1 $2 $3);
    do
        get_stats_for $1 $2 $3 $VARIANT
    done
}

TYPES_ARG=$3
if [ "$TYPES_ARG" = "" ]; then
    TYPES_ARG="clean opt"
fi

# Get reference performance
REF=$(get_benchmark_for $SZ_ARG $UNROLL_ARG aws-lc main)
REF_ARR=(${REF})
echo "main $REF - - - - - - -"
for T in $TYPES_ARG;
do
    get_all_stats $SZ_ARG $UNROLL_ARG $T
done
