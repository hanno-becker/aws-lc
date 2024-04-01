#!/usr/bin/env sh
set -e

BENCHMARKS=${BENCHMARKS:=benchmarks_g2.md}
if [ ! -f ${BENCHMARKS} ]; then
   echo "Benchmark file not found: ${BENCHMARKS}"
   exit 1
else
    echo "OK"
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

TYPES=$3
if [ "$TYPES" = "" ]; then
    TYPES="clean opt"
fi

for T in $TYPES;
do
    get_all_stats $1 $2 $T
done
