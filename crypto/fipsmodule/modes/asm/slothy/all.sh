#!/bin/bash

export OPT=1
export BENCH=1

echo "Starting AES GCM benchmark tests at $(date)"
echo "========================================"

for SZ in 128 192 256; do
    for ENC in 1 0; do
        echo ""
        echo "Getting variants for ENC=$ENC, SZ=$SZ"

        # Get variants for this specific combination
        VARIANTS=$(ENC=$ENC SZ=$SZ ./test.sh --help 2>/dev/null | grep -E "^\* (awslc|x4_)" | sed 's/^\* //')

        echo "Available variants: $VARIANTS"
        echo "----------------------------------------"

        # Run benchmark for each variant
        for VARIANT in $VARIANTS; do
            echo ""
            echo "Benchmarking: ENC=$ENC, SZ=$SZ, VARIANT=$VARIANT"
            echo "..."

            script -qec "ENC=$ENC SZ=$SZ ./test.sh $VARIANT" /dev/null

            echo "Exit code: $?"
        done
    done
done

echo ""
echo "All benchmarks completed at $(date)"
