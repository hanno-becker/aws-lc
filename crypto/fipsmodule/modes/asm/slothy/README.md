# Auto-optimized AES-GCM implementations

## Overview

This directory contains source files and scripts for the automatic generation of high-performance AArch64 AES-GCM
implementations from 'clean' base versions.

The 'clean' versions reside in [clean](clean): They emphasize the logic of the computation and employ no scheduling
optimizations, with the exception of some very coarse software pipelining in some cases. They use descriptive register
names and assembly macros to keep the code readable. The naming scheme is
`aesv8-gcm-armv8-base-{KEYLENGTH}_{UNROLL}_{TEXT}.S`, where `KEYLENGTH=128,192,256` and `UNROLL=x4,x6,x8` indicate key
length and the level of unrolling of the core loop, respectively. `TEXT` is an indicator of the implementation strategy.

The optimized versions reside in [opt](opt). They are automatically generated from the clean versions by
[SLOTHY](https://github.com/slothy-optimizer/slothy), which applies scheduling optimizations and software pipelining
based on models of the target microarchitecture. Here, we consider implementations optimized for either Neoverse N1 or
Neoverse V1.

## Tests

To test one or more implementations, use:

```
> [BUILD_DIR=build] [OPT=0/1] [SZ=128/192/256] [VERBOSE=0/1] test.sh [VARIANT]
```

* `VARIANT` is a list of implementations to be tested; for example, if you want to test
`aesv8-gcm-armv8-base-128_x4_basic` and `aesv8-gcm-armv8-base-128_x4_dual_acc`, you'd pass `x4_basic x4_dual_acc`. When
`VARIANT` is omitted, all clean implementations will be tested. To see all variants, use `test.sh --help`. A 'test'
merely consists of (a) building AWS-LC via Ninja, (b) running `crypto_test`.

* `BUILD_DIR` is the name of the build directory you're using (e.g. `build` or `build_release`).

* `OPT` indicates whether you want to test the clean or optimized version of the chosen implementation variant

* `VERBOSE` indicates if you want to see build and test output

## Benchmark

To benchmark one or more implementations, use:

```
> BENCH=1 [BUILD_DIR=build] [OPT=0/1] [SZ=128/192/256] [VERBOSE=0/1] test.sh [VARIANT]
```

with the rest of the arguments for `test.sh` as explained above.

## Optimization

To optimize a clean implementation, use `optimize.sh`:

```
> [SZ=128/192/256] optimize.sh [VARIANTS]
```

For example, `optimize.sh x4_basic` would optimize `clean/aesv8-gcm-armv8-base-128_x4_basic.S` and write the result to
`opt/aesv8-gcm-armv8-opt-128_x4_basic.S`. If no variant is given, all will be optimized (Warning: This will take a very long time).

**Prerequisites:** `slothy-cli` has to be in your `PATH`. To obtain SLOTHY, clone the [SLOTHY
repository](https://github.com/slothy-optimizer/slothy) and setup via PyPI as described in the README.

## Results

See [benchmarks_g2.md](benchmarks_g2.md) for benchmarks on Graviton 2.
