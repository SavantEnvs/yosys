#!/usr/bin/env bash
#
# mayhem/build.sh — builds, inside the commit image (as `mayhem`, in /mayhem):
#   1. libyosys with $SANITIZER_FLAGS + libFuzzer coverage (build-fuzz/), for the libyosys harness;
#   2. the fuzz harnesses and their *-standalone reproducers;
#   3. the stock `yosys` driver with normal flags (build-tests/), which mayhem/test.sh runs.
# Idempotent and offline: every dependency is a submodule already in the tree or a base-image package.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The in-tree third-party libraries and ABC are git submodules; the slang ones are not needed (slang is off).
for d in libs/fmt libs/tomlplusplus libs/boost_regex libs/symfpu libs/cxxopts abc; do
	[ -n "$(ls -A "$d" 2>/dev/null)" ] || { echo "build.sh: submodule $d is empty; checkout with --recurse-submodules" >&2; exit 1; }
done

COMMON_CMAKE=(
	-G Ninja
	-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
	-DYOSYS_ENABLE_UNIT_TESTS=OFF
	-DYOSYS_WITHOUT_SLANG=ON -DYOSYS_WITHOUT_ABC=ON -DYOSYS_WITHOUT_TCL=ON
	-DYOSYS_WITHOUT_READLINE=ON -DYOSYS_WITHOUT_EDITLINE=ON -DYOSYS_WITHOUT_LIBFFI=ON
)

# 1) Sanitized + coverage-instrumented libyosys.
cmake -S . -B build-fuzz "${COMMON_CMAKE[@]}" -DBUILD_SHARED_LIBS=ON \
	-DCMAKE_C_FLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
	-DCMAKE_CXX_FLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target libyosys

# Compile flags the project itself uses for a kernel source, reused for the harness.
YOSYS_INC=$(python3 - <<'PY'
import json, shlex
for e in json.load(open("build-fuzz/compile_commands.json")):
    if e["file"].endswith("kernel/calc.cc"):
        print(" ".join(t for t in shlex.split(e["command"]) if t.startswith(("-I", "-isystem", "-D"))))
        break
PY
)
LIBYOSYS=$(ls build-fuzz/lib*yosys.so | head -1)

# 2) Harnesses: fuzzer binary + standalone reproducer.
O=build-fuzz/mayhem-objs
mkdir -p "$O"
$CXX $SANITIZER_FLAGS -c mayhem/lsan_off.cc -o "$O/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$O/standalone_main.o"

build_harness() { # name extra-compile-flags... -- extra-link-args...
	local name=$1; shift
	local cflags=() lflags=()
	while [ "$1" != "--" ]; do cflags+=("$1"); shift; done; shift
	lflags=("$@")
	$CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS "${cflags[@]}" $LIB_FUZZING_ENGINE \
		"mayhem/$name.cc" "$O/lsan_off.o" "${lflags[@]}" -o "/mayhem/$name"
	$CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS "${cflags[@]}" \
		"mayhem/$name.cc" "$O/lsan_off.o" "$O/standalone_main.o" "${lflags[@]}" -o "/mayhem/$name-standalone"
}

build_harness cxxrtl_format -Ibackends/cxxrtl/runtime --
build_harness cxxrtl_value -Ibackends/cxxrtl/runtime --
build_harness yosys_const $YOSYS_INC -- "$LIBYOSYS" "-Wl,-rpath,$SRC/build-fuzz" -ldl -lz

# 3) The upstream driver with its normal flags, for mayhem/test.sh.
cmake -S . -B build-tests "${COMMON_CMAKE[@]}" -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS" --target yosys
