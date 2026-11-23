#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/build}"
ENV_ROOT="${OLLVM_DEMO_ROOT:-/home/kali/Downloads/demo}"
OPT="$ENV_ROOT/build/ollvm/bin/opt"
SYSROOT="$ENV_ROOT/android-ndk/sysroot"
RESOURCE="$ENV_ROOT/android-ndk/clang11"
LLD="$ENV_ROOT/tools/lld-root/usr/bin/ld.lld-11"
COMMON=(--target=aarch64-linux-android23 --sysroot="$SYSROOT" -resource-dir="$RESOURCE")
LINK=(-fuse-ld="$LLD" -rtlib=compiler-rt)

mkdir -p "$OUT"
clang-11 "${COMMON[@]}" -fPIC -O0 -c "$HERE/route_identity.c" -o "$OUT/route_identity.o"
clang-11 "${COMMON[@]}" -fPIC -O0 -fno-inline -c "$HERE/route_score.c" -o "$OUT/route_score_plain.o"
clang-11 "${COMMON[@]}" "${LINK[@]}" -shared -fPIC -O0 "$OUT/route_score_plain.o" "$OUT/route_identity.o" -o "$OUT/libroute_plain.so"

clang-11 --target=aarch64-linux-android23 --sysroot="$SYSROOT" -S -emit-llvm -O0 \
  -fno-discard-value-names -Xclang -disable-O0-optnone \
  "$HERE/route_score.c" -o "$OUT/route_raw.ll"
sed -i -E -e 's/dso_local //g' -e 's/#[0-9][0-9]* //g' \
  -e '/^attributes/d' -e '/^!llvm\.(module\.flags|ident)/d' \
  -e '/^![0-9]+ =/d' "$OUT/route_raw.ll"
"$OPT" -O0 -fla -S "$OUT/route_raw.ll" -o "$OUT/route_fla.ll"
clang-11 "${COMMON[@]}" -fPIC -O0 -c "$OUT/route_fla.ll" -o "$OUT/route_score_fla.o"
clang-11 "${COMMON[@]}" "${LINK[@]}" -shared -fPIC -O0 "$OUT/route_score_fla.o" "$OUT/route_identity.o" -o "$OUT/libroute_fla.so"
llvm-objdump-11 -d --no-show-raw-insn "$OUT/libroute_fla.so" > "$OUT/route_fla.disasm.txt"
llvm-objdump-11 -d --no-show-raw-insn "$OUT/libroute_plain.so" > "$OUT/route_plain.disasm.txt"
NDK_CC="${NDK29_CC:-/home/kali/Downloads/ai-reverse-lab-v2/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android25-clang}"
"$NDK_CC" "$HERE/runner.c" -ldl -o "$OUT/runner"
"$NDK_CC" "$HERE/trace_runner.c" -ldl -o "$OUT/trace_runner"
llvm-readelf-11 -Ws "$OUT/libroute_fla.so" | grep -E 'route_score|route_identity'
