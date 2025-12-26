#!/bin/bash
LLVM_CLANG=$(afl-clang-fast -print-prog-name=clang)
LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_COV=$(dirname $LLVM_CLANG)/llvm-cov

echo "LLVM версия: $LLVM_CLANG"

# Перекомпиляция с -O0 (критично!)
$LLVM_CLANG -O0 -g \
  -fprofile-instr-generate \
  -fcoverage-mapping \
  $(pkg-config --cflags glib-2.0) \
  -o dhcp-debug_cov main.c \
  $(pkg-config --libs glib-2.0) -lpcap

# Тест на ПУСТОМ входе
rm -f test.profraw
LLVM_PROFILE_FILE=test.profraw strace -e trace=execve ./dhcp-debug_cov </dev/null
ls -la test.profraw  # Размер?
xxd test.profraw | head -5  # Содержимое (должно начинаться с LLVM magic)

# Тест на seed (замените на реальный)
SEED="afl_out/default/queue/id:000000"  # Или любой
rm -f seed.profraw
LLVM_PROFILE_FILE=seed.profraw strace -e trace=execve,fork timeout 30 ./dhcp-debug_cov "$SEED"
ls -la seed.profraw  # >0?
$LLVM_PROFDATA merge seed.profraw -o seed.merged.profdata
$LLVM_PROFDATA show seed.merged.profdata  # Counts >0?
