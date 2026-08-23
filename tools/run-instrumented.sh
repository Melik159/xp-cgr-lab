#!/bin/bash
set -e

cd "$HOME/xp-cgr-lab"

exec qemu-system-i386 \
  -name XP_SP3_CGR_INSTRUMENTED \
  -accel kvm \
  -machine pc-i440fx-6.2 \
  -m 1024 \
  -smp 1 \
  -drive file=vm/xp-system-instrumented.qcow2,format=qcow2,if=ide,index=0 \
  -drive file=vm/xp-test-instrumented.qcow2,format=qcow2,if=ide,index=1 \
  -boot order=c \
  -nic none \
  -vga std \
  -rtc base=localtime
