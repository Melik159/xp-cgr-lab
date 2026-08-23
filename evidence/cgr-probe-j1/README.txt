XP_SP3_CGR_LAB - Jalon 1 - XP execution evidence
=================================================

The final probe was executed on 2026-08-23 in the isolated XPCASE-2009 VM.
The captured environment identifies Microsoft Windows XP version 5.1.2600,
Service Pack 3. QEMU was started with "-nic none". cgr_probe.exe was read from
D:\cgr_probe.exe on tools/cgr-probe.iso. Results were written to a dedicated
FAT floppy image and extracted after a clean ACPI shutdown.

Five iterations were run separately for each API. Each iteration requested 32
bytes and then 64 bytes. Both processes returned exit code 0 and empty stderr.
The JSONL validation checks passed for sequential event IDs, API labels,
success flags, zero error codes, hexadecimal syntax, exact 2*length hex sizes,
PID, TID and timestamp shape.

The SystemFunction036 results are separate observations. They are not treated
as CryptGenRandom results and no behavioral equivalence is inferred.

Recreate the test-only overlays and result floppy from the project root:

  qemu-img create -f qcow2 -F qcow2 \
    -b /home/hal/xp-cgr-lab/vm/xp-system-instrumented.qcow2 \
    vm/xp-system-cgr-j1.qcow2
  qemu-img create -f qcow2 -F qcow2 \
    -b /home/hal/xp-cgr-lab/vm/xp-test-instrumented.qcow2 \
    vm/xp-test-cgr-j1.qcow2
  mkfs.fat -C -F 12 -n CGRRESULT build/xp-cgr-results.img 1440
  mcopy -o -i build/xp-cgr-results.img \
    tools/xp-run-from-iso.bat ::XP-RUN.BAT

Start the VM with:

  qemu-system-i386 \
    -name XP_SP3_CGR_J1 \
    -accel kvm \
    -machine pc-i440fx-6.2 \
    -m 1024 -smp 1 \
    -drive file=vm/xp-system-cgr-j1.qcow2,format=qcow2,if=ide,index=0 \
    -drive file=vm/xp-test-cgr-j1.qcow2,format=qcow2,if=ide,index=1 \
    -drive file=tools/cgr-probe.iso,format=raw,media=cdrom,readonly=on,if=ide,index=2 \
    -drive file=build/xp-cgr-results.img,format=raw,if=floppy,index=0 \
    -boot order=c -nic none -vga std -rtc base=localtime

In XP, open cmd.exe and run A:\XP-RUN.BAT. Shut down XP cleanly, then extract
the named result files with mcopy. hashes.sha256 records the exact final
source, binary, ISO and XP evidence files.

The following four protected images are never command targets for writes:
vm/xp-system-base.qcow2, vm/xp-system-baseline.qcow2,
vm/xp-test-base.qcow2 and vm/xp-test-baseline.qcow2. The test-only overlays
write above the existing instrumented overlays.
