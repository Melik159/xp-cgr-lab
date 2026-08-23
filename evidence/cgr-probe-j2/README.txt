XP_SP3_CGR_LAB - Jalon 2 - Dynamic RNG provenance evidence
================================================================

VERDICT: PASS

Execution environment
---------------------
The experiment ran on XPCASE-2009, Microsoft Windows XP 5.1.2600 Service
Pack 3. QEMU used the exact command in qemu-command.txt, including "-nic
none". The J2 ISO was attached read-only and the results were recovered from a
dedicated FAT floppy after a clean ACPI shutdown.

A preparatory boot before the recorded runs exposed a batch-path expansion bug
(`D::\...`). No runner, probe or hook was started during that attempt. The ISO
was corrected and the result floppy was reformatted before RUN1 and RUN2. That
preparatory boot did write ordinary XP state to the J2 system overlay, so it is
reported rather than treated as experimentally invisible.

The J1 cgr_probe.exe embedded in the J2 ISO is byte-identical to the immutable
J1 executable (SHA-256 4a745cdaea15b2500e29b93d90e49ef37eed0fcb0ad422b3d8a533cb0ddbceb7).

Instrumentation method
----------------------
cgr_trace_runner.exe creates cgr_probe.exe suspended and, only for RUN_TRACE,
injects cgr_trace.dll before resuming the main thread. The DLL changes two IAT
slots in the probe main image:

- ADVAPI32.dll!CryptGenRandom is redirected to the CGR hook.
- KERNEL32.dll!GetProcAddress is redirected to a resolver hook. A successful
  lookup of the exact name SystemFunction036 is returned as the RTL hook.

No code bytes in advapi32.dll are changed. CGR and RTL maintain independent
event counters and logs (CGR_000001... and RTL_000001...). The hook calls the
original function, captures its result and returned bytes, writes the trace,
restores the observed last-error value, and returns to the caller.

What was observed
-----------------
Two complete runs were performed. In each run and for each API, RUN_CONTROL and
RUN_TRACE each contained ten calls in the order 32,64 repeated five times. All
calls succeeded. All eight launched probes returned exit code zero and wrote no
stderr.

For every one of the 40 trace/probe pairs across both runs:

- request length and order matched;
- returned bytes matched exactly, byte for byte;
- PID and TID matched;
- success and Win32 error matched;
- module base plus RVA equalled the captured return address.

The immediate CGR return address was 0x004017c8, in cgr_probe.exe loaded at
0x00400000 (RVA 0x000017c8). The immediate RTL return address was 0x00401867,
also in cgr_probe.exe at RVA 0x00001867. Both signatures were identical in RUN1
and RUN2. caller-disassembly.txt shows the offline disassembly around these two
return sites. No online symbol service was used.

What was inferred
-----------------
VirtualQuery associated both immediate return addresses with the loaded main
module cgr_probe.exe. The arithmetic address = module_base + RVA was checked
for every event. This supports the limited inference that the immediate machine
call sites observed in this controlled probe reside in cgr_probe.exe.

The immediate caller must not be treated automatically as the functional
component that originated a higher-level operation. No symbol/function name is
assigned because the distributed J1 executable is stripped and no verified
offline symbols were available.

Instrumentation perturbation
----------------------------
Instrumentation is NOT claimed to be transparent. QueryPerformanceCounter
measurements for the child execution interval were:

  RUN1 CGR: control 47.753 ms; trace 129.858 ms; +82.105 ms; ratio 2.719
  RUN2 CGR: control 48.380 ms; trace 121.579 ms; +73.199 ms; ratio 2.513
  RUN1 RTL: control 18.874 ms; trace  96.259 ms; +77.385 ms; ratio 5.100
  RUN2 RTL: control 23.189 ms; trace 122.122 ms; +98.933 ms; ratio 5.266

Trace setup/injection time was also recorded separately in each metrics file.
The hook performs synchronous file I/O after each RNG call, changes execution
timing, changes process memory/IAT state, adds a DLL and injection thread, and
forces the post-hook last-error value to the captured call result (zero on the
successful controlled calls). These are material perturbations.

What remains unknown
--------------------
- the verified symbolic function name containing either call site;
- any higher-level functional origin beyond the immediate probe call site;
- the internal RNG algorithms or state transitions;
- whether CryptGenRandom and SystemFunction036 have equivalent behavior;
- any use of these bytes as AES, disk, volume or derived keys.

Evidence map
------------
comparison.json contains the 40 explicit probe_event/trace_event comparisons
and the four control/trace timing comparisons. modules.json contains the
offline module/base/address/RVA records. The canonical *.jsonl files are RUN1;
the complete RUN1 and RUN2 raw outputs are under runs/. hashes.sha256 covers all
evidence plus the source, binaries, ISO, result image and J2 overlays.

Parent integrity
----------------
parents-before.sha256 and parents-after.sha256 are identical. The protected
base/baseline images and both instrumented parents were unchanged. The J1
QCOW2 hashes still match evidence/cgr-probe-j1/j1-qcow2.sha256. J2 writes exist
only in xp-system-cgr-j2.qcow2; the J2 test overlay remained byte-identical to
its initial empty-overlay hash.
