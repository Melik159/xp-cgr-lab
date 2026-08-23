XP_SP3_CGR_LAB - Jalon 2 - Dynamic RNG provenance
==================================================

This ISO contains process-local x86 instrumentation for Windows XP SP3. It is
independent of any disk-encryption study.

cgr_trace_runner.exe starts the J1 cgr_probe.exe suspended. In trace mode it
injects cgr_trace.dll before the main thread runs. The DLL patches only two IAT
entries in the probe's main executable:

1. ADVAPI32.dll!CryptGenRandom is replaced by a CGR hook.
2. KERNEL32.dll!GetProcAddress is replaced by a resolver hook. Only a successful
   request for the name SystemFunction036 is substituted with the RTL hook.

No advapi32 code bytes are modified. The two APIs have independent event
counters and output files. This method identifies the immediate return address;
it does not prove that this immediate caller is the functional origin of a
higher-level operation.

Each trace event records timestamp, PID, TID, process, request size, buffer,
return address, caller module/base/RVA, result, Win32 error and returned bytes.
If symbols are absent, only module plus addresses/RVA are reported.

RUN
---
Attach a blank writable FAT floppy as A: and this ISO read-only. In cmd.exe:

  D:\run-j2.bat

The batch locates the actual CD letter. It performs RUN_CONTROL and RUN_TRACE
for both APIs, then repeats the full sequence as RUN2. Each API process makes
five 32-byte and five 64-byte requests. Outputs are written beneath A:\RUN1 and
A:\RUN2. Shut down XP cleanly before reading the floppy on Linux.

Instrumentation is not claimed to be transparent. The runner records setup,
injection, execution and total durations using QueryPerformanceCounter.

SCOPE LIMITS
------------
No result establishes use as an AES key, volume key, disk key or key derivation
input. CryptGenRandom and SystemFunction036 observations remain conceptually
separate.
