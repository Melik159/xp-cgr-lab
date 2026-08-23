XP_SP3_CGR_LAB - Jalon 1 - cgr_probe
=====================================

TARGET
------
Windows XP Professional SP3 x86, machine XPCASE-2009. The executable is a
32-bit PE console program with subsystem version 5.01. It needs only the
Windows system DLLs and the Microsoft C runtime supplied by XP.

PURPOSE AND SCOPE
-----------------
The probe records calls requesting 32 and 64 bytes from CryptGenRandom. It can
also test advapi32.dll!SystemFunction036 (commonly called RtlGenRandom) in a
separate run. The two APIs are labelled and logged separately. No equivalence
between them is assumed.

This milestone does NOT study disk encryption and does NOT demonstrate that:
- CryptGenRandom output is directly used as a disk key;
- a 32-byte request means AES-256;
- a 64-byte request is split into two keys.

RUN ON WINDOWS XP
-----------------
Copy the entire CD contents to a writable directory before running. From a
cmd.exe prompt in that directory:

  cgr_probe.exe --api cgr --repetitions 5 > cgr_probe.jsonl 2> cgr_probe.stderr.txt
  cgr_probe.exe --api rtl --repetitions 5 > rtl_probe.jsonl 2> rtl_probe.stderr.txt
  run_probe.bat 5

The first two commands are equivalent to the work performed by run_probe.bat.
If no repetition count is supplied to the batch file, it uses 5.

OUTPUT
------
Standard output is JSON Lines: exactly one JSON object for each attempted API
call. Each object contains:

  event_id          sequential from 1 within the process
  iteration         repetition number, starting at 1
  api               CryptGenRandom or SystemFunction036
  requested_length  32 or 64
  success           JSON boolean
  win32_error       0 on success; GetLastError value on failure
  bytes_hex         all returned bytes in lowercase hex on success; empty on failure
  pid               process identifier
  tid               thread identifier
  timestamp_utc     UTC from XP GetSystemTime, formatted with milliseconds

The timestamp is sampled immediately after each API call. A failed
SystemFunction036 symbol lookup is represented by failed events with Win32
error 127 (ERROR_PROC_NOT_FOUND), unless LoadLibraryA itself returned another
error. SystemFunction036 is dynamically resolved and is never reported as a
CryptGenRandom observation.

Exit code bits are: 1 = one or more CryptGenRandom failures; 2 = one or more
SystemFunction036 failures or unavailable API; 4 = output or cleanup failure.
Invalid command-line syntax returns 64.

HASH THE XP RESULTS
-------------------
Windows XP has no built-in SHA-256 command. Move the generated files back to
the isolated Linux host, then run:

  sha256sum cgr_probe.jsonl cgr_probe.stderr.txt rtl_probe.jsonl rtl_probe.stderr.txt

Keep those hashes with the logs. hashes.txt on this CD covers the distributed
source, executable, documentation, scripts and build metadata. The ISO hash is
stored on the Linux host in build/iso.sha256 because an ISO cannot contain its
own hash.

CRYPTOAPI DETAILS
-----------------
The provider is acquired once per process using the default PROV_RSA_FULL
provider with CRYPT_VERIFYCONTEXT | CRYPT_SILENT, then released explicitly.
Every CryptGenRandom invocation and every cleanup result is checked. Buffers
are cleared after their complete hexadecimal representation is written.

SystemFunction036 is obtained with LoadLibraryA and GetProcAddress from
advapi32.dll and is called through its own function type. Its observations go
to rtl_probe.jsonl when run_probe.bat is used.

REPRODUCIBLE LINUX BUILD
------------------------
Toolchain used for this ISO:

  i686-w64-mingw32-gcc (GCC 10-win32 20220113)
  Ubuntu package gcc-mingw-w64-i686 10.3.0-14ubuntu1+24.3
  GNU Binutils 2.38, package binutils-mingw-w64-i686 2.38-3ubuntu1+9build1
  xorriso 1.5.4, package xorriso 1.5.4-2

From the project root:

  ./build-cgr-probe.sh
  ./make-cgr-probe-iso.sh

The exact compiler/linker flags are in build-cgr-probe.sh. PE headers and
imports are recorded in pe-info.txt. ISO timestamps and metadata are fixed, so
identical inputs and tool versions produce an identical ISO.
