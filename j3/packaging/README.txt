XP_SP3_CGR_LAB - J3 TrueCrypt 6.2a micro-test media

This disc contains the validated J2 tracer unchanged and the independently
validated TrueCrypt 6.2a setup package. J3 uses a writable FAT data disk
labelled J3DATA for extracted binaries, one small synthetic container, and
raw logs.

Interactive sequence in Windows XP:
  1. setup-extract.bat (choose Extract and destination <J3DATA>:\TC62A)
  2. trace-launch.bat (close TrueCrypt without starting volume creation)
  3. trace-format.bat (create <J3DATA>:\j3micro.tc, 5 MB, FAT)
  4. trace-mount.bat
  5. trace-unmount.bat
  6. trace-remount.bat
  7. trace-final-unmount.bat
  8. collect-env.bat

Synthetic test password used by the mount scripts: J3micro62a

The trace records RNG API outputs. Those bytes are observations of API calls;
this experiment does not identify them as TrueCrypt keys or key material.
