# Phase G — FULL-160 Oracle-Isolated Challenge Bundle

This directory is the complete input surface for the Phase-G solver run.

## Public relation

For each instance, recover a 160-bit `xval` satisfying:

    out_a = G(xval)
    out_b = G((xval + out_a + 1) mod 2^160)

where `G` is SHA-1 compression of `xval || 44*00`, using the standard
SHA-1 IV, with no SHA-1 message padding.

## Isolation contract

The solver may read only files in this directory.

The bundle contains no captured AUX value, no CGR640 event log, no reduced
benchmark, and no serialized known XVAL candidate.

`xkey_before_hex`, `out_a_hex`, and `out_b_hex` are public challenge data.

The verifier independently recomputes both compression relations and pins the
challenge file to its frozen SHA-256.

This is oracle-isolated, not operator-blind: the experimenter may know a
reference solution from earlier phases, but that solution is not available to
the solver input surface.
