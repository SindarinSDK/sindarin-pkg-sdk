# Canonical C Time and Date modules

`src/time/time.native.c` and `date.native.c` build independently of generated
application records. Their public headers own storage with the existing reference
count prefix and exposed milliseconds/days fields. Create returns one credit;
retain preserves identity; release frees storage at zero; refs/retain/release
accept nil. Owner credits are atomic; callers serialize field mutation.

The original C operation bodies remain in `time.sn.c` and `date.sn.c`. Standalone
mode supplies canonical types/constructors; legacy mode keeps generated records
and constructors and checks matching layout. Public Sindarin modules and original
callers/oracles are unchanged. Date-to-Time conversion allocates canonical Time
storage in standalone mode and retains its legacy layout in source mode.

```sh
python3 scripts/check_time_date_native.py --compiler /path/to/bin/sn
python3 scripts/check_time_date_native.py --compiler /path/to/bin/sn --sanitize
```

Local validation passes 38 independent C/Rust archive and unchanged Time/Date
caller cases across O0/O1/O2 and default/checked/unchecked modes. A separate check
instruments the actual C runtime and both modules with address, undefined-behavior
and leak checking. It covers aliases, 80,000 retain/release operations, typed
resource cleanup, independent arithmetic/conversion results and owned strings
surviving record cleanup. Public-before-standalone and repeated header inclusion
also compile as C++. The original Date caller needs the compiler's private method
name collision repair for Rust.

Compiler dependencies `3a8d675a`/`2c0f1c08` now have complete hosted acceptance.
The SDK CI matrix builds accepted compiler `2c0f1c08` on Linux, macOS and Windows,
then checks the independent C/Rust archives and all unchanged Time/Date caller
modes. Linux also instruments both modules and the actual shared runtime. Reports
retain compiler and source hashes. Calendar artifact adapters are separately
validated locally in compiler batch `0941f0af`: 108 source/sealed cases pass
normally and under strict sanitizers, including the unchanged opaque `toTime()`
result with explicit ownership, source-owner cleanup and caller cleanup. That
compiler batch and whole SDK artifact migration still await hosted acceptance. Original Time formatting code also
produces existing GCC buffer-bound warnings for unconstrained year values; these
operation bodies are unchanged and this evidence covers the original fixture
ranges. Whole SDK migration and hosted platform/lifecycle acceptance remain
required.
