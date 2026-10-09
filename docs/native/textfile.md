# Independent TextFile C backing

Status: native module pilot. The same C implementation can now compile without
per-application generated records/constructors. Complete SDK package artifacts and
compiler-generated import/export adapters remain implementation work.

`src/io/textfile.native.c` selects package-owned storage in
`textfile.native.h` and includes the canonical `textfile.sn.c` implementation.
Existing Sindarin imports still use their generated record/constructor path.
Compile-time size/offset checks preserve the reference-count prefix and the
existing `fp`, `path`, and `is_open` fields. The public `.sn` declarations are
unchanged; underscore field names remain language-visible.

The standalone module exports the existing C file operations and independent
retain/release functions. Final release closes the file and frees C-owned path and
record storage once. Credits are atomic; file operations themselves retain their
existing synchronization requirements. `sn_text_file_dispose` still performs its
idempotent explicit close without deleting a live record. The path adapter returns
an owned string through the shared Sindarin C runtime. Go validates C ownership across garbage collection with stronger cgo pointer checks.
Foreign clients can inspect
field accessors and reported layout without reinterpreting a private Rust/Go layout.

Validation with a compiler implementing the shared runtime and native builder:

```sh
python3 scripts/check_textfile_native.py --compiler /path/to/compiler/bin/sn
python3 scripts/check_textfile_native.py --compiler /path/to/compiler/bin/sn \
  --sanitize --runtime-source /path/to/compiler/src/runtime
```

Checks cover independent C, Rust and Go clients, strings/arrays, four-thread credit
traffic, explicit/final close, field offsets and lifetime after owner release.
The unchanged SDK TextFile Sindarin fixture runs through both targets across all
nine optimization/arithmetic combinations with exact platform byte oracles. An
additional raw source pins public field access/mutation, shared identity and the
existing language-visible pointer `sizeof` (distinct from record storage size).
The raw filename keeps this compiler-dependent integration test outside the SDK's
released-compiler fixture discovery; the script stages its identical `.sn` bytes.

This pilot does not claim that generated SDK package adapters or full Rust parity
are complete, and does not introduce another SDK implementation language.

## Typed shared-runtime bridge (local implementation)

The standalone C module now exposes `sn_sdk_text_file_open_abi`, `path_abi`,
`read_line_abi`, `dispose_abi` and `is_open_abi`. They use a shared-runtime resource
handle tagged `SindarinSDK/sindarin-pkg-sdk:io.TextFile@1` and call the existing
canonical C implementation. No Rust/Go SDK implementation is introduced and the
Sindarin declarations, public fields and legacy C path remain unchanged.

An opened handle owns one package record credit. Retaining the runtime handle
preserves identity; its final release drops that record credit and performs
canonical cleanup. Explicit disposal remains idempotent. Returned strings own
independent C-runtime credits and survive resource release. Wrong resource types
are rejected before a C record pointer is used, preserving output values.

C, Rust and Go clients exercise the bridge alongside all existing native/legacy
checks. This implementation requires compiler runtime typed-resource entry points
currently under development. It is not yet a complete compiler-generated TextFile
package artifact import; broader SDK/resource/array/method contracts remain work.
