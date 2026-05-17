# libvgc

Analysis toolkit for Riot Games' Vanguard Client (VGC) binary.

Combines PE fixing (libpefix), Griffin deobfuscation (libgriffin), and VGC-specific protocol/structure analysis into a single pipeline that transforms a raw memory dump into an IDA-ready annotated binary.

> This project was fully generated with AI assistance (Claude, Anthropic).

## Build

Requires Visual Studio 2017+ with C++ desktop workload.
Depends on libpefix and libgriffin (expected at `../libpefix`, `../libgriffin` or `deps/`).
Optional: Unicorn Engine in `vendor/unicorn/` for emulation passes.

```
build.bat
```

Output: `build\Release\libvgc.exe`

## Usage

```
libvgc.exe <input.exe> [options]
```

With no options, the full pipeline runs. ImageBase is auto-detected from the PE header.

| Option | Description |
|--------|-------------|
| `-o <path>` | Output file (default: `input_fixed.exe`) |
| `--all` | Full pipeline (default) |
| `--recover-sections` | Recover hidden code sections |
| `--fix-nullsub` | Patch dead code patterns |
| `--flatten-jmp` | Flatten JMP chains |
| `--resolve-thunks` | Redirect thunk wrappers |
| `--recover-symbols` | Recover OpenSSL function names |
| `--deobf-scan` | Griffin batch deobfuscation |
| `--proto-scan` | Protobuf schema extraction |
| `--idc <path>` | Generate IDC script |
| `--dry-run` | Analyze only |
| `--verbose` | Detailed output |

## Pipeline

See **[PIPELINE.md](PIPELINE.md)** for the phase-by-phase orchestration: what runs
when, what each phase hands off to the next, where the two RIP-relative scan passes
sit relative to the deobf and structural-analysis work.

## Algorithms

See **[ALGORITHMS.md](ALGORITHMS.md)** for the techniques used inside individual
phases: Griffin deobfuscation (constprop, MBA, INT3, JMP L1-L5), protobuf discovery,
_InternalParse identification, vtable resolution, and field setter search.

## Project structure

```
include/vgc/
  antidisasm.h         EB FF, nullsub, dead code patterns
  thunks.h             import thunk resolution
  imports.h            import wrapper decoding
  symbols.h            OpenSSL symbol recovery
  funcfix.h            function boundary detection
  srcmap.h             source file mapping
  output/idc.h         IDC/IDA script generation
  griffin/
    proto_scan.h       protobuf message discovery + field trace
    ucemu.h            Unicorn-based emulation
    z3solve.h          Z3 symbolic solving (optional)

src/                   implementation
tools/
  libvgc.cpp           CLI entry point
  cli.h                colored console output
vendor/unicorn/        Unicorn Engine (not included, see below)
```

## Unicorn setup

Download Unicorn Engine and place in `vendor/`:
```
vendor/unicorn/
  include/unicorn/unicorn.h
  lib/unicorn.lib
  lib/unicorn.dll
```

Build without Unicorn (disables L4 emulation):
```
build.bat --no-unicorn
```

## Dependencies

- **[libpefix](https://github.com/hajunwon/libpefix)** — PE parsing, x86-64 analysis, RTTI, JMP flatten
- **[libgriffin](https://github.com/hajunwon/libgriffin)** — Griffin deobfuscation (constprop, MBA, INT3, JMP resolution)
- **[Unicorn Engine](https://github.com/unicorn-engine/unicorn)** (optional) — full x86-64 emulation for Level 4 JMP resolution

## License

MIT
