# Algorithms

Phase-level orchestration is in [PIPELINE.md](PIPELINE.md). This file covers the
specific techniques used inside individual phases.

Two cross-library passes are covered in their owning repos:

- **Function boundary recovery (FBR)** — multi-source seeds (pdata / export /
  RTTI / EH / data fnptrs) plus caller-driven expansion through E8/E9 targets,
  validated by a score-based filter. Pipeline runs it twice (Phase 2 measurement,
  Phase 5 L4 input). Full flowchart in
  **[libpefix/ALGORITHMS.md#function-boundary-recovery-fbr](../libpefix/ALGORITHMS.md)**.
- **Layered xref reachability** — L1 `.grfn1` roots, L2 export roots, L3 fnptr
  roots, plus the append-only L4 FBR augmentation that registers `.rdata`
  targets reachable from FBR-discovered functions the other layers miss. Full
  flowchart in
  **[libgriffin/ALGORITHMS.md#layered-xref-reachability](../libgriffin/ALGORITHMS.md)**.

## Griffin deobfuscation

```mermaid
flowchart TD
    F[Function entry] --> CFG[Build CFG]
    CFG --> CP[Constant propagation]
    CP --> MBA[MBA pattern simplification]
    MBA --> OP[Opaque predicate resolution]
    OP --> PATCH[Patch simplified instructions]
    PATCH --> NEXT{More functions?}
    NEXT -->|Yes| F
    NEXT -->|No| INT3

    INT3[INT3 VEH scan] --> RESOLVE[Follow call->INT3->NOP->JMP]
    RESOLVE --> PJMP[Patch: direct JMP to target]
    PJMP --> JMP

    subgraph JMP[JMP Resolution Cascade]
        direction LR
        L1[L1: Pattern] -->|fail| L3[L3: Static parse]
        L3 -->|fail| L3b[L3b: LEA+LEA+JMP]
        L3b -->|fail| L5[L5: Symbolic inverse]
        L5 -->|fail| L4[L4: Unicorn emulation]
    end

    JMP --> INOP[Inline INT3 NOP]
```

## Protobuf message discovery

```mermaid
flowchart TD
    A[Scan .rdata for 'pkg.Msg.field' strings] --> B[Group by message name]
    B --> C[For each message:<br/>find Serialize via LEA xref to field descriptor]
    C --> D[Walk vtable from Serialize position]
    D --> E[Map vtable slot names<br/>dtor / Clear / ByteSizeLong / MergeFrom / ...]
    E --> F[parseSerializeOffsets:<br/>extract field offsets from Serialize body]
    F --> G[parseFromInternalParseFunc:<br/>extract field#, wire type, struct offset<br/>from _InternalParse tag dispatch]
    G --> H[Per-message ProtoMessage record]
    H --> I[Synthesize export names:<br/>Msg_method, Msg_field_ref, vfunc_N]
```

## _InternalParse identification (table-driven build)

For protobuf-lite + table-driven builds, the per-message `Serialize`/`ByteSizeLong`
exports are short thunks; the real wire-format dispatch lives in `_InternalParse`,
which is named generically (`vfunc_N`, `InternalSwap`, etc.) by the deobf pass.

```mermaid
flowchart TD
    A[Find EpsCopyInputStream::DoneFallback<br/>by byte-signature scan] --> B[Cache RVA per PE]
    B --> C[For each vtable function:]
    C --> D{Calls boundary helper?}
    D -->|No| C
    D -->|Yes| E[Count distinct field-number tag cmps]
    E --> F[Pick candidate with most cases<br/>tie-break by .pdata size]
    F --> G[parser RVA]
    G --> H[Walk function body:<br/>cmp byte_reg, TAG -> case<br/>lea rcx, this+OFFSET -> field offset<br/>call HELPER -> wire-type hint]
    H --> I[Merge into ProtoMessage.fields]
```

## Field setter discovery

```mermaid
flowchart TD
    A[Per ProtoMessage: known field offsets] --> B[Scan .grfn1 for offset computations<br/>lea/add reg, imm32 where imm32 matches]
    B --> C[Cluster hits by proximity]
    C --> D[Score per cluster:<br/>sibling offsets in same message,<br/>setter stub call nearby,<br/>target match]
    D --> E[Output: field setter candidates with confidence]
```

## Vtable layout recovery

```mermaid
flowchart TD
    A[Message descriptor LEA xref<br/>-> Serialize function RVA] --> B[Find QWORD in .data/.rdata<br/>equal to Serialize VA = vtable slot]
    B --> C[Vtable starts at first non-code pointer<br/>scanning backward from slot]
    C --> D[Walk forward, name each slot<br/>by protoc-lite layout]
    D --> E[Cross-check with COFF symbol names<br/>resolve ICF-shared functions]
```

## Vtable call devirtualization

Once layouts are known, indirect vcalls and tail-call thunks of the form
`mov rax,[rcx]; call|jmp [rax+N]` get rewritten to a direct `call`/`jmp sub_X`.
Three resolver phases run after RTTI + type propagation:

```mermaid
flowchart TD
    SEED[Seed funcType:<br/>RTTI class methods, proto messages,<br/>default_instances, .rdata fnptr arrays] --> PROP
    PROP[Bidirectional worklist:<br/>caller<->callee type flow] --> PA

    subgraph PA[Phase A: typed]
        PA1[Per typed func F, vtRVA] --> PA2[Run pefix::ConstProp<br/>with each of RCX/RDX/R8/R9/RBX/RSI/RDI<br/>seeded to TypedPtr vtRVA]
        PA2 --> PA3[Collect CALL or JMP with<br/>simplified + LABEL dst]
        PA3 --> PA4[Decode call/jmp base reg<br/>from raw bytes incl. REX.B]
        PA4 --> PA5[Match preceding mov dst<br/>against call/jmp base]
        PA5 --> PA6[Patch E8 CALL / E9 JMP + disp32,<br/>NOP absorbed mov tail]
    end

    PA --> PB
    subgraph PB[Phase B: untyped brute]
        PB1[For each untyped func with vcall] --> PB2[Try every known vtRVA<br/>on RCX/RDX/R8]
        PB2 --> PB3[Patch only when single<br/>unambiguous target]
    end

    PB --> PC
    subgraph PC[Phase C: slot consensus]
        PC1[For each remaining vcall] --> PC2[Check slot N across<br/>all known vtables]
        PC2 --> PC3{All vtables agree?}
        PC3 -->|Yes| PC4[Patch]
        PC3 -->|No| PC5[Skip]
    end
```

The preceding-mov absorb step covers three encodings:

- 3-byte `mov reg, [base]`              (REX + 8B + modrm mod=00)
- 4-byte `mov reg, [base + disp8]`      (REX + 8B + modrm mod=01 + disp8)
- 7-byte `mov reg, [base + disp32]`     (REX + 8B + modrm mod=10 + disp32)

Each is only absorbed when the mov's destination register matches the call/jmp's
base register (accounting for REX.R and REX.B). This is what keeps the rewrite
semantically safe when an unrelated `mov` happens to sit immediately in front.

Phase A is where the bulk of patching lands; Phases B and C sweep residuals.
Untyped sites that reduce to a single vtable target via brute force or that
share a slot across every vtable (rare for class-specific layouts) get cleaned
up there. Sites that survive all three phases are typically constructor entries
that rewrite `rcx` from a parameter struct, container iterations with dynamic
indices, or member-object vcalls -- cases where abstract interpretation alone
cannot recover the type.
