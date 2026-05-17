# Algorithms

Phase-level orchestration is in [PIPELINE.md](PIPELINE.md). This file covers the
specific techniques used inside individual phases.

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

Once layouts are known, indirect vcalls `mov rax,[rcx]; call [rax+N]` get rewritten
to direct `call sub_X`. Three resolver phases run after RTTI + type propagation:

```mermaid
flowchart TD
    SEED[Seed funcType:<br/>RTTI ctors, default_instances, proto messages] --> PROP
    PROP[Bidirectional worklist:<br/>caller<->callee type flow] --> PA

    subgraph PA[Phase A: typed]
        PA1[Per typed func F, vtRVA] --> PA2[Run pefix::ConstProp<br/>with seedReg = vtRVA]
        PA2 --> PA3[Collect CALL with<br/>simplified+LABEL dst]
        PA3 --> PA4[Patch E8 disp32, NOP tail]
    end

    PA --> PB
    subgraph PB[Phase B: untyped brute]
        PB1[For each untyped func with vcall] --> PB2[Try every known vtRVA<br/>on RCX/RDX/R8]
        PB2 --> PB3[Patch only when single<br/>unambiguous target]
    end

    PB --> PC
    subgraph PC[Phase C: slot consensus]
        PC1[For each remaining vcall] --> PC2[Check slot N across<br/>all 348 vtables]
        PC2 --> PC3{All vtables agree?}
        PC3 -->|Yes| PC4[Patch]
        PC3 -->|No| PC5[Skip]
    end
```

Phase A does the heavy lifting -- it's where the dataflow engine (pefix::ConstProp,
augmented with TypedPtr propagation through `mov rax,[rcx]` and CALL mem-operand
resolution) converts the vtable seed into a concrete call target. Phases B and C
sweep the residual cases.
