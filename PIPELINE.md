# Pipeline

End-to-end orchestration: which phases run, in what order, with what they hand off to
each other. Algorithmic detail for any individual phase lives in [ALGORITHMS.md](ALGORITHMS.md).

```mermaid
flowchart TD
    INPUT[Memory Dump] --> P1

    subgraph P1[Phase 1: Surface Cleanup]
        direction LR
        P1A[EB FF patch] ~~~ P1B[Nullsub patch] ~~~ P1C[JMP flatten] ~~~ P1D[Thunk resolve]
    end

    P1 --> XREF1[RIP-relative scan]

    XREF1 --> P2

    subgraph P2[Phase 2: Import + Symbol Recovery]
        direction LR
        P2A[.riot1 decode] ~~~ P2B[OpenSSL symbols] ~~~ P2C[RTTI classes] ~~~ P2D[Pointer chains] ~~~ P2E[FBR measure 1]
    end

    P2 --> P3

    subgraph P3[Phase 3: Griffin Deobfuscation]
        direction LR
        P3A[Constprop] ~~~ P3B[MBA simplify] ~~~ P3C[INT3 resolve] ~~~ P3D[JMP L1-L5] ~~~ P3E[Inline NOP]
    end

    P3 --> P4

    subgraph P4[Phase 4: Post-deobf]
        direction LR
        P4A[VEH handlers] ~~~ P4B[.riot1 dispatch] ~~~ P4C[NOP to CC] ~~~ P4D[Boundary repair]
    end

    P4 --> XREF2[RIP-relative scan 2nd pass]

    XREF2 --> P5

    subgraph P5[Phase 5: Structural Analysis]
        direction LR
        P5A[Protobuf schema] ~~~ P5B[PFR pop+jmp unroll] ~~~ P5C[Call graph build] ~~~ P5D[Vtable resolve A/B/C/D] ~~~ P5E[Type propagation] ~~~ P5F[Call graph rebuild + diagnostics] ~~~ P5G[Import chain BFS] ~~~ P5H[FBR measure 2 + L4 xref]
    end

    P5 --> OUTPUT[Export table + COFF symbols + Output PE]
```

Phase boundaries also gate two RIP-relative scan passes: the first runs after Phase 1
so xref data feeds the symbol recovery in Phase 2; the second runs after Phase 4 so
deobfuscated code contributes refs that Phase 5 needs for vtable and protobuf work.

FBR runs twice. The first call sits in Phase 2 right after RTTI parsing — it
reports the discoverable function set against the original `.pdata` baseline as
a measurement-only sanity check, before any deobf has rewritten code. The second
call sits at the top of Phase 5 once deobf has expanded the reachable instruction
surface; its output feeds `griffin::extendWithFbrRoots` so xref reachability picks
up FBR-only roots as an `XrefLayerFbr` (L4) augmentation. Both calls are
side-effect free against the PE bytes — they read only.

The Phase 5 call graph is built twice. The first pass (P5C) consumes the PFR
alias table so trampoline entries already resolve to their real targets; this
feeds type propagation. The second pass (P5F) runs after Phases A/B/C/D have
rewritten vtable-indirect sites to E8 directs, picking up the freshly visible
edges. Caller resolution uses three layers in order: `.pdata` exact ranges,
FBR boundaries (with `endRVA` when computed), and a `.text`-only fallback that
walks back to the nearest RET to recover FBR-missed tail-called helpers.
Anything still unattached is counted as an orphan and bucketed by call target
for diagnostics.
