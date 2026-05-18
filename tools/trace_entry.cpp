#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <set>
#include <algorithm>
#include <unordered_map>
#include <pefix/pe.h>
#include <pefix/xrefs.h>
#include <pefix/x86_64/ir.h>
#include <griffin/xref_trace.h>

using namespace pefix;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: trace_entry <pe_file> [target_rva_hex ...]\n");
        return 1;
    }

    PEFile pe;
    if (!pe.load(argv[1])) {
        printf("Failed to load PE: %s\n", argv[1]);
        return 1;
    }

    uint64_t imageBase = pe.nt->OptionalHeader.ImageBase;

    std::vector<uint32_t> targets;
    for (int i = 2; i < argc; i++) {
        uint32_t rva = (uint32_t)strtoul(argv[i], nullptr, 16);
        targets.push_back(rva);
    }

    if (targets.empty()) {
        targets.push_back(0x4BCDF2F);  // machine_id
        targets.push_back(0x4BD131E);  // ac.pvp.net
        targets.push_back(0x4BD1369);  // /vanguard/v1/gateway
        targets.push_back(0x4BD139E);  // application/x-protobuf
        targets.push_back(0x4BCDF5F);  // game_token
        targets.push_back(0x4BCDF8F);  // client_rsa_public_key
        targets.push_back(0x4BCDFC7);  // game_id
        targets.push_back(0x4BCDFEF);  // ephemeral_identifiers
    }

    printf("Resolving Griffin xrefs (depth 3)...\n");
    auto xr = griffin::resolveGriffinXrefs(pe, imageBase, 3);
    printf("L1 (.grfn1 root):     %zu xrefs, %u unique targets\n",
           xr.xrefs.size(), xr.layerTargets[griffin::XrefLayerGrfn1]);

    size_t sz1 = xr.xrefs.size();
    griffin::extendWithExportRoots(xr, pe, imageBase, 3);
    printf("L2 (+ PE exports):    %zu xrefs (+%zu), +%u unique targets\n",
           xr.xrefs.size(), xr.xrefs.size() - sz1,
           xr.layerTargets[griffin::XrefLayerExport]);

    size_t sz2 = xr.xrefs.size();
    griffin::extendWithFnPtrRoots(xr, pe, imageBase, 3);
    printf("L3 (+ fn ptr root):   %zu xrefs (+%zu), +%u unique targets\n",
           xr.xrefs.size(), xr.xrefs.size() - sz2,
           xr.layerTargets[griffin::XrefLayerFnPtr]);

    size_t sz3 = xr.xrefs.size();
    griffin::expandSubstringTargets(xr, pe, imageBase);
    printf("After substring expansion: %zu xrefs (+%zu), %u total unique targets\n\n",
           xr.xrefs.size(), xr.xrefs.size() - sz3, xr.uniqueTargets);

    printf("=== Searching for target strings ===\n\n");
    for (uint32_t tgt : targets) {
        printf("Target RVA 0x%X (VA 0x%llX):\n", tgt, imageBase + tgt);
        int found = 0;
        for (auto& x : xr.xrefs) {
            if (x.targetRVA == tgt) {
                const char* layerName = "?";
                switch (x.layer) {
                    case griffin::XrefLayerGrfn1:  layerName = "L1 .grfn1"; break;
                    case griffin::XrefLayerExport: layerName = "L2 export"; break;
                    case griffin::XrefLayerFnPtr:  layerName = "L3 fnptr";  break;
                }
                printf("  <- [%s] caller RVA 0x%X\n", layerName, x.instrRVA);
                found++;
                if (found >= 10) { printf("  ... (more)\n"); break; }
            }
        }
        if (found == 0) printf("  (not in graph join)\n");
        printf("\n");
    }

    // Follow pointer chains from resolved targets into deeper .rdata
    printf("=== Following pointer chains from %u resolved targets ===\n", xr.uniqueTargets);
    uint32_t rdataStart = 0, rdataEnd = 0;
    for (int i = 0; i < pe.numSections; i++) {
        char nm[9] = {}; memcpy(nm, pe.sections[i].Name, 8);
        if (strcmp(nm, ".rdata") == 0) {
            rdataStart = pe.sections[i].VirtualAddress;
            rdataEnd = rdataStart + pe.sections[i].Misc.VirtualSize;
        }
    }

    std::set<uint32_t> allReachable;
    for (auto& x : xr.xrefs) allReachable.insert(x.targetRVA);

    uint32_t initialSize = (uint32_t)allReachable.size();
    for (int depth = 0; depth < 3; depth++) {
        std::vector<uint32_t> current(allReachable.begin(), allReachable.end());
        uint32_t added = 0;
        for (uint32_t rva : current) {
            uint32_t off = pe.rvaToOffset(rva);
            if (!off) continue;
            // Read pointers at this .rdata location (scan up to 256 bytes for pointer-like values)
            uint32_t maxScan = std::min(256u, (uint32_t)(pe.data.size() - off));
            for (uint32_t p = 0; p + 8 <= maxScan; p += 8) {
                uint64_t val = *(uint64_t*)(pe.data.data() + off + p);
                if (val < imageBase) continue;
                uint32_t ptrRVA = (uint32_t)(val - imageBase);
                if (ptrRVA >= rdataStart && ptrRVA < rdataEnd) {
                    if (allReachable.insert(ptrRVA).second) added++;
                }
            }
        }
        printf("  depth %d: +%u new .rdata addresses (total %zu)\n", depth + 1, added, allReachable.size());
        if (added == 0) break;
    }
    printf("  Expanded: %u -> %zu .rdata addresses\n\n", initialSize, allReachable.size());

    printf("=== Re-checking target strings after pointer expansion ===\n\n");
    for (uint32_t tgt : targets) {
        bool found = allReachable.count(tgt) > 0;
        printf("  0x%X: %s\n", tgt, found ? "FOUND" : "not found");
    }
    printf("\n");

    printf("=== RIP scan: who references these targets? ===\n\n");
    auto allRipRefs = scanRipRelativeRefs(pe, imageBase);
    for (uint32_t tgt : targets) {
        printf("RVA 0x%X:\n", tgt);
        int found = 0;
        for (auto& ref : allRipRefs) {
            if (ref.targetRVA == tgt) {
                const char* sec = "?";
                if (ref.instrRVA >= 0x55C000) sec = ".grfn1";
                else if (ref.instrRVA >= 0x1000 && ref.instrRVA < 0x3E9000) sec = ".text";
                printf("  <- %s RVA 0x%X (%s%s%s)\n", sec, ref.instrRVA,
                       ref.isLea ? "LEA" : "", ref.isCall ? "CALL" : "",
                       (!ref.isLea && !ref.isCall && !ref.isJmp) ? "MOV" : "");
                found++;
            }
        }
        if (found == 0) printf("  (no RIP-relative reference anywhere)\n");
        printf("\n");
    }

    return 0;
}
