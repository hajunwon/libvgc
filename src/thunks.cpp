#include <vgc/thunks.h>
#include <vgc/log.h>
#include <vgc/antidisasm.h>
#include <unordered_map>

namespace vgc {

using pefix::PEFile;

uint32_t flattenJmpChains(PEFile& pe) {
    uint32_t flattened = 0;

    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!isObfuscatedSectionIdx(pe, i)) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 5 <= rawSz; pos++) {
            if (code[pos] != 0xE9) continue;

            int32_t disp = *(int32_t*)(code + pos + 1);
            uint32_t targetRVA = va + pos + 5 + disp;

            uint32_t finalRVA = targetRVA;
            int hops = 0;
            while (hops < 16) {
                uint32_t fOff = pe.rvaToOffset(finalRVA);
                if (!fOff && finalRVA < pe.data.size()) fOff = finalRVA;
                if (!fOff || fOff + 5 > pe.data.size()) break;
                if (pe.data[fOff] != 0xE9) break;

                int32_t nd = *(int32_t*)(pe.data.data() + fOff + 1);
                uint32_t next = finalRVA + 5 + nd;
                if (next == finalRVA) break;
                finalRVA = next;
                hops++;
            }

            if (hops > 0 && finalRVA != targetRVA) {
                int32_t newDisp = (int32_t)(finalRVA - (va + pos + 5));
                *(int32_t*)(code + pos + 1) = newDisp;
                flattened++;
            }
        }
    }
    return flattened;
}

uint32_t resolveThunks(PEFile& pe) {
    std::unordered_map<uint32_t, uint32_t> thunkMap;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    // Pass 1: collect thunks from .text and .riot1 (NOT .grfn1  - those are obfuscation jmps)
    // Pattern: E9 XX XX XX XX followed by CC (strict: only INT3 terminator)
    // Preceded by CC, C3, or section start (function boundary)
    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        char secName[9] = {};
        memcpy(secName, pe.sections[i].Name, 8);
        // Skip .grfn1  - jmps there are part of obfuscation, not thunks
        if (strncmp(secName, ".grfn", 5) == 0) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 6 <= rawSz; pos++) {
            if (code[pos] != 0xE9) continue;
            uint8_t after = code[pos + 5];
            // Strict: only CC (INT3) or C3 (RET) as terminator
            if (after != 0xCC && after != 0xC3) continue;

            // Verify function boundary before the jmp
            if (pos > 0) {
                uint8_t before = code[pos - 1];
                if (before != 0xCC && before != 0xC3 && before != 0x90) continue;
            }

            int32_t disp = *(int32_t*)(code + pos + 1);
            uint32_t target = va + pos + 5 + disp;
            if (target < sizeOfImage && target != va + pos)
                thunkMap[va + pos] = target;
        }
    }

    // Follow chains: if A→B and B→C, resolve A→C
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& [src, dst] : thunkMap) {
            auto it = thunkMap.find(dst);
            if (it != thunkMap.end() && it->second != dst) {
                dst = it->second;
                changed = true;
            }
        }
    }

    if (thunkMap.empty()) return 0;
    vgc::log::raw("    Found %zu thunk entries\n", thunkMap.size());

    // Pass 2: redirect callers (scan ALL sections for E8 calls AND E9 jmps)
    uint32_t resolved = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 5 <= rawSz; pos++) {
            uint8_t op = code[pos];
            if (op != 0xE8 && op != 0xE9) continue;
            int32_t cd = *(int32_t*)(code + pos + 1);
            uint32_t ct = va + pos + 5 + cd;
            auto it = thunkMap.find(ct);
            if (it == thunkMap.end()) continue;

            // Safety: don't redirect the thunk itself
            if (va + pos == ct) continue;

            int32_t newDisp = (int32_t)(it->second - (va + pos + 5));
            *(int32_t*)(code + pos + 1) = newDisp;
            resolved++;
        }
    }
    return resolved;
}

std::vector<Trampoline> decodeTrampolines(const PEFile& pe, uint64_t imageBase) {
    std::vector<Trampoline> result;
    // Pattern: 8F 84 24 XX XX XX XX E9 XX XX XX XX
    //          pop [rsp+XXXX]       jmp rel32
    const uint8_t popPattern[] = { 0x8F, 0x84, 0x24 };

    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!isObfuscatedSectionIdx(pe, i)) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 12 <= rawSz; pos++) {
            if (memcmp(code + pos, popPattern, 3) != 0) continue;
            if (code[pos + 7] != 0xE9) continue;

            int32_t disp = *(int32_t*)(code + pos + 8);
            uint32_t targetRVA = va + pos + 12 + disp;
            uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;
            if (targetRVA >= sizeOfImage) continue;

            Trampoline t;
            t.trampolineVA = imageBase + va + pos;
            t.targetVA = imageBase + targetRVA;
            result.push_back(t);
        }
    }
    return result;
}

} // namespace vgc
