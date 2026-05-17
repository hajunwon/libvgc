#include <vgc/antidisasm.h>
#include <vgc/log.h>
#include <griffin/griffin.h>
#include <map>

namespace vgc {

using pefix::PEFile;

std::vector<NullsubPatch> patchNullsubs(PEFile& pe) {
    // Delegate to griffin with VGC-specific section names
    std::vector<std::string> obfSections = {".grfn", ".riot"};
    auto gPatches = griffin::patchNullsubs(pe, obfSections);

    // Convert griffin::NullsubPatch to vgc::NullsubPatch
    std::vector<NullsubPatch> patches;
    patches.reserve(gPatches.size());
    for (auto& gp : gPatches)
        patches.push_back({gp.fileOffset, gp.rva});

    if (!patches.empty()) {
        std::map<std::string, int> secCount;
        for (auto& p : patches) {
            for (WORD si = 0; si < pe.numSections; si++) {
                uint32_t sva = pe.sections[si].VirtualAddress;
                uint32_t svs = pe.sections[si].Misc.VirtualSize;
                if (!svs) svs = pe.sections[si].SizeOfRawData;
                if (p.rva >= sva && p.rva < sva + svs) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                    secCount[sn]++;
                    break;
                }
            }
        }
        for (auto& [sn, cnt] : secCount)
            vgc::log::raw("    [%s] %d nullsubs patched\n", sn.c_str(), cnt);
    }

    return patches;
}

uint32_t patchAntiDisasm(PEFile& pe) {
    uint32_t patched = 0;

    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 19 <= rawSz; pos++) {
            if (code[pos] != 0xEB || code[pos+1] != 0xFF) continue;
            if (code[pos+2] != 0xF0) continue;
            if (code[pos+3] != 0x48 || code[pos+4] != 0x8D || code[pos+5] != 0x05) continue;
            if (code[pos+10] != 0x48 || code[pos+11] != 0x8D || code[pos+12] != 0x80) continue;
            if (code[pos+17] != 0xFF || code[pos+18] != 0xE0) continue;

            code[pos] = 0x90;
            code[pos+1] = 0x90;
            code[pos+2] = 0x90;
            patched++;
        }

        // EB FE (jmp -2, infinite loop dead code) -> CC CC
        for (uint32_t pos = 0; pos + 2 <= rawSz; pos++) {
            if (code[pos] == 0xEB && code[pos+1] == 0xFE) {
                if (pos > 0 && (code[pos-1] == 0xC3 || code[pos-1] == 0xCC)) {
                    code[pos] = 0xCC;
                    code[pos+1] = 0xCC;
                    patched++;
                }
            }
        }

        // EB FF (jmp -1) anti-disasm
        for (uint32_t pos = 0; pos + 3 <= rawSz; pos++) {
            if (code[pos] != 0xEB || code[pos+1] != 0xFF) continue;
            if (code[pos] == 0x90) continue;
            uint8_t after = code[pos+2];
            bool validAfter = (after >= 0x40 && after <= 0x4F) ||
                              after == 0x0F ||
                              after == 0xF0 || after == 0xF2 || after == 0xF3 ||
                              (after >= 0x50 && after <= 0x5F) ||
                              (after >= 0x80 && after <= 0x8F) ||
                              (after >= 0xB0 && after <= 0xBF) ||
                              after == 0x33 || after == 0x31 || after == 0x29 || after == 0x01 ||
                              after == 0xE8 || after == 0xE9 || after == 0xEB ||
                              after == 0xC3 || after == 0xCC || after == 0x90 ||
                              after == 0xFF || after == 0xC7 || after == 0xC6 ||
                              after == 0x66 || after == 0x65 || after == 0x64;
            if (validAfter) {
                code[pos] = 0x90;
                code[pos+1] = 0x90;
                patched++;
            }
        }

        // CD 29 (int 29h __fastfail) in obfuscated sections -> CC CC
        if (isObfuscatedSectionIdx(pe, i)) {
            for (uint32_t pos = 0; pos + 2 <= rawSz; pos++) {
                if (code[pos] == 0xCD && code[pos+1] == 0x29) {
                    code[pos] = 0xCC;
                    code[pos+1] = 0xCC;
                    patched++;
                }
            }
        }

        // Null byte runs in obfuscated sections
        if (isObfuscatedSectionIdx(pe, i)) {
            uint32_t nullRun = 0;
            for (uint32_t pos = 0; pos < rawSz; pos++) {
                if (code[pos] == 0x00) { nullRun++; continue; }
                if (nullRun >= 8) {
                    for (uint32_t k = pos - nullRun; k < pos; k++) code[k] = 0xCC;
                    patched++;
                }
                nullRun = 0;
            }
        }

        // 0F 0B (ud2) after control flow
        for (uint32_t pos = 0; pos + 2 <= rawSz; pos++) {
            if (code[pos] == 0x0F && code[pos+1] == 0x0B) {
                if (pos > 0) {
                    uint8_t prev = code[pos-1];
                    if (prev == 0xC3 || prev == 0xCC || prev == 0x90) {
                        code[pos] = 0xCC; code[pos+1] = 0xCC; patched++;
                    }
                }
            }
        }

        // .riot1 specific patterns
        {
            char sname2[9] = {}; memcpy(sname2, pe.sections[i].Name, 8);
            if (strcmp(sname2, ".riot1") == 0) {
                // CC 90 E9 [disp32]
                for (uint32_t pos = 0; pos + 7 <= rawSz; pos++) {
                    if (code[pos] != 0xCC || code[pos+1] != 0x90 || code[pos+2] != 0xE9) continue;
                    code[pos] = 0x90;
                    code[pos+1] = 0x90;
                    patched++;
                }

                // Dead MOV rax, imm64 chains
                for (uint32_t pos = 0; pos + 10 <= rawSz; pos++) {
                    if (code[pos] != 0x48 || code[pos+1] != 0xB8) continue;
                    if (pos > 0 && code[pos-1] != 0xCC && code[pos-1] != 0x90 &&
                        code[pos-1] != 0xC3 && code[pos-1] != 0x00) continue;
                    uint32_t run = 0;
                    uint32_t p2 = pos;
                    while (p2 + 10 <= rawSz && code[p2] == 0x48 && code[p2+1] == 0xB8) {
                        run++; p2 += 10;
                    }
                    if (run >= 3) {
                        for (uint32_t k = pos; k < p2; k++) code[k] = 0xCC;
                        patched++;
                        pos = p2 - 1;
                    }
                }

                // Data-in-code tables
                for (uint32_t pos = 1; pos + 32 <= rawSz; pos++) {
                    uint8_t prev = code[pos-1];
                    if (prev != 0xCC && prev != 0xC3) continue;
                    bool isData = true;
                    int zeroCount = 0;
                    for (uint32_t k = 0; k < 16; k++) {
                        if (code[pos+k] == 0x00) zeroCount++;
                        if (code[pos+k] == 0x48 || code[pos+k] == 0x4C ||
                            code[pos+k] == 0x55 || code[pos+k] == 0x41) { isData = false; break; }
                    }
                    if (isData && zeroCount < 4) {
                        uint32_t endP = pos;
                        while (endP + 4 < rawSz) {
                            if (code[endP] == 0x41 && code[endP+1] >= 0x54 && code[endP+1] <= 0x57) break;
                            if (code[endP] == 0x48 && code[endP+1] == 0x83 && code[endP+2] == 0xEC) break;
                            if (code[endP] == 0x55 && code[endP+1] == 0x48) break;
                            if (code[endP] == 0xCC && code[endP+1] == 0xCC) break;
                            endP++;
                        }
                        if (endP - pos >= 16) {
                            for (uint32_t k = pos; k < endP; k++) code[k] = 0xCC;
                            patched++;
                            pos = endP - 1;
                        }
                    }
                }
            }
        }
    }
    return patched;
}

} // namespace vgc
