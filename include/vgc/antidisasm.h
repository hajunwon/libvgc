#pragma once
#include <pefix/pefix.h>
#include <cstring>
#include <vector>

namespace vgc {

inline bool isObfuscatedSectionIdx(const pefix::PEFile& pe, int idx) {
    if (idx < 0 || idx >= pe.numSections) return false;
    char name[9] = {};
    memcpy(name, pe.sections[idx].Name, 8);
    return (strcmp(name, ".grfn1") == 0 || strcmp(name, ".riot1") == 0 ||
            strcmp(name, ".riot0") == 0);
}

struct NullsubPatch {
    uint32_t fileOffset;
    uint32_t rva;
};

uint32_t patchAntiDisasm(pefix::PEFile& pe);

std::vector<NullsubPatch> patchNullsubs(pefix::PEFile& pe);

inline uint32_t stripJunkSections(pefix::PEFile&) { return 0; }

} // namespace vgc
