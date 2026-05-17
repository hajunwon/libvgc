#include <vgc/funcfix.h>
#include <vgc/log.h>
#include <cstring>

namespace vgc {

using pefix::PEFile;

std::vector<FuncBoundary> readPdataFunctions(const PEFile& pe) {
    std::vector<FuncBoundary> result;

    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        if (strcmp(name, ".pdata") != 0) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

        for (uint32_t pos = 0; pos + 12 <= rawSz; pos += 12) {
            uint32_t begin = *(uint32_t*)(pe.data.data() + rawOff + pos);
            uint32_t end = *(uint32_t*)(pe.data.data() + rawOff + pos + 4);
            if (begin == 0 && end == 0) continue;
            if (begin >= end) continue;
            if (end > pe.nt->OptionalHeader.SizeOfImage) continue;
            result.push_back({begin, end});
        }
    }

    vgc::log::raw("    .pdata: %zu function boundaries\n", result.size());
    return result;
}

} // namespace vgc
