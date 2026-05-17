#pragma once
#include <pefix/pefix.h>
#include <vector>

namespace vgc {

struct Trampoline {
    uint64_t trampolineVA;
    uint64_t targetVA;
};

uint32_t flattenJmpChains(pefix::PEFile& pe);

uint32_t resolveThunks(pefix::PEFile& pe);

std::vector<Trampoline> decodeTrampolines(const pefix::PEFile& pe, uint64_t imageBase);

} // namespace vgc
