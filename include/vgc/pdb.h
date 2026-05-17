#pragma once
#include <pefix/pefix.h>
#include <string>
#include <vector>

namespace vgc {

struct PdbSymbol {
    uint32_t rva;
    uint16_t section;
    std::string name;
    bool isFunction;
};

bool generatePdb(pefix::PEFile& pe, uint64_t imageBase,
    const std::vector<PdbSymbol>& symbols,
    const char* pdbPath);

} // namespace vgc
