#pragma once
#include <pefix/pefix.h>
#include <string>
#include <vector>

namespace vgc {

struct ImportWrapper {
    uint64_t wrapperVA;
    uint32_t constA;
    uint32_t constB;
    std::string apiName;
};

std::vector<ImportWrapper> decodeImportWrappers(const pefix::PEFile& pe, uint64_t imageBase);

void resolveImportNames(std::vector<ImportWrapper>& wrappers, const pefix::PEFile& pe);

} // namespace vgc
