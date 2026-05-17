#pragma once
#include <pefix/pefix.h>
#include <pefix/xrefs.h>
#include <string>
#include <vector>

namespace vgc {

struct FuncBoundary {
    uint32_t beginRVA;
    uint32_t endRVA;
};

std::vector<FuncBoundary> readPdataFunctions(const pefix::PEFile& pe);

// Forwarded to pefix::InferredName
using InferredName = pefix::InferredName;

inline std::vector<InferredName> inferFunctionNames(const pefix::PEFile& pe, uint64_t imageBase,
    const std::vector<pefix::RipRelativeRef>& refs) {
    return pefix::inferFunctionNames(pe, imageBase, refs);
}

} // namespace vgc
