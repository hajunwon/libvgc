#pragma once
#include <pefix/pefix.h>
#include <pefix/xrefs.h>
#include <string>
#include <vector>

namespace vgc {

struct OpenSSLSymbol {
    uint64_t funcVA;
    std::string name;
};

// Forwarded to pefix::RTTIClass
using RTTIClass = pefix::RTTIClass;

struct KeyStringRef {
    uint64_t instrVA;
    std::string value;
    std::string category;
};

std::vector<OpenSSLSymbol> recoverOpenSSLSymbols(const pefix::PEFile& pe, uint64_t imageBase);

inline std::vector<RTTIClass> parseRTTI(const pefix::PEFile& pe, uint64_t imageBase) {
    return pefix::parseRTTI(pe, imageBase);
}

std::vector<KeyStringRef> findKeyStringRefs(const pefix::PEFile& pe,
    const std::vector<pefix::RipRelativeRef>& refs, uint64_t imageBase);

} // namespace vgc
