#pragma once
#include <pefix/pefix.h>
#include <pefix/xrefs.h>
#include <vgc/antidisasm.h>
#include <vgc/symbols.h>
#include <vgc/imports.h>

namespace vgc {

void generateIdcScript(const char* path,
    const std::vector<pefix::RipRelativeRef>& refs,
    const std::vector<NullsubPatch>& nullsubs,
    const std::vector<OpenSSLSymbol>& sslSymbols,
    const std::vector<RTTIClass>& rttiClasses,
    const std::vector<ImportWrapper>& importWrappers,
    const std::vector<pefix::PointerRef>& ptrRefs,
    uint64_t imageBase, uint32_t sizeOfImage);

void generateIdaScript(const char* path,
    const std::vector<pefix::RipRelativeRef>& refs,
    uint64_t imageBase, uint32_t sizeOfImage);

} // namespace vgc
