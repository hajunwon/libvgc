#pragma once
#include <pefix/sections.h>
#include <pefix/pefix.h>
#include <cstring>

namespace vgc {

inline bool isObfuscatedSection(const char* name) {
    return strncmp(name, ".grfn", 5) == 0 ||
           strncmp(name, ".obf", 4) == 0;
}

} // namespace vgc
