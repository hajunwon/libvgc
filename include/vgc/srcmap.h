#pragma once
#include <pefix/pefix.h>
#include <string>
#include <vector>
#include <map>

namespace vgc {

struct SourceFile {
    std::string path;
    std::string category;
    std::vector<uint64_t> functionVAs;
    std::vector<std::string> classNames;
};

struct SourceMap {
    std::vector<SourceFile> files;
    std::map<std::string, int> categoryCount;
};

SourceMap inferSourceMap(const pefix::PEFile& pe, uint64_t imageBase);

void printSourceMap(const SourceMap& map);

} // namespace vgc
