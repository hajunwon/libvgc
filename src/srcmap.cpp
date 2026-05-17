#include <vgc/srcmap.h>
#include <vgc/log.h>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <set>
#include <regex>

namespace vgc {

using pefix::PEFile;

static std::string categorize(const std::string& path) {
    if (path.find("crypto") != std::string::npos || path.find("ssl") != std::string::npos ||
        path.find("providers") != std::string::npos || path.find("include\\openssl") != std::string::npos)
        return "openssl";
    if (path.find("CryptoPP") != std::string::npos || path.find("cryptopp") != std::string::npos)
        return "cryptopp";
    if (path.find("Vanguard") != std::string::npos || path.find("vanguard") != std::string::npos)
        return "vanguard";
    if (path.find("VanguardSDK") != std::string::npos)
        return "sdk";
    if (path.find("nlohmann") != std::string::npos || path.find("json") != std::string::npos)
        return "json";
    if (path.find("protobuf") != std::string::npos || path.find("google") != std::string::npos)
        return "protobuf";
    if (path.find("curl") != std::string::npos || path.find("libcurl") != std::string::npos)
        return "libcurl";
    if (path.find("std::") != std::string::npos)
        return "std";
    return "other";
}

static std::string classToFile(const std::string& className) {
    // CryptoPP::Rijndael::Base → cryptopp/rijndael.cpp
    // VanguardSDK::Message → vanguardsdk/message.cpp
    // Vanguard::AresLoginMessage → vanguard/ares_login_message.cpp

    size_t lastSep = className.rfind("::");
    std::string leaf = (lastSep != std::string::npos) ? className.substr(lastSep + 2) : className;
    std::string ns = (lastSep != std::string::npos) ? className.substr(0, lastSep) : "";

    // Convert CamelCase to snake_case
    std::string snake;
    for (size_t i = 0; i < leaf.size(); i++) {
        if (i > 0 && isupper(leaf[i]) && islower(leaf[i-1]))
            snake += '_';
        snake += (char)tolower(leaf[i]);
    }

    // Namespace to directory
    std::string dir;
    if (ns.find("CryptoPP") != std::string::npos) dir = "cryptopp/";
    else if (ns.find("VanguardSDK") != std::string::npos) dir = "vanguard_sdk/";
    else if (ns.find("Vanguard") != std::string::npos) dir = "vanguard/";
    else if (ns.find("nlohmann") != std::string::npos) dir = "json/";
    else if (ns.find("google") != std::string::npos) dir = "protobuf/";

    return dir + snake + ".cpp";
}

SourceMap inferSourceMap(const PEFile& pe, uint64_t imageBase) {
    (void)imageBase;
    SourceMap map;
    std::set<std::string> seenPaths;

    // 1. Extract debug file paths from strings
    std::string text((const char*)pe.data.data(), pe.data.size());

    // Search for .c/.cpp/.h file paths
    for (size_t i = 0; i + 10 < pe.data.size(); i++) {
        if (pe.data[i] == '.' && (pe.data[i+1] == 'c' || pe.data[i+1] == 'h') &&
            (pe.data[i+2] == 0 || pe.data[i+2] == 'p')) {
            // Find start of path
            size_t start = i;
            while (start > 0 && pe.data[start-1] >= 0x20 && pe.data[start-1] < 0x7F)
                start--;

            size_t end = i + 1;
            while (end < pe.data.size() && pe.data[end] >= 0x20 && pe.data[end] < 0x7F)
                end++;

            if (end - start >= 5 && end - start < 80) {
                std::string path((const char*)pe.data.data() + start, end - start);
                if ((path.find(".c") != std::string::npos || path.find(".h") != std::string::npos) &&
                    path.find('\\') != std::string::npos) {
                    if (seenPaths.insert(path).second) {
                        SourceFile sf;
                        sf.path = path;
                        sf.category = categorize(path);
                        map.files.push_back(sf);
                    }
                }
            }
        }
    }

    // 2. Extract RTTI class names → infer files
    for (size_t i = 0; i + 8 < pe.data.size(); i++) {
        if (pe.data[i] == '.' && pe.data[i+1] == '?' && pe.data[i+2] == 'A' && pe.data[i+3] == 'V') {
            size_t end = i + 4;
            while (end < pe.data.size() && pe.data[end] != 0 && end - i < 200)
                end++;

            std::string raw((const char*)pe.data.data() + i + 4, end - i - 4);
            // Demangle: replace @ with ::, remove trailing @@
            std::string name;
            for (size_t j = 0; j < raw.size(); j++) {
                if (raw[j] == '@') {
                    if (j + 1 < raw.size() && raw[j+1] == '@') break;
                    name += "::";
                } else {
                    name += raw[j];
                }
            }

            // Reverse namespace order (RTTI stores inner→outer)
            std::vector<std::string> parts;
            size_t pos = 0;
            while (pos < name.size()) {
                size_t sep = name.find("::", pos);
                if (sep == std::string::npos) { parts.push_back(name.substr(pos)); break; }
                parts.push_back(name.substr(pos, sep - pos));
                pos = sep + 2;
            }
            std::reverse(parts.begin(), parts.end());
            std::string fullName;
            for (size_t j = 0; j < parts.size(); j++) {
                if (j > 0) fullName += "::";
                fullName += parts[j];
            }

            if (fullName.size() > 2 && fullName.find("std::") == std::string::npos) {
                std::string inferredFile = classToFile(fullName);
                if (!inferredFile.empty() && seenPaths.insert(inferredFile).second) {
                    SourceFile sf;
                    sf.path = inferredFile;
                    sf.category = categorize(fullName);
                    sf.classNames.push_back(fullName);
                    map.files.push_back(sf);
                }
            }
        }
    }

    // Count categories
    for (auto& f : map.files) {
        map.categoryCount[f.category]++;
    }

    // Sort by category then path
    std::sort(map.files.begin(), map.files.end(), [](const SourceFile& a, const SourceFile& b) {
        if (a.category != b.category) return a.category < b.category;
        return a.path < b.path;
    });

    return map;
}

void printSourceMap(const SourceMap& map) {
    vgc::log::raw("\n=== Inferred Source File Map ===\n");
    vgc::log::raw("Total files: %zu\n\n", map.files.size());

    for (auto& [cat, count] : map.categoryCount)
        vgc::log::raw("  %-12s %d files\n", cat.c_str(), count);
    vgc::log::raw("\n");

    std::string lastCat;
    for (auto& f : map.files) {
        if (f.category != lastCat) {
            vgc::log::raw("\n[%s]\n", f.category.c_str());
            lastCat = f.category;
        }
        vgc::log::raw("  %s", f.path.c_str());
        if (!f.classNames.empty())
            vgc::log::raw("  ← %s", f.classNames[0].c_str());
        vgc::log::raw("\n");
    }
}

} // namespace vgc
