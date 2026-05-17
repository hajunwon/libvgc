#include <vgc/imports.h>
#include <vgc/log.h>

namespace vgc {

using pefix::PEFile;

std::vector<ImportWrapper> decodeImportWrappers(const PEFile& pe, uint64_t imageBase) {
    std::vector<ImportWrapper> result;

    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        if (strcmp(name, ".riot1") != 0) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const uint8_t* code = pe.data.data() + rawOff;

        // Detect wrappers by finding the dispatcher hash constant 0x564C5004
        for (uint32_t pos = 0; pos + 20 <= rawSz; pos++) {
            if (code[pos] != 0xB9) continue;
            uint32_t hashVal = *(uint32_t*)(code + pos + 1);
            if ((hashVal & 0xFFFF0000) != 0x56470000) continue;

            // Found dispatcher call. Search backward for function start
            uint32_t funcStart = 0;
            for (uint32_t back = 1; back < 60 && pos > back; back++) {
                uint32_t p = pos - back;
                bool isStart = false;
                if (code[p] == 0x48 && p+2 < rawSz && code[p+1] == 0x83 && code[p+2] == 0xEC) isStart = true;
                if (code[p] == 0x48 && p+2 < rawSz && code[p+1] == 0x89 && (code[p+2] == 0x4C || code[p+2] == 0x54)) isStart = true;
                if (code[p] == 0x40 && p+1 < rawSz && (code[p+1] >= 0x50 && code[p+1] <= 0x57)) isStart = true;
                if (code[p] >= 0x50 && code[p] <= 0x57) isStart = true;
                if (isStart) {
                    if (p > 0 && (code[p-1] == 0xCC || code[p-1] == 0xC3 || code[p-1] == 0x00)) {
                        funcStart = p;
                        break;
                    }
                }
            }
            if (!funcStart) funcStart = pos;

            // Extract the two dword constants (v4[0], v4[1])
            uint32_t constA = 0, constB = 0;
            bool foundA = false, foundB = false;
            uint32_t searchStart = (funcStart > 5) ? funcStart - 5 : 0;
            for (uint32_t j = searchStart; j < pos + 5 && j + 8 <= rawSz; j++) {
                if (code[j] == 0xC7) {
                    uint32_t val = 0;
                    int valOff = 0;
                    if (j+3 < rawSz && code[j+1] == 0x04 && code[j+2] == 0x24) valOff = 3;
                    else if (j+4 < rawSz && code[j+1] == 0x44 && code[j+2] == 0x24) valOff = 4;
                    else if (j+7 < rawSz && code[j+1] == 0x84 && code[j+2] == 0x24) valOff = 7;
                    else if (j+2 < rawSz && code[j+1] == 0x02) valOff = 2;
                    else if (j+3 < rawSz && code[j+1] == 0x42 && code[j+2] == 0x04) valOff = 3;
                    if (valOff && j + valOff + 4 <= rawSz) {
                        val = *(uint32_t*)(code + j + valOff);
                        if (val < 0x1000000) {
                            if (!foundA) { constA = val; foundA = true; }
                            else if (!foundB && val != constA) { constB = val; foundB = true; }
                        }
                    }
                }
            }

            if (!foundA && !foundB) continue;

            ImportWrapper w;
            w.wrapperVA = imageBase + va + funcStart;
            w.constA = foundA ? constA : 0;
            w.constB = foundB ? constB : 0;

            result.push_back(w);
        }
    }
    return result;
}

void resolveImportNames(std::vector<ImportWrapper>& wrappers, const PEFile& pe) {
    if (wrappers.empty()) return;

    // Find smallest CONST_A (first entry in the string table)
    uint32_t minConstA = UINT32_MAX;
    for (auto& w : wrappers)
        if (w.constA > 0 && w.constA < minConstA) minConstA = w.constA;
    if (minConstA == UINT32_MAX) return;

    // Multi-anchor voting
    static const char* anchors[] = {
        "CreateFileW", "RegOpenKeyExW", "GetProcAddress", "LoadLibraryA",
        "GetSystemFirmwareTable", "DeviceIoControl", "VirtualAlloc",
        "CreateToolhelp32Snapshot", "GetModuleFileNameW", "CloseHandle",
        "SetServiceStatus", "RegCloseKey", "HeapAlloc", "GetLastError",
        "WSAStartup", "WSACloseEvent", "NtAllocateVirtualMemory",
        "NtMapViewOfSection", "NtWaitForSingleObject",
        NULL
    };

    // Find file offsets of ALL occurrences of anchor strings in the entire binary
    std::vector<uint32_t> anchorOffsets;
    for (int ai = 0; anchors[ai]; ai++) {
        size_t alen = strlen(anchors[ai]);
        for (uint32_t fpos = 0; fpos + alen + 1 < pe.data.size(); fpos++) {
            if (pe.data[fpos] != (uint8_t)anchors[ai][0]) continue;
            if (memcmp(pe.data.data() + fpos, anchors[ai], alen) == 0 &&
                pe.data[fpos + alen] == 0 && (fpos == 0 || pe.data[fpos-1] == 0)) {
                anchorOffsets.push_back(fpos);
            }
        }
    }

    if (anchorOffsets.empty()) { vgc::log::raw("    WARNING: no anchor strings found\n"); return; }

    uint32_t bestBase = 0;
    int bestCount = 0;

    std::sort(anchorOffsets.begin(), anchorOffsets.end());

    for (uint32_t ancOff : anchorOffsets) {
        for (auto& w : wrappers) {
            if (w.constA == 0 || w.constA > ancOff) continue;
            uint32_t candidateBase = ancOff - w.constA;

            uint32_t firstOff = candidateBase + minConstA;
            if (firstOff < 1 || firstOff + 4 >= pe.data.size()) continue;
            if (pe.data[firstOff-1] != 0 || pe.data[firstOff] < 'A' || pe.data[firstOff] > 'Z') continue;

            int count = 0;
            for (auto& w2 : wrappers) {
                if (w2.constA == 0) continue;
                for (int d = 0; d <= 8; d++) {
                    for (int dir = 0; dir <= 1; dir++) {
                        int dd = dir == 0 ? -d : d;
                        if (d == 0 && dir == 1) continue;
                        uint32_t nameOff = (uint32_t)((int)(candidateBase + w2.constA) + dd);
                        if (nameOff < 1 || nameOff + 4 >= pe.data.size()) continue;
                        if (pe.data[nameOff-1] == 0 && pe.data[nameOff] >= 'A' && pe.data[nameOff] <= 'Z') {
                            const char* s = (const char*)(pe.data.data() + nameOff);
                            size_t slen = strnlen(s, 80);
                            if (slen >= 4 && slen < 60) {
                                bool hasDot = false;
                                for (size_t k = 0; k < slen; k++) if (s[k] == '.') hasDot = true;
                                if (!hasDot) { count++; break; }
                            }
                        }
                    }
                    if (count > bestCount) break;
                }
            }
            if (count > bestCount) { bestCount = count; bestBase = candidateBase; }
        }
    }

    if (bestCount == 0) { vgc::log::raw("    WARNING: could not determine string table base\n"); return; }
    vgc::log::raw("    String table base auto-detected: fileOff=0x%X (%d matches)\n", bestBase, bestCount);

    // Try to find a SECOND string table for remaining wrappers
    uint32_t bestBase2 = 0;
    int bestCount2 = 0;
    for (uint32_t ancOff : anchorOffsets) {
        if (ancOff == 0) continue;
        if (ancOff > bestBase && ancOff < bestBase + 0x10000) continue;
        for (auto& w : wrappers) {
            if (w.constA == 0 || w.constA > ancOff) continue;
            uint32_t cb = ancOff - w.constA;
            if (cb == bestBase || abs((int)cb - (int)bestBase) < 0x1000) continue;
            int count = 0;
            for (auto& w2 : wrappers) {
                if (w2.constA == 0) continue;
                for (int d = 0; d <= 8; d++) {
                    for (int dir = 0; dir <= 1; dir++) {
                        int dd = dir == 0 ? -d : d;
                        if (d == 0 && dir == 1) continue;
                        uint32_t nameOff = (uint32_t)((int)(cb + w2.constA) + dd);
                        if (nameOff < 1 || nameOff + 4 >= pe.data.size()) continue;
                        if (pe.data[nameOff-1] == 0 && pe.data[nameOff] >= 'A' && pe.data[nameOff] <= 'Z') {
                            const char* s = (const char*)(pe.data.data() + nameOff);
                            size_t slen = strnlen(s, 80);
                            if (slen >= 4 && slen < 60) {
                                bool hasDot = false;
                                for (size_t k = 0; k < slen; k++) if (s[k] == '.') hasDot = true;
                                if (!hasDot) { count++; break; }
                            }
                        }
                    }
                }
            }
            if (count > bestCount2) { bestCount2 = count; bestBase2 = cb; }
        }
    }
    if (bestCount2 > 10) {
        vgc::log::raw("    Second string table candidate: fileOff=0x%X (%d matches)\n", bestBase2, bestCount2);
    }

    // Better second base detection: use RESOLVED wrapper names to find alternate locations
    {
        std::map<uint32_t, int> baseVotes;
        for (auto& w : wrappers) {
            if (w.apiName.empty() || w.constA == 0) continue;
            const char* name = w.apiName.c_str();
            size_t nlen = w.apiName.size();
            uint32_t firstPos = bestBase + w.constA;
            for (uint32_t fp = 0; fp + nlen + 1 < pe.data.size(); fp++) {
                if (abs((int)fp - (int)firstPos) < 0x1000) continue;
                if (pe.data[fp] != (uint8_t)name[0]) continue;
                if (memcmp(pe.data.data() + fp, name, nlen) == 0 &&
                    pe.data[fp + nlen] == 0 && (fp == 0 || pe.data[fp-1] == 0)) {
                    uint32_t cb = fp - w.constA;
                    baseVotes[cb]++;
                    break;
                }
            }
        }
        uint32_t voteBest = 0; int voteMax = 0;
        for (auto it = baseVotes.begin(); it != baseVotes.end(); ++it) {
            if (it->second > voteMax) { voteMax = it->second; voteBest = it->first; }
        }
        if (voteMax > bestCount2 && voteMax >= 3) {
            bestBase2 = voteBest;
            bestCount2 = voteMax;
            vgc::log::raw("    Second string table (vote-based): fileOff=0x%X (%d votes)\n", bestBase2, bestCount2);
        }
    }

    // Resolve names using the best base(s), with fuzzy search fallback
    int resolved = 0;
    uint32_t bases[] = { bestBase, bestBase2 };
    int numBases = bestBase2 > 0 ? 2 : 1;
    for (auto& w : wrappers) {
        if (w.constA == 0) continue;
        for (int bi = 0; bi < numBases && w.apiName.empty(); bi++) {
        uint32_t approxOff = bases[bi] + w.constA;

        std::string bestName;
        int bestDist = 999;
        for (int delta = 0; delta <= 128; delta++) {
            for (int dir = 0; dir <= 1; dir++) {
                int d = dir == 0 ? -delta : delta;
                if (delta == 0 && dir == 1) continue;
                uint32_t tryOff = (uint32_t)((int)approxOff + d);
                if (tryOff < 1 || tryOff + 4 >= pe.data.size()) continue;
                if (pe.data[tryOff-1] == 0 && ((pe.data[tryOff] >= 'A' && pe.data[tryOff] <= 'Z') || (pe.data[tryOff] >= 'a' && pe.data[tryOff] <= 'z'))) {
                    const char* s = (const char*)(pe.data.data() + tryOff);
                    size_t slen = strnlen(s, 80);
                    if (slen >= 4 && slen < 60) {
                        bool valid = true, hasDot = false;
                        for (size_t k = 0; k < slen; k++) {
                            if (s[k] < 0x20 || s[k] > 0x7E) { valid = false; break; }
                            if (s[k] == '.') hasDot = true;
                        }
                        if (valid && !hasDot && abs(d) < bestDist) {
                            bestName = std::string(s, slen);
                            bestDist = abs(d);
                        }
                    }
                }
            }
            if (bestDist == 0) break;
        }
        if (!bestName.empty()) { w.apiName = bestName; resolved++; }
        } // bases loop
    }
    // Third pass: for still-unresolved wrappers, brute-force search ALL sections
    for (auto& w : wrappers) {
        if (!w.apiName.empty() || w.constA == 0) continue;
        for (WORD si = 0; si < pe.numSections; si++) {
            if (!w.apiName.empty()) break;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
            uint32_t target = w.constA;
            if (target >= rawSz) continue;
            for (uint32_t delta = 0; delta <= 128; delta++) {
                for (int dir = -1; dir <= 1; dir += 2) {
                    uint32_t tryPos = rawOff + target + dir * delta;
                    if (tryPos < 1 || tryPos + 4 >= pe.data.size()) continue;
                    if (pe.data[tryPos-1] != 0) continue;
                    uint8_t c = pe.data[tryPos];
                    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) continue;
                    const char* s = (const char*)(pe.data.data() + tryPos);
                    size_t slen = strnlen(s, 80);
                    if (slen < 4 || slen >= 60) continue;
                    bool valid = true, hasDot = false;
                    for (size_t k = 0; k < slen; k++) {
                        if (s[k] < 0x20 || s[k] > 0x7E) { valid = false; break; }
                        if (s[k] == '.') hasDot = true;
                    }
                    bool hasSpace = false, hasColon = false;
                    for (size_t k = 0; k < slen; k++) {
                        if (s[k] == ' ') hasSpace = true;
                        if (s[k] == ':') hasColon = true;
                    }
                    if (valid && !hasDot && !hasSpace && !hasColon) {
                        w.apiName = std::string(s, slen);
                        resolved++;
                        break;
                    }
                }
                if (!w.apiName.empty()) break;
            }
        }
    }
    // Final pass: give remaining unresolved wrappers placeholder names
    for (auto& w : wrappers) {
        if (!w.apiName.empty() || w.constA == 0) continue;
        char buf[32];
        sprintf_s(buf, "unknown_%X", w.constA);
        w.apiName = buf;
        resolved++;
    }
    vgc::log::raw("    Resolved: %d / %zu\n", resolved, wrappers.size());
}

} // namespace vgc
