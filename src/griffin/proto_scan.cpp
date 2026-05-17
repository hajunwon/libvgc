#include <vgc/griffin/proto_scan.h>
#include <vgc/log.h>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <set>
#include <map>
#include <unordered_map>

namespace vgc {

using pefix::PEFile;

const ProtoField* ProtoMessage::fieldByName(const char* name) const {
    for (auto& f : fields)
        if (f.name == name) return &f;
    return nullptr;
}

const ProtoField* ProtoMessage::fieldByNumber(uint32_t num) const {
    for (auto& f : fields)
        if (f.fieldNumber == num) return &f;
    return nullptr;
}

static std::vector<uint32_t> findLeaRipRefs(const PEFile& pe, uint32_t targetRVA) {
    std::vector<uint32_t> results;
    for (int si = 0; si < pe.numSections; si++) {
        if (!(pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t secRVA = pe.sections[si].VirtualAddress;
        for (uint32_t p = 0; p + 7 <= rawSz; p++) {
            const uint8_t* b = pe.data.data() + rawOff + p;
            if ((b[0] == 0x48 || b[0] == 0x4C) && b[1] == 0x8D && (b[2] & 0xC7) == 0x05) {
                int32_t disp = *(int32_t*)(b + 3);
                uint32_t ref = secRVA + p + 7 + disp;
                if (ref == targetRVA)
                    results.push_back(secRVA + p);
            }
        }
    }
    return results;
}

static uint32_t findContainingFunc(const PEFile& pe, uint32_t instrRVA) {
    int sec = pe.findSection(instrRVA);
    if (sec < 0) return 0;
    uint32_t secRVA = pe.sections[sec].VirtualAddress;
    uint32_t rawOff = pe.sections[sec].PointerToRawData;
    uint32_t posInSec = instrRVA - secRVA;

    for (uint32_t back = 1; back < 0x2000 && back <= posInSec; back++) {
        uint32_t o = rawOff + posInSec - back;
        uint8_t b = pe.data[o];

        if (b == 0xCC || b == 0x90)
            return secRVA + posInSec - back + 1;

        // C3 (RET) followed by a prologue = previous function's end
        if (b == 0xC3 && posInSec - back + 1 < posInSec) {
            const uint8_t* next = pe.data.data() + o + 1;
            if (next[0] == 0x48 && next[1] == 0x89) return secRVA + posInSec - back + 1;
            if (next[0] == 0x48 && next[1] == 0x83 && next[2] == 0xEC) return secRVA + posInSec - back + 1;
            if (next[0] == 0x48 && next[1] == 0x81 && next[2] == 0xEC) return secRVA + posInSec - back + 1;
            if (next[0] == 0x40 && next[1] >= 0x53 && next[1] <= 0x57) return secRVA + posInSec - back + 1;
            if (next[0] == 0x55 || next[0] == 0x53) return secRVA + posInSec - back + 1;
        }
    }
    return instrRVA;
}

static std::vector<uint32_t> findPointerTo(const PEFile& pe, uint64_t targetVA) {
    std::vector<uint32_t> results;
    uint8_t needle[8];
    memcpy(needle, &targetVA, 8);
    for (int si = 0; si < pe.numSections; si++) {
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t secRVA = pe.sections[si].VirtualAddress;
        if (rawSz < 8) continue;
        for (uint32_t p = 0; p + 8 <= rawSz; p += 8) {
            if (memcmp(pe.data.data() + rawOff + p, needle, 8) == 0)
                results.push_back(secRVA + p);
        }
    }
    return results;
}

// Precise serialize function parser.
// Detects 3 field patterns emitted by protobuf codegen:
//
// Pattern A (string/bytes): struct offset from MOV rcx,[r13+disp32], field number from MOV edx,imm32
//   49 8B 8D [disp32]  ... BA [fieldnum] 00 00 00
//
// Pattern B (embedded message): struct offset from MOV rdx,[r13+disp32], field number from MOV ecx,imm32
//   49 8B 95 [disp32]  ... B9 [fieldnum] 00 00 00
//   OR: 4D 8B 85 [disp32] ... B9 [fieldnum] 00 00 00 (mov r8,[r13+disp32])
//
// Pattern C (varint): struct offset from CMP [r13+disp32],r14d, wire tag from MOV byte [rsi],tag
//   45 39 B5 [disp32]  ... C6 06 [tag]
//
void parseSerializeOffsets(const PEFile& pe, uint64_t imageBase,
                           uint32_t serializeRVA, ProtoMessage& msg) {
    (void)imageBase;
    uint32_t off = pe.rvaToOffset(serializeRVA);
    if (!off) return;
    int sec = pe.findSection(serializeRVA);
    if (sec < 0) return;

    uint32_t secRVA = pe.sections[sec].VirtualAddress;
    uint32_t rawBase = pe.sections[sec].PointerToRawData;
    uint32_t secSz = pe.sections[sec].SizeOfRawData;
    uint32_t funcStart = serializeRVA - secRVA;

    uint32_t scanStart = (funcStart > 0x20) ? funcStart - 0x20 : 0;
    uint32_t scanEnd = std::min(funcStart + 0x1000, secSz);
    const uint8_t* base = pe.data.data() + rawBase;

    vgc::log::raw("    Parsing serialize at RVA 0x%X...\n", serializeRVA);

    // Phase 1: Collect all field number literals and struct offset accesses
    struct FieldNumLit {
        uint32_t fieldNumber;
        uint32_t pos;         // position in section
        uint8_t reg;          // which register: 0=edx(BA), 1=ecx(B9), 2=r8d(41 B8)
    };
    struct WireTagLit {
        uint8_t tag;
        uint32_t pos;
    };
    struct StructAccess {
        uint32_t offset;
        uint32_t pos;
    };
    struct DescRef {
        uint32_t descStringRVA;
        uint32_t pos;
    };

    std::vector<FieldNumLit> fieldNums;
    std::vector<WireTagLit> wireTags;
    std::vector<StructAccess> structAccs;
    std::vector<DescRef> descRefs;

    for (uint32_t p = scanStart; p + 7 < scanEnd; p++) {
        const uint8_t* b = base + p;

        // Field number: BA XX 00 00 00 (mov edx, XX)
        if (b[0] == 0xBA && b[2] == 0x00 && b[3] == 0x00 && b[4] == 0x00 && b[1] >= 1 && b[1] <= 30)
            fieldNums.push_back({b[1], p, 0});
        // Field number: B9 XX 00 00 00 (mov ecx, XX)
        if (b[0] == 0xB9 && b[2] == 0x00 && b[3] == 0x00 && b[4] == 0x00 && b[1] >= 1 && b[1] <= 30)
            fieldNums.push_back({b[1], p, 1});
        // Field number: 41 B8 XX 00 00 00 (mov r8d, XX)
        if (b[0] == 0x41 && b[1] == 0xB8 && b[3] == 0x00 && b[4] == 0x00 && b[5] == 0x00 && b[2] >= 1 && b[2] <= 30)
            fieldNums.push_back({b[2], p, 2});

        // Wire tag: C6 06 XX (mov byte [rsi], tag)
        if (b[0] == 0xC6 && b[1] == 0x06 && (b[2] >> 3) >= 1 && (b[2] >> 3) <= 30 && (b[2] & 7) == 0)
            wireTags.push_back({b[2], p});

        // Struct access: REX {8B|39|8D|83} ModRM disp8/disp32, rm!=4 (no SIB)
        if ((b[0] & 0xF0) == 0x40 && (b[1] == 0x8B || b[1] == 0x39 || b[1] == 0x8D || b[1] == 0x83)) {
            uint8_t rex = b[0];
            uint8_t modrm = b[2];
            uint8_t mod = modrm >> 6;
            uint8_t rm = modrm & 7;
            bool rexB = (rex & 0x01) != 0;
            // Actual base register: rm + REX.B extension
            int baseReg = rm + (rexB ? 8 : 0);

            if (rm != 4) { // no SIB
                if (mod == 2) { // disp32
                    int32_t disp = *(int32_t*)(b + 3);
                    if (disp > 0x08 && disp < 0x200)
                        structAccs.push_back({(uint32_t)disp, p});
                } else if (mod == 1 && baseReg != 4 && baseReg != 5) {
                    // disp8: accept any base except RSP(4) and RBP(5)
                    uint8_t disp = b[3];
                    if (disp >= 0x10 && disp < 0x7F)
                        structAccs.push_back({(uint32_t)disp, p});
                }
            }
        }
        // Also: non-REX struct access (e.g., 83 79 20 00 = cmp [rcx+0x20], 0)
        if (b[0] == 0x83 || b[0] == 0x8B || b[0] == 0x39) {
            uint8_t modrm = b[1];
            uint8_t mod = modrm >> 6;
            uint8_t rm = modrm & 7;
            if (mod == 1 && rm != 4 && rm != 5) {
                uint8_t disp = b[2];
                if (disp >= 0x10 && disp < 0x7F)
                    structAccs.push_back({(uint32_t)disp, p});
            }
        }

        // Descriptor LEA: 4C 8D 0D [disp32] (lea r9, [rip+disp])
        if (b[0] == 0x4C && b[1] == 0x8D && b[2] == 0x0D) {
            int32_t disp = *(int32_t*)(b + 3);
            uint32_t target = secRVA + p + 7 + disp;
            descRefs.push_back({target, p});
        }
    }

    // Phase 2: For each field number literal, find nearest preceding struct access
    // This is the reverse-lookup approach: fieldnum → offset
    struct ResolvedField {
        uint32_t fieldNumber;
        uint32_t structOffset;
        uint32_t fnPos;
        bool isVarint;
    };
    std::vector<ResolvedField> resolved;
    std::map<uint32_t, bool> usedFieldNums;

    // Also track used offsets to prevent same offset → multiple fields
    std::set<uint32_t> usedOffsets;

    // Handle BA/B9/41 B8 field numbers (string/message fields)
    for (auto& fn : fieldNums) {
        if (usedFieldNums.count(fn.fieldNumber)) continue;
        uint32_t bestDist = UINT32_MAX;
        uint32_t bestOffset = 0;
        for (auto& sa : structAccs) {
            if (sa.pos >= fn.pos) continue;
            if (usedOffsets.count(sa.offset)) continue; // offset already claimed
            uint32_t dist = fn.pos - sa.pos;
            if (dist < bestDist && dist < 200) {
                bestDist = dist;
                bestOffset = sa.offset;
            }
        }
        if (bestOffset > 0) {
            resolved.push_back({fn.fieldNumber, bestOffset, fn.pos, false});
            usedFieldNums[fn.fieldNumber] = true;
            usedOffsets.insert(bestOffset);
        }
    }

    // Handle wire tags (varint fields)
    for (auto& wt : wireTags) {
        uint32_t fn = wt.tag >> 3;
        if (usedFieldNums.count(fn)) continue;
        uint32_t bestDist = UINT32_MAX;
        uint32_t bestOffset = 0;
        for (auto& sa : structAccs) {
            if (sa.pos >= wt.pos) continue;
            if (usedOffsets.count(sa.offset)) continue;
            uint32_t dist = wt.pos - sa.pos;
            if (dist < bestDist && dist < 200) {
                bestDist = dist;
                bestOffset = sa.offset;
            }
        }
        if (bestOffset > 0) {
            resolved.push_back({fn, bestOffset, wt.pos, true});
            usedFieldNums[fn] = true;
            usedOffsets.insert(bestOffset);
        }
    }

    // Phase 3: Match descriptor strings to resolved fields by proximity
    // The descriptor LEA appears within the same code block as the field number literal.
    // Match each descriptor to the nearest field number literal (not struct access).
    std::set<uint32_t> assignedFieldNums;
    for (auto& f : msg.fields) {
        uint32_t descPos = UINT32_MAX;
        for (auto& dr : descRefs)
            if (dr.descStringRVA == f.stringRVA) { descPos = dr.pos; break; }
        if (descPos == UINT32_MAX) continue;

        // Find the nearest field number literal within 40 bytes of the descriptor
        uint32_t bestDist = UINT32_MAX;
        const ResolvedField* bestRF = nullptr;
        for (auto& rf : resolved) {
            if (assignedFieldNums.count(rf.fieldNumber)) continue;
            uint32_t dist = (descPos > rf.fnPos) ? descPos - rf.fnPos : rf.fnPos - descPos;
            if (dist < bestDist && dist < 40) {
                bestDist = dist;
                bestRF = &rf;
            }
        }
        if (bestRF) {
            f.fieldNumber = bestRF->fieldNumber;
            f.structOffset = bestRF->structOffset;
            f.wireType = bestRF->isVarint ? 0 : 2;
            assignedFieldNums.insert(bestRF->fieldNumber);
        }
    }

    // Remove unresolved named fields (fieldNumber still 0)
    msg.fields.erase(
        std::remove_if(msg.fields.begin(), msg.fields.end(),
            [](const ProtoField& f) { return f.fieldNumber == 0 && f.structOffset == 0; }),
        msg.fields.end());

    // Add resolved fields without descriptor strings as unnamed entries
    for (auto& rf : resolved) {
        bool found = false;
        for (auto& f : msg.fields)
            if (f.fieldNumber == rf.fieldNumber) { found = true; break; }
        if (!found) {
            ProtoField f = {};
            f.fieldNumber = rf.fieldNumber;
            f.structOffset = rf.structOffset;
            f.wireType = rf.isVarint ? 0 : 2;
            f.type = rf.isVarint ? ProtoField::INT32 : ProtoField::STRING;
            char nameBuf[64];
            sprintf_s(nameBuf, "field_%u_%s", rf.fieldNumber, rf.isVarint ? "int" : "ld");
            f.name = nameBuf;
            msg.fields.push_back(f);
        }
    }

    std::sort(msg.fields.begin(), msg.fields.end(),
        [](const ProtoField& a, const ProtoField& b) { return a.fieldNumber < b.fieldNumber; });

    vgc::log::raw("    Extracted %zu fields from serialize:\n", msg.fields.size());
    for (auto& f : msg.fields) {
        const char* typeName = "?";
        if (f.wireType == 0) typeName = "varint";
        else if (f.wireType == 2) {
            if (f.type == ProtoField::MESSAGE) typeName = "message";
            else typeName = "string";
        }
        vgc::log::raw("      field %2u: +0x%02X  %-10s  %s\n",
               f.fieldNumber, f.structOffset, typeName, f.name.c_str());
    }
}

static bool isCodePointer(const PEFile& pe, uint64_t imageBase, uint64_t val) {
    if (val < imageBase) return false;
    uint32_t rva = (uint32_t)(val - imageBase);
    int sec = pe.findSection(rva);
    if (sec < 0) return false;
    return (pe.sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

void resolveVtable(const PEFile& pe, uint64_t imageBase, ProtoMessage& msg) {
    if (!msg.serializeRVA) return;

    uint64_t serializeVA = imageBase + msg.serializeRVA;
    auto ptrLocs = findPointerTo(pe, serializeVA);

    if (ptrLocs.empty()) {
        vgc::log::raw("    Vtable: not found (no pointer to serialize)\n");
        return;
    }

    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    for (auto ptrRVA : ptrLocs) {
        uint32_t ptrOff = pe.rvaToOffset(ptrRVA);
        if (!ptrOff) continue;

        // Walk backward: entries must be CODE pointers (in executable sections)
        // This prevents including RTTI COL pointer (data) as a vtable entry
        uint32_t vtStart = ptrRVA;
        for (int back = 1; back <= 32; back++) {
            if (ptrRVA < (uint32_t)(back * 8)) break;
            uint32_t candRVA = ptrRVA - back * 8;
            uint32_t candOff = pe.rvaToOffset(candRVA);
            if (!candOff || candOff + 8 > pe.data.size()) break;
            uint64_t val = *(uint64_t*)(pe.data.data() + candOff);
            if (isCodePointer(pe, imageBase, val))
                vtStart = candRVA;
            else
                break;
        }

        // Walk forward to determine vtable end
        uint32_t vtEnd = ptrRVA + 8;
        for (int fwd = 1; fwd <= 32; fwd++) {
            uint32_t candRVA = ptrRVA + fwd * 8;
            uint32_t candOff = pe.rvaToOffset(candRVA);
            if (!candOff || candOff + 8 > pe.data.size()) break;
            uint64_t val = *(uint64_t*)(pe.data.data() + candOff);
            if (isCodePointer(pe, imageBase, val))
                vtEnd = candRVA + 8;
            else
                break;
        }

        msg.vtableRVA = vtStart;
        uint32_t numEntries = (vtEnd - vtStart) / 8;
        uint32_t serializeIdx = (ptrRVA - vtStart) / 8;
        vgc::log::raw("    Vtable at RVA 0x%X (%u entries, serialize = vtable[%u])\n",
               vtStart, numEntries, serializeIdx);

        // Read vtable entries into msg for downstream use
        uint32_t vtOff = pe.rvaToOffset(vtStart);
        if (!vtOff) continue;

        for (uint32_t i = 0; i < numEntries && i <= 20; i++) {
            uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i * 8);
            uint32_t entryRVA = (uint32_t)(entry - imageBase);
            vgc::log::raw("      vtable[%2u] = 0x%X\n", i, entryRVA);
        }

        break;
    }
}

// Extracts field_number -> struct_offset mapping from the Parse
// function's switch-case structure (protobuf codegen pattern).
void parseFromParseFunc(const PEFile& pe, uint64_t imageBase, ProtoMessage& msg) {
    if (!msg.vtableRVA) return;

    // Locate Parse function: large function near serialize in vtable
    // Pattern: Parse has >100 instructions, contains "shr eax, 3" + switch
    uint32_t vtOff = pe.rvaToOffset(msg.vtableRVA);
    if (!vtOff) return;
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    // Find serialize entry position in vtable
    uint32_t serializeIdx = UINT32_MAX;
    for (uint32_t i = 0; i < 64; i++) {
        if (vtOff + (i + 1) * 8 > pe.data.size()) break;
        uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i * 8);
        if (entry < imageBase || entry >= imageBase + soi) break;
        if ((uint32_t)(entry - imageBase) == msg.serializeRVA) {
            serializeIdx = i;
            break;
        }
    }
    if (serializeIdx == UINT32_MAX) {
        vgc::log::raw("    Parse function: serialize not found in vtable\n");
        return;
    }

    // Parse function search: scan entries near serialize (offset -4 to +4)
    // In protobuf MSVC, Parse is typically 2 entries before Serialize
    uint32_t parseRVA = 0;
    for (int delta = -4; delta <= 4; delta++) {
        if (delta == 0) continue;
        int idx = (int)serializeIdx + delta;
        if (idx < 0 || vtOff + (idx + 1) * 8 > pe.data.size()) continue;
        uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + idx * 8);
        if (!isCodePointer(pe, imageBase, entry)) continue;
        uint32_t rva = (uint32_t)(entry - imageBase);
        if (rva == msg.serializeRVA) continue;
        uint32_t off = pe.rvaToOffset(rva);
        if (!off || off + 100 > pe.data.size()) continue;

        // Check for Parse signature: large frame (sub rsp, >= 0x100) + "shr eax, 3"
        const uint8_t* code = pe.data.data() + off;
        bool hasShrEax3 = false;
        bool hasLargeFrame = false;
        uint32_t scanMax = std::min((uint32_t)250, (uint32_t)(pe.data.size() - off));
        for (uint32_t p = 0; p + 3 < scanMax; p++) {
            if (code[p] == 0xC1 && code[p+1] == 0xE8 && code[p+2] == 0x03)
                hasShrEax3 = true;
            if (code[p] == 0x48 && code[p+1] == 0x81 && code[p+2] == 0xEC)
                hasLargeFrame = true;
        }
        if (hasShrEax3 && hasLargeFrame) {
            parseRVA = rva;
            vgc::log::raw("    Parse function: vtable[serialize%+d] = RVA 0x%X\n", delta, rva);
            break;
        }
    }

    if (!parseRVA) {
        vgc::log::raw("    Parse function: not found in vtable\n");
        return;
    }

    vgc::log::raw("    Parse function: RVA 0x%X\n", parseRVA);

    // Analyze the Parse function's switch-case structure
    // Look for patterns:
    //   case N: cmp sil/esi, TAG  (TAG = field_num * 8 + wire_type)
    //           lea rcx, [r15 + disp32]  (struct offset for string/message fields)
    //           mov [r15 + disp32], eax  (struct offset for varint fields)

    uint32_t parseOff = pe.rvaToOffset(parseRVA);
    if (!parseOff) return;
    int parseSec = pe.findSection(parseRVA);
    if (parseSec < 0) return;

    uint32_t secRawOff = pe.sections[parseSec].PointerToRawData;
    uint32_t secRawSz = pe.sections[parseSec].SizeOfRawData;
    uint32_t funcRelOff = parseOff - secRawOff;
    uint32_t scanLen = std::min((uint32_t)0x1000, secRawSz - funcRelOff);
    const uint8_t* code = pe.data.data() + parseOff;

    struct ParseCase {
        uint8_t tag;         // wire tag byte (field_num * 8 + wire_type)
        uint32_t offset;     // struct offset found
        uint32_t pos;        // position in function
    };
    std::vector<ParseCase> cases;

    // Find "cmp sil/esi, IMM8" patterns followed by "lea rcx, [rXX + disp32]"
    for (uint32_t p = 0; p + 12 < scanLen; p++) {
        // Pattern: 40 80 FE XX = cmp sil, imm8
        //      or: 81 FE XX 00 00 00 = cmp esi, imm32 (rare)
        //      or: 83 FE XX = cmp esi, imm8 (3-byte form)
        uint8_t tag = 0;
        uint32_t tagPos = p;
        if (code[p] == 0x40 && code[p+1] == 0x80 && code[p+2] == 0xFE) {
            tag = code[p+3]; tagPos = p;
        } else if (code[p] == 0x80 && code[p+1] == 0xFE) {
            tag = code[p+2]; tagPos = p;
        } else if (code[p] == 0x83 && code[p+1] == 0xFE) {
            tag = code[p+2]; tagPos = p;
        } else {
            continue;
        }

        uint8_t wireType = tag & 7;
        uint8_t fieldNum = tag >> 3;
        if (fieldNum < 1 || fieldNum > 30) continue;
        if (wireType != 0 && wireType != 2) continue; // varint or length-delimited

        // Scan forward for struct offset access within 60 bytes
        for (uint32_t q = tagPos + 3; q + 7 < scanLen && q < tagPos + 60; q++) {
            // LEA rcx, [rXX + disp32]: 4X 8D 8X/89/8B/... disp32
            // Common: 49 8D 8F [disp32] = lea rcx, [r15 + disp32]
            //         48 8D 8B [disp32] = lea rcx, [rbx + disp32]
            //         48 8D 8F [disp32] = lea rcx, [rdi + disp32]
            if ((code[q] == 0x49 || code[q] == 0x48 || code[q] == 0x4C) && code[q+1] == 0x8D) {
                uint8_t modrm = code[q+2];
                uint8_t mod = modrm >> 6;
                uint8_t rm = modrm & 7;
                uint8_t reg = (modrm >> 3) & 7;
                if (mod == 2 && rm != 4 && reg == 1) { // reg=1 = rcx, disp32
                    uint32_t disp = *(uint32_t*)(code + q + 3);
                    if (disp > 0x08 && disp < 0x200) {
                        cases.push_back({tag, disp, tagPos});
                        break;
                    }
                }
            }
            // MOV [rXX + disp32], eax: 41/49 89 87/85/... [disp32]
            // For varint: mov [r15 + disp32], eax = 41 89 87 [disp32]
            if (wireType == 0) {
                if ((code[q] == 0x41 || code[q] == 0x44) && code[q+1] == 0x89) {
                    uint8_t modrm = code[q+2];
                    uint8_t mod = modrm >> 6;
                    uint8_t rm = modrm & 7;
                    if (mod == 2 && rm != 4) {
                        uint32_t disp = *(uint32_t*)(code + q + 3);
                        if (disp > 0x08 && disp < 0x200) {
                            cases.push_back({tag, disp, tagPos});
                            break;
                        }
                    }
                }
            }
        }
    }

    if (cases.empty()) {
        vgc::log::raw("    Parse analysis: no field cases found\n");
        return;
    }

    // Merge results into msg.fields
    vgc::log::raw("    Parse analysis: %zu field cases extracted\n", cases.size());
    std::map<uint32_t, uint32_t> fieldToOffset; // field_num → struct_offset

    for (auto& c : cases) {
        uint8_t fieldNum = c.tag >> 3;
        uint8_t wireType = c.tag & 7;
        fieldToOffset[fieldNum] = c.offset;

        // Update existing field or add new one
        bool found = false;
        for (auto& f : msg.fields) {
            if (f.fieldNumber == fieldNum) {
                f.structOffset = c.offset;
                if (wireType == 0) f.type = ProtoField::INT32;
                else if (wireType == 2 && f.type == ProtoField::UNKNOWN) f.type = ProtoField::STRING;
                found = true;
                break;
            }
        }
        if (!found) {
            ProtoField f = {};
            f.fieldNumber = fieldNum;
            f.structOffset = c.offset;
            f.wireType = wireType;
            f.type = (wireType == 0) ? ProtoField::INT32 : ProtoField::STRING;
            char nameBuf[32];
            sprintf_s(nameBuf, "field_%u", fieldNum);
            f.name = nameBuf;
            msg.fields.push_back(f);
        }
    }

    std::sort(msg.fields.begin(), msg.fields.end(),
        [](const ProtoField& a, const ProtoField& b) { return a.fieldNumber < b.fieldNumber; });

    vgc::log::raw("    Parse-derived field map:\n");
    for (auto& f : msg.fields) {
        if (f.structOffset > 0)
            vgc::log::raw("      field %2u: +0x%02X  %s\n", f.fieldNumber, f.structOffset, f.name.c_str());
    }
}

// Pattern-based schema extractor for table-driven protobuf-lite builds, where
// the per-message _Serialize/ByteSizeLong/Clear are thunks and the real work
// lives in _InternalParse (a tag dispatch table that calls into shared helpers).

// Locate EpsCopyInputStream::DoneFallback by its prologue byte signature. Every
// _InternalParse calls into it once on buffer underflow, so its callers are the
// parser set with zero false positives. Returns 0 if the helper isn't found
// (different protobuf version or stripped); callers then fall back to ranking.
static uint32_t findBoundaryHelper(const PEFile& pe) {
    static const uint8_t kSig[] = {
        0x40, 0x53,       // push rbx (with REX prefix)
        0x55,             // push rbp
        0x56,             // push rsi
        0x41, 0x56,       // push r14
        0x41, 0x57,       // push r15
        0x48, 0x83, 0xEC, 0x40,  // sub rsp, 40h
    };
    for (int si = 0; si < pe.numSections; si++) {
        if (!(pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t raw = pe.sections[si].PointerToRawData;
        uint32_t sz = pe.sections[si].SizeOfRawData;
        for (uint32_t p = 0; p + sizeof(kSig) <= sz; p++) {
            if (memcmp(pe.data.data() + raw + p, kSig, sizeof(kSig)) == 0)
                return pe.sections[si].VirtualAddress + p;
        }
    }
    return 0;
}

// Check whether a function body calls `targetRVA` via direct `call rel32`.
static bool funcCallsTarget(const PEFile& pe, uint32_t funcRVA, uint32_t size, uint32_t targetRVA) {
    uint32_t off = pe.rvaToOffset(funcRVA);
    if (!off) return false;
    uint32_t scan = std::min(size, (uint32_t)0x4000);
    const uint8_t* code = pe.data.data() + off;
    for (uint32_t p = 0; p + 5 <= scan; p++) {
        if (code[p] != 0xE8) continue;
        int32_t disp = *(int32_t*)(code + p + 1);
        uint32_t tgt = funcRVA + p + 5 + disp;
        if (tgt == targetRVA) return true;
    }
    return false;
}

struct PdataTable {
    std::vector<std::pair<uint32_t, uint32_t>> entries;  // (begin, end) sorted by begin
    bool ready = false;
};
static PdataTable& pdataTable(const PEFile& pe) {
    static thread_local PdataTable t;
    if (t.ready) return t;
    for (int si = 0; si < pe.numSections; si++) {
        char nm[9] = {}; memcpy(nm, pe.sections[si].Name, 8);
        if (strcmp(nm, ".pdata") != 0) continue;
        uint32_t raw = pe.sections[si].PointerToRawData;
        uint32_t sz  = pe.sections[si].SizeOfRawData;
        uint32_t count = sz / 12;
        t.entries.reserve(count);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t b = *(uint32_t*)(pe.data.data() + raw + i*12);
            uint32_t e = *(uint32_t*)(pe.data.data() + raw + i*12 + 4);
            if (b && e > b) t.entries.push_back({b, e});
        }
        break;
    }
    std::sort(t.entries.begin(), t.entries.end());
    t.ready = true;
    return t;
}

// CC-pad scan was wrong on contiguous parser+Clear pairs (no padding between).
// .pdata gives the true bounds; only fall back when the function isn't listed.
static uint32_t estimateFuncSize(const PEFile& pe, uint32_t funcRVA, uint32_t maxScan = 0x2000) {
    auto& tbl = pdataTable(pe);
    auto it = std::lower_bound(tbl.entries.begin(), tbl.entries.end(),
                                std::make_pair(funcRVA, (uint32_t)0));
    if (it != tbl.entries.end() && it->first == funcRVA) return it->second - it->first;
    uint32_t off = pe.rvaToOffset(funcRVA);
    if (!off) return 0;
    uint32_t scan = std::min(maxScan, (uint32_t)(pe.data.size() - off));
    for (uint32_t p = 16; p + 1 < scan; p++) {
        if (pe.data[off+p] == 0xCC && pe.data[off+p+1] == 0xCC) return p;
    }
    return scan;
}

// `cmp <reg>, imm` with small immediate (tag byte fits in 8 bits). Covers
// 80/81/83 /7 (with REX), 3C (AL), 3D (EAX). Returns instruction length
// or 0 if not matched.
static int matchCmpRegImm(const uint8_t* p, uint32_t avail, uint8_t* outImm) {
    if (avail < 2) return 0;
    int idx = 0;
    if (p[idx] >= 0x40 && p[idx] <= 0x4F) {
        idx++;
        if (avail < (uint32_t)(idx + 2)) return 0;
    }
    uint8_t op = p[idx];

    if (op == 0x3C) {
        if (avail < (uint32_t)(idx + 2)) return 0;
        *outImm = p[idx + 1];
        return idx + 2;
    }
    if (op == 0x3D) {
        if (avail < (uint32_t)(idx + 5)) return 0;
        uint32_t v = *(uint32_t*)(p + idx + 1);
        if (v > 0xFF) return 0;
        *outImm = (uint8_t)v;
        return idx + 5;
    }

    if (op != 0x80 && op != 0x81 && op != 0x83) return 0;
    if (avail < (uint32_t)(idx + 3)) return 0;
    uint8_t modrm = p[idx + 1];
    if (((modrm >> 3) & 7) != 7) return 0;
    if ((modrm >> 6) != 3) return 0;

    if (op == 0x80 || op == 0x83) {
        *outImm = p[idx + 2];
        return idx + 3;
    }
    if (avail < (uint32_t)(idx + 6)) return 0;
    uint32_t v32 = *(uint32_t*)(p + idx + 2);
    if (v32 > 0xFF) return 0;
    *outImm = (uint8_t)v32;
    return idx + 6;
}

// Count distinct field numbers that appear as tag-cmp targets. Used to pick
// the parser among vtable entries when several pass the boundary-call filter.
static uint32_t countTagCases(const PEFile& pe, uint32_t funcRVA, uint32_t size) {
    uint32_t off = pe.rvaToOffset(funcRVA);
    if (!off) return 0;
    const uint8_t* code = pe.data.data() + off;
    uint32_t scan = std::min(size, (uint32_t)0x4000);
    std::set<uint8_t> uniqueFieldNums;
    uint32_t p = 0;
    while (p + 3 < scan) {
        uint8_t imm = 0;
        int len = matchCmpRegImm(code + p, scan - p, &imm);
        if (len == 0) { p++; continue; }
        uint8_t fn = imm >> 3;
        uint8_t wt = imm & 7;
        if (fn >= 1 && fn <= 30 && wt <= 5) uniqueFieldNums.insert(fn);
        p += len;
    }
    return (uint32_t)uniqueFieldNums.size();
}

// Identification is two-tier: (1) keep vtable entries that call the boundary
// helper, (2) pick the one with the most distinct tag cmps. Without the helper
// (different protobuf version), step 1 is skipped and ranking does all the work.
static uint32_t findInternalParseFunc(const PEFile& pe, uint64_t imageBase, uint32_t vtableRVA) {
    static thread_local uint32_t cachedHelper = UINT32_MAX;
    if (cachedHelper == UINT32_MAX)
        cachedHelper = findBoundaryHelper(pe);
    uint32_t helper = cachedHelper;

    uint32_t vtOff = pe.rvaToOffset(vtableRVA);
    if (!vtOff) return 0;
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    struct Cand { uint32_t rva; uint32_t size; uint32_t cases; };
    std::vector<Cand> cands;
    for (uint32_t i = 0; i < 64 && vtOff + (i+1)*8 <= pe.data.size(); i++) {
        uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i*8);
        if (entry < imageBase || entry >= imageBase + soi) {
            if (i > 0) break;
            continue;
        }
        uint32_t rva = (uint32_t)(entry - imageBase);
        int sec = pe.findSection(rva);
        if (sec < 0 || !(pe.sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            if (i > 0) break;
            continue;
        }
        uint32_t size = estimateFuncSize(pe, rva);
        if (size < 100) continue;
        if (helper && !funcCallsTarget(pe, rva, size, helper)) continue;
        uint32_t cases = countTagCases(pe, rva, size);
        if (cases < 1) continue;
        cands.push_back({rva, size, cases});
    }
    if (cands.empty()) return 0;
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b){
        if (a.cases != b.cases) return a.cases > b.cases;
        return a.size > b.size;
    });
    return cands.front().rva;
}

// REX.W `lea r64, [base + disp32]` (no SIB).
static int matchLeaRegDisp32(const uint8_t* p, uint32_t avail, int32_t* outDisp) {
    if (avail < 7) return 0;
    if ((p[0] & 0xF8) != 0x48) return 0;
    if (p[1] != 0x8D) return 0;
    uint8_t modrm = p[2];
    if ((modrm >> 6) != 2) return 0;
    if ((modrm & 7) == 4) return 0;
    *outDisp = *(int32_t*)(p + 3);
    return 7;
}

// `mov [base + disp32], r32` (varint stores).
static int matchMovMemDisp32Reg(const uint8_t* p, uint32_t avail, int32_t* outDisp) {
    if (avail < 7) return 0;
    int idx = 0;
    if (p[idx] >= 0x40 && p[idx] <= 0x4F) { idx++; if (avail < (uint32_t)(idx + 7)) return 0; }
    if (p[idx] != 0x89) return 0;
    uint8_t modrm = p[idx + 1];
    if ((modrm >> 6) != 2) return 0;
    if ((modrm & 7) == 4) return 0;
    *outDisp = *(int32_t*)(p + idx + 2);
    return idx + 6;
}

static int matchCallRel32(const uint8_t* p, uint32_t avail, uint32_t instrRVA, uint32_t* outTgtRVA) {
    if (avail < 5) return 0;
    if (p[0] != 0xE8) return 0;
    int32_t disp = *(int32_t*)(p + 1);
    *outTgtRVA = instrRVA + 5 + disp;
    return 5;
}

void parseFromInternalParseFunc(const PEFile& pe, uint64_t imageBase, ProtoMessage& msg) {
    if (!msg.vtableRVA) return;
    uint32_t parseRVA = findInternalParseFunc(pe, imageBase, msg.vtableRVA);
    if (!parseRVA) {
        vgc::log::raw("    [parseInternalParse] no parser found in vtable 0x%X\n", msg.vtableRVA);
        return;
    }
    uint32_t size = estimateFuncSize(pe, parseRVA);
    uint32_t off = pe.rvaToOffset(parseRVA);
    if (!off) return;
    vgc::log::raw("    [parseInternalParse] %s parser @ RVA 0x%X (size %u)\n",
           msg.fullName.c_str(), parseRVA, size);

    struct CaseHit {
        uint32_t pos;
        uint8_t  tagByte;        // (field<<3) | wire_type
        int32_t  fieldOffset;    // -1 if not found
        uint32_t helperRVA;      // 0 if not found
    };
    std::vector<CaseHit> hits;

    const uint8_t* code = pe.data.data() + off;
    uint32_t scan = std::min(size, (uint32_t)0x4000);
    uint32_t p = 0;
    while (p + 3 < scan) {
        uint8_t imm = 0;
        int cmpLen = matchCmpRegImm(code + p, scan - p, &imm);
        if (cmpLen == 0) { p++; continue; }

        uint8_t fieldNum = imm >> 3;
        uint8_t wireType = imm & 7;
        if (fieldNum < 1 || fieldNum > 30) { p += cmpLen; continue; }
        if (wireType > 5) { p += cmpLen; continue; }

        CaseHit hit{};
        hit.pos = p;
        hit.tagByte = imm;
        hit.fieldOffset = -1;

        uint32_t q = p + cmpLen;
        uint32_t limit = std::min(scan, q + 160);
        while (q < limit) {
            int32_t disp = 0;
            int leaLen = matchLeaRegDisp32(code + q, limit - q, &disp);
            if (leaLen > 0 && disp > 0 && disp < 0x400 && hit.fieldOffset < 0) {
                hit.fieldOffset = disp;
                q += leaLen;
                continue;
            }
            int movLen = matchMovMemDisp32Reg(code + q, limit - q, &disp);
            if (movLen > 0 && disp > 0 && disp < 0x400 && hit.fieldOffset < 0) {
                hit.fieldOffset = disp;
                q += movLen;
                continue;
            }
            uint32_t tgt = 0;
            int callLen = matchCallRel32(code + q, limit - q, parseRVA + q, &tgt);
            if (callLen > 0 && hit.helperRVA == 0) {
                hit.helperRVA = tgt;
            }
            q++;
        }
        if (hit.fieldOffset >= 0 || hit.helperRVA != 0) hits.push_back(hit);
        p += cmpLen;
    }

    std::map<uint8_t, CaseHit> byField;
    for (auto& h : hits) {
        uint8_t fn = h.tagByte >> 3;
        if (!byField.count(fn)) byField[fn] = h;
    }
    if (byField.empty()) {
        vgc::log::raw("    [parseInternalParse] no field cases extracted\n");
        return;
    }

    for (auto& [fn, h] : byField) {
        uint8_t wireType = h.tagByte & 7;
        ProtoField* existing = nullptr;
        for (auto& f : msg.fields) {
            if (f.fieldNumber == fn) { existing = &f; break; }
        }
        if (existing) {
            if (existing->structOffset == 0 && h.fieldOffset > 0)
                existing->structOffset = (uint32_t)h.fieldOffset;
            existing->wireType = wireType;
            if (existing->type == ProtoField::UNKNOWN) {
                if (wireType == 0) existing->type = ProtoField::INT32;
                else if (wireType == 2) existing->type = ProtoField::STRING;
            }
        } else {
            ProtoField nf{};
            nf.fieldNumber = fn;
            nf.structOffset = (h.fieldOffset > 0) ? (uint32_t)h.fieldOffset : 0;
            nf.wireType = wireType;
            if (wireType == 0) nf.type = ProtoField::INT32;
            else if (wireType == 2) nf.type = ProtoField::STRING;
            else nf.type = ProtoField::UNKNOWN;
            char buf[32]; sprintf_s(buf, "field_%u", fn);
            nf.name = buf;
            msg.fields.push_back(nf);
        }
    }
    std::sort(msg.fields.begin(), msg.fields.end(),
              [](const ProtoField& a, const ProtoField& b){ return a.fieldNumber < b.fieldNumber; });

    vgc::log::raw("    [parseInternalParse] %zu fields:\n", byField.size());
    for (auto& [fn, h] : byField) {
        vgc::log::raw("      field %2u: tag=0x%02X wire=%u offset=%s helper=0x%X\n",
               fn, h.tagByte, h.tagByte & 7,
               (h.fieldOffset >= 0) ? ("+0x" + std::to_string((uint64_t)h.fieldOffset)).c_str() : "?",
               h.helperRVA);
    }
}

ProtoMessage scanProtoMessage(const PEFile& pe, uint64_t imageBase,
                              const char* messageName) {
    ProtoMessage msg = {};
    msg.fullName = messageName;
    std::string prefix = std::string(messageName) + ".";

    vgc::log::raw("  [proto_scan] Searching for \"%s\"...\n", messageName);

    // Find descriptor strings "messageName.fieldName"
    for (int si = 0; si < pe.numSections; si++) {
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t secRVA = pe.sections[si].VirtualAddress;

        for (uint32_t p = 0; p + prefix.size() + 2 < rawSz; p++) {
            const char* s = (const char*)(pe.data.data() + rawOff + p);
            if (memcmp(s, prefix.c_str(), prefix.size()) != 0) continue;
            size_t slen = strnlen(s, rawSz - p);
            if (slen >= rawSz - p) continue;

            ProtoField field = {};
            field.fullName = std::string(s, slen);
            field.name = field.fullName.substr(prefix.size());
            field.stringRVA = secRVA + p;
            msg.fields.push_back(field);
            p += (uint32_t)slen;
        }
    }

    // Filter out sub-message descriptors (contain '.' after prefix, e.g. "FlagsEntry.key")
    std::vector<ProtoField> directFields;
    std::vector<ProtoField> subMsgFields;
    for (auto& f : msg.fields) {
        if (f.name.find('.') != std::string::npos)
            subMsgFields.push_back(f);
        else
            directFields.push_back(f);
    }
    msg.fields = directFields;

    vgc::log::raw("    Found %zu direct fields, %zu sub-message fields\n",
           directFields.size(), subMsgFields.size());
    for (auto& f : msg.fields)
        vgc::log::raw("      \"%s\" at RVA 0x%X\n", f.name.c_str(), f.stringRVA);

    if (msg.fields.empty()) return msg;

    // Find serialize function via LEA xref to any descriptor string
    for (auto& f : msg.fields) {
        auto leaRefs = findLeaRipRefs(pe, f.stringRVA);
        if (!leaRefs.empty()) {
            msg.serializeRVA = findContainingFunc(pe, leaRefs[0]);
            vgc::log::raw("    Serialize: RVA 0x%X (via \"%s\" LEA at 0x%X)\n",
                   msg.serializeRVA, f.name.c_str(), leaRefs[0]);
            break;
        }
    }
    if (!msg.serializeRVA) {
        vgc::log::raw("    [!] No LEA xrefs to any descriptor string\n");
        return msg;
    }

    // Parse serialize for field number / struct offset mapping
    if (msg.serializeRVA)
        parseSerializeOffsets(pe, imageBase, msg.serializeRVA, msg);

    // Resolve vtable
    resolveVtable(pe, imageBase, msg);

    // Pattern-based _InternalParse extractor (table-driven build). Runs in addition
    // to legacy Serialize/Parse extractors; merges results into msg.fields.
    if (msg.vtableRVA)
        parseFromInternalParseFunc(pe, imageBase, msg);

    return msg;
}

ProtoScanResult scanAllProtoMessages(const PEFile& pe, uint64_t imageBase) {
    ProtoScanResult result = {};

    // Find ALL protobuf descriptor strings
    // Pattern: "package.MessageName.field_name\0"
    // Protobuf descriptors have format: dots-separated fully qualified name
    // We detect them by: printable chars + at least 2 dots + null terminator
    struct RawDesc {
        std::string fullName;  // e.g. "vanguard.AuthenticationRequest.machine_id"
        uint32_t rva;
    };
    std::vector<RawDesc> allDescs;

    for (int si = 0; si < pe.numSections; si++) {
        if (pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t secRVA = pe.sections[si].VirtualAddress;

        for (uint32_t p = 0; p + 10 < rawSz; p++) {
            const char* s = (const char*)(pe.data.data() + rawOff + p);
            if (!islower((unsigned char)s[0]) && !isupper((unsigned char)s[0])) continue;

            size_t slen = strnlen(s, std::min(rawSz - p, (uint32_t)256));
            if (slen < 5 || slen >= 256) continue;

            int dots = 0;
            bool valid = true;
            for (size_t i = 0; i < slen; i++) {
                char c = s[i];
                if (c == '.') { dots++; continue; }
                if (isalnum((unsigned char)c) || c == '_') continue;
                valid = false; break;
            }
            if (!valid || dots < 2) continue;

            // Must have at least "package.Message.field" structure
            std::string str(s, slen);
            size_t firstDot = str.find('.');
            size_t lastDot = str.rfind('.');
            if (firstDot == lastDot) continue;

            allDescs.push_back({str, secRVA + p});
            p += (uint32_t)slen;
        }
    }

    // Group by message name (everything before the last dot)
    std::map<std::string, std::vector<RawDesc>> byMessage;
    for (auto& d : allDescs) {
        size_t lastDot = d.fullName.rfind('.');
        std::string msgName = d.fullName.substr(0, lastDot);
        byMessage[msgName].push_back(d);
    }

    vgc::log::raw("  [proto_scan] Found %zu descriptor strings → %zu message types\n",
           allDescs.size(), byMessage.size());

    // For each message, run full analysis
    for (auto& [msgName, descs] : byMessage) {
        // Skip sub-messages (contain '.' in message name after package)
        // e.g. "vanguard.AuthenticationRequest.FlagsEntry" is a sub-message
        size_t firstDot = msgName.find('.');
        std::string afterPackage = (firstDot != std::string::npos) ? msgName.substr(firstDot + 1) : msgName;
        if (afterPackage.find('.') != std::string::npos) continue;

        auto msg = scanProtoMessage(pe, imageBase, msgName.c_str());
        if (msg.serializeRVA || !msg.fields.empty()) {
            for (auto& f : msg.fields) {
                result.totalFields++;
                if (f.structOffset > 0) result.resolvedFields++;
            }
            result.messages.push_back(std::move(msg));
        }
    }

    vgc::log::raw("  [proto_scan] Summary: %zu messages, %u/%u fields resolved\n",
           result.messages.size(), result.resolvedFields, result.totalFields);

    return result;
}

FieldSetterTrace traceFieldSetters(const PEFile& pe, uint64_t imageBase,
                                   const ProtoMessage& msg, uint32_t targetFieldOffset,
                                   uint32_t setterFuncRVA) {
    FieldSetterTrace trace = {};
    trace.targetOffset = targetFieldOffset;
    trace.setterFuncRVA = setterFuncRVA;

    // Collect all known field offsets from the message (for sibling detection)
    std::set<uint32_t> knownOffsets;
    for (auto& f : msg.fields)
        if (f.structOffset > 0) knownOffsets.insert(f.structOffset);

    vgc::log::raw("  [field_trace] Target: +0x%X, setter=0x%X, %zu known sibling offsets\n",
           targetFieldOffset, setterFuncRVA, knownOffsets.size());

    // Phase 1: Find ALL "reg + offset" computations in .grfn1 for known offsets
    // Patterns:
    //   LEA reg, [reg + disp32]: REX.W(48/4C/49) 8D ModRM(mod=2,rm!=4) [disp32]
    //   ADD reg, imm32:         REX.W(48/4C/49) 81 C0-C7 [imm32]
    //   ADD reg, imm8:          REX.W(48/49) 83 C0-C7 [imm8]

    struct OffsetHit {
        uint32_t rva;
        uint32_t offset;
        uint8_t baseReg;   // register holding the base pointer
        uint8_t dstReg;    // register receiving the result
    };
    std::vector<OffsetHit> allHits;

    for (int si = 0; si < pe.numSections; si++) {
        char sname[9] = {};
        memcpy(sname, pe.sections[si].Name, 8);
        if (strcmp(sname, ".grfn1") != 0) continue;

        uint32_t secRVA = pe.sections[si].VirtualAddress;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        const uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t p = 0; p + 7 < rawSz; p++) {
            const uint8_t* b = code + p;

            // MOV/CMP/LEA with REX.W and disp32 accessing [reg + known_offset]
            // Captures: MOV reg,[reg+0x88], LEA reg,[reg+0x88], CMP [reg+0x88],reg
            // Opcodes: 8B(MOV load), 89(MOV store), 8D(LEA), 39/3B(CMP), 01/03(ADD mem)
            if ((b[0] & 0xF0) == 0x40 &&
                (b[1] == 0x8B || b[1] == 0x89 || b[1] == 0x3B || b[1] == 0x39 ||
                 b[1] == 0x03 || b[1] == 0x01)) {
                uint8_t modrm = b[2];
                uint8_t mod = modrm >> 6;
                uint8_t rm = modrm & 7;
                if (mod == 2 && rm != 4) { // disp32, no SIB
                    uint8_t rexB = (b[0] & 0x01) ? 8 : 0;
                    uint8_t baseReg = rm | rexB;
                    if (baseReg != 4 && baseReg != 5) {
                        uint32_t disp = *(uint32_t*)(b + 3);
                        if (knownOffsets.count(disp))
                            allHits.push_back({secRVA + p, disp, baseReg, 0xFF});
                    }
                }
            }

            // LEA with REX.W prefix and disp32 (mod=10, rm != 100)
            // Exclude RSP(4)/RBP(5) as base — those are stack-relative, not object fields
            if ((b[0] == 0x48 || b[0] == 0x4C || b[0] == 0x49 || b[0] == 0x4D) &&
                b[1] == 0x8D) {
                uint8_t modrm = b[2];
                uint8_t mod = modrm >> 6;
                uint8_t rm = modrm & 7;
                if (mod == 2 && rm != 4) { // disp32, no SIB
                    uint8_t rexB = (b[0] & 0x01) ? 8 : 0;
                    uint8_t baseReg = rm | rexB;
                    if (baseReg != 4 && baseReg != 5) { // skip RSP, RBP base
                        uint32_t disp = *(uint32_t*)(b + 3);
                        if (knownOffsets.count(disp)) {
                            uint8_t rexR = (b[0] & 0x04) ? 8 : 0;
                            uint8_t dstReg = ((modrm >> 3) & 7) | rexR;
                            allHits.push_back({secRVA + p, disp, baseReg, dstReg});
                        }
                    }
                }
            }

            // ADD reg, imm32: 48/49 81 C0-C7 [imm32]
            // Exclude RSP(4) and RBP(5) — those are stack/frame adjustments
            if ((b[0] == 0x48 || b[0] == 0x49) && b[1] == 0x81) {
                uint8_t modrm = b[2];
                if ((modrm & 0xF8) == 0xC0) { // /0 = ADD, reg direct
                    uint8_t rexB = (b[0] & 0x01) ? 8 : 0;
                    uint8_t reg = (modrm & 7) | rexB;
                    if (reg != 4 && reg != 5) { // skip RSP, RBP
                        uint32_t imm = *(uint32_t*)(b + 3);
                        if (knownOffsets.count(imm))
                            allHits.push_back({secRVA + p, imm, reg, reg});
                    }
                }
            }

            // ADD reg, imm8: 48/49 83 C0-C7 [imm8] (only for offsets < 0x80)
            if ((b[0] == 0x48 || b[0] == 0x49) && b[1] == 0x83) {
                uint8_t modrm = b[2];
                if ((modrm & 0xF8) == 0xC0) {
                    uint8_t rexB = (b[0] & 0x01) ? 8 : 0;
                    uint8_t reg = (modrm & 7) | rexB;
                    if (reg != 4 && reg != 5) {
                        uint32_t imm = b[3];
                        if (knownOffsets.count(imm))
                            allHits.push_back({secRVA + p, imm, reg, reg});
                    }
                }
            }
        }
    }

    vgc::log::raw("  [field_trace] Phase 1: %zu offset-computation hits in .grfn1\n", allHits.size());
    // Debug: show offset distribution
    std::map<uint32_t, int> offsetDist;
    for (auto& h : allHits) offsetDist[h.offset]++;
    for (auto& [off, cnt] : offsetDist)
        vgc::log::raw("    offset +0x%02X: %d hits\n", off, cnt);
    // Show first 5 hits with target offset
    int shown = 0;
    for (auto& h : allHits) {
        if (h.offset == targetFieldOffset && shown < 5) {
            vgc::log::raw("    [TARGET] RVA 0x%X base=r%u dst=r%u\n", h.rva, h.baseReg, h.dstReg);
            shown++;
        }
    }

    // Phase 2: Cluster hits by proximity (within 0x400 bytes = same function/dispatch block)
    // Sort by RVA for clustering
    std::sort(allHits.begin(), allHits.end(),
        [](const OffsetHit& a, const OffsetHit& b) { return a.rva < b.rva; });

    struct Cluster {
        uint32_t startRVA;
        uint32_t endRVA;
        std::vector<OffsetHit> hits;
        std::set<uint32_t> offsets;
    };
    std::vector<Cluster> clusters;

    for (size_t i = 0; i < allHits.size(); i++) {
        bool merged = false;
        for (auto& cl : clusters) {
            if (allHits[i].rva >= cl.startRVA && allHits[i].rva <= cl.endRVA + 0x400) {
                cl.endRVA = std::max(cl.endRVA, allHits[i].rva);
                cl.hits.push_back(allHits[i]);
                cl.offsets.insert(allHits[i].offset);
                merged = true;
                break;
            }
        }
        if (!merged) {
            Cluster cl = {};
            cl.startRVA = allHits[i].rva;
            cl.endRVA = allHits[i].rva;
            cl.hits.push_back(allHits[i]);
            cl.offsets.insert(allHits[i].offset);
            clusters.push_back(cl);
        }
    }

    vgc::log::raw("  [field_trace] Phase 2: %zu clusters\n", clusters.size());

    // Phase 3: Score clusters
    // Higher score = more likely to be the AuthReq manipulation site
    // Scoring: +1 per known sibling offset present, +3 if target offset present,
    //          +2 if setter function (text_132990) is called within range
    struct ScoredCluster {
        Cluster* cluster;
        int score;
        bool hasTarget;
        bool hasSetterCall;
    };
    std::vector<ScoredCluster> scored;

    for (auto& cl : clusters) {
        ScoredCluster sc = {};
        sc.cluster = &cl;
        sc.hasTarget = cl.offsets.count(targetFieldOffset) > 0;
        sc.score = (int)cl.offsets.size();
        if (sc.hasTarget) sc.score += 3;

        // Check for calls to setter function within cluster range + margin
        uint32_t scanStart = cl.startRVA > 0x100 ? cl.startRVA - 0x100 : 0;
        uint32_t scanEnd = cl.endRVA + 0x200;

        int sec = pe.findSection(cl.startRVA);
        if (sec >= 0) {
            uint32_t secRVA = pe.sections[sec].VirtualAddress;
            uint32_t rawOff = pe.sections[sec].PointerToRawData;
            uint32_t rawSz = pe.sections[sec].SizeOfRawData;
            uint32_t relStart = (scanStart > secRVA) ? scanStart - secRVA : 0;
            uint32_t relEnd = std::min(scanEnd - secRVA, rawSz - 5);

            for (uint32_t p = relStart; p < relEnd; p++) {
                uint8_t opcode = pe.data[rawOff + p];
                if (opcode != 0xE8) continue;
                int32_t disp = *(int32_t*)(pe.data.data() + rawOff + p + 1);
                uint32_t callTarget = secRVA + p + 5 + disp;
                if (callTarget == setterFuncRVA) {
                    sc.hasSetterCall = true;
                    sc.score += 5;
                    break;
                }
            }
        }

        // Only keep clusters with target offset AND at least 2 siblings
        if (sc.hasTarget && cl.offsets.size() >= 2)
            scored.push_back(sc);
    }

    std::sort(scored.begin(), scored.end(),
        [](const ScoredCluster& a, const ScoredCluster& b) { return a.score > b.score; });

    vgc::log::raw("  [field_trace] Phase 3: %zu qualified clusters (have target + siblings)\n", scored.size());

    // Phase 4: Build results from top-scored clusters
    for (auto& sc : scored) {
        auto& cl = *sc.cluster;
        for (auto& hit : cl.hits) {
            if (hit.offset != targetFieldOffset) continue;
            FieldSetterHit fsh = {};
            fsh.rva = hit.rva;
            fsh.fieldOffset = hit.offset;
            fsh.funcRVA = findContainingFunc(pe, hit.rva);
            fsh.clusterRVA = cl.startRVA;
            fsh.siblingCount = (uint32_t)cl.offsets.size();
            fsh.callsSetterStub = sc.hasSetterCall;
            fsh.confidence = std::min(1.0f, sc.score / 10.0f);
            trace.hits.push_back(fsh);
        }
    }

    // Phase 5: Report
    if (trace.hits.empty()) {
        vgc::log::raw("  [field_trace] No setter candidates found.\n");
    } else {
        vgc::log::raw("  [field_trace] Results (target +0x%X):\n", targetFieldOffset);
        for (auto& h : trace.hits) {
            vgc::log::raw("    RVA 0x%06X  func=0x%06X  cluster=0x%06X  siblings=%u  setter_call=%s  conf=%.0f%%\n",
                   h.rva, h.funcRVA, h.clusterRVA, h.siblingCount,
                   h.callsSetterStub ? "YES" : "no", h.confidence * 100);
        }
    }

    return trace;
}

} // namespace vgc
