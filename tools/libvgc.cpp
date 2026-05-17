// pe_fixer.cpp — CLI tool for libvgc
#include "cli.h"
#include <vgc/log.h>
#include <pefix/log.h>
#include <griffin/log.h>
#include <cstring>
#include <cstdio>

static FILE* g_dbgLog = nullptr;

static void cli_sink(int level, const char* msg) {
    char buf[8192];
    size_t n = strlen(msg);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, msg, n);
    buf[n] = 0;
    while (n && buf[n - 1] == '\n') buf[--n] = 0;

    if (g_dbgLog) { fputs(buf, g_dbgLog); fputc('\n', g_dbgLog); fflush(g_dbgLog); }

    if (strncmp(buf, "[+] ", 4) == 0) { cli::ok("%s", buf + 4);     return; }
    if (strncmp(buf, "[-] ", 4) == 0) { cli::fail("%s", buf + 4);   return; }
    if (strncmp(buf, "[!] ", 4) == 0) { cli::warn("%s", buf + 4);   return; }
    if (strncmp(buf, "[*] ", 4) == 0) { cli::info("%s", buf + 4);   return; }
    if (strncmp(buf, "    ", 4) == 0) { cli::detail("%s", buf + 4); return; }
    switch (level) {
        case 0: cli::ok("%s", buf);     break;
        case 1: cli::fail("%s", buf);   break;
        case 2: cli::warn("%s", buf);   break;
        case 3: cli::info("%s", buf);   break;
        case 4: cli::detail("%s", buf); break;
        default: fputs(buf, stdout); fputc('\n', stdout); break;
    }
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>

#include <vgc/vgc.h>

using namespace pefix;
using namespace griffin;
using namespace vgc;

using GriffinDisasm = pefix::Disasm;
using GriffinEmulator = pefix::Emulator;
using GriffinStaticTracer = pefix::Tracer;
using GriffinDispatchExtractor = griffin::DispatchExtractor;
using GriffinMBA = griffin::MBA;
using GriffinConstProp = griffin::ConstProp;
using GriffinOutput = griffin::Output;
using GrFunc = pefix::Func;
using GrInstr = pefix::Instr;
using GrBlock = pefix::Block;
using GrReg = pefix::Reg;
using GrOp = pefix::Op;
using GrWidth = pefix::Width;
using GrCC = pefix::CC;
using GrValue = pefix::Value;
inline const char* grRegName(GrReg r) { return pefix::regName(r); }
inline const char* grOpName(GrOp op) { return pefix::opName(op); }

static void dbgOpen(const char* outputPath) {
    if (!outputPath) return;
    std::string p(outputPath);
    auto dot = p.rfind('.');
    std::string dbgPath = (dot != std::string::npos ? p.substr(0, dot) : p) + "_debug.log";
    g_dbgLog = fopen(dbgPath.c_str(), "w");
    cli::info("Debug log: %s", dbgPath.c_str());
}
#define DBG(...) do { if (g_dbgLog) { fprintf(g_dbgLog, __VA_ARGS__); fflush(g_dbgLog); } } while(0)

struct Timer {
    std::chrono::high_resolution_clock::time_point t0;
    Timer() : t0(std::chrono::high_resolution_clock::now()) {}
    double elapsedMs() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - t0).count();
    }
    void report(const char* label) const {
        cli::detail("[time] %s: %.0f ms", label, elapsedMs());
    }
};

static void printUsage(const char* argv0) {
    printf("PE Post-Processor for dumped executables (x64)\n");
    printf("Fixes ImageBase, patches nullsubs, scans RIP-relative references.\n\n");
    printf("Usage:\n");
    printf("  %s <input> <actual_base_hex> [options]\n\n", argv0);
    printf("Options:\n");
    printf("  -o <output>             Output file (default: <input>_fixed.exe)\n");
    printf("  --all                   Enable all safe fixups (recommended)\n");
    printf("  --recover-sections      Add section headers for hidden code gaps\n");
    printf("  --fix-nullsub           Patch C3 in obfuscation blocks to CC (INT3)\n");
    printf("  --flatten-jmp           Flatten jmp chains in obfuscated sections\n");
    printf("  --resolve-thunks        Redirect calls through thunks to real targets\n");
    printf("  --recover-symbols       Recover OpenSSL function names from ERR strings\n");
    printf("  --strip-junk            Remove exec flag from obfuscated sections\n");
    printf("  --idc <out.idc>         Generate IDC script (symbols + xrefs + cleanup)\n");
    printf("  --ida-script <out.py>   Generate IDA Python script for xref fixup\n");
    printf("  --add-reloc             Add a .reloc section (experimental)\n");
    printf("  --deobf-scan            Batch deobfuscate all .grfn1 functions + PE patch\n");
    printf("  --debug-log             Mirror all log output to <output>_debug.log\n");
    printf("  --dry-run               Analyze only, don't write output\n");
    printf("  --verbose               Print details for each reference found\n");
    printf("\nExamples:\n");
    printf("  %s vgc_dump.exe 0x564700000 --all --idc xrefs.idc\n", argv0);
    printf("  %s vgc_dump.exe 0x564700000 --recover-sections --recover-symbols --idc xrefs.idc\n", argv0);
}

int main(int argc, char* argv[]) {
    pefix::log::set_sink(cli_sink);
    griffin::log::set_sink(cli_sink);
    vgc::log::set_sink(cli_sink);
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const char* inputPath = argv[1];
    const char* baseStr = nullptr;
    const char* outputPath = nullptr;
    const char* idaScriptPath = nullptr;
    const char* idcScriptPath = nullptr;
    bool recoverSectionsOpt = false;
    bool stripJunk = false;
    bool fixNullsub = false;
    bool flattenJmp = false;
    bool resolveThunksOpt = false;
    bool recoverSymbols = false;
    bool addReloc = false;
    bool dryRun = false;
    bool verbose = false;
    const char* deobfTarget = nullptr;
    const char* deobfOutput = nullptr;
    int64_t dispatchKey = INT64_MIN;
    const char* emuTarget = nullptr;
    uint32_t emuMaxSteps = 50000;
    bool deobfScan = false;
    bool protoScan = false;
    bool traceEntry = false;
    bool debugLog = false;
    uint32_t traceEntrySteps = 2000000;

    bool hasOptions = false;
    for (int i = 2; i < argc; i++) {
        if (!baseStr && argv[i][0] == '0' && (argv[i][1] == 'x' || argv[i][1] == 'X')) {
            baseStr = argv[i];
            continue;
        }
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (strcmp(argv[i], "--ida-script") == 0 && i + 1 < argc) {
            idaScriptPath = argv[++i];
        } else if (strcmp(argv[i], "--idc") == 0 && i + 1 < argc) {
            idcScriptPath = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            hasOptions = true;
            recoverSectionsOpt = fixNullsub = flattenJmp = resolveThunksOpt = recoverSymbols = true;
            deobfScan = true;
            protoScan = true;
        } else if (strcmp(argv[i], "--recover-sections") == 0) {
            hasOptions = true;
            recoverSectionsOpt = true;
        } else if (strcmp(argv[i], "--strip-junk") == 0) {
            stripJunk = true;
        } else if (strcmp(argv[i], "--fix-nullsub") == 0) {
            fixNullsub = true;
        } else if (strcmp(argv[i], "--flatten-jmp") == 0) {
            flattenJmp = true;
        } else if (strcmp(argv[i], "--resolve-thunks") == 0) {
            resolveThunksOpt = true;
        } else if (strcmp(argv[i], "--recover-symbols") == 0) {
            recoverSymbols = true;
        } else if (strcmp(argv[i], "--add-reloc") == 0) {
            addReloc = true;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dryRun = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--deobfuscate") == 0 && i + 1 < argc) {
            deobfTarget = argv[++i];
        } else if (strcmp(argv[i], "--dispatch-key") == 0 && i + 1 < argc) {
            const char* s = argv[++i];
            if (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0) s += 2;
            dispatchKey = (int64_t)strtoull(s, nullptr, 16);
        } else if (strcmp(argv[i], "--deobf-output") == 0 && i + 1 < argc) {
            deobfOutput = argv[++i];
        } else if (strcmp(argv[i], "--emulate") == 0 && i + 1 < argc) {
            emuTarget = argv[++i];
        } else if (strcmp(argv[i], "--emu-steps") == 0 && i + 1 < argc) {
            emuMaxSteps = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--deobf-scan") == 0) {
            deobfScan = true;
        } else if (strcmp(argv[i], "--proto-scan") == 0) {
            protoScan = true;
        } else if (strcmp(argv[i], "--trace-entry") == 0) {
            traceEntry = true;
            if (i + 1 < argc && argv[i+1][0] != '-')
                traceEntrySteps = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--debug-log") == 0) {
            debugLog = true;
        } else {
            cli::fail("Unknown option: %s", argv[i]);
            return 1;
        }
    }

    if (!recoverSectionsOpt && !fixNullsub && !flattenJmp && !resolveThunksOpt &&
        !recoverSymbols && !deobfScan && !protoScan && !stripJunk) {
        recoverSectionsOpt = fixNullsub = flattenJmp = resolveThunksOpt = recoverSymbols = true;
        deobfScan = true;
        protoScan = true;
    }

    uint64_t actualBase = 0;
    if (baseStr) {
        const char* s = baseStr;
        if (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0) s += 2;
        actualBase = strtoull(s, nullptr, 16);
    }

    // Generate default output path
    std::string defaultOutput;
    if (!outputPath) {
        defaultOutput = inputPath;
        size_t dot = defaultOutput.rfind('.');
        if (dot != std::string::npos) {
            defaultOutput.insert(dot, "_fixed");
        } else {
            defaultOutput += "_fixed";
        }
        outputPath = defaultOutput.c_str();
    }

    // Load PE
    cli::info("Loading: %s", inputPath);
    PEFile pe;
    if (!pe.load(inputPath)) {
        cli::fail("Failed to load PE file.");
        return 1;
    }

    uint64_t originalBase = pe.nt->OptionalHeader.ImageBase;
    if (actualBase == 0) actualBase = originalBase;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    cli::info("PE64 loaded: %zu bytes", pe.data.size());
    if (debugLog) dbgOpen(outputPath);
    cli::detail("Original ImageBase: 0x%llX", originalBase);
    cli::detail("Actual base:        0x%llX", actualBase);
    cli::detail("SizeOfImage:        0x%X", sizeOfImage);
    cli::detail("Sections:           %d", pe.numSections);

    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        cli::detail("[%d] %-8s  VA=0x%08X  VSize=0x%08X  Raw=0x%08X  RSize=0x%08X  Char=0x%08X",
               i, name,
               pe.sections[i].VirtualAddress,
               pe.sections[i].Misc.VirtualSize,
               pe.sections[i].PointerToRawData,
               pe.sections[i].SizeOfRawData,
               pe.sections[i].Characteristics);
    }

    // Fix ImageBase
    if (originalBase != actualBase) {
        cli::info("Fixing ImageBase: 0x%llX -> 0x%llX", originalBase, actualBase);
        pe.nt->OptionalHeader.ImageBase = actualBase;
    } else {
        cli::info("ImageBase already correct: 0x%llX", actualBase);
    }

    // Fix DataDirectory
    {
        auto& opt = pe.nt->OptionalHeader;
        // Ensure 16 entries, zero unused
        if (opt.NumberOfRvaAndSizes < 16) {
            cli::info("Fixing NumberOfRvaAndSizes: %u -> 16", opt.NumberOfRvaAndSizes);
            for (uint32_t i = opt.NumberOfRvaAndSizes; i < 16; i++) {
                opt.DataDirectory[i].VirtualAddress = 0;
                opt.DataDirectory[i].Size = 0;
            }
            opt.NumberOfRvaAndSizes = 16;
        }
        // Keep import directory (IDA Imports tab). Zero garbage IAT/bound entries.
        // IDA PE loader causes "?" at IAT addresses — this is a display-only issue,
        // not data loss. Import names also available via COFF symbols (imp_XXX).
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = {};
    }

    // Recover hidden sections (must be before scanning)
    if (recoverSectionsOpt) {
        cli::info("Scanning for hidden code sections (gaps in section layout)...");
        int recovered = recoverHiddenSections(pe);
        if (recovered > 0) {
            cli::ok("Recovered %d hidden section(s)", recovered);
            sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;
        } else {
            cli::info("No hidden sections found");
        }
    }

    // Strip junk sections
    if (stripJunk) {
        cli::info("Stripping executable flag from obfuscated sections...");
        int stripped = stripJunkSections(pe);
        if (stripped > 0)
            cli::ok("Stripped %d junk section(s)", stripped);
        else
            cli::info("No junk sections found");
    }

    // Resolve thunks BEFORE nullsub patching
    if (resolveThunksOpt) {
        cli::info("Resolving thunk wrappers...");
        uint32_t n = resolveThunks(pe);
        cli::ok("Resolved %u thunk calls", n);
    }

    // Flatten jmp chains
    if (flattenJmp) {
        cli::info("Flattening jmp chains...");
        uint32_t n = vgc::flattenJmpChains(pe);
        cli::ok("Flattened %u jmp chains", n);
    }

    // Patch anti-disassembly tricks
    if (recoverSectionsOpt || flattenJmp) {
        cli::info("Patching anti-disassembly (EB FF F0 48)...");
        uint32_t ad = patchAntiDisasm(pe);
        cli::ok("Patched %u anti-disassembly sequences", ad);
    }

    // Patch nullsub patterns AFTER thunk resolution
    std::vector<vgc::NullsubPatch> nullsubPatches;
    if (fixNullsub) {
        cli::info("Patching nullsub dead code (C3 90 E9 00 00 00 00 48 B8)...");
        nullsubPatches = vgc::patchNullsubs(pe);
        cli::ok("Patched %zu nullsub locations", nullsubPatches.size());
    }

    // Scan executable sections for RIP-relative instructions
    cli::info("Scanning for RIP-relative instructions...");
    std::vector<RipRelativeRef> allRefs = scanRipRelativeRefs(pe, actualBase);
    cli::ok("Total RIP-relative references: %zu", allRefs.size());

    std::vector<NamedAddress> orphanNames; // populated by orphan detection, used by COFF embed
    std::vector<FuncBoundary> extraFunctions; // populated by hidden func discovery, used by deobf + COFF

    // Classify references
    int refToCode = 0, refToData = 0, refToOutside = 0;
    int callCount = 0, jmpCount = 0, leaCount = 0, memCount = 0;

    for (auto& ref : allRefs) {
        if (ref.isCall) callCount++;
        else if (ref.isJmp) jmpCount++;
        else if (ref.isLea) leaCount++;
        else memCount++;

        if (ref.targetRVA < sizeOfImage) {
            int sec = pe.findSection(ref.targetRVA);
            if (sec >= 0 && pe.isExecutableSection(sec)) {
                refToCode++;
            } else {
                refToData++;
            }
        } else {
            refToOutside++;
        }
    }

    cli::detail("CALL [rip+disp32]:  %d", callCount);
    cli::detail("JMP  [rip+disp32]:  %d", jmpCount);
    cli::detail("LEA  reg,[rip+d32]: %d", leaCount);
    cli::detail("Other mem ops:      %d", memCount);
    cli::detail("-> to code:         %d", refToCode);
    cli::detail("-> to data:         %d", refToData);
    cli::detail("-> outside image:   %d", refToOutside);

    if (verbose) {
        cli::info("Detailed reference list:");
        for (size_t i = 0; i < allRefs.size() && i < 500; i++) {
            auto& ref = allRefs[i];
            const char* type = ref.isCall ? "CALL" : ref.isJmp ? "JMP" : ref.isLea ? "LEA" : "MEM";
            cli::detail("RVA 0x%08X [len=%2u] %4s -> 0x%llX (disp=%+d)",
                   ref.instrRVA, ref.instrLen, type, ref.targetVA, ref.displacement);
        }
        if (allRefs.size() > 500) {
            cli::detail("... (%zu more entries truncated)", allRefs.size() - 500);
        }
    }

    // Build .reloc section if requested
    if (addReloc) {
        cli::info("Building .reloc section...");

        // Collect relocation entries from RIP-relative references
        struct RelocEntry {
            uint32_t rva;
            uint16_t type;
        };
        std::vector<RelocEntry> relocEntries;
        for (auto& ref : allRefs) {
            if (ref.targetRVA >= sizeOfImage) continue;
            RelocEntry re;
            re.rva = ref.instrRVA + ref.dispOffset;
            re.type = 10; // IMAGE_REL_BASED_DIR64
            relocEntries.push_back(re);
        }

        cli::detail("Relocation entries: %zu", relocEntries.size());

        if (!relocEntries.empty() && !dryRun) {
            // Build reloc data manually (same logic as buildRelocSection)
            std::map<uint32_t, std::vector<uint16_t>> pages;
            for (auto& e : relocEntries) {
                uint32_t page = e.rva & ~0xFFFu;
                uint16_t offset = (uint16_t)(e.rva & 0xFFF);
                uint16_t typeOffset = (uint16_t)((e.type << 12) | offset);
                pages[page].push_back(typeOffset);
            }

            std::vector<uint8_t> relocData;
            for (auto& [pageRVA, offsets] : pages) {
                auto sorted = offsets;
                std::sort(sorted.begin(), sorted.end());
                if (sorted.size() & 1) sorted.push_back(0);
                uint32_t blockSize = (uint32_t)(sizeof(IMAGE_BASE_RELOCATION) + sorted.size() * sizeof(uint16_t));
                size_t off = relocData.size();
                relocData.resize(off + blockSize);
                auto* block = (IMAGE_BASE_RELOCATION*)(relocData.data() + off);
                block->VirtualAddress = pageRVA;
                block->SizeOfBlock = blockSize;
                uint16_t* dst = (uint16_t*)(relocData.data() + off + sizeof(IMAGE_BASE_RELOCATION));
                for (size_t j = 0; j < sorted.size(); j++) dst[j] = sorted[j];
            }

            cli::detail(".reloc section size: %zu bytes", relocData.size());

            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

            uint32_t secAlign = pe.nt->OptionalHeader.SectionAlignment;
            if (!secAlign) secAlign = 0x1000;
            uint32_t newRelocRVA = 0;
            for (WORD i = 0; i < pe.numSections; i++) {
                uint32_t end = pe.sections[i].VirtualAddress + pe.sections[i].Misc.VirtualSize;
                if (end > newRelocRVA) newRelocRVA = end;
            }
            newRelocRVA = (newRelocRVA + secAlign - 1) & ~(secAlign - 1);

            if (appendSection(pe, ".reloc", relocData,
                              IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE)) {
                pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = newRelocRVA;
                pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (DWORD)relocData.size();
                cli::ok(".reloc section added successfully");
            } else {
                cli::fail("Failed to add .reloc section");
            }
        }
    }

    // Generate IDA Python script
    if (idaScriptPath) {
        cli::info("Generating IDA Python script...");
        generateIdaScript(idaScriptPath, allRefs, actualBase, sizeOfImage);
    }

    // Decode .grfn1 trampolines
    std::vector<Trampoline> trampolines;
    {
        cli::info("Decoding trampolines (pop [rsp+X]; jmp target)...");
        trampolines = decodeTrampolines(pe, actualBase);
        cli::ok("Decoded %zu trampolines", trampolines.size());
        if (verbose) {
            for (size_t j = 0; j < trampolines.size() && j < 20; j++)
                cli::detail("0x%llX -> 0x%llX", trampolines[j].trampolineVA, trampolines[j].targetVA);
            if (trampolines.size() > 20)
                cli::detail("... (%zu more)", trampolines.size() - 20);
        }
    }

    // Find key string references
    std::vector<KeyStringRef> keyRefs;
    {
        cli::info("Searching for key string references (IOCTL, protobuf, pipe, crypto)...");
        keyRefs = findKeyStringRefs(pe, allRefs, actualBase);
        if (!keyRefs.empty()) {
            cli::ok("Found %zu key references:", keyRefs.size());
            for (auto& kr : keyRefs)
                cli::detail("[%s] 0x%llX refs \"%s\"", kr.category.c_str(), kr.instrVA, kr.value.c_str());
        } else {
            cli::info("No key string references found via RIP-relative (may need IDA xrefs)");
        }
    }

    // Parse RTTI
    std::vector<RTTIClass> rttiClasses;
    {
        cli::info("Parsing MSVC RTTI (class names + vtables)...");
        rttiClasses = pefix::parseRTTI(pe, actualBase);
        cli::ok("Found %zu classes with vtables", rttiClasses.size());
        size_t totalMethods = 0;
        for (auto& c : rttiClasses) totalMethods += c.methodVAs.size();
        cli::detail("Total virtual methods: %zu", totalMethods);
        if (verbose) {
            for (size_t j = 0; j < rttiClasses.size() && j < 30; j++)
                cli::detail("%s (vtable=0x%llX, %zu methods)",
                       rttiClasses[j].demangledName.c_str(), rttiClasses[j].vtableVA,
                       rttiClasses[j].methodVAs.size());
        }
    }

    // Decode .riot1 import wrappers
    std::vector<ImportWrapper> importWrappers;
    {
        cli::info("Decoding .riot1 import wrappers...");
        importWrappers = decodeImportWrappers(pe, actualBase);
        cli::ok("Decoded %zu import wrappers", importWrappers.size());
        resolveImportNames(importWrappers, pe);

        // Import wrappers end with "jmp rax" — IDA can't fully analyze callers.
        // Tested "call rax; ret" conversion but it causes "positive sp value" errors.
        // Leave as jmp rax — IDA handles tail jumps better than unknown calls.

        if (verbose) {
            for (size_t j = 0; j < importWrappers.size(); j++)
                cli::detail("0x%llX: A=0x%X B=0x%X  %s",
                       importWrappers[j].wrapperVA, importWrappers[j].constA, importWrappers[j].constB,
                       importWrappers[j].apiName.empty() ? "(unresolved)" : importWrappers[j].apiName.c_str());
        }
        // Scan .riot0 for API name strings
        {
            cli::info("Scanning .riot0 for API name strings...");
            for (WORD si = 0; si < pe.numSections; si++) {
                char sname[9] = {};
                memcpy(sname, pe.sections[si].Name, 8);
                if (strcmp(sname, ".riot0") != 0) continue;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                const char* data = (const char*)(pe.data.data() + rawOff);
                int apiCount = 0;
                for (uint32_t pos = 0; pos + 4 < rawSz; pos++) {
                    if (data[pos] == 0) continue;
                    if (data[pos] < 'A' || data[pos] > 'Z') continue;
                    size_t len = strnlen(data + pos, rawSz - pos);
                    if (len < 3 || len > 80) continue;
                    bool valid = true;
                    for (size_t k = 0; k < len; k++)
                        if (data[pos+k] < 0x20 || data[pos+k] > 0x7E) { valid = false; break; }
                    if (!valid) continue;
                    if (strstr(data+pos, "SHA") == data+pos && len == 3) { pos += (uint32_t)len; continue; }
                    uint64_t va = actualBase + pe.sections[si].VirtualAddress + pos;
                    cli::detail("[%d] 0x%llX: %s", apiCount, va, data + pos);
                    apiCount++;
                    pos += (uint32_t)len;
                }
                cli::ok("Found %d API-like strings in .riot0", apiCount);
            }
        }
    }

    // Resolve pointer chains
    std::vector<PointerRef> ptrRefs;
    {
        cli::info("Resolving pointer chains in data sections...");
        ptrRefs = resolvePointerChains(pe, actualBase);
        cli::ok("Found %zu internal pointers", ptrRefs.size());
    }

    // Resolve indirect calls: FF 15/FF 25 [rip+disp] → direct E8/E9
    {
        cli::info("Resolving indirect calls (FF 15/FF 25)...");
        auto indirectCalls = resolveIndirectCalls(pe, actualBase);
        auto icStats = patchIndirectCalls(pe, actualBase, indirectCalls);
        cli::ok("Indirect calls: %u resolved, %u patched, %u IAT skipped",
               icStats.resolved, icStats.patched, icStats.skippedIAT);
    }

    // Resolve vtable calls: mov rax,[rcx]; call [rax+N] → direct call
    // For each known vtable (RTTI + proto_scan), find call sites and patch.
    {
        cli::info("Resolving vtable calls...");
        Timer tVtbl;
        uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

        // Collect all known vtable addresses → function pointer arrays
        struct VtableInfo {
            uint32_t vtableRVA;
            std::string className;
            std::vector<uint32_t> methods; // vtable[i] = method RVA
        };
        std::vector<VtableInfo> vtables;

        // From RTTI classes (already parsed)
        // From proto_scan: done later, but we can scan .rdata for vtable-like arrays
        // Simplest: scan .rdata for arrays of code pointers (all pointing to executable sections)
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".rdata") != 0) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            uint32_t secRVA = pe.sections[si].VirtualAddress;

            for (uint32_t p = 0; p + 64 <= rawSz; p += 8) {
                // Check if this looks like a vtable (>= 4 consecutive code pointers)
                int codeCount = 0;
                for (int e = 0; e < 40 && p + (e+1)*8 <= rawSz; e++) {
                    uint64_t val = *(uint64_t*)(pe.data.data() + rawOff + p + e*8);
                    if (val >= actualBase && val < actualBase + soi) {
                        uint32_t rva = (uint32_t)(val - actualBase);
                        int sec2 = pe.findSection(rva);
                        if (sec2 >= 0 && pe.isExecutableSection(sec2)) { codeCount++; continue; }
                    }
                    break;
                }
                if (codeCount >= 4) {
                    VtableInfo vt;
                    vt.vtableRVA = secRVA + p;
                    for (int e = 0; e < codeCount; e++) {
                        uint64_t val = *(uint64_t*)(pe.data.data() + rawOff + p + e*8);
                        vt.methods.push_back((uint32_t)(val - actualBase));
                    }
                    vtables.push_back(std::move(vt));
                    p += codeCount * 8 - 8; // skip past this vtable
                }
            }
        }
        cli::detail("Found %zu vtable-like arrays in .rdata", vtables.size());

        // Build vtable pointer → index map for fast lookup
        // key = (vtableVA), value = index in vtables[]
        std::unordered_map<uint64_t, size_t> vtableByVA;
        for (size_t i = 0; i < vtables.size(); i++)
            vtableByVA[actualBase + vtables[i].vtableRVA] = i;

        // Scan executable sections for:
        //   Pattern: 48 8B 01 FF 50 XX      (mov rax,[rcx]; call [rax+disp8])
        //   Pattern: 48 8B 01 FF 90 XX XX XX XX  (mov rax,[rcx]; call [rax+disp32])
        // Look backward in the same function for LEA rcx, [rip+X]
        // where [X] contains a known vtable pointer
        uint32_t vtblResolved = 0, vtblPatched = 0;
        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;

            for (uint32_t p = 3; p + 6 <= rawSz; p++) {
                uint32_t off = rawOff + p;
                // mov rax, [rcx]
                if (pe.data[off] != 0x48 || pe.data[off+1] != 0x8B || pe.data[off+2] != 0x01) continue;

                uint32_t callOff = off + 3;
                uint32_t vtableOffset = 0;
                uint32_t callLen = 0;

                if (pe.data[callOff] == 0xFF && pe.data[callOff+1] == 0x50) {
                    vtableOffset = pe.data[callOff+2]; callLen = 3;
                } else if (pe.data[callOff] == 0xFF && pe.data[callOff+1] == 0x90 && p + 9 <= rawSz) {
                    vtableOffset = *(uint32_t*)(pe.data.data() + callOff + 2); callLen = 6;
                } else continue;

                if (vtableOffset % 8 != 0) continue;
                uint32_t vtIdx = vtableOffset / 8;
                uint32_t callRVA = secRVA + p + 3;

                // Backward scan for LEA rcx, [rip+X] (48 8D 0D [disp32])
                // within 100 bytes before the mov rax,[rcx]
                for (int back = 7; back < 100 && p >= (uint32_t)back; back++) {
                    uint32_t sOff = rawOff + p - back;
                    if (pe.data[sOff] == 0x48 && pe.data[sOff+1] == 0x8D && pe.data[sOff+2] == 0x0D) {
                        int32_t disp = *(int32_t*)(pe.data.data() + sOff + 3);
                        uint32_t leaRVA = secRVA + p - back;
                        uint64_t objVA = actualBase + leaRVA + 7 + disp;

                        // Read vtable pointer from object address
                        uint32_t objOff = pe.rvaToOffset((uint32_t)(objVA - actualBase));
                        if (!objOff || objOff + 8 > pe.data.size()) continue;
                        uint64_t vtableVA = *(uint64_t*)(pe.data.data() + objOff);

                        auto it = vtableByVA.find(vtableVA);
                        if (it == vtableByVA.end()) continue;

                        auto& vt = vtables[it->second];
                        if (vtIdx >= vt.methods.size()) continue;

                        uint32_t targetRVA = vt.methods[vtIdx];
                        // Patch: 48 8B 01 FF 50 XX (6 bytes) or 48 8B 01 FF 90 ... (9 bytes)
                        // → 90 90 90 E8 [disp32] (for disp8: 6 bytes = 3 NOP + 5 call - needs 8? no)
                        // Actually: NOP the mov rax,[rcx] (3 bytes) + replace call [rax+N]
                        uint32_t totalLen = 3 + callLen; // mov(3) + call(3 or 6)
                        if (totalLen >= 5) {
                            int32_t relDisp = (int32_t)(targetRVA - (callRVA - 3 + 5)); // from start of patch
                            uint32_t patchOff = rawOff + p;
                            pe.data[patchOff] = 0xE8; // CALL rel32
                            memcpy(pe.data.data() + patchOff + 1, &relDisp, 4);
                            for (uint32_t n = 5; n < totalLen; n++)
                                pe.data[patchOff + n] = 0x90;
                            vtblPatched++;
                        }
                        vtblResolved++;
                        break;
                    }
                }
            }
        }
        cli::ok("Vtable calls (static): %u resolved, %u patched (%.0f ms)",
               vtblResolved, vtblPatched, tVtbl.elapsedMs());
        // Note: vtable call → direct call requires type propagation (which register
        // holds which class). This is beyond PE-level patching — IDA handles it via
        // type system. Proto vtable method names are added as COFF symbols instead.
    }

    // Recover OpenSSL symbols
    std::vector<OpenSSLSymbol> sslSymbols;
    if (recoverSymbols) {
        cli::info("Recovering OpenSSL symbols from ERR strings...");
        sslSymbols = recoverOpenSSLSymbols(pe, actualBase);
        cli::ok("Recovered %zu OpenSSL function names", sslSymbols.size());
        for (auto& s : sslSymbols)
            cli::detail("0x%llX = %s", s.funcVA, s.name.c_str());
    }

    // Build synthetic export table
    std::vector<NamedAddress> allNames; // moved to function scope for final COFF
    if (!dryRun) {
        // Clear any existing export/COFF from previous pe_fixer runs
        if (pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
            cli::info("Clearing previous export directory");
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
        }
        if (pe.nt->FileHeader.PointerToSymbolTable != 0) {
            cli::info("Clearing previous COFF symbol table");
            // Truncate file to remove old COFF data appended at end
            uint32_t oldSymOff = pe.nt->FileHeader.PointerToSymbolTable;
            if (oldSymOff < pe.data.size()) {
                pe.data.resize(oldSymOff);
                pe.reparse();
            }
            pe.nt->FileHeader.PointerToSymbolTable = 0;
            pe.nt->FileHeader.NumberOfSymbols = 0;
        }
        // Import wrappers
        for (auto& w : importWrappers)
            if (!w.apiName.empty())
                allNames.push_back({w.wrapperVA, w.apiName});
        // OpenSSL symbols
        for (auto& s : sslSymbols)
            allNames.push_back({s.funcVA, s.name});
        // RTTI classes + methods
        for (auto& cls : rttiClasses) {
            std::string vtblName = "vtbl_" + cls.demangledName;
            for (auto& c : vtblName) if (c == ':' || c == '<' || c == '>' || c == ' ' || c == ',') c = '_';
            allNames.push_back({cls.vtableVA, vtblName});
            for (size_t m = 0; m < cls.methodVAs.size(); m++) {
                std::string mname = cls.demangledName;
                for (auto& c : mname) if (c == ':' || c == '<' || c == '>' || c == ' ' || c == ',') c = '_';
                char buf[16]; sprintf_s(buf, "__vf%zu", m);
                allNames.push_back({cls.methodVAs[m], mname + buf});
            }
        }
        // Detect constructors: any LEA that loads a known RTTI vtable VA,
        // followed by a store to [reg] or [reg+offset] = vtable write
        {
            uint32_t ctorNamed = 0;
            uint32_t soi2 = pe.nt->OptionalHeader.SizeOfImage;

            // Build RTTI vtable RVA -> class name map
            std::unordered_map<uint32_t, std::string> vtableToClassName;
            for (auto& cls : rttiClasses) {
                if (cls.vtableVA < actualBase) continue;
                uint32_t vtRVA = (uint32_t)(cls.vtableVA - actualBase);
                std::string name = cls.demangledName;
                for (auto& c : name) if (c == ':' || c == '<' || c == '>' || c == ' ' || c == ',') c = '_';
                vtableToClassName[vtRVA] = name;
            }

            // Also detect vtables via RTTI COL pointer (vtable-8 → COL → TypeDescriptor → name)
            // This catches vtables NOT in the RTTI parser output
            auto resolveVtableName = [&](uint32_t vtableRVA) -> std::string {
                auto it = vtableToClassName.find(vtableRVA);
                if (it != vtableToClassName.end()) return it->second;
                if (vtableRVA < 8) return "";
                uint32_t rttipOff = pe.rvaToOffset(vtableRVA - 8);
                if (!rttipOff || rttipOff + 8 > pe.data.size()) return "";
                uint64_t colVA = *(uint64_t*)(pe.data.data() + rttipOff);
                if (colVA < actualBase || colVA >= actualBase + soi2) return "";
                uint32_t colOff = pe.rvaToOffset((uint32_t)(colVA - actualBase));
                if (!colOff || colOff + 24 > pe.data.size()) return "";
                int32_t tdOff2 = *(int32_t*)(pe.data.data() + colOff + 12);
                uint32_t tdFileOff = pe.rvaToOffset(tdOff2);
                if (!tdFileOff || tdFileOff + 24 > pe.data.size()) return "";
                const char* mn = (const char*)(pe.data.data() + tdFileOff + 16);
                if (mn[0] != '.' || mn[1] != '?') return "";
                std::string raw(mn + 4);
                auto atAt = raw.find("@@");
                if (atAt != std::string::npos) raw = raw.substr(0, atAt);
                for (auto& c : raw) if (c == '@') c = '_';
                return raw;
            };

            // Use allRefs: find LEA instructions targeting known vtable RVAs
            std::unordered_set<uint32_t> ctorFuncRVAs;
            for (auto& ref : allRefs) {
                if (!ref.isLea) continue;
                if (ref.targetRVA == 0 || ref.targetRVA >= soi2) continue;

                std::string className = resolveVtableName(ref.targetRVA);
                if (className.empty()) continue;

                // Check next bytes after LEA: is it a store to [reg] or [reg+offset]?
                uint32_t afterOff = pe.rvaToOffset(ref.instrRVA + ref.instrLen);
                if (!afterOff || afterOff + 3 > pe.data.size()) continue;
                uint8_t b0 = pe.data[afterOff];
                uint8_t b1 = pe.data[afterOff + 1];
                uint8_t b2 = pe.data[afterOff + 2];

                bool isVtWrite = false;
                // Pattern: [48|4C] 89 modrm — MOV [reg], reg (64-bit store)
                if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x49) && b1 == 0x89) {
                    uint8_t mod = b2 >> 6;
                    uint8_t rm = b2 & 7;
                    // mod=00: [reg], mod=01: [reg+disp8], mod=10: [reg+disp32]
                    // rm=4 means SIB (skip), rm=5 with mod=0 means RIP-relative (skip)
                    if (mod <= 2 && rm != 4 && !(mod == 0 && rm == 5))
                        isVtWrite = true;
                }

                if (!isVtWrite) continue;

                // Find function start: backward scan for boundary
                uint32_t instrOff = pe.rvaToOffset(ref.instrRVA);
                if (!instrOff) continue;
                uint32_t funcRVA = ref.instrRVA;
                for (uint32_t back = 1; back < 0x200 && instrOff > back; back++) {
                    uint8_t b = pe.data[instrOff - back];
                    if (b == 0xCC || b == 0xC3) { funcRVA = ref.instrRVA - back + 1; break; }
                }

                if (!ctorFuncRVAs.count(funcRVA)) {
                    ctorFuncRVAs.insert(funcRVA);
                    allNames.push_back({actualBase + funcRVA, className + "_ctor"});
                    ctorNamed++;
                }
            }
            cli::detail("Constructor detection: %u named via RTTI", ctorNamed);
        }

        // Export table generation deferred to end (after all symbols collected)

        // Read .pdata function boundaries for correct function starts
        auto pdataFuncs = readPdataFunctions(pe);
        // Add .pdata function starts as hints (ensures IDA merges split functions)
        std::unordered_set<uint64_t> namedVAs;
        for (auto& n : allNames) namedVAs.insert(n.va);
        int pdataHints = 0;
        for (auto& fb : pdataFuncs) {
            uint64_t va = actualBase + fb.beginRVA;
            bool alreadyNamed = namedVAs.count(va) > 0;
            if (!alreadyNamed && fb.endRVA > fb.beginRVA) {
                // Give section-based prefix
                int sec = pe.findSection(fb.beginRVA);
                std::string prefix = "fn_";
                if (sec >= 0) {
                    char sn[9] = {}; memcpy(sn, pe.sections[sec].Name, 8);
                    if (strncmp(sn, ".text", 5) == 0) prefix = "text_";
                    else if (strncmp(sn, ".grfn", 5) == 0) prefix = "grfn_";
                    else if (strncmp(sn, ".riot", 5) == 0) prefix = "riot_";
                }
                char nameBuf[32];
                sprintf_s(nameBuf, "%s%X", prefix.c_str(), fb.beginRVA);
                allNames.push_back({va, nameBuf});
                pdataHints++;
            }
        }
        if (pdataHints > 0)
            cli::detail(".pdata function hints: %d", pdataHints);

        // Add .grfn1 function entries (IDA can't find these without help)
        {
            int grfnExports = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {};
                memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".grfn1") != 0) continue;

                uint32_t secRVA = pe.sections[si].VirtualAddress;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;

                // Call targets from xrefs
                uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;
                for (auto& ref : allRefs) {
                    if (!ref.isCall) continue;
                    uint32_t t = ref.targetRVA;
                    for (int h = 0; h < 8; h++) {
                        uint32_t o = pe.rvaToOffset(t);
                        if (!o || o + 5 > pe.data.size() || pe.data[o] != 0xE9) break;
                        int32_t d = *(int32_t*)(pe.data.data() + o + 1);
                        t = t + 5 + d;
                        if (t >= soi) break;
                    }
                    uint64_t va = actualBase + t;
                    if (t >= secRVA && t < secRVA + rawSz && !namedVAs.count(va)) {
                        char buf[32]; sprintf_s(buf, "grfn_%X", t);
                        allNames.push_back({va, buf});
                        namedVAs.insert(va);
                        grfnExports++;
                    }
                }

                // Trampoline targets
                for (auto& tr : trampolines) {
                    uint32_t t = (uint32_t)(tr.targetVA - actualBase);
                    uint64_t va = tr.targetVA;
                    if (t >= secRVA && t < secRVA + rawSz && !namedVAs.count(va)) {
                        char buf[32]; sprintf_s(buf, "grfn_%X", t);
                        allNames.push_back({va, buf});
                        namedVAs.insert(va);
                        grfnExports++;
                    }
                }

                // Prologue scan (sub rsp patterns)
                for (uint32_t pos = 0; pos + 7 < rawSz; pos++) {
                    const uint8_t* p = pe.data.data() + rawOff + pos;
                    if (!((p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) ||
                          (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC))) continue;
                    if (pos > 0) {
                        uint8_t prev = pe.data[rawOff + pos - 1];
                        if (prev != 0xCC && prev != 0xC3 && prev != 0x00 && prev != 0x90) continue;
                    }
                    uint32_t rva = secRVA + pos;
                    uint64_t va = actualBase + rva;
                    if (!namedVAs.count(va)) {
                        char buf[32]; sprintf_s(buf, "grfn_%X", rva);
                        allNames.push_back({va, buf});
                        namedVAs.insert(va);
                        grfnExports++;
                    }
                }
            }
            if (grfnExports > 0)
                cli::detail(".grfn1 function exports: %d", grfnExports);
        }

        // Infer additional function names from string refs, CRT patterns, etc.
        auto inferred = pefix::inferFunctionNames(pe, actualBase, allRefs);
        for (auto& inf : inferred)
            allNames.push_back({inf.va, inf.name});

        // Protobuf auto-discovery (adds symbols to allNames before COFF embedding)
        if (protoScan) {
            cli::info("Protobuf auto-discovery (all messages)...");
            auto protoResult = scanAllProtoMessages(pe, actualBase);
            uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

            // Protobuf MessageLite vtable slot names (MSVC layout)
            const char* pbVtSlotNames[] = {
                "dtor_deleting", "dtor", "GetTypeName", "Clear",
                "IsInitialized", "Serialize", "ByteSizeLong",
                "MergeFrom", "CopyFrom", "InternalSwap",
                "GetClassData", "GetMetadata"
            };
            constexpr int pbVtSlotCount = sizeof(pbVtSlotNames) / sizeof(pbVtSlotNames[0]);

            uint32_t protoSymsAdded = 0;
            uint32_t protoCallersFound = 0;

            for (auto& msg : protoResult.messages) {
                std::string shortName = msg.fullName;
                size_t lastDot = shortName.rfind('.');
                if (lastDot != std::string::npos)
                    shortName = shortName.substr(lastDot + 1);

                if (msg.serializeRVA) {
                    allNames.push_back({actualBase + msg.serializeRVA, shortName + "_Serialize"});
                    protoSymsAdded++;
                }

                // Name vtable slots with meaningful protobuf names
                if (msg.vtableRVA) {
                    uint32_t vtOff = pe.rvaToOffset(msg.vtableRVA);
                    if (vtOff) {
                        for (int i = 0; vtOff + (i + 1) * 8 <= pe.data.size(); i++) {
                            uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i * 8);
                            if (entry < actualBase || entry >= actualBase + soi) break;
                            char buf[128];
                            if (i < pbVtSlotCount)
                                sprintf_s(buf, "%s_%s", shortName.c_str(), pbVtSlotNames[i]);
                            else
                                sprintf_s(buf, "%s_vfunc_%d", shortName.c_str(), i);
                            allNames.push_back({entry, buf});
                            protoSymsAdded++;
                            if (i > 20) break;
                        }
                    }
                }

                // Find callers of serialize (E8 rel32 → serialize RVA)
                if (msg.serializeRVA) {
                    for (int si2 = 0; si2 < pe.numSections; si2++) {
                        if (!pe.isExecutableSection(si2)) continue;
                        uint32_t secRVA = pe.sections[si2].VirtualAddress;
                        uint32_t rawOff2 = pe.sections[si2].PointerToRawData;
                        uint32_t rawSz2 = pe.sections[si2].SizeOfRawData;
                        for (uint32_t p2 = 0; p2 + 5 <= rawSz2; p2++) {
                            if (pe.data[rawOff2 + p2] != 0xE8) continue;
                            int32_t cd = *(int32_t*)(pe.data.data() + rawOff2 + p2 + 1);
                            uint32_t ct = secRVA + p2 + 5 + cd;
                            if (ct == msg.serializeRVA) {
                                // Find function start (scan backward for CC boundary)
                                uint32_t callerRVA = secRVA + p2;
                                uint32_t funcStart = callerRVA;
                                for (int bk = 1; bk < 4096; bk++) {
                                    uint32_t checkOff = rawOff2 + p2 - bk;
                                    if (checkOff < rawOff2) break;
                                    if (pe.data[checkOff] == 0xCC && pe.data[checkOff+1] != 0xCC) {
                                        funcStart = secRVA + p2 - bk + 1;
                                        break;
                                    }
                                }
                                char buf2[128];
                                sprintf_s(buf2, "%s_caller_%X", shortName.c_str(), funcStart);
                                allNames.push_back({actualBase + funcStart, buf2});
                                protoCallersFound++;
                            }
                        }
                    }
                }

            }

            // === Dynamic import caller chain reverse-tracing ===
            // Build reverse call graph from E8 instructions, then trace
            // callers of high-interest import wrappers recursively.
            {
                Timer tChain;

                // Step 1: Build forward call map (E8 scan → callerRVA → targetRVA)
                // and function start map (RVA → estimated function start)
                std::unordered_map<uint32_t, std::vector<uint32_t>> reverseCallMap; // target → callers
                std::unordered_map<uint32_t, uint32_t> funcStartOf; // any RVA → func start

                auto findFuncStart = [&](uint32_t rva) -> uint32_t {
                    uint32_t off = pe.rvaToOffset(rva);
                    if (!off) return rva;
                    for (uint32_t bk = 1; bk < 8192 && off > bk; bk++) {
                        if (pe.data[off - bk] == 0xCC && pe.data[off - bk + 1] != 0xCC)
                            return rva - bk + 1;
                        if (pe.data[off - bk] == 0xC3 && pe.data[off - bk + 1] != 0xC3 &&
                            pe.data[off - bk + 1] != 0xCC && pe.data[off - bk + 1] != 0x90)
                            return rva - bk + 1;
                    }
                    return rva;
                };

                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    if (!pe.isExecutableSection(si2)) continue;
                    uint32_t secRVA = pe.sections[si2].VirtualAddress;
                    uint32_t rawOff2 = pe.sections[si2].PointerToRawData;
                    uint32_t rawSz2 = pe.sections[si2].SizeOfRawData;
                    for (uint32_t p2 = 0; p2 + 5 <= rawSz2; p2++) {
                        if (pe.data[rawOff2 + p2] != 0xE8) continue;
                        int32_t cd = *(int32_t*)(pe.data.data() + rawOff2 + p2 + 1);
                        uint32_t callerRVA = secRVA + p2;
                        int64_t targetRVA64 = (int64_t)callerRVA + 5 + cd;
                        uint32_t targetRVA = (uint32_t)(targetRVA64 & 0xFFFFFFFF);
                        if (targetRVA > 0 && targetRVA < soi)
                            reverseCallMap[targetRVA].push_back(callerRVA);
                    }
                }

                // Step 2: Identify high-interest import wrappers by API name keywords
                const char* interestKeywords[] = {
                    "Firmware", "Registry", "Adapter", "Volume", "Serial",
                    "Crypt", "Hash", "Encrypt", "Decrypt", "Cert",
                    "Token", "Pipe", "Socket", "Send", "Recv",
                    "Process", "Thread", "Module", "DeviceIo",
                    "SMBIOS", "WMI", "Setup"
                };
                constexpr int nKeywords = sizeof(interestKeywords) / sizeof(interestKeywords[0]);

                struct ImportChainEntry {
                    uint32_t funcRVA;
                    std::string label;
                    int depth;
                };
                std::vector<ImportChainEntry> chainEntries;
                std::unordered_set<uint32_t> chainVisited;
                uint32_t chainsTraced = 0;

                for (auto& w : importWrappers) {
                    if (w.apiName.empty()) continue;
                    bool interesting = false;
                    for (int k = 0; k < nKeywords; k++) {
                        if (w.apiName.find(interestKeywords[k]) != std::string::npos) {
                            interesting = true;
                            break;
                        }
                    }
                    if (!interesting) continue;

                    uint32_t wrapRVA = (uint32_t)(w.wrapperVA - actualBase);

                    // BFS reverse trace up to depth 4
                    std::vector<std::pair<uint32_t, int>> bfsQueue; // (targetRVA, depth)
                    bfsQueue.push_back({wrapRVA, 0});

                    for (size_t qi = 0; qi < bfsQueue.size() && qi < 200; qi++) {
                        auto [tgt, depth] = bfsQueue[qi];
                        if (depth > 4) continue;
                        auto it = reverseCallMap.find(tgt);
                        if (it == reverseCallMap.end()) continue;
                        for (uint32_t callerRVA : it->second) {
                            uint32_t fs = findFuncStart(callerRVA);
                            if (chainVisited.count(fs)) continue;
                            chainVisited.insert(fs);

                            char buf3[256];
                            sprintf_s(buf3, "%s_chain_%d_%X", w.apiName.c_str(), depth + 1, fs);
                            chainEntries.push_back({fs, buf3, depth + 1});
                            allNames.push_back({actualBase + fs, buf3});
                            protoSymsAdded++;

                            if (depth + 1 < 4)
                                bfsQueue.push_back({fs, depth + 1});
                        }
                    }
                    if (!chainEntries.empty()) chainsTraced++;
                }

                cli::detail("Import call chains: %u APIs traced, %zu chain functions named (%.0f ms)",
                       chainsTraced, chainEntries.size(), tChain.elapsedMs());
            }

            cli::detail("Proto symbols: %u named, %u serialize callers found",
                   protoSymsAdded, protoCallersFound);
        }

        // Early hidden function discovery — expands known functions before type propagation
        // Validation-based: each source is verified before accepting
        {
            Timer tHidden;
            uint32_t soiH = pe.nt->OptionalHeader.SizeOfImage;
            auto pdataKnown = readPdataFunctions(pe);
            std::unordered_set<uint32_t> knownFuncStarts;
            for (auto& fb : pdataKnown) knownFuncStarts.insert(fb.beginRVA);

            std::unordered_set<uint32_t> discovered;
            uint32_t src1 = 0, src2 = 0, src3 = 0;

            // Source 1 (highest confidence): E8 direct call targets not in .pdata
            // Verification: target must be in exec section AND first byte must not be 00/CC
            for (auto& ref : allRefs) {
                if (!ref.isCall) continue;
                uint32_t t = ref.targetRVA;
                if (t == 0 || t >= soiH) continue;
                if (knownFuncStarts.count(t)) continue;
                int sec = pe.findSection(t);
                if (sec < 0 || !pe.isExecutableSection(sec)) continue;
                uint32_t tOff = pe.rvaToOffset(t);
                if (!tOff || tOff >= pe.data.size()) continue;
                uint8_t firstByte = pe.data[tOff];
                if (firstByte == 0x00 || firstByte == 0xCC) continue;
                discovered.insert(t);
                src1++;
            }

            // Source 2 (high confidence): RTTI vtable method entries not in .pdata
            // Verification: already validated by RTTI parser (code pointers in vtable)
            for (auto& cls : rttiClasses) {
                for (auto& mva : cls.methodVAs) {
                    uint32_t rva = (uint32_t)(mva - actualBase);
                    if (rva > 0 && rva < soiH && !knownFuncStarts.count(rva) && !discovered.count(rva)) {
                        discovered.insert(rva);
                        src2++;
                    }
                }
            }

            // Source 3 (medium confidence): boundary scan with prologue matching
            // Phase 3a: STRICT multi-byte patterns after CC/C3/90/FFE0/E9
            // Phase 3b: RELAXED patterns after CC/C3/90 (broader coverage)
            for (int si = 0; si < pe.numSections; si++) {
                if (!pe.isExecutableSection(si)) continue;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                uint32_t secRVA = pe.sections[si].VirtualAddress;
                for (uint32_t p = 2; p + 4 < rawSz; p++) {
                    uint8_t prev = pe.data[rawOff + p - 1];
                    uint8_t prev2 = pe.data[rawOff + p - 2];
                    // Standard boundaries: CC, C3 (ret), 90 (nop)
                    bool isBoundary = (prev == 0xCC || prev == 0xC3 || prev == 0x90);
                    // Extended: FF E0 (jmp rax), FF E1..E7 (jmp reg), 41 FF E0..E7 (jmp r8-r15)
                    if (!isBoundary && prev == 0xE0 && prev2 == 0xFF) isBoundary = true;
                    if (!isBoundary && prev >= 0xE0 && prev <= 0xE7 && prev2 == 0xFF) isBoundary = true;
                    if (!isBoundary && prev == 0xE0 && prev2 == 0xFF) isBoundary = true;
                    // E9 + 4-byte disp (jmp rel32): check if p-5 has E9
                    if (!isBoundary && p >= 5 && pe.data[rawOff + p - 5] == 0xE9) isBoundary = true;
                    if (!isBoundary) continue;
                    uint32_t rva = secRVA + p;
                    if (knownFuncStarts.count(rva) || discovered.count(rva)) continue;
                    const uint8_t* b = pe.data.data() + rawOff + p;
                    if (b[0] == 0xCC || b[0] == 0x90 || b[0] == 0x00) continue;
                    bool valid = false;
                    // Strict: 3-byte match
                    if (b[0]==0x48 && b[1]==0x83 && b[2]==0xEC) valid = true;
                    if (b[0]==0x48 && b[1]==0x81 && b[2]==0xEC) valid = true;
                    if (b[0]==0x48 && b[1]==0x89 && (b[2]&0xC7)==0x44) valid = true; // mov [rsp+X], reg
                    if (b[0]==0x48 && b[1]==0x8B && b[2]==0xC4) valid = true;
                    // 2-byte match with boundary confirmation
                    if (prev == 0xCC || prev == 0xC3) {
                        if (b[0]==0x55 && (b[1]==0x48 || b[1]==0x41)) valid = true;
                        if (b[0]==0x53 && (b[1]==0x48 || b[1]==0x41)) valid = true;
                        if (b[0]==0x56 && (b[1]==0x48 || b[1]==0x57)) valid = true;
                        if (b[0]==0x57 && (b[1]==0x48 || b[1]==0x56)) valid = true;
                        if (b[0]==0x41 && b[1]>=0x54 && b[1]<=0x57) valid = true;
                        if (b[0]==0x40 && b[1]>=0x53 && b[1]<=0x57) valid = true;
                        if (b[0]==0x4C && b[1]==0x89) valid = true;
                        if (b[0]==0x4C && b[1]==0x8B) valid = true;
                        if (b[0]==0x44 && (b[1]==0x88 || b[1]==0x89)) valid = true;
                        if (b[0]==0x89 && (b[1]==0x4C || b[1]==0x54)) valid = true;
                    }
                    if (!valid) continue;
                    // Instruction stream validation: decode >= 3 valid instructions
                    uint32_t fOff2 = rawOff + p;
                    uint32_t remain = rawSz - p;
                    int validInsns = 0;
                    uint32_t ipos = 0;
                    for (int ni = 0; ni < 8 && ipos + 1 < remain; ni++) {
                        // Minimal instruction length check
                        uint8_t ib = pe.data[fOff2 + ipos];
                        if (ib == 0x00 || ib == 0xCC) break;
                        // Use simple heuristic: REX prefix + opcode = >= 2 bytes
                        uint32_t ilen = 1;
                        if ((ib & 0xF0) == 0x40) ilen++; // REX
                        if (ib == 0x0F || ib == 0x66 || ib == 0xF2 || ib == 0xF3) ilen++; // prefix
                        uint8_t op = pe.data[fOff2 + ipos + (ilen > 1 ? 1 : 0)];
                        // ModRM-based → add modrm + potential SIB/disp
                        if (op >= 0x80 && op <= 0x8F) ilen += 2;
                        else if (op == 0xE8 || op == 0xE9) ilen += 4;
                        else if (op == 0xEB) ilen += 1;
                        else if (op >= 0xB8 && op <= 0xBF) ilen += 4;
                        else ilen += 1;
                        if (ilen > 15 || ipos + ilen > remain) break;
                        validInsns++;
                        ipos += ilen;
                    }
                    if (validInsns >= 3) { discovered.insert(rva); src3++; }
                }
            }

            // Build FuncBoundary entries with estimated end addresses
            std::vector<uint32_t> allStarts;
            for (auto& fb : pdataKnown) allStarts.push_back(fb.beginRVA);
            for (uint32_t rva : discovered) allStarts.push_back(rva);
            std::sort(allStarts.begin(), allStarts.end());
            allStarts.erase(std::unique(allStarts.begin(), allStarts.end()), allStarts.end());

            for (uint32_t rva : discovered) {
                auto it = std::upper_bound(allStarts.begin(), allStarts.end(), rva);
                uint32_t endRVA = (it != allStarts.end()) ? *it : rva + 0x100;
                if (endRVA - rva > 0x10000) endRVA = rva + 0x1000; // cap at 64KB
                extraFunctions.push_back({rva, endRVA});
            }

            cli::ok("Hidden function discovery: %zu new (%u call-target + %u vtable + %u boundary) (%.0f ms)",
                   discovered.size(), src1, src2, src3, tHidden.elapsedMs());
        }

        // Resolve vtable calls in .text protobuf functions via constprop
        if (protoScan) {
            Timer tVtProp;
            uint32_t vtCallResolved = 0;
            auto protoResult2 = scanAllProtoMessages(pe, actualBase);
            uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

            // Collect all protobuf function RVAs (vtable methods)
            std::set<uint32_t> protoFuncRVAs;
            for (auto& msg : protoResult2.messages) {
                if (msg.serializeRVA) protoFuncRVAs.insert(msg.serializeRVA);
                if (msg.vtableRVA) {
                    uint32_t vtOff = pe.rvaToOffset(msg.vtableRVA);
                    if (vtOff) {
                        for (int i = 0; vtOff + (i+1)*8 <= pe.data.size(); i++) {
                            uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i*8);
                            if (entry < actualBase || entry >= actualBase + soi) break;
                            protoFuncRVAs.insert((uint32_t)(entry - actualBase));
                        }
                    }
                }
            }

            // For each message, find default_instance (the object whose vtable ptr
            // is stored in .rdata and referenced by serialize as comparison target).
            // Then run constprop on vtable members with rcx = default_instance.
            std::unordered_map<uint32_t, uint32_t> funcToDefaultInst; // funcRVA → defaultInst RVA
            for (auto& msg : protoResult2.messages) {
                if (!msg.vtableRVA) continue;
                uint64_t vtableVA = actualBase + msg.vtableRVA;
                // Find default_instance: scan .rdata for a qword == vtableVA
                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si2].Name, 8);
                    if (strcmp(sn, ".rdata") != 0 && strcmp(sn, ".data") != 0) continue;
                    uint32_t raw2 = pe.sections[si2].PointerToRawData;
                    uint32_t sz2 = pe.sections[si2].SizeOfRawData;
                    uint32_t va2 = pe.sections[si2].VirtualAddress;
                    for (uint32_t p = 0; p + 8 <= sz2; p += 8) {
                        if (*(uint64_t*)(pe.data.data() + raw2 + p) == vtableVA) {
                            uint32_t defaultInstRVA = va2 + p;
                            // Map all vtable members to this default_instance
                            uint32_t vtOff = pe.rvaToOffset(msg.vtableRVA);
                            if (vtOff) {
                                for (int i = 0; vtOff + (i+1)*8 <= pe.data.size(); i++) {
                                    uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + i*8);
                                    if (entry < actualBase || entry >= actualBase + soi) break;
                                    funcToDefaultInst[(uint32_t)(entry - actualBase)] = defaultInstRVA;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            // Also seed RTTI class vtable methods
            for (auto& cls : rttiClasses) {
                if (cls.vtableVA < actualBase) continue;
                uint64_t clsVtVA = cls.vtableVA;
                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si2].Name, 8);
                    if (strcmp(sn, ".rdata") != 0 && strcmp(sn, ".data") != 0) continue;
                    uint32_t raw2 = pe.sections[si2].PointerToRawData;
                    uint32_t sz2 = pe.sections[si2].SizeOfRawData;
                    uint32_t va2 = pe.sections[si2].VirtualAddress;
                    for (uint32_t p = 0; p + 8 <= sz2; p += 8) {
                        if (*(uint64_t*)(pe.data.data() + raw2 + p) == clsVtVA) {
                            uint32_t diRVA = va2 + p;
                            for (auto& mva : cls.methodVAs) {
                                uint32_t mRVA = (uint32_t)(mva - actualBase);
                                if (mRVA > 0 && mRVA < soi && !funcToDefaultInst.count(mRVA))
                                    funcToDefaultInst[mRVA] = diRVA;
                            }
                            break;
                        }
                    }
                }
            }
            cli::detail("%zu funcs mapped to default_instances (%zu proto + RTTI)",
                   funcToDefaultInst.size(), funcToDefaultInst.size());

            // Interprocedural type propagation + vtable call resolution
            // Phase 1: Propagate types along call graph
            //   - Start: vtable members have rcx = default_instance
            //   - For each typed function, scan E8 calls
            //   - If callee receives this pointer → callee gets same type
            //   - Repeat until fixpoint
            std::unordered_map<uint32_t, uint32_t> funcType; // funcRVA -> vtableRVA (direct)
            // Convert funcToDefaultInst seeds to direct vtable RVA mapping
            for (auto& [fRVA, diRVA] : funcToDefaultInst) {
                uint32_t diOff = pe.rvaToOffset(diRVA);
                if (diOff && diOff + 8 <= pe.data.size()) {
                    uint64_t vtVA2 = *(uint64_t*)(pe.data.data() + diOff);
                    if (vtVA2 >= actualBase && vtVA2 < actualBase + soi)
                        funcType[fRVA] = (uint32_t)(vtVA2 - actualBase);
                }
            }
            // Also seed ALL RTTI class methods directly (no default_instance needed)
            for (auto& cls : rttiClasses) {
                if (cls.vtableVA < actualBase) continue;
                uint32_t vtRVA2 = (uint32_t)(cls.vtableVA - actualBase);
                for (auto& mva : cls.methodVAs) {
                    uint32_t mRVA = (uint32_t)(mva - actualBase);
                    if (mRVA > 0 && mRVA < soi && !funcType.count(mRVA))
                        funcType[mRVA] = vtRVA2;
                }
            }
            // Seed from ALL .rdata function pointer arrays (covers non-RTTI vtables)
            for (int si2 = 0; si2 < pe.numSections; si2++) {
                char sn2[9] = {}; memcpy(sn2, pe.sections[si2].Name, 8);
                if (strcmp(sn2, ".rdata") != 0) continue;
                uint32_t raw2 = pe.sections[si2].PointerToRawData;
                uint32_t sz2 = pe.sections[si2].SizeOfRawData;
                uint32_t va2 = pe.sections[si2].VirtualAddress;
                for (uint32_t p = 0; p + 32 <= sz2; p += 8) {
                    int cc = 0;
                    for (int e = 0; e < 40 && p + (e+1)*8 <= sz2; e++) {
                        uint64_t v = *(uint64_t*)(pe.data.data() + raw2 + p + e*8);
                        if (v >= actualBase && v < actualBase + soi) {
                            int s3 = pe.findSection((uint32_t)(v - actualBase));
                            if (s3 >= 0 && pe.isExecutableSection(s3)) { cc++; continue; }
                        }
                        break;
                    }
                    if (cc >= 4) {
                        uint32_t vtRVA3 = va2 + p;
                        for (int e = 0; e < cc; e++) {
                            uint64_t v = *(uint64_t*)(pe.data.data() + raw2 + p + e*8);
                            uint32_t mRVA = (uint32_t)(v - actualBase);
                            if (!funcType.count(mRVA))
                                funcType[mRVA] = vtRVA3;
                        }
                        p += cc * 8 - 8;
                    }
                }
            }

            // Build call graph from .text E8 instructions
            struct CallEdge { uint32_t callerRVA; uint32_t calleeRVA; uint32_t callSiteRVA; };
            std::unordered_map<uint32_t, std::vector<CallEdge>> callerToEdges;
            {
                int textSec = -1;
                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si2].Name, 8);
                    if (strcmp(sn, ".text") == 0) { textSec = si2; break; }
                }
                if (textSec >= 0) {
                    uint32_t tRaw = pe.sections[textSec].PointerToRawData;
                    uint32_t tSz = pe.sections[textSec].SizeOfRawData;
                    uint32_t tVA = pe.sections[textSec].VirtualAddress;
                    // Sorted function starts for binary search
                    auto pdataAll = readPdataFunctions(pe);
                    std::vector<uint32_t> funcStarts;
                    for (auto& fb : pdataAll)
                        if (fb.beginRVA >= tVA && fb.beginRVA < tVA + tSz)
                            funcStarts.push_back(fb.beginRVA);
                    // Include hidden functions in call graph
                    for (auto& fb : extraFunctions)
                        if (fb.beginRVA >= tVA && fb.beginRVA < tVA + tSz)
                            funcStarts.push_back(fb.beginRVA);
                    std::sort(funcStarts.begin(), funcStarts.end());
                    funcStarts.erase(std::unique(funcStarts.begin(), funcStarts.end()), funcStarts.end());

                    for (uint32_t p = 0; p + 5 < tSz; p++) {
                        uint32_t off = tRaw + p;
                        if (pe.data[off] != 0xE8) continue;
                        int32_t disp = *(int32_t*)(pe.data.data() + off + 1);
                        uint32_t callSiteRVA = tVA + p;
                        uint32_t calleeRVA = callSiteRVA + 5 + disp;
                        if (calleeRVA < tVA || calleeRVA >= tVA + tSz) continue;
                        // Find containing function
                        auto it = std::upper_bound(funcStarts.begin(), funcStarts.end(), callSiteRVA);
                        if (it == funcStarts.begin()) continue;
                        uint32_t callerRVA = *--it;
                        callerToEdges[callerRVA].push_back({callerRVA, calleeRVA, callSiteRVA});
                    }
                }
            }

            // Also seed: any function that CALLS a constructor/New gets the return type
            // text_E09E0 returns AuthReq*, text_DC880 takes AuthReq* as first arg
            // Find callers of known constructors and add them as seeds
            for (auto& msg : protoResult2.messages) {
                if (!msg.vtableRVA) continue;
                // Find New function: scan for calls to constructor from New-like patterns
                // Simpler: find all E8 calls to constructor addresses
                uint32_t ctorRVA = 0;
                // Constructor = vtable[0] typically, or we know DC880 for AuthReq
                // Use the first vtable entry as a heuristic
                uint32_t vtOff = pe.rvaToOffset(msg.vtableRVA);
                if (!vtOff) continue;
                // Find default_instance for this message
                uint64_t vtVA = actualBase + msg.vtableRVA;
                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si2].Name, 8);
                    if (strcmp(sn, ".rdata") != 0 && strcmp(sn, ".data") != 0) continue;
                    uint32_t raw2 = pe.sections[si2].PointerToRawData;
                    uint32_t sz2 = pe.sections[si2].SizeOfRawData;
                    uint32_t va2 = pe.sections[si2].VirtualAddress;
                    for (uint32_t p = 0; p + 8 <= sz2; p += 8) {
                        if (*(uint64_t*)(pe.data.data() + raw2 + p) == vtVA) {
                            uint32_t diRVA = va2 + p;
                            // Scan callers of all vtable methods — add callers as seeds
                            for (auto& [callerRVA, edges] : callerToEdges) {
                                for (auto& edge : edges) {
                                    if (funcToDefaultInst.count(edge.calleeRVA)) {
                                        if (!funcType.count(callerRVA)) {
                                            funcType[callerRVA] = funcToDefaultInst[edge.calleeRVA];
                                        }
                                    }
                                }
                            }
                            goto done_seed;
                        }
                    }
                }
                done_seed:;
            }

            // Worklist propagation (bidirectional: caller->callee + callee->caller)
            // Also build reverse call graph
            std::unordered_map<uint32_t, std::vector<uint32_t>> calleeToCallers;
            for (auto& [callerRVA, edges] : callerToEdges)
                for (auto& edge : edges)
                    calleeToCallers[edge.calleeRVA].push_back(callerRVA);

            size_t seedCount = funcType.size();
            std::queue<uint32_t> typeWorklist;
            for (auto& [fRVA, vtRVA] : funcType) typeWorklist.push(fRVA);
            int typeIterations = 0;
            while (!typeWorklist.empty() && typeIterations < 30000) {
                uint32_t fRVA = typeWorklist.front(); typeWorklist.pop();
                uint32_t vtRVA = funcType[fRVA];
                typeIterations++;

                // Forward: typed function's callees get same type
                auto eit = callerToEdges.find(fRVA);
                if (eit != callerToEdges.end()) {
                    for (auto& edge : eit->second) {
                        if (!funcType.count(edge.calleeRVA)) {
                            funcType[edge.calleeRVA] = vtRVA;
                            typeWorklist.push(edge.calleeRVA);
                        }
                    }
                }
                // Reverse: typed function's callers get same type
                auto cit = calleeToCallers.find(fRVA);
                if (cit != calleeToCallers.end()) {
                    for (uint32_t callerRVA : cit->second) {
                        if (!funcType.count(callerRVA)) {
                            funcType[callerRVA] = vtRVA;
                            typeWorklist.push(callerRVA);
                        }
                    }
                }
            }
            std::unordered_set<uint32_t> distinctVtRVAs;
            for (auto& [f, vt] : funcType) distinctVtRVAs.insert(vt);
            cli::detail("Type propagation: %zu typed funcs, %zu distinct vtables (from %zu seeds, %d iterations)",
                   funcType.size(), distinctVtRVAs.size(), seedCount, typeIterations);

            // funcType already maps funcRVA -> vtableRVA directly
            // Return type map: typed functions return typed pointers
            std::unordered_map<uint32_t, uint32_t> returnTypeMap;
            for (auto& [fRVA, vtRVA] : funcType)
                returnTypeMap[fRVA] = vtRVA;

            // Build vtableRVA → defaultInstRVA map for concrete address seeding
            // This enables struct field access via PE memory reads
            std::unordered_map<uint32_t, uint32_t> vtToDefaultInst;
            for (auto& [fRVA, diRVA] : funcToDefaultInst) {
                uint32_t diOff = pe.rvaToOffset(diRVA);
                if (!diOff || diOff + 8 > pe.data.size()) continue;
                uint64_t vtVA3 = *(uint64_t*)(pe.data.data() + diOff);
                if (vtVA3 >= actualBase && vtVA3 < actualBase + soi) {
                    uint32_t vtRVA3 = (uint32_t)(vtVA3 - actualBase);
                    if (!vtToDefaultInst.count(vtRVA3))
                        vtToDefaultInst[vtRVA3] = diRVA;
                }
            }
            cli::detail("%zu vtables with default_instances for field access", vtToDefaultInst.size());

            // Build field type map: (vtableRVA << 32 | fieldOffset) → sub-vtableRVA
            // Sources: 1) protobuf MESSAGE fields, 2) default_instance field scan
            std::unordered_map<uint64_t, uint32_t> fieldTypeMap;
            {
                std::unordered_set<uint64_t> knownVtableVAs;
                for (auto& [vt, di] : vtToDefaultInst) knownVtableVAs.insert(actualBase + vt);
                for (auto& cls : rttiClasses) knownVtableVAs.insert(cls.vtableVA);

                // Source 1: Protobuf MESSAGE fields → sub-message vtable
                // For each message with a vtable, find its default_instance, scan MESSAGE fields
                uint32_t protoFieldMaps = 0;
                for (auto& msg : protoResult2.messages) {
                    if (!msg.vtableRVA) continue;
                    // Find default_instance for this message via vtToDefaultInst
                    auto diIt2 = vtToDefaultInst.find(msg.vtableRVA);
                    if (diIt2 == vtToDefaultInst.end()) continue;
                    uint32_t diOff = pe.rvaToOffset(diIt2->second);
                    if (!diOff) continue;
                    for (auto& field : msg.fields) {
                        if (field.type != ProtoField::MESSAGE || field.structOffset == 0) continue;
                        uint32_t fOff = field.structOffset;
                        if (diOff + fOff + 8 > pe.data.size()) continue;
                        uint64_t subPtr = *(uint64_t*)(pe.data.data() + diOff + fOff);
                        if (subPtr < actualBase || subPtr >= actualBase + soi) continue;
                        uint32_t subObjOff = pe.rvaToOffset((uint32_t)(subPtr - actualBase));
                        if (!subObjOff || subObjOff + 8 > pe.data.size()) continue;
                        uint64_t subVtVA = *(uint64_t*)(pe.data.data() + subObjOff);
                        if (knownVtableVAs.count(subVtVA)) {
                            uint32_t subVtRVA = (uint32_t)(subVtVA - actualBase);
                            uint64_t key = ((uint64_t)msg.vtableRVA << 32) | fOff;
                            fieldTypeMap[key] = subVtRVA;
                            protoFieldMaps++;
                        }
                    }
                }

                // Source 2: Brute-force scan default_instance fields for object pointers
                uint32_t bruteFieldMaps = 0;
                for (auto& [vtRVA, diRVA] : vtToDefaultInst) {
                    uint32_t diOff = pe.rvaToOffset(diRVA);
                    if (!diOff) continue;
                    for (uint32_t fOff = 8; diOff + fOff + 8 <= pe.data.size() && fOff < 0x200; fOff += 8) {
                        uint64_t key = ((uint64_t)vtRVA << 32) | fOff;
                        if (fieldTypeMap.count(key)) continue;
                        uint64_t fieldVal = *(uint64_t*)(pe.data.data() + diOff + fOff);
                        if (fieldVal < actualBase || fieldVal >= actualBase + soi) continue;
                        uint32_t objOff = pe.rvaToOffset((uint32_t)(fieldVal - actualBase));
                        if (!objOff || objOff + 8 > pe.data.size()) continue;
                        uint64_t subVtVA = *(uint64_t*)(pe.data.data() + objOff);
                        if (knownVtableVAs.count(subVtVA)) {
                            fieldTypeMap[key] = (uint32_t)(subVtVA - actualBase);
                            bruteFieldMaps++;
                        }
                    }
                }
                cli::detail("%u proto + %u brute = %zu field type mappings",
                       protoFieldMaps, bruteFieldMaps, fieldTypeMap.size());
            }

            // Phase 2: For EVERY .text function with vtable calls,
            // try each known vtable as rcx type → brute force but correct
            auto pdataAll2 = readPdataFunctions(pe);
            // Merge hidden functions into the function list
            pdataAll2.insert(pdataAll2.end(), extraFunctions.begin(), extraFunctions.end());
            int textSec2 = -1;
            for (int si2 = 0; si2 < pe.numSections; si2++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si2].Name, 8);
                if (strcmp(sn, ".text") == 0) { textSec2 = si2; break; }
            }
            uint32_t textVA2 = textSec2 >= 0 ? pe.sections[textSec2].VirtualAddress : 0;
            uint32_t textEnd2 = textVA2 + (textSec2 >= 0 ? pe.sections[textSec2].Misc.VirtualSize : 0);

            // Phase 2: Resolve vtable calls via constprop
            // A) Typed functions: constprop with typed pointer (1 run/function)
            // B) Untyped functions: constprop without typed pointer (concrete value resolution)
            GriffinDisasm textDisasm(pe, actualBase);
            uint32_t totalVtCallSites = 0;

            // A) Iterative constprop: run multiple passes until fixpoint
            // Each pass resolves vtable calls → patched to E8 → next pass gets return types
            std::unordered_set<uint32_t> globalPatchedSites;
            // Convert funcType to vector for indexed parallel access
            std::vector<std::pair<uint32_t,uint32_t>> funcTypeVec(funcType.begin(), funcType.end());

            for (int pass = 0; pass < 2; pass++) {
                std::atomic<uint32_t> passResolved{0}, vtIdx{0};
                uint32_t numT = std::min(std::thread::hardware_concurrency(), 8u);
                if (numT < 1) numT = 4;
                std::mutex vtMtx;

                auto vtWorker = [&]() {
                    struct PatchInfo {
                        uint32_t callRVA, targetRVA, patchRVA, patchOff;
                        uint8_t totalLen, opcode;
                    };
                    std::vector<PatchInfo> localPatches;
                    while (true) {
                        uint32_t i = vtIdx.fetch_add(1);
                        if (i >= funcTypeVec.size()) break;
                        auto [fRVA, vtRVA2] = funcTypeVec[i];

                        GriffinDisasm td(pe, actualBase);
                        GrFunc tf;
                        if (!td.buildCFG(fRVA, tf)) continue;

                        auto origBlocks = tf.blocks;
                        for (GrReg seedReg : {GrReg::RCX, GrReg::RDX, GrReg::R8, GrReg::R9,
                                              GrReg::RBX, GrReg::RSI, GrReg::RDI}) {
                            tf.blocks = origBlocks;
                            GriffinConstProp cp;
                            cp.setPE(&pe, actualBase);
                            cp.setReturnTypes(&returnTypeMap);
                            cp.setFieldTypes(&fieldTypeMap);
                            cp.setTypedPtr(seedReg, vtRVA2);
                            cp.run(tf);

                            for (auto& blk : tf.blocks)
                                for (auto& instr : blk.instrs) {
                                    bool isCall = (instr.op == GrOp::CALL);
                                    bool isJmp  = (instr.op == GrOp::JMP);
                                    if (!isCall && !isJmp) continue;
                                    if (!instr.simplified) continue;
                                    if (instr.dst.kind != GrValue::LABEL || instr.dst.imm <= 0) continue;

                                    uint64_t targetRva64 = (uint64_t)instr.dst.imm - actualBase;
                                    if (targetRva64 == 0 || targetRva64 >= soi) continue;
                                    uint32_t targetRVA = (uint32_t)targetRva64;
                                    uint32_t callRVA = (uint32_t)(instr.addr - actualBase);
                                    uint32_t off = pe.rvaToOffset(callRVA);
                                    if (!off || off + instr.rawLen > pe.data.size()) continue;

                                    // ConstProp rewrote dst to LABEL; decode the original base
                                    // reg from raw bytes so we can match the preceding mov.
                                    int callBaseReg = -1;
                                    uint8_t b0 = pe.data[off];
                                    if (b0 >= 0x40 && b0 <= 0x4F && off + 2 < pe.data.size() && pe.data[off+1] == 0xFF) {
                                        callBaseReg = (pe.data[off+2] & 7) + ((b0 & 1) ? 8 : 0);
                                    } else if (b0 == 0xFF && off + 1 < pe.data.size()) {
                                        callBaseReg = pe.data[off+1] & 7;
                                    }
                                    if (callBaseReg < 0) continue;

                                    uint32_t patchOff = off, patchRVA = callRVA, totalLen = instr.rawLen;
                                    auto tryAbsorb = [&](uint32_t movLen, uint8_t expectedMod) -> bool {
                                        if (off < movLen) return false;
                                        uint8_t rex = pe.data[off - movLen];
                                        if ((rex & 0xF8) != 0x48) return false;
                                        if (pe.data[off - movLen + 1] != 0x8B) return false;
                                        uint8_t modrm = pe.data[off - movLen + 2];
                                        if ((modrm >> 6) != expectedMod) return false;
                                        uint8_t rm = modrm & 7;
                                        if (rm == 4) return false;
                                        if (expectedMod == 0 && rm == 5) return false;
                                        int movDst = ((modrm >> 3) & 7) + ((rex & 0x04) ? 8 : 0);
                                        if (movDst != callBaseReg) return false;
                                        patchOff  = off - movLen;
                                        patchRVA  = callRVA - movLen;
                                        totalLen  = movLen + instr.rawLen;
                                        return true;
                                    };
                                    tryAbsorb(3, 0) || tryAbsorb(4, 1) || tryAbsorb(7, 2);

                                    if (totalLen >= 5) {
                                        PatchInfo p;
                                        p.callRVA   = callRVA;
                                        p.targetRVA = targetRVA;
                                        p.patchRVA  = patchRVA;
                                        p.patchOff  = patchOff;
                                        p.totalLen  = (uint8_t)totalLen;
                                        p.opcode    = isJmp ? 0xE9 : 0xE8;
                                        localPatches.push_back(p);
                                    }
                                }
                        }

                        if (i % 2000 == 0) {
                            printf("\r      [PhaseA] %u/%zu (%.1fs)  ", i, funcTypeVec.size(), tVtProp.elapsedMs()/1000.0);
                            fflush(stdout);
                        }
                    }

                    std::lock_guard<std::mutex> lk(vtMtx);
                    for (auto& p : localPatches) {
                        if (globalPatchedSites.count(p.callRVA)) continue;
                        int32_t d = (int32_t)(p.targetRVA - (p.patchRVA + 5));
                        pe.data[p.patchOff] = p.opcode;
                        memcpy(pe.data.data() + p.patchOff + 1, &d, 4);
                        for (uint32_t n = 5; n < p.totalLen; n++) pe.data[p.patchOff + n] = 0x90;
                        globalPatchedSites.insert(p.callRVA);
                        vtCallResolved++;
                        passResolved++;
                    }
                };

                std::vector<std::thread> threads;
                for (uint32_t t = 0; t < numT; t++) threads.emplace_back(vtWorker);
                for (auto& t : threads) t.join();

                printf("\r      Phase A pass %d: +%u (total %u) (%.1fs)              \n",
                       pass+1, passResolved.load(), vtCallResolved, tVtProp.elapsedMs()/1000.0);
                if (passResolved.load() == 0) break;
            }

            // Diagnose: count unpatched vtable call sites (3-byte mov + call disp form).
            // Patched sites have their REX byte rewritten to E8/E9 and fall out of the scan.
            {
                uint32_t unpatchedSites = 0, inTyped = 0, inUntyped = 0;
                for (auto& fb : pdataAll2) {
                    if (fb.beginRVA < textVA2 || fb.beginRVA >= textEnd2) continue;
                    uint32_t fOff2 = pe.rvaToOffset(fb.beginRVA);
                    if (!fOff2) continue;
                    uint32_t fSz = fb.endRVA - fb.beginRVA;
                    for (uint32_t i = 3; i + 3 < fSz && i < 0x2000; i++) {
                        uint8_t b0 = pe.data[fOff2+i-3], b1 = pe.data[fOff2+i-2], b2 = pe.data[fOff2+i-1];
                        if ((b0 & 0xF8) != 0x48) continue; // REX.W
                        if (b1 != 0x8B) continue;
                        uint8_t mod = b2 >> 6, rm = b2 & 7;
                        if (mod != 0 || rm == 4 || rm == 5) continue;
                        // Check FF 50/90 follows
                        if (pe.data[fOff2+i] != 0xFF) continue;
                        uint8_t cm = pe.data[fOff2+i+1];
                        if (((cm >> 3) & 7) != 2) continue;
                        uint8_t cmod = cm >> 6;
                        if (cmod != 1 && cmod != 2) continue;
                        uint32_t callRVA = fb.beginRVA + i;
                        if (globalPatchedSites.count(callRVA)) continue;
                        unpatchedSites++;
                        if (funcType.count(fb.beginRVA)) inTyped++;
                        else inUntyped++;
                    }
                }
                cli::detail("[vtable-diag] %u patched, %u unpatched (%u in typed funcs, %u in untyped)",
                       (uint32_t)globalPatchedSites.size(), unpatchedSites, inTyped, inUntyped);
            }

            // B) Untyped functions: try all known vtables (small set so affordable)
            uint32_t phaseB = 0;
            std::vector<uint32_t> allSeedVtRVAs;
            for (uint32_t vt : distinctVtRVAs) allSeedVtRVAs.push_back(vt);

            for (auto& fb : pdataAll2) {
                if (fb.beginRVA < textVA2 || fb.beginRVA >= textEnd2) continue;
                uint32_t fSize = fb.endRVA - fb.beginRVA;
                if (fSize < 0x10 || fSize > 0x8000) continue;
                if (funcType.count(fb.beginRVA)) continue;

                uint32_t fOff = pe.rvaToOffset(fb.beginRVA);
                if (!fOff) continue;

                bool hasVtCall = false;
                for (uint32_t i = 0; i + 2 < fSize && i < 0x2000; i++) {
                    if (pe.data[fOff+i] != 0xFF) continue;
                    uint8_t modrm = pe.data[fOff+i+1];
                    uint8_t opExt = (modrm >> 3) & 7;
                    if ((opExt == 2 || opExt == 4) && (modrm >> 6) >= 1 && (modrm >> 6) <= 2) {
                        hasVtCall = true; break;
                    }
                }
                if (!hasVtCall) continue;
                totalVtCallSites++;

                GrFunc tf;
                if (!textDisasm.buildCFG(fb.beginRVA, tf)) continue;
                auto origB = tf.blocks;

                struct SiteInfo { std::set<uint32_t> targets; uint8_t rawLen; bool isJmp; };
                std::unordered_map<uint32_t, SiteInfo> siteInfoB;
                for (uint32_t vtRVA : allSeedVtRVAs) {
                    for (GrReg reg : {GrReg::RCX, GrReg::RDX, GrReg::R8}) {
                        tf.blocks = origB;
                        GriffinConstProp cp;
                        cp.setPE(&pe, actualBase);
                        cp.setReturnTypes(&returnTypeMap);
                        cp.setFieldTypes(&fieldTypeMap);
                        cp.setTypedPtr(reg, vtRVA);
                        cp.run(tf);

                        for (auto& blk : tf.blocks) {
                            for (auto& instr : blk.instrs) {
                                bool isCall = (instr.op == GrOp::CALL);
                                bool isJmp  = (instr.op == GrOp::JMP);
                                if (!isCall && !isJmp) continue;
                                if (!instr.simplified) continue;
                                if (instr.dst.kind != GrValue::LABEL || instr.dst.imm <= 0) continue;
                                uint64_t targetRva64 = (uint64_t)instr.dst.imm - actualBase;
                                if (targetRva64 == 0 || targetRva64 >= soi) continue;
                                uint32_t targetRVA = (uint32_t)targetRva64;
                                uint32_t callRVA = (uint32_t)(instr.addr - actualBase);
                                if (globalPatchedSites.count(callRVA)) continue;
                                auto& s = siteInfoB[callRVA];
                                s.targets.insert(targetRVA);
                                s.rawLen = instr.rawLen;
                                s.isJmp = isJmp;
                            }
                        }
                    }
                }

                for (auto& [callRVA, s] : siteInfoB) {
                    if (s.targets.size() != 1) continue;
                    if (globalPatchedSites.count(callRVA)) continue;
                    uint32_t targetRVA = *s.targets.begin();
                    uint32_t off = pe.rvaToOffset(callRVA);
                    if (!off) continue;

                    int callBaseReg = -1;
                    uint8_t b0 = pe.data[off];
                    if (b0 >= 0x40 && b0 <= 0x4F && off + 2 < pe.data.size() && pe.data[off+1] == 0xFF) {
                        callBaseReg = (pe.data[off+2] & 7) + ((b0 & 1) ? 8 : 0);
                    } else if (b0 == 0xFF && off + 1 < pe.data.size()) {
                        callBaseReg = pe.data[off+1] & 7;
                    }
                    if (callBaseReg < 0) continue;

                    uint32_t patchOff = off, patchRVA = callRVA, totalLen = s.rawLen;
                    auto tryAbsorbB = [&](uint32_t movLen, uint8_t expectedMod) -> bool {
                        if (off < movLen) return false;
                        uint8_t rex = pe.data[off - movLen];
                        if ((rex & 0xF8) != 0x48) return false;
                        if (pe.data[off - movLen + 1] != 0x8B) return false;
                        uint8_t modrm = pe.data[off - movLen + 2];
                        if ((modrm >> 6) != expectedMod) return false;
                        uint8_t rm = modrm & 7;
                        if (rm == 4) return false;
                        if (expectedMod == 0 && rm == 5) return false;
                        int movDst = ((modrm >> 3) & 7) + ((rex & 0x04) ? 8 : 0);
                        if (movDst != callBaseReg) return false;
                        patchOff = off - movLen; patchRVA = callRVA - movLen;
                        totalLen = movLen + s.rawLen;
                        return true;
                    };
                    tryAbsorbB(3, 0) || tryAbsorbB(4, 1) || tryAbsorbB(7, 2);

                    if (totalLen >= 5) {
                        int32_t d = (int32_t)(targetRVA - (patchRVA + 5));
                        pe.data[patchOff] = s.isJmp ? 0xE9 : 0xE8;
                        memcpy(pe.data.data() + patchOff + 1, &d, 4);
                        for (uint32_t n = 5; n < totalLen; n++) pe.data[patchOff+n] = 0x90;
                        globalPatchedSites.insert(callRVA);
                        vtCallResolved++;
                        phaseB++;
                    }
                }
            }
            cli::detail("Phase B (untyped brute): %u resolved (%u funcs scanned)",
                   phaseB, totalVtCallSites);

            // C) Vtable slot consensus: for each remaining CALL [rax+N],
            // check if ALL known vtables have the SAME target at slot N/8.
            // If so, the call target is unambiguous regardless of object type.
            uint32_t phaseC = 0;
            {
                // Build slot → set<target> map from ALL known vtable arrays
                // (reuse the .rdata scan data)
                struct VtSlotInfo { uint32_t entryCount; uint32_t vtOff; };
                std::vector<VtSlotInfo> vtInfos;
                for (int si2 = 0; si2 < pe.numSections; si2++) {
                    char sn2[9] = {}; memcpy(sn2, pe.sections[si2].Name, 8);
                    if (strcmp(sn2, ".rdata") != 0) continue;
                    uint32_t raw2 = pe.sections[si2].PointerToRawData;
                    uint32_t sz2 = pe.sections[si2].SizeOfRawData;
                    for (uint32_t p = 0; p + 32 <= sz2; p += 8) {
                        int cc = 0;
                        for (int e = 0; e < 60 && p + (e+1)*8 <= sz2; e++) {
                            uint64_t v = *(uint64_t*)(pe.data.data() + raw2 + p + e*8);
                            if (v >= actualBase && v < actualBase + soi) {
                                int s3 = pe.findSection((uint32_t)(v - actualBase));
                                if (s3 >= 0 && pe.isExecutableSection(s3)) { cc++; continue; }
                            }
                            break;
                        }
                        if (cc >= 4) {
                            vtInfos.push_back({(uint32_t)cc, raw2 + p});
                            p += cc * 8 - 8;
                        }
                    }
                }

                // For each unresolved vtable call, extract the slot and check consensus
                for (auto& fb : pdataAll2) {
                    if (fb.beginRVA < textVA2 || fb.beginRVA >= textEnd2) continue;
                    uint32_t fOff2 = pe.rvaToOffset(fb.beginRVA);
                    if (!fOff2) continue;
                    uint32_t fSz = fb.endRVA - fb.beginRVA;

                    for (uint32_t i = 3; i + 3 < fSz && i < 0x2000; i++) {
                        // Match: [REX] 8B modrm(mod=0) + FF modrm(reg=2, mod=1|2)
                        uint8_t b0 = pe.data[fOff2+i-3], b1 = pe.data[fOff2+i-2], b2 = pe.data[fOff2+i-1];
                        if ((b0 & 0xF8) != 0x48 || b1 != 0x8B || (b2 >> 6) != 0) continue;
                        uint8_t rm = b2 & 7;
                        if (rm == 4 || rm == 5) continue;
                        if (pe.data[fOff2+i] != 0xFF) continue;
                        uint8_t cm = pe.data[fOff2+i+1];
                        if (((cm >> 3) & 7) != 2) continue;
                        uint8_t cmod = cm >> 6;
                        uint32_t vtOff2 = 0;
                        uint8_t callLen = 0;
                        if (cmod == 1) { vtOff2 = pe.data[fOff2+i+2]; callLen = 3; }
                        else if (cmod == 2 && i + 6 < fSz) { vtOff2 = *(uint32_t*)(pe.data.data()+fOff2+i+2); callLen = 6; }
                        else continue;
                        if (vtOff2 % 8 != 0) continue;
                        uint32_t slot = vtOff2 / 8;

                        uint32_t callRVA = fb.beginRVA + i;
                        if (globalPatchedSites.count(callRVA)) continue;

                        // Check consensus: do all vtables agree on the target at this slot?
                        std::unordered_set<uint32_t> targets;
                        for (auto& vi : vtInfos) {
                            if (slot >= vi.entryCount) continue;
                            uint64_t t = *(uint64_t*)(pe.data.data() + vi.vtOff + slot * 8);
                            targets.insert((uint32_t)(t - actualBase));
                        }

                        if (targets.size() == 1) {
                            uint32_t targetRVA = *targets.begin();
                            if (targetRVA == 0 || targetRVA >= soi) continue;
                            uint32_t patchOff = fOff2 + i - 3;
                            uint32_t patchRVA = callRVA - 3;
                            uint32_t totalLen = 3 + callLen;
                            if (totalLen >= 5) {
                                int32_t d = (int32_t)(targetRVA - (patchRVA + 5));
                                pe.data[patchOff] = 0xE8;
                                memcpy(pe.data.data() + patchOff + 1, &d, 4);
                                for (uint32_t n = 5; n < totalLen; n++) pe.data[patchOff+n] = 0x90;
                                globalPatchedSites.insert(callRVA);
                                vtCallResolved++;
                                phaseC++;
                            }
                        }
                    }
                }
            }
            cli::detail("Phase C (slot consensus): %u resolved", phaseC);
            cli::detail("[vtable-resolve] %u vtable calls patched (%.0f ms)",
                   vtCallResolved, tVtProp.elapsedMs());
        }

        // Name hidden functions + orphan discoveries and add to allNames
        allNames.insert(allNames.end(), orphanNames.begin(), orphanNames.end());
        for (auto& fb : extraFunctions) {
            char sn2[9] = {};
            int sec = pe.findSection(fb.beginRVA);
            if (sec >= 0) memcpy(sn2, pe.sections[sec].Name, 8);
            std::string prefix = "hidden_";
            if (strncmp(sn2, ".text", 5) == 0) prefix = "text_";
            else if (strncmp(sn2, ".grfn1", 6) == 0) prefix = "grfn_";
            char buf[32]; sprintf_s(buf, "%s%X", prefix.c_str(), fb.beginRVA);
            allNames.push_back({actualBase + fb.beginRVA, buf});
        }

        // Embed COFF symbols (all names including proto + hidden + annotations)
        std::vector<CoffSymEntry> coffSyms;
        for (auto& n : allNames) {
            if (n.va < actualBase) continue;
            uint32_t rva = (uint32_t)(n.va - actualBase);
            int sec = pe.findSection(rva);
            bool isFunc = (sec >= 0 && pe.isExecutableSection(sec));
            coffSyms.push_back({rva, (uint16_t)(sec >= 0 ? sec + 1 : 0), n.name, isFunc});
        }
        embedCoffSymbols(pe, actualBase, coffSyms);
    }

    // Generate IDC script
    if (idcScriptPath) {
        cli::info("Generating IDC script...");
        generateIdcScript(idcScriptPath, allRefs, nullsubPatches, sslSymbols, rttiClasses, importWrappers, ptrRefs, actualBase, sizeOfImage);
    }

    // Summary (output is written AFTER deobfuscation below)
    cli::info("=== Summary ===");
    cli::detail("ImageBase:             0x%llX", actualBase);
    cli::detail("Sections:              %d", pe.numSections);
    cli::detail("RIP-relative refs:     %zu (in-image: %d)", allRefs.size(), refToCode + refToData);
    if (fixNullsub)
        cli::detail("Nullsubs patched:      %zu", nullsubPatches.size());
    if (!sslSymbols.empty())
        cli::detail("OpenSSL symbols:       %zu", sslSymbols.size());
    if (!trampolines.empty())
        cli::detail("Trampolines decoded:   %zu", trampolines.size());
    if (!rttiClasses.empty()) {
        size_t totalMeth = 0;
        for (auto& c : rttiClasses) totalMeth += c.methodVAs.size();
        cli::detail("RTTI classes:          %zu (%zu methods)", rttiClasses.size(), totalMeth);
    }
    if (!importWrappers.empty())
        cli::detail("Import wrappers:       %zu", importWrappers.size());
    if (!ptrRefs.empty())
        cli::detail("Pointer chains:        %zu", ptrRefs.size());
    if (!keyRefs.empty())
        cli::detail("Key string refs:       %zu", keyRefs.size());
    if (addReloc)
        cli::detail(".reloc entries added:  yes");
    if (idcScriptPath)
        cli::detail("IDC script:            %s", idcScriptPath);
    if (idaScriptPath)
        cli::detail("Python script:         %s", idaScriptPath);
    cli::info("Workflow:");
    cli::detail("1. Open the fixed PE in IDA");
    cli::detail("2. Wait for auto-analysis (idle)");
    if (idcScriptPath)
        cli::detail("3. File -> Script file -> %s", idcScriptPath);
    cli::detail("4. Check xrefs: X key on any symbol");

    // Griffin deobfuscation (--deobfuscate)
    if (deobfTarget) {
        uint32_t targetRVA = 0;
        const char* ts = deobfTarget;
        if (strncmp(ts, "0x", 2) == 0 || strncmp(ts, "0X", 2) == 0) ts += 2;
        targetRVA = (uint32_t)strtoull(ts, nullptr, 16);

        cli::info("Griffin deobfuscation: RVA 0x%X (VA 0x%llX)",
               targetRVA, (unsigned long long)(actualBase + targetRVA));

        GriffinDispatchExtractor extractor(pe, actualBase);

        // Auto-extract dispatch key if not provided
        if (dispatchKey == INT64_MIN) {
            cli::detail("Auto-extracting dispatch key...");
            auto keys = extractor.extractKeys(targetRVA, allRefs);

            for (auto& k : keys) {
                if (k.found) {
                    cli::detail("Caller 0x%llX: %s = 0x%X",
                           (unsigned long long)k.callerVA,
                           grRegName(k.keyReg),
                           (uint32_t)(uint64_t)k.dispatchKey);
                    if (dispatchKey == INT64_MIN)
                        dispatchKey = k.dispatchKey;
                } else {
                    cli::detail("Caller 0x%llX: key not resolved",
                           (unsigned long long)k.callerVA);
                }
            }
            if (keys.empty())
                cli::detail("No callers found via xref");

            // Fallback: multi-key extraction from function body
            std::vector<DispatchKey> extractedKeys;
            if (dispatchKey == INT64_MIN) {
                cli::detail("Trying multi-key extraction...");
                GriffinDisasm preDisasm(pe, actualBase);
                GrFunc preFunc;
                if (preDisasm.buildCFG(targetRVA, preFunc)) {
                    GriffinMBA preMba;
                    for (auto& blk : preFunc.blocks)
                        if (!blk.isDeadCode) preMba.simplifyBlock(blk);
                    auto mkr = extractor.extractAllKeys(preFunc);
                    extractedKeys = mkr.keys;
                    for (auto& dk : extractedKeys)
                        cli::detail("Key: %s = 0x%X", grRegName(dk.reg), dk.value);
                }
            }
        }

        GriffinDisasm disasm(pe, actualBase);
        GrFunc func;

        if (disasm.buildCFG(targetRVA, func)) {
            // Multi-key extraction on the actual func
            {
                GriffinMBA preMba;
                for (auto& blk : func.blocks)
                    if (!blk.isDeadCode) preMba.simplifyBlock(blk);
                auto mkr = extractor.extractAllKeys(func);
                // func.dispatchKeys is set by extractAllKeys
                if (!mkr.keys.empty()) {
                    cli::detail("Multi-key: %zu keys found", mkr.keys.size());
                    for (auto& dk : mkr.keys)
                        cli::detail("%s = 0x%X", grRegName(dk.reg), dk.value);
                }
            }

            // CLI --dispatch-key overrides primary key
            if (dispatchKey != INT64_MIN) {
                func.dispatchKeyReg = GrReg::RDI;
                func.dispatchKeyValue = dispatchKey;
                // Also add to multi-key list if not already present
                bool found = false;
                for (auto& dk : func.dispatchKeys)
                    if (dk.reg == GrReg::RDI) { dk.value = (uint32_t)dispatchKey; found = true; }
                if (!found)
                    func.dispatchKeys.push_back({GrReg::RDI, (uint32_t)dispatchKey});
            }

            GriffinMBA mba;
            GriffinConstProp constprop;

            uint32_t prevLive = func.totalInstrs();
            for (int pass = 0; pass < 6; pass++) {
                mba.run(func);
                constprop.run(func);

                // Dead path elimination + liveness DCE
                int deadPaths = 0;
                for (auto& blk : func.blocks)
                    if (!blk.isDeadCode)
                        deadPaths += mba.eliminateDeadPaths(blk);

                int dceKilled = mba.livenessDCE(func);
                if (deadPaths + dceKilled > 0)
                    cli::detail("DCE: %d dead paths + %d liveness = %d eliminated",
                           deadPaths, dceKilled, deadPaths + dceKilled);

                uint32_t curLive = func.liveInstrs();
                uint32_t totalI = func.totalInstrs();
                cli::detail("Pass %d: %u/%u live (%.0f%% eliminated)",
                       pass + 1, curLive, totalI,
                       totalI > 0 ? (1.0 - (double)curLive / totalI) * 100.0 : 0.0);

                if (curLive >= prevLive) break;
                prevLive = curLive;
            }

            GriffinOutput output;
            output.emitText(deobfOutput, func, actualBase);

            // Apply patches to PE binary
            if (!dryRun) {
                PatchStats ps = applyDeobfPatches(pe, actualBase, func);
                cli::detail("PE patch: %u instructions (%u NOP, %u IMUL→MOV, %u CMOV→MOV), %u bytes",
                       ps.totalPatched, ps.nopsWritten, ps.imulFolded, ps.cmovResolved, ps.bytesPatched);
            }
        } else {
            cli::fail("Failed to build CFG at RVA 0x%X", targetRVA);
        }
    }

    std::vector<griffin::DispatchEntry> collectedKeys;

    if (deobfScan) {
        cli::info("Batch Griffin deobfuscation: scanning .grfn1 functions...");

        // Collect .grfn1 function entries from .pdata
        std::vector<uint32_t> grfnFuncs;
        int grfnSec = -1;
        uint32_t grfnStart = 0, grfnEnd = 0;
        for (int si = 0; si < pe.numSections; si++) {
            char sname[9] = {};
            memcpy(sname, pe.sections[si].Name, 8);
            if (strcmp(sname, ".grfn1") == 0) {
                grfnSec = si;
                grfnStart = pe.sections[si].VirtualAddress;
                grfnEnd = grfnStart + pe.sections[si].Misc.VirtualSize;
                break;
            }
        }

        if (grfnSec >= 0) {
            // .grfn1 has no .pdata entries — find functions via call targets
            std::set<uint32_t> funcSet;
            uint32_t grfnRaw = pe.sections[grfnSec].PointerToRawData;
            uint32_t grfnRawSz = pe.sections[grfnSec].SizeOfRawData;
            uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

            // 1. E8 direct calls from .text targeting .grfn1
            for (auto& ref : allRefs) {
                if (!ref.isCall) continue;
                uint32_t t = ref.targetRVA;
                // Follow jmp chains
                for (int h = 0; h < 8; h++) {
                    uint32_t o = pe.rvaToOffset(t);
                    if (!o || o + 5 > pe.data.size() || pe.data[o] != 0xE9) break;
                    int32_t d = *(int32_t*)(pe.data.data() + o + 1);
                    t = t + 5 + d;
                    if (t >= soi) break;
                }
                if (t >= grfnStart && t < grfnEnd) funcSet.insert(t);
            }

            // 2. Trampoline targets in .grfn1
            for (auto& tr : trampolines) {
                uint32_t t = (uint32_t)(tr.targetVA - actualBase);
                if (t >= grfnStart && t < grfnEnd) funcSet.insert(t);
            }

            // 3. Scan .grfn1 for push rbx; sub rsp prologue (48 83 EC or 48 81 EC)
            for (uint32_t pos = 0; pos + 7 < grfnRawSz; pos++) {
                const uint8_t* p = pe.data.data() + grfnRaw + pos;
                bool isPrologue = false;
                // sub rsp, imm8: 48 83 EC XX
                if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) isPrologue = true;
                // sub rsp, imm32: 48 81 EC XX XX XX XX
                if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) isPrologue = true;
                if (isPrologue) {
                    uint32_t rva = grfnStart + pos;
                    // Verify: byte before should be CC, C3, or 00 (function boundary)
                    if (pos > 0) {
                        uint8_t prev = pe.data[grfnRaw + pos - 1];
                        if (prev != 0xCC && prev != 0xC3 && prev != 0x00 && prev != 0x90) continue;
                    }
                    funcSet.insert(rva);
                }
            }

            // Save original func set (for L4 Unicorn — orphans excluded from heavy emulation)
            std::vector<uint32_t> originalGrfnFuncs(funcSet.begin(), funcSet.end());

            // Merge early-discovered hidden functions for L1/L2/L3/L3b (cheap passes)
            uint32_t hiddenAdded = 0;
            for (auto& ef : extraFunctions) {
                if (ef.beginRVA >= grfnStart && ef.beginRVA < grfnEnd) {
                    if (funcSet.insert(ef.beginRVA).second) hiddenAdded++;
                }
            }
            grfnFuncs.assign(funcSet.begin(), funcSet.end());
            cli::detail("Found %zu .grfn1 function candidates (%zu original + %u hidden)",
                   grfnFuncs.size(), originalGrfnFuncs.size(), hiddenAdded);

            uint32_t totalPatched = 0, totalFuncs = 0, failedCFG = 0;
            uint32_t skippedSmall = 0, skippedLarge = 0, skippedTiny = 0, keysFound = 0;
            Timer tScan;

            // === Phase 1: Fast pattern-matching pass (no Z3) ===
            cli::detail("Phase 1: Pattern matching (no Z3)...");
            fflush(stdout);

            struct FuncInfo { uint32_t rva; uint32_t totalInstrs; uint32_t liveInstrs; uint32_t numKeys; };
            std::vector<FuncInfo> funcInfos;

            std::vector<ResolvedJmp> constpropJmps;

            // Multi-threaded Phase 1: each function is independent
            {
                uint32_t numT = std::min(std::thread::hardware_concurrency(), 8u);
                if (numT < 1) numT = 4;
                cli::detail("Phase 1 on %u threads...", numT);

                // Pre-build caller map: targetRVA → list of caller RipRelativeRefs
                // Avoids O(N) allRefs scan per function in extractKeys fallback
                std::unordered_map<uint32_t, std::vector<const RipRelativeRef*>> callerMap;
                for (auto& ref : allRefs)
                    if (ref.isCall && ref.targetRVA > 0)
                        callerMap[ref.targetRVA].push_back(&ref);

                std::atomic<uint32_t> p1Idx{0};
                std::atomic<uint32_t> aTotalPatched{0}, aTotalFuncs{0}, aFailedCFG{0};
                std::atomic<uint32_t> aSkippedTiny{0}, aKeysFound{0};
                std::mutex mtx;
                uint32_t soi2 = pe.nt->OptionalHeader.SizeOfImage;

                auto p1Worker = [&]() {
                    std::vector<ResolvedJmp> localJmps;
                    std::vector<FuncInfo> localInfos;
                    uint32_t localPatched = 0, localFuncs = 0, localKeys = 0;
                    uint32_t localSkip = 0, localFail = 0;

                    while (true) {
                        uint32_t fi = p1Idx.fetch_add(1);
                        if (fi >= grfnFuncs.size()) break;
                        uint32_t rva = grfnFuncs[fi];

                        // Pre-check
                        uint32_t preOff = pe.rvaToOffset(rva);
                        if (preOff && preOff < pe.data.size()) {
                            uint8_t fb = pe.data[preOff];
                            if (fb == 0xCC || fb == 0x00 || fb == 0x90 || fb == 0xC3) { localSkip++; continue; }
                        }

                        GriffinDisasm disasm(pe, actualBase);
                        GrFunc func;
                        if (!disasm.buildCFG(rva, func)) { localFail++; continue; }
                        if (func.totalInstrs() < 4) { localSkip++; continue; }
                        if (func.totalInstrs() > 50000) { continue; }

                        GriffinMBA mba;
                        for (auto& blk : func.blocks)
                            if (!blk.isDeadCode) mba.simplifyBlock(blk);

                        GriffinDispatchExtractor ext(pe, actualBase);
                        auto mkr = ext.extractAllKeys(func);
                        // Fallback: caller-based key extraction via pre-built map
                        if (mkr.keys.empty()) {
                            auto cit = callerMap.find(rva);
                            if (cit != callerMap.end()) {
                                for (auto* ref : cit->second) {
                                    // Read bytes before the CALL to find MOV reg, imm32 (dispatch key setup)
                                    uint32_t cOff = pe.rvaToOffset(ref->instrRVA);
                                    if (!cOff || cOff < 10) continue;
                                    // Scan backward for MOV edi/esi, imm32 (common dispatch key registers)
                                    for (uint32_t bk = 5; bk < 30 && cOff >= bk; bk++) {
                                        uint8_t b0 = pe.data[cOff - bk];
                                        // MOV edi, imm32: BF XX XX XX XX
                                        if (b0 == 0xBF && bk >= 5) {
                                            uint32_t key = *(uint32_t*)(pe.data.data() + cOff - bk + 1);
                                            func.dispatchKeys.push_back({GrReg::RDI, key});
                                            break;
                                        }
                                        // MOV esi, imm32: BE XX XX XX XX
                                        if (b0 == 0xBE && bk >= 5) {
                                            uint32_t key = *(uint32_t*)(pe.data.data() + cOff - bk + 1);
                                            func.dispatchKeys.push_back({GrReg::RSI, key});
                                            break;
                                        }
                                        // MOV edx, imm32: BA XX XX XX XX
                                        if (b0 == 0xBA && bk >= 5) {
                                            uint32_t key = *(uint32_t*)(pe.data.data() + cOff - bk + 1);
                                            func.dispatchKeys.push_back({GrReg::RDX, key});
                                            break;
                                        }
                                        // MOV ecx, imm32: B9 XX XX XX XX
                                        if (b0 == 0xB9 && bk >= 5) {
                                            uint32_t key = *(uint32_t*)(pe.data.data() + cOff - bk + 1);
                                            func.dispatchKeys.push_back({GrReg::RCX, key});
                                            break;
                                        }
                                    }
                                    if (!func.dispatchKeys.empty()) break;
                                }
                            }
                        }
                        localKeys += (uint32_t)mkr.keys.size() + (uint32_t)func.dispatchKeys.size();

                        {
                            std::lock_guard<std::mutex> lk(mtx);
                            for (auto& dk : mkr.keys) {
                                griffin::DispatchEntry de;
                                de.funcRVA = rva;
                                de.key = (int64_t)dk.value;
                                de.keyReg = (uint8_t)dk.reg;
                                de.firstImulRVA = dk.firstImulRVA;
                                de.imulConsts = dk.imulConsts;
                                collectedKeys.push_back(std::move(de));
                            }
                            for (auto& dk : func.dispatchKeys)
                                collectedKeys.push_back({rva, (int64_t)dk.value, (uint8_t)dk.reg});
                            if (func.dispatchKeyValue != INT64_MIN && func.dispatchKeyReg != GrReg::NONE)
                                collectedKeys.push_back({rva, func.dispatchKeyValue, (uint8_t)func.dispatchKeyReg});
                        }

                        GriffinConstProp cp;
                        cp.setPE(&pe, actualBase);
                        cp.run(func);

                        for (auto& blk : func.blocks)
                            for (auto& instr : blk.instrs)
                                if (instr.simplified && instr.dst.kind == GrValue::LABEL && instr.dst.imm > 0
                                    && (instr.op == GrOp::JMP || instr.op == GrOp::CALL)) {
                                    uint64_t targetRva64 = (uint64_t)instr.dst.imm - actualBase;
                                    if (targetRva64 > 0 && targetRva64 < soi2)
                                        localJmps.push_back({(uint32_t)(instr.addr-actualBase), (uint32_t)targetRva64, (uint8_t)instr.rawLen});
                                }

                        mba.livenessDCE(func);

                        if (!dryRun) {
                            PatchStats ps = applyDeobfPatches(pe, actualBase, func);
                            localPatched += ps.totalPatched;
                        }

                        localInfos.push_back({rva, func.totalInstrs(), func.liveInstrs(), (uint32_t)mkr.keys.size()});
                        localFuncs++;

                        if (localFuncs % 200 == 0 && localFuncs > 0) {
                            printf("\r    [%u/%zu] (%.1fs)  ",
                                   p1Idx.load(), grfnFuncs.size(), tScan.elapsedMs()/1000.0);
                            fflush(stdout);
                        }
                    }

                    // Merge thread-local results
                    aTotalPatched += localPatched;
                    aTotalFuncs += localFuncs;
                    aSkippedTiny += localSkip;
                    aFailedCFG += localFail;
                    aKeysFound += localKeys;
                    std::lock_guard<std::mutex> lk(mtx);
                    constpropJmps.insert(constpropJmps.end(), localJmps.begin(), localJmps.end());
                    funcInfos.insert(funcInfos.end(), localInfos.begin(), localInfos.end());
                };

                std::vector<std::thread> threads;
                for (uint32_t t = 0; t < numT; t++) threads.emplace_back(p1Worker);
                for (auto& t : threads) t.join();

                totalPatched = aTotalPatched.load();
                totalFuncs = aTotalFuncs.load();
                failedCFG = aFailedCFG.load();
                skippedTiny = aSkippedTiny.load();
                keysFound = aKeysFound.load();
                printf("\r    Phase 1: %u funcs, %u patched, %u keys, %u skip (%.1fs)        \n",
                       totalFuncs, totalPatched, keysFound, skippedTiny, tScan.elapsedMs()/1000.0);
            }
            // INT3 control flow resolution
            if (!dryRun) {
                auto int3Sites = scanInt3Sites(pe);
                resolveInt3Targets(int3Sites, pe);

                // NOP out dead INT3 constant data BEFORE patching INT3 blocks
                uint32_t deadConsts = 0;
                for (auto& site : int3Sites) {
                    uint32_t siteOff = pe.rvaToOffset(site.siteRVA);
                    if (!siteOff) continue;
                    // The mov rax, CONST instructions start at offset +7
                    // They're harmless but waste IDA instruction count
                    uint32_t pos = 7;
                    while (pos + 10 < 200 && siteOff + pos + 10 <= pe.data.size()) {
                        if (pe.data[siteOff + pos] == 0x48 && pe.data[siteOff + pos + 1] == 0xB8) {
                            for (int n = 0; n < 10; n++)
                                pe.data[siteOff + pos + n] = 0x90;
                            deadConsts++;
                            pos += 10;
                        } else break;
                    }
                    // Also NOP opaque predicate: 49 F7 C7 00 00 00 00 (test r15, 0)
                    if (siteOff + pos + 7 <= pe.data.size() &&
                        pe.data[siteOff + pos] == 0x49 && pe.data[siteOff + pos + 1] == 0xF7 &&
                        pe.data[siteOff + pos + 2] == 0xC7 &&
                        pe.data[siteOff + pos + 3] == 0x00) {
                        for (int n = 0; n < 7; n++)
                            pe.data[siteOff + pos + n] = 0x90;
                        pos += 7;
                    }
                }
                if (deadConsts > 0)
                    cli::detail("Dead INT3 constants: %u NOP'd", deadConsts);

                // Now patch INT3 blocks themselves
                auto int3Stats = patchInt3Sites(pe, actualBase, int3Sites);
                cli::detail("INT3: %u sites, %u resolved, %u patched",
                       int3Stats.totalSites, int3Stats.resolved, int3Stats.patched);

                // Patch trampolines: pop [rsp+X]; jmp target → jmp target + NOP
                uint32_t trampPatched = 0;
                for (auto& tr : trampolines) {
                    uint32_t trRVA = (uint32_t)(tr.trampolineVA - actualBase);
                    uint32_t tgtRVA = (uint32_t)(tr.targetVA - actualBase);
                    uint32_t off = pe.rvaToOffset(trRVA);
                    if (!off || off + 13 > pe.data.size()) continue;

                    // Write: E9 [disp32] + NOP padding
                    int32_t disp = (int32_t)(tgtRVA - (trRVA + 5));
                    pe.data[off] = 0xE9;
                    memcpy(pe.data.data() + off + 1, &disp, 4);
                    // NOP remaining bytes (trampolines are typically 7-13 bytes)
                    for (int n = 5; n < 13 && off + n < pe.data.size(); n++) {
                        if (pe.data[off + n] == 0xCC) break; // don't cross into next function
                        pe.data[off + n] = 0x90;
                    }
                    trampPatched++;
                }
                cli::detail("Trampolines: %u patched (→ direct JMP)", trampPatched);

                // === Indirect jump resolution (cascading: cheap → expensive) ===
                Timer tJmp;
                std::vector<ResolvedJmp> resolvedJmps;
                std::unordered_set<uint32_t> resolvedSet;

                auto mergeResults = [&](const std::vector<ResolvedJmp>& newJmps) {
                    for (auto& rj : newJmps)
                        if (!resolvedSet.count(rj.jmpRVA)) {
                            resolvedJmps.push_back(rj);
                            resolvedSet.insert(rj.jmpRVA);
                        }
                };

                // Build per-function dispatch key map (funcRVA → keys)
                // Reuse from deobf pass
                std::unordered_map<uint32_t, std::vector<std::pair<int,uint32_t>>> funcKeyMap;
                {
                    static const int grToUc[] = {
                        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
                    };
                    GriffinDispatchExtractor extMap(pe, actualBase);
                    for (auto funcRVA : grfnFuncs) {
                        GrFunc tf; GriffinDisasm td(pe, actualBase);
                        if (!td.buildCFG(funcRVA, tf)) continue;
                        auto mk = extMap.extractAllKeys(tf);
                        if (mk.keys.empty()) continue;
                        auto& kv = funcKeyMap[funcRVA];
                        for (auto& k : mk.keys) {
                            int ri = (int)k.reg;
                            if (ri >= 0 && ri < 16) kv.push_back({grToUc[ri], k.value});
                        }
                    }
                    cli::detail("[JMP] %zu functions with dispatch keys", funcKeyMap.size());
                }

                // --- Level 1: Pattern scan (cheapest) ---
                {
                    Timer t1;
                    auto r = resolveIndirectJumps(pe, actualBase, grfnFuncs);
                    mergeResults(r);
                    cli::detail("[L1-pattern] %u resolved (%.0f ms)", (uint32_t)r.size(), t1.elapsedMs());
                }

                // --- Level 2: Constprop (from deobf pass) ---
                {
                    uint32_t added = 0;
                    for (auto& cj : constpropJmps)
                        if (!resolvedSet.count(cj.jmpRVA)) { resolvedJmps.push_back(cj); resolvedSet.insert(cj.jmpRVA); added++; }
                    cli::detail("[L2-constprop] %u added", added);
                }

                // --- Level 3: Call+JMP static dispatch parsing (NO Unicorn!) ---
                // Pattern A (79%): dispatch stub = pop [rsp+228h]; jmp REAL_TARGET
                //   → extract JMP target directly from E9 disp32
                // Pattern B (21%): dispatch stub = EB FF F0; lea rax, [rip+X]
                //   → extract LEA target directly
                {
                    Timer t3;
                    uint32_t soi3 = pe.nt->OptionalHeader.SizeOfImage;
                    uint32_t patA = 0, patB = 0, patUnk = 0, cjPatched = 0;

                    for (int si2 = 0; si2 < pe.numSections; si2++) {
                        char sn2[9] = {}; memcpy(sn2, pe.sections[si2].Name, 8);
                        if (strcmp(sn2, ".grfn1") != 0) continue;
                        uint32_t secRVA = pe.sections[si2].VirtualAddress;
                        uint32_t rawOff = pe.sections[si2].PointerToRawData;
                        uint32_t rawSz = pe.sections[si2].SizeOfRawData;

                        for (uint32_t p = 0; p + 7 < rawSz; p++) {
                            uint32_t off = rawOff + p;
                            if (pe.data[off] != 0xE8) continue;
                            // Check for FF E0-E7 or 41 FF E0-E7 after CALL
                            bool hasJmpReg = (pe.data[off+5] == 0xFF && (pe.data[off+6] & 0xF8) == 0xE0);
                            if (!hasJmpReg && pe.data[off+5] == 0x41 && pe.data[off+6] == 0xFF &&
                                p+8 < rawSz && (pe.data[off+7] & 0xF8) == 0xE0)
                                hasJmpReg = true;
                            if (!hasJmpReg) continue;

                            uint32_t siteRVA = secRVA + p;
                            if (resolvedSet.count(siteRVA) || resolvedSet.count(siteRVA+5)) continue;

                            int32_t callDisp = *(int32_t*)(pe.data.data() + off + 1);
                            uint32_t callTarget = siteRVA + 5 + callDisp;
                            if (callTarget == 0 || callTarget >= soi3) continue;

                            uint32_t ctOff = pe.rvaToOffset(callTarget);
                            if (!ctOff || ctOff + 12 > pe.data.size()) continue;
                            const uint8_t* stub = pe.data.data() + ctOff;

                            uint32_t realTarget = 0;

                            // Pattern A (post-patch): E9 [disp32] {90|CC}+ (was: pop [rsp]; jmp)
                            if (stub[0] == 0xE9 && (stub[5] == 0xCC || stub[5] == 0x90)) {
                                int32_t jmpDisp = *(int32_t*)(stub + 1);
                                realTarget = callTarget + 5 + jmpDisp;
                                patA++;
                            }
                            // Pattern A (original): 8F 84 24 28 02 00 00 E9 [disp32]
                            else if (stub[0] == 0x8F && stub[1] == 0x84 && stub[2] == 0x24 &&
                                     stub[7] == 0xE9) {
                                int32_t jmpDisp = *(int32_t*)(stub + 8);
                                realTarget = callTarget + 12 + jmpDisp;
                                patA++;
                            }
                            // Pattern B (post-patch): 90 90 90 48 8D 05 [disp32]
                            else if (stub[0] == 0x90 && stub[1] == 0x90 && stub[2] == 0x90 &&
                                     stub[3] == 0x48 && stub[4] == 0x8D && stub[5] == 0x05) {
                                int32_t leaDisp = *(int32_t*)(stub + 6);
                                realTarget = callTarget + 3 + 7 + leaDisp;
                                patB++;
                            }
                            // Pattern B (original): EB FF F0 48 8D 05 [disp32]
                            else if (stub[0] == 0xEB && stub[1] == 0xFF && stub[2] == 0xF0 &&
                                     stub[3] == 0x48 && stub[4] == 0x8D && stub[5] == 0x05) {
                                int32_t leaDisp = *(int32_t*)(stub + 6);
                                realTarget = callTarget + 3 + 7 + leaDisp;
                                patB++;
                            }
                            else {
                                patUnk++;
                                if (patUnk <= 5)
                                    cli::detail("[L3-unk] stub 0x%X: %02X %02X %02X %02X %02X %02X %02X %02X",
                                           callTarget, stub[0],stub[1],stub[2],stub[3],stub[4],stub[5],stub[6],stub[7]);
                                continue;
                            }

                            if (realTarget == 0 || realTarget >= soi3) continue;

                            // Patch: E8 [5] FF E0 [2] = 7 bytes → E9 [5] 90 90
                            int32_t newDisp = (int32_t)(realTarget - (siteRVA + 5));
                            pe.data[off] = 0xE9;
                            memcpy(pe.data.data() + off + 1, &newDisp, 4);
                            pe.data[off + 5] = 0x90;
                            pe.data[off + 6] = 0x90;
                            resolvedSet.insert(siteRVA);
                            resolvedSet.insert(siteRVA + 5);
                            resolvedSet.insert(siteRVA + 6);
                            resolvedJmps.push_back({siteRVA, realTarget, 7});
                            cjPatched++;
                        }
                    }
                    cli::detail("[L3-static] patA=%u patB=%u unknown=%u → %u patched (%.0f ms)",
                           patA, patB, patUnk, cjPatched, t3.elapsedMs());
                }

                // --- Level 3b: LEA+LEA+JMP static resolution ---
                // Pattern: 48 8D 05 [d1] 48 8D 80 [d2] FF E0  (lea rax,[rip+d1]; lea rax,[rax+d2]; jmp rax)
                // Target = instrAddr + 7 + d1 + d2 (pure constant computation, no dispatch key)
                // Also handles: 4C 8D 05 ... 4D 8D 80 ... 41 FF E0 (r8 variant)
                {
                    Timer t3b;
                    uint32_t soi3b = pe.nt->OptionalHeader.SizeOfImage;
                    uint32_t l3bPatched = 0;

                    for (int si2 = 0; si2 < pe.numSections; si2++) {
                        char sn2[9] = {}; memcpy(sn2, pe.sections[si2].Name, 8);
                        if (strcmp(sn2, ".grfn1") != 0 && strcmp(sn2, ".text") != 0 && strcmp(sn2, ".riot1") != 0) continue;
                        uint32_t secRVA = pe.sections[si2].VirtualAddress;
                        uint32_t rawOff = pe.sections[si2].PointerToRawData;
                        uint32_t rawSz = pe.sections[si2].SizeOfRawData;

                        for (uint32_t p = 0; p + 16 <= rawSz; p++) {
                            uint32_t off = rawOff + p;
                            const uint8_t* b = pe.data.data() + off;

                            // Pattern: [48|4C] 8D 05 [d1:4] [48|4D] 8D [80|40] [d2:4|d2:1] FF E0
                            // Check for first LEA: reg, [rip+disp32]
                            if ((b[0] != 0x48 && b[0] != 0x4C) || b[1] != 0x8D || b[2] != 0x05) continue;
                            int32_t d1 = *(int32_t*)(b + 3);
                            uint32_t lea1RVA = secRVA + p;
                            uint32_t afterLea1 = 7; // LEA is 7 bytes

                            // Check for second LEA: reg, [reg+disp32] (mod=10, rm=0 for rax)
                            const uint8_t* b2 = b + afterLea1;
                            uint32_t afterLea2 = 0;
                            int32_t d2 = 0;
                            bool validLea2 = false;

                            if (p + afterLea1 + 7 + 2 <= rawSz) {
                                uint8_t rex2 = b2[0];
                                if ((rex2 == 0x48 || rex2 == 0x4D) && b2[1] == 0x8D) {
                                    uint8_t modrm2 = b2[2];
                                    uint8_t mod2 = modrm2 >> 6;
                                    uint8_t rm2 = modrm2 & 7;
                                    if (mod2 == 2 && rm2 == 0) { // [rax+disp32]
                                        d2 = *(int32_t*)(b2 + 3);
                                        afterLea2 = 7;
                                        validLea2 = true;
                                    } else if (mod2 == 1 && rm2 == 0) { // [rax+disp8]
                                        d2 = (int8_t)b2[3];
                                        afterLea2 = 4;
                                        validLea2 = true;
                                    }
                                }
                            }
                            if (!validLea2) continue;

                            // Check for JMP reg (FF E0 or 41 FF E0)
                            const uint8_t* b3 = b + afterLea1 + afterLea2;
                            uint8_t jmpLen = 0;
                            if (b3[0] == 0xFF && (b3[1] & 0xF8) == 0xE0) jmpLen = 2;
                            else if (b3[0] == 0x41 && b3[1] == 0xFF && (b3[2] & 0xF8) == 0xE0) jmpLen = 3;
                            if (!jmpLen) continue;

                            uint32_t jmpRVA = secRVA + p + afterLea1 + afterLea2;
                            // Allow re-patching if already in resolvedSet but not yet patched
                            // (e.g., constprop resolved it but patchIndirectJumps couldn't fit E9)
                            if (resolvedSet.count(jmpRVA)) {
                                uint32_t jmpOff = rawOff + p + afterLea1 + afterLea2;
                                if (pe.data[jmpOff] != 0xFF) continue; // already patched
                            }

                            // Compute target: lea1_addr + 7 + d1 + d2
                            uint32_t target = lea1RVA + 7 + d1 + d2;
                            if (target == 0 || target >= soi3b) continue;
                            int targetSec = pe.findSection(target);
                            if (targetSec < 0 || !pe.isExecutableSection(targetSec)) continue;

                            // Patch entire sequence to E9 + NOPs
                            uint32_t totalLen = afterLea1 + afterLea2 + jmpLen;
                            if (totalLen >= 5) {
                                int32_t relDisp = (int32_t)(target - (lea1RVA + 5));
                                pe.data[off] = 0xE9;
                                memcpy(pe.data.data() + off + 1, &relDisp, 4);
                                for (uint32_t n = 5; n < totalLen; n++) pe.data[off + n] = 0x90;
                                resolvedSet.insert(jmpRVA);
                                resolvedJmps.push_back({lea1RVA, target, (uint8_t)totalLen});
                                l3bPatched++;
                                p += totalLen - 1;
                            }
                        }
                    }
                    if (l3bPatched)
                        cli::detail("[L3b-lea] %u LEA+LEA+JMP resolved (%.0f ms)", l3bPatched, t3b.elapsedMs());
                }

                // --- Level 5: Symbolic dispatch key inference ---
                // For each unresolved jmp-reg, backward-scan for IMUL chain,
                // then try ALL known function starts as possible targets,
                // compute required key via modular inverse, validate with constprop
                {
                    Timer t5;
                    uint32_t l5Resolved = 0;
                    uint32_t soi5 = pe.nt->OptionalHeader.SizeOfImage;

                    // Collect all known function starts as potential jmp targets
                    std::vector<uint32_t> knownTargets;
                    for (auto rva : grfnFuncs) knownTargets.push_back(rva);
                    // Also .text function starts
                    auto pdataT = readPdataFunctions(pe);
                    for (auto& fb : pdataT) knownTargets.push_back(fb.beginRVA);
                    std::sort(knownTargets.begin(), knownTargets.end());

                    // Modular inverse helper (extended Euclidean)
                    auto modInverse32 = [](uint32_t a) -> uint32_t {
                        // Compute multiplicative inverse of a mod 2^32
                        // Using: a * a^(-1) ≡ 1 (mod 2^32)
                        // Newton's method: x = x * (2 - a*x)
                        uint32_t x = a; // initial guess (odd numbers are self-inverse-ish)
                        for (int i = 0; i < 5; i++) x = x * (2 - a * x);
                        return x;
                    };

                    for (int si2 = 0; si2 < pe.numSections; si2++) {
                        char sn2[9] = {}; memcpy(sn2, pe.sections[si2].Name, 8);
                        // L5 applies to ALL obfuscated sections
                        if (strcmp(sn2, ".grfn1") != 0 && strcmp(sn2, ".riot1") != 0 && strcmp(sn2, ".text") != 0) continue;
                        uint32_t secRVA = pe.sections[si2].VirtualAddress;
                        uint32_t rawOff = pe.sections[si2].PointerToRawData;
                        uint32_t rawSz = pe.sections[si2].SizeOfRawData;

                        for (uint32_t p = 0; p + 3 < rawSz; p++) {
                            uint32_t off = rawOff + p;
                            // Find jmp reg (FF E0-E7)
                            bool isJmp = false;
                            uint8_t jLen = 0;
                            if (pe.data[off]==0xFF && (pe.data[off+1]&0xF8)==0xE0) { isJmp=true; jLen=2; }
                            if (pe.data[off]==0x41 && pe.data[off+1]==0xFF && p+3<rawSz && (pe.data[off+2]&0xF8)==0xE0) { isJmp=true; jLen=3; }
                            if (!isJmp) continue;
                            uint32_t jmpRVA = secRVA + p;
                            if (resolvedSet.count(jmpRVA)) continue;

                            // Backward scan for IMUL chains that compute jmp target
                            uint32_t imulConst = 0;
                            int32_t addConst = 0;
                            bool foundChain = false;
                            for (uint32_t bk = 3; bk < 80 && p >= bk; bk++) {
                                uint32_t sOff = rawOff + p - bk;
                                // Pattern A (Griffin): IMUL r32, r/m32, imm32 (69 modrm [imm32])
                                if (pe.data[sOff] == 0x69 && (pe.data[sOff+1] >> 6) == 3) {
                                    imulConst = *(uint32_t*)(pe.data.data() + sOff + 2);
                                    if (imulConst != 0 && (imulConst & 1)) {
                                        foundChain = true;
                                        uint32_t afterImul = sOff + 6;
                                        if (afterImul + 6 <= rawOff + p) {
                                            if (pe.data[afterImul] == 0x81 && (pe.data[afterImul+1]>>6)==3) {
                                                uint8_t op = (pe.data[afterImul+1] >> 3) & 7;
                                                if (op == 0) addConst = *(int32_t*)(pe.data.data() + afterImul + 2);
                                                if (op == 5) addConst = -*(int32_t*)(pe.data.data() + afterImul + 2);
                                            }
                                        }
                                    }
                                    break;
                                }
                                // Pattern B (riot1): IMUL rax, rbp, imm32 (48 69 C5 [imm32])
                                // followed by NOT rbp (48 F7 D5) + IMUL rdx, rbp, imm32 + ADD rax, rdx
                                if (sOff + 20 <= rawOff + rawSz &&
                                    pe.data[sOff] == 0x48 && pe.data[sOff+1] == 0x69 && pe.data[sOff+2] == 0xC5) {
                                    int32_t c1 = *(int32_t*)(pe.data.data() + sOff + 3);
                                    // Check NOT rbp at sOff+7
                                    if (pe.data[sOff+7] == 0x48 && pe.data[sOff+8] == 0xF7 && pe.data[sOff+9] == 0xD5) {
                                        // IMUL rdx, rbp, C2 at sOff+10
                                        if (pe.data[sOff+10] == 0x48 && pe.data[sOff+11] == 0x69 && pe.data[sOff+12] == 0xD5) {
                                            int32_t c2 = *(int32_t*)(pe.data.data() + sOff + 13);
                                            // ADD rax, rdx at sOff+17
                                            if (pe.data[sOff+17] == 0x48 && pe.data[sOff+18] == 0x03 && pe.data[sOff+19] == 0xC2) {
                                                // target = rbp * c1 + (~rbp) * c2 = rbp * (c1 - c2) + c2 * 0xFFFFFFFF...
                                                // Simplified: this is MBA XOR → target = rbp XOR (c1 XOR c2 derived)
                                                // For modular inverse: target = rbp * c1 + NOT(rbp) * c2
                                                // = rbp * c1 + (0xFFFFFFFFFFFFFFFF - rbp) * c2
                                                // = rbp * (c1 - c2) + 0xFFFFFFFFFFFFFFFF * c2
                                                // In 32-bit: target = key * (c1 - c2) + (-1) * c2 (mod 2^32)
                                                imulConst = (uint32_t)(c1 - c2);
                                                addConst = (int32_t)((uint32_t)(-1) * (uint32_t)c2);
                                                if (imulConst != 0 && (imulConst & 1)) foundChain = true;
                                            }
                                        }
                                    }
                                    if (foundChain) break;
                                }
                                // Pattern C: IMUL rax, reg, imm32 (48 69 XX [imm32]) — general form
                                if (pe.data[sOff] == 0x48 && pe.data[sOff+1] == 0x69 && (pe.data[sOff+2] >> 6) == 3) {
                                    imulConst = *(uint32_t*)(pe.data.data() + sOff + 3);
                                    if (imulConst != 0 && (imulConst & 1)) {
                                        foundChain = true;
                                        uint32_t afterImul = sOff + 7;
                                        if (afterImul + 3 <= rawOff + p && pe.data[afterImul] == 0x48 && pe.data[afterImul+1] == 0x03) {
                                            // ADD rax, rdx follows — MBA pattern, addConst from NOT+IMUL
                                        }
                                    }
                                    if (foundChain) break;
                                }
                            }
                            if (!foundChain) continue;

                            // Try known targets: target = key * imulConst + addConst
                            // → key = (target - addConst) * modInverse(imulConst)
                            uint32_t inv = modInverse32(imulConst);
                            for (auto candidateTarget : knownTargets) {
                                if (candidateTarget == 0 || candidateTarget >= soi5) continue;
                                uint32_t neededKey = (candidateTarget - (uint32_t)addConst) * inv;
                                // Validate: key * imulConst + addConst == candidateTarget
                                if (neededKey * imulConst + (uint32_t)addConst == candidateTarget) {
                                    // Verify target is valid code
                                    uint32_t tOff = pe.rvaToOffset(candidateTarget);
                                    if (!tOff) continue;
                                    uint8_t tb = pe.data[tOff];
                                    if (tb == 0xCC || tb == 0x00 || tb == 0x90) continue;
                                    // Accept!
                                    resolvedJmps.push_back({jmpRVA, candidateTarget, jLen});
                                    resolvedSet.insert(jmpRVA);
                                    l5Resolved++;
                                    break;
                                }
                            }
                        }
                    }
                    if (l5Resolved)
                        cli::detail("[L5-symbolic] %u jmp resolved via modular inverse (%.0f ms)",
                               l5Resolved, t5.elapsedMs());
                }

#ifdef USE_UNICORN

                // --- Level 4: Full function Unicorn (only for remaining unresolved) ---
                {
                    Timer t4;
                    uint32_t numThreads = std::min(std::thread::hardware_concurrency(), 8u);
                    if (numThreads < 1) numThreads = 4;
                    uint32_t soi4 = pe.nt->OptionalHeader.SizeOfImage;

                    // Build task list: functions with STILL-unresolved jmp reg
                    struct UcTask { uint32_t funcRVA; std::vector<std::pair<int,uint32_t>> keys; std::vector<std::pair<uint32_t,uint8_t>> jmps; };
                    std::vector<UcTask> ucTasks;
                    {
                        // Use ORIGINAL funcs only (orphans excluded from L4 — too expensive)
                        for (auto funcRVA : originalGrfnFuncs) {
                            GrFunc tf; GriffinDisasm td(pe, actualBase);
                            if (!td.buildCFG(funcRVA, tf)) continue;
                            UcTask task; task.funcRVA = funcRVA;
                            for (auto& blk : tf.blocks) {
                                if (blk.isDeadCode) continue;
                                for (auto& instr : blk.instrs) {
                                    if (instr.dead) continue;
                                    if (instr.op == GrOp::JMP && instr.dst.isReg() &&
                                        !resolvedSet.count((uint32_t)(instr.addr - actualBase)))
                                        task.jmps.push_back({(uint32_t)(instr.addr-actualBase),(uint8_t)instr.rawLen});
                                }
                            }
                            if (task.jmps.empty()) continue;
                            auto kit = funcKeyMap.find(funcRVA);
                            if (kit != funcKeyMap.end()) task.keys = kit->second;
                            ucTasks.push_back(std::move(task));
                        }
                    }
                    cli::detail("[L4-unicorn] %zu tasks on %u threads...", ucTasks.size(), numThreads);

                    std::atomic<uint32_t> ucIdx{0}, ucRes{0}, ucFail{0};
                    std::atomic<uint32_t> uc4_rip0{0}, uc4_ooi{0};
                    std::mutex ucMtx;
                    std::vector<ResolvedJmp> ucResults;
                    std::vector<uint64_t> ucFailRIPs; // final RIP of failed tasks
                    std::vector<uint32_t> ucFailFuncs; // funcRVAs of failed tasks

                    // Build vtable map for vtable call tracking during emulation
                    // key = vtable VA, value = method VAs
                    std::unordered_map<uint64_t, std::vector<uint64_t>> vtableMap;
                    {
                        for (int si = 0; si < pe.numSections; si++) {
                            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                            if (strcmp(sn, ".rdata") != 0) continue;
                            uint32_t rawOff2 = pe.sections[si].PointerToRawData;
                            uint32_t rawSz2 = pe.sections[si].SizeOfRawData;
                            uint32_t secRVA2 = pe.sections[si].VirtualAddress;
                            for (uint32_t p = 0; p + 32 <= rawSz2; p += 8) {
                                int cc = 0;
                                for (int e = 0; e < 40 && p+(e+1)*8 <= rawSz2; e++) {
                                    uint64_t v = *(uint64_t*)(pe.data.data()+rawOff2+p+e*8);
                                    if (v >= actualBase && v < actualBase+soi4) cc++; else break;
                                }
                                if (cc >= 4) {
                                    uint64_t vtVA = actualBase + secRVA2 + p;
                                    auto& methods = vtableMap[vtVA];
                                    for (int e = 0; e < cc; e++)
                                        methods.push_back(*(uint64_t*)(pe.data.data()+rawOff2+p+e*8));
                                    p += cc * 8 - 8;
                                }
                            }
                        }
                    }
                    std::atomic<uint32_t> vtblHits{0};

                    auto ucWorker = [&]() {
                        UnicornVGC uc(pe, actualBase);
                        if (!uc.loadSections() || !uc.setupStack()) return;
                        uc.enableInt3Handler();
                        uc.setKnownVtables(&vtableMap);
                        for (auto& w : importWrappers) uc.addStub(w.wrapperVA, 0);
                        uint64_t sp = (actualBase + soi4 + 0xFFF) & ~0xFFFULL;
                        uint64_t sent = sp + 0x200;
                        uint8_t retB = 0xC3; uc.writeMem(sent, &retB, 1);
                        uc.addExecRange(sp, sp + 0x1000);
                        std::vector<ResolvedJmp> local;
                        while (true) {
                            uint32_t i = ucIdx.fetch_add(1);
                            if (i >= ucTasks.size()) break;
                            if (i % 100 == 0) {
                                printf("\r      [L4] %u/%zu res=%u fail=%u (%.1fs)  ",
                                       i, ucTasks.size(), ucRes.load(), ucFail.load(), t4.elapsedMs()/1000.0);
                                fflush(stdout);
                            }
                            auto& task = ucTasks[i];

                            uc.clearJmpRegWatches();
                            for (auto& [jrva,jlen] : task.jmps)
                                uc.watchJmpReg(actualBase + jrva);

                            for (auto& [reg,val] : task.keys) uc.setReg(reg, val);
                            uint64_t rsp = 0x7FFE0000+0x100000-0x1000;
                            uc.setReg(UC_X86_REG_RSP, rsp); uc.setReg(UC_X86_REG_RBP, rsp);
                            rsp -= 8; uc.writeMem(rsp, &sent, 8); uc.setReg(UC_X86_REG_RSP, rsp);
                            uc.run(actualBase + task.funcRVA, sent, 10000);

                            auto& hits = uc.jmpRegHits();
                            if (!hits.empty()) {
                                for (auto& hit : hits) {
                                    uint32_t jmpRVA = (uint32_t)(hit.jmpAddr - actualBase);
                                    uint32_t targetRVA = (uint32_t)(hit.targetVA - actualBase);
                                    if (targetRVA > 0 && targetRVA < soi4)
                                        local.push_back({jmpRVA, targetRVA, hit.instrLen});
                                }
                                ucRes++;
                            } else {
                                ucFail++;
                                uint64_t fr = uc.getReg(UC_X86_REG_RIP);
                                if (fr == 0 || fr == actualBase + task.funcRVA) uc4_rip0++;
                                else {
                                    uc4_ooi++;
                                    std::lock_guard<std::mutex> lk(ucMtx);
                                    ucFailRIPs.push_back(fr);
                                    ucFailFuncs.push_back(task.funcRVA);
                                }
                            }
                        }
                        // Collect vtable hits
                        vtblHits += (uint32_t)uc.vtableHits().size();
                        std::lock_guard<std::mutex> lk(ucMtx);
                        ucResults.insert(ucResults.end(), local.begin(), local.end());
                        // Collect vtable call resolutions
                        for (auto& vh : uc.vtableHits()) {
                            uint32_t callRVA = (uint32_t)(vh.callAddr - actualBase);
                            uint32_t targetRVA = (uint32_t)(vh.targetVA - actualBase);
                            if (targetRVA > 0 && targetRVA < soi4)
                                ucResults.push_back({callRVA, targetRVA, 6}); // 6 = call [rax+N] len
                        }
                    };
                    { std::vector<std::thread> th;
                      for (uint32_t t=0;t<numThreads;t++) th.emplace_back(ucWorker);
                      for (auto& t:th) t.join(); }

                    mergeResults(ucResults);
                    cli::detail("[L4-unicorn] %u jmp resolved, %u failed (rip0=%u ooi=%u), %u vtable hits (%.0f ms)",
                           ucRes.load(), ucFail.load(), uc4_rip0.load(), uc4_ooi.load(),
                           vtblHits.load(), t4.elapsedMs());
                    // Diagnose: where do failed tasks stop?
                    if (!ucFailRIPs.empty()) {
                        std::unordered_map<std::string, int> secHist;
                        int outsideImage = 0;
                        for (uint64_t rip : ucFailRIPs) {
                            uint32_t rv = (uint32_t)(rip - actualBase);
                            if (rv >= soi4) { outsideImage++; continue; }
                            int sec = pe.findSection(rv);
                            if (sec >= 0) {
                                char sn2[9] = {}; memcpy(sn2, pe.sections[sec].Name, 8);
                                secHist[sn2]++;
                            }
                        }
                        printf("    [L4-diag] Stop section distribution:");
                        for (auto& [s,c] : secHist) printf(" %s=%d", s.c_str(), c);
                        if (outsideImage) printf(" outside=%d", outsideImage);
                        printf("\n");
                        // Print sample failed function RVAs for IDA analysis
                        printf("    [L4-diag] Sample failed funcs:");
                        for (size_t j = 0; j < std::min((size_t)10, ucFailFuncs.size()); j++)
                            printf(" 0x%X", ucFailFuncs[j]);
                        printf("\n");
                    }
                }
#endif

                auto jmpStats = patchIndirectJumps(pe, actualBase, resolvedJmps);
                cli::detail("[JMP-total] %u resolved, %u patched (%.0f ms total)",
                       jmpStats.resolved, jmpStats.patched, tJmp.elapsedMs());

                // Redirect .grfn1 duplicates to .text originals
                // Many .grfn1 functions are obfuscated copies of .text functions.
                // If .text has a function at the same RVA-based name, redirect.
                {
                    Timer tRedir;
                    uint32_t redirected = 0;
                    int textSec = -1, grfnSec = -1;
                    for (int si = 0; si < pe.numSections; si++) {
                        char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                        if (strcmp(sn, ".text") == 0) textSec = si;
                        if (strcmp(sn, ".grfn1") == 0) grfnSec = si;
                    }
                    if (textSec >= 0 && grfnSec >= 0) {
                        uint32_t textVA = pe.sections[textSec].VirtualAddress;
                        uint32_t textEnd = textVA + pe.sections[textSec].Misc.VirtualSize;
                        uint32_t grfnVA = pe.sections[grfnSec].VirtualAddress;
                        uint32_t grfnEnd = grfnVA + pe.sections[grfnSec].Misc.VirtualSize;
                        uint32_t grfnRaw = pe.sections[grfnSec].PointerToRawData;

                        // For each .grfn1 function, check if a .text function exists
                        // that is a call target from .grfn1 trampolines
                        // Simpler: check if the .grfn1 function's first instruction is
                        // a trampoline that jumps to .text (already patched by trampoline pass)
                        // These are already E9 jumps — nothing to do.

                        // Instead: find .grfn1 functions that CALL a .text function
                        // with the same first few bytes (prologue match) — these are copies.
                        // Redirect the .grfn1 entry to the .text version.

                        // Practical approach: for each .grfn1 function entry from .pdata,
                        // if the function starts with E9 (already a trampoline/redirect), skip.
                        // If it starts with real code that has unresolved jmp reg →
                        // check if .text has a function with matching prologue bytes.
                        auto pdataFuncs2 = readPdataFunctions(pe);
                        std::unordered_map<uint64_t, uint32_t> textPrologueMap;

                        // Build map: first 8 prologue bytes → .text function RVA
                        for (auto& fb : pdataFuncs2) {
                            if (fb.beginRVA < textVA || fb.beginRVA >= textEnd) continue;
                            uint32_t off = pe.rvaToOffset(fb.beginRVA);
                            if (!off || off + 8 > pe.data.size()) continue;
                            uint64_t prologKey = *(uint64_t*)(pe.data.data() + off);
                            if (prologKey == 0 || prologKey == 0xCCCCCCCCCCCCCCCC) continue;
                            textPrologueMap[prologKey] = fb.beginRVA;
                        }

                        for (auto funcRVA : grfnFuncs) {
                            uint32_t off = pe.rvaToOffset(funcRVA);
                            if (!off || off + 8 > pe.data.size()) continue;
                            if (pe.data[off] == 0xE9) continue; // already redirected

                            uint64_t prologKey = *(uint64_t*)(pe.data.data() + off);
                            auto it = textPrologueMap.find(prologKey);
                            if (it == textPrologueMap.end()) continue;

                            uint32_t textFuncRVA = it->second;
                            if (textFuncRVA == funcRVA) continue;

                            // Redirect: write E9 [disp to .text func]
                            int32_t disp = (int32_t)(textFuncRVA - (funcRVA + 5));
                            pe.data[off] = 0xE9;
                            memcpy(pe.data.data() + off + 1, &disp, 4);
                            redirected++;
                        }
                    }
                    if (redirected)
                        cli::detail("[Redirect] %u .grfn1 duplicates → .text originals (%.0f ms)",
                               redirected, tRedir.elapsedMs());
                }

                // === Comprehensive sanitize pass ===
                cli::detail("[Sanitize]");
                uint32_t sanAD = 0, sanNopToCC = 0;

                // 1. Anti-disasm: full rescan all executable sections
                for (int si = 0; si < pe.numSections; si++) {
                    if (!pe.isExecutableSection(si)) continue;
                    uint32_t rawOff = pe.sections[si].PointerToRawData;
                    uint32_t rawSz = pe.sections[si].SizeOfRawData;
                    for (uint32_t p = 0; p + 4 < rawSz; p++) {
                        uint32_t o = rawOff + p;
                        if (pe.data[o] == 0xEB && pe.data[o+1] == 0xFF &&
                            pe.data[o+2] == 0xF0 && pe.data[o+3] == 0x48) {
                            pe.data[o] = 0x90; pe.data[o+1] = 0x90; pe.data[o+2] = 0x90;
                            sanAD++;
                        }
                        if (pe.data[o] == 0xEB && pe.data[o+1] == 0xFE) {
                            pe.data[o] = 0xCC; pe.data[o+1] = 0xCC;
                            sanAD++;
                        }
                    }
                }

                // 2. Pattern-based CC/NOP classification in .grfn1
                //    Step A: ALL CC → NOP (clean slate)
                //    Step B: Scan NOP runs, classify as boundary vs intra-function
                //      Boundary (→CC): (RET/JMP before) AND (prologue after OR known func entry)
                //      Intra-function (stays NOP): everything else
                uint32_t boundaryRuns = 0, intraRuns = 0;

                // Build fast lookup for known function entries
                std::unordered_set<uint32_t> funcEntrySet(grfnFuncs.begin(), grfnFuncs.end());

                for (int si = 0; si < pe.numSections; si++) {
                    char sn2[9] = {};
                    memcpy(sn2, pe.sections[si].Name, 8);
                    if (strcmp(sn2, ".grfn1") != 0) continue;
                    uint32_t secRVA = pe.sections[si].VirtualAddress;
                    uint32_t rawOff = pe.sections[si].PointerToRawData;
                    uint32_t rawSz = pe.sections[si].SizeOfRawData;

                    // Step A: ALL CC → NOP
                    for (uint32_t p = 0; p < rawSz; p++) {
                        if (pe.data[rawOff + p] == 0xCC) {
                            pe.data[rawOff + p] = 0x90;
                            sanNopToCC++;
                        }
                    }

                    // Step B: Pattern-based boundary detection
                    for (uint32_t p = 0; p < rawSz; p++) {
                        if (pe.data[rawOff + p] != 0x90) continue;
                        uint32_t runStart = p;
                        uint32_t nopLen = 0;
                        while (p + nopLen < rawSz && pe.data[rawOff + p + nopLen] == 0x90) nopLen++;

                        if (nopLen < 2) { p += nopLen - 1; continue; }

                        // --- Check BEFORE the run: function terminator? ---
                        bool terminatorBefore = false;
                        if (runStart > 0) {
                            uint8_t prev = pe.data[rawOff + runStart - 1];
                            // C3 = RET
                            if (prev == 0xC3) terminatorBefore = true;
                            // Check for JMP near (E9 xx xx xx xx) ending at runStart
                            if (runStart >= 5) {
                                uint8_t b5 = pe.data[rawOff + runStart - 5];
                                if (b5 == 0xE9) terminatorBefore = true;
                            }
                            // JMP short (EB xx) ending at runStart
                            if (runStart >= 2) {
                                uint8_t b2 = pe.data[rawOff + runStart - 2];
                                if (b2 == 0xEB) terminatorBefore = true;
                            }
                            // CALL near (E8 xx xx xx xx) — noreturn call
                            if (runStart >= 5) {
                                uint8_t bc = pe.data[rawOff + runStart - 5];
                                if (bc == 0xE8) terminatorBefore = true;
                            }
                        } else {
                            terminatorBefore = true; // section start
                        }

                        // --- Check AFTER the run: prologue or known entry? ---
                        bool prologueAfter = false;
                        uint32_t afterPos = runStart + nopLen;
                        uint32_t afterRVA = secRVA + afterPos;

                        // Known function entry?
                        if (funcEntrySet.count(afterRVA))
                            prologueAfter = true;

                        // Pattern-match prologue
                        if (!prologueAfter && afterPos + 4 < rawSz) {
                            const uint8_t* a = pe.data.data() + rawOff + afterPos;
                            // 48 89 5C 24 — mov [rsp+X], rbx
                            if (a[0] == 0x48 && a[1] == 0x89 && a[2] == 0x5C && a[3] == 0x24)
                                prologueAfter = true;
                            // 48 89 4C 24 — mov [rsp+X], rcx
                            if (a[0] == 0x48 && a[1] == 0x89 && a[2] == 0x4C && a[3] == 0x24)
                                prologueAfter = true;
                            // 48 89 6C 24 — mov [rsp+X], rbp
                            if (a[0] == 0x48 && a[1] == 0x89 && a[2] == 0x6C && a[3] == 0x24)
                                prologueAfter = true;
                            // 48 89 74 24 — mov [rsp+X], rsi
                            if (a[0] == 0x48 && a[1] == 0x89 && a[2] == 0x74 && a[3] == 0x24)
                                prologueAfter = true;
                            // 48 83 EC — sub rsp, imm8
                            if (a[0] == 0x48 && a[1] == 0x83 && a[2] == 0xEC)
                                prologueAfter = true;
                            // 48 81 EC — sub rsp, imm32
                            if (a[0] == 0x48 && a[1] == 0x81 && a[2] == 0xEC)
                                prologueAfter = true;
                            // 48 8B C4 — mov rax, rsp
                            if (a[0] == 0x48 && a[1] == 0x8B && a[2] == 0xC4)
                                prologueAfter = true;
                            // 4C 8B DC — mov r11, rsp
                            if (a[0] == 0x4C && a[1] == 0x8B && a[2] == 0xDC)
                                prologueAfter = true;
                            // 40 53/55/56/57 — push rbx/rbp/rsi/rdi
                            if (a[0] == 0x40 && (a[1] == 0x53 || a[1] == 0x55 || a[1] == 0x56 || a[1] == 0x57))
                                prologueAfter = true;
                            // 41 54~57 — push r12~r15
                            if (a[0] == 0x41 && a[1] >= 0x54 && a[1] <= 0x57)
                                prologueAfter = true;
                            // 55/53/56/57 — push rbp/rbx/rsi/rdi (without REX)
                            if (a[0] == 0x55 || a[0] == 0x53 || a[0] == 0x56 || a[0] == 0x57)
                                prologueAfter = true;
                            // E9 — JMP (trampoline entry)
                            if (a[0] == 0xE9)
                                prologueAfter = true;
                            // C3 — RET (stub function)
                            if (a[0] == 0xC3)
                                prologueAfter = true;
                        }

                        // --- Classify ---
                        bool isBoundary = false;
                        if (terminatorBefore && prologueAfter)
                            isBoundary = true;
                        // Very long runs (>=64) at section edges: likely boundary
                        if (nopLen >= 64 && (runStart == 0 || afterPos >= rawSz))
                            isBoundary = true;

                        if (isBoundary) {
                            for (uint32_t n = 0; n < nopLen; n++)
                                pe.data[rawOff + runStart + n] = 0xCC;
                            boundaryRuns++;
                        } else {
                            intraRuns++;
                        }

                        p += nopLen - 1;
                    }
                }
                cli::detail("Pattern CC/NOP: %u boundary runs (→CC), %u intra-func runs (→NOP)",
                       boundaryRuns, intraRuns);

                // 3. Collapse JMP short + CC filler to pure CC (.grfn1 only)
                for (int si = 0; si < pe.numSections; si++) {
                    char sn3[9] = {};
                    memcpy(sn3, pe.sections[si].Name, 8);
                    if (strcmp(sn3, ".grfn1") != 0) continue;
                    uint32_t rawOff = pe.sections[si].PointerToRawData;
                    uint32_t rawSz = pe.sections[si].SizeOfRawData;
                    for (uint32_t p = 0; p + 3 < rawSz; p++) {
                        uint32_t o = rawOff + p;
                        if (pe.data[o] == 0xEB && pe.data[o + 2] == 0xCC) {
                            uint8_t jl = pe.data[o + 1] + 2;
                            if (jl >= 3 && jl <= 127) {
                                bool allCC = true;
                                for (int n = 2; n < jl && o + n < rawOff + rawSz; n++)
                                    if (pe.data[o + n] != 0xCC) { allCC = false; break; }
                                if (allCC) { pe.data[o] = 0xCC; pe.data[o + 1] = 0xCC; }
                            }
                        }
                    }
                }

                cli::detail("Anti-disasm: %u", sanAD);
                cli::detail("CC→NOP (clean slate): %u bytes", sanNopToCC);

                // 4. Validate exports (skip — exports are generated by us, always valid)

                // NOP collapse removed — sanitize handles long NOPs (>=10 → CC)
                // Short NOPs (1-9) stay as NOP inside functions

                // Function boundary repair: ensure CC/INT3 before each function entry
                // This helps IDA correctly split functions
                uint32_t boundaryFixed = 0;
                for (auto funcRVA : grfnFuncs) {
                    uint32_t off = pe.rvaToOffset(funcRVA);
                    if (!off || off < 2) continue;

                    // Write CC before function start (if it's NOP or other non-CC)
                    if (pe.data[off - 1] == 0x90 || pe.data[off - 1] == 0x00) {
                        pe.data[off - 1] = 0xCC;
                        boundaryFixed++;
                    }
                    // If 2 bytes before is also NOP, make it CC too (wider boundary)
                    if (off >= 2 && (pe.data[off - 2] == 0x90 || pe.data[off - 2] == 0x00)) {
                        pe.data[off - 2] = 0xCC;
                    }
                }
                // Also fix trampoline boundaries
                for (auto& tr : trampolines) {
                    uint32_t trRVA = (uint32_t)(tr.trampolineVA - actualBase);
                    uint32_t off = pe.rvaToOffset(trRVA);
                    if (!off || off < 2) continue;
                    // CC after trampoline JMP (5 bytes)
                    for (int n = 5; n < 12 && off + n < pe.data.size(); n++) {
                        if (pe.data[off + n] == 0x90)
                            pe.data[off + n] = 0xCC;
                        else break;
                    }
                }
                if (boundaryFixed > 0)
                    cli::detail("Boundaries: %u entries fixed", boundaryFixed);

                // (Intra-func CC→NOP is now handled by pattern-based pass above)

                // Validate .pdata entries: check that each function start
                // points to valid code (not NOP/CC filler)
                uint32_t pdataValid = 0, pdataInvalid = 0, pdataRepaired = 0;
                for (int si = 0; si < pe.numSections; si++) {
                    char sn[9] = {};
                    memcpy(sn, pe.sections[si].Name, 8);
                    if (strcmp(sn, ".pdata") != 0) continue;
                    uint32_t pdataOff = pe.sections[si].PointerToRawData;
                    uint32_t pdataSz = pe.sections[si].SizeOfRawData;
                    uint32_t count = pdataSz / 12;
                    uint32_t soi2 = pe.nt->OptionalHeader.SizeOfImage;

                    for (uint32_t e = 0; e < count; e++) {
                        uint32_t* entry = (uint32_t*)(pe.data.data() + pdataOff + e * 12);
                        uint32_t beginRVA = entry[0];
                        uint32_t unwindRVA = entry[2];

                        if (beginRVA == 0 || beginRVA >= soi2) continue;

                        // Remove ALL .grfn1 entries unconditionally (deobf invalidates unwind)
                        int beginSec = pe.findSection(beginRVA);
                        if (beginSec >= 0) {
                            char secN[9] = {};
                            memcpy(secN, pe.sections[beginSec].Name, 8);
                            if (strcmp(secN, ".grfn1") == 0) {
                                entry[0] = 0; entry[1] = 0; entry[2] = 0;
                                pdataInvalid++;
                                continue;
                            }
                        }

                        // beginRVA must point to an executable section
                        if (beginSec < 0 || !pe.isExecutableSection(beginSec)) {
                            entry[0] = 0; entry[1] = 0; entry[2] = 0;
                            pdataInvalid++;
                            continue;
                        }

                        uint32_t codeOff = pe.rvaToOffset(beginRVA);
                        if (!codeOff) { pdataInvalid++; continue; }

                        uint8_t firstByte = pe.data[codeOff];

                        // Valid: function prologue (push, sub rsp, mov rsp)
                        bool isValid = (firstByte == 0x40 || firstByte == 0x41 ||
                                       firstByte == 0x48 || firstByte == 0x4C ||
                                       firstByte == 0x55 || firstByte == 0x53 ||
                                       firstByte == 0x56 || firstByte == 0x57 ||
                                       firstByte == 0x50 || firstByte == 0x51 ||
                                       firstByte == 0xE9 || // JMP (trampoline)
                                       firstByte == 0xC3);  // RET (stub)

                        // Invalid: CC, 90, EB (filler), 00
                        if (firstByte == 0xCC || firstByte == 0x90 ||
                            firstByte == 0xEB || firstByte == 0x00) {
                            isValid = false;
                        }

                        // E9 = JMP trampoline: unwind prolog can never match a JMP instruction.
                        // Remove unconditionally — functions are still found via COFF/exports.
                        if (firstByte == 0xE9) {
                            entry[0] = 0; entry[1] = 0; entry[2] = 0;
                            pdataInvalid++;
                            continue;
                        }

                        if (isValid) {
                            // After deobf, ALL .grfn1 unwind data is invalid (code was patched)
                            // Remove .grfn1 entries unconditionally to prevent IDA unwind errors
                            char secName[9] = {};
                            memcpy(secName, pe.sections[beginSec].Name, 8);
                            if (strcmp(secName, ".grfn1") == 0) {
                                entry[0] = 0; entry[1] = 0; entry[2] = 0;
                                pdataInvalid++;
                                continue;
                            }

                            // For other sections: validate UNWIND_INFO structure
                            uint32_t uwOff = pe.rvaToOffset(unwindRVA);
                            bool unwindOK = false;
                            if (uwOff && uwOff + 4 < pe.data.size()) {
                                uint8_t ver = pe.data[uwOff] & 0x7;
                                uint8_t flags = (pe.data[uwOff] >> 3) & 0x1F;
                                uint8_t prologSz = pe.data[uwOff + 1];
                                uint8_t codeCount = pe.data[uwOff + 2];
                                unwindOK = (ver >= 1 && ver <= 2 && flags <= 7
                                            && prologSz < 200 && codeCount < 128);
                            }
                            if (unwindOK) {
                                pdataValid++;
                                continue;
                            }
                            entry[0] = 0; entry[1] = 0; entry[2] = 0;
                            pdataInvalid++;
                        } else {
                            // Function start is in patched area — remove entry
                            entry[0] = 0;
                            entry[1] = 0;
                            entry[2] = 0;
                            pdataInvalid++;
                        }
                    }
                }
                cli::detail(".pdata: %u valid, %u removed, %u repaired",
                       pdataValid, pdataInvalid, pdataRepaired);
            }

            cli::info("=== Batch scan complete: %.1f seconds ===", tScan.elapsedMs() / 1000.0);
            cli::detail("Functions: %u/%zu processed (%.0f%%), %u tiny(<10), %u large(>30k), %u CFG failed",
                   totalFuncs, grfnFuncs.size(),
                   grfnFuncs.size() > 0 ? totalFuncs * 100.0 / grfnFuncs.size() : 0,
                   skippedTiny, skippedLarge, failedCFG);
            cli::detail("Dispatch keys: %u/%u (%.0f%%)", keysFound, totalFuncs,
                   totalFuncs > 0 ? keysFound * 100.0 / totalFuncs : 0);
            cli::detail("PE patches:  %u instructions", totalPatched);
        } else {
            cli::detail(".grfn1 section not found");
        }
    }

    if (deobfScan) {
        auto xr = griffin::resolveGriffinXrefs(pe, actualBase, 3);
        cli::ok("Griffin xref resolve: %zu xrefs, %u unique .rdata targets",
                xr.xrefs.size(), xr.uniqueTargets);
    }

    // A5: Post-deobf NOP → CC conversion (IDA function boundary clarity)
    if (deobfScan) {
        uint32_t nopConverted = 0;
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".grfn1") != 0) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            uint32_t nopRun = 0;
            for (uint32_t p = 0; p < rawSz; p++) {
                if (pe.data[rawOff+p] == 0x90) { nopRun++; continue; }
                // Convert NOP runs >= 4 bytes to CC (INT3) — marks dead code for IDA
                if (nopRun >= 4) {
                    for (uint32_t k = p - nopRun; k < p; k++) pe.data[rawOff+k] = 0xCC;
                    nopConverted += nopRun;
                }
                nopRun = 0;
            }
        }
        if (nopConverted) printf("[+] Post-deobf: %u NOP bytes → CC in .grfn1 (%u KB)\n",
                                  nopConverted, nopConverted/1024);
    }

    // A5b: Inline INT3 constant NOP (Griffin uses INT3 as inline data between code)
    // Griffin VEH embeds constant data as CC runs within functions. The handler reads
    // the CC bytes as data and skips over them. NOP them so IDA can disassemble through.
    // Expanded: CC runs 3-15, code gaps up to 15 bytes, chain processing, wide valid-byte set.
    if (deobfScan) {
        uint32_t inlineInt3 = 0;

        auto isValidInstrByte = [](uint8_t b) -> bool {
            if (b >= 0x40 && b <= 0x4F) return true; // REX prefixes
            if (b >= 0x50 && b <= 0x5F) return true; // PUSH/POP reg
            if (b >= 0x80 && b <= 0x8F) return true; // ALU r/m,imm / MOV / Jcc
            if (b >= 0xB0 && b <= 0xBF) return true; // MOV reg, imm
            switch (b) {
                case 0x0F: case 0x01: case 0x03: case 0x09: case 0x0B:
                case 0x21: case 0x23: case 0x25: case 0x29: case 0x2B: case 0x2D:
                case 0x31: case 0x33: case 0x35: case 0x39: case 0x3B: case 0x3D:
                case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
                case 0x68: case 0x69: case 0x6B:
                case 0xC1: case 0xC6: case 0xC7:
                case 0xD1: case 0xD3:
                case 0xE8: case 0xE9: case 0xEB:
                case 0xF2: case 0xF3: case 0xF6: case 0xF7:
                case 0xFE: case 0xFF:
                    return true;
            }
            return false;
        };

        // Bytes that indicate a function boundary (CC after these = padding, not inline data)
        auto isBoundaryBefore = [](uint8_t b) -> bool {
            return b == 0xC3 || b == 0x00 || b == 0x90;
        };

        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".grfn1") != 0) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;

            for (uint32_t p = 1; p + 8 < rawSz; p++) {
                if (pe.data[rawOff+p] != 0xCC) continue;
                if (pe.data[rawOff+p-1] == 0xCC) continue; // must start at CC boundary

                uint8_t beforeByte = pe.data[rawOff + p - 1];
                if (isBoundaryBefore(beforeByte)) continue;

                // Count first CC run
                uint32_t run1 = 0;
                while (p + run1 < rawSz && pe.data[rawOff+p+run1] == 0xCC) run1++;
                if (run1 < 3 || run1 > 15) continue;

                // After first CC run: must be valid instruction byte
                uint32_t cursor = p + run1;
                if (cursor + 1 >= rawSz) continue;
                if (!isValidInstrByte(pe.data[rawOff + cursor])) continue;

                // Chain: process consecutive (code + CC) segments
                // Accumulate all CC runs to NOP as a batch
                struct CCRun { uint32_t start; uint32_t len; };
                std::vector<CCRun> runs;
                runs.push_back({p, run1});

                while (cursor + 3 < rawSz) {
                    // Measure code gap
                    uint32_t codeLen = 0;
                    while (cursor + codeLen < rawSz && pe.data[rawOff+cursor+codeLen] != 0xCC) codeLen++;
                    if (codeLen < 1 || codeLen > 15) break;

                    // Measure next CC run
                    uint32_t nextCC = cursor + codeLen;
                    uint32_t runN = 0;
                    while (nextCC + runN < rawSz && pe.data[rawOff+nextCC+runN] == 0xCC) runN++;
                    if (runN < 3 || runN > 15) break;

                    // After this CC run: must also be valid code (or we're at the last segment)
                    uint32_t afterN = nextCC + runN;
                    if (afterN < rawSz && !isValidInstrByte(pe.data[rawOff + afterN])) break;

                    runs.push_back({nextCC, runN});
                    cursor = afterN;
                }

                // Need at least 2 CC runs to confirm inline data pattern
                if (runs.size() < 2) continue;

                // Final validation: byte after last CC run must be valid instruction
                uint32_t lastEnd = runs.back().start + runs.back().len;
                if (lastEnd >= rawSz) continue;
                if (!isValidInstrByte(pe.data[rawOff + lastEnd])) continue;

                // NOP all CC runs in the chain
                for (auto& r : runs) {
                    for (uint32_t k = 0; k < r.len; k++)
                        pe.data[rawOff + r.start + k] = 0x90;
                    inlineInt3 += r.len;
                }
                p = lastEnd - 1;
            }
        }

        // Pass 2: Single CC runs (3-15) bounded by valid code on BOTH sides
        // These are isolated inline constants that don't form chains
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".grfn1") != 0) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;

            for (uint32_t p = 1; p + 4 < rawSz; p++) {
                if (pe.data[rawOff+p] != 0xCC) continue;
                if (pe.data[rawOff+p-1] == 0xCC) continue;

                uint32_t run = 0;
                while (p + run < rawSz && pe.data[rawOff+p+run] == 0xCC) run++;
                if (run < 3 || run > 15) { p += run - 1; continue; }

                // Already NOP'd by pass 1?
                if (pe.data[rawOff+p] == 0x90) { p += run - 1; continue; }

                uint8_t before = pe.data[rawOff + p - 1];
                if (isBoundaryBefore(before)) { p += run - 1; continue; }

                // E9 (jmp rel32) before = tail call → boundary, not inline
                if (p >= 5 && pe.data[rawOff+p-5] == 0xE9) { p += run - 1; continue; }

                uint32_t after = p + run;
                if (after >= rawSz) { p += run - 1; continue; }
                if (!isValidInstrByte(pe.data[rawOff + after])) { p += run - 1; continue; }

                // Additional safety: check 2 bytes after CC run for plausibility
                // (prevents NOP'ing actual function-boundary padding that follows a JMP)
                if (after + 1 < rawSz) {
                    uint8_t b2 = pe.data[rawOff + after + 1];
                    // If first byte is REX (40-4F) and second byte is CC, it's likely boundary
                    if (pe.data[rawOff + after] >= 0x40 && pe.data[rawOff + after] <= 0x4F && b2 == 0xCC)
                        { p += run - 1; continue; }
                }

                for (uint32_t k = 0; k < run; k++)
                    pe.data[rawOff + p + k] = 0x90;
                inlineInt3 += run;
                p += run - 1;
            }
        }

        if (inlineInt3)
            cli::ok("Inline INT3 constants NOP'd: %u bytes (%u KB)", inlineInt3, inlineInt3/1024);
    }

    // A6: Extended EB FF patch (residual anti-disasm after deobf)
    if (deobfScan) {
        uint32_t ebffPost = 0;
        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            for (uint32_t p = 0; p + 3 <= rawSz; p++) {
                if (pe.data[rawOff+p] != 0xEB || pe.data[rawOff+p+1] != 0xFF) continue;
                if (pe.data[rawOff+p] == 0x90) continue;
                // Patch any remaining EB FF → NOP NOP
                pe.data[rawOff+p] = 0x90;
                pe.data[rawOff+p+1] = 0x90;
                ebffPost++;
            }
        }
        cli::ok("Post-deobf: %u EB FF patched", ebffPost);
    }

    // A7: Griffin VEH handler detection (dynamic, version-independent)
    // Signature: 9C 48 8D A4 24 XX FD FF FF  (pushfq; lea rsp, [rsp-XXXh])
    // Detects convergence points where dispatch stubs route to shared handlers
    if (deobfScan) {
        Timer tVeh;
        uint32_t soi_vh = pe.nt->OptionalHeader.SizeOfImage;
        std::vector<uint32_t> vehHandlers;

        // Step 1: Find VEH handler candidates by signature
        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            for (uint32_t p = 0; p + 9 <= rawSz; p++) {
                uint32_t off = rawOff + p;
                if (pe.data[off] != 0x9C) continue; // pushfq
                if (pe.data[off+1] != 0x48 || pe.data[off+2] != 0x8D ||
                    pe.data[off+3] != 0xA4 || pe.data[off+4] != 0x24) continue; // lea rsp, [rsp+...]
                // Check negative displacement (0xFDxxxxxx = large stack frame)
                if (pe.data[off+7] != 0xFF || pe.data[off+8] != 0xFF) continue;
                vehHandlers.push_back(secRVA + p);
            }
        }

        // Step 2: Count how many dispatch stubs (NOP/CC + E9) target each handler
        std::unordered_map<uint32_t, uint32_t> handlerRefCount;
        for (auto h : vehHandlers) handlerRefCount[h] = 0;

        uint32_t totalDispStubs = 0;
        std::unordered_map<uint32_t, uint32_t> stubToHandler; // stubRVA → handlerRVA

        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            for (uint32_t p = 0; p + 8 <= rawSz; p++) {
                uint32_t off = rawOff + p;
                uint8_t b0 = pe.data[off], b1 = pe.data[off+1], b2 = pe.data[off+2], b3 = pe.data[off+3];
                if (!((b0 == 0xCC || b0 == 0x90) && (b1 == 0xCC || b1 == 0x90) &&
                      (b2 == 0xCC || b2 == 0x90) && b3 == 0xE9)) continue;
                int32_t d = *(int32_t*)(pe.data.data() + off + 4);
                uint32_t stubRVA = secRVA + p;
                uint32_t target = stubRVA + 3 + 5 + d;
                if (handlerRefCount.count(target)) {
                    handlerRefCount[target]++;
                    stubToHandler[stubRVA] = target;
                    totalDispStubs++;
                }
            }
        }

        // Filter: only handlers with 10+ references are confirmed
        std::unordered_set<uint32_t> confirmedHandlers;
        for (auto& [h, cnt] : handlerRefCount)
            if (cnt >= 10) confirmedHandlers.insert(h);

        // Step 3: Find CALL+JMP rax sites where CALL targets a confirmed dispatch stub
        uint32_t deadJmpRax = 0;
        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            for (uint32_t p = 0; p + 7 <= rawSz; p++) {
                uint32_t off = rawOff + p;
                if (pe.data[off] != 0xE8) continue; // CALL rel32
                if (pe.data[off+5] != 0xFF || pe.data[off+6] != 0xE0) continue; // followed by jmp rax
                int32_t cd = *(int32_t*)(pe.data.data() + off + 1);
                uint32_t callTarget = secRVA + p + 5 + cd;
                if (stubToHandler.count(callTarget) && confirmedHandlers.count(stubToHandler[callTarget])) {
                    // This jmp rax is dead code — the dispatch stub never returns
                    pe.data[off+5] = 0xCC;
                    pe.data[off+6] = 0xCC;
                    deadJmpRax++;
                }
            }
        }

        if (!vehHandlers.empty()) {
            cli::info("Griffin VEH handler detection:");
            cli::detail("Signature: pushfq + lea rsp, [rsp-XXXh]");
            cli::detail("Candidates: %zu, confirmed (10+ refs): %zu", vehHandlers.size(), confirmedHandlers.size());
            for (auto h : confirmedHandlers)
                cli::detail("Handler 0x%X: %u dispatch stubs", h, handlerRefCount[h]);
            cli::detail("Total dispatch stubs: %u", totalDispStubs);
            cli::detail("Dead jmp-rax patched: %u (%.0f ms)", deadJmpRax, tVeh.elapsedMs());
        }
    }

    // .riot1 dispatch chain resolution
    // MBA pattern: imul rax, rbp, C1; not rbp; imul rdx, rbp, C2; add rax, rdx → rax = XOR(rbp, C1^C2)
    // Resolve by: scanning epilogue pattern, extracting C1/C2, trying known targets
    if (deobfScan) {
        Timer tRiot;
        uint32_t riotResolved = 0, riotStubs = 0;
        uint32_t soi_r = pe.nt->OptionalHeader.SizeOfImage;

        // Collect all known function starts as candidate targets
        std::unordered_set<uint32_t> candidateTargetSet;
        auto pdataR = readPdataFunctions(pe);
        for (auto& fb : pdataR) candidateTargetSet.insert(fb.beginRVA);
        for (auto& ef : extraFunctions) candidateTargetSet.insert(ef.beginRVA);
        // Import wrapper addresses
        for (auto& w : importWrappers) {
            uint32_t wRVA = (uint32_t)(w.wrapperVA - actualBase);
            if (wRVA > 0 && wRVA < soi_r) candidateTargetSet.insert(wRVA);
        }

        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".riot1") != 0) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;

            // Scan for epilogue pattern: pop rbx; pop rbp; pop rdi; pop rsi; pop r12-r15; jmp rax
            // Bytes: 5B 5D 5F 5E 41 5C 41 5D 41 5E 41 5F FF E0
            // Or variant with add rsp first
            for (uint32_t p = 20; p + 14 < rawSz; p++) {
                uint32_t off = rawOff + p;
                // Check epilogue ending with jmp rax (FF E0)
                if (pe.data[off+12] != 0xFF || pe.data[off+13] != 0xE0) continue;
                // Verify pop chain: 5B 5D 5F 5E 41 5C 41 5D 41 5E 41 5F
                if (pe.data[off] != 0x5B || pe.data[off+1] != 0x5D ||
                    pe.data[off+2] != 0x5F || pe.data[off+3] != 0x5E ||
                    pe.data[off+4] != 0x41 || pe.data[off+5] != 0x5C ||
                    pe.data[off+6] != 0x41 || pe.data[off+7] != 0x5D ||
                    pe.data[off+8] != 0x41 || pe.data[off+9] != 0x5E ||
                    pe.data[off+10] != 0x41 || pe.data[off+11] != 0x5F) continue;

                riotStubs++;
                uint32_t jmpRVA = secRVA + p + 12;

                // Backward scan for MBA target computation
                // Pattern A: 48 69 XX [C1:4] 48 F7 Dx 48 69 XX [C2:4] 48 03 XX (imul+not+imul+add)
                // Pattern C: 49 B8/B9 [imm64] 4D 0F AF XX (mov r8/r9,imm64; imul r9,r10)
                for (uint32_t bk = 14; bk < 100 && p >= bk; bk++) {
                    uint32_t sOff = rawOff + p - bk;

                    // === Pattern A: IMUL rax, reg, imm32 + NOT + IMUL + ADD ===
                    if (pe.data[sOff] == 0x48 && pe.data[sOff+1] == 0x69) {
                        uint8_t modrm1 = pe.data[sOff+2];
                        if ((modrm1 & 0xC0) != 0xC0) continue;
                        int32_t c1 = *(int32_t*)(pe.data.data() + sOff + 3);

                        for (uint32_t fwd = 7; fwd < 30 && sOff + fwd + 10 <= rawOff + p; fwd++) {
                            uint32_t nOff = sOff + fwd;
                            if (pe.data[nOff] != 0x48 || pe.data[nOff+1] != 0xF7) continue;
                            uint8_t notReg = pe.data[nOff+2];
                            if ((notReg & 0xF8) != 0xD0) continue;

                            if (nOff + 3 + 7 > rawOff + p) continue;
                            if (pe.data[nOff+3] != 0x48 || pe.data[nOff+4] != 0x69) continue;
                            int32_t c2 = *(int32_t*)(pe.data.data() + nOff + 6);

                            uint32_t addOff = nOff + 10;
                            bool hasAdd = false;
                            for (uint32_t af = 0; af < 5 && addOff + af + 3 <= rawOff + p; af++) {
                                uint32_t a = addOff + af;
                                if (pe.data[a]==0x48 && pe.data[a+1]==0x03 && (pe.data[a+2]&0xC0)==0xC0) { hasAdd=true; break; }
                                if (pe.data[a]==0x48 && pe.data[a+1]==0x01 && (pe.data[a+2]&0xC0)==0xC0) { hasAdd=true; break; }
                                if (pe.data[a]==0x4C && pe.data[a+1]==0x01 && (pe.data[a+2]&0xC0)==0xC0) { hasAdd=true; break; }
                                if (pe.data[a]==0x49 && pe.data[a+1]==0x01 && (pe.data[a+2]&0xC0)==0xC0) { hasAdd=true; break; }
                            }
                            if (!hasAdd) continue;

                            // MBA XOR: target = rbp * c1 + (~rbp) * c2
                            // = rbp * (c1 - c2) + (-1) * c2 (mod 2^64)
                            // For each candidate target T:
                            //   T = rbp * (c1-c2) + FFFF...FF * c2
                            //   rbp = (T - FFFF...FF * c2) / (c1 - c2) — need modular inverse
                            int64_t diff = (int64_t)c1 - (int64_t)c2;
                            if (diff == 0) break;
                            // 64-bit modular inverse
                            uint64_t udiff = (uint64_t)diff;
                            if ((udiff & 1) == 0) break; // must be odd
                            uint64_t inv = udiff;
                            for (int it = 0; it < 6; it++) inv = inv * (2 - udiff * inv);
                            uint64_t base = (uint64_t)(-1LL) * (uint64_t)(uint32_t)c2;

                            // Try each candidate
                            for (uint32_t cand : candidateTargetSet) {
                                uint64_t candVA = (uint64_t)actualBase + cand;
                                uint64_t rbpNeeded = (candVA - base) * inv;
                                // Verify: rbpNeeded * c1 + (~rbpNeeded) * c2 == candVA
                                uint64_t check = rbpNeeded * (uint64_t)(uint32_t)c1 + (~rbpNeeded) * (uint64_t)(uint32_t)c2;
                                if (check == candVA) {
                                    // Verify target is valid code
                                    uint32_t tOff = pe.rvaToOffset(cand);
                                    if (!tOff) continue;
                                    uint8_t tb = pe.data[tOff];
                                    if (tb == 0xCC || tb == 0x00) continue;

                                    // Patch: replace epilogue+jmp with E9 direct jmp
                                    // Use the add rsp instruction as patch start (before pop chain)
                                    // Find add rsp before the pop chain
                                    uint32_t patchStart = off;
                                    if (off >= 4 && pe.data[off-4] == 0x48 && pe.data[off-3] == 0x83 && pe.data[off-2] == 0xC4) {
                                        patchStart = off - 4; // include add rsp, imm8
                                    } else if (off >= 7 && pe.data[off-7] == 0x48 && pe.data[off-6] == 0x81 && pe.data[off-5] == 0xC4) {
                                        patchStart = off - 7; // include add rsp, imm32
                                    }
                                    uint32_t patchRVA = secRVA + (patchStart - rawOff);
                                    uint32_t patchLen = (off + 14) - patchStart;
                                    if (patchLen >= 5) {
                                        int32_t rel = (int32_t)(cand - (patchRVA + 5));
                                        pe.data[patchStart] = 0xE9;
                                        memcpy(pe.data.data() + patchStart + 1, &rel, 4);
                                        for (uint32_t n = 5; n < patchLen; n++) pe.data[patchStart + n] = 0x90;
                                        riotResolved++;
                                    }
                                    goto nextStub;
                                }
                            }
                            break; // found MBA pattern but no matching target
                        }

                        // === Pattern C: MOV r9, imm64 + IMUL r9, r10 chain ===
                        // 49 B8/B9 [imm64:8] + 4D 0F AF [modrm] + ADD/NOT chain
                        if ((pe.data[sOff] == 0x49 || pe.data[sOff] == 0x48) &&
                            (pe.data[sOff+1] >= 0xB8 && pe.data[sOff+1] <= 0xBF)) {
                            int64_t c64 = *(int64_t*)(pe.data.data() + sOff + 2);
                            // Look for NOT + second MOV imm64 + IMUL + ADD nearby
                            for (uint32_t fwd2 = 10; fwd2 < 40 && sOff + fwd2 + 12 <= rawOff + p; fwd2++) {
                                uint32_t n2 = sOff + fwd2;
                                // NOT reg: 48/49 F7 Dx
                                if ((pe.data[n2] == 0x48 || pe.data[n2] == 0x49) && pe.data[n2+1] == 0xF7 &&
                                    (pe.data[n2+2] & 0xF8) == 0xD0) {
                                    // Second MOV imm64
                                    if (n2 + 3 + 10 <= rawOff + p &&
                                        (pe.data[n2+3] == 0x48 || pe.data[n2+3] == 0x49) &&
                                        (pe.data[n2+4] >= 0xB8 && pe.data[n2+4] <= 0xBF)) {
                                        int64_t c64_2 = *(int64_t*)(pe.data.data() + n2 + 5);
                                        // MBA XOR: target = key * c64 + (~key) * c64_2
                                        int64_t diff64 = c64 - c64_2;
                                        if (diff64 != 0 && (diff64 & 1)) {
                                            uint64_t inv64 = (uint64_t)diff64;
                                            for (int it = 0; it < 6; it++) inv64 = inv64 * (2 - (uint64_t)diff64 * inv64);
                                            uint64_t base64 = (uint64_t)(-1LL) * (uint64_t)c64_2;
                                            for (uint32_t cand : candidateTargetSet) {
                                                uint64_t candVA = (uint64_t)actualBase + cand;
                                                uint64_t keyNeeded = (candVA - base64) * inv64;
                                                uint64_t check = keyNeeded * (uint64_t)c64 + (~keyNeeded) * (uint64_t)c64_2;
                                                if (check == candVA) {
                                                    uint32_t tOff = pe.rvaToOffset(cand);
                                                    if (!tOff) continue;
                                                    uint8_t tb = pe.data[tOff];
                                                    if (tb == 0xCC || tb == 0x00) continue;
                                                    uint32_t patchStart = off;
                                                    if (off >= 4 && pe.data[off-4]==0x48 && pe.data[off-3]==0x83 && pe.data[off-2]==0xC4)
                                                        patchStart = off - 4;
                                                    else if (off >= 7 && pe.data[off-7]==0x48 && pe.data[off-6]==0x81 && pe.data[off-5]==0xC4)
                                                        patchStart = off - 7;
                                                    uint32_t patchRVA = secRVA + (patchStart - rawOff);
                                                    uint32_t patchLen = (off + 14) - patchStart;
                                                    if (patchLen >= 5) {
                                                        int32_t rel = (int32_t)(cand - (patchRVA + 5));
                                                        pe.data[patchStart] = 0xE9;
                                                        memcpy(pe.data.data() + patchStart + 1, &rel, 4);
                                                        for (uint32_t n = 5; n < patchLen; n++) pe.data[patchStart + n] = 0x90;
                                                        riotResolved++;
                                                    }
                                                    goto nextStub;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                nextStub:;
            }
        }
        // Phase R2: ALL stubs go to same central dispatcher
        // Key insight: all 1075 resolved stubs target the SAME address (central import resolver)
        // Unresolved stubs ALSO target this same address — just patch them directly
        uint32_t riotDeobfed = 0;
        if (riotResolved > 0 && riotStubs > riotResolved) {
            // Find the common target from resolved stubs
            uint32_t centralTarget = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".riot1") != 0) continue;
                uint32_t secRVA2 = pe.sections[si].VirtualAddress;
                uint32_t rawOff2 = pe.sections[si].PointerToRawData;
                uint32_t rawSz2 = pe.sections[si].SizeOfRawData;
                for (uint32_t pp = 0; pp + 12 < rawSz2; pp++) {
                    uint32_t o2 = rawOff2 + pp;
                    // Find imul ecx, CONST; E9 [disp32]
                    if (pe.data[o2] == 0x69 && pe.data[o2+1] == 0xC9 && pe.data[o2+6] == 0xE9) {
                        int32_t disp = *(int32_t*)(pe.data.data() + o2 + 7);
                        centralTarget = (secRVA2 + pp + 6) + 5 + disp;
                        break;
                    }
                }
                if (centralTarget) break;
            }

            if (centralTarget) {
                cli::detail("Central dispatcher: RVA 0x%X", centralTarget);
                // Patch all remaining unresolved stubs to jmp centralTarget
                for (int si = 0; si < pe.numSections; si++) {
                    char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                    if (strcmp(sn, ".riot1") != 0) continue;
                    uint32_t secRVA2 = pe.sections[si].VirtualAddress;
                    uint32_t rawOff2 = pe.sections[si].PointerToRawData;
                    uint32_t rawSz2 = pe.sections[si].SizeOfRawData;

                    for (uint32_t pp = 20; pp + 14 < rawSz2; pp++) {
                        uint32_t o2 = rawOff2 + pp;
                        if (pe.data[o2+12] != 0xFF || pe.data[o2+13] != 0xE0) continue;
                        if (pe.data[o2]!=0x5B || pe.data[o2+1]!=0x5D || pe.data[o2+2]!=0x5F ||
                            pe.data[o2+3]!=0x5E || pe.data[o2+4]!=0x41 || pe.data[o2+5]!=0x5C) continue;
                        // Skip already patched
                        if (pe.data[o2+12] == 0xE9) continue;
                        // Check not already patched in the add rsp area
                        uint32_t ps2 = o2;
                        if (o2>=4 && pe.data[o2-4]==0x48 && pe.data[o2-3]==0x83 && pe.data[o2-2]==0xC4) ps2=o2-4;
                        else if (o2>=7 && pe.data[o2-7]==0x48 && pe.data[o2-6]==0x81 && pe.data[o2-5]==0xC4) ps2=o2-7;
                        if (pe.data[ps2] == 0xE9) continue;

                        uint32_t patchRVA2 = secRVA2 + (ps2 - rawOff2);
                        uint32_t patchLen2 = (o2 + 14) - ps2;
                        if (patchLen2 >= 5) {
                            int32_t rel = (int32_t)(centralTarget - (patchRVA2 + 5));
                            pe.data[ps2] = 0xE9;
                            memcpy(pe.data.data() + ps2 + 1, &rel, 4);
                            for (uint32_t n = 5; n < patchLen2; n++) pe.data[ps2 + n] = 0x90;
                            riotDeobfed++;
                        }
                    }
                }
            }
            cli::detail("Phase R2 (central dispatch): %u additional resolved", riotDeobfed);
        }

        cli::ok(".riot1 dispatch: %u stubs found, %u resolved + %u deobfed = %u total (%.0f ms)",
               riotStubs, riotResolved, riotDeobfed, riotResolved + riotDeobfed, tRiot.elapsedMs());
    }

    // A8: NOP→CC conversion for .text and .riot1 (IDA function boundary clarity)
    // .grfn1 is already handled in post-deobf. This covers the remaining sections.
    // Safety: only convert NOP runs of 8+ bytes between CC/C3 boundaries
    if (deobfScan) {
        uint32_t textCCd = 0, riotCCd = 0;
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            bool isText = (strcmp(sn, ".text") == 0);
            bool isRiot1 = (strcmp(sn, ".riot1") == 0);
            if (!isText && !isRiot1) continue;

            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

            uint32_t nopRun = 0;
            uint32_t converted = 0;
            for (uint32_t p = 0; p < rawSz; p++) {
                if (pe.data[rawOff + p] == 0x90) { nopRun++; continue; }
                if (nopRun >= 8) {
                    // Verify: NOP run is between code boundaries (CC/C3 before, CC/C3/code after)
                    uint32_t runStart = rawOff + p - nopRun;
                    bool safeBefore = (runStart == rawOff) ||
                                     (pe.data[runStart - 1] == 0xCC || pe.data[runStart - 1] == 0xC3);
                    bool safeAfter = (pe.data[rawOff + p] == 0xCC || pe.data[rawOff + p] == 0xC3 ||
                                     pe.data[rawOff + p] == 0x40 || pe.data[rawOff + p] == 0x48 ||
                                     pe.data[rawOff + p] == 0x4C || pe.data[rawOff + p] == 0x55 ||
                                     pe.data[rawOff + p] == 0x53 || pe.data[rawOff + p] == 0x41 ||
                                     pe.data[rawOff + p] == 0x56 || pe.data[rawOff + p] == 0x57);
                    if (safeBefore && safeAfter) {
                        for (uint32_t k = 0; k < nopRun; k++)
                            pe.data[runStart + k] = 0xCC;
                        converted += nopRun;
                    }
                }
                nopRun = 0;
            }
            if (isText) textCCd = converted;
            if (isRiot1) riotCCd = converted;
        }
        if (textCCd || riotCCd)
            cli::ok("NOP→CC: .text %u bytes, .riot1 %u bytes", textCCd, riotCCd);
    }

    // A9: Proto descriptor LEA → function naming
    // Scan all exec sections for LEA rip+disp pointing to known proto descriptor strings.
    // Functions containing these LEAs are proto message construction/access functions.
    if (protoScan && deobfScan) {
        Timer tPdesc;
        uint32_t protoFuncsNamed = 0;
        std::unordered_set<uint32_t> namedFuncs;

        // Collect all proto descriptor string RVAs
        struct ProtoDesc { uint32_t rva; std::string label; };
        std::vector<ProtoDesc> protoDescs;
        auto protoResult3 = scanAllProtoMessages(pe, actualBase);
        for (auto& msg : protoResult3.messages) {
            std::string shortName = msg.fullName;
            size_t dot = shortName.rfind('.');
            if (dot != std::string::npos) shortName = shortName.substr(dot + 1);
            if (msg.serializeRVA)
                protoDescs.push_back({msg.serializeRVA, shortName + "_ref"});
            for (auto& fld : msg.fields) {
                if (fld.stringRVA)
                    protoDescs.push_back({fld.stringRVA, shortName + "_" + fld.name + "_ref"});
            }
        }

        // Scan for LEA rip+disp → proto descriptor
        std::unordered_set<uint32_t> protoDescSet;
        for (auto& pd : protoDescs) protoDescSet.insert(pd.rva);
        std::unordered_map<uint32_t, std::string> descToLabel;
        for (auto& pd : protoDescs) descToLabel[pd.rva] = pd.label;

        for (int si = 0; si < pe.numSections; si++) {
            if (!pe.isExecutableSection(si)) continue;
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            for (uint32_t p = 0; p + 7 <= rawSz; p++) {
                uint32_t off = rawOff + p;
                if (pe.data[off+1] != 0x8D) continue;
                uint8_t rex = pe.data[off];
                if (rex != 0x48 && rex != 0x4C) continue;
                uint8_t modrm = pe.data[off+2];
                if ((modrm & 0xC7) != 0x05) continue; // [rip+disp32]
                int32_t disp = *(int32_t*)(pe.data.data() + off + 3);
                uint32_t instrRVA = secRVA + p;
                uint32_t target = instrRVA + 7 + disp;
                if (!protoDescSet.count(target)) continue;

                // Find function start
                uint32_t funcStart = instrRVA;
                for (uint32_t bk = 1; bk < 8192 && (rawOff + p) > bk; bk++) {
                    uint8_t b = pe.data[rawOff + p - bk];
                    if (b == 0xCC && pe.data[rawOff + p - bk + 1] != 0xCC) {
                        funcStart = instrRVA - bk + 1;
                        break;
                    }
                }
                if (namedFuncs.count(funcStart)) continue;
                namedFuncs.insert(funcStart);
                allNames.push_back({actualBase + funcStart, descToLabel[target] + "_" +
                    std::to_string(funcStart & 0xFFFFF).substr(0,5)});
                protoFuncsNamed++;
            }
        }
        if (protoFuncsNamed)
            cli::ok("Proto descriptor LEA: %u functions named (%.0f ms)",
                   protoFuncsNamed, tPdesc.elapsedMs());
    }

    // Proto field setter trace — fully automatic pipeline:
    // 1. proto_scan → find message + serialize
    // 2. resolveVtable → find vtable + entries
    // 3. parseFromParseFunc → extract field→offset from Parse switch-case
    // 4. traceFieldSetters → scan .grfn1 for offset-computation clusters
    if (protoScan && deobfScan) {
        auto authMsg = scanProtoMessage(pe, actualBase, "vanguard.AuthenticationRequest");
        if (authMsg.serializeRVA) {
            // Step 2-3: vtable + Parse-derived offsets
            resolveVtable(pe, actualBase, authMsg);
            parseFromParseFunc(pe, actualBase, authMsg);

            // Find the string setter RVA by scanning MergeFrom for CALL targets
            // MergeFrom is typically vtable entry after serialize that accesses all string fields
            uint32_t setterRVA = 0;
            if (authMsg.vtableRVA) {
                uint32_t vtOff = pe.rvaToOffset(authMsg.vtableRVA);
                if (vtOff) {
                    // Scan vtable entries for a function that calls a common string setter
                    // (the function called with LEA rcx, [reg+offset] pattern)
                    for (uint32_t ei = 0; ei < 16; ei++) {
                        if (vtOff + (ei + 1) * 8 > pe.data.size()) break;
                        uint64_t entry = *(uint64_t*)(pe.data.data() + vtOff + ei * 8);
                        uint32_t rva = (uint32_t)(entry - actualBase);
                        uint32_t eOff = pe.rvaToOffset(rva);
                        if (!eOff || eOff + 200 > pe.data.size()) continue;
                        // Look for function that has multiple LEA rcx,[reg+field_offset]
                        // followed by CALL (same target) = MergeFrom pattern
                        const uint8_t* fc = pe.data.data() + eOff;
                        uint32_t callTargets[8] = {};
                        int nCalls = 0;
                        for (uint32_t p = 0; p + 7 < 200 && nCalls < 8; p++) {
                            if (fc[p] == 0xE8) {
                                int32_t d = *(int32_t*)(fc + p + 1);
                                callTargets[nCalls++] = rva + p + 5 + d;
                            }
                        }
                        // If first 3+ calls go to the same target, it's likely the string setter
                        if (nCalls >= 3 && callTargets[0] == callTargets[1] && callTargets[1] == callTargets[2]) {
                            setterRVA = callTargets[0];
                            cli::detail("String setter auto-detected: RVA 0x%X (from vtable[%u])", setterRVA, ei);
                            break;
                        }
                    }
                }
            }
            if (!setterRVA) setterRVA = 0x132990; // fallback

            // Find target field offset for machine_id
            uint32_t targetOffset = 0;
            for (auto& f : authMsg.fields) {
                if (f.name == "machine_id" && f.structOffset > 0) {
                    targetOffset = f.structOffset;
                    break;
                }
            }
            if (!targetOffset) {
                cli::warn("machine_id offset not resolved, using 0x88 fallback");
                targetOffset = 0x88;
            }

            auto trace = traceFieldSetters(pe, actualBase, authMsg, targetOffset, setterRVA);
            if (!trace.hits.empty()) {
                cli::ok("machine_id setter candidates: %zu", trace.hits.size());
            }

            // Static trace: find all .grfn1 dispatchers and trace to find text_132990 calls
            cli::info("Static tracing Griffin dispatchers for field setter calls...");
            GriffinStaticTracer tracer(pe, actualBase);
            tracer.watchFunction(setterRVA);
            tracer.watchFunction(0x132790);
            tracer.watchFunction(0x130EF0);

            // Find grfn setter stubs: .grfn1 functions that call text_132990 directly
            std::vector<uint32_t> setterStubs;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".grfn1") != 0) continue;
                uint32_t secRVA = pe.sections[si].VirtualAddress;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                for (uint32_t p = 0; p + 5 < rawSz; p++) {
                    if (pe.data[rawOff + p] != 0xE8) continue;
                    int32_t disp = *(int32_t*)(pe.data.data() + rawOff + p + 1);
                    uint32_t callTarget = secRVA + p + 5 + disp;
                    if (callTarget == setterRVA) {
                        // Find function start (scan backward for CC boundary)
                        uint32_t funcStart = secRVA + p;
                        for (int bk = 1; bk < 200; bk++) {
                            if (p < (uint32_t)bk) break;
                            if (pe.data[rawOff + p - bk] == 0xCC) {
                                funcStart = secRVA + p - bk + 1;
                                break;
                            }
                        }
                        setterStubs.push_back(funcStart);
                        p += 4;
                    }
                }
            }
            cli::detail("Found %zu setter stubs calling 0x%X", setterStubs.size(), setterRVA);

            // Trace each setter stub (these directly call text_132990)
            Timer tTrace;
            uint32_t totalCalls = 0;
            uint32_t setterCalls = 0;
            uint32_t tracedOk = 0, tracedFail = 0;
            std::map<std::string, int> stopReasons;
            for (auto stubRVA : setterStubs) {
                auto result = tracer.trace(stubRVA, 1000);
                if (result.calls.empty() && !result.stopReason.empty())
                    stopReasons[result.stopReason]++;
                if (result.stepsExecuted > 10) tracedOk++;
                else tracedFail++;
                for (auto& c : result.calls) {
                    totalCalls++;
                    uint32_t targetRVA2 = (uint32_t)(c.targetVA - actualBase);
                    if (targetRVA2 == setterRVA) {
                        setterCalls++;
                        uint64_t fieldAddr = c.args[0]; // rcx = field pointer
                        printf("    [HIT] ArenaStringPtr::Set called from 0x%llX, rcx=0x%llX",
                               (unsigned long long)(c.callerVA - actualBase),
                               (unsigned long long)fieldAddr);
                        // Check if rcx looks like obj+0x88
                        if ((fieldAddr & 0xFF) == targetOffset)
                            printf(" ← MATCH +0x%X!", targetOffset);
                        printf("\n");
                    }
                }
            }
            cli::ok("Static trace: %u stubs, %u total calls, %u setter calls (%.0f ms)",
                   (uint32_t)setterStubs.size(), totalCalls, setterCalls, tTrace.elapsedMs());
            cli::detail("Traced OK (>10 steps): %u, Failed (<10 steps): %u", tracedOk, tracedFail);
            if (!stopReasons.empty()) {
                cli::detail("Stop reasons:");
                for (auto& [reason, cnt] : stopReasons)
                    cli::detail("%s: %d", reason.c_str(), cnt);
            }
        }
    }

    // Griffin emulation (--emulate)
    if (emuTarget) {
        uint32_t targetRVA = 0;
        const char* ts = emuTarget;
        if (strncmp(ts, "0x", 2) == 0 || strncmp(ts, "0X", 2) == 0) ts += 2;
        targetRVA = (uint32_t)strtoull(ts, nullptr, 16);

        cli::info("Griffin emulation: RVA 0x%X, max %u steps", targetRVA, emuMaxSteps);

        GriffinEmulator emu(pe, actualBase);
        emu.loadSections();
        emu.setupStack();

        // AuthReq constructor: allocate fake object at known address
        uint64_t authReqAddr = 0xAA000000;
        uint32_t authReqSize = 0x200;
        emu.addStub(0x5647DC880, authReqAddr);

        // Watch AuthReq object memory for field writes
        emu.watchRange(authReqAddr, authReqAddr + authReqSize);

        // Stub other known functions
        emu.addStub(0x5647DD700, 0);           // AuthReq serialize
        emu.addStub(0x564A9EA54, 0);           // EncryptAndAuthenticate
        emu.addStub(0x56720CFE3, 0);           // INT3 dispatch site (NOP'd)

        // Set up fake stack parameters for the function
        // The AuthReq caller reads params from deep stack offsets
        uint64_t rsp = emu.state().regs[4]; // RSP after setupStack
        // Write some recognizable values to stack params
        for (int p = 0; p < 64; p++) {
            uint64_t paramAddr = rsp + 0x20 + p * 8;
            uint64_t paramVal = 0xBB000000 + p * 0x10; // distinguishable values
            emu.writeMemory(paramAddr, paramVal);
        }

        emu.setRIP(actualBase + targetRVA);

        cli::detail("Watching AuthReq object at 0x%llX (size 0x%X)",
               (unsigned long long)authReqAddr, authReqSize);

        if (emu.execute(emuMaxSteps))
            cli::ok("Emulation completed: %llu steps", (unsigned long long)emu.stepsExecuted());
        else
            cli::fail("Emulation stopped: %llu steps", (unsigned long long)emu.stepsExecuted());

        const char* rnames[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                "r8","r9","r10","r11","r12","r13","r14","r15"};
        for (int i = 0; i < 16; i++)
            cli::detail("%s = 0x%llX", rnames[i], (unsigned long long)emu.state().regs[i]);

        // Report calls
        if (!emu.callLog().empty()) {
            cli::detail("Calls (%zu):", emu.callLog().size());
            for (auto& c : emu.callLog())
                cli::detail("0x%llX -> 0x%llX (rcx=0x%llX rdx=0x%llX r8=0x%llX)",
                       (unsigned long long)c.caller, (unsigned long long)c.target,
                       (unsigned long long)c.args[0], (unsigned long long)c.args[1],
                       (unsigned long long)c.args[2]);
        }

        // Report AuthReq field writes
        auto& memWrites = emu.memLog();
        cli::detail("AuthReq field writes:");
        for (auto& m : memWrites) {
            if (m.isWrite && m.addr >= authReqAddr && m.addr < authReqAddr + authReqSize) {
                uint32_t fieldOff = (uint32_t)(m.addr - authReqAddr);
                const char* fieldName = "";
                if (fieldOff == 0x00) fieldName = "vtable";
                else if (fieldOff == 0x08) fieldName = "arena";
                else if (fieldOff == 0x88) fieldName = "machine_id";
                else if (fieldOff == 0x90) fieldName = "game_token";
                else if (fieldOff == 0x98) fieldName = "rsa_pubkey";
                else if (fieldOff == 0xA0) fieldName = "game_id";
                else if (fieldOff == 0xA8) fieldName = "external_sid";
                else if (fieldOff == 0x10) fieldName = "ephemeral_ids";
                else if (fieldOff == 0xE0) fieldName = "has_bits";
                cli::detail("[+0x%03X] %-16s = 0x%llX  (at RIP 0x%llX)",
                       fieldOff, fieldName, (unsigned long long)m.value,
                       (unsigned long long)m.rip);
            }
        }
    }

#ifdef USE_UNICORN
    // Unicorn-based emulation (--emulate with Unicorn)
    if (emuTarget) {
        uint32_t targetRVA = 0;
        const char* ts2 = emuTarget;
        if (strncmp(ts2, "0x", 2) == 0 || strncmp(ts2, "0X", 2) == 0) ts2 += 2;
        targetRVA = (uint32_t)strtoull(ts2, nullptr, 16);

        cli::info("Unicorn emulation: RVA 0x%X", targetRVA);

        UnicornVGC uc(pe, actualBase);
        if (uc.loadSections() && uc.setupStack()) {
            // Emulate SMBIOS reader (text_1728E0) to trace HWID collection
            uint64_t smbiosBuffer = 0xBB000000;
            uc.watchObject(smbiosBuffer, 0x1000, "SMBIOS_output");

            // Auto-stub ALL import wrappers (328 known)
            for (auto& w : importWrappers) {
                if (!w.apiName.empty()) {
                    uint64_t retval = 0;
                    // Special return values for specific APIs
                    if (w.apiName == "GetSystemFirmwareTable") retval = 256;
                    else if (w.apiName.find("Alloc") != std::string::npos) retval = 0xCC000000;
                    else if (w.apiName.find("Create") != std::string::npos) retval = 0xDD000000;
                    else if (w.apiName == "GetLastError") retval = 0;
                    uc.addStub(w.wrapperVA, retval);
                }
            }
            uc.enableInt3Handler();

            // Stub all import wrappers
            for (auto& w : importWrappers) {
                if (w.apiName.empty()) continue;
                uint64_t retval = 0;
                if (w.apiName.find("Alloc") != std::string::npos ||
                    w.apiName == "HeapAlloc" || w.apiName == "malloc")
                    retval = 0xCC000000;
                else if (w.apiName == "GetLastError") retval = 0;
                else if (w.apiName == "GetProcessHeap") retval = 0xDD000000;
                uc.addStub(w.wrapperVA, retval);
            }

            // Allocate fake AuthReq object and watch it
            uint64_t fakeAuthReq = 0xAA000000;
            uc.watchObject(fakeAuthReq, 0x200, "AuthReq");

            // Use proto_scan results for field-aware tracing
            auto authReq = scanProtoMessage(pe, actualBase, "vanguard.AuthenticationRequest");

            // Stub allocator to return fakeAuthReq (so New() writes to our watched region)
            uc.addStub(actualBase + 0x1519C0, fakeAuthReq); // operator new(size_t)
            uc.addStub(actualBase + 0x132AB0, fakeAuthReq); // arena allocate

            cli::detail("[Emulate] Target RVA: 0x%X", targetRVA);
            cli::detail("[Emulate] AuthReq at: 0x%llX", (unsigned long long)fakeAuthReq);

            // Call New(arena=0) — allocates+constructs AuthReq
            uint64_t result = uc.callFunction(actualBase + targetRVA, 0);
            cli::detail("[Emulate] Returned: 0x%llX", (unsigned long long)result);

            // Dump AuthReq fields via ArenaStringPtr reading
            cli::detail("[Emulate] AuthReq field dump:");
            std::vector<std::pair<uint32_t, std::string>> fieldMap;
            for (auto& f : authReq.fields) {
                if (f.structOffset > 0)
                    fieldMap.push_back({f.structOffset, f.name});
            }
            auto dump = uc.dumpProtoFields(fakeAuthReq, fieldMap);
            for (auto& fd : dump) {
                if (!fd.value.empty())
                    cli::detail("+0x%02X %-30s = \"%s\"", fd.offset, fd.name.c_str(), fd.value.c_str());
            }

            // Also report raw field writes
            cli::detail("[Emulate] Memory writes to AuthReq:");
            for (auto& fw : uc.fieldWrites()) {
                cli::detail("[+0x%03X] = 0x%llX (%u bytes, RIP=0x%llX)",
                       fw.offset, (unsigned long long)fw.value, fw.size, (unsigned long long)fw.rip);
            }

            cli::detail("[Emulate] Total calls: %zu", uc.calls().size());
        }
    }
#endif

    // Infer source file structure
    {
        auto srcMap = inferSourceMap(pe, actualBase);
        printSourceMap(srcMap);
    }

    // Orphan byte detection: pointer-tracking based unreferenced region analysis
    {
        cli::info("Orphan byte detection (pointer-tracking)...");
        Timer tOrphan;
        uint32_t soiO = pe.nt->OptionalHeader.SizeOfImage;

        // Phase 1: Build reference coverage map
        // Every RVA that is the TARGET of any reference is "covered"
        std::vector<bool> covered(soiO, false);
        auto markCovered = [&](uint32_t rva, uint32_t len) {
            for (uint32_t i = 0; i < len && rva + i < soiO; i++) covered[rva + i] = true;
        };

        // Source A: RIP-relative references (code → data/code)
        for (auto& ref : allRefs) {
            if (ref.targetRVA < soiO)
                markCovered(ref.targetRVA, ref.isCall || ref.isJmp ? 1 : 8);
        }
        // Source B: Pointer chains (data → data/code)
        for (auto& pr : ptrRefs) {
            markCovered(pr.targetRVA, 8);
            markCovered(pr.ptrRVA, 8);
        }
        // Source C: RTTI vtable entries (vtable → code)
        for (auto& cls : rttiClasses) {
            uint32_t vtRVA = (uint32_t)(cls.vtableVA - actualBase);
            markCovered(vtRVA, (uint32_t)(cls.methodVAs.size() * 8));
            for (auto& mva : cls.methodVAs)
                markCovered((uint32_t)(mva - actualBase), 1);
        }
        // Source D: Import wrappers
        for (auto& w : importWrappers)
            markCovered((uint32_t)(w.wrapperVA - actualBase), 16);
        // Source E: Section headers themselves
        for (int si = 0; si < pe.numSections; si++) {
            uint32_t va = pe.sections[si].VirtualAddress;
            uint32_t vsz = pe.sections[si].Misc.VirtualSize;
            // Mark first 16 bytes of each section as covered (header area)
            markCovered(va, vsz < 16 ? vsz : 16);
        }

        // Phase 2: Find uncovered regions in data sections
        // Focus on .rdata and .data where hidden structures would live
        struct OrphanRegion {
            uint32_t rva;
            uint32_t size;
            std::string section;
            std::string content; // what we found in it
        };
        std::vector<OrphanRegion> orphans;

        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            uint32_t secRVA = pe.sections[si].VirtualAddress;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            uint32_t vsz = pe.sections[si].Misc.VirtualSize;
            if (rawOff + rawSz > pe.data.size()) continue;

            // Scan for uncovered runs of 32+ bytes with non-zero content
            uint32_t uncovRun = 0;
            uint32_t uncovStart = 0;
            uint32_t scanSz = rawSz < vsz ? rawSz : vsz;
            for (uint32_t p = 0; p < scanSz; p++) {
                bool isCovered = (secRVA + p < soiO) ? covered[secRVA + p] : false;
                bool isZero = (pe.data[rawOff + p] == 0x00);
                bool isCC = (pe.data[rawOff + p] == 0xCC);
                bool isNOP = (pe.data[rawOff + p] == 0x90);

                if (!isCovered && !isZero && !isCC && !isNOP) {
                    if (uncovRun == 0) uncovStart = p;
                    uncovRun++;
                } else {
                    if (uncovRun >= 32) {
                        // Analyze content of this orphan region
                        OrphanRegion orph;
                        orph.rva = secRVA + uncovStart;
                        orph.size = uncovRun;
                        orph.section = sn;

                        // Check what's in this region
                        const uint8_t* data = pe.data.data() + rawOff + uncovStart;
                        int ptrCount = 0, strCount = 0, codeHints = 0;

                        // Count internal pointers (8-byte values pointing into image)
                        for (uint32_t j = 0; j + 8 <= uncovRun; j += 8) {
                            uint64_t val = *(uint64_t*)(data + j);
                            if (val >= actualBase && val < actualBase + soiO) ptrCount++;
                        }
                        // Count printable ASCII strings (>= 4 chars)
                        for (uint32_t j = 0; j < uncovRun; j++) {
                            if (data[j] >= 0x20 && data[j] < 0x7F) {
                                uint32_t slen = 0;
                                while (j + slen < uncovRun && data[j+slen] >= 0x20 && data[j+slen] < 0x7F) slen++;
                                if (slen >= 4) strCount++;
                                j += slen;
                            }
                        }
                        // Check for code-like patterns
                        for (uint32_t j = 0; j + 2 < uncovRun; j++) {
                            if (data[j] == 0x48 || data[j] == 0x4C || data[j] == 0xE8 || data[j] == 0xE9)
                                codeHints++;
                        }

                        char desc[128];
                        sprintf_s(desc, "%u bytes: %d ptrs, %d strings, %d code-hints",
                                  uncovRun, ptrCount, strCount, codeHints);
                        orph.content = desc;
                        orphans.push_back(orph);
                    }
                    uncovRun = 0;
                }
            }
            if (uncovRun >= 32) {
                OrphanRegion orph;
                orph.rva = secRVA + uncovStart;
                orph.size = uncovRun;
                orph.section = sn;
                orph.content = std::to_string(uncovRun) + " bytes at section tail";
                orphans.push_back(orph);
            }

            // Also check: section tail padding (VirtualSize < SizeOfRawData)
            if (rawSz > vsz) {
                uint32_t tailOff = rawOff + vsz;
                uint32_t tailSz = rawSz - vsz;
                bool hasContent = false;
                for (uint32_t j = 0; j < tailSz && j < 1024; j++)
                    if (pe.data[tailOff + j] != 0x00 && pe.data[tailOff + j] != 0xCC) { hasContent = true; break; }
                if (hasContent && tailSz > 32) {
                    OrphanRegion orph;
                    orph.rva = secRVA + vsz;
                    orph.size = tailSz;
                    orph.section = std::string(sn) + "_tail";
                    orph.content = std::to_string(tailSz) + " bytes past VirtualSize";
                    orphans.push_back(orph);
                }
            }
        }

        // Phase 3: Check PE header gaps
        {
            uint32_t headerEnd = pe.nt->OptionalHeader.SizeOfHeaders;
            uint32_t firstSection = UINT32_MAX;
            for (int si = 0; si < pe.numSections; si++)
                if (pe.sections[si].PointerToRawData > 0)
                    if (pe.sections[si].PointerToRawData < firstSection)
                        firstSection = pe.sections[si].PointerToRawData;
            if (firstSection != UINT32_MAX && firstSection > headerEnd) {
                uint32_t gap = firstSection - headerEnd;
                bool hasContent = false;
                for (uint32_t j = headerEnd; j < firstSection && j < pe.data.size(); j++)
                    if (pe.data[j] != 0x00) { hasContent = true; break; }
                if (hasContent && gap > 16) {
                    OrphanRegion orph;
                    orph.rva = 0;
                    orph.size = gap;
                    orph.section = "PE_header_gap";
                    orph.content = std::to_string(gap) + " bytes between headers and first section";
                    orphans.push_back(orph);
                }
            }
        }

        // Phase 4: Section gaps (VA ranges between sections)
        {
            std::vector<std::pair<uint32_t,uint32_t>> secRanges;
            for (int si = 0; si < pe.numSections; si++) {
                uint32_t start = pe.sections[si].VirtualAddress;
                uint32_t end = start + pe.sections[si].Misc.VirtualSize;
                if (start > 0) secRanges.push_back({start, end});
            }
            std::sort(secRanges.begin(), secRanges.end());
            for (size_t i = 1; i < secRanges.size(); i++) {
                if (secRanges[i].first > secRanges[i-1].second) {
                    uint32_t gapStart = secRanges[i-1].second;
                    uint32_t gapEnd = secRanges[i].first;
                    uint32_t gapSz = gapEnd - gapStart;
                    if (gapSz > 64) {
                        // Check if gap has content in the file
                        uint32_t gapFileOff = pe.rvaToOffset(gapStart);
                        if (gapFileOff && gapFileOff + gapSz <= pe.data.size()) {
                            bool hasContent = false;
                            int ptrCount = 0;
                            for (uint32_t j = 0; j < gapSz; j++)
                                if (pe.data[gapFileOff+j] != 0x00) hasContent = true;
                            for (uint32_t j = 0; j + 8 <= gapSz; j += 8) {
                                uint64_t val = *(uint64_t*)(pe.data.data() + gapFileOff + j);
                                if (val >= actualBase && val < actualBase + soiO) ptrCount++;
                            }
                            if (hasContent) {
                                OrphanRegion orph;
                                orph.rva = gapStart;
                                orph.size = gapSz;
                                orph.section = "section_gap";
                                char desc[128];
                                sprintf_s(desc, "%u bytes, %d internal ptrs", gapSz, ptrCount);
                                orph.content = desc;
                                orphans.push_back(orph);
                            }
                        }
                    }
                }
            }
        }

        // Phase 5: Automated processing of significant orphan regions
        uint32_t orphanStringsFound = 0, orphanFuncsFound = 0, orphanPtrsFound = 0;

        for (auto& o : orphans) {
            uint32_t fileOff = pe.rvaToOffset(o.rva);
            if (!fileOff || fileOff + o.size > pe.data.size()) continue;
            const uint8_t* data = pe.data.data() + fileOff;

            // A) Extract printable strings >= 6 chars (function names, error messages, protocol data)
            for (uint32_t j = 0; j < o.size; j++) {
                if (data[j] < 0x20 || data[j] >= 0x7F) continue;
                uint32_t slen = 0;
                while (j + slen < o.size && data[j+slen] >= 0x20 && data[j+slen] < 0x7F) slen++;
                if (slen >= 6 && (j == 0 || data[j-1] == 0x00)) {
                    std::string str((const char*)(data + j), slen);
                    // Filter: only meaningful strings (not random ASCII)
                    bool meaningful = false;
                    if (str.find("_") != std::string::npos) meaningful = true; // function names
                    if (str.find("::") != std::string::npos) meaningful = true; // C++ names
                    if (str.find(".") != std::string::npos) meaningful = true; // file paths
                    if (str.find("Error") != std::string::npos || str.find("error") != std::string::npos) meaningful = true;
                    if (str.find("vanguard") != std::string::npos || str.find("riot") != std::string::npos) meaningful = true;
                    if (str.find("machine") != std::string::npos || str.find("token") != std::string::npos) meaningful = true;
                    if (str.find("SSL") != std::string::npos || str.find("EVP") != std::string::npos) meaningful = true;
                    if (str.find("IOCTL") != std::string::npos || str.find("pipe") != std::string::npos) meaningful = true;
                    if (str.find("http") != std::string::npos || str.find("pvp.net") != std::string::npos) meaningful = true;
                    if (meaningful) {
                        // Try to derive a meaningful name from the string content
                        std::string symName;
                        if (str.find("vanguard.") == 0) {
                            // "vanguard.AuthenticationRequest.machine_id" → "proto_AuthReq_machine_id"
                            std::string shortMsg = str;
                            size_t lastDot = shortMsg.rfind('.');
                            size_t msgDot = shortMsg.find('.', 10); // after "vanguard."
                            if (lastDot != std::string::npos && msgDot != std::string::npos && lastDot > msgDot) {
                                std::string msgPart = shortMsg.substr(9, msgDot > 9 ? msgDot - 9 : 0);
                                // Shorten common names
                                if (msgPart.find("AuthenticationRequest") != std::string::npos) msgPart = "AuthReq";
                                else if (msgPart.find("HeartbeatRequest") != std::string::npos) msgPart = "HbReq";
                                else if (msgPart.find("HeartbeatResponse") != std::string::npos) msgPart = "HbResp";
                                else if (msgPart.find("TokenResponse") != std::string::npos) msgPart = "TokenResp";
                                else if (msgPart.find("DisconnectRequest") != std::string::npos) msgPart = "DisconReq";
                                else if (msgPart.find("TaskResultRequest") != std::string::npos) msgPart = "TaskResReq";
                                else if (msgPart.find("AccessRequest") != std::string::npos) msgPart = "AccReq";
                                std::string fieldPart = shortMsg.substr(lastDot + 1);
                                symName = "proto_" + msgPart + "_" + fieldPart;
                            } else {
                                symName = "proto_" + str.substr(9);
                            }
                        } else {
                            char buf[96];
                            sprintf_s(buf, "orphan_str_%X", o.rva + j);
                            symName = buf;
                        }
                        // Sanitize: replace non-identifier chars
                        for (auto& c : symName) if (c == '.' || c == '-' || c == ' ' || c == '/' || c == '\\') c = '_';
                        orphanNames.push_back({actualBase + o.rva + j, symName});
                        orphanStringsFound++;
                        // Log high-value strings
                        if (str.find("vanguard") != std::string::npos || str.find("riot") != std::string::npos ||
                            str.find("machine") != std::string::npos || str.find("token") != std::string::npos ||
                            str.find("auth") != std::string::npos || str.find("IOCTL") != std::string::npos ||
                            str.find("pvp.net") != std::string::npos || str.find("pipe") != std::string::npos ||
                            str.find("ephemeral") != std::string::npos || str.find("hwid") != std::string::npos ||
                            str.find("serial") != std::string::npos || str.find("encrypt") != std::string::npos ||
                            str.find("GCM") != std::string::npos || str.find("device") != std::string::npos)
                            cli::detail("[HIGH] RVA=0x%X \"%s\"", o.rva + j, str.c_str());
                    }
                }
                j += slen;
            }

            // B) Detect function entries in executable orphan regions
            int secIdx = pe.findSection(o.rva);
            if (secIdx >= 0 && pe.isExecutableSection(secIdx)) {
                for (uint32_t j = 0; j + 4 < o.size; j++) {
                    // Strict prologue at orphan start or after 00/CC byte
                    if (j > 0 && data[j-1] != 0x00 && data[j-1] != 0xCC && data[j-1] != 0xC3) continue;
                    bool isPrologue = false;
                    if (data[j]==0x48 && data[j+1]==0x83 && data[j+2]==0xEC) isPrologue = true;
                    if (data[j]==0x48 && data[j+1]==0x81 && data[j+2]==0xEC) isPrologue = true;
                    if (data[j]==0x48 && data[j+1]==0x89 && (data[j+2]==0x5C || data[j+2]==0x4C)) isPrologue = true;
                    if (data[j]==0x55 && data[j+1]==0x48) isPrologue = true;
                    if (data[j]==0x53 && data[j+1]==0x48) isPrologue = true;
                    if (isPrologue) {
                        uint32_t funcRVA = o.rva + j;
                        // extraFunctions is in if(!dryRun) scope; store in orphanNames only
                        char symName[64];
                        sprintf_s(symName, "orphan_func_%X", funcRVA);
                        orphanNames.push_back({actualBase + funcRVA, symName});
                        orphanFuncsFound++;
                    }
                }
            }

            // C) Trace internal pointers in data orphan regions (4-byte stride for better coverage)
            if (secIdx >= 0 && !pe.isExecutableSection(secIdx) && o.size >= 16) {
                for (uint32_t j = 0; j + 8 <= o.size; j += 4) {
                    uint64_t val = *(uint64_t*)(data + j);
                    if (val >= actualBase && val < actualBase + soiO) {
                        uint32_t targetRVA = (uint32_t)(val - actualBase);
                        int targetSec = pe.findSection(targetRVA);
                        if (targetSec >= 0) {
                            char symName[64];
                            if (pe.isExecutableSection(targetSec))
                                sprintf_s(symName, "orphan_fptr_%X", o.rva + j);
                            else
                                sprintf_s(symName, "orphan_dptr_%X", o.rva + j);
                            orphanNames.push_back({actualBase + o.rva + j, symName});
                            orphanPtrsFound++;
                        }
                    }
                }
            }
        }

        // Report
        cli::ok("Orphan detection: %zu regions found (%.0f ms)", orphans.size(), tOrphan.elapsedMs());
        std::sort(orphans.begin(), orphans.end(), [](const OrphanRegion& a, const OrphanRegion& b) {
            return a.size > b.size;
        });
        uint32_t totalOrphanBytes = 0;
        for (auto& o : orphans) totalOrphanBytes += o.size;
        cli::detail("Total orphan bytes: %u (%u KB)", totalOrphanBytes, totalOrphanBytes / 1024);
        cli::detail("Extracted: %u strings, %u functions, %u pointers",
               orphanStringsFound, orphanFuncsFound, orphanPtrsFound);
        for (size_t i = 0; i < orphans.size() && i < 15; i++) {
            cli::detail("[%zu] RVA=0x%06X  %6u bytes  %-12s  %s",
                   i, orphans[i].rva, orphans[i].size, orphans[i].section.c_str(), orphans[i].content.c_str());
        }
        if (orphans.size() > 15)
            cli::detail("... and %zu more regions", orphans.size() - 15);

        // Add orphan discoveries to allNames (for COFF)
        // Note: allNames is in if(!dryRun) scope, orphanNames needs to be merged later
    }

    // Hidden pattern scan: check for gaps/undiscovered regions
    std::vector<NamedAddress> contextAnnotations;
    {
        cli::info("Checking for hidden/undiscovered PE regions...");
        uint32_t soiCheck = pe.nt->OptionalHeader.SizeOfImage;
        // 1. Section gaps: any unmapped VA ranges between sections?
        std::vector<std::pair<uint32_t,uint32_t>> sectionRanges;
        for (int si = 0; si < pe.numSections; si++) {
            uint32_t start = pe.sections[si].VirtualAddress;
            uint32_t end = start + pe.sections[si].Misc.VirtualSize;
            if (start > 0) sectionRanges.push_back({start, end});
        }
        std::sort(sectionRanges.begin(), sectionRanges.end());
        uint32_t gapTotal = 0;
        for (size_t i = 1; i < sectionRanges.size(); i++) {
            if (sectionRanges[i].first > sectionRanges[i-1].second) {
                uint32_t gapStart = sectionRanges[i-1].second;
                uint32_t gapEnd = sectionRanges[i].first;
                uint32_t gapSz = gapEnd - gapStart;
                if (gapSz > 0x100) {
                    cli::detail("Gap: VA 0x%X - 0x%X (%u bytes)", gapStart, gapEnd, gapSz);
                    gapTotal += gapSz;
                }
            }
        }
        // 2. Check file beyond last section (overlay data?)
        uint32_t lastRaw = 0;
        for (int si = 0; si < pe.numSections; si++) {
            uint32_t end = pe.sections[si].PointerToRawData + pe.sections[si].SizeOfRawData;
            if (end > lastRaw) lastRaw = end;
        }
        // COFF symbols are appended at end, skip those
        uint32_t coffEnd = pe.nt->FileHeader.PointerToSymbolTable;
        if (coffEnd > 0) lastRaw = std::max(lastRaw, coffEnd);
        if (lastRaw < pe.data.size()) {
            uint32_t overlay = (uint32_t)(pe.data.size() - lastRaw);
            if (overlay > 0x100)
                cli::detail("Overlay data: %u bytes at file offset 0x%X", overlay, lastRaw);
        }
        // 3. Check for encrypted/compressed sections (high entropy)
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            if (rawSz < 0x100 || rawOff + rawSz > pe.data.size()) continue;
            // Quick entropy: count unique bytes in first 4KB
            uint32_t sampleSz = std::min(rawSz, (uint32_t)4096);
            int hist[256] = {};
            for (uint32_t j = 0; j < sampleSz; j++) hist[pe.data[rawOff+j]]++;
            int usedBytes = 0;
            for (int j = 0; j < 256; j++) if (hist[j]) usedBytes++;
            if (usedBytes > 240 && rawSz > 0x1000)
                cli::detail("High entropy section: %s (%.0f%% byte diversity, %u bytes)",
                       sn, usedBytes * 100.0 / 256, rawSz);
        }
        // 4. Scan data sections for unresolved function pointer arrays
        uint32_t unresolvedFpArrays = 0;
        for (int si = 0; si < pe.numSections; si++) {
            char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
            if (strcmp(sn, ".rdata") != 0 && strcmp(sn, ".data") != 0) continue;
            uint32_t rawOff = pe.sections[si].PointerToRawData;
            uint32_t rawSz = pe.sections[si].SizeOfRawData;
            uint32_t va = pe.sections[si].VirtualAddress;
            for (uint32_t p = 0; p + 32 <= rawSz; p += 8) {
                int cc = 0;
                for (int e = 0; e < 8 && p + (e+1)*8 <= rawSz; e++) {
                    uint64_t v = *(uint64_t*)(pe.data.data() + rawOff + p + e*8);
                    if (v >= actualBase && v < actualBase + soiCheck) {
                        int s2 = pe.findSection((uint32_t)(v - actualBase));
                        if (s2 >= 0 && pe.isExecutableSection(s2)) { cc++; continue; }
                    }
                    break;
                }
                if (cc >= 4) { unresolvedFpArrays++; p += cc*8-8; }
            }
        }
        cli::detail("Function pointer arrays in .rdata/.data: %u", unresolvedFpArrays);
        cli::detail("No section gaps found");

        // 5. Function entry validation: check .pdata entries against actual prologue bytes
        {
            auto pdataCheck = readPdataFunctions(pe);
            uint32_t validPrologue = 0, invalidPrologue = 0, unreachable = 0;
            for (auto& fb : pdataCheck) {
                uint32_t off = pe.rvaToOffset(fb.beginRVA);
                if (!off || off + 4 > pe.data.size()) { unreachable++; continue; }
                uint8_t b0 = pe.data[off], b1 = pe.data[off+1], b2 = pe.data[off+2];
                bool valid = false;
                // Standard prologues
                if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) valid = true; // sub rsp, imm8
                if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) valid = true; // sub rsp, imm32
                if (b0 == 0x48 && b1 == 0x89) valid = true; // mov [rsp+X], reg (REX.W)
                if (b0 == 0x48 && b1 == 0x8B) valid = true; // mov reg, [mem] (REX.W)
                if (b0 == 0x48 && b1 == 0x8D) valid = true; // lea (REX.W)
                if (b0 == 0x40 && b1 >= 0x50 && b1 <= 0x57) valid = true; // push with REX
                if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) valid = true; // push rbp/rbx/rsi/rdi
                // REX.R prefix (r8-r15 register operations)
                if (b0 == 0x4C && b1 == 0x89) valid = true; // mov [mem], r8-r15
                if (b0 == 0x4C && b1 == 0x8B) valid = true; // mov r8-r15, [mem]
                if (b0 == 0x4C && b1 == 0x8D) valid = true; // lea r8-r15, [mem]
                if (b0 == 0x4C && b1 == 0x63) valid = true; // movsxd r8-r15, [mem]
                if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) valid = true; // push r12-r15
                if (b0 == 0x41 && b1 == 0xB8) valid = true; // mov r8d, imm32
                if (b0 == 0x41 && b1 == 0xB9) valid = true; // mov r9d, imm32
                if (b0 == 0x41 && b1 == 0x8B) valid = true; // mov r8d, [mem]
                if (b0 == 0x41 && b1 == 0x89) valid = true; // mov [mem], r8d
                if (b0 == 0x41 && b1 == 0x0F) valid = true; // cmov/movzx r8-r15
                // Other register saves
                if (b0 == 0x44 && b1 == 0x88) valid = true; // mov [rsp+X], r8b
                if (b0 == 0x44 && b1 == 0x89) valid = true; // mov [rsp+X], r8d-r15d
                if (b0 == 0x89 && b1 == 0x54) valid = true; // mov [rsp+X], edx
                if (b0 == 0x89 && b1 == 0x4C) valid = true; // mov [rsp+X], ecx
                // Simple functions
                if (b0 == 0xC3) valid = true; // bare ret (stub)
                if (b0 == 0xE9) valid = true; // jmp (thunk)
                if (b0 == 0xCC) valid = true; // int3 (dead)
                if (b0 == 0x33 && b1 == 0xC0) valid = true; // xor eax,eax
                if (b0 == 0xB8) valid = true; // mov eax, imm
                if (b0 == 0xE8) valid = true; // call
                if (b0 == 0x90) valid = true; // nop (patched)
                if (b0 == 0xFF) valid = true; // jmp/call indirect
                // VEX prefix (AVX/SSE encoding)
                if (b0 == 0xC4 || b0 == 0xC5) valid = true;
                // F3/F2 prefix (REP/REPNE, also SSE)
                if (b0 == 0xF3 || b0 == 0xF2) valid = true;
                // 66 prefix (operand size override)
                if (b0 == 0x66) valid = true;
                // MOVAPS/MOVUPS/etc
                if (b0 == 0x0F) valid = true;
                if (valid) validPrologue++; else invalidPrologue++;
            }
            cli::detail("Function entries: %u valid prologue, %u invalid, %u unreachable",
                   validPrologue, invalidPrologue, unreachable);
            // Sample invalid prologues to understand what they are
            if (invalidPrologue > 0) {
                std::unordered_map<uint16_t, int> byteHist; // first 2 bytes → count
                int samples = 0;
                for (auto& fb2 : pdataCheck) {
                    uint32_t off2 = pe.rvaToOffset(fb2.beginRVA);
                    if (!off2 || off2 + 4 > pe.data.size()) continue;
                    uint8_t b0 = pe.data[off2], b1 = pe.data[off2+1], b2 = pe.data[off2+2];
                    // Comprehensive prologue check (same as main valid check)
                    bool valid2 = false;
                    if (b0 == 0x48 || b0 == 0x49 || b0 == 0x4C || b0 == 0x4D) valid2 = true; // REX.*
                    if (b0 == 0x40 && b1 >= 0x50 && b1 <= 0x57) valid2 = true;
                    if (b0 >= 0x50 && b0 <= 0x57) valid2 = true; // push
                    if (b0 == 0x41 && b1 >= 0x50 && b1 <= 0x57) valid2 = true;
                    if (b0 == 0x44 || b0 == 0x45) valid2 = true; // REX.R
                    if (b0 == 0x89 || b0 == 0x8B || b0 == 0x8D) valid2 = true; // MOV/LEA
                    if (b0 == 0xC3 || b0 == 0xE9 || b0 == 0xE8 || b0 == 0xEB) valid2 = true;
                    if (b0 == 0xCC || b0 == 0x90 || b0 == 0x33 || b0 == 0xB8) valid2 = true;
                    if (b0 == 0xFF || b0 == 0x0F || b0 == 0x66 || b0 == 0xF2 || b0 == 0xF3) valid2 = true;
                    if (b0 == 0xC4 || b0 == 0xC5) valid2 = true; // VEX
                    if (!valid2) byteHist[(uint16_t)(b0 << 8 | b1)]++;
                }
                printf("      Invalid prologue top bytes:");
                std::vector<std::pair<int,uint16_t>> sorted;
                for (auto& [k,v] : byteHist) sorted.push_back({v, k});
                std::sort(sorted.rbegin(), sorted.rend());
                for (size_t j = 0; j < std::min(sorted.size(), (size_t)10); j++)
                    printf(" %02X_%02X=%d", sorted[j].second>>8, sorted[j].second&0xFF, sorted[j].first);
                printf("\n");
            }
        }

        // 6. Hidden code detection: find executable byte sequences between INT3 padding
        {
            uint32_t hiddenFuncs = 0;
            for (int si = 0; si < pe.numSections; si++) {
                if (!pe.isExecutableSection(si)) continue;
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                uint32_t secRVA = pe.sections[si].VirtualAddress;
                // Look for code between CC runs that isn't a known function
                auto pdataFuncs = readPdataFunctions(pe);
                std::unordered_set<uint32_t> knownStarts;
                for (auto& fb : pdataFuncs) knownStarts.insert(fb.beginRVA);
                bool inCC = false;
                for (uint32_t p = 0; p + 4 < rawSz; p++) {
                    uint8_t b = pe.data[rawOff + p];
                    if (b == 0xCC) { inCC = true; continue; }
                    if (inCC) {
                        uint32_t rva = secRVA + p;
                        if (!knownStarts.count(rva) && b != 0x90 && b != 0x00) {
                            bool isPrologue = (b == 0x48 || b == 0x40 || b == 0x55 || b == 0x53 ||
                                             b == 0x41 || b == 0x4C || b == 0x56 || b == 0x57);
                            if (isPrologue) hiddenFuncs++;
                        }
                        inCC = false;
                    }
                }
            }
            cli::detail("Potential hidden functions (between CC padding): %u", hiddenFuncs);
        }

        // 7. Unreferenced data structures: scan .rdata for structures not referenced by any xref
        {
            std::unordered_set<uint32_t> referencedRVAs;
            for (auto& ref : allRefs) referencedRVAs.insert(ref.targetRVA);
            for (auto& pr : ptrRefs) {
                referencedRVAs.insert(pr.ptrRVA);
                referencedRVAs.insert(pr.targetRVA);
            }
            uint32_t unreferencedStructs = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".rdata") != 0) continue;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                uint32_t va = pe.sections[si].VirtualAddress;
                // Scan for 8-byte aligned entries that look like struct arrays
                for (uint32_t p = 0; p + 32 <= rawSz; p += 8) {
                    uint32_t rva = va + p;
                    if (referencedRVAs.count(rva)) continue;
                    // Check if this looks like a struct (has internal pointers)
                    uint64_t v0 = *(uint64_t*)(pe.data.data() + rawOff + p);
                    if (v0 >= actualBase && v0 < actualBase + soiCheck) {
                        uint64_t v1 = *(uint64_t*)(pe.data.data() + rawOff + p + 8);
                        if (v1 >= actualBase && v1 < actualBase + soiCheck)
                            unreferencedStructs++;
                    }
                }
            }
            cli::detail("Unreferenced pointer pairs in .rdata: %u", unreferencedStructs);
        }

        // 8. IDA analysis interference check — per-section breakdown
        {
            cli::info("=== IDA Friendliness Check ===");
            uint32_t totalDeadBytes = 0;

            for (int si = 0; si < pe.numSections; si++) {
                if (!pe.isExecutableSection(si)) continue;
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;

                uint32_t jmpReg = 0, callMem = 0, ebFF = 0, deadNop = 0;
                uint32_t nopRun = 0;
                for (uint32_t p = 0; p + 3 < rawSz; p++) {
                    uint8_t b = pe.data[rawOff+p];
                    // jmp reg
                    if (b == 0xFF && (pe.data[rawOff+p+1] & 0xF8) == 0xE0) jmpReg++;
                    if (b == 0x41 && pe.data[rawOff+p+1] == 0xFF && (pe.data[rawOff+p+2] & 0xF8) == 0xE0) jmpReg++;
                    // call [reg+disp]
                    if (b == 0xFF) {
                        uint8_t md = pe.data[rawOff+p+1];
                        if (((md>>3)&7) == 2 && (md>>6) >= 1 && (md>>6) <= 2) callMem++;
                    }
                    // EB FF
                    if (b == 0xEB && pe.data[rawOff+p+1] == 0xFF) ebFF++;
                    // NOP runs
                    if (b == 0x90) { nopRun++; } else {
                        if (nopRun >= 16) { deadNop += nopRun; totalDeadBytes += nopRun; }
                        nopRun = 0;
                    }
                }
                // Only print sections with issues
                if (jmpReg + callMem + ebFF > 0)
                    cli::detail("%-8s jmpReg=%u callMem=%u ebFF=%u deadNop=%uKB",
                           sn, jmpReg, callMem, ebFF, deadNop/1024);
            }
            cli::detail("Total dead bytes: %u KB", totalDeadBytes / 1024);

            // Context analysis: for .text jmpReg, backward scan for target hints
            uint32_t textJmpAnnotated = 0, textCallAnnotated = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn2[9] = {}; memcpy(sn2, pe.sections[si].Name, 8);
                if (strcmp(sn2, ".text") != 0) continue;
                uint32_t rawOff = pe.sections[si].PointerToRawData;
                uint32_t rawSz = pe.sections[si].SizeOfRawData;
                uint32_t secRVA = pe.sections[si].VirtualAddress;
                uint32_t soiC = pe.nt->OptionalHeader.SizeOfImage;

                for (uint32_t p = 0; p + 2 < rawSz; p++) {
                    bool isJmpReg = false;
                    int targetReg = -1;
                    uint8_t jLen = 0;
                    if (pe.data[rawOff+p] == 0xFF && (pe.data[rawOff+p+1] & 0xF8) == 0xE0) {
                        isJmpReg = true; targetReg = pe.data[rawOff+p+1] & 7; jLen = 2;
                    }
                    if (pe.data[rawOff+p] == 0x41 && pe.data[rawOff+p+1] == 0xFF &&
                        p+3 < rawSz && (pe.data[rawOff+p+2] & 0xF8) == 0xE0) {
                        isJmpReg = true; targetReg = 8 + (pe.data[rawOff+p+2] & 7); jLen = 3;
                    }
                    if (!isJmpReg) continue;

                    uint32_t jmpRVA = secRVA + p;
                    // Follow MOV reg, reg chain backward to find the source register
                    int traceReg = targetReg;
                    uint32_t tracePos = p;
                    for (int chain = 0; chain < 5 && tracePos > 3; chain++) {
                        bool found = false;
                        for (uint32_t bk = 3; bk < 30 && tracePos >= bk; bk++) {
                            uint32_t chkOff = rawOff + tracePos - bk;
                            uint8_t c0 = pe.data[chkOff], c1 = pe.data[chkOff+1], c2 = pe.data[chkOff+2];
                            // MOV reg, reg: [48|4C|49] 8B modrm(mod=3)
                            if ((c0 & 0xF8) == 0x48 && c1 == 0x8B && (c2 >> 6) == 3) {
                                int dst = ((c2 >> 3) & 7) + ((c0 & 0x04) ? 8 : 0);
                                int src = (c2 & 7) + ((c0 & 0x01) ? 8 : 0);
                                if (dst == traceReg) { traceReg = src; tracePos -= bk; found = true; break; }
                            }
                        }
                        if (!found) break;
                    }

                    // Backward scan for LEA/MOV [rip+X] that sets the (traced) target register
                    for (uint32_t back = 7; back < 200 && p >= back; back++) {
                        uint32_t sOff = rawOff + p - back;
                        uint8_t s0 = pe.data[sOff], s1 = pe.data[sOff+1], s2 = pe.data[sOff+2];
                        // LEA with RIP-relative: [48|4C] 8D [05 + reg*8]
                        if ((s0 == 0x48 || s0 == 0x4C) && s1 == 0x8D && (s2 & 0xC7) == 0x05) {
                            int leaReg = (s2 >> 3) & 7;
                            if (s0 == 0x4C) leaReg += 8;
                            if (leaReg == traceReg) {
                                int32_t disp = *(int32_t*)(pe.data.data() + sOff + 3);
                                uint32_t leaRVA = secRVA + p - back;
                                uint32_t target = leaRVA + 7 + disp;
                                if (target > 0 && target < soiC) {
                                    // Patch: LEA + JMP reg → E9 direct jmp
                                    uint32_t leaOff = rawOff + p - back;
                                    uint32_t totalLen = back + jLen; // LEA-to-JMPreg span
                                    if (totalLen >= 5) {
                                        int32_t rel = (int32_t)(target - (leaRVA + 5));
                                        pe.data[leaOff] = 0xE9;
                                        memcpy(pe.data.data() + leaOff + 1, &rel, 4);
                                        for (uint32_t n = 5; n < totalLen; n++) pe.data[leaOff+n] = 0x90;
                                    }
                                    char annot[64];
                                    sprintf_s(annot, "jmpTo_%X", target);
                                    contextAnnotations.push_back({actualBase + jmpRVA, annot});
                                    textJmpAnnotated++;
                                }
                                break;
                            }
                        }
                        // MOV reg, [rip+X]: [48|4C] 8B [05 + reg*8]
                        if ((s0 == 0x48 || s0 == 0x4C) && s1 == 0x8B && (s2 & 0xC7) == 0x05) {
                            int movReg = (s2 >> 3) & 7;
                            if (s0 == 0x4C) movReg += 8;
                            if (movReg == traceReg) {
                                int32_t disp = *(int32_t*)(pe.data.data() + sOff + 3);
                                uint32_t movRVA = secRVA + p - back;
                                uint32_t ptrRVA = movRVA + 7 + disp;
                                uint32_t ptrOff2 = pe.rvaToOffset(ptrRVA);
                                if (ptrOff2 && ptrOff2 + 8 <= pe.data.size()) {
                                    uint64_t targetVA = *(uint64_t*)(pe.data.data() + ptrOff2);
                                    if (targetVA >= actualBase && targetVA < actualBase + soiC) {
                                        uint32_t targetRVA = (uint32_t)(targetVA - actualBase);
                                        uint32_t movOff = rawOff + p - back;
                                        uint32_t totalLen = back + jLen;
                                        if (totalLen >= 5) {
                                            int32_t rel = (int32_t)(targetRVA - (movRVA + 5));
                                            pe.data[movOff] = 0xE9;
                                            memcpy(pe.data.data() + movOff + 1, &rel, 4);
                                            for (uint32_t n = 5; n < totalLen; n++) pe.data[movOff+n] = 0x90;
                                        }
                                        char annot[64];
                                        sprintf_s(annot, "jmpTo_%X", targetRVA);
                                        contextAnnotations.push_back({actualBase + jmpRVA, annot});
                                        textJmpAnnotated++;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                // Annotate unresolved vtable calls with slot info
                for (uint32_t p = 3; p + 3 < rawSz; p++) {
                    uint8_t b0 = pe.data[rawOff+p-3], b1 = pe.data[rawOff+p-2], b2 = pe.data[rawOff+p-1];
                    if ((b0 & 0xF8) != 0x48 || b1 != 0x8B || (b2 >> 6) != 0) continue;
                    if (pe.data[rawOff+p] != 0xFF) continue;
                    uint8_t cm = pe.data[rawOff+p+1];
                    if (((cm>>3)&7) != 2 || (cm>>6) < 1) continue;
                    uint32_t callRVA = secRVA + p;
                    if (pe.data[rawOff+p] == 0xE8) continue; // already patched
                    uint32_t slot = 0;
                    if ((cm>>6) == 1) slot = pe.data[rawOff+p+2] / 8;
                    else if ((cm>>6) == 2) slot = (*(uint32_t*)(pe.data.data()+rawOff+p+2)) / 8;
                    uint8_t srcReg = b2 & 7;
                    char annot[64];
                    sprintf_s(annot, "vcall_r%d_slot%u", srcReg, slot);
                    contextAnnotations.push_back({actualBase + callRVA, annot});
                    textCallAnnotated++;
                }
            }
            if (textJmpAnnotated || textCallAnnotated)
                cli::detail(".text annotations: %u jmpReg targets, %u vtable call slots",
                       textJmpAnnotated, textCallAnnotated);
        }

        cli::ok("Hidden pattern scan complete");

    // Log context annotations
    if (!contextAnnotations.empty()) {
        cli::detail("Context annotations: %zu total", contextAnnotations.size());
    }
    }

    // Final COFF re-embed with ALL discoveries (orphan strings, context annotations, etc.)
    if (!dryRun) {
        // Merge orphan discoveries into allNames
        allNames.insert(allNames.end(), orphanNames.begin(), orphanNames.end());
        allNames.insert(allNames.end(), contextAnnotations.begin(), contextAnnotations.end());

        // Clear previous COFF and re-embed with complete data
        if (pe.nt->FileHeader.PointerToSymbolTable != 0) {
            uint32_t oldSymOff = pe.nt->FileHeader.PointerToSymbolTable;
            if (oldSymOff < pe.data.size()) {
                pe.data.resize(oldSymOff);
                pe.reparse();
            }
            pe.nt->FileHeader.PointerToSymbolTable = 0;
            pe.nt->FileHeader.NumberOfSymbols = 0;
        }

        // === Filtered export table FIRST (before COFF, so .edata raw data is contiguous) ===
        // NOTE: No VA dedup here — exports.cpp handles dedup with longest-name-wins policy
        {
            uint32_t soiExp = pe.nt->OptionalHeader.SizeOfImage;
            std::vector<NamedAddress> exportNames;

            auto isCodeByte = [](uint8_t b) -> bool {
                return b == 0x48 || b == 0x4C || b == 0x40 || b == 0x55 || b == 0x53 ||
                       b == 0x56 || b == 0x57 || b == 0x41 || b == 0x50 || b == 0x51 ||
                       b == 0x52 || b == 0x89 || b == 0x8B || b == 0x33 || b == 0xE9 ||
                       b == 0xB8 || b == 0x44 || b == 0x45 || b == 0xF3 || b == 0xC3;
            };

            for (auto& n : allNames) {
                if (n.va < actualBase) continue;
                uint32_t rva = (uint32_t)(n.va - actualBase);
                if (rva == 0 || rva >= soiExp) continue;
                int sec = pe.findSection(rva);
                if (sec < 0 || !pe.isExecutableSection(sec)) continue;
                uint32_t off = pe.rvaToOffset(rva);
                if (!off || off >= pe.data.size()) continue;
                uint8_t fb = pe.data[off];
                if (fb == 0xCC || fb == 0x00 || fb == 0x90) continue;
                if (!isCodeByte(fb)) continue;
                if (n.name.rfind("orphan_func_", 0) == 0) continue;
                if (n.name.rfind("orphan_str_", 0) == 0) continue;
                if (n.name.rfind("orphan_byte_", 0) == 0) continue;
                if (n.name.rfind("orphan_arr_", 0) == 0) continue;
                exportNames.push_back(n);
            }

            if (exportNames.size() > 15000) {
                std::stable_sort(exportNames.begin(), exportNames.end(),
                    [](const NamedAddress& a, const NamedAddress& b) {
                        auto pri = [](const std::string& s) -> int {
                            if (s.find("_Serialize") != std::string::npos) return 0;
                            if (s.find("_ctor") != std::string::npos) return 0;
                            if (s.rfind("imp_", 0) == 0) return 1;
                            if (s.find("_chain_") != std::string::npos) return 2;
                            if (s.find("_ref_") != std::string::npos) return 2;
                            if (s.rfind("grfn_", 0) == 0) return 4;
                            if (s.rfind("text_", 0) == 0) return 5;
                            return 3;
                        };
                        return pri(a.name) < pri(b.name);
                    });
                exportNames.resize(15000);
            }

            addSyntheticExports(pe, actualBase, exportNames);
            cli::info("Exports: %zu entries (filtered from %zu allNames)",
                   exportNames.size(), allNames.size());
        }

        // COFF AFTER exports (COFF always last in file — not section data)
        std::vector<CoffSymEntry> finalCoffSyms;
        for (auto& n : allNames) {
            if (n.va < actualBase) continue;
            uint32_t rva = (uint32_t)(n.va - actualBase);
            int sec = pe.findSection(rva);
            bool isFunc = (sec >= 0 && pe.isExecutableSection(sec));
            finalCoffSyms.push_back({rva, (uint16_t)(sec >= 0 ? sec + 1 : 0), n.name, isFunc});
        }
        embedCoffSymbols(pe, actualBase, finalCoffSyms);
        cli::info("Final COFF: %zu entries (including %zu orphan + %zu context)",
               finalCoffSyms.size(), orphanNames.size(), contextAnnotations.size());

        // === .pdata regeneration for .grfn1 (IDA function boundary detection) ===
        {
            int grfnSecIdx = -1;
            uint32_t grfnSecStart = 0, grfnSecEnd = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".grfn1") == 0) {
                    grfnSecIdx = si;
                    grfnSecStart = pe.sections[si].VirtualAddress;
                    grfnSecEnd = grfnSecStart + pe.sections[si].Misc.VirtualSize;
                    break;
                }
            }

            // Find .pdata section
            uint32_t pdataOff3 = 0, pdataSz3 = 0;
            for (int si = 0; si < pe.numSections; si++) {
                char sn[9] = {}; memcpy(sn, pe.sections[si].Name, 8);
                if (strcmp(sn, ".pdata") == 0) {
                    pdataOff3 = pe.sections[si].PointerToRawData;
                    pdataSz3 = pe.sections[si].SizeOfRawData;
                    break;
                }
            }

            if (grfnSecIdx >= 0 && pdataOff3 && pdataSz3 >= 12) {
                uint32_t totalSlots = pdataSz3 / 12;

                // Collect existing valid entries and count zeroed slots
                struct PdataEnt { uint32_t begin, end, unwind; };
                std::vector<PdataEnt> validEntries;
                uint32_t zeroedSlots = 0;

                for (uint32_t e = 0; e < totalSlots; e++) {
                    uint32_t* ent = (uint32_t*)(pe.data.data() + pdataOff3 + e * 12);
                    if (ent[0] == 0) { zeroedSlots++; continue; }
                    validEntries.push_back({ent[0], ent[1], ent[2]});
                }

                // Collect validated .grfn1 function starts from allNames
                // (grfnFuncs is out of scope here, but allNames has grfn_ entries)
                std::vector<uint32_t> grfnStarts;
                for (auto& n : allNames) {
                    if (n.va < actualBase) continue;
                    uint32_t rva = (uint32_t)(n.va - actualBase);
                    if (rva < grfnSecStart || rva >= grfnSecEnd) continue;
                    uint32_t off = pe.rvaToOffset(rva);
                    if (!off || off >= pe.data.size()) continue;
                    uint8_t fb = pe.data[off];
                    // Strict prologue validation
                    if (fb == 0xCC || fb == 0x00 || fb == 0x90) continue;
                    if (!(fb == 0x48 || fb == 0x4C || fb == 0x40 || fb == 0x55 ||
                          fb == 0x53 || fb == 0x56 || fb == 0x57 || fb == 0x41 ||
                          fb == 0x50 || fb == 0x44 || fb == 0x45 || fb == 0x89 ||
                          fb == 0x8B || fb == 0xE9 || fb == 0xB8 || fb == 0xF3 ||
                          fb == 0x33 || fb == 0x51 || fb == 0x52)) continue;
                    grfnStarts.push_back(rva);
                }
                std::sort(grfnStarts.begin(), grfnStarts.end());
                grfnStarts.erase(std::unique(grfnStarts.begin(), grfnStarts.end()), grfnStarts.end());

                // Find or create minimal UNWIND_INFO (01 00 00 00)
                uint32_t minUnwindRVA = 0;
                // First try: find an existing minimal unwind in .text
                for (auto& ve : validEntries) {
                    uint32_t uwOff = pe.rvaToOffset(ve.unwind);
                    if (uwOff && uwOff + 4 <= pe.data.size()) {
                        if (pe.data[uwOff] == 0x01 && pe.data[uwOff+1] == 0x00 &&
                            pe.data[uwOff+2] == 0x00 && pe.data[uwOff+3] == 0x00) {
                            minUnwindRVA = ve.unwind;
                            break;
                        }
                    }
                }
                // Fallback: place in CC padding in .grfn1
                if (!minUnwindRVA) {
                    uint32_t grfnRaw = pe.sections[grfnSecIdx].PointerToRawData;
                    uint32_t grfnRawSz = pe.sections[grfnSecIdx].SizeOfRawData;
                    for (uint32_t p = 0; p + 4 <= grfnRawSz; p++) {
                        if (pe.data[grfnRaw+p]==0xCC && pe.data[grfnRaw+p+1]==0xCC &&
                            pe.data[grfnRaw+p+2]==0xCC && pe.data[grfnRaw+p+3]==0xCC) {
                            pe.data[grfnRaw+p] = 0x01;
                            pe.data[grfnRaw+p+1] = 0x00;
                            pe.data[grfnRaw+p+2] = 0x00;
                            pe.data[grfnRaw+p+3] = 0x00;
                            minUnwindRVA = grfnSecStart + p;
                            break;
                        }
                    }
                }

                // If too many candidates, cap to available slots
                if (grfnStarts.size() > zeroedSlots) {
                    grfnStarts.resize(zeroedSlots);
                }

                if (minUnwindRVA && grfnStarts.size() <= zeroedSlots) {
                    // Build new .pdata entries for .grfn1
                    // EndAddress = scan forward from start to find actual function end:
                    // Look for last C3(RET) or E9(JMP rel32) before CC padding or next func
                    auto findFuncEnd = [&](uint32_t startRVA, uint32_t maxRVA) -> uint32_t {
                        uint32_t off = pe.rvaToOffset(startRVA);
                        if (!off) return startRVA + 0x10;
                        uint32_t maxOff = pe.rvaToOffset(maxRVA);
                        if (!maxOff) maxOff = off + 0x2000;
                        uint32_t lastEnd = off; // track last valid end point
                        for (uint32_t p = off; p < maxOff && p + 5 < pe.data.size(); p++) {
                            uint8_t b = pe.data[p];
                            // RET instruction = definite function end
                            if (b == 0xC3) {
                                lastEnd = p + 1;
                                // Check if followed by CC/NOP padding = function boundary
                                if (p + 1 < maxOff && (pe.data[p+1] == 0xCC || pe.data[p+1] == 0x90))
                                    return startRVA + (p + 1 - off);
                            }
                            // JMP rel32 at function end (tail call)
                            if (b == 0xE9 && p + 5 <= maxOff) {
                                uint32_t afterJmp = p + 5;
                                if (afterJmp < maxOff && (pe.data[afterJmp] == 0xCC || pe.data[afterJmp] == 0x90))
                                    return startRVA + (afterJmp - off);
                            }
                            // CC run = definitely past function end
                            if (b == 0xCC && p > off && pe.data[p-1] != 0xCC) {
                                return startRVA + (p - off);
                            }
                        }
                        // Fallback: use last RET position or max
                        if (lastEnd > off)
                            return startRVA + (lastEnd - off);
                        return std::min(startRVA + 0x1000, maxRVA);
                    };

                    for (size_t i = 0; i < grfnStarts.size(); i++) {
                        uint32_t maxRVA = (i + 1 < grfnStarts.size()) ? grfnStarts[i+1] : grfnSecEnd;
                        uint32_t endRVA = findFuncEnd(grfnStarts[i], maxRVA);
                        if (endRVA <= grfnStarts[i]) continue;
                        validEntries.push_back({grfnStarts[i], endRVA, minUnwindRVA});
                    }

                    // Sort by BeginAddress (PE spec requirement)
                    std::sort(validEntries.begin(), validEntries.end(),
                        [](const PdataEnt& a, const PdataEnt& b) { return a.begin < b.begin; });
                    // Dedup
                    validEntries.erase(std::unique(validEntries.begin(), validEntries.end(),
                        [](const PdataEnt& a, const PdataEnt& b) { return a.begin == b.begin; }),
                        validEntries.end());

                    if (validEntries.size() <= totalSlots) {
                        memset(pe.data.data() + pdataOff3, 0, totalSlots * 12);
                        for (size_t e = 0; e < validEntries.size(); e++) {
                            uint32_t* ent = (uint32_t*)(pe.data.data() + pdataOff3 + e * 12);
                            ent[0] = validEntries[e].begin;
                            ent[1] = validEntries[e].end;
                            ent[2] = validEntries[e].unwind;
                        }
                        cli::info(".pdata regen: %zu total entries (%zu .grfn1 new, %u slots)",
                               validEntries.size(), grfnStarts.size(), totalSlots);
                    }
                } else if (!minUnwindRVA) {
                    cli::warn(".pdata regen: no minimal unwind record found");
                } else {
                    cli::warn(".pdata regen: %zu entries > %u available slots",
                           grfnStarts.size(), zeroedSlots);
                }
            }
        }
    }

    // Write output (AFTER all deobfuscation patches + final COFF + exports + pdata)
    if (!dryRun) {
        // Final .pdata repair: directly walk PE bytes (no pe infra dependency)
        {
            uint32_t pdataFixed = 0;
            auto& excDir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (excDir.VirtualAddress && excDir.Size >= 12) {
                // Manual RVA→offset using raw section table scan
                auto r2o = [&](uint32_t rva) -> uint32_t {
                    for (int s = 0; s < pe.numSections; s++) {
                        uint32_t sv = pe.sections[s].VirtualAddress;
                        uint32_t ss = pe.sections[s].Misc.VirtualSize;
                        if (!ss) ss = pe.sections[s].SizeOfRawData;
                        if (rva >= sv && rva < sv + ss)
                            return pe.sections[s].PointerToRawData + (rva - sv);
                    }
                    return 0;
                };
                uint32_t pdOff = r2o(excDir.VirtualAddress);
                uint32_t cnt = excDir.Size / 12;
                cli::info("Final .pdata scan: %u entries at off=0x%X (numSec=%d)", cnt, pdOff, pe.numSections);
                if (pdOff && pdOff + excDir.Size <= pe.data.size()) {
                    for (uint32_t e = 0; e < cnt; e++) {
                        uint32_t* ent = (uint32_t*)(pe.data.data() + pdOff + e * 12);
                        if (ent[0] == 0) continue;
                        uint32_t cOff = r2o(ent[0]);
                        if (!cOff || cOff >= pe.data.size()) continue;
                        uint8_t fb = pe.data[cOff];
                        // Also remove tiny stubs (nullsub: single RET/NOP/CC)
                    uint32_t funcSz = (ent[1] > ent[0]) ? ent[1] - ent[0] : 0;
                    if (funcSz <= 2 && (fb == 0xC3 || fb == 0xCC || fb == 0x90)) {
                        uint32_t uwOff2 = r2o(ent[2]);
                        if (uwOff2 && uwOff2 + 4 <= pe.data.size()) {
                            pe.data[uwOff2] = 0x01; pe.data[uwOff2+1] = 0;
                            pe.data[uwOff2+2] = 0; pe.data[uwOff2+3] = 0;
                            pdataFixed++;
                        }
                    }
                    if (fb == 0x90 || fb == 0xCC || fb == 0x00) {
                            uint32_t uwOff = r2o(ent[2]);
                            if (uwOff && uwOff + 4 <= pe.data.size()) {
                                pe.data[uwOff] = 0x01;
                                pe.data[uwOff+1] = 0;
                                pe.data[uwOff+2] = 0;
                                pe.data[uwOff+3] = 0;
                                pdataFixed++;
                            }
                        }
                        // Fix .riot1 sp-analysis: if function starts with CC 90 (anti-disasm entry),
                        // reset unwind to minimal — the obfuscated prologue breaks IDA stack tracking
                        if (fb == 0xCC || fb == 0x90) {
                            // Already handled above
                        } else if (cOff + 2 < pe.data.size() && pe.data[cOff] == 0xCC &&
                                   pe.data[cOff+1] == 0x90) {
                            uint32_t uwOff = r2o(ent[2]);
                            if (uwOff && uwOff + 4 <= pe.data.size()) {
                                pe.data[uwOff] = 0x01; pe.data[uwOff+1] = 0;
                                pe.data[uwOff+2] = 0; pe.data[uwOff+3] = 0;
                                pdataFixed++;
                            }
                        }
                    }
                }
            }
            cli::ok("Final .pdata repair: %u unwind entries fixed", pdataFixed);
        }

        cli::info("Writing output: %s", outputPath);
        if (pe.save(outputPath)) {
            cli::ok("Done. Output: %s (%zu bytes)", outputPath, pe.data.size());
        } else {
            cli::fail("Failed to write output file.");
            return 1;
        }
    }

    return 0;
}
