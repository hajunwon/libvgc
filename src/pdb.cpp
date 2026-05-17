#include <vgc/pdb.h>
#include <vgc/log.h>
#include <pefix/sections.h>
#include <cstring>
#include <ctime>
#include <algorithm>

namespace vgc {

using pefix::PEFile;
using pefix::appendSection;

// MSF (Multi-Stream File) constants
static constexpr uint32_t MSF_PAGE_SIZE = 4096;
static constexpr char MSF_MAGIC[] = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

// PDB stream indices
static constexpr int STREAM_PDB = 1;
static constexpr int STREAM_TPI = 2;
static constexpr int STREAM_DBI = 3;
static constexpr int STREAM_IPI = 4;

// CodeView signature for PE debug directory
#pragma pack(push, 1)
struct CV_INFO_PDB70 {
    uint32_t Signature;      // 'RSDS'
    uint8_t  Guid[16];
    uint32_t Age;
    // followed by null-terminated PDB path
};

// MSF SuperBlock
struct MSFSuperBlock {
    char Magic[32];
    uint32_t BlockSize;
    uint32_t FreeBlockMapBlock;
    uint32_t NumBlocks;
    uint32_t NumDirectoryBytes;
    uint32_t Unknown;
    uint32_t BlockMapAddr;
};

// PDB Info Stream header
struct PdbStreamHeader {
    uint32_t Version;        // 20000404
    uint32_t Signature;      // timestamp
    uint32_t Age;            // 1
    uint8_t  UniqueId[16];   // GUID
};

// DBI Stream header
struct DbiStreamHeader {
    int32_t  VersionSignature;  // -1
    uint32_t VersionHeader;     // 19990903
    uint32_t Age;               // 1
    uint16_t GlobalStreamIndex; // GSI stream
    uint16_t BuildNumber;       // (14 << 8) | 0
    uint16_t PublicStreamIndex; // PSI stream
    uint16_t PdbDllVersion;
    uint16_t SymRecordStream;   // Symbol records stream
    uint16_t PdbDllRbld;
    int32_t  ModInfoSize;       // 0
    int32_t  SectionContributionSize; // 0
    int32_t  SectionMapSize;    // 0
    int32_t  SourceInfoSize;    // 0
    int32_t  TypeServerMapSize; // 0
    uint32_t MFCTypeServerIndex;
    int32_t  OptionalDbgHeaderSize; // 0
    int32_t  ECSubstreamSize;   // 0
    uint16_t Flags;
    uint16_t Machine;           // 0x8664 = AMD64
    uint32_t Padding;
};

// S_PUB32 symbol record
struct PubSym32 {
    uint16_t RecLen;
    uint16_t RecTyp;     // 0x110E = S_PUB32
    uint32_t Flags;      // 0 = data, 2 = function
    uint32_t Off;         // offset within section
    uint16_t Seg;         // section number (1-based)
    // followed by null-terminated name
};
#pragma pack(pop)

// Helper: compute pages needed
static uint32_t pagesNeeded(uint32_t bytes) {
    return (bytes + MSF_PAGE_SIZE - 1) / MSF_PAGE_SIZE;
}

// Helper: generate a simple GUID from timestamp + data
static void generateGuid(uint8_t guid[16]) {
    srand((unsigned)time(NULL));
    for (int i = 0; i < 16; i++)
        guid[i] = (uint8_t)(rand() & 0xFF);
    guid[6] = (guid[6] & 0x0F) | 0x40; // version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // variant 1
}

bool generatePdb(PEFile& pe, uint64_t imageBase,
    const std::vector<PdbSymbol>& symbols,
    const char* pdbPath)
{
    vgc::log::raw("[*] Generating PDB: %s (%zu symbols)\n", pdbPath, symbols.size());

    uint8_t guid[16];
    generateGuid(guid);
    uint32_t age = 1;
    uint32_t timestamp = (uint32_t)time(NULL);

    // Stream 1: PDB Info
    std::vector<uint8_t> pdbInfoStream(sizeof(PdbStreamHeader), 0);
    {
        auto* hdr = (PdbStreamHeader*)pdbInfoStream.data();
        hdr->Version = 20000404;
        hdr->Signature = timestamp;
        hdr->Age = age;
        memcpy(hdr->UniqueId, guid, 16);
    }

    // Stream 2: TPI (empty — no type info)
    std::vector<uint8_t> tpiStream;
    {
        // Minimal TPI header
        uint32_t tpiHdr[8] = {};
        tpiHdr[0] = 20040203; // version
        tpiHdr[1] = sizeof(tpiHdr); // header size
        tpiHdr[2] = 0x1000;   // TypeIndexBegin
        tpiHdr[3] = 0x1000;   // TypeIndexEnd (empty range)
        tpiStream.resize(sizeof(tpiHdr));
        memcpy(tpiStream.data(), tpiHdr, sizeof(tpiHdr));
    }

    // Stream 5: Symbol records (S_PUB32 entries)
    std::vector<uint8_t> symStream;
    {
        // Signature
        uint32_t sig = 4; // CV_SIGNATURE_C13
        symStream.resize(4);
        memcpy(symStream.data(), &sig, 4);

        for (auto& sym : symbols) {
            size_t nameLen = sym.name.size() + 1; // include null
            size_t recDataLen = sizeof(PubSym32) - 4 + nameLen; // -4 for RecLen/RecTyp
            size_t totalLen = 4 + recDataLen; // RecLen(2) + RecTyp(2) + data
            // Align to 4 bytes
            totalLen = (totalLen + 3) & ~3;

            size_t off = symStream.size();
            symStream.resize(off + totalLen, 0);

            auto* rec = (PubSym32*)(symStream.data() + off);
            rec->RecLen = (uint16_t)(totalLen - 2); // excludes RecLen itself
            rec->RecTyp = 0x110E; // S_PUB32
            rec->Flags = sym.isFunction ? 2 : 0;
            rec->Off = sym.rva; // offset within image
            rec->Seg = sym.section;
            memcpy((char*)rec + sizeof(PubSym32), sym.name.c_str(), nameLen);
        }
    }

    // Stream 6: GSI (Global Symbol Index — empty hash table)
    std::vector<uint8_t> gsiStream;
    {
        // Minimal GSI header: just mark as empty
        uint32_t gsiHdr[4] = {};
        gsiHdr[0] = 0xFFFFFFFF; // VersionSignature
        gsiHdr[1] = 0xF12F091A; // VersionHeader (GSI hash)
        gsiHdr[2] = 0;          // HashRecordsByteSize
        gsiHdr[3] = 0;          // BucketsByteSize
        gsiStream.resize(sizeof(gsiHdr));
        memcpy(gsiStream.data(), gsiHdr, sizeof(gsiHdr));
    }

    // Stream 7: PSI (Public Symbol Index — references symStream)
    std::vector<uint8_t> psiStream;
    {
        // Minimal PSI: hash header + symbol hash records
        // For simplicity, empty hash — IDA falls back to linear search
        uint32_t psiHdr[5] = {};
        psiHdr[0] = (uint32_t)symStream.size() - 4; // SymHash size
        psiHdr[1] = 0; // AddrMap size
        psiHdr[2] = 0; // NumThunks
        psiHdr[3] = 0; // ThunkSize
        psiHdr[4] = 0; // ISectThunkTable
        psiStream.resize(sizeof(psiHdr));
        memcpy(psiStream.data(), psiHdr, sizeof(psiHdr));
    }

    // Stream 3: DBI
    std::vector<uint8_t> dbiStream(sizeof(DbiStreamHeader), 0);
    {
        auto* hdr = (DbiStreamHeader*)dbiStream.data();
        hdr->VersionSignature = -1;
        hdr->VersionHeader = 19990903;
        hdr->Age = age;
        hdr->GlobalStreamIndex = 6; // GSI stream
        hdr->BuildNumber = (14 << 8);
        hdr->PublicStreamIndex = 7; // PSI stream
        hdr->SymRecordStream = 5;   // symbol records
        hdr->Machine = 0x8664;      // AMD64
    }

    // Stream 4: IPI (empty)
    std::vector<uint8_t> ipiStream = tpiStream; // same format, empty

    // Streams: 0=old dir(empty), 1=PDB info, 2=TPI, 3=DBI, 4=IPI, 5=SymRec, 6=GSI, 7=PSI
    std::vector<std::vector<uint8_t>*> streams = {
        nullptr,       // stream 0 (empty)
        &pdbInfoStream,
        &tpiStream,
        &dbiStream,
        &ipiStream,
        &symStream,
        &gsiStream,
        &psiStream
    };

    // Calculate total pages needed
    uint32_t numStreams = (uint32_t)streams.size();

    // Stream directory: numStreams(4) + sizes(4*N) + page numbers
    uint32_t totalStreamPages = 0;
    std::vector<uint32_t> streamSizes(numStreams, 0);
    std::vector<uint32_t> streamPageCounts(numStreams, 0);
    for (uint32_t i = 0; i < numStreams; i++) {
        if (streams[i]) {
            streamSizes[i] = (uint32_t)streams[i]->size();
            streamPageCounts[i] = pagesNeeded(streamSizes[i]);
        }
        totalStreamPages += streamPageCounts[i];
    }

    uint32_t dirBytes = 4 + numStreams * 4 + totalStreamPages * 4;
    uint32_t dirPages = pagesNeeded(dirBytes);

    // Page layout:
    // Page 0: SuperBlock
    // Page 1: Free Page Map 1
    // Page 2: Free Page Map 2
    // Page 3: Block Map (directory page list)
    // Page 4+: Directory pages, then stream data pages
    uint32_t nextPage = 4;
    uint32_t dirStartPage = nextPage;
    nextPage += dirPages;

    std::vector<std::vector<uint32_t>> streamPageLists(numStreams);
    for (uint32_t i = 0; i < numStreams; i++) {
        for (uint32_t p = 0; p < streamPageCounts[i]; p++) {
            streamPageLists[i].push_back(nextPage++);
        }
    }

    uint32_t totalPages = nextPage;

    // Build the file
    std::vector<uint8_t> pdb(totalPages * MSF_PAGE_SIZE, 0);

    // SuperBlock (page 0)
    auto* sb = (MSFSuperBlock*)pdb.data();
    memcpy(sb->Magic, MSF_MAGIC, sizeof(MSF_MAGIC) - 1);
    sb->BlockSize = MSF_PAGE_SIZE;
    sb->FreeBlockMapBlock = 1;
    sb->NumBlocks = totalPages;
    sb->NumDirectoryBytes = dirBytes;
    sb->Unknown = 0;
    sb->BlockMapAddr = 3; // page 3 = block map

    // Block Map (page 3): list of pages containing the directory
    uint32_t* blockMap = (uint32_t*)(pdb.data() + 3 * MSF_PAGE_SIZE);
    for (uint32_t i = 0; i < dirPages; i++)
        blockMap[i] = dirStartPage + i;

    // Directory (starting at dirStartPage)
    std::vector<uint8_t> dirData;
    // NumStreams
    dirData.resize(4);
    memcpy(dirData.data(), &numStreams, 4);
    // Stream sizes
    for (uint32_t i = 0; i < numStreams; i++) {
        size_t off = dirData.size();
        dirData.resize(off + 4);
        memcpy(dirData.data() + off, &streamSizes[i], 4);
    }
    // Stream page numbers
    for (uint32_t i = 0; i < numStreams; i++) {
        for (uint32_t pg : streamPageLists[i]) {
            size_t off = dirData.size();
            dirData.resize(off + 4);
            memcpy(dirData.data() + off, &pg, 4);
        }
    }
    // Write directory to its pages
    for (uint32_t i = 0; i < dirPages; i++) {
        uint32_t copyLen = MSF_PAGE_SIZE;
        if (i * MSF_PAGE_SIZE + copyLen > dirData.size())
            copyLen = (uint32_t)dirData.size() - i * MSF_PAGE_SIZE;
        if (copyLen > 0)
            memcpy(pdb.data() + (dirStartPage + i) * MSF_PAGE_SIZE,
                   dirData.data() + i * MSF_PAGE_SIZE, copyLen);
    }

    // Write stream data to their pages
    for (uint32_t i = 0; i < numStreams; i++) {
        if (!streams[i] || streams[i]->empty()) continue;
        for (uint32_t p = 0; p < streamPageCounts[i]; p++) {
            uint32_t pageIdx = streamPageLists[i][p];
            uint32_t srcOff = p * MSF_PAGE_SIZE;
            uint32_t copyLen = MSF_PAGE_SIZE;
            if (srcOff + copyLen > streams[i]->size())
                copyLen = (uint32_t)streams[i]->size() - srcOff;
            if (copyLen > 0)
                memcpy(pdb.data() + pageIdx * MSF_PAGE_SIZE,
                       streams[i]->data() + srcOff, copyLen);
        }
    }

    // Write PDB file
    FILE* f = nullptr;
    fopen_s(&f, pdbPath, "wb");
    if (!f) { vgc::log::raw("[!] Failed to create PDB: %s\n", pdbPath); return false; }
    fwrite(pdb.data(), 1, pdb.size(), f);
    fclose(f);
    vgc::log::raw("[+] PDB written: %s (%zu KB, %u pages)\n",
           pdbPath, pdb.size() / 1024, totalPages);

    // Build CV_INFO_PDB70 + path string
    std::string pdbFilename = pdbPath;
    size_t lastSlash = pdbFilename.rfind('\\');
    if (lastSlash != std::string::npos) pdbFilename = pdbFilename.substr(lastSlash + 1);
    size_t lastSlash2 = pdbFilename.rfind('/');
    if (lastSlash2 != std::string::npos) pdbFilename = pdbFilename.substr(lastSlash2 + 1);

    std::vector<uint8_t> cvInfo(sizeof(CV_INFO_PDB70) + pdbFilename.size() + 1, 0);
    auto* cv = (CV_INFO_PDB70*)cvInfo.data();
    cv->Signature = 0x53445352; // 'RSDS'
    memcpy(cv->Guid, guid, 16);
    cv->Age = age;
    memcpy(cvInfo.data() + sizeof(CV_INFO_PDB70), pdbFilename.c_str(), pdbFilename.size());

    // Build debug directory entry + CV info as a new section
    IMAGE_DEBUG_DIRECTORY dbgDir = {};
    dbgDir.TimeDateStamp = timestamp;
    dbgDir.MajorVersion = 0;
    dbgDir.MinorVersion = 0;
    dbgDir.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    dbgDir.SizeOfData = (DWORD)cvInfo.size();

    // Combine debug directory + CV info into one section
    std::vector<uint8_t> dbgSection(sizeof(IMAGE_DEBUG_DIRECTORY) + cvInfo.size(), 0);

    // We need to know the section RVA to set AddressOfRawData
    uint32_t secAlign = pe.nt->OptionalHeader.SectionAlignment;
    if (!secAlign) secAlign = 0x1000;
    uint32_t dbgSectionRVA = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t end = pe.sections[i].VirtualAddress + pe.sections[i].Misc.VirtualSize;
        if (end > dbgSectionRVA) dbgSectionRVA = end;
    }
    dbgSectionRVA = (dbgSectionRVA + secAlign - 1) & ~(secAlign - 1);

    dbgDir.AddressOfRawData = dbgSectionRVA + sizeof(IMAGE_DEBUG_DIRECTORY);
    dbgDir.PointerToRawData = 0; // will be set by appendSection

    memcpy(dbgSection.data(), &dbgDir, sizeof(dbgDir));
    memcpy(dbgSection.data() + sizeof(dbgDir), cvInfo.data(), cvInfo.size());

    // Append .debug section
    if (!appendSection(pe, ".debug", dbgSection,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE)) {
        vgc::log::raw("[!] Failed to append .debug section\n");
        return false;
    }

    // Fix PointerToRawData in the debug directory (now we know the file offset)
    // Find the .debug section we just added
    for (WORD i = 0; i < pe.numSections; i++) {
        char sn[9] = {}; memcpy(sn, pe.sections[i].Name, 8);
        if (strcmp(sn, ".debug") == 0) {
            dbgDir.PointerToRawData = pe.sections[i].PointerToRawData + sizeof(IMAGE_DEBUG_DIRECTORY);
            memcpy(pe.data.data() + pe.sections[i].PointerToRawData, &dbgDir, sizeof(dbgDir));
            break;
        }
    }

    // Update PE debug data directory
    pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = dbgSectionRVA;
    pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(IMAGE_DEBUG_DIRECTORY);

    vgc::log::raw("[+] Debug directory added to PE (PDB: %s)\n", pdbFilename.c_str());
    return true;
}

} // namespace vgc
