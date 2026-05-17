#pragma once

#ifdef USE_UNICORN

#include <pefix/pefix.h>
#include <unicorn/unicorn.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>
#include <unordered_set>

struct UcFieldWrite {
    uint64_t addr;
    uint32_t offset;
    uint64_t value;
    uint32_t size;
    uint64_t rip;
};

struct UcCallInfo {
    uint64_t caller;
    uint64_t target;
    uint64_t rcx, rdx, r8, r9;
};

class UnicornVGC {
public:
    UnicornVGC(const pefix::PEFile& pe, uint64_t imageBase);
    ~UnicornVGC();

    bool loadSections();

    bool setupStack(uint64_t base = 0x7FFE0000, uint32_t size = 0x100000);

    void addStub(uint64_t va, uint64_t retval);

    void watchObject(uint64_t addr, uint32_t size, const char* name);

    void enableInt3Handler();

    bool run(uint64_t startVA, uint64_t endVA = 0, uint64_t maxInsns = 0);

    uint64_t callFunction(uint64_t funcVA, uint64_t arg1 = 0, uint64_t arg2 = 0,
                          uint64_t arg3 = 0, uint64_t arg4 = 0);

    std::string readArenaString(uint64_t arenaStringPtrVA);

    std::string readCString(uint64_t va, size_t maxLen = 4096);

    struct ProtoFieldDump {
        uint32_t offset;
        std::string name;
        std::string value;
    };
    std::vector<ProtoFieldDump> dumpProtoFields(uint64_t objVA,
        const std::vector<std::pair<uint32_t, std::string>>& fieldMap);

    struct VtableCallHit {
        uint64_t callAddr;
        uint64_t vtableVA;
        uint32_t offset;
        uint64_t targetVA;
    };
    void setKnownVtables(const std::unordered_map<uint64_t, std::vector<uint64_t>>* vt) { knownVtables_ = vt; }
    const std::vector<VtableCallHit>& vtableHits() const { return vtableHits_; }

    struct JmpRegHit {
        uint64_t jmpAddr;
        uint64_t targetVA;
        uint8_t instrLen;
    };
    void watchJmpReg(uint64_t addr) { watchedJmps_.insert(addr); }
    void clearJmpRegWatches() { watchedJmps_.clear(); jmpRegHits_.clear(); }
    const std::vector<JmpRegHit>& jmpRegHits() const { return jmpRegHits_; }

    const std::vector<UcFieldWrite>& fieldWrites() const { return fieldWrites_; }
    const std::vector<UcCallInfo>& calls() const { return calls_; }
    uint64_t getReg(int ucRegId) const;
    void setReg(int ucRegId, uint64_t val);

    void writeMem(uint64_t addr, const void* data, size_t size);
    void readMem(uint64_t addr, void* data, size_t size);

private:
    uc_engine* uc_;
    const pefix::PEFile& pe_;
    uint64_t imageBase_;
    uint64_t stackBase_;
    uint32_t stackSize_;

    std::unordered_map<uint64_t, uint64_t> stubs_;
    std::vector<UcFieldWrite> fieldWrites_;
    std::vector<UcCallInfo> calls_;
    std::vector<VtableCallHit> vtableHits_;
    const std::unordered_map<uint64_t, std::vector<uint64_t>>* knownVtables_ = nullptr;
    std::unordered_set<uint64_t> watchedJmps_;
    std::vector<JmpRegHit> jmpRegHits_;

    struct ExecRange { uint64_t start; uint64_t end; };
    std::vector<ExecRange> execRanges_;
public:
    void addExecRange(uint64_t start, uint64_t end) { execRanges_.push_back({start, end}); }
private:

    struct WatchRegion { uint64_t addr; uint32_t size; std::string name; };
    std::vector<WatchRegion> watches_;

    bool int3Enabled_;

    static void hookCode(uc_engine* uc, uint64_t addr, uint32_t size, void* user);
    static void hookMemWrite(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user);
    static bool hookMemInvalid(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user);
    static void hookIntr(uc_engine* uc, uint32_t intno, void* user);
};

#endif // USE_UNICORN
