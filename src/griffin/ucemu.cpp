#ifdef USE_UNICORN
#include <vgc/log.h>

#include <vgc/griffin/ucemu.h>
#include <unicorn/x86.h>
#include <cstdio>
#include <cstring>
#include <algorithm>

extern FILE* g_dbgLog;
#define DBG(...) do { if (g_dbgLog) { fprintf(g_dbgLog, __VA_ARGS__); } } while(0)

UnicornVGC::UnicornVGC(const pefix::PEFile& pe, uint64_t imageBase)
    : uc_(nullptr), pe_(pe), imageBase_(imageBase), stackBase_(0), stackSize_(0), int3Enabled_(false) {
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);
    if (err != UC_ERR_OK) {
        vgc::log::raw("[!] Unicorn init failed: %s\n", uc_strerror(err));
    }
}

UnicornVGC::~UnicornVGC() {
    if (uc_) uc_close(uc_);
}

bool UnicornVGC::loadSections() {
    if (!uc_) return false;

    uint32_t soi = pe_.nt->OptionalHeader.SizeOfImage;
    uint64_t alignedSize = (soi + 0xFFF) & ~0xFFFULL;

    uc_err err = uc_mem_map(uc_, imageBase_, alignedSize, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        vgc::log::raw("[!] Failed to map image: %s\n", uc_strerror(err));
        return false;
    }

    // Write section data + record executable ranges
    execRanges_.clear();
    uint32_t riot1Stubbed = 0;
    for (int i = 0; i < pe_.numSections; i++) {
        uint32_t rva = pe_.sections[i].VirtualAddress;
        uint32_t rawOff = pe_.sections[i].PointerToRawData;
        uint32_t rawSz = pe_.sections[i].SizeOfRawData;
        if (rawOff + rawSz > pe_.data.size()) continue;

        uc_mem_write(uc_, imageBase_ + rva, pe_.data.data() + rawOff, rawSz);

        if (pe_.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            execRanges_.push_back({imageBase_ + rva, imageBase_ + rva + rawSz});

        // Auto-stub .riot1: write RET at every function-like entry
        char sname[9] = {};
        memcpy(sname, pe_.sections[i].Name, 8);
        if (strcmp(sname, ".riot1") == 0) {
            // Scan for function prologues and write RET
            for (uint32_t pos = 0; pos + 4 < rawSz; pos++) {
                uint8_t b0 = pe_.data[rawOff + pos];
                // push rcx (51) or sub rsp (48 83 EC / 48 81 EC) at function start
                bool isEntry = false;
                if (pos == 0) isEntry = true;
                else if (b0 == 0x51 || (b0 == 0x48 && pe_.data[rawOff+pos+1] == 0x83)) {
                    uint8_t prev = pe_.data[rawOff + pos - 1];
                    if (prev == 0xCC || prev == 0xC3 || prev == 0x90) isEntry = true;
                }
                if (isEntry && (b0 == 0x51 || b0 == 0x48 || b0 == 0x40 || b0 == 0x55)) {
                    uint8_t ret = 0xC3;
                    uc_mem_write(uc_, imageBase_ + rva + pos, &ret, 1);
                    riot1Stubbed++;
                }
            }
        }
    }

    // Mapping log removed
    return true;
}

bool UnicornVGC::setupStack(uint64_t base, uint32_t size) {
    stackBase_ = base;
    stackSize_ = size;

    uc_err err = uc_mem_map(uc_, base, size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        vgc::log::raw("[!] Failed to map stack: %s\n", uc_strerror(err));
        return false;
    }

    uint64_t rsp = base + size - 0x1000;
    uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
    uc_reg_write(uc_, UC_X86_REG_RBP, &rsp);

    return true;
}

void UnicornVGC::addStub(uint64_t va, uint64_t retval) {
    stubs_[va] = retval;
    // Write RET instruction at stub address so Unicorn naturally returns
    uint8_t ret = 0xC3;
    uc_mem_write(uc_, va, &ret, 1);
}

void UnicornVGC::watchObject(uint64_t addr, uint32_t size, const char* name) {
    // Map watch region if not already mapped
    uc_mem_map(uc_, addr & ~0xFFFULL, (size + 0xFFF) & ~0xFFFULL, UC_PROT_ALL);
    watches_.push_back({addr, size, name});
}

void UnicornVGC::enableInt3Handler() {
    int3Enabled_ = true;
}

uint64_t UnicornVGC::getReg(int ucRegId) const {
    uint64_t val = 0;
    uc_reg_read(uc_, ucRegId, &val);
    return val;
}

void UnicornVGC::setReg(int ucRegId, uint64_t val) {
    uc_reg_write(uc_, ucRegId, &val);
}

void UnicornVGC::writeMem(uint64_t addr, const void* data, size_t size) {
    uc_mem_write(uc_, addr, data, size);
}

void UnicornVGC::readMem(uint64_t addr, void* data, size_t size) {
    uc_mem_read(uc_, addr, data, size);
}

// === Hooks ===

void UnicornVGC::hookCode(uc_engine* uc, uint64_t addr, uint32_t size, void* user) {
    auto* self = (UnicornVGC*)user;

    // Auto-stub: if execution leaves any PE executable section, force return
    bool inExec = false;
    for (auto& r : self->execRanges_)
        if (addr >= r.start && addr < r.end) { inExec = true; break; }
    if (!inExec && addr != 0) {
        uint64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uint64_t retAddr;
        uc_mem_read(uc, rsp, &retAddr, 8);
        rsp += 8;
        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
        uc_reg_write(uc, UC_X86_REG_RIP, &retAddr);
        uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_emu_stop(uc);
        return;
    }

    // Track vtable calls: detect "call [rax+N]" by checking current instruction bytes
    if (self->knownVtables_ && size >= 3) {
        uint8_t code[10];
        uc_mem_read(uc, addr, code, std::min((uint32_t)size, (uint32_t)10));
        // FF 50 XX = call [rax+disp8], FF 90 XX XX XX XX = call [rax+disp32]
        if (code[0] == 0xFF && (code[1] == 0x50 || code[1] == 0x90)) {
            uint32_t vtOff = (code[1] == 0x50) ? code[2] : *(uint32_t*)(code + 2);
            uint64_t rax;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            auto vit = self->knownVtables_->find(rax);
            if (vit != self->knownVtables_->end()) {
                uint32_t idx = vtOff / 8;
                if (idx < vit->second.size()) {
                    VtableCallHit hit = {addr, rax, vtOff, vit->second[idx]};
                    self->vtableHits_.push_back(hit);
                }
            }
        }
    }

    // Track jmp reg at watched addresses
    if (!self->watchedJmps_.empty() && self->watchedJmps_.count(addr)) {
        uint8_t code[3];
        uc_mem_read(uc, addr, code, 3);
        int targetReg = -1;
        uint8_t iLen = 0;
        // FF E0-E7: jmp rax-rdi
        if (code[0] == 0xFF && (code[1] & 0xF8) == 0xE0) {
            targetReg = code[1] & 7; iLen = 2;
        }
        // 41 FF E0-E7: jmp r8-r15
        if (code[0] == 0x41 && code[1] == 0xFF && (code[2] & 0xF8) == 0xE0) {
            targetReg = 8 + (code[2] & 7); iLen = 3;
        }
        if (targetReg >= 0) {
            static const int regMap[] = {
                UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
            };
            uint64_t val = 0;
            uc_reg_read(uc, regMap[targetReg], &val);
            self->jmpRegHits_.push_back({addr, val, iLen});
            uc_emu_stop(uc); // Early exit — got what we need
        }
    }

    // Check if this address is a stub
    auto it = self->stubs_.find(addr);
    if (it != self->stubs_.end()) {
        uint64_t retval = it->second;

        // Log call info (return address is at [RSP] since CALL already pushed it)
        UcCallInfo ci;
        ci.target = addr;
        uc_reg_read(uc, UC_X86_REG_RCX, &ci.rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &ci.rdx);
        uc_reg_read(uc, UC_X86_REG_R8, &ci.r8);
        uc_reg_read(uc, UC_X86_REG_R9, &ci.r9);
        uint64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uc_mem_read(uc, rsp, &ci.caller, 8);
        self->calls_.push_back(ci);

        // Set return value — the RET at this address will naturally pop and return
        uc_reg_write(uc, UC_X86_REG_RAX, &retval);
    }
}

void UnicornVGC::hookMemWrite(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user) {
    auto* self = (UnicornVGC*)user;

    for (auto& w : self->watches_) {
        if (addr >= w.addr && addr < w.addr + w.size) {
            UcFieldWrite fw;
            fw.addr = addr;
            fw.offset = (uint32_t)(addr - w.addr);
            fw.value = (uint64_t)value;
            fw.size = size;
            uc_reg_read(uc, UC_X86_REG_RIP, &fw.rip);
            self->fieldWrites_.push_back(fw);
        }
    }
}

bool UnicornVGC::hookMemInvalid(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user) {
    // Auto-map unmapped regions (heap, etc.)
    uint64_t pageAddr = addr & ~0xFFFULL;
    uc_mem_map(uc, pageAddr, 0x1000, UC_PROT_ALL);
    return true;
}

void UnicornVGC::hookIntr(uc_engine* uc, uint32_t intno, void* user) {
    auto* self = (UnicornVGC*)user;

    if (!self->int3Enabled_) return;

    if (intno == 3) {
        uint64_t rip;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);

        // INT3 was reached via CALL (return address on stack)
        // VEH handler would: set up AES context + redirect to AES function
        // We can't fully replicate VEH, so we pop return address and return
        // This effectively makes the INT3 call a no-op
        uint64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uint64_t retAddr;
        uc_mem_read(uc, rsp, &retAddr, 8);
        rsp += 8;
        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
        uc_reg_write(uc, UC_X86_REG_RIP, &retAddr);

        // Stop current emulation — Unicorn will restart from new RIP
        uc_emu_stop(uc);
    }
}

bool UnicornVGC::run(uint64_t startVA, uint64_t endVA, uint64_t maxInsns) {
    if (!uc_) return false;

    // Install hooks
    uc_hook hCode, hMemW, hMemInv, hIntr;

    uc_hook_add(uc_, &hCode, UC_HOOK_CODE, (void*)hookCode, this, 0, ~0ULL);
    uc_hook_add(uc_, &hMemW, UC_HOOK_MEM_WRITE, (void*)hookMemWrite, this, 0, ~0ULL);
    uc_hook_add(uc_, &hMemInv, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                (void*)hookMemInvalid, this, 0, ~0ULL);

    if (int3Enabled_)
        uc_hook_add(uc_, &hIntr, UC_HOOK_INTR, (void*)hookIntr, this, 0, ~0ULL);

    uint64_t end = endVA ? endVA : 0;
    uint64_t count = maxInsns ? maxInsns : 0;

    // Per-run logging removed — batch progress in pe_fixer instead

    // Run in a loop — INT3 handler calls uc_emu_stop, we restart from new RIP
    uint64_t totalInsns = 0;
    uint64_t curStart = startVA;
    uc_err err = UC_ERR_OK;

    for (int restarts = 0; restarts < 5000; restarts++) {
        uint64_t remaining = count ? count - totalInsns : 0;
        if (count && remaining == 0) break;
        err = uc_emu_start(uc_, curStart, end, 0, remaining);

        uint64_t newRip = getReg(UC_X86_REG_RIP);

        if (err == UC_ERR_OK) {
            break;
        }

        if (newRip != curStart && newRip != 0) {
            curStart = newRip;
            totalInsns += 2;
            continue;
        }

        break;
    }

    uint64_t finalRip = getReg(UC_X86_REG_RIP);
    // Completed logging removed

    return err == UC_ERR_OK;
}

uint64_t UnicornVGC::callFunction(uint64_t funcVA, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4) {
    // x64 calling convention: RCX, RDX, R8, R9
    setReg(UC_X86_REG_RCX, arg1);
    setReg(UC_X86_REG_RDX, arg2);
    setReg(UC_X86_REG_R8, arg3);
    setReg(UC_X86_REG_R9, arg4);

    // Sentinel: place just after the image so hookCode's auto-stub doesn't catch it.
    uint32_t soi = pe_.nt->OptionalHeader.SizeOfImage;
    uint64_t sentinelPage = (imageBase_ + soi + 0xFFF) & ~0xFFFULL;
    uint64_t sentinel = sentinelPage + 0x100;
    uc_mem_map(uc_, sentinelPage, 0x1000, UC_PROT_ALL);
    uint8_t retInstr = 0xC3;
    uc_mem_write(uc_, sentinel, &retInstr, 1);

    // Push return address + shadow space
    uint64_t rsp = getReg(UC_X86_REG_RSP);
    rsp -= 8;
    writeMem(rsp, &sentinel, 8);
    rsp -= 32; // shadow space
    setReg(UC_X86_REG_RSP, rsp);

    run(funcVA, sentinel, 500000);

    return getReg(UC_X86_REG_RAX);
}

std::string UnicornVGC::readArenaString(uint64_t arenaStringPtrVA) {
    // ArenaStringPtr layout: raw pointer with tag bits in lower 3 bits
    // Dereference: actual_ptr = *arenaStringPtrVA & ~7
    // std::string layout at actual_ptr:
    //   +0x00: data ptr (or inline buffer if SSO)
    //   +0x10: size
    //   +0x18: capacity (if >= 16, data is at *+0x00; else inline at +0x00)
    uint64_t rawPtr = 0;
    readMem(arenaStringPtrVA, &rawPtr, 8);
    rawPtr &= ~7ULL;
    if (rawPtr == 0) return "";

    uint64_t strSize = 0, strCap = 0;
    readMem(rawPtr + 0x10, &strSize, 8);
    readMem(rawPtr + 0x18, &strCap, 8);

    if (strSize == 0 || strSize > 0x10000) return "";

    uint64_t dataPtr = rawPtr; // SSO: data is inline
    if (strCap > 0x0F) {
        readMem(rawPtr, &dataPtr, 8); // heap: data is at ptr
    }

    std::string result(strSize, '\0');
    readMem(dataPtr, result.data(), strSize);
    return result;
}

std::string UnicornVGC::readCString(uint64_t va, size_t maxLen) {
    std::string result;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t ch = 0;
        readMem(va + i, &ch, 1);
        if (ch == 0) break;
        result += (char)ch;
    }
    return result;
}

std::vector<UnicornVGC::ProtoFieldDump> UnicornVGC::dumpProtoFields(
    uint64_t objVA,
    const std::vector<std::pair<uint32_t, std::string>>& fieldMap) {

    std::vector<ProtoFieldDump> result;
    for (auto& [offset, name] : fieldMap) {
        ProtoFieldDump fd;
        fd.offset = offset;
        fd.name = name;
        fd.value = readArenaString(objVA + offset);
        if (fd.value.empty()) {
            // Try reading as int32
            uint32_t intVal = 0;
            readMem(objVA + offset, &intVal, 4);
            if (intVal != 0)
                fd.value = "int:" + std::to_string(intVal);
        }
        result.push_back(fd);
    }
    return result;
}

#endif // USE_UNICORN
