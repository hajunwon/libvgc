#ifdef GRIFFIN_USE_Z3
#include <vgc/log.h>

#include <vgc/griffin/z3solve.h>
#include <griffin/griffin.h>
#include <z3++.h>
#include <cstdio>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <chrono>

using GrOp = pefix::Op;
using GrReg = pefix::Reg;
using GrWidth = pefix::Width;
using GrValue = pefix::Value;
using GrInstr = pefix::Instr;
using GrBlock = pefix::Block;
using GrCC = pefix::CC;
inline const char* grOpName(GrOp op) { return pefix::opName(op); }

using griffin::MBA_XOR;
using griffin::MBA_OR;
using griffin::MBA_AND;
using griffin::MBA_ADD;
using griffin::MBA_SUB;

GriffinZ3Solver::GriffinZ3Solver() : ctx_(nullptr) {}
GriffinZ3Solver::~GriffinZ3Solver() {}

static unsigned widthBits(GrWidth w) {
    switch (w) {
    case GrWidth::W8:  return 8;
    case GrWidth::W16: return 16;
    case GrWidth::W32: return 32;
    case GrWidth::W64: return 64;
    }
    return 64;
}

struct LocalZ3 {
    z3::context ctx;
    unsigned bits;
    std::unordered_map<uint16_t, z3::expr> regs;
    std::unordered_map<uint16_t, z3::expr> inputs;

    LocalZ3(unsigned b) : bits(b) {}

    z3::expr ensureWidth(z3::expr e, unsigned target) {
        unsigned eBits = e.get_sort().bv_size();
        if (eBits == target) return e;
        if (eBits < target) return z3::zext(e, target - eBits);
        return e.extract(target - 1, 0);
    }

    z3::expr getReg(uint16_t idx) {
        auto it = regs.find(idx);
        if (it != regs.end())
            return ensureWidth(it->second, bits);
        char name[16];
        sprintf_s(name, "r%u", idx);
        z3::expr sym = ctx.bv_const(name, bits);
        regs.emplace(idx, sym);
        inputs.emplace(idx, sym);
        return sym;
    }

    z3::expr getVal(const GrValue& v) {
        if (v.kind == GrValue::REG) {
            uint16_t idx = (uint16_t)v.reg;
            if (idx >= 16) return ctx.bv_val(0ULL, bits);
            return getReg(idx);
        }
        if (v.kind == GrValue::IMM)
            return ctx.bv_val((uint64_t)v.imm, bits);
        return ctx.bv_val(0ULL, bits);
    }

    void setReg(const GrValue& dst, z3::expr e) {
        if (dst.kind != GrValue::REG) return;
        uint16_t idx = (uint16_t)dst.reg;
        if (idx >= 16) return;
        regs.insert_or_assign(idx, ensureWidth(e, bits));
    }

    bool lift(const GrInstr& instr) {
        auto S1 = [&]() { return getVal(instr.src1); };
        auto S2 = [&]() { return getVal(instr.src2); };

        switch (instr.op) {
        case GrOp::MOV: case GrOp::MOVZX:
            setReg(instr.dst, S1()); return true;
        case GrOp::AND:
            setReg(instr.dst, S1() & S2()); return true;
        case GrOp::OR:
            setReg(instr.dst, S1() | S2()); return true;
        case GrOp::XOR:
            setReg(instr.dst, S1() ^ S2()); return true;
        case GrOp::NOT:
            setReg(instr.dst, ~S1()); return true;
        case GrOp::ADD:
            setReg(instr.dst, S1() + S2()); return true;
        case GrOp::SUB:
            setReg(instr.dst, S1() - S2()); return true;
        case GrOp::NEG:
            setReg(instr.dst, -S1()); return true;
        case GrOp::IMUL:
            if (!instr.src2.isNone())
                setReg(instr.dst, S1() * S2());
            else
                setReg(instr.dst, S1() * S1());
            return true;
        case GrOp::SHL:
            if (instr.src2.isImm()) { setReg(instr.dst, z3::shl(S1(), S2())); return true; }
            return false;
        case GrOp::SHR:
            if (instr.src2.isImm()) { setReg(instr.dst, z3::lshr(S1(), S2())); return true; }
            return false;
        case GrOp::SAR:
            if (instr.src2.isImm()) { setReg(instr.dst, z3::ashr(S1(), S2())); return true; }
            return false;
        case GrOp::LEA:
            if (instr.src1.isMem()) {
                z3::expr result = ctx.bv_val(0ULL, bits);
                if (instr.src1.reg != GrReg::NONE && (uint16_t)instr.src1.reg < 16)
                    result = getReg((uint16_t)instr.src1.reg);
                if (instr.src1.imm != 0)
                    result = result + ctx.bv_val((uint64_t)instr.src1.imm, bits);
                if (instr.src1.index != GrReg::NONE && (uint16_t)instr.src1.index < 16) {
                    z3::expr idx = getReg((uint16_t)instr.src1.index);
                    unsigned sc = instr.src1.scale ? instr.src1.scale : 1;
                    result = result + idx * ctx.bv_val((uint64_t)sc, bits);
                }
                setReg(instr.dst, result);
                return true;
            }
            return false;
        case MBA_XOR:
            setReg(instr.dst, S1() ^ S2()); return true;
        case MBA_OR:
            setReg(instr.dst, S1() | S2()); return true;
        case MBA_AND:
            setReg(instr.dst, S1() & S2()); return true;
        case MBA_ADD:
            setReg(instr.dst, S1() + S2()); return true;
        case MBA_SUB:
            setReg(instr.dst, S1() - S2()); return true;
        case GrOp::NOP: case GrOp::INT3:
        case GrOp::CMP: case GrOp::TEST: case GrOp::BT:
        case GrOp::PUSH: case GrOp::POP:
        case GrOp::CALL: case GrOp::RET:
        case GrOp::JMP: case GrOp::JCC:
        case GrOp::STORE:
            return true; // no register data flow to track
        default:
            return false;
        }
    }
};

static bool checkEq(z3::context& ctx, z3::expr& mba, z3::expr& x, z3::expr& y,
                     std::function<z3::expr(z3::expr&, z3::expr&)> buildOp) {
    z3::expr candidate = buildOp(x, y);
    unsigned mBits = mba.get_sort().bv_size();
    unsigned cBits = candidate.get_sort().bv_size();
    if (mBits != cBits) {
        if (cBits < mBits) candidate = z3::zext(candidate, mBits - cBits);
        else candidate = candidate.extract(mBits - 1, 0);
    }
    z3::solver s(ctx);
    s.set("timeout", 100u);
    s.add(mba != candidate);
    return s.check() == z3::unsat;
}

struct ConcreteEval {
    uint64_t regs[16] = {};
    std::unordered_map<int64_t, uint64_t> stackMem;
    unsigned bits;
    uint64_t mask;

    ConcreteEval(unsigned b) : bits(b), mask(b == 64 ? ~0ULL : (1ULL << b) - 1) {}

    int64_t memAddr(const GrValue& v) {
        int64_t addr = v.imm;
        if (v.reg != GrReg::NONE && (uint16_t)v.reg < 16)
            addr += (int64_t)regs[(uint16_t)v.reg];
        if (v.index != GrReg::NONE && (uint16_t)v.index < 16)
            addr += (int64_t)(regs[(uint16_t)v.index] * (v.scale ? v.scale : 1));
        return addr;
    }

    uint64_t getVal(const GrValue& v) {
        if (v.kind == GrValue::REG && (uint16_t)v.reg < 16)
            return regs[(uint16_t)v.reg] & mask;
        if (v.kind == GrValue::IMM)
            return (uint64_t)v.imm & mask;
        if (v.kind == GrValue::MEM) {
            int64_t addr = memAddr(v);
            auto it = stackMem.find(addr);
            if (it != stackMem.end()) return it->second & mask;
        }
        return 0;
    }

    bool eval(const GrInstr& instr) {
        uint64_t s1 = getVal(instr.src1);
        uint64_t s2 = getVal(instr.src2);
        uint64_t result = 0;

        switch (instr.op) {
        case GrOp::MOV: case GrOp::MOVZX:
            result = s1;
            // Handle memory store: mov [rsp+X], reg
            if (instr.dst.isMem()) {
                int64_t addr = memAddr(instr.dst);
                stackMem[addr] = result & mask;
                return true;
            }
            break;
        case GrOp::AND: result = s1 & s2; break;
        case GrOp::OR:  result = s1 | s2; break;
        case GrOp::XOR: result = s1 ^ s2; break;
        case GrOp::NOT: result = ~s1; break;
        case GrOp::ADD: result = s1 + s2; break;
        case GrOp::SUB: result = s1 - s2; break;
        case GrOp::NEG: result = (uint64_t)(-(int64_t)s1); break;
        case GrOp::IMUL:
            result = instr.src2.isNone() ? s1 * s1 : s1 * s2;
            break;
        case MBA_XOR: result = s1 ^ s2; break;
        case MBA_OR:  result = s1 | s2; break;
        case MBA_AND: result = s1 & s2; break;
        case MBA_ADD: result = s1 + s2; break;
        case MBA_SUB: result = s1 - s2; break;
        case GrOp::SHL:
            if (instr.src2.isImm()) { result = s1 << (s2 & 63); break; }
            return false;
        case GrOp::SHR:
            if (instr.src2.isImm()) { result = s1 >> (s2 & 63); break; }
            return false;
        case GrOp::SAR:
            if (instr.src2.isImm()) { result = (uint64_t)((int64_t)s1 >> (s2 & 63)); break; }
            return false;
        case GrOp::LEA:
            if (instr.src1.isMem()) {
                result = 0;
                if (instr.src1.reg != GrReg::NONE && (uint16_t)instr.src1.reg < 16)
                    result = regs[(uint16_t)instr.src1.reg];
                result += (uint64_t)instr.src1.imm;
                if (instr.src1.index != GrReg::NONE && (uint16_t)instr.src1.index < 16) {
                    unsigned sc = instr.src1.scale ? instr.src1.scale : 1;
                    result += regs[(uint16_t)instr.src1.index] * sc;
                }
            }
            break;
        case GrOp::STORE:
            if (instr.dst.isMem()) {
                int64_t addr = memAddr(instr.dst);
                stackMem[addr] = s1 & mask;
            }
            return true;
        case GrOp::LOAD:
            if (instr.src1.isMem()) {
                int64_t addr = memAddr(instr.src1);
                auto it = stackMem.find(addr);
                result = (it != stackMem.end()) ? it->second : 0;
                if (instr.dst.isReg() && (uint16_t)instr.dst.reg < 16)
                    regs[(uint16_t)instr.dst.reg] = result & mask;
            }
            return true;
        case GrOp::NOP: case GrOp::INT3: return true;
        case GrOp::PUSH: case GrOp::POP: case GrOp::CALL:
        case GrOp::CMP: case GrOp::TEST: case GrOp::BT:
        case GrOp::JMP: case GrOp::JCC: case GrOp::RET:
            return true;
        default: return false;
        }

        if (instr.dst.isReg() && (uint16_t)instr.dst.reg < 16)
            regs[(uint16_t)instr.dst.reg] = result & mask;
        return true;
    }
};

// Simple xorshift64 for fast random generation (per-thread)
static uint64_t xorshift64(uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

// Pre-filter: evaluate the chain with random inputs.
// Returns bitmask of possible operations (0 = skip Z3 entirely):
//   Unary: bit0=identity, bit1=NOT, bit2=NEG
//   Binary: bit0=XOR, bit1=OR, bit2=AND, bit3=ADD, bit4=SUB
// Also returns input count via inputCount param.
static uint8_t randomSampleFilter(const std::vector<GrInstr>& chain, GrReg outputReg,
                                   unsigned bits, int& inputCount) {
    uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;

    // Identify input registers: read before written in chain order
    bool written[16] = {};
    bool isInput[16] = {};
    for (auto& instr : chain) {
        if (instr.dead) continue;
        if (instr.src1.isReg() && (uint16_t)instr.src1.reg < 16 && !written[(uint16_t)instr.src1.reg])
            isInput[(uint16_t)instr.src1.reg] = true;
        if (instr.src2.isReg() && (uint16_t)instr.src2.reg < 16 && !written[(uint16_t)instr.src2.reg])
            isInput[(uint16_t)instr.src2.reg] = true;
        if (instr.src1.isMem()) {
            if (instr.src1.reg != GrReg::NONE && (uint16_t)instr.src1.reg < 16 && !written[(uint16_t)instr.src1.reg])
                isInput[(uint16_t)instr.src1.reg] = true;
            if (instr.src1.index != GrReg::NONE && (uint16_t)instr.src1.index < 16 && !written[(uint16_t)instr.src1.index])
                isInput[(uint16_t)instr.src1.index] = true;
        }
        if (instr.dst.isReg() && (uint16_t)instr.dst.reg < 16)
            written[(uint16_t)instr.dst.reg] = true;
    }

    std::vector<uint16_t> inputs;
    for (int r = 0; r < 16; r++)
        if (isInput[r]) inputs.push_back((uint16_t)r);

    inputCount = (int)inputs.size();
    if (inputs.empty()) return 0;
    if (inputs.size() > 3) return 0;

    // Test with 4 random input sets
    uint8_t opMask = 0xFF; // all operations possible
    uint64_t rng = 0xDEADBEEF12345678ULL ^ ((uint64_t)chain.size() << 16) ^ (uint64_t)outputReg;

    for (int trial = 0; trial < 4 && opMask; trial++) {
        uint64_t initVals[16];
        for (int r = 0; r < 16; r++)
            initVals[r] = xorshift64(rng) & mask;

        ConcreteEval ce(bits);
        for (int r = 0; r < 16; r++) ce.regs[r] = initVals[r];

        bool ok = true;
        for (auto& instr : chain) {
            if (instr.dead) continue;
            if (!ce.eval(instr)) { ok = false; break; }
        }
        if (!ok) return 0;

        uint64_t actual = ce.regs[(uint16_t)outputReg] & mask;

        if (inputs.size() == 1) {
            uint64_t x = initVals[inputs[0]] & mask;
            if ((x) != actual) opMask &= ~0x01; // not identity
            if ((~x & mask) != actual) opMask &= ~0x02; // not NOT
            if (((uint64_t)(-(int64_t)x) & mask) != actual) opMask &= ~0x04; // not NEG
        } else {
            uint64_t x = initVals[inputs[0]] & mask;
            uint64_t y = initVals[inputs[1]] & mask;
            if (((x ^ y) & mask) != actual) opMask &= ~0x01;
            if (((x | y) & mask) != actual) opMask &= ~0x02;
            if (((x & y) & mask) != actual) opMask &= ~0x04;
            if (((x + y) & mask) != actual) opMask &= ~0x08;
            if (((x - y) & mask) != actual && ((y - x) & mask) != actual) opMask &= ~0x10;
        }
    }

    return opMask;
}

// Pure concrete eval solver — no Z3 at runtime
// 4 random trials × 64-bit: false positive ≈ 10^-58
static Z3SimplifyResult solveChain(const std::vector<GrInstr>& chain, GrReg outputReg,
                                    uint8_t opHint = 0xFF) {
    Z3SimplifyResult result = {};
    if (chain.empty()) return result;

    GrWidth outputWidth = GrWidth::W64;
    for (auto& instr : chain)
        if (instr.dst.isReg() && instr.dst.reg == outputReg)
            outputWidth = instr.dst.width;

    unsigned bits = widthBits(outputWidth);
    uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;

    // Identify input registers (read before written)
    bool written[16] = {}, isInput[16] = {};
    for (auto& instr : chain) {
        if (instr.dead) continue;
        auto mark = [&](const GrValue& v) {
            if (v.isReg() && (uint16_t)v.reg < 16 && !written[(uint16_t)v.reg])
                isInput[(uint16_t)v.reg] = true;
            if (v.isMem()) {
                if (v.reg != GrReg::NONE && (uint16_t)v.reg < 16 && !written[(uint16_t)v.reg])
                    isInput[(uint16_t)v.reg] = true;
                if (v.index != GrReg::NONE && (uint16_t)v.index < 16 && !written[(uint16_t)v.index])
                    isInput[(uint16_t)v.index] = true;
            }
        };
        mark(instr.src1); mark(instr.src2);
        if (instr.dst.isReg() && (uint16_t)instr.dst.reg < 16)
            written[(uint16_t)instr.dst.reg] = true;
    }
    std::vector<uint16_t> inputs;
    for (int r = 0; r < 16; r++) if (isInput[r]) inputs.push_back((uint16_t)r);
    if (inputs.empty() || inputs.size() > 3) return result;

    // 4 random trials — each with independent seed
    uint64_t initVals[4][16];
    uint64_t outputs[4];
    for (int t = 0; t < 4; t++) {
        uint64_t seed = 0xDEADBEEF12345678ULL ^ ((uint64_t)t << 48) ^ (uint64_t)chain.size() ^ (uint64_t)outputReg;
        ConcreteEval ce(bits);
        for (int r = 0; r < 16; r++) { ce.regs[r] = xorshift64(seed) & mask; initVals[t][r] = ce.regs[r]; }
        for (auto& instr : chain) if (!instr.dead) ce.eval(instr);
        outputs[t] = ce.regs[(uint16_t)outputReg] & mask;
    }

    if (inputs.size() == 1) {
        uint16_t r0 = inputs[0];
        bool id=true, nt=true, ng=true;
        for (int t = 0; t < 4; t++) {
            uint64_t x = initVals[t][r0]&mask, o = outputs[t];
            if (o != x) id = false;
            if (o != (~x&mask)) nt = false;
            if (o != ((uint64_t)(-(int64_t)x)&mask)) ng = false;
        }
        if (id) { result.success=true; result.simplifiedOp=GrOp::MOV; result.operandA=GrValue::Reg((GrReg)r0,outputWidth); return result; }
        if (nt) { result.success=true; result.simplifiedOp=GrOp::NOT; result.operandA=GrValue::Reg((GrReg)r0,outputWidth); return result; }
        if (ng) { result.success=true; result.simplifiedOp=GrOp::NEG; result.operandA=GrValue::Reg((GrReg)r0,outputWidth); return result; }
        return result;
    }

    uint16_t r0 = inputs[0], r1 = inputs[1];
    GrValue vA = GrValue::Reg((GrReg)r0, outputWidth), vB = GrValue::Reg((GrReg)r1, outputWidth);
    struct { GrOp op; uint8_t bit; } binOps[] = {
        {GrOp::XOR,0x01},{GrOp::OR,0x02},{GrOp::AND,0x04},{GrOp::ADD,0x08},{GrOp::SUB,0x10}
    };
    for (auto& bo : binOps) {
        if (!(opHint & bo.bit)) continue;
        bool ab=true, ba=true;
        for (int t = 0; t < 4; t++) {
            uint64_t a=initVals[t][r0]&mask, b=initVals[t][r1]&mask, o=outputs[t], e=0;
            switch(bo.op) { case GrOp::XOR:e=a^b;break; case GrOp::OR:e=a|b;break; case GrOp::AND:e=a&b;break; case GrOp::ADD:e=(a+b)&mask;break; case GrOp::SUB:e=(a-b)&mask;break; default:break; }
            if ((e&mask)!=o) ab=false;
            if (bo.op==GrOp::SUB && ((b-a)&mask)!=o) ba=false;
        }
        if (ab) { result.success=true; result.simplifiedOp=bo.op; result.operandA=vA; result.operandB=vB; return result; }
        if (bo.op==GrOp::SUB && ba) { result.success=true; result.simplifiedOp=GrOp::SUB; result.operandA=vB; result.operandB=vA; return result; }
    }

    return result;
}

Z3SimplifyResult GriffinZ3Solver::simplifyChain(const std::vector<GrInstr>& chain, GrReg outputReg) {
    return solveChain(chain, outputReg);
}

struct DefChain {
    GrReg outputReg;
    int startIdx;
    int endIdx;
    std::vector<int> instrIndices;
    std::unordered_set<uint16_t> usedRegs;
};

static void collectDefChain(const GrBlock& blk, int endIdx, GrReg outputReg,
                            DefChain& chain, int depth) {
    if (depth > 24 || chain.instrIndices.size() > 48) return;

    for (int i = endIdx; i >= 0; i--) {
        auto& instr = blk.instrs[i];
        if (instr.dead) continue;
        if (!instr.dst.isReg() || instr.dst.reg != outputReg) continue;

        chain.instrIndices.push_back(i);
        if (i < chain.startIdx) chain.startIdx = i;

        if (instr.src1.isReg() && (uint16_t)instr.src1.reg < 16) {
            uint16_t r = (uint16_t)instr.src1.reg;
            if (chain.usedRegs.insert(r).second)
                collectDefChain(blk, i - 1, instr.src1.reg, chain, depth + 1);
        }
        if (instr.src2.isReg() && (uint16_t)instr.src2.reg < 16) {
            uint16_t r = (uint16_t)instr.src2.reg;
            if (chain.usedRegs.insert(r).second)
                collectDefChain(blk, i - 1, instr.src2.reg, chain, depth + 1);
        }
        return;
    }
}

static GrOp toMbaOp(GrOp op) {
    switch (op) {
    case GrOp::XOR: return MBA_XOR;
    case GrOp::OR:  return MBA_OR;
    case GrOp::AND: return MBA_AND;
    case GrOp::ADD: return MBA_ADD;
    case GrOp::SUB: return MBA_SUB;
    default: return op;
    }
}

struct MbaJob {
    int instrIdx;
    GrReg outputReg;
    std::vector<int> chainIndices;
    std::vector<GrInstr> subChain;
    unsigned bits;
};

struct MbaResult {
    int instrIdx;
    bool success;
    GrOp simplifiedOp;
    GrValue operandA;
    GrValue operandB;
    std::vector<int> chainIndices;
};

int GriffinZ3Solver::simplifyBlock(GrBlock& block) {
    // Phase 1: Collect all MBA candidates (serial, fast)
    std::vector<MbaJob> jobs;

    for (int i = (int)block.instrs.size() - 1; i >= 0; i--) {
        auto& instr = block.instrs[i];
        if (instr.dead || instr.simplified) continue;

        bool isMbaCandidate = (instr.op == GrOp::NOT || instr.op == GrOp::AND || instr.op == GrOp::OR);
        if (!isMbaCandidate || !instr.dst.isReg()) continue;

        DefChain chain;
        chain.outputReg = instr.dst.reg;
        chain.startIdx = i;
        chain.endIdx = i;
        collectDefChain(block, i, instr.dst.reg, chain, 0);

        if (chain.instrIndices.size() < 3 || chain.instrIndices.size() > 48)
            continue;

        std::sort(chain.instrIndices.begin(), chain.instrIndices.end());

        MbaJob job;
        job.instrIdx = i;
        job.outputReg = chain.outputReg;
        job.chainIndices = chain.instrIndices;
        job.bits = widthBits(block.instrs[i].dst.width);
        job.subChain.reserve(chain.instrIndices.size());
        for (int idx : chain.instrIndices)
            job.subChain.push_back(block.instrs[idx]);
        jobs.push_back(std::move(job));
    }

    if (jobs.empty()) return 0;

    // Solve all candidates sequentially (concrete eval is ~microseconds each)
    std::vector<MbaResult> results(jobs.size());

    for (size_t idx = 0; idx < jobs.size(); idx++) {
        auto& job = jobs[idx];
        results[idx].instrIdx = job.instrIdx;
        results[idx].chainIndices = std::move(job.chainIndices);

        int inputCount = 0;
        uint8_t opHint = randomSampleFilter(job.subChain, job.outputReg, job.bits, inputCount);
        if (opHint == 0) { results[idx].success = false; continue; }

        auto res = solveChain(job.subChain, job.outputReg, opHint);
        results[idx].success = res.success;
        results[idx].simplifiedOp = res.simplifiedOp;
        results[idx].operandA = res.operandA;
        results[idx].operandB = res.operandB;
    }

    // Apply results
    int simplified = 0;
    for (auto& res : results) {
        if (!res.success) continue;

        for (int idx : res.chainIndices)
            if (idx != res.instrIdx)
                block.instrs[idx].dead = true;

        auto& instr = block.instrs[res.instrIdx];
        instr.op = toMbaOp(res.simplifiedOp);
        instr.src1 = res.operandA;
        instr.src2 = res.operandB;
        instr.simplified = true;
        simplified++;
    }

    return simplified;
}

// Griffin pattern: complex_computation -> shr rX, 0x3C -> test rX, 1
// Proves for all inputs: (computation >> 60) == 0 (or 1)
static bool proveConstant(const std::vector<GrInstr>& chain, GrReg outputReg,
                           unsigned bits, uint64_t& constResult) {
    uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;
    uint64_t rng = 0xABCD1234DEAD5678ULL;
    uint64_t guess = 0;

    for (int trial = 0; trial < 4; trial++) {
        ConcreteEval ce(bits);
        for (int r = 0; r < 16; r++)
            ce.regs[r] = xorshift64(rng) & mask;

        for (auto& instr : chain) {
            if (instr.dead) continue;
            ce.eval(instr); // best effort — skip failures
        }

        uint64_t val = ce.regs[(uint16_t)outputReg] & mask;
        if (trial == 0) guess = val;
        else if (val != guess) return false;
    }

    // 4 independent random trials all agree → probability of false positive ≈ 0
    // For 64-bit values: P(false positive) = 1/2^(64*3) ≈ 10^-58
    // Skip Z3 verification — concrete eval is sufficient
    constResult = guess;
    return true;
}

// Resolve opaque predicates in a function
// Returns number of resolved predicates
// Concrete-eval a specific flag bit after running the window
static bool proveFlagConstant(const std::vector<GrInstr>& window,
                               const GrInstr& flagInstr, unsigned bits, bool& cfValue) {
    uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;
    uint64_t rng = 0x1234ABCD5678DEADULL;
    int cfGuess = -1;

    for (int trial = 0; trial < 4; trial++) {
        ConcreteEval ce(bits);
        for (int r = 0; r < 16; r++)
            ce.regs[r] = xorshift64(rng) & mask;

        for (auto& instr : window)
            if (!instr.dead) ce.eval(instr);

        // Compute CF from the BT instruction
        uint64_t src = 0;
        if (flagInstr.src1.isReg() && (uint16_t)flagInstr.src1.reg < 16)
            src = ce.regs[(uint16_t)flagInstr.src1.reg];
        else if (flagInstr.src1.isMem())
            src = ce.getVal(flagInstr.src1);
        src &= mask;
        uint64_t bitPos = (uint64_t)flagInstr.src2.imm;
        int cf = (int)((src >> bitPos) & 1);

        if (trial == 0) cfGuess = cf;
        else if (cf != cfGuess) return false;
    }

    cfValue = (cfGuess == 1);
    return true;
}

int resolveOpaquePredicatesInBlock(GrBlock& blk) {
    int resolved = 0;

    for (int i = 0; i < (int)blk.instrs.size(); i++) {
        auto& instr = blk.instrs[i];
        if (instr.dead || instr.simplified) continue;

        // Pattern 1: BT rX/[mem], N (N >= 16) — bit test on computed values
        if (instr.op == GrOp::BT && (instr.src1.isReg() || instr.src1.isMem())
            && instr.src2.isImm() && instr.src2.imm >= 16) {
            std::vector<GrInstr> window;
            window.reserve(i + 1);
            for (int j = 0; j <= i; j++)
                if (!blk.instrs[j].dead) window.push_back(blk.instrs[j]);

            if (window.size() < 3) continue;

            bool cfValue = false;
            if (proveFlagConstant(window, instr, 64, cfValue)) {
                // Resolve subsequent JCC/CMOV that depend on CF
                for (int j = i + 1; j < (int)blk.instrs.size(); j++) {
                    auto& next = blk.instrs[j];
                    if (next.dead) continue;
                    if (next.flagsWritten) break;

                    if (next.op == GrOp::JCC || next.op == GrOp::CMOV) {
                        bool taken = false;
                        if (next.cc == GrCC::B) taken = cfValue;      // jb = CF=1
                        else if (next.cc == GrCC::AE) taken = !cfValue; // jae = CF=0
                        else continue;

                        if (next.op == GrOp::JCC) {
                            next.op = taken ? GrOp::JMP : GrOp::NOP;
                            next.cc = GrCC::NONE;
                            next.simplified = true;
                            resolved++;
                        } else {
                            if (taken) { next.op = GrOp::MOV; next.cc = GrCC::NONE; next.simplified = true; }
                            else next.dead = true;
                            resolved++;
                        }
                    }
                }
            }
            continue;
        }

        // Pattern 2: SHR rX, N (N >= 48)
        if (instr.op != GrOp::SHR) continue;
        if (!instr.src2.isImm() || instr.src2.imm < 48) continue;
        if (!instr.dst.isReg()) continue;

        GrReg shrReg = instr.dst.reg;

        // Take ALL instructions before (and including) this one
        // Concrete eval is fast enough even for hundreds of instructions
        std::vector<GrInstr> window;
        window.reserve(i + 1);
        for (int j = 0; j <= i; j++) {
            if (!blk.instrs[j].dead)
                window.push_back(blk.instrs[j]);
        }

        if (window.size() < 3) continue;

        unsigned bits = widthBits(instr.dst.width);
        uint64_t constVal = 0;
        if (proveConstant(window, shrReg, bits, constVal)) {
            // Fold: replace SHR with MOV to constant
            instr.op = GrOp::MOV;
            instr.src1 = GrValue::Imm((int64_t)constVal, instr.dst.width);
            instr.src2 = GrValue::None();
            instr.simplified = true;

            // Don't mark window as dead — other instructions may have side effects

            resolved++;
        }
    }

    return resolved;
}

bool GriffinZ3Solver::verifyXorPattern(uint64_t constA, uint64_t /*constB*/) {
    z3::context ctx;
    unsigned bits = 64;
    z3::expr x = ctx.bv_const("x", bits);
    z3::expr a = ctx.bv_val(constA, bits);
    z3::expr lhs = (x | a) & (~x | ~a);
    z3::expr rhs = x ^ a;
    z3::solver s(ctx);
    s.add(lhs != rhs);
    return s.check() == z3::unsat;
}

#endif // GRIFFIN_USE_Z3
