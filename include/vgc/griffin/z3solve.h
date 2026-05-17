#pragma once

#ifdef GRIFFIN_USE_Z3

#include <pefix/x86_64/ir.h>
#include <string>
#include <vector>

struct Z3SimplifyResult {
    bool success;
    pefix::Op simplifiedOp;
    pefix::Value operandA;
    pefix::Value operandB;
    std::string description;
};

class GriffinZ3Solver {
public:
    GriffinZ3Solver();
    ~GriffinZ3Solver();

    Z3SimplifyResult simplifyChain(const std::vector<pefix::Instr>& chain, pefix::Reg outputReg);

    int simplifyBlock(pefix::Block& block);

    bool verifyXorPattern(uint64_t constA, uint64_t constB);

private:
    void* ctx_;
};

int resolveOpaquePredicatesInBlock(pefix::Block& blk);

#endif // GRIFFIN_USE_Z3
