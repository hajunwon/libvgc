#ifdef GRIFFIN_USE_Z3

#include <vgc/griffin/z3solve.h>
#include <pefix/x86_64/ir.h>
#include <cstdio>
#include <vector>

using GrOp = pefix::Op;
using GrReg = pefix::Reg;
using GrWidth = pefix::Width;
using GrValue = pefix::Value;
using GrInstr = pefix::Instr;
inline const char* grOpName(GrOp op) { return pefix::opName(op); }

// Test: Verify (X|A) & (~X|~A) = X XOR A via Z3
static void testXorIdentity() {
    printf("[Test 1] Verify XOR MBA identity...\n");
    GriffinZ3Solver solver;
    bool ok = solver.verifyXorPattern(0xDEADBEEF, 0);
    printf("  (X|0xDEADBEEF) & (~X|~0xDEADBEEF) == X XOR 0xDEADBEEF : %s\n", ok ? "PASS" : "FAIL");

    ok = solver.verifyXorPattern(0x12345678ABCDEF00ULL, 0);
    printf("  (X|C) & (~X|~C) for 64-bit constant : %s\n", ok ? "PASS" : "FAIL");
}

// Test: Simplify a NOT(NOT(A) AND NOT(B)) chain ??A OR B
static void testOrChain() {
    printf("[Test 2] Simplify NOT(NOT(A) AND NOT(B)) ??OR...\n");

    // Simulate:
    //   t0 = NOT rcx        ; ~A
    //   t1 = NOT rdx        ; ~B
    //   t2 = AND t0, t1     ; ~A & ~B
    //   rax = NOT t2         ; ~(~A & ~B) = A | B
    std::vector<GrInstr> chain;
    {
        GrInstr i = {};
        i.op = GrOp::NOT;
        i.dst = GrValue::Reg(GrReg::R8, GrWidth::W64);
        i.src1 = GrValue::Reg(GrReg::RCX, GrWidth::W64);
        chain.push_back(i);
    }
    {
        GrInstr i = {};
        i.op = GrOp::NOT;
        i.dst = GrValue::Reg(GrReg::R9, GrWidth::W64);
        i.src1 = GrValue::Reg(GrReg::RDX, GrWidth::W64);
        chain.push_back(i);
    }
    {
        GrInstr i = {};
        i.op = GrOp::AND;
        i.dst = GrValue::Reg(GrReg::R10, GrWidth::W64);
        i.src1 = GrValue::Reg(GrReg::R8, GrWidth::W64);
        i.src2 = GrValue::Reg(GrReg::R9, GrWidth::W64);
        chain.push_back(i);
    }
    {
        GrInstr i = {};
        i.op = GrOp::NOT;
        i.dst = GrValue::Reg(GrReg::RAX, GrWidth::W64);
        i.src1 = GrValue::Reg(GrReg::R10, GrWidth::W64);
        chain.push_back(i);
    }

    GriffinZ3Solver solver;
    auto result = solver.simplifyChain(chain, GrReg::RAX);
    if (result.success)
        printf("  Simplified to: %s ??%s\n", grOpName(result.simplifiedOp), result.description.c_str());
    else
        printf("  FAIL: could not simplify\n");
}

// Test: XOR MBA ??NOT(NOT(A AND NOT(B)) AND NOT(NOT(A) AND B))
static void testXorMba() {
    printf("[Test 3] Simplify Griffin XOR MBA...\n");
    // Real Griffin pattern:
    //   r8  = NOT rdx       ; ~B
    //   r9  = AND rcx, r8   ; A & ~B
    //   r10 = NOT rcx       ; ~A
    //   r11 = AND r10, rdx  ; ~A & B
    //   r12 = NOT r9        ; ~(A & ~B)
    //   r13 = NOT r11       ; ~(~A & B)
    //   r14 = AND r12, r13  ; ~(A & ~B) & ~(~A & B)
    //   rax = NOT r14       ; ~(~(A&~B) & ~(~A&B)) = (A&~B) | (~A&B) = A XOR B
    std::vector<GrInstr> chain;
    auto mk = [&](GrOp op, GrReg dst, GrReg s1, GrReg s2 = GrReg::NONE) {
        GrInstr i = {};
        i.op = op;
        i.dst = GrValue::Reg(dst, GrWidth::W64);
        i.src1 = GrValue::Reg(s1, GrWidth::W64);
        if (s2 != GrReg::NONE)
            i.src2 = GrValue::Reg(s2, GrWidth::W64);
        chain.push_back(i);
    };

    mk(GrOp::NOT, GrReg::R8,  GrReg::RDX);
    mk(GrOp::AND, GrReg::R9,  GrReg::RCX, GrReg::R8);
    mk(GrOp::NOT, GrReg::R10, GrReg::RCX);
    mk(GrOp::AND, GrReg::R11, GrReg::R10, GrReg::RDX);
    mk(GrOp::NOT, GrReg::R12, GrReg::R9);
    mk(GrOp::NOT, GrReg::R13, GrReg::R11);
    mk(GrOp::AND, GrReg::R14, GrReg::R12, GrReg::R13);
    mk(GrOp::NOT, GrReg::RAX, GrReg::R14);

    GriffinZ3Solver solver;
    auto result = solver.simplifyChain(chain, GrReg::RAX);
    if (result.success)
        printf("  Simplified to: %s ??%s\n", grOpName(result.simplifiedOp), result.description.c_str());
    else
        printf("  FAIL: could not simplify\n");
}

// Test: dispatch key computation ??IMUL + ADD with constants
static void testDispatchKey() {
    printf("[Test 4] Dispatch key MBA (IMUL + ADD + XOR with constants)...\n");
    // edi = dispatch key
    // r8d = imul edi, 0x7A3B1F
    // r9d = add r8d, 0x1234
    // eax = xor r9d, 0xABCD
    std::vector<GrInstr> chain;
    {
        GrInstr i = {};
        i.op = GrOp::IMUL;
        i.dst = GrValue::Reg(GrReg::R8, GrWidth::W32);
        i.src1 = GrValue::Reg(GrReg::RDI, GrWidth::W32);
        i.src2 = GrValue::Imm(0x7A3B1F, GrWidth::W32);
        chain.push_back(i);
    }
    {
        GrInstr i = {};
        i.op = GrOp::ADD;
        i.dst = GrValue::Reg(GrReg::R9, GrWidth::W32);
        i.src1 = GrValue::Reg(GrReg::R8, GrWidth::W32);
        i.src2 = GrValue::Imm(0x1234, GrWidth::W32);
        chain.push_back(i);
    }
    {
        GrInstr i = {};
        i.op = GrOp::XOR;
        i.dst = GrValue::Reg(GrReg::RAX, GrWidth::W32);
        i.src1 = GrValue::Reg(GrReg::R9, GrWidth::W32);
        i.src2 = GrValue::Imm(0xABCD, GrWidth::W32);
        chain.push_back(i);
    }

    GriffinZ3Solver solver;
    auto result = solver.simplifyChain(chain, GrReg::RAX);
    if (result.success)
        printf("  Simplified to: %s ??%s\n", grOpName(result.simplifiedOp), result.description.c_str());
    else
        printf("  Not a simple binary op (expected for mixed constant+var expression)\n");
}

int main() {
    printf("=== Z3 MBA Solver Test ===\n\n");
    testXorIdentity();
    printf("\n");
    testOrChain();
    printf("\n");
    testXorMba();
    printf("\n");
    testDispatchKey();
    printf("\n=== Done ===\n");
    return 0;
}

#else
#include <cstdio>
int main() { printf("Z3 not enabled. Build with GRIFFIN_USE_Z3.\n"); return 1; }
#endif
