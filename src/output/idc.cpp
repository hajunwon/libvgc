#include <vgc/output/idc.h>
#include <vgc/log.h>

namespace vgc {

using pefix::RipRelativeRef;
using pefix::PointerRef;

void generateIdcScript(const char* path,
                       const std::vector<RipRelativeRef>& refs,
                       const std::vector<NullsubPatch>& nullsubs,
                       const std::vector<OpenSSLSymbol>& sslSymbols,
                       const std::vector<RTTIClass>& rttiClasses,
                       const std::vector<ImportWrapper>& importWrappers,
                       const std::vector<PointerRef>& ptrRefs,
                       uint64_t imageBase,
                       uint32_t sizeOfImage) {
    FILE* f = nullptr;
    fopen_s(&f, path, "w");
    if (!f) {
        vgc::log::raw("[!] Failed to create IDC script: %s\n", path);
        return;
    }

    fprintf(f, "// pe_fixer IDC script - auto-generated\n");
    fprintf(f, "// Adds xrefs for RIP-relative instructions + cleans up nullsubs\n");
    fprintf(f, "// Usage: File -> Script file -> select this .idc\n\n");
    fprintf(f, "#include <idc.idc>\n\n");

    fprintf(f, "static main() {\n");
    fprintf(f, "    auto added = 0;\n");
    fprintf(f, "    auto skipped = 0;\n");
    fprintf(f, "    auto cleaned = 0;\n\n");

    // Phase 1: Clean up nullsub functions
    fprintf(f, "    // Phase 1: Clean nullsub functions\n");
    fprintf(f, "    msg(\"[pe_fixer] Cleaning nullsubs...\\n\");\n");

    for (auto& ns : nullsubs) {
        uint64_t addr = imageBase + ns.rva;
        fprintf(f, "    if (get_func_attr(0x%llX, FUNCATTR_START) == 0x%llX) { del_func(0x%llX); cleaned++; }\n",
                addr, addr, addr);
    }
    fprintf(f, "    msg(form(\"[pe_fixer] Cleaned %%d nullsubs\\n\", cleaned));\n\n");

    // Phase 2: Add xrefs for RIP-relative instructions
    fprintf(f, "    // Phase 2: Add cross-references\n");
    fprintf(f, "    msg(\"[pe_fixer] Adding xrefs...\\n\");\n");

    int count = 0;
    for (auto& ref : refs) {
        if (ref.targetRVA >= sizeOfImage) continue;

        uint64_t instrVA = imageBase + ref.instrRVA;
        uint64_t targetVA = ref.targetVA;

        if (ref.isCall) {
            fprintf(f, "    if (is_code(get_full_flags(0x%llX))) { create_qword(0x%llX); add_dref(0x%llX, 0x%llX, dr_R); added++; } else { skipped++; }\n",
                    instrVA, targetVA, instrVA, targetVA);
        } else if (ref.isJmp) {
            fprintf(f, "    if (is_code(get_full_flags(0x%llX))) { create_qword(0x%llX); add_dref(0x%llX, 0x%llX, dr_R); added++; } else { skipped++; }\n",
                    instrVA, targetVA, instrVA, targetVA);
        } else if (ref.isLea) {
            fprintf(f, "    if (is_code(get_full_flags(0x%llX))) { add_dref(0x%llX, 0x%llX, dr_O); added++; } else { skipped++; }\n",
                    instrVA, instrVA, targetVA);
        } else {
            fprintf(f, "    if (is_code(get_full_flags(0x%llX))) { add_dref(0x%llX, 0x%llX, dr_R); added++; } else { skipped++; }\n",
                    instrVA, instrVA, targetVA);
        }
        count++;
    }

    fprintf(f, "    msg(form(\"[pe_fixer] Added %%d xrefs, skipped %%d\\n\", added, skipped));\n\n");

    // Phase 3: OpenSSL symbol recovery
    fprintf(f, "    // Phase 3: OpenSSL symbol recovery\n");
    fprintf(f, "    auto renamed = 0;\n");
    if (!sslSymbols.empty()) {
        fprintf(f, "    msg(\"[pe_fixer] Restoring OpenSSL symbols...\\n\");\n");
        for (auto& sym : sslSymbols) {
            fprintf(f, "    if (set_name(0x%llX, \"%s\", SN_NOWARN)) renamed++;\n",
                    sym.funcVA, sym.name.c_str());
        }
    }
    // Phase 3.5: RTTI vtable + method naming
    if (!rttiClasses.empty()) {
        fprintf(f, "    // RTTI class/vtable naming\n");
        fprintf(f, "    msg(\"[pe_fixer] Applying RTTI class names...\\n\");\n");
        fprintf(f, "    auto rtti_named = 0;\n");
        fprintf(f, "    batch(1);\n");
        for (auto& cls : rttiClasses) {
            std::string vtblName = "vtable_" + cls.demangledName;
            for (auto& c : vtblName) if (c == ':' || c == '<' || c == '>' || c == ' ' || c == ',') c = '_';
            fprintf(f, "    create_qword(0x%llX); set_name(0x%llX, \"%s\", SN_NOWARN);\n",
                    cls.vtableVA, cls.vtableVA, vtblName.c_str());

            for (size_t m = 0; m < cls.methodVAs.size(); m++) {
                std::string methName = cls.demangledName;
                for (auto& c : methName) if (c == ':' || c == '<' || c == '>' || c == ' ' || c == ',') c = '_';
                char buf[256];
                sprintf_s(buf, "%s__vf%zu", methName.c_str(), m);
                fprintf(f, "    if (get_func_attr(0x%llX, FUNCATTR_START) != 0x%llX) add_func(0x%llX);\n",
                        cls.methodVAs[m], cls.methodVAs[m], cls.methodVAs[m]);
                fprintf(f, "    set_name(0x%llX, \"%s\", SN_NOWARN); rtti_named++;\n",
                        cls.methodVAs[m], buf);
            }
        }
        fprintf(f, "    batch(0);\n");
        fprintf(f, "    msg(form(\"[pe_fixer] %%d RTTI methods named\\n\", rtti_named));\n\n");
    }

    // Phase 3.6: Rename .riot1 import wrappers
    if (!importWrappers.empty()) {
        fprintf(f, "    // Import wrapper renaming\n");
        fprintf(f, "    msg(\"[pe_fixer] Renaming import wrappers...\\n\");\n");
        fprintf(f, "    auto wrappers = 0;\n");
        fprintf(f, "    batch(1);\n");
        for (auto& w : importWrappers) {
            fprintf(f, "    if (get_func_attr(0x%llX, FUNCATTR_START) != 0x%llX) add_func(0x%llX);\n",
                    w.wrapperVA, w.wrapperVA, w.wrapperVA);
            if (!w.apiName.empty()) {
                std::string safeName = "imp_" + w.apiName;
                for (auto& c : safeName) if (c == '@' || c == '.') c = '_';
                fprintf(f, "    set_name(0x%llX, \"%s\", SN_NOWARN); wrappers++;\n",
                        w.wrapperVA, safeName.c_str());
            } else {
                fprintf(f, "    set_name(0x%llX, form(\"import_%%X_%%X\", %u, %u), SN_NOWARN); wrappers++;\n",
                        w.wrapperVA, w.constA, w.constB);
            }
        }
        fprintf(f, "    batch(0);\n");
        fprintf(f, "    msg(form(\"[pe_fixer] %%d import wrappers renamed\\n\", wrappers));\n\n");
    }

    // Phase 4: Pointer chain xrefs
    if (!ptrRefs.empty()) {
        fprintf(f, "    // Phase 4: Pointer chain xrefs\n");
        fprintf(f, "    auto ptrs = 0;\n");
        fprintf(f, "    msg(\"[pe_fixer] Adding pointer chain xrefs...\\n\");\n");
        fprintf(f, "    batch(1);\n");
        for (auto& pr : ptrRefs) {
            uint64_t ptrVA = imageBase + pr.ptrRVA;
            uint64_t targetVA = imageBase + pr.targetRVA;
            fprintf(f, "    create_qword(0x%llX); add_dref(0x%llX, 0x%llX, dr_O); ptrs++;\n",
                    ptrVA, ptrVA, targetVA);
        }
        fprintf(f, "    batch(0);\n");
        fprintf(f, "    msg(form(\"[pe_fixer] %%d pointer xrefs added\\n\", ptrs));\n\n");
    }

    // Phase 5+6: FLIRT/TIL
    fprintf(f, "    // FLIRT/TIL: apply manually via IDA GUI (no stable IDC API)\n");
    fprintf(f, "    // View > Open subviews > Signatures: vc64_14, vc64rtf, mscrt64\n");
    fprintf(f, "    // View > Open subviews > Type Libraries: mssdk64_win10, ntapi64\n");
    fprintf(f, "    msg(\"[pe_fixer] Apply FLIRT/TIL manually: View > Open subviews > Signatures / Type Libraries\\n\");\n\n");

    fprintf(f, "    msg(form(\"[pe_fixer] Complete. %%d nullsubs, %%d xrefs, %%d symbols\\n\", cleaned, added, renamed));\n");
    fprintf(f, "}\n");

    fclose(f);
    vgc::log::raw("[+] IDC script written: %s (%d xrefs, %zu nullsubs, %zu pointer chains)\n",
           path, count, nullsubs.size(), ptrRefs.size());
}

void generateIdaScript(const char* path,
                       const std::vector<RipRelativeRef>& refs,
                       uint64_t imageBase,
                       uint32_t sizeOfImage) {
    FILE* f = nullptr;
    fopen_s(&f, path, "w");
    if (!f) {
        vgc::log::raw("[!] Failed to create IDA script: %s\n", path);
        return;
    }

    fprintf(f, "# pe_fixer IDA Python script — auto-generated\n");
    fprintf(f, "# Adds cross-references for RIP-relative instructions found in the dumped PE.\n");
    fprintf(f, "# Usage: File -> Script file... -> select this .py\n");
    fprintf(f, "#\n");
    fprintf(f, "# Image base: 0x%llX, Size of image: 0x%X\n", imageBase, sizeOfImage);
    fprintf(f, "# Total RIP-relative references found: %zu\n", refs.size());
    fprintf(f, "\n");
    fprintf(f, "import idautils\n");
    fprintf(f, "import idaapi\n");
    fprintf(f, "import idc\n");
    fprintf(f, "\n");
    fprintf(f, "IMAGE_BASE = 0x%llX\n", imageBase);
    fprintf(f, "\n");

    fprintf(f, "def add_rip_xrefs():\n");
    fprintf(f, "    added = 0\n");
    fprintf(f, "    skipped = 0\n");
    fprintf(f, "    # Format: (instr_va, target_va, is_call, is_jmp, is_lea)\n");
    fprintf(f, "    refs = [\n");

    int count = 0;
    for (auto& ref : refs) {
        if (ref.targetRVA < sizeOfImage) {
            uint64_t instrVA = imageBase + ref.instrRVA;
            fprintf(f, "        (0x%llX, 0x%llX, %s, %s, %s),\n",
                    instrVA, ref.targetVA,
                    ref.isCall ? "True" : "False",
                    ref.isJmp ? "True" : "False",
                    ref.isLea ? "True" : "False");
            count++;
        }
    }

    fprintf(f, "    ]\n\n");
    fprintf(f, "    for insn_va, target_va, is_call, is_jmp, is_lea in refs:\n");
    fprintf(f, "        # Ensure the target address is mapped\n");
    fprintf(f, "        if not idaapi.is_mapped(target_va):\n");
    fprintf(f, "            skipped += 1\n");
    fprintf(f, "            continue\n");
    fprintf(f, "\n");
    fprintf(f, "        if is_call or is_jmp:\n");
    fprintf(f, "            # Indirect call/jmp through [rip+disp] — the target is a pointer\n");
    fprintf(f, "            idc.del_items(target_va, 0, 8)\n");
    fprintf(f, "            idc.create_qword(target_va)\n");
    fprintf(f, "            idaapi.add_dref(insn_va, target_va, idaapi.dr_R)\n");
    fprintf(f, "            ptr_val = idc.get_qword(target_va)\n");
    fprintf(f, "            if ptr_val and ptr_val != idaapi.BADADDR:\n");
    fprintf(f, "                if is_call:\n");
    fprintf(f, "                    idaapi.add_cref(insn_va, ptr_val, idaapi.fl_CF)\n");
    fprintf(f, "                else:\n");
    fprintf(f, "                    idaapi.add_cref(insn_va, ptr_val, idaapi.fl_JF)\n");
    fprintf(f, "        elif is_lea:\n");
    fprintf(f, "            idaapi.add_dref(insn_va, target_va, idaapi.dr_O)\n");
    fprintf(f, "        else:\n");
    fprintf(f, "            idaapi.add_dref(insn_va, target_va, idaapi.dr_R)\n");
    fprintf(f, "        added += 1\n");
    fprintf(f, "\n");
    fprintf(f, "    print(f\"[pe_fixer] Added {added} xrefs, skipped {skipped} (unmapped targets)\")\n");
    fprintf(f, "    return added\n");
    fprintf(f, "\n");

    fprintf(f, "def force_analyze_code():\n");
    fprintf(f, "    \"\"\"Try to create functions at common code patterns.\"\"\"\n");
    fprintf(f, "    created = 0\n");
    fprintf(f, "    for seg_ea in idautils.Segments():\n");
    fprintf(f, "        seg = idaapi.getseg(seg_ea)\n");
    fprintf(f, "        if not seg or seg.perm & idaapi.SFL_COMDEF:\n");
    fprintf(f, "            continue\n");
    fprintf(f, "        if not (seg.perm & 1):  # Not executable\n");
    fprintf(f, "            continue\n");
    fprintf(f, "        ea = seg.start_ea\n");
    fprintf(f, "        end = seg.end_ea\n");
    fprintf(f, "        while ea < end - 4:\n");
    fprintf(f, "            if not idc.is_unknown(idc.get_full_flags(ea)):\n");
    fprintf(f, "                ea += 1\n");
    fprintf(f, "                continue\n");
    fprintf(f, "            b = idc.get_bytes(ea, 4)\n");
    fprintf(f, "            if b is None:\n");
    fprintf(f, "                ea += 1\n");
    fprintf(f, "                continue\n");
    fprintf(f, "            is_prologue = False\n");
    fprintf(f, "            if b[0] == 0x48 and b[1] == 0x83 and b[2] == 0xEC:\n");
    fprintf(f, "                is_prologue = True  # sub rsp, imm8\n");
    fprintf(f, "            elif b[0] == 0x48 and b[1] == 0x89 and b[2] == 0x5C:\n");
    fprintf(f, "                is_prologue = True  # mov [rsp+xx], rbx\n");
    fprintf(f, "            elif b[0] == 0x40 and b[1] == 0x53:\n");
    fprintf(f, "                is_prologue = True  # push rbx (with REX)\n");
    fprintf(f, "            elif b[0] == 0x40 and b[1] == 0x55:\n");
    fprintf(f, "                is_prologue = True  # push rbp (with REX)\n");
    fprintf(f, "            elif b[0] == 0x40 and b[1] == 0x57:\n");
    fprintf(f, "                is_prologue = True  # push rdi (with REX)\n");
    fprintf(f, "            elif b[0:2] == b'\\xCC\\xCC' and len(b) >= 4:\n");
    fprintf(f, "                pass  # padding, skip\n");
    fprintf(f, "            elif b[0] == 0x48 and b[1] == 0x8B and b[2] == 0xC4:\n");
    fprintf(f, "                is_prologue = True  # mov rax, rsp\n");
    fprintf(f, "\n");
    fprintf(f, "            if is_prologue:\n");
    fprintf(f, "                if idc.add_func(ea):\n");
    fprintf(f, "                    created += 1\n");
    fprintf(f, "                ea += 16  # skip ahead\n");
    fprintf(f, "            else:\n");
    fprintf(f, "                ea += 1\n");
    fprintf(f, "\n");
    fprintf(f, "    print(f\"[pe_fixer] Created {created} new functions from prologue scan\")\n");
    fprintf(f, "    return created\n");
    fprintf(f, "\n");

    // Main
    fprintf(f, "if __name__ == '__main__' or True:\n");
    fprintf(f, "    print('[pe_fixer] Starting xref fixup...')\n");
    fprintf(f, "    n = add_rip_xrefs()\n");
    fprintf(f, "    print('[pe_fixer] Running forced code analysis...')\n");
    fprintf(f, "    m = force_analyze_code()\n");
    fprintf(f, "    print(f'[pe_fixer] Done. {n} xrefs added, {m} functions created.')\n");
    fprintf(f, "    # Trigger auto-analysis\n");
    fprintf(f, "    idaapi.auto_mark_range(0, idaapi.BADADDR, idaapi.AU_USED)\n");
    fprintf(f, "    print('[pe_fixer] Auto-analysis triggered. Wait for IDA to finish processing.')\n");

    fclose(f);
    vgc::log::raw("[+] IDA Python script written: %s (%d references)\n", path, count);
}

} // namespace vgc
