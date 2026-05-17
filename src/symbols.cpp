#include <vgc/symbols.h>
#include <vgc/log.h>
#include <vgc/xrefs.h>
#include <set>
#include <unordered_map>

namespace vgc {

using pefix::PEFile;
using pefix::RipRelativeRef;
using pefix::scanRipRelativeRefs;

std::vector<OpenSSLSymbol> recoverOpenSSLSymbols(
    const PEFile& pe, uint64_t imageBase) {

    std::vector<RipRelativeRef> refs = scanRipRelativeRefs(pe, imageBase);

    std::vector<OpenSSLSymbol> symbols;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    struct StrRef { uint32_t strRVA; std::string value; };
    std::vector<StrRef> funcNameStrings;

    for (WORD i = 0; i < pe.numSections; i++) {
        char sn[9] = {}; memcpy(sn, pe.sections[i].Name, 8);
        if (strcmp(sn, ".rdata") != 0 && strcmp(sn, ".data") != 0) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) continue;

        const char* base = (const char*)(pe.data.data() + rawOff);
        for (uint32_t pos = 0; pos + 4 < rawSz; pos++) {
            if (base[pos] == 0) continue;

            if (strncmp(base + pos, "crypto\\", 7) == 0 || strncmp(base + pos, "ssl\\", 4) == 0 ||
                strncmp(base + pos, "cryptopp", 8) == 0 || strncmp(base + pos, "cryptlib", 8) == 0 ||
                strncmp(base + pos, "google\\protobuf", 15) == 0 || strncmp(base + pos, "protobuf\\", 9) == 0 ||
                strncmp(base + pos, "src\\google", 10) == 0) {
                size_t len = strnlen(base + pos, rawSz - pos);
                if (len > 4 && len < 100) {
                    std::string s(base + pos, len);
                    if (s.find(".c") != std::string::npos || s.find(".h") != std::string::npos) {}
                }
                pos += (uint32_t)strnlen(base + pos, rawSz - pos);
                continue;
            }

            const char* prefixes[] = {
                "EVP_", "SSL_", "CRYPTO_", "BIO_", "RSA_", "EC_",
                "AES_", "SHA", "HMAC_", "RAND_", "X509_", "PEM_",
                "PKCS", "DH_", "DSA_", "ECDSA_", "ECDH_", "ENGINE_",
                "ERR_", "OBJ_", "ASN1_", "BN_", "CONF_", "SHAKE",
                "OSSL_", "OPENSSL_", "CMS_", "TS_", "OCSP_",
                "Riot", "riot_", "vgc_", "VGC_", "Vanguard",
                "Rtl", "Nt", "Zw",
                "std::", "boost::",
            };
            bool match = false;
            for (auto* pfx : prefixes) {
                if (strncmp(base + pos, pfx, strlen(pfx)) == 0) { match = true; break; }
            }
            if (match) {
                size_t len = strnlen(base + pos, rawSz - pos);
                if (len >= 4 && len < 80) {
                    std::string s(base + pos, len);
                    bool validName = true;
                    for (char c : s) {
                        if (!isalnum(c) && c != '_') { validName = false; break; }
                    }
                    if (validName)
                        funcNameStrings.push_back({va + pos, s});
                }
                pos += (uint32_t)len;
            }
        }
    }

    vgc::log::raw("    Found %zu function name strings\n", funcNameStrings.size());

    std::unordered_map<uint32_t, std::vector<const RipRelativeRef*>> targetToRefs;
    for (auto& ref : refs) {
        if (ref.targetRVA < sizeOfImage && ref.isLea)
            targetToRefs[ref.targetRVA].push_back(&ref);
    }

    for (auto& fns : funcNameStrings) {
        auto it = targetToRefs.find(fns.strRVA);
        if (it == targetToRefs.end()) continue;

        for (auto* ref : it->second) {
            uint32_t instrOff = pe.rvaToOffset(ref->instrRVA);
            if (!instrOff && ref->instrRVA < pe.data.size()) instrOff = ref->instrRVA;
            if (!instrOff) continue;

            uint32_t funcStart = 0;
            for (uint32_t back = 0; back < 0x4000 && instrOff > back + 4; back++) {
                uint32_t checkOff = instrOff - back;
                if (checkOff + 2 >= pe.data.size()) continue;
                uint8_t b0 = pe.data[checkOff];
                uint8_t b1 = pe.data[checkOff + 1];
                uint8_t b2 = pe.data[checkOff + 2];

                bool isPrologue = false;
                if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) isPrologue = true;
                if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) isPrologue = true;
                if (b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0x4C || b2 == 0x54)) isPrologue = true;
                if (b0 == 0x40 && b1 >= 0x50 && b1 <= 0x57) isPrologue = true;
                if (b0 == 0x48 && b1 == 0x8B && b2 == 0xC4) isPrologue = true;
                if (b0 == 0x55 && b1 == 0x48 && b2 == 0x8B) isPrologue = true;
                if (b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57) {
                    if (b1 == 0x48 || b1 == 0x41) isPrologue = true;
                }
                if (b0 == 0x41 && (b1 == 0x54 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) isPrologue = true;
                if (b0 == 0x44 && b1 == 0x88 && b2 == 0x44) isPrologue = true;
                if (b0 == 0x4C && b1 == 0x89 && b2 == 0x44) isPrologue = true;
                if (b0 == 0x89 && b1 == 0x54 && b2 == 0x24) isPrologue = true;
                if (b0 == 0x44 && b1 == 0x89 && b2 == 0x44) isPrologue = true;

                if (isPrologue) {
                    if (checkOff > 0) {
                        uint8_t prev = pe.data[checkOff - 1];
                        if (prev == 0xCC || prev == 0xC3 || prev == 0x90 || prev == 0x00 ||
                            prev == 0xCB || prev == 0xC2) {
                            funcStart = checkOff;
                            break;
                        }
                    } else {
                        funcStart = checkOff;
                        break;
                    }
                }
            }

            if (funcStart) {
                uint32_t funcRVA = 0;
                for (WORD s = 0; s < pe.numSections; s++) {
                    uint32_t sRaw = pe.sections[s].PointerToRawData;
                    uint32_t sSz = pe.sections[s].SizeOfRawData;
                    if (funcStart >= sRaw && funcStart < sRaw + sSz) {
                        funcRVA = pe.sections[s].VirtualAddress + (funcStart - sRaw);
                        break;
                    }
                }
                if (!funcRVA && funcStart < pe.nt->OptionalHeader.SizeOfImage)
                    funcRVA = funcStart;

                if (funcRVA) {
                    OpenSSLSymbol sym;
                    sym.funcVA = imageBase + funcRVA;
                    sym.name = fns.value;
                    symbols.push_back(sym);
                }
            }
        }
    }

    std::set<uint64_t> seen;
    std::vector<OpenSSLSymbol> unique;
    for (auto& s : symbols) {
        if (seen.insert(s.funcVA).second)
            unique.push_back(s);
    }

    return unique;
}

std::vector<KeyStringRef> findKeyStringRefs(
    const PEFile& pe, const std::vector<RipRelativeRef>& refs, uint64_t imageBase) {

    std::vector<KeyStringRef> result;

    struct KeyPattern {
        const char* pattern;
        const char* category;
    };
    KeyPattern patterns[] = {
        {"ac.pvp.net", "network"},
        {"vanguard/v1/gateway", "network"},
        {"application/x-protobuf", "network"},
        {"X-VG-", "network"},
        {"com.riotgames", "protobuf"},
        {"\\\\.\\vgk", "ioctl"},
        {"gobbledygook", "ioctl"},
        {"DeviceIoControl", "ioctl"},
        {"NtDeviceIoControlFile", "ioctl"},
        {"933823D3", "pipe"},
        {"CreateNamedPipe", "pipe"},
        {"EVP_Encrypt", "crypto"},
        {"EVP_Decrypt", "crypto"},
        {"SSL_write", "crypto"},
        {"SSL_read", "crypto"},
        {"SSL_connect", "crypto"},
        {"RSA_", "crypto"},
        {"machine_id", "auth"},
        {"ephemeral", "auth"},
        {"game_token", "auth"},
    };

    for (WORD si = 0; si < pe.numSections; si++) {
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t va = pe.sections[si].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) continue;
        const char* data = (const char*)(pe.data.data() + rawOff);

        for (uint32_t pos = 0; pos + 4 < rawSz; pos++) {
            if (data[pos] == 0) continue;
            for (auto& kp : patterns) {
                size_t plen = strlen(kp.pattern);
                if (pos + plen <= rawSz && strncmp(data + pos, kp.pattern, plen) == 0) {
                    uint32_t strRVA = va + pos;
                    for (auto& ref : refs) {
                        if (ref.targetRVA == strRVA && ref.isLea) {
                            KeyStringRef ks;
                            ks.instrVA = imageBase + ref.instrRVA;
                            ks.value = std::string(data + pos, strnlen(data + pos, rawSz - pos));
                            if (ks.value.length() > 80) ks.value = ks.value.substr(0, 80);
                            ks.category = kp.category;
                            result.push_back(ks);
                        }
                    }
                }
            }
        }
    }
    return result;
}

} // namespace vgc
