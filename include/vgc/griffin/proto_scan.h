#pragma once
#include <pefix/pefix.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace vgc {

struct ProtoField {
    uint32_t fieldNumber = 0;
    std::string name;
    std::string fullName;
    uint32_t stringRVA = 0;
    uint32_t structOffset = 0;
    uint8_t wireType = 0;
    enum Type { UNKNOWN, INT32, INT64, STRING, BYTES, MESSAGE } type = UNKNOWN;
};

struct ProtoMessage {
    std::string fullName;
    uint32_t serializeRVA = 0;
    uint32_t constructorRVA = 0;
    uint32_t defaultInstRVA = 0;
    uint32_t vtableRVA = 0;
    std::vector<ProtoField> fields;

    const ProtoField* fieldByName(const char* name) const;
    const ProtoField* fieldByNumber(uint32_t num) const;
};

struct ProtoScanResult {
    std::vector<ProtoMessage> messages;
    uint32_t totalFields = 0;
    uint32_t resolvedFields = 0;
};

struct FieldSetterHit {
    uint32_t rva;
    uint32_t fieldOffset;
    uint32_t funcRVA;
    uint32_t clusterRVA;
    uint32_t siblingCount;
    bool callsSetterStub;
    float confidence;
};

struct FieldSetterTrace {
    std::vector<FieldSetterHit> hits;
    uint32_t targetOffset;
    uint32_t setterFuncRVA;
};

FieldSetterTrace traceFieldSetters(const pefix::PEFile& pe, uint64_t imageBase,
                                   const ProtoMessage& msg, uint32_t targetFieldOffset,
                                   uint32_t setterFuncRVA);

ProtoMessage scanProtoMessage(const pefix::PEFile& pe, uint64_t imageBase,
                              const char* messageName);

ProtoScanResult scanAllProtoMessages(const pefix::PEFile& pe, uint64_t imageBase);

void parseSerializeOffsets(const pefix::PEFile& pe, uint64_t imageBase,
                           uint32_t serializeRVA, ProtoMessage& msg);

void resolveVtable(const pefix::PEFile& pe, uint64_t imageBase, ProtoMessage& msg);

void parseFromParseFunc(const pefix::PEFile& pe, uint64_t imageBase, ProtoMessage& msg);

// Pattern-based extractor for table-driven protobuf-lite. Locates the message's
// _InternalParse in the vtable, walks the tag-dispatch switch, and merges
// (field number, wire type, struct offset) into msg.fields.
void parseFromInternalParseFunc(const pefix::PEFile& pe, uint64_t imageBase, ProtoMessage& msg);

} // namespace vgc
