#pragma once

// libvgc -- VGC-specific binary analysis
// Depends on libpefix (PE/x86) and libgriffin (Griffin deobfuscation)

#include <pefix/pefix.h>
#include <griffin/griffin.h>
#include <pefix/x86_64/ir.h>

// VGC-specific headers
#include <vgc/sections.h>
#include <vgc/antidisasm.h>
#include <vgc/thunks.h>
#include <vgc/imports.h>
#include <vgc/symbols.h>
#include <vgc/funcfix.h>
#include <vgc/srcmap.h>
#include <vgc/pdb.h>
#include <vgc/output/idc.h>
#include <vgc/griffin/proto_scan.h>
#include <vgc/griffin/z3solve.h>
#ifdef USE_UNICORN
#include <vgc/griffin/ucemu.h>
#endif
