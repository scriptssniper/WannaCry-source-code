// wncry_container.h — WANACRY! container header parser, extension
// classification, and MS CryptoAPI RSA PRIVATEKEYBLOB struct walk.
// All functions are pure memory parsers/printers — NO file IO, NO crypto.
#ifndef WCRY_CONTAINER_H
#define WCRY_CONTAINER_H

#include "wcry_types.h"

// ---------------------------------------------------------------------------
// 1. Container header (FUN_004020a0 DecryptWncryFile, REVIEW.md claim 13)
//    0x000  8B  magic  "WANACRY!"            (u.wnry .rdata @0x4200e4)
//    0x008  u32 rsaLen  == 0x100
//    0x00C  256B RSA-encrypted per-file AES key
//    0x10C  u32 fileType  (3 = .WNCYR tail-recoverable, else AES lane)
//    0x110  u64 original size (little-endian lo/hi)
//    0x118  ..  AES-128-CBC payload, NULL IV
// ---------------------------------------------------------------------------
typedef struct {
    char magic[9];        // NUL-terminated
    u32  rsaLen;          // must be 0x100
    u8   rsaCt[256];      // RSA ciphertext block (opaque reference data here)
    u32  fileType;
    u64  origSize;        // original plaintext size
    u32  payloadOff;      // == 0x118
    u32  payloadLen;      // bytes available in the parsed buffer
} wcry_header_t;

// Parse from a memory buffer. Returns 0 = ok,
//  -1 NULL arg, -2 buffer shorter than the fixed header (0x118),
//  -3 bad magic, -4 rsaLen != 0x100.
int wcry_parse_header(const u8 *buf, u32 bufLen, wcry_header_t *out);

// Human-readable field dump (parse+print only).
void wcry_header_print(const wcry_header_t *h);

// fileType semantics (FUN_004020a0 branch): 3 = tail-swap recovery, no AES;
// any other value takes the full AES-128-CBC decrypt lane.
const char *wcry_filetype_name(u32 fileType);

// ---------------------------------------------------------------------------
// 2. Extension classification (FUN_00402560 DecryptOneFileW +
//    dropper naming; case-insensitive like the original _wcsicmp lanes)
//    .WNCRY  full encrypted container
//    .WNCYR  partial/tail-recoverable (fileType 3)
//    .WNCRYT in-progress temp file
// ---------------------------------------------------------------------------
typedef enum {
    WCRY_EXT_NONE = 0,
    WCRY_EXT_WNCRY,
    WCRY_EXT_WNCYR,
    WCRY_EXT_WNCRYT
} wcry_ext_t;

wcry_ext_t wcry_classify_extension(const char *path);
const char *wcry_ext_name(wcry_ext_t e);
// FUN_00402560 target-name decision: .WNCRY/.WNCYR -> strip the extension;
// anything else (incl. .WNCRYT) -> decrypt to name + ".org" then rename back.
int wcry_ext_strip_on_decrypt(wcry_ext_t e);

// ---------------------------------------------------------------------------
// 3. MS CryptoAPI RSA PRIVATEKEYBLOB struct walk (parse+print only)
//    Layout (wincrypt.h): bType, bVersion, reserved, aiKeyAlg, then
//    RSAPubKey {magic "RSA2", bitlen, pubexp}, then modulus/prime1/prime2/
//    exponent1/exponent2/coefficient/privexp.
//    u.wnry embeds a 2048-bit blob @VA 0x420794, 0x494 B (REVIEW claim 14):
//    07 02 00 00 | 00 A4 00 00 | "RSA2" | 0800 | 010001
//    Reference data only — this module never imports or uses the key.
// ---------------------------------------------------------------------------
typedef struct {
    u8  bType, bVersion;
    u16 reserved;
    u32 aiKeyAlg;
    char magic[5];        // NUL-terminated, expect "RSA2"
    u32 bitLen;
    u32 pubExp;
    u32 modOff, modLen;   // component table (byte offsets into the blob)
    u32 p1Off,  p1Len;
    u32 p2Off,  p2Len;
    u32 e1Off,  e1Len;
    u32 e2Off,  e2Len;
    u32 cOff,   cLen;
    u32 dOff,   dLen;
    u32 totalExpected;    // structural size implied by bitLen
} wcry_rsablob_t;

// Walk + optionally print the fields. Returns 0 = structurally valid
// PRIVATEKEYBLOB (type/version/alg/magic/size all expected), 1 = parsed but
// unexpected field values, negative = malformed/short buffer.
int wcry_walk_rsa_privatekeyblob(const u8 *blob, u32 len,
                                 wcry_rsablob_t *out, int verbose);

#endif // WCRY_CONTAINER_H
