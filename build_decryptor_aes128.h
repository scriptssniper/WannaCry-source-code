// aes128.h — standard AES-128 core (FIPS-197) + CBC (NIST SP800-38A).
// Reconstructs the CRijndael lane used by u.wnry (FUN_0040a150 MakeKey /
// FUN_0040a9d0 DecryptBlock / FUN_0040b3c0 CBC, function_map.md S4).
// WannaCry always uses keyLen=16, blockLen=16, 10 rounds, CBC with a
// NULL (16 zero byte) IV — the original passes the static zero page at
// VA 0x4218b0 as the `chain` argument (REVIEW.md claim 13).
// Pure software, portable: no OS headers, no external crypto dependency.
#ifndef WCRY_AES128_H
#define WCRY_AES128_H

#include "wcry_types.h"

// Expand a 128-bit key into the 44-word round-key schedule (ENC and DEC use
// the same schedule; the decrypt cipher walks it in reverse, FIPS-197 A.3).
// Returns 0 on success, -1 on NULL args.
int  aes128_expand_key(u32 rk[44], const u8 key[16]);

// Single-block primitives (in/out may alias).
void aes128_encrypt_block(const u32 rk[44], const u8 in[16], u8 out[16]);
void aes128_decrypt_block(const u32 rk[44], const u8 in[16], u8 out[16]);

// CBC in place. len MUST be a multiple of 16 (the original throws otherwise,
// 0x0040b3ea). iv==NULL selects the WannaCry NULL-IV convention (zero chain,
// matching the 512-byte zero page the binary passes at 0x0040235e).
// Returns 0 on success, -1 on length/NULL error.
int aes128_cbc_encrypt(const u8 key[16], const u8 iv[16], u8 *buf, u32 len);
int aes128_cbc_decrypt(const u8 key[16], const u8 iv[16], u8 *buf, u32 len);

#endif // WCRY_AES128_H
