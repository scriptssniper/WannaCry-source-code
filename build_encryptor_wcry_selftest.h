// ===========================================================================
// wcry_selftest.h — benign self-test suite for the wcry_payload.dll
// reconstruction core. Shared verbatim by the Windows EXE/DLL builds and the
// Linux-native harness (selftest.cc). Pure computation only: NO file writes,
// NO processes, NO handles, NO network. Expected vectors:
//   * FIPS-197 C.1 block vector
//   * NIST SP 800-38A F.1.1 (ECB) + F.2.1 (CBC) 4-block vectors —
//     independently confirmed against the validated reference cipher in
//     ../../reconstruction/shared/crypto_test/crypto_test.py (15/15 PASS)
//   * WannaCry-key round keys from CRYPTO_TEST.md T4
// ===========================================================================
#ifndef WCRY_SELFTEST_H
#define WCRY_SELFTEST_H

#include <cstdio>
#include <cstring>

#include "wcry_core.h"

static int wcry_st_pass = 0;
static int wcry_st_fail = 0;

inline void wcry_st_check(const char *name, int ok, const char *detail = "")
{
    std::printf("[%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail[0] ? " — " : "", detail);
    if (ok) wcry_st_pass++; else wcry_st_fail++;
}

inline void wcry_st_hex(const uint8_t *buf, size_t n, char *out, size_t cap)
{
    size_t j = 0;
    for (size_t i = 0; i < n && j + 2 < cap; i++) {
        static const char H[] = "0123456789abcdef";
        out[j++] = H[(buf[i] >> 4) & 0xF];
        out[j++] = H[buf[i] & 0xF];
    }
    out[j] = '\0';
}

// Serialize round-key words big-endian (the schedule words are BE-convention).
inline void wcry_st_hex_words(const uint32_t *w, size_t nwords, char *out, size_t cap)
{
    uint8_t tmp[64];
    for (size_t i = 0; i < nwords && i < 16; i++) {
        tmp[4 * i]     = (uint8_t)(w[i] >> 24);
        tmp[4 * i + 1] = (uint8_t)(w[i] >> 16);
        tmp[4 * i + 2] = (uint8_t)(w[i] >> 8);
        tmp[4 * i + 3] = (uint8_t)w[i];
    }
    wcry_st_hex(tmp, nwords * 4, out, cap);
}

inline void wcry_st_unhex(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[2 * i + k];
            v <<= 4;
            v |= (unsigned)((c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
}

// ---------------------------------------------------------------------------
inline int wcry_run_selftest(void)
{
    char hex[800];

    // T1 — SBOX table == FIPS-197 (extracted @0x10007A3C, CRYPTO_TEST T1)
    uint8_t ref_sbox[256];
    wcry_st_unhex(
        "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16",
        ref_sbox, 256);
    wcry_st_check("T1 SBOX == FIPS-197 (extracted @0x10007A3C)",
                  memcmp(WCRY_SBOX256, ref_sbox, 256) == 0);

    // T2 — RCON (extracted @0x1000AC3C): first 10 = AES-128 constants
    static const uint8_t rcon10[10] = {1,2,4,8,0x10,0x20,0x40,0x80,0x1b,0x36};
    wcry_st_check("T2 RCON[:10] == standard AES-128 constants",
                  memcmp(WCRY_RCON30, rcon10, 10) == 0);

    // T3 — generated T-tables == extracted standard tables
    {
        const WcryTeTables *t = wcry_aes_te();
        int ok = t->te0[0] == 0xC66363A5u && t->te1[0] == 0xA5C66363u &&
                 t->te2[0] == 0x63A5C663u && t->te3[0] == 0x6363A5C6u;
        for (int x = 0; x < 256 && ok; x++)
            ok = (t->te1[x] == ((t->te0[x] >> 8) | (t->te0[x] << 24))) &&
                 (t->te2[x] == ((t->te1[x] >> 8) | (t->te1[x] << 24))) &&
                 (t->te3[x] == ((t->te2[x] >> 8) | (t->te2[x] << 24)));
        wcry_st_check("T3 Te0..Te3 == extracted tables (Te0[0]=0xC66363A5, rotations)",
                      ok);
    }

    // T4 — WannaCry-key key schedule (CRYPTO_TEST T4: RK1/RK10)
    {
        uint8_t key[16];
        wcry_st_unhex("bee19b98d2e5b12211ce211eecb13de6", key, 16);
        WcryAesCtx c;
        wcry_aes_set_key(&c, key, 16, NULL, 16);
        wcry_st_hex_words(&c.enc[4], 4, hex, sizeof(hex));
        wcry_st_check("T4 WannaCry-key RK1 == 77c61556a523a474b4ed856a585cb88c",
                      strcmp(hex, "77c61556a523a474b4ed856a585cb88c") == 0, hex);
        wcry_st_hex_words(&c.enc[40], 4, hex, sizeof(hex));
        wcry_st_check("T4 WannaCry-key RK10 == 9f1c1a8333a83857f2748614f7d26bd9",
                      strcmp(hex, "9f1c1a8333a83857f2748614f7d26bd9") == 0, hex);
    }

    // T5 — FIPS-197 C.1 block vector through our tables
    {
        uint8_t key[16], pt[16], ct[16];
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
        wcry_st_unhex("00112233445566778899aabbccddeeff", pt, 16);
        WcryAesCtx c;
        wcry_aes_set_key(&c, key, 16, NULL, 16);
        wcry_aes_encrypt_block(&c, pt, ct);
        wcry_st_hex(ct, 16, hex, sizeof(hex));
        wcry_st_check("T5 FIPS-197 C.1 vector == 69c4e0d86a7b0430d8cdb78070b4c55a",
                      strcmp(hex, "69c4e0d86a7b0430d8cdb78070b4c55a") == 0, hex);
    }

    // T6 — SP 800-38A F.1.1 ECB, 4 blocks (mode 0)
    {
        uint8_t key[16], pt[64], ct[64];
        wcry_st_unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        wcry_st_unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac"
                      "45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17"
                      "ad2b417be66c3710", pt, 64);
        WcryAesCtx c;
        wcry_aes_set_key(&c, key, 16, NULL, 16);
        wcry_aes_crypt_modes(&c, pt, ct, 64, 0);
        wcry_st_hex(ct, 64, hex, sizeof(hex));
        wcry_st_check("T6 SP800-38A F.1.1 ECB (mode 0)",
                      strcmp(hex, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699d"
                                  "e785895a96fdbaaf43b1cd7f598ece23881b00e3ed030688"
                                  "7b0c785e27e8ad3f8223207104725dd4") == 0, hex);
    }

    // T7 — SP 800-38A F.2.1 CBC, 4 blocks (mode 1)
    {
        uint8_t key[16], iv[16], pt[64], ct[64];
        wcry_st_unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        for (int i = 0; i < 16; i++) iv[i] = (uint8_t)i;
        wcry_st_unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac"
                      "45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17"
                      "ad2b417be66c3710", pt, 64);
        WcryAesCtx c;
        wcry_aes_set_key(&c, key, 16, iv, 16);
        wcry_aes_crypt_modes(&c, pt, ct, 64, 1);
        wcry_st_hex(ct, 64, hex, sizeof(hex));
        wcry_st_check("T7 SP800-38A F.2.1 CBC (mode 1)",
                      strcmp(hex, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee"
                                  "95db113a917678b273bed6b8e3c1743b7116e69e22229516"
                                  "3ff1caa1681fac09120eca307586e1a7") == 0, hex);
    }

    // T8 — CFB-style mode 2 wiring: out = E(chain) ^ in, chain = out (no
    // caller in the binary; formula cross-check vs the block primitive)
    {
        uint8_t key[16], iv[16], pt[32], ref[32], ct[32];
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0xA0 + i);
        for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(0x10 * i);
        for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(i * 7 + 3);
        WcryAesCtx c;
        wcry_aes_set_key(&c, key, 16, iv, 16);
        uint8_t chain[16], e[16];
        memcpy(chain, iv, 16);
        for (int b = 0; b < 32; b += 16) {
            wcry_aes_encrypt_block(&c, chain, e);
            for (int i = 0; i < 16; i++) ref[b + i] = (uint8_t)(e[i] ^ pt[b + i]);
            memcpy(chain, &ref[b], 16);
        }
        wcry_aes_crypt_modes(&c, pt, ct, 32, 2);
        wcry_st_check("T8 CFB-style mode 2 formula (out=E(chain)^in; chain=out)",
                      memcmp(ref, ct, 32) == 0);
    }

    // T9 — container header round-trip on a synthetic buffer (no real files)
    {
        uint8_t buf[WCRY_HEADER_FIXED_SIZE + 16], ct[256];
        WcryHeader h;
        for (int i = 0; i < 256; i++) ct[i] = (uint8_t)(i ^ 0x5A);
        int n = wcry_header_build(buf, sizeof(buf), ct, 0x100, 4, 0x10000);
        int ok = (n == WCRY_HEADER_FIXED_SIZE);
        ok = ok && wcry_header_parse_full(buf, (size_t)n, &h) == 0 &&
             h.rsaLen == 0x100 && h.fileType == 4 && h.payloadSize == 0x10000 &&
             memcmp(buf + 0x0C, ct, 256) == 0;
        wcry_st_check("T9 header build→parse round-trip (rsaLen/type/size/ct)",
                      ok);

        uint32_t rl = 0;
        int ok2 = wcry_header_parse_base(buf + 1, 64, &rl) != 0;   // bad magic
        uint8_t s0 = buf[8], s1 = buf[9];
        buf[8] = 0x01; buf[9] = 0x02;   // rsaLen = 0x201 → reader gate rejects
        ok2 = ok2 && wcry_header_parse_base(buf, 12, &rl) != 0;
        buf[8] = s0; buf[9] = s1;
        ok2 = ok2 && wcry_header_parse_base(buf, 8, &rl) != 0;     // too short
        ok2 = ok2 && wcry_header_parse_base(buf, 12, &rl) == 0 && rl == 0x100;
        wcry_st_check("T9 base parse rejects bad magic / rsaLen>=0x201 / short", ok2);
    }

    // T10 — extension-class matrix [10002D60]
    {
        struct EC { const wchar_t *path; int cls; };
        static const EC cases[] = {
            {L"a.doc", 2}, {L"a.docx", 2}, {L"a.pst", 2}, {L"a.TXT", 2},
            {L"b.docb", 3}, {L"b.cpp", 3}, {L"b.7z", 3}, {L"b.PFX", 3},
            {L"c.exe", 1}, {L"c.dll", 1},
            {L"d.WNCRY", 6}, {L"d.wncry", 6},
            {L"e.WNCRYT", 4}, {L"f.WNCYR", 5},
            {L"g.unknown", 0}, {L"noext", 0},
        };
        int ok = 1, bad = -1;
        for (int i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
            int got = wcry_get_file_ext_class(cases[i].path);
            if (got != cases[i].cls) { ok = 0; bad = i; break; }
        }
        wcry_st_check("T10 ext-class matrix (16 cases)", ok,
                      ok ? "doc/docx/pst/txt→2 docb/cpp/7z/pfx→3 exe/dll→1 WNCRY→6 WNCRYT→4 WNCYR→5 other→0"
                         : "mismatch");
        (void)bad;
    }

    // T11 — file-action matrix [10002E70]
    {
        struct DA { int cls; uint32_t size; int stop; unsigned stage; int act; };
        static const DA cases[] = {
            {0, 0x4000u,    0, 1, 1},   // unclassified → 1
            {2, 0x4000u,    0, 1, 4},   // normal size → 4
            {2, 0x400u,     0, 1, 3},   // <0x401 → tooBig (decompile 1465) → 3
            {2, 0xC800000u, 0, 1, 3},   // >0xC7FFFFF → tooBig → 3
            {2, 0x4000u,    1, 1, 3},   // stop flag → 3
            {3, 0x4000u,    0, 1, 1},   // stage1 class3 → 1
            {2, 0x4000u,    0, 2, 1},   // stage2 class2 → 1
            {3, 0x400u,     0, 2, 3},   // stage2 class3 small → tooBig → 3
            {3, 0x4000u,    0, 2, 4},   // stage2 class3 → 4
            {3, 0xC800000u, 0, 2, 3},   // stage2 class3 tooBig (>0xC7FFFFF) → 3
            {4, 0x4000u,    0, 2, 2},   // class4 → 2
            {5, 0x4000u,    0, 2, 1},   // class5 → 1
            {2, 0x4000u,    0, 3, 4},   // stage3 → 4
            {2, 0x4000u,    0, 4, 4},   // stage>3 → 4
        };
        int ok = 1;
        for (int i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
            int got = wcry_decide_file_action(cases[i].cls, cases[i].size,
                                              cases[i].stop, cases[i].stage);
            if (got != cases[i].act) { ok = 0; break; }
        }
        wcry_st_check("T11 decide-action matrix (14 cases)", ok);
    }

    // T12 — path-exclusion matrix [100032C0]
    {
        struct PE { const wchar_t *dir; const wchar_t *name; int excl; };
        static const PE cases[] = {
            {L"C:\\Intel",                 L"dir", 1},
            {L"C:\\WINDOWS",               L"dir", 1},
            {L"C:\\ProgramData",           L"dir", 1},
            {L"C:\\Program Files",         L"dir", 1},
            {L"C:\\Program Files (x86)",   L"dir", 1},
            {L"C:\\Users\\x\\AppData\\Local\\Temp", L"x", 1},
            {L"C:\\Users\\x\\Local Settings\\Temp", L"x", 1},
            {L"\\\\srv\\c$\\Intel",        L"dir", 1},
            {L"C:\\Users\\x\\Documents",   L"dir", 0},
            {L"C:\\Intel\\sub",            L"dir", 0},   // equality, not prefix
            {L"C:",                        L"Content.IE5", 1},
            {L"C:",                        L"Temporary Internet Files", 1},
            {L"C:", L" This folder protects against ransomware. Modifying it will reduce protection", 1},
            {L"C:\\Users",                 L"normal", 0},
        };
        int ok = 1;
        for (int i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
            int got = wcry_is_path_excluded(cases[i].dir, cases[i].name);
            if (got != cases[i].excl) { ok = 0; break; }
        }
        wcry_st_check("T12 path-exclusion matrix (14 cases)", ok);
    }

    // T13 — install-tag structure + determinism [100014A0]
    {
        int ok = 1;
        for (unsigned seed = 1; ok && seed <= 5000u; seed += 997u) {
            char tag[32], tag2[32];
            wcry_gen_random_tag_from_seed(seed, tag);
            size_t L = strlen(tag);
            if (L < 11 || L > 18) { ok = 0; break; }            // 8-15 letters + 3
            int digits = 0;
            for (size_t i = 0; i < L; i++) {
                if (tag[i] >= 'a' && tag[i] <= 'z') {
                    if (digits) { ok = 0; break; }              // digits only last
                } else if (tag[i] >= '0' && tag[i] <= '9') {
                    digits++;
                } else { ok = 0; break; }
            }
            if (!ok || digits != 3) { ok = 0; break; }          // exactly 3 digits
            wcry_gen_random_tag_from_seed(seed, tag2);
            if (strcmp(tag, tag2) != 0) { ok = 0; break; }      // deterministic
        }
        wcry_st_check("T13 tag: 8-15 letters + exactly 3 digits, deterministic", ok);
        uint16_t host[3] = { 'A', 'B', 0 };
        wcry_st_check("T13 seed = product of hostname UTF-16 units",
                      wcry_tag_seed_host16(host, 3) == 65u * 66u);
    }

    // T14 — key-blob walk (synthetic blobs, parse+validate only)
    {
        uint8_t pub[276], priv[1172];
        memset(pub, 0xAB, sizeof(pub));
        memset(priv, 0xCD, sizeof(priv));
        pub[0] = 0x06; pub[1] = 0x02;                 // PUBLICKEYBLOB v2
        priv[0] = 0x07; priv[1] = 0x02;               // PRIVATEKEYBLOB v2
        pub[2] = pub[3] = 0; priv[2] = priv[3] = 0;   // BLOBHEADER reserved
        pub[4] = 0x00; pub[5] = 0xA4;                 // aiKeyAlg 0xA400 (LE)
        priv[4] = 0x00; priv[5] = 0xA4;
        pub[6] = pub[7] = 0; priv[6] = priv[7] = 0;
        memcpy(pub + 8, "RSA1", 4);
        memcpy(priv + 8, "RSA2", 4);
        wcry_put_le32(pub + 12, 2048);  wcry_put_le32(pub + 16, 65537);
        wcry_put_le32(priv + 12, 2048); wcry_put_le32(priv + 16, 65537);
        WcryKeyBlobInfo ki;
        int ok = wcry_keyblob_parse(pub, sizeof(pub), &ki) == 0 && ki.valid &&
                 ki.expectedSize == 276u && ki.pubexp == 65537u;
        WcryKeyBlobInfo kp;
        ok = ok && wcry_keyblob_parse(priv, sizeof(priv), &kp) == 0 && kp.valid &&
             kp.expectedSize == 1172u;
        uint8_t bad[20] = {0};
        WcryKeyBlobInfo kb;
        ok = ok && wcry_keyblob_parse(bad, sizeof(bad), &kb) == 0 && !kb.valid;
        wcry_st_check("T14 keyblob walk: pub 0x114=276, priv 1172, reject garbage", ok);
    }

    // T15 — mutex NAME wiring (strings only, no handles)
    {
        char built[64];
        wcry_st_check("T15 base+7 == MsWinZonesCacheCounterMutexA",
                      strcmp(wcry_mutex_base_plus7(), "MsWinZonesCacheCounterMutexA") == 0);
        wcry_mutex_build_a0(built, sizeof(built), 0);
        wcry_st_check("T15 sprintf(%s%d,base,0) == Global\\…MutexA0",
                      strcmp(built, "Global\\MsWinZonesCacheCounterMutexA0") == 0, built);
        wcry_st_check("T15 OpenMutexA literal @0x1000D520 == Global\\…MutexW",
                      strcmp(wcry_mutex_open_literal(),
                             "Global\\MsWinZonesCacheCounterMutexW") == 0);
    }

    // T16 — config struct validate (synthetic, pure)
    {
        WcryConfig cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.f000 = 0; cfg.f004 = 1; cfg.f070 = 3; cfg.f074 = 7;
        cfg.priceUsd = 300.0f;
        strcpy(cfg.onions,
               "gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;xxlvbrloxvriy2c5.onion");
        strcpy(cfg.torUrl, "https://dist.torproject.org/torbrowser/6.5.1/tor-win32-0.2.9.10.zip");
        int ok = wcry_config_validate(&cfg) == 0;
        cfg.f004 = 9;                 ok = ok && wcry_config_validate(&cfg) != 0;
        cfg.f004 = 1; cfg.priceUsd = -1.0f; ok = ok && wcry_config_validate(&cfg) != 0;
        cfg.priceUsd = 300.0f; cfg.torUrl[6] = ':'; ok = ok && wcry_config_validate(&cfg) != 0;
        wcry_st_check("T16 config validate (observed markers + corruptions)", ok);
    }

    std::printf("SELFTEST: %d passed, %d failed\n", wcry_st_pass, wcry_st_fail);
    return wcry_st_fail ? 1 : 0;
}

#endif // WCRY_SELFTEST_H
