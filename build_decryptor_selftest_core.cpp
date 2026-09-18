// selftest_core.cpp — benign selftest suite for the decryptor reconstruction.
// Coverage (build contract):
//   [1] NIST FIPS-197 C.1 AES-128 ECB vector (enc + dec)
//   [2] NIST SP800-38A F.2.1 CBC-AES128.Encrypt vector (4 blocks)
//   [3] CBC round-trip under the WannaCry NULL-IV convention
//   [4] TESTDATA key-verification gate pattern (FUN_004047c0, AES stand-in)
//   [5] WANACRY! container header parse on a synthetic container (+ payload
//       decrypt via NULL-IV CBC) + negative parses
//   [6] extension classification (.WNCRY/.WNCYR/.WNCRYT)
//   [7] RSA PRIVATEKEYBLOB struct walk (embedded blob header @0x420794)
//   [8] RFC1071 checksum unit vectors (FUN_00412b00)
//   [9] SOCKS5 greeting/CONNECT builders (byte-dump, no sockets)
//  [10] C2 session handshake frame builder (structure + checksum)
//  [11] rolling XOR crypt unit vector (FUN_0040d2b0)
//  [12] payment-command frames 0x0B/0x0C/0x0D (header order + byte-dump)
//  [13] onion-string parser (c.wnry@0xE0 layout)
//  [14] stubbed harmful paths print their dead markers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wcry_build.h"
#include "aes128.h"
#include "wncry_container.h"
#include "c2_protocol.h"
#include "weaponized_stubs.h"

static int g_fail;

#define CHECK(cond, name)                                                  \
    do {                                                                   \
        if (cond) { printf("  [PASS] %s\n", (name)); }                     \
        else      { printf("  [FAIL] %s\n", (name)); g_fail++; }           \
    } while (0)

static void section(const char *title)
{
    printf("\n== %s ==\n", title);
}

static int buf_eq(const u8 *a, const u8 *b, u32 n)
{
    return memcmp(a, b, n) == 0;
}

static void st32le(u8 *p, u32 v)
{
    p[0] = (u8)(v);
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

static void hexdump(const char *label, const u8 *p, u32 n)
{
    u32 i;
    printf("  %s (%u bytes):\n", label, n);
    for (i = 0; i < n; i++) {
        if ((i % 16) == 0) printf("    %04X  ", i);
        printf("%02X ", p[i]);
        if ((i % 16) == 15 || i + 1 == n) {
            u32 j, row = (i / 16) * 16;
            for (j = (i % 16) + 1; j < 16; j++) printf("   ");
            printf(" |");
            for (j = row; j <= i; j++)
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7F) ? (char)p[j] : '.');
            printf("|\n");
        }
    }
}

// ---------------------------------------------------------------------------
// [1][2][3][4] AES
// ---------------------------------------------------------------------------
static void test_aes(void)
{
    // FIPS-197 C.1
    static const u8 K1[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                              0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    static const u8 PT1[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const u8 CT1[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                               0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    // SP800-38A F.2.1 CBC-AES128.Encrypt
    static const u8 K2[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                              0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const u8 IV2[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    static const u8 PT2[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
    static const u8 CT2[64] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
        0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
        0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7 };

    u8 buf[64], rt[48];
    u32 rk[44];
    int i;

    section("[1] AES-128 ECB — NIST FIPS-197 C.1");
    aes128_expand_key(rk, K1);
    aes128_encrypt_block(rk, PT1, buf);
    CHECK(buf_eq(buf, CT1, 16), "encrypt(PT1) == CT1");
    aes128_decrypt_block(rk, CT1, buf);
    CHECK(buf_eq(buf, PT1, 16), "decrypt(CT1) == PT1");

    section("[2] AES-128 CBC — NIST SP800-38A F.2.1");
    memcpy(buf, PT2, 64);
    CHECK(aes128_cbc_encrypt(K2, IV2, buf, 64) == 0, "cbc_encrypt rc==0");
    CHECK(buf_eq(buf, CT2, 64), "4-block ciphertext matches SP800-38A");

    section("[3] CBC round-trip — NULL IV (WannaCry convention, zero page @0x4218b0)");
    for (i = 0; i < 48; i++) rt[i] = (u8)(i * 3 + 7);
    memcpy(buf, rt, 48);
    aes128_cbc_encrypt(K2, NULL, buf, 48);          // NULL iv -> zero chain
    CHECK(!buf_eq(buf, rt, 48), "NULL-IV encrypt changes payload");
    aes128_cbc_decrypt(K2, NULL, buf, 48);
    CHECK(buf_eq(buf, rt, 48), "NULL-IV decrypt restores payload");

    section("[4] TESTDATA verification gate (FUN_004047c0 pattern, AES stand-in)");
    memset(buf, 0, 16);
    memcpy(buf, "TESTDATA", 8);
    aes128_cbc_encrypt(K1, NULL, buf, 16);
    aes128_cbc_decrypt(K1, NULL, buf, 16);
    CHECK(strncmp((char*)buf, "TESTDATA", 8) == 0,
          "enc/dec round-trip proves the key (strncmp==0 => VERIFIED)");
}

// ---------------------------------------------------------------------------
// [5] container header
// ---------------------------------------------------------------------------
static void test_container(void)
{
    static const u8 KEY[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                               0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    u8 ctnr[0x118 + 48], pt[48], work[48];
    wcry_header_t h;
    int i, rc;

    section("[5] WANACRY! container header parse (synthetic)");

    memset(ctnr, 0, sizeof ctnr);
    memcpy(ctnr, "WANACRY!", 8);                    // +0x000 magic
    st32le(ctnr + 0x08, 0x100);                     // +0x008 rsaLen
    for (i = 0; i < 256; i++) ctnr[0x0C + i] = (u8)(i ^ 0xA5);   // +0x00C RSA ct (filler)
    st32le(ctnr + 0x10C, 1);                        // +0x10C fileType (AES lane)
    st32le(ctnr + 0x110, 48);                       // +0x110 size lo
    st32le(ctnr + 0x114, 0);                        // +0x114 size hi
    for (i = 0; i < 48; i++) pt[i] = (u8)(i * 7 + 1);
    memcpy(work, pt, 48);
    aes128_cbc_encrypt(KEY, NULL, work, 48);        // NULL-IV payload
    memcpy(ctnr + 0x118, work, 48);

    rc = wcry_parse_header(ctnr, (u32)sizeof ctnr, &h);
    CHECK(rc == 0, "parse rc==0");
    wcry_header_print(&h);
    CHECK(memcmp(h.magic, "WANACRY!", 8) == 0 && h.rsaLen == 0x100 &&
          h.fileType == 1 && h.origSize == 48 &&
          h.payloadOff == 0x118 && h.payloadLen == 48,
          "fields: magic/rsaLen/fileType/size/payload");
    aes128_cbc_decrypt(KEY, NULL, ctnr + 0x118, 48);
    CHECK(buf_eq(ctnr + 0x118, pt, 48), "payload decrypts (NULL IV) to known PT");

    ctnr[3] = 'X';                                  // break magic
    CHECK(wcry_parse_header(ctnr, (u32)sizeof ctnr, &h) == -3, "bad magic -> -3");
    ctnr[3] = 'A';                                  // restore "WANACRY!"
    st32le(ctnr + 0x08, 0x101);                     // break rsaLen
    CHECK(wcry_parse_header(ctnr, (u32)sizeof ctnr, &h) == -4, "bad rsaLen -> -4");
    CHECK(wcry_parse_header(ctnr, 0x50, &h) == -2, "short buffer -> -2");

    CHECK(strcmp(wcry_filetype_name(3), "tail-swap recoverable, no AES (.WNCYR)") == 0,
          "fileType 3 -> tail-recovery class (no AES lane)");
}

// ---------------------------------------------------------------------------
// [6] extensions  [7] PRIVATEKEYBLOB walk
// ---------------------------------------------------------------------------
static void test_format_helpers(void)
{
    section("[6] extension classification");
    CHECK(wcry_classify_extension("doc.WNCRY")  == WCRY_EXT_WNCRY,  "doc.WNCRY  -> WNCRY");
    CHECK(wcry_classify_extension("DOC.wncyr")  == WCRY_EXT_WNCYR,  "DOC.wncyr  -> WNCYR (case-ins)");
    CHECK(wcry_classify_extension("a.WNCRYT")   == WCRY_EXT_WNCRYT, "a.WNCRYT   -> WNCRYT");
    CHECK(wcry_classify_extension("readme.txt") == WCRY_EXT_NONE,   "readme.txt -> NONE");
    CHECK(wcry_classify_extension("noext")      == WCRY_EXT_NONE,   "noext      -> NONE");
    CHECK(wcry_ext_strip_on_decrypt(WCRY_EXT_WNCRY) &&
          wcry_ext_strip_on_decrypt(WCRY_EXT_WNCYR) &&
          !wcry_ext_strip_on_decrypt(WCRY_EXT_WNCRYT),
          "FUN_00402560 target rule: WNCRY/WNCYR strip, WNCRYT takes the .org lane");

    section("[7] RSA PRIVATEKEYBLOB struct walk (header @0x420794, 0x494 B)");
    {
        // Real 20-byte header prefix of the embedded master blob (REVIEW
        // claim 14, byte-verified); remainder is synthetic pattern fill —
        // reference data only, never imported/used as a key here.
        static const u8 HDR[20] = {0x07,0x02,0x00,0x00, 0x00,0xA4,0x00,0x00,
                                   'R','S','A','2', 0x00,0x08,0x00,0x00,
                                   0x01,0x00,0x01,0x00};
        u8 blob[0x494];
        wcry_rsablob_t rb;
        int i;
        memcpy(blob, HDR, 20);
        for (i = 20; i < 0x494; i++) blob[i] = (u8)(i & 0xFF);
        CHECK(wcry_walk_rsa_privatekeyblob(blob, (u32)sizeof blob, &rb, 1) == 0,
              "walk: valid PRIVATEKEYBLOB structure");
        CHECK(rb.bType == 0x07 && rb.bVersion == 2 && rb.aiKeyAlg == 0x0000A400u,
              "bType=7(PRIVATEKEYBLOB) ver=2 alg=CALG_RSA_KEYX");
        CHECK(memcmp(rb.magic, "RSA2", 4) == 0 && rb.bitLen == 2048 && rb.pubExp == 65537,
              "magic=RSA2 bitLen=2048 pubExp=65537");
        CHECK(rb.modOff == 20 && rb.modLen == 256 && rb.p1Off == 276 &&
              rb.p2Off == 404 && rb.e1Off == 532 && rb.e2Off == 660 &&
              rb.cOff == 788 && rb.dOff == 916 && rb.totalExpected == 0x494,
              "component table: mod@20 p@276/404 exp@532/660 coeff@788 privExp@916, total 0x494");
        blob[8] = 'X';   // break magic
        CHECK(wcry_walk_rsa_privatekeyblob(blob, (u32)sizeof blob, &rb, 0) == 1,
              "negative: wrong magic -> rc=1");
        blob[8] = 'R';
        CHECK(wcry_walk_rsa_privatekeyblob(blob, 20, &rb, 0) == 1,
              "negative: truncated blob -> rc=1");
    }
}

// ---------------------------------------------------------------------------
// [8] checksum  [9] SOCKS5  [10] handshake  [11] xor  [12] frames  [13] onions
// ---------------------------------------------------------------------------
static void test_c2(void)
{
    section("[8] RFC1071 checksum unit vectors (FUN_00412b00)");
    {
        static const u8 v1[2] = {0x00,0x00};
        static const u8 v2[4] = {0x01,0x02,0x03,0x04};
        static const u8 v3[3] = {0x11,0x22,0x33};
        static const u8 v4[4] = {0xFF,0xFF,0xFF,0xFF};
        CHECK(wcry_rfc1071_checksum(v1, 2) == 0xFFFF, "{00 00} -> FFFF");
        CHECK(wcry_rfc1071_checksum(v2, 4) == 0xF9FB, "{01 02 03 04} -> F9FB");
        CHECK(wcry_rfc1071_checksum(v3, 3) == 0xDDBB, "{11 22 33} -> DDBB (odd tail)");
        CHECK(wcry_rfc1071_checksum(v4, 4) == 0x0000, "{FF FF FF FF} -> 0000 (fold)");
    }

    section("[9] SOCKS5 greeting/CONNECT builders (in-memory only)");
    {
        u8 b[64];
        int n;
        n = wcry_socks5_greeting(b);
        CHECK(n == 3 && b[0] == 5 && b[1] == 1 && b[2] == 0,
              "greeting == 05 01 00");
        hexdump("SOCKS5 greeting", b, 3);

        n = wcry_socks5_connect_domain(b, sizeof b, "gx7ekbenv2riucmf.onion", 9050);
        CHECK(n == 29 && b[0] == 5 && b[1] == 1 && b[2] == 0 && b[3] == 3 &&
              b[4] == 22 && b[5] == 'g' &&
              b[27] == 0x23 && b[28] == 0x5A,
              "CONNECT domain: 05 01 00 03 | 22 | host | 23 5A (port BE)");
        hexdump("SOCKS5 CONNECT (primary onion :9050)", b, (u32)n);

        {
            static const u8 ip[4] = {127,0,0,1};
            n = wcry_socks5_connect_ipv4(b, sizeof b, ip, 9050);
            CHECK(n == 10 && b[3] == 1 && b[4] == 127 && b[8] == 0x23 && b[9] == 0x5A,
                  "CONNECT ipv4 127.0.0.1:9050 == 05 01 00 01 7F 00 00 01 23 5A");
        }
        CHECK(wcry_socks5_connect_domain(b, 8, "abc.onion", 80) == -2,
              "capacity guard -> -2");
    }

    section("[10] C2 session handshake frame (FUN_0040d0a0)");
    {
        u8 f[64], key31[31];
        int n;
        u16 ck;
        srand(0x57435259u);                     // deterministic selftest run
        n = wcry_handshake_frame(f, sizeof f, 0x0B, 0x0D, 0, key31);
        CHECK(n == 36, "frame length == 36 (send n+36, pad n=0)");
        CHECK(f[31] == 0x0B && f[32] == 0x00 && f[33] == 0x0D,
              "offsets 31/32/33 = cmd1/0x00/cmd2");
        ck = wcry_rfc1071_checksum(f, 0x1F);
        CHECK(f[34] == (u8)(ck & 0xFF) && f[35] == (u8)(ck >> 8),
              "bytes 34..35 = RFC1071 checksum over the 31-byte key (LE)");
        CHECK(buf_eq(f, key31, 31), "session key = blob[0..30]");
        hexdump("handshake frame", f, 36);
    }

    section("[11] rolling XOR crypt unit vector (FUN_0040d2b0)");
    {
        static const u8 EXPECT[8] = {0x1F,0x1E,0x1D,0x1C,0x1B,0x1A,0x19,0x18};
        u8 key[31], buf[8];
        int i;
        for (i = 0; i < 30; i++) key[i] = (u8)(i + 1);
        key[30] = 31;                           // current byte (obj +0x26)
        memset(buf, 0, 8);
        wcry_xor_crypt(key, buf, 8);
        CHECK(buf_eq(buf, EXPECT, 8), "keystream over 8 zero bytes == 1F 1E .. 18");
        CHECK(key[30] == 0x17, "current byte advanced 31 -> 0x17 (window shift per tap)");
    }

    section("[12] payment-command frames 0x0B/0x0C/0x0D (pure builders)");
    {
        wcry_frame_t f;
        static const u8 blob[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
        u8 expect_id[8] = {0x44,0x33,0x22,0x11,0,0,0,0};

        wcry_frame_init(&f);
        CHECK(wcry_frame_cmd_0B(&f, 0x11223344ULL, "WCRY-BOX", "tester", "hi") == 0,
              "0x0B build rc==0");
        CHECK(f.used == 25 && memcmp(f.buf, expect_id, 8) == 0 &&
              memcmp(f.buf + 8, "WCRY-BOX", 8) == 0 &&
              f.buf[16] == 0x0B && memcmp(f.buf + 17, "tester", 6) == 0 &&
              memcmp(f.buf + 23, "hi", 2) == 0,
              "header order id(8)|computer|cmd|user + message (id LE, cmd@16)");
        hexdump("cmd 0x0B contact-message frame", f.buf, f.used);
        wcry_frame_free(&f);

        wcry_frame_init(&f);
        CHECK(wcry_frame_cmd_0C(&f, 0x11223344ULL, "WCRY-BOX", "tester",
                                "11223344.dky", blob, 8) == 0,
              "0x0C build rc==0");
        CHECK(f.used == 62 && f.buf[16] == 0x0C &&
              memcmp(f.buf + 23, "11223344.dky", 12) == 0 &&
              memcmp(f.buf + 39, "WanaCrypt0r", 11) == 0 &&
              f.buf[50] == 8 && f.buf[51] == 0 &&
              memcmp(f.buf + 54, blob, 8) == 0,
              "0x0C payload: dkyName|00x4|WanaCrypt0r||len LE|blob (total 62)");
        hexdump("cmd 0x0C request-private-key frame", f.buf, f.used);
        wcry_frame_free(&f);

        wcry_frame_init(&f);
        CHECK(wcry_frame_cmd_0D(&f, 0x11223344ULL, "WCRY-BOX", "tester", "hi") == 0 &&
              f.used == 25 && f.buf[16] == 0x0D,
              "0x0D build rc==0, cmd byte @16");
        wcry_frame_free(&f);
    }

    section("[13] onion-string parser (c.wnry@0xE0 field layout)");
    {
        // NUL lead-in (field start 0xE0) + validated literal (starts 0xE4)
        static const char ONIONS_FIELD[] =
            "\x00\x00\x00\x00"
            "gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;"
            "xxlvbrloxvriy2c5.onion;76jdd2ir2embyv47.onion;"
            "cwwnhwhlz52maqm7.onion";
        static u8 cfg[0x30C];                   // 780-byte c.wnry image, zeroed
        char onions[8][64];
        int n;
        memcpy(cfg + 0xE0, ONIONS_FIELD, sizeof(ONIONS_FIELD));
        n = wcry_onions_parse(cfg + 0xE0, 0x30C - 0xE0, onions, 8);
        CHECK(n == 5, "parsed 5 onions from ';'-joined field");
        CHECK(strcmp(onions[0], "gx7ekbenv2riucmf.onion") == 0 &&
              strcmp(onions[1], "57g7spgrzlojinas.onion") == 0 &&
              strcmp(onions[4], "cwwnhwhlz52maqm7.onion") == 0,
              "primary (token[0]) + tail tokens match c.wnry@0xE4");
    }
}

// ---------------------------------------------------------------------------
// [14] harmful paths are dead
// ---------------------------------------------------------------------------
static void test_stubs(void)
{
    section("[14] stubbed harmful paths (ENABLE_WEAPONIZED_PATHS undefinable)");
    CHECK(stub_decrypt_file_io() == 0, "file decrypt/restore IO dead");
    (void)stub_dky_write();
    (void)stub_tor_bootstrap();
    (void)stub_socks_connect();
    (void)stub_file_rename_pass();
    (void)stub_mfc_gui();
    printf("  all harmful entry points compiled to printf stubs only\n");
}

int wcry_run_selftests(void)
{
    g_fail = 0;
    test_aes();
    test_container();
    test_format_helpers();
    test_c2();
    test_stubs();
    printf("\n%s (%d check groups, %d failures)\n",
           g_fail == 0 ? "SELFTEST PASSED" : "SELFTEST FAILED", 14, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
