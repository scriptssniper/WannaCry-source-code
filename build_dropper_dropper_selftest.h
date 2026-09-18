// dropper_selftest.h — benign check suite for the dropper reconstruction.
// Shared by:
//   * build/dropper/dropper.cpp  (mingw EXE, `dropper.exe` with no args)
//   * build/dropper/selftest.cc  (Linux-native harness, `make selftest`)
// Parses only bundled evidence constants (dropper_data.h). Zero file writes,
// zero handles, zero registry. Exits 0 when every check passes.
#ifndef WCRY_DROPPER_SELFTEST_H
#define WCRY_DROPPER_SELFTEST_H

#include <stdio.h>
#include <string.h>

#include "dropper_core.h"
#include "dropper_data.h"

static int wcry_st_fails = 0;

static void wcry_st_check(int cond, const char *what, const char *detail)
{
    if (cond)
        printf("  [ok]   %s%s%s\n", what, detail ? " — " : "",
               detail ? detail : "");
    else {
        wcry_st_fails++;
        printf("  [FAIL] %s%s%s\n", what, detail ? " — " : "",
               detail ? detail : "");
    }
}

/* Runs the full benign suite. Returns 0 on all-pass, else failure count. */
static int wcry_dropper_selftest(void)
{
    printf("=== WanaCry dropper reconstruction — benign selftest ===\n");
    printf("binary: WannaCry.exe ed01ebfbc9eb5bbea545af4d01bf5f10716618"
           "40480439c6e5babe8e080e41aa\n");
    printf("policy: weaponized paths stubbed (build/README.md); this suite "
           "performs no writes\n\n");

    /* ---- c.wnry config struct + parse [00401000 context] ---- */
    printf("[component] c.wnry config parse\n");
    {
        WcryConfig cfg;
        wcry_config_parse(WCRY_CWNRY_SAMPLE, WCRY_CWNRY_SAMPLE_SIZE, &cfg);
        wcry_st_check(cfg.ok && cfg.size == 0x30Cu,
                      "parse 0x30C config", "size 780 B");
        wcry_st_check(cfg.dword_000 == 0 && cfg.dword_004 == 1,
                      "header dwords @0/4", "0,1");
        wcry_st_check(cfg.dword_070 == 3 && cfg.dword_074 == 7 &&
                          cfg.dword_078 == 0x43960000u,
                      "payment fields @0x70..", "3,7,float 300.0");
        wcry_st_check(cfg.btc_addr[0] == '\0',
                      "BTC slot @178 empty as shipped",
                      "dropper fills addrs[rand()%3] at runtime");
        wcry_st_check(strcmp(cfg.onion_pool,
            "gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;"
            "xxlvbrloxvriy2c5.onion;76jdd2ir2embyv47.onion;"
            "cwwnhwhlz52maqm7.onion;") == 0,
            "onion pool @0xE4", "5 v2 addresses ';'-joined");
        wcry_st_check(strcmp(cfg.tor_url,
            "https://dist.torproject.org/torbrowser/6.5.1/"
            "tor-win32-0.2.9.10.zip") == 0,
            "tor URL @0x1DE", "torbrowser 6.5.1 / tor 0.2.9.10");
    }

    /* ---- GenRandomTag algorithm [00401225], pure ---- */
    printf("[component] GenRandomTag (computer-name-seeded, msvcrt rand)\n");
    {
        static const uint16_t host[] = {
            'D','E','S','K','T','O','P','-','W','C','R','Y','T','E','S','T',0 };
        WcryRand rng;
        char tag[19], tag2[19];
        wcry_gen_random_tag(&rng, host, tag);
        wcry_st_check(strcmp(tag, "pnzdokaooi368") == 0,
                      "tag for 'DESKTOP-WCRYTEST'", tag);
        wcry_st_check(strlen(tag) >= 11 && strlen(tag) <= 18,
                      "length 11..18", "");
        {
            size_t i, digits = 0, letters = strlen(tag);
            for (i = 0; i < letters; i++)
                if (tag[i] >= '0' && tag[i] <= '9') digits++;
            wcry_st_check(digits == 3, "exactly 3 digits",
                          "r%8+0xB minus r%8+8");
        }
        wcry_gen_random_tag(&rng, host, tag2);
        wcry_st_check(strcmp(tag, tag2) == 0, "deterministic per name", "");
        /* same stream tail feeds SetRandomBtcAddr [00401e9e] */
        wcry_st_check(wcry_pick_btc_addr(&rng) == WCRY_BTC_ADDRS[2],
                      "stream-tail BTC pick", WCRY_BTC_ADDRS[2]);
        /* fresh stream, fixed seed */
        wcry_srand(&rng, 42);
        wcry_st_check(wcry_pick_btc_addr(&rng) == WCRY_BTC_ADDRS[1],
                      "rand()%3 pick (seed 42)", WCRY_BTC_ADDRS[1]);
    }

    /* ---- BTC address table [00401e9e / globals 0x40F440..88] ---- */
    printf("[component] BTC address table\n");
    {
        int i, ok = 1;
        for (i = 0; i < WCRY_BTC_COUNT; i++) {
            size_t n = 0;
            while (WCRY_BTC_ADDRS[i][n] != '\0') n++;
            if (n != 34) ok = 0;
        }
        wcry_st_check(ok, "3 addresses, 34 chars each",
                      "known WannaCry payment wallets");
    }

    /* ---- ZIP password check [0x40F52C -> UnzOpen_Mem] ---- */
    printf("[component] zip password + legacy crypt keys\n");
    {
        uint32_t k[3], i;
        wcry_st_check(wcry_zip_password_ok(WCRY_ZIP_PASSWORD),
                      "password accepted", WCRY_ZIP_PASSWORD);
        wcry_st_check(!wcry_zip_password_ok("WNcry@2017") &&
                          !wcry_zip_password_ok(""),
                      "wrong passwords rejected", "string compare");
        wcry_zip_init_keys(k);
        for (i = 0; i < (uint32_t)strlen(WCRY_ZIP_PASSWORD); i++)
            wcry_zip_update_keys(k, (uint8_t)WCRY_ZIP_PASSWORD[i]);
        printf("         keys after password: %08lx %08lx %08lx\n",
               (unsigned long)k[0], (unsigned long)k[1], (unsigned long)k[2]);
        wcry_st_check(k[0] == 0x619937ddu && k[1] == 0xbccacfa2u &&
                          k[2] == 0x004537e2u,
                      "ZipCrypt key schedule [00405535]",
                      "0x12345678/0x23456789/0x34567890 base");
    }

    /* ---- t.wnry "WANACRY!" header parse [004014a6 front half] ---- */
    printf("[component] t.wnry header parse\n");
    {
        WcryTwnryHeader h;
        wcry_twnry_parse_header(WCRY_TWNRY_HEADER, WCRY_TWNRY_HEADER_SIZE, &h);
        wcry_st_check(h.ok && strcmp(h.magic, WCRY_MAGIC) == 0,
                      "magic \"WANACRY!\" [0x40EB7C]", h.magic);
        wcry_st_check(h.blobLen == 0x100u, "RSA blob len @0x08 == 0x100",
                      "256-B wrapped AES key");
        wcry_st_check(h.unusedField == 4u,
                      "u32 @0x10C read-but-unused", "REVIEW.md W2");
        wcry_st_check(h.payloadSize == 0x10000u,
                      "u64 payload size @0x110 == 0x10000",
                      "65536-B MZ DLL");
        wcry_st_check(h.payloadOff == 0x118u,
                      "ciphertext offset 0x118",
                      "header consumes exactly 0x118 B");
    }

    /* ---- RSA PRIVATEKEYBLOB struct walk [00401861 CryptImportKey] ---- */
    printf("[component] RSA PRIVATEKEYBLOB struct walk (offsets only, "
           "no key files written)\n");
    {
        WcryRsaBlob b;
        char detail[128];
        wcry_rsablob_parse(WCRY_RSA_PRIVKEYBLOB, WCRY_RSA_PRIVKEYBLOB_SIZE, &b);
        wcry_st_check(b.ok, "header valid", "type 7 PRIVATEKEYBLOB, ver 2");
        wcry_st_check(b.aiKeyAlg == 0xA400u, "aiKeyAlg CALG_RSA_KEYX",
                      "0x0000A400");
        wcry_st_check(b.bitlen == 2048u && b.pubexp == 65537u,
                      "RSA-2048, e=65537", "matches wcry_private.pem");
        sprintf(detail,
                "mod=%lu p=%lu q=%lu dp=%lu dq=%lu qinv=%lu d=%lu",
                (unsigned long)b.off_modulus, (unsigned long)b.off_prime1,
                (unsigned long)b.off_prime2, (unsigned long)b.off_exp1,
                (unsigned long)b.off_exp2, (unsigned long)b.off_coeff,
                (unsigned long)b.off_privexp);
        wcry_st_check(b.off_modulus == 20 && b.off_prime1 == 276 &&
                          b.off_prime2 == 404 && b.off_exp1 == 532 &&
                          b.off_exp2 == 660 && b.off_coeff == 788 &&
                          b.off_privexp == 916,
                      "field offsets (bitlen-derived)", detail);
        wcry_st_check(b.total == 0x494u && b.total == (size_t)WCRY_RSA_PRIVKEYBLOB_SIZE,
                      "total 0x494 B", "== exe 0xEBF8 blob size");
    }

    /* ---- resource-offset math (XIA/2058) ---- */
    printf("[component] resource-offset math (RVA -> file)\n");
    {
        static const WcrySection syn[1] =
            { { 0x5000u, 0x1000u, 0x2000u, 0x1800u } };
        wcry_st_check(wcry_rva_to_offset(0x100F0u, WCRY_SAMPLE_SECTIONS, 4)
                          == (long)0x100F0,
                      "XIA/2058 data RVA 0x100F0",
                      ".rsrc VA==raw in this image");
        wcry_st_check(wcry_rva_to_offset(0x100F0u + 0x100u,
                                         WCRY_SAMPLE_SECTIONS, 4)
                          == (long)(0x100F0 + 0x100),
                      "zip interior offsets translate", "");
        wcry_st_check(wcry_rva_to_offset(0x5234u, syn, 1) == 0x1234L,
                      "synthetic va!=raw section", "0x5234 -> 0x1234");
        wcry_st_check(wcry_rva_to_offset(0x7FFFFFFFu, WCRY_SAMPLE_SECTIONS, 4)
                          == -1L,
                      "unmapped RVA rejected", "");
    }

    /* ---- workdir candidate chain [00401B5F] (paths only) ---- */
    printf("[component] workdir path computation\n");
    {
        char cand[WCRY_WD_MAX][WCRY_WD_SLOT];
        int n = wcry_workdir_candidates("C:\\Windows",
                                        "C:\\Users\\u\\AppData\\Local\\Temp\\",
                                        1, cand);
        wcry_st_check(n == 4, "4 candidates (ProgramData exists)", "");
        wcry_st_check(strcmp(cand[0], "C:\\Windows\\ProgramData") == 0 &&
                          strcmp(cand[1], "C:\\Windows\\Intel") == 0 &&
                          strcmp(cand[2], "C:\\Windows") == 0 &&
                          strcmp(cand[3],
                                 "C:\\Users\\u\\AppData\\Local\\Temp") == 0,
                      "chain order + trailing-backslash strip", "");
        n = wcry_workdir_candidates("C:\\Windows", "C:\\Temp\\", 0, cand);
        wcry_st_check(n == 3 && strcmp(cand[0], "C:\\Windows\\Intel") == 0,
                      "ProgramData skipped when absent",
                      "gated on dir existing [00401c10]");
    }

    /* ---- mutex name + arg gate [00401eff / 00402020] ---- */
    printf("[component] launch plumbing strings\n");
    {
        char m[64];
        wcry_mutex_name(m);
        wcry_st_check(strcmp(m, WCRY_MUTEX_FULL) == 0, "mutex name", m);
        wcry_st_check(wcry_is_install_arg("/i") == 1 &&
                          wcry_is_install_arg("/x") == 0 &&
                          wcry_is_install_arg(NULL) == 0,
                      "argv gate: only \"/i\" is install mode", "");
    }

    printf("\n%s (9 check groups, 0 file writes)\n",
           wcry_st_fails == 0 ? "ALL CHECKS PASSED" : "FAILURES PRESENT");
    return wcry_st_fails;
}

#endif /* WCRY_DROPPER_SELFTEST_H */
