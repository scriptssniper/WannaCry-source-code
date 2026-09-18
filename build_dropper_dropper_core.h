// dropper_core.h — pure, OS-portable logic of the WannaCry dropper
// reconstruction. No windows.h: compiles with mingw (dropper.cpp) and native
// g++ (selftest.cc). Every function cites the reconstruction address it
// mirrors (see reconstruction/dropper/function_map.md, REVIEW.md).
//
// All msvcrt-dependent behavior (rand) is reproduced with the documented
// MSVC LCG so results are identical on Windows and Linux.
//
// BENIGN ONLY — parsing, string building and arithmetic. Nothing here opens
// handles, writes files, or touches the registry.
#ifndef WCRY_DROPPER_CORE_H
#define WCRY_DROPPER_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* .data string constants (byte-verified, addresses in comments)      */
/* ------------------------------------------------------------------ */

#define WCRY_CWNRY          "c.wnry"        /* 0x40E010 */
#define WCRY_TWNRY          "t.wnry"        /* 0x40F4F4 */
#define WCRY_TASKSCHE       "tasksche.exe"  /* 0x40F4D8 */
#define WCRY_TASKSTART      "TaskStart"     /* 0x40F4E8 */
#define WCRY_ARG_INSTALL    "/i"            /* 0x40F538 */
#define WCRY_MAGIC          "WANACRY!"      /* 0x40EB7C */
#define WCRY_ZIP_PASSWORD   "WNcry@2ol7"    /* 0x40F52C */
#define WCRY_MUTEX_BASE     "Global\\MsWinZonesCacheCounterMutexA" /* 0x40F4B4 */
/* "%s%d" @0x40F4AC with arg 0 => trailing '0' (REVIEW.md #6) */
#define WCRY_MUTEX_FULL     "Global\\MsWinZonesCacheCounterMutexA0"

/* BTC addresses — order as pushed at 0x401E9E (function_map.md globals) */
#define WCRY_BTC_COUNT 3
static const char *const WCRY_BTC_ADDRS[WCRY_BTC_COUNT] = {
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",   /* 0x40F488  addrs[0] */
    "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",   /* 0x40F464  addrs[1] */
    "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",   /* 0x40F440  addrs[2] */
};

/* c.wnry fixed layout: 0x30C total; BTC slot 178 (0xB2); onion pool 0xE4;
 * tor installer URL 0x1DC (all byte-verified on extracted/c.wnry).        */
#define WCRY_CFG_SIZE        0x30Cu
#define WCRY_CFG_OFF_BTC     178u    /* 0xB2 — SetRandomBtcAddr writes here */
#define WCRY_CFG_OFF_ONION   0xE4u
#define WCRY_CFG_OFF_TOR     0x1DEu  /* 478 — tor installer URL             */
#define WCRY_CFG_ONION_MAX   0xFAu   /* 0xE4..0x1DE */
#define WCRY_CFG_TOR_MAX     0x12Eu  /* 0x1DE..0x30C */

/* t.wnry container layout (REVIEW.md #9 + W2 correction: payload size is the
 * 8-B little-endian field @0x110, NOT the 4-B field @0x10C).              */
#define WCRY_TWNRY_OFF_MAGIC      0x0u   /* "WANACRY!" (8 B)        */
#define WCRY_TWNRY_OFF_BLOBLEN    0x8u   /* u32 == 0x100            */
#define WCRY_TWNRY_OFF_RSA_BLOB   0xCu   /* 256 B RSA-wrapped AES key */
#define WCRY_TWNRY_OFF_UNUSED     0x10Cu /* u32, read but unused (=4) */
#define WCRY_TWNRY_OFF_SIZE       0x110u /* u64 payload size (=0x10000) */
#define WCRY_TWNRY_OFF_PAYLOAD    0x118u /* AES-128-CBC (NULL IV) data */
#define WCRY_TWNRY_MAX_FILE  0x6400000u  /* 100 MiB read cap [00401529] */
#define WCRY_TWNRY_MAX_PAYLOAD 0x6400001u/* bounds check [00401605]  */

/* ------------------------------------------------------------------ */
/* msvcrt-compatible PRNG: rand() == (state*214013+2531011)>>16 &0x7fff */
/* (msvcrt implementation; the binary calls srand/rand @004012d7/d c)  */
/* ------------------------------------------------------------------ */
typedef struct { uint32_t state; } WcryRand;

static void wcry_srand(WcryRand *r, uint32_t seed) { r->state = seed; }

static int wcry_rand(WcryRand *r)
{
    r->state = r->state * 214013u + 2531011u;
    return (int)((r->state >> 16) & 0x7fffu);
}

/* ------------------------------------------------------------------ */
/* 00401225 — GenRandomName core. seed = 1 * each UTF-16 code unit     */
/* (32-bit wrap); srand(seed); r = rand();                             */
/*   letters = r%8 + 8        lower-case                               */
/*   digits  = r%8 + 0xB      stop  => always exactly 3 digits         */
/*   total length 11..18                                               */
/* `name` = NUL-terminated UTF-16 code units (what GetComputerNameW    */
/* returns on Windows). out needs >= 19 bytes.                         */
/* ------------------------------------------------------------------ */
static void wcry_gen_random_tag(WcryRand *r, const uint16_t *name, char *out)
{
    unsigned seed = 1;
    size_t n = 0, i;
    int rr, nletters, ndigits, k;
    while (name[n] != 0) n++;
    for (i = 0; i < n; i++) seed *= (unsigned)name[i];      /* 004012b4 */
    wcry_srand(r, seed);                                    /* 004012d7 */
    rr      = wcry_rand(r);                                 /* 004012dc */
    nletters = rr % 8 + 8;                                  /* 004012e2 */
    ndigits  = rr % 8 + 0xB;                                /* 004012fe */
    for (k = 0; k < nletters; k++)                          /* 004012e9 */
        out[k] = (char)(wcry_rand(r) % 0x1a) + 'a';
    for (; k < ndigits; k++)                                /* 004012fe */
        out[k] = (char)(wcry_rand(r) % 10) + '0';
    out[k] = '\0';                                          /* 0040131b */
}

/* SetRandomBtcAddr selection [00401e9e]: strcpy(buf+178, addrs[rand()%3])
 * on the same (un-reseeded) rand stream as the tag.                       */
static const char *wcry_pick_btc_addr(WcryRand *r)
{
    return WCRY_BTC_ADDRS[wcry_rand(r) % WCRY_BTC_COUNT];
}

/* ------------------------------------------------------------------ */
/* classic zip (ZipCrypt) password key schedule [00405535/88/a3].      */
/* Kept for the password-check check: the archive is plain deflate +   */
/* this legacy password layer only (function_map.md 0040671d).         */
/* ------------------------------------------------------------------ */
static uint32_t wcry_crc32_byte(uint32_t c, uint8_t b)
{
    int i;
    c ^= b;
    for (i = 0; i < 8; i++)
        c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    return c;
}

static void wcry_zip_init_keys(uint32_t k[3])
{
    k[0] = 0x12345678u; k[1] = 0x23456789u; k[2] = 0x34567890u; /* 0040671d */
}

static void wcry_zip_update_keys(uint32_t k[3], uint8_t c)       /* 00405535 */
{
    k[0] = wcry_crc32_byte(k[0], c);
    k[1] = (k[1] + (k[0] & 0xffu)) * 134775813u + 1u;
    k[2] = wcry_crc32_byte(k[2], (uint8_t)(k[1] >> 24));
}

/* ZIP password check: the dropper hands the literal "WNcry@2ol7"      */
/* (0x40F52C) to the archive opener; check = exact string compare.     */
static int wcry_zip_password_ok(const char *candidate)
{
    return strcmp(candidate, WCRY_ZIP_PASSWORD) == 0;
}

/* ------------------------------------------------------------------ */
/* c.wnry config struct + parse [00401000 context; layout verified on  */
/* extracted/c.wnry].                                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    int      ok;
    uint32_t size;              /* must be 0x30C                    */
    uint32_t dword_000;         /* 0 in shipped sample              */
    uint32_t dword_004;         /* 1 in shipped sample              */
    uint32_t dword_070;         /* 3                                */
    uint32_t dword_074;         /* 7                                */
    uint32_t dword_078;         /* 0x43960000 == float 300.0 (USD)  */
    char     btc_addr[64];      /* slot @178 — EMPTY as shipped;    */
                                /* dropper fills addrs[rand()%3]    */
    char     onion_pool[WCRY_CFG_ONION_MAX];               /* @0xE4 */
    char     tor_url[WCRY_CFG_TOR_MAX];                    /* @0x1DC */
} WcryConfig;

static void wcry_copy_sz(char *dst, size_t cap,
                         const uint8_t *src, size_t off, size_t avail)
{
    size_t i = 0;
    if (off >= avail) { dst[0] = '\0'; return; }
    while (i + 1 < cap && off + i < avail && src[off + i] != 0) {
        dst[i] = (char)src[off + i];
        i++;
    }
    dst[i] = '\0';
}

static uint32_t wcry_rd32(const uint8_t *b, size_t off)
{
    return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}

static int wcry_config_parse(const uint8_t *buf, size_t len, WcryConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->size = (uint32_t)len;
    if (len != WCRY_CFG_SIZE) return 0;
    cfg->ok        = 1;
    cfg->dword_000 = wcry_rd32(buf, 0x00);
    cfg->dword_004 = wcry_rd32(buf, 0x04);
    cfg->dword_070 = wcry_rd32(buf, 0x70);
    cfg->dword_074 = wcry_rd32(buf, 0x74);
    cfg->dword_078 = wcry_rd32(buf, 0x78);
    wcry_copy_sz(cfg->btc_addr, sizeof(cfg->btc_addr),
                 buf, WCRY_CFG_OFF_BTC, len);
    wcry_copy_sz(cfg->onion_pool, sizeof(cfg->onion_pool),
                 buf, WCRY_CFG_OFF_ONION, len);
    wcry_copy_sz(cfg->tor_url, sizeof(cfg->tor_url),
                 buf, WCRY_CFG_OFF_TOR, len);
    return 1;
}

/* ------------------------------------------------------------------ */
/* t.wnry "WANACRY!" header parse [004014a6 ReadTwnry front half].     */
/* Pure parse only — no decrypt, no allocation of the payload.         */
/* ------------------------------------------------------------------ */
typedef struct {
    int      ok;
    char     magic[9];
    uint32_t blobLen;         /* @0x08 — must be 0x100               */
    uint32_t unusedField;     /* @0x10C — read, never used (W2)      */
    uint64_t payloadSize;     /* @0x110 — u64, low dword used        */
    size_t   payloadOff;      /* 0x118                               */
} WcryTwnryHeader;

static int wcry_twnry_parse_header(const uint8_t *buf, size_t len,
                                   WcryTwnryHeader *h)
{
    memset(h, 0, sizeof(*h));
    if (len < WCRY_TWNRY_OFF_PAYLOAD) return 0;
    memcpy(h->magic, buf, 8);
    h->magic[8]    = '\0';
    h->blobLen     = wcry_rd32(buf, WCRY_TWNRY_OFF_BLOBLEN);
    h->unusedField = wcry_rd32(buf, WCRY_TWNRY_OFF_UNUSED);
    h->payloadSize = (uint64_t)wcry_rd32(buf, WCRY_TWNRY_OFF_SIZE) |
                     ((uint64_t)wcry_rd32(buf, WCRY_TWNRY_OFF_SIZE + 4) << 32);
    h->payloadOff  = WCRY_TWNRY_OFF_PAYLOAD;
    h->ok = (memcmp(h->magic, WCRY_MAGIC, 8) == 0) &&   /* 00401564 */
            (h->blobLen == 0x100u);                     /* 00401582 */
    return h->ok;
}

/* ------------------------------------------------------------------ */
/* RSA PRIVATEKEYBLOB struct walk (evidence blob @exe 0xEBF8, 0x494 B).*/
/* Layout: PUBLICKEYSTRUC{bType,bVersion,reserved,aiKeyAlg} (8 B) +    */
/* RSAPUBKEY{magic "RSA2",bitlen,pubexp} (12 B) + modulus(bitlen/8) +  */
/* prime1,prime2,exp1,exp2,coefficient (bitlen/16 each) +              */
/* privateExponent (bitlen/8). 2048-bit => 1172 = 0x494 total.         */
/* Parse + offsets only — key material is never written out.           */
/* ------------------------------------------------------------------ */
typedef struct {
    int      ok;
    uint8_t  bType;        /* 0x07 PRIVATEKEYBLOB                */
    uint8_t  bVersion;     /* 0x02                               */
    uint16_t reserved;
    uint32_t aiKeyAlg;     /* 0x0000A400 CALG_RSA_KEYX           */
    uint32_t magic;        /* 'RSA2' = 0x32415352                */
    uint32_t bitlen;       /* 0x800 = 2048                       */
    uint32_t pubexp;       /* 0x10001 = 65537                    */
    size_t   off_modulus, off_prime1, off_prime2, off_exp1;
    size_t   off_exp2, off_coeff, off_privexp;
    size_t   len_modulus, len_half;
    size_t   total;        /* 0x494                              */
} WcryRsaBlob;

static int wcry_rsablob_parse(const uint8_t *b, size_t len, WcryRsaBlob *o)
{
    memset(o, 0, sizeof(*o));
    if (len < 20) return 0;
    o->bType    = b[0];
    o->bVersion = b[1];
    o->reserved = (uint16_t)(b[2] | (b[3] << 8));
    o->aiKeyAlg = wcry_rd32(b, 4);
    o->magic    = wcry_rd32(b, 8);
    o->bitlen   = wcry_rd32(b, 12);
    o->pubexp   = wcry_rd32(b, 16);
    o->ok = (o->bType == 0x07) && (o->bVersion == 0x02) &&
            (o->aiKeyAlg == 0x0000A400u) &&
            (o->magic == 0x32415352u /* 'RSA2' */) &&
            (o->bitlen == 0x0800u) && (o->pubexp == 0x10001u);
    o->len_modulus = o->bitlen / 8;
    o->len_half    = o->bitlen / 16;
    o->off_modulus = 20;
    o->off_prime1  = o->off_modulus + o->len_modulus;      /*  276 */
    o->off_prime2  = o->off_prime1  + o->len_half;         /*  404 */
    o->off_exp1    = o->off_prime2  + o->len_half;         /*  532 */
    o->off_exp2    = o->off_exp1    + o->len_half;         /*  660 */
    o->off_coeff   = o->off_exp2    + o->len_half;         /*  788 */
    o->off_privexp = o->off_coeff   + o->len_half;         /*  916 */
    o->total       = o->off_privexp + o->len_modulus;      /* 1172 */
    if (!o->ok || o->total != len) { o->ok = 0; return 0; }
    return 1;
}

/* ------------------------------------------------------------------ */
/* RVA -> file offset math (resource-offset check). Matching rule per  */
/* section: rva in [va, va + max(vsz, rsz)) => raw + (rva - va).       */
/* ------------------------------------------------------------------ */
typedef struct { uint32_t rva, raw, vsz, rsz; } WcrySection;

static long wcry_rva_to_offset(uint32_t rva, const WcrySection *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        uint32_t span = (s[i].vsz > s[i].rsz) ? s[i].vsz : s[i].rsz;
        if (rva >= s[i].rva && rva - s[i].rva < span)
            return (long)(s[i].raw + (rva - s[i].rva));
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* 00401B5F — workdir candidate chain (pure path computation; the      */
/* create/cd/attr side is a stubbed Win32 concern in dropper.cpp).     */
/*   <windir>\ProgramData  only if that dir already exists             */
/*   <windir>\Intel                                                    */
/*   <windir>                                                          */
/*   %TEMP% with the trailing '\' stripped (00401c9c..00401cbd)        */
/* out: 4 slots of >=260 bytes; returns candidate count.               */
/* ------------------------------------------------------------------ */
#define WCRY_WD_MAX 4
#define WCRY_WD_SLOT 260

static void wcry_join(char *dst, size_t cap, const char *a, const char *b)
{
    size_t i = 0, j;
    while (i + 1 < cap && a[i] != '\0') { dst[i] = a[i]; i++; }
    if (i + 1 < cap && i > 0 && a[i - 1] != '\\' && b[0] != '\0')
        dst[i++] = '\\';
    for (j = 0; i + 1 < cap && b[j] != '\0'; j++, i++) dst[i] = b[j];
    dst[i] = '\0';
}

static int wcry_workdir_candidates(const char *windir, const char *tempdir,
                                   int programDataExists,
                                   char out[WCRY_WD_MAX][WCRY_WD_SLOT])
{
    int n = 0;
    if (programDataExists) {                                   /* 00401c04 */
        wcry_join(out[n], WCRY_WD_SLOT, windir, "ProgramData");
        n++;
    }
    wcry_join(out[n], WCRY_WD_SLOT, windir, "Intel");          /* 00401c4d */
    n++;
    wcry_join(out[n], WCRY_WD_SLOT, windir, "");               /* 00401c83 */
    n++;
    {   /* GetTempPathW keeps the trailing backslash; strip one */ /* 00401cac */
        char tmp[WCRY_WD_SLOT];
        size_t l;
        wcry_copy_sz(tmp, sizeof(tmp), (const uint8_t *)tempdir,
                     0, strlen(tempdir));
        l = strlen(tmp);
        if (l > 1 && tmp[l - 1] == '\\') tmp[l - 1] = '\0';
        wcry_copy_sz(out[n], WCRY_WD_SLOT, (const uint8_t *)tmp, 0, l);
        n++;
    }
    return n;
}

/* Mutex name the launcher WAITS for: sprintf("%s%d", base, 0)         */
/* [00401eff] => "Global\MsWinZonesCacheCounterMutexA0".               */
static void wcry_mutex_name(char *out /* >= 64 */)
{
    strcpy(out, WCRY_MUTEX_FULL);
}

/* Arg gate [00402020]: install mode iff argc==2 && argv[1]=="/i".     */
static int wcry_is_install_arg(const char *a)
{
    return a != NULL && strcmp(a, WCRY_ARG_INSTALL) == 0;
}

#endif /* WCRY_DROPPER_CORE_H */
