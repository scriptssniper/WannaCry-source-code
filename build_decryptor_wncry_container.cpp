// wncry_container.cpp — pure parsers for the WANACRY! container format,
// extension classification, and CryptoAPI RSA PRIVATEKEYBLOB structure.
// See wncry_container.h for format citations (function_map.md S1/S2,
// REVIEW.md claims 13/14). No file IO, no cryptographic operations.
#include <stdio.h>
#include <string.h>
#include "wncry_container.h"

// ---- little-endian scalar loads -------------------------------------------
static u32 ld32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

// ---- 1. container header --------------------------------------------------

int wcry_parse_header(const u8 *buf, u32 bufLen, wcry_header_t *out)
{
    if (!buf || !out) return -1;
    if (bufLen < 0x118) return -2;                       // fixed header = 0x118
    if (memcmp(buf, "WANACRY!", 8) != 0) return -3;      // magic @0x4200e4
    memset(out, 0, sizeof *out);
    memcpy(out->magic, buf, 8);
    out->rsaLen = ld32(buf + 0x08);
    if (out->rsaLen != 0x100) return -4;
    memcpy(out->rsaCt, buf + 0x0C, 0x100);
    out->fileType  = ld32(buf + 0x10C);
    out->origSize  = (u64)ld32(buf + 0x110) | ((u64)ld32(buf + 0x114) << 32);
    out->payloadOff = 0x118;
    out->payloadLen = bufLen - 0x118;
    return 0;
}

void wcry_header_print(const wcry_header_t *h)
{
    int i;
    printf("  magic       : %s\n", h->magic);
    printf("  rsaLen      : 0x%08X (%u)\n", h->rsaLen, h->rsaLen);
    printf("  rsaCt[0..7] :");
    for (i = 0; i < 8; i++) printf(" %02X", h->rsaCt[i]);
    printf("\n");
    printf("  fileType    : %u (%s)\n", h->fileType, wcry_filetype_name(h->fileType));
    printf("  origSize    : %u (lo=0x%08X hi=0x%08X)\n",
           (unsigned)(h->origSize & 0xFFFFFFFFu),
           (unsigned)(h->origSize & 0xFFFFFFFFu),
           (unsigned)(h->origSize >> 32));
    printf("  payload     : @0x%X, %u bytes (AES-128-CBC, NULL IV)\n",
           h->payloadOff, h->payloadLen);
}

const char *wcry_filetype_name(u32 fileType)
{
    switch (fileType) {
    case 3:  return "tail-swap recoverable, no AES (.WNCYR)";
    case 1:  return "full AES-128-CBC container (.WNCRY)";
    default: return "unknown (non-3 takes the AES lane in the original)";
    }
}

// ---- 2. extension classification ------------------------------------------

static int ieq_suffix(const char *a, const char *b)   // case-insensitive ASCII
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

wcry_ext_t wcry_classify_extension(const char *path)
{
    const char *dot;
    if (!path) return WCRY_EXT_NONE;
    dot = strrchr(path, '.');
    if (!dot) return WCRY_EXT_NONE;
    if (ieq_suffix(dot, ".wncry"))  return WCRY_EXT_WNCRY;
    if (ieq_suffix(dot, ".wncyr"))  return WCRY_EXT_WNCYR;
    if (ieq_suffix(dot, ".wncryt")) return WCRY_EXT_WNCRYT;
    return WCRY_EXT_NONE;
}

const char *wcry_ext_name(wcry_ext_t e)
{
    switch (e) {
    case WCRY_EXT_WNCRY:  return ".WNCRY (full container)";
    case WCRY_EXT_WNCYR:  return ".WNCYR (tail-recoverable)";
    case WCRY_EXT_WNCRYT: return ".WNCRYT (in-progress temp)";
    default:              return "(not a WannaCry extension)";
    }
}

int wcry_ext_strip_on_decrypt(wcry_ext_t e)
{
    return (e == WCRY_EXT_WNCRY || e == WCRY_EXT_WNCYR) ? 1 : 0;
}

// ---- 3. RSA PRIVATEKEYBLOB struct walk ------------------------------------

int wcry_walk_rsa_privatekeyblob(const u8 *blob, u32 len,
                                 wcry_rsablob_t *o, int verbose)
{
    u32 hb, hh, off;

    if (!blob || !o) return -1;
    if (len < 20) return -2;                     // BLOBHEADER + RSAPubKey head

    o->bType    = blob[0];
    o->bVersion = blob[1];
    o->reserved = (u16)((u16)blob[2] | ((u16)blob[3] << 8));
    o->aiKeyAlg = ld32(blob + 4);
    memcpy(o->magic, blob + 8, 4);
    o->magic[4] = 0;
    o->bitLen   = ld32(blob + 12);
    o->pubExp   = ld32(blob + 16);

    if (o->bitLen == 0 || (o->bitLen % 16) != 0) return -3;

    hb = o->bitLen / 8;                          // full-size components
    hh = o->bitLen / 16;                         // half-size components
    off = 20;
    o->modOff = off; o->modLen = hb; off += hb;  // modulus
    o->p1Off  = off; o->p1Len  = hh; off += hh;  // prime1
    o->p2Off  = off; o->p2Len  = hh; off += hh;  // prime2
    o->e1Off  = off; o->e1Len  = hh; off += hh;  // exponent1
    o->e2Off  = off; o->e2Len  = hh; off += hh;  // exponent2
    o->cOff   = off; o->cLen   = hh; off += hh;  // coefficient
    o->dOff   = off; o->dLen   = hb; off += hb;  // privateExponent
    o->totalExpected = off;

    if (verbose) {
        printf("  BLOBHEADER : bType=0x%02X bVersion=%u reserved=0x%04X aiKeyAlg=0x%08X\n",
               o->bType, o->bVersion, o->reserved, o->aiKeyAlg);
        printf("  RSAPubKey  : magic=\"%s\" bitLen=%u pubExp=%u (0x%X)\n",
               o->magic, o->bitLen, o->pubExp, o->pubExp);
        printf("  components : modulus@%u(%u) prime1@%u(%u) prime2@%u(%u)\n"
               "               exp1@%u(%u) exp2@%u(%u) coeff@%u(%u) privExp@%u(%u)\n",
               o->modOff, o->modLen, o->p1Off, o->p1Len, o->p2Off, o->p2Len,
               o->e1Off, o->e1Len, o->e2Off, o->e2Len, o->cOff, o->cLen,
               o->dOff, o->dLen);
        printf("  total      : %u (0x%X) bytes\n", o->totalExpected, o->totalExpected);
    }

    if (o->totalExpected != len) return 1;       // structurally parsed, size off
    if (o->bType != 0x07 || o->bVersion != 0x02) return 1;
    if (o->aiKeyAlg != 0x0000A400u) return 1;    // CALG_RSA_KEYX
    if (memcmp(o->magic, "RSA2", 4) != 0) return 1;
    return 0;
}
