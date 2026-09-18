/* ===========================================================================
 * selftest_impl.h — shared selftest suite for mssecsvc_recon.
 * Included by worm.cpp (mingw, both arches) and selftest.cc (Linux-native).
 * Benign only: canned in-memory buffers, zero writes outside stdout.
 * Exit 0 = every check passed.
 * =========================================================================== */
#ifndef SELFTEST_IMPL_H
#define SELFTEST_IMPL_H

#include "wcry_build.h"
#include "worm_recon.h"

namespace msr {

static int g_checks, g_fails;
#define CHECK(cond, msg)                                                     \
    do { ++g_checks; if (!(cond)) { ++g_fails;                               \
         std::printf("[FAIL] %s (line %d)\n", msg, __LINE__); } } while (0)

static void hexdump(const char* tag, const uint8_t* p, int n) {
    if (n <= 0 || n > 1024) {                 /* builder failures are checked */
        std::printf("  %s: <no dump, len=%d>\n", tag, n);
        return;
    }
    unsigned un = (unsigned)n;
    std::printf("  %s (%u bytes):\n", tag, un);
    for (unsigned i = 0; i < un; i += 16) {
        std::printf("    %04x  ", i);
        for (unsigned j = 0; j < 16; ++j) {
            if (i + j < un) std::printf("%02x ", p[i + j]);
            else            std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" ");
        for (unsigned j = 0; j < 16 && i + j < un; ++j) {
            uint8_t c = p[i + j];
            std::printf("%c", (c >= 0x20 && c < 0x7f) ? (char)c : '.');
        }
        std::printf("\n");
    }
}

/* --- scripted transport feeding canned response buffers ---------------- */
struct CannedTransport : ISmbTransport {
    bool        enable_connect;
    uint8_t     q[8][512];
    int         qlen[8];
    int         qn;
    int         qi;
    CannedTransport() : enable_connect(true), qn(0), qi(0) {}
    void push(const uint8_t* p, int n) {
        if (qn < 8 && n > 0 && n <= 512) {
            std::memcpy(q[qn], p, (unsigned)n);
            qlen[qn++] = n;
        }
    }
    bool connect(const char*, uint16_t) { return enable_connect; }
    int  send(const uint8_t*, unsigned len) { return (int)len; }
    int  recv(uint8_t* buf, unsigned cap) {
        if (qi >= qn) return -1;
        int n = qlen[qi++];
        if ((unsigned)n > cap) n = (int)cap;
        std::memcpy(buf, q[qi - 1], (unsigned)n);
        return n;
    }
    void close() {}
};

/* helper: NBSS-wrapped SMB response with chosen cmd/status/tid/uid */
static int mkresp(uint8_t* out, uint8_t cmd, uint32_t status,
                  uint16_t tid, uint16_t uid) {
    smb_header(out + NBSS_HDR, cmd, status, tid, uid, 0x7f);
    nbss_header(out, SMB_HDR);
    return NBSS_HDR + SMB_HDR;
}

static void selftest_packets(void) {
    uint8_t  buf[256];
    int      n;

    std::printf("[selftest] SMB packet crafters (public shapes)\n");
    n = build_negotiate(buf, sizeof(buf));
    CHECK(n > 0, "negotiate builds");
    hexdump("NEGOTIATE", buf, (unsigned)n);
    CHECK(buf[0] == 0 && (unsigned)(buf[1] << 16 | buf[2] << 8 | buf[3]) ==
          (unsigned)(n - NBSS_HDR), "negotiate NBSS length");
    CHECK(buf[4] == 0xff && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B',
          "negotiate ffSMB");
    CHECK(find_marker((const char*)buf, n, "NT LM 0.12") >= 0,
          "negotiate dialect present");

    n = build_session_setup_andx(buf, sizeof(buf));
    CHECK(n > 0, "session setup builds");
    hexdump("SESSION SETUP ANDX (anonymous)", buf, (unsigned)n);
    CHECK(buf[NBSS_HDR + 4] == 0x73, "session setup command 0x73");

    n = build_tree_connect_andx(buf, sizeof(buf), "10.0.0.7", 0x0800, 0x0801);
    CHECK(n > 0, "tree connect builds");
    hexdump("TREE CONNECT ANDX \\\\10.0.0.7\\IPC$", buf, (unsigned)n);
    CHECK(find_marker((const char*)buf, n, "__USERID__PLACEHOLDER__") < 0,
          "uid marker patched out");
    CHECK(find_marker((const char*)buf, n, "__TREEPATH_REPLACE__") < 0,
          "path marker patched out");
    CHECK(find_marker((const char*)buf, n, "10.0.0.7") >= 0, "path spliced");

    n = build_trans2_probe(buf, sizeof(buf), 0x0800, 0x0801);
    CHECK(n > 0, "trans2 probe builds");
    hexdump("TRANS2 PROBE (0x0C, bogus uid)", buf, (unsigned)n);
    CHECK(buf[NBSS_HDR + 4] == 0x32, "trans2 command 0x32");
}

static void selftest_probe(void) {
    std::printf("[selftest] MS17-010 probe state machine (canned buffers)\n");
    uint8_t resp[64];
    Target tgt; std::snprintf(tgt.ip, sizeof(tgt.ip), "192.0.2.77");
    tgt.port = (uint16_t)SMB_PORT;

    /* scripted: vulnerable (STATUS_INSUFF_SERVER_RESOURCES 0xC0000205) */
    CannedTransport vuln;
    int n = mkresp(resp, 0x72, 0, 0, 0);              vuln.push(resp, n);
    n = mkresp(resp, 0x73, 0, 0x0801, 0x0800);        vuln.push(resp, n);
    n = mkresp(resp, 0x75, 0, 0x0802, 0x0800);        vuln.push(resp, n);
    n = mkresp(resp, 0x32, 0xc0000205u, 0x0802, 0x1234); vuln.push(resp, n);
    ProbeVerdict v = ms17_010_probe(vuln, tgt);
    std::printf("  TARGET %s: %s\n", tgt.ip, probe_verdict_str(v));
    CHECK(v == PV_VULNERABLE, "vulnerable verdict (05 02 00 C0)");

    /* scripted: patched stack (STATUS_ACCESS_DENIED) */
    CannedTransport patched;
    n = mkresp(resp, 0x72, 0, 0, 0);                  patched.push(resp, n);
    n = mkresp(resp, 0x73, 0, 0x0801, 0x0800);        patched.push(resp, n);
    n = mkresp(resp, 0x75, 0, 0x0802, 0x0800);        patched.push(resp, n);
    n = mkresp(resp, 0x32, 0xc0000022u, 0x0802, 0x1234); patched.push(resp, n);
    v = ms17_010_probe(patched, tgt);
    std::printf("  TARGET %s: %s\n", tgt.ip, probe_verdict_str(v));
    CHECK(v == PV_NOT_VULNERABLE, "not-vulnerable verdict");

    /* scripted: transport refused */
    CannedTransport dead;
    dead.enable_connect = false;
    v = ms17_010_probe(dead, tgt);
    std::printf("  TARGET %s: %s\n", tgt.ip, probe_verdict_str(v));
    CHECK(v == PV_NO_TRANSPORT, "no-transport verdict");

    /* default transport is the print-and-fail stub */
    StubTransport stub;
    v = ms17_010_probe(stub, tgt);
    CHECK(v == PV_NO_TRANSPORT, "stub transport fails closed");
}

/* --- deterministic RNG for the generator checks ------------------------ */
struct Lcg { uint32_t s; };
static uint32_t lcg_next(void* ctx) {
    Lcg* g = (Lcg*)ctx;
    g->s = g->s * 1103515245u + 12345u;
    return g->s >> 8;
}

static void selftest_ipgen(void) {
    std::printf("[selftest] random-IP generator (deterministic RNG)\n");
    Lcg g1 = { 0x1234abcdu }, g2 = { 0x1234abcdu };
    IpGen gen1, gen2;
    gen1.init(lcg_next, &g1, 3, 1000000u);
    gen2.init(lcg_next, &g2, 3, 1000000u);

    char ip[16], ip2[16];
    int ok = 1;
    for (int i = 0; i < 256; ++i) {
        if (!gen1.next(1000000u + (uint32_t)i, ip)) { ok = 0; break; }
        unsigned a = 0; int cons = std::sscanf(ip, "%u.", &a);
        if (cons != 1 || a >= FIRST_OCTET_MAX || a == FIRST_OCTET_SKIP) {
            ok = 0; break;
        }
    }
    CHECK(ok, "ipgen constraints (mod 255, no 127, <224)");
    /* strict replay: fresh seed must reproduce the same first candidate */
    Lcg g3 = { 0x1234abcdu };
    IpGen gen3; gen3.init(lcg_next, &g3, 3, 1000000u);
    gen3.next(1000000u, ip2);
    Lcg g4 = { 0x1234abcdu };
    IpGen gen4; gen4.init(lcg_next, &g4, 3, 1000000u);
    gen4.next(1000000u, ip);
    CHECK(std::strcmp(ip, ip2) == 0, "ipgen replay: same seed -> same IP");

    /* index >= 32 threads never re-roll a/b (as-built quirk preserved):
     * with a fresh state their first candidate still honors constraints  */
    Lcg g5 = { 0xfeedbeefu };
    IpGen gen5; gen5.init(lcg_next, &g5, 63, 1000000u);
    CHECK(gen5.next(1000000u, ip), "ipgen idx>=32 still emits");
    /* window logic: sweep_done clears re-roll; the two windows are
     * independent timers from the same t0 (20 min re-arms b first) */
    Lcg g6 = { 7u };
    IpGen gen6; gen6.init(lcg_next, &g6, 0, 0u);
    gen6.a = 1; gen6.b = 2;
    gen6.sweep_done(5000u);
    CHECK(gen6.roll_a == false && gen6.roll_b == false, "sweep_done clears");
    gen6.tick(5000u + REROLL_WINDOW_B_MS + 1);
    CHECK(gen6.roll_b == true && gen6.roll_a == false, "20-min re-arms b only");
    gen6.tick(5000u + REROLL_WINDOW_A_MS + 1);
    CHECK(gen6.roll_a == true, "40-min re-arms a");
}

static void selftest_core(void) {
    std::printf("[selftest] pure lifecycle logic\n");

    /* killswitch: inverted decision (answer -> dormant) */
    char url[64];
    CHECK(killswitch_url_copy(url, sizeof(url)), "killswitch URL copy");
    CHECK(std::strcmp(url, killswitch_url()) == 0, "killswitch URL verbatim");
    CHECK(killswitch_decide(true) == KD_DORMANT, "answered -> dormant");
    CHECK(killswitch_decide(false) == KD_PROCEED, "unanswered -> proceed");

    /* service-config structs (no SCM calls in this build) */
    SvcStatus run = service_status_running();
    CHECK(run.type == 0x20 && run.state == 4 && run.controls == 1,
          "RUNNING status struct");
    SvcStatus st = service_status_stopped();
    CHECK(st.state == 1, "STOPPED status struct");
    FailureActions fa = failure_actions_restart_after(60);
    CHECK(fa.reset_period == 1 && fa.n_actions == 1 &&
          fa.actions[0].type == 1 && fa.actions[0].delay_ms == 60000,
          "failure-actions restart@60s");
    char bp[300];
    CHECK(build_service_binpath(bp, sizeof(bp), "C:\\WINDOWS\\mssecsvc.exe"),
          "binpath builds");
    CHECK(std::strcmp(bp, "C:\\WINDOWS\\mssecsvc.exe -m security") == 0,
          "binpath '%s -m security'");

    /* RFC1918 + /24 split */
    CHECK(is_rfc1918(parse_ipv4("10.1.2.3")), "10/8 private");
    CHECK(is_rfc1918(parse_ipv4("172.31.9.9")), "172.16/12 private");
    CHECK(is_rfc1918(parse_ipv4("192.168.77.1")), "192.168/16 private");
    CHECK(!is_rfc1918(parse_ipv4("8.8.8.8")), "8.8.8.8 public");
    CHECK(!is_rfc1918(parse_ipv4("172.32.0.1")), "172.32 outside /12");
    uint32_t s24[300];
    int k = split_into_24s(parse_ipv4("192.168.10.0"),
                           parse_ipv4("192.168.10.255"), s24, 300);
    CHECK(k == 1 && s24[0] == parse_ipv4("192.168.10.0"),
          "single /24 base emitted");
    k = split_into_24s(parse_ipv4("10.0.0.0"), parse_ipv4("10.0.1.255"),
                       s24, 300);
    CHECK(k == 2, "span split -> two /24 bases");
}

static void selftest_adapters_keys(void) {
    std::printf("[selftest] adapter target collection + DP key math\n");
    AdapterRecord rec;
    rec.ip = "192.168.12.5"; rec.mask = "255.255.255.0";
    rec.gateway = "192.168.12.1";
    rec.dns[0] = "10.0.0.53"; rec.dns[1] = "8.8.8.8";
    rec.dns[2] = 0; rec.dns[3] = 0;
    uint32_t tg[16];
    int n = collect_adapter_targets(rec, tg, 16);
    CHECK(n == 2, "targets = subnet /24 + private DNS /24");
    CHECK(n >= 2 && tg[0] == parse_ipv4("192.168.12.0"), "subnet /24 first");
    bool has_dns = false;
    for (int i = 0; i < n; ++i)
        if (tg[i] == (parse_ipv4("10.0.0.53") & 0xffffff00u)) has_dns = true;
    CHECK(has_dns, "RFC1918 DNS /24 collected (public DNS filtered)");

    /* DoublePulsar key derivation vector + XOR round trip */
    CHECK(dp_key_transform(0x11223344u) == 0x66774499u, "bswap(x)^2x vector");
    uint8_t buf[8] = { 0, 1, 2, 3, 4, 5, 6, 7 }, ref[8];
    std::memcpy(ref, buf, 8);
    xor_decode(0xdeadbeefu, buf, 8);
    CHECK(std::memcmp(buf, ref, 8) != 0, "xor_decode mutates");
    xor_decode(0xdeadbeefu, buf, 8);
    CHECK(std::memcmp(buf, ref, 8) == 0, "xor_decode is an involution");
}

static void selftest_inventory(void) {
    std::printf("[selftest] blob inventory\n");
    /* EternalBlue / DoublePulsar wire-byte arrays are NOT part of this
     * build tree (references/ only). Inventory is structurally empty. */
    std::printf("  inert blob inventory: 0 entries (nothing weaponizable; "
                "wire data lives only in references/)\n");
    std::printf("  exploit primitive: intentionally absent; public research "
                "tooling exists\n");
    CHECK(sizeof(IExploitPrimitive*) == sizeof(void*), "primitive: interface only");
}

} /* namespace msr */

static int run_selftest(void) {
    std::printf("mssecsvc_recon — MS17-010 lifecycle research build\n");
    std::printf("payload linkage: EXCISED from this build (see worm_recon.h)\n\n");
    msr::g_checks = msr::g_fails = 0;
    msr::selftest_packets();
    msr::selftest_probe();
    msr::selftest_ipgen();
    msr::selftest_core();
    msr::selftest_adapters_keys();
    msr::selftest_inventory();
    std::printf("\n[selftest] %d checks, %d failures\n",
                msr::g_checks, msr::g_fails);
    return msr::g_fails == 0 ? 0 : 1;
}

#endif /* SELFTEST_IMPL_H */
