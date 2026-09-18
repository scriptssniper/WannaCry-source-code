// wse_logic.h — taskse.exe (launcher) portable logic, shared verbatim by the
// mingw build (taskse.cpp) and the native selftest (selftest.cc), so both run
// the SAME checks (build/README.md policy).
//
// REAL (unstubbed) logic per build/README.md:
//   - privilege-name lookup table [mirrors LookupPrivilegeValueA(NULL, name,
//     &luid); original .data string "SeTcbPrivilege" @ 0x00403020]
//   - session-number parse [LaunchInSession arg2, 0x00401278: (DWORD)-1
//     sentinel -> WTSGetActiveConsoleSessionId]
//   - quote-aware argv split [CRT _acmdln handling; WinMain 0x00401510 reads
//     __p___argc/__p___argv and gates on argc < 2]
//   - wide-path handling of the launch target [argv[1] consumed as the
//     lpApplicationName form, 0x00401353]
//
// Everything here is static and exercised by wse_run_selftest(), so no TU
// carries an unused-function warning under -Wall -Wextra.
//
// Weaponization policy: NO token/proc/env APIs live here — see taskse.cpp.
#ifndef WSE_LOGIC_H
#define WSE_LOGIC_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* Sentinel used by the original for "ask WTSGetActiveConsoleSessionId". */
#define WSE_SESSION_CONSOLE 0xFFFFFFFFul

/* -------------------------------------------------------------------------
 * Privilege constant table — well-known NT LUIDs (winnt.h SE_*_LUID values).
 * LookupPrivilegeValueA(NULL, name, &luid) is what the original calls with
 * "SeTcbPrivilege"; the name->LUID mapping is table-driven system constants,
 * reproduced here as pure data so the lookup logic is testable natively.
 * ---------------------------------------------------------------------- */
typedef struct { unsigned long lo; unsigned long hi; } WseLuid;
typedef struct { const char *name; WseLuid luid; } WsePrivEntry;

static const WsePrivEntry WSE_PRIVILEGES[] = {
    { "SeCreateTokenPrivilege",           {  2, 0 } },
    { "SeAssignPrimaryTokenPrivilege",    {  3, 0 } },
    { "SeLockMemoryPrivilege",            {  4, 0 } },
    { "SeIncreaseQuotaPrivilege",         {  5, 0 } },
    { "SeMachineAccountPrivilege",        {  6, 0 } },
    { "SeTcbPrivilege",                   {  7, 0 } },  /* 0x00403020 — launcher target */
    { "SeSecurityPrivilege",              {  8, 0 } },
    { "SeTakeOwnershipPrivilege",         {  9, 0 } },
    { "SeLoadDriverPrivilege",            { 10, 0 } },
    { "SeSystemProfilePrivilege",         { 11, 0 } },
    { "SeSystemtimePrivilege",            { 12, 0 } },
    { "SeProfileSingleProcessPrivilege",  { 13, 0 } },
    { "SeIncreaseBasePriorityPrivilege",  { 14, 0 } },
    { "SeCreatePagefilePrivilege",        { 15, 0 } },
    { "SeCreatePermanentPrivilege",       { 16, 0 } },
    { "SeBackupPrivilege",                { 17, 0 } },
    { "SeRestorePrivilege",               { 18, 0 } },
    { "SeShutdownPrivilege",              { 19, 0 } },
    { "SeDebugPrivilege",                 { 20, 0 } },
    { "SeAuditPrivilege",                 { 21, 0 } },
    { "SeSystemEnvironmentPrivilege",     { 22, 0 } },
    { "SeChangeNotifyPrivilege",          { 23, 0 } },
    { "SeRemoteShutdownPrivilege",        { 24, 0 } },
    { "SeUndockPrivilege",                { 25, 0 } },
    { "SeSyncAgentPrivilege",             { 26, 0 } },
    { "SeEnableDelegationPrivilege",      { 27, 0 } },
    { "SeManageVolumePrivilege",          { 28, 0 } },
    { "SeImpersonatePrivilege",           { 29, 0 } },
    { "SeCreateGlobalPrivilege",          { 30, 0 } },
    { "SeTrustedCredManAccessPrivilege",  { 31, 0 } },
    { "SeRelabelPrivilege",               { 32, 0 } },
    { "SeIncreaseWorkingSetPrivilege",    { 33, 0 } },
    { "SeTimeZonePrivilege",              { 34, 0 } },
    { "SeCreateSymbolicLinkPrivilege",    { 35, 0 } },
};

#define WSE_PRIV_COUNT (sizeof(WSE_PRIVILEGES) / sizeof(WSE_PRIVILEGES[0]))

static int wse_ci_eq(const char *a, const char *b)  /* case-insensitive strcmp */
{
    while (*a != '\0' && *b != '\0') {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

/* [mirrors LookupPrivilegeValueA] 1 = found, 0 = not a privilege name */
static int wse_lookup_privilege(const char *name, WseLuid *out)
{
    size_t i;
    if (name == NULL || name[0] == '\0')
        return 0;
    for (i = 0; i < WSE_PRIV_COUNT; i++) {
        if (wse_ci_eq(WSE_PRIVILEGES[i].name, name)) {
            if (out != NULL)
                *out = WSE_PRIVILEGES[i].luid;
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Session-number parse. The original takes dwSessionId as a raw DWORD with
 * (DWORD)-1 = "use the active console session" (0x00401278). This adds only
 * the string form the CRT argv would carry; behavior is identical.
 * strict full-string decimal; "-1"/"console" (any case) -> sentinel.
 * ---------------------------------------------------------------------- */
static int wse_parse_session(const char *s, unsigned long *out)
{
    const char *p;
    unsigned long long acc = 0;

    if (s == NULL || s[0] == '\0')
        return 0;
    if (wse_ci_eq(s, "console")) {                 /* documented alias */
        *out = WSE_SESSION_CONSOLE;
        return 1;
    }
    if (s[0] == '-' && s[1] != '\0') {             /* "-1" sentinel (and only that) */
        if (wse_ci_eq(s, "-1")) {
            *out = WSE_SESSION_CONSOLE;
            return 1;
        }
        return 0;
    }
    for (p = s; *p != '\0'; p++) {
        if (*p < '0' || *p > '9')
            return 0;
        acc = acc * 10ull + (unsigned long long)(*p - '0');
        if (acc > 0xFFFFFFFFull)
            return 0;
    }
    *out = (unsigned long)acc;                     /* 0xFFFFFFFF == sentinel, as in the binary */
    return 1;
}

/* -------------------------------------------------------------------------
 * Quote-aware argv split — the CRT __getmainargs rules the original relies
 * on (it reads __p___argc/__p___argv directly at 0x00401510):
 *   2n backslashes + '"'  -> n backslashes, toggle quoting
 *   2n+1 backslashes + '"'-> n backslashes + literal '"'
 * Tokens are copied into buf; pointers land in argv. Returns token count,
 * or -1 on capacity overflow. argc<2 is the original's no-op gate (0x401516).
 * ---------------------------------------------------------------------- */
static int wse_cmdline_split(const char *cmd, char *buf, size_t bufCap,
                             char **argv, int argvMax)
{
    const char *p = cmd;
    size_t used = 0;
    int n = 0;

    if (cmd == NULL || buf == NULL || argv == NULL)
        return -1;

    while (*p != '\0') {
        int inq = 0;
        size_t bs = 0;                             /* pending backslash run */

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;
        if (n >= argvMax)
            return -1;
        argv[n++] = buf + used;

        while (*p != '\0') {
            char c = *p;
            if (c == '\\') { bs++; p++; continue; }
            if (c == '"') {
                size_t emit = bs / 2;              /* floor */
                if (used + emit + 2 > bufCap) return -1;
                while (emit > 0) { buf[used++] = '\\'; emit--; }
                if (bs % 2 == 0) inq = !inq;       /* even: toggle */
                else { buf[used++] = '"'; }        /* odd: literal quote */
                bs = 0; p++; continue;
            }
            if (!inq && (c == ' ' || c == '\t'))
                break;
            if (used + bs + 2 > bufCap) return -1;
            while (bs > 0) { buf[used++] = '\\'; bs--; }
            buf[used++] = c;
            p++;
        }
        if (used + bs + 1 > bufCap) return -1;
        while (bs > 0) { buf[used++] = '\\'; bs--; }
        buf[used++] = '\0';
    }
    return n;
}

/* -------------------------------------------------------------------------
 * Wide-path handling of the launch target (argv[1] -> lpApplicationName).
 * ---------------------------------------------------------------------- */
static int wse_widen_path(const char *in, wchar_t *out, size_t cap)
{
    const char *p;
    size_t n = 0;

    if (in == NULL || out == NULL || cap == 0)
        return 0;
    for (p = in; *p != '\0'; p++) {
        if (n + 1 >= cap)
            return 0;
        out[n++] = (wchar_t)(unsigned char)*p;
    }
    out[n] = L'\0';
    return n != 0;
}

/* absolute = "X:..." drive form (any case letter) or UNC "\\\\..." */
static int wse_is_absolute_path_w(const wchar_t *p)
{
    if (p == NULL)
        return 0;
    if (p[0] == L'\\' && p[1] == L'\\')
        return 1;
    if (((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) &&
        p[1] == L':')
        return 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Selftest — the exact benign no-arg run of taskse.exe (build policy: exit 0
 * on success, zero writes outside stdout).
 * ---------------------------------------------------------------------- */
static int wse_run_selftest(void)
{
    int total = 0, fails = 0;
    WseLuid luid;
    unsigned long sid;
    char buf[512];
    char *av[16];
    wchar_t wide[64];
    size_t i, j;

#define WSE_CHECK(cond, label) \
    do { total++; if (cond) { printf("ok   %s\n", label); } \
         else { fails++; printf("FAIL %s\n", label); } } while (0)

    /* --- privilege constant table [LookupPrivilegeValueA logic] --- */
    WSE_CHECK(wse_lookup_privilege("SeTcbPrivilege", &luid) == 1 &&
              luid.lo == 7ul && luid.hi == 0ul,
              "priv: SeTcbPrivilege -> {7,0} [0x403020]");
    WSE_CHECK(wse_lookup_privilege("SeDebugPrivilege", &luid) == 1 &&
              luid.lo == 20ul && luid.hi == 0ul,
              "priv: SeDebugPrivilege -> {20,0}");
    WSE_CHECK(wse_lookup_privilege("setcbprivilege", &luid) == 1 && luid.lo == 7ul,
              "priv: lookup is case-insensitive");
    WSE_CHECK(wse_lookup_privilege("SeNopePrivilege", &luid) == 0,
              "priv: unknown name rejected");
    WSE_CHECK(wse_lookup_privilege("", &luid) == 0, "priv: empty name rejected");
    WSE_CHECK(WSE_PRIV_COUNT >= 33, "priv: table size sane");
    {
        int uniq = 1, mono = 1;
        for (i = 0; i < WSE_PRIV_COUNT && uniq; i++) {
            for (j = i + 1; j < WSE_PRIV_COUNT; j++) {
                if (wse_ci_eq(WSE_PRIVILEGES[i].name, WSE_PRIVILEGES[j].name)) {
                    uniq = 0;
                    break;
                }
            }
            if (i > 0 && WSE_PRIVILEGES[i].luid.lo <= WSE_PRIVILEGES[i-1].luid.lo)
                mono = 0;
        }
        WSE_CHECK(uniq, "priv: no duplicate names");
        WSE_CHECK(mono, "priv: LUIDs strictly increasing");
    }

    /* --- session-number parse [0x00401278 sentinel] --- */
    WSE_CHECK(wse_parse_session("5", &sid) == 1 && sid == 5ul, "sess: \"5\" -> 5");
    WSE_CHECK(wse_parse_session("0", &sid) == 1 && sid == 0ul, "sess: \"0\" -> 0");
    WSE_CHECK(wse_parse_session("-1", &sid) == 1 && sid == WSE_SESSION_CONSOLE,
              "sess: \"-1\" -> console sentinel");
    WSE_CHECK(wse_parse_session("console", &sid) == 1 && sid == WSE_SESSION_CONSOLE,
              "sess: \"console\" -> sentinel");
    WSE_CHECK(wse_parse_session("CONSOLE", &sid) == 1, "sess: \"CONSOLE\" -> sentinel");
    WSE_CHECK(wse_parse_session("4294967295", &sid) == 1 && sid == 0xFFFFFFFFul,
              "sess: DWORD max accepted (== sentinel, as in binary)");
    WSE_CHECK(wse_parse_session("4294967296", &sid) == 0, "sess: overflow rejected");
    WSE_CHECK(wse_parse_session("12a", &sid) == 0, "sess: trailing junk rejected");
    WSE_CHECK(wse_parse_session(" 5", &sid) == 0, "sess: leading space rejected");
    WSE_CHECK(wse_parse_session("", &sid) == 0, "sess: empty rejected");

    /* --- argv plumbing [CRT quote rules / WinMain gate 0x401516] --- */
    WSE_CHECK(wse_cmdline_split("taskse.exe C:\\tmp\\dec.exe", buf, sizeof(buf),
                                av, 16) == 2 &&
              strcmp(av[1], "C:\\tmp\\dec.exe") == 0,
              "argv: plain two-token line");
    WSE_CHECK(wse_cmdline_split("taskse.exe \"C:\\Program Files\\@WanaDecryptor@.exe\"",
                                buf, sizeof(buf), av, 16) == 2 &&
              strcmp(av[1], "C:\\Program Files\\@WanaDecryptor@.exe") == 0,
              "argv: quoted path with spaces (real caller contract)");
    WSE_CHECK(wse_cmdline_split("a \"b  c\" d", buf, sizeof(buf), av, 16) == 3 &&
              strcmp(av[1], "b  c") == 0 && strcmp(av[2], "d") == 0,
              "argv: embedded spaces inside quotes");
    WSE_CHECK(wse_cmdline_split("\"C:\\dir\\\\\"", buf, sizeof(buf), av, 16) == 1 &&
              strcmp(av[0], "C:\\dir\\") == 0,
              "argv: 2 backslashes + quote = 1 backslash, close");
    WSE_CHECK(wse_cmdline_split("a\\\"b", buf, sizeof(buf), av, 16) == 1 &&
              strcmp(av[0], "a\"b") == 0,
              "argv: 1 backslash + quote = literal quote");
    WSE_CHECK(wse_cmdline_split("", buf, sizeof(buf), av, 16) == 0,
              "argv: empty line -> argc 0");
    WSE_CHECK(wse_cmdline_split("x y z w", buf, 6, av, 16) == -1,
              "argv: buffer overflow -> -1");

    /* --- wide-path handling [argv[1] -> lpApplicationName] --- */
    WSE_CHECK(wse_widen_path("C:\\a.exe", wide, 64) == 1 &&
              wcscmp(wide, L"C:\\a.exe") == 0,
              "wide: ANSI -> wchar path");
    WSE_CHECK(wse_widen_path("", wide, 64) == 0, "wide: empty rejected");
    WSE_CHECK(wse_widen_path("C:\\a-longer-path-than-cap", wide, 8) == 0,
              "wide: truncation rejected");
    WSE_CHECK(wse_is_absolute_path_w(L"C:\\x.exe") == 1, "wide: drive path absolute");
    WSE_CHECK(wse_is_absolute_path_w(L"\\\\srv\\share\\x.exe") == 1, "wide: UNC absolute");
    WSE_CHECK(wse_is_absolute_path_w(L"x.exe") == 0, "wide: bare name rejected");
    WSE_CHECK(wse_is_absolute_path_w(L"") == 0, "wide: empty rejected");
    WSE_CHECK(wse_is_absolute_path_w(L"1C:\\x") == 0, "wide: non-alpha drive rejected");

#undef WSE_CHECK

    printf("wse selftest: %d checks, %d failure(s)\n", total, fails);
    return fails == 0 ? 0 : 1;
}

#endif /* WSE_LOGIC_H */
