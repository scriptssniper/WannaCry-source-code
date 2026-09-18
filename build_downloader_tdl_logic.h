// tdl_logic.h — taskdl.exe (tor-downloader binary = staged-file cleaner)
// portable logic, shared verbatim by the mingw build (taskdl.cpp) and the
// native selftest (selftest.cc) so both run the SAME checks.
//
// Ground truth: reconstruction/tor-downloader/{function_map.md, taskdl.cpp}
// (MD5 4fef5e34143e646dbf9907c4374276f5). The binary has NO network code —
// it sweeps drives Z:→C: and deletes *.WNCRYT under X:\$RECYCLE (or %TEMP%
// on the Windows drive), Sleep(10) per drive.
//
// REAL (unstubbed) logic per build/README.md:
//   - .WNCRYT extension matcher [search pattern "%s\*%s" @ 0x004010e9,
//     ext L".WNCRYT" @ 0x403050]
//   - per-drive scan-base decision [BuildScanBasePath 0x00401000]
//   - path building [FMT_DIR_PATTERN 0x403040, FMT_DIR_FILE 0x403034]
//   - drive sweep plan [WinMain 0x004012c0: GetLogicalDrives bit test,
//     DRIVE_REMOTE skip, idx 25→2]
//
// Everything is static and exercised by tdl_run_selftest() — no unused
// functions under -Wall -Wextra. NO deletion APIs live here (see taskdl.cpp).
#ifndef TDL_LOGIC_H
#define TDL_LOGIC_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define TDL_DRIVE_REMOTE 4u       /* GetDriveTypeW "network drive" [0x00401305] */
#define TDL_MAX_DRIVES   24       /* 'C'..'Z' — the sweep's reachable range    */

static const wchar_t TDL_STAGED_EXT[]   = L".WNCRYT";   /* 0x403050 */
static const wchar_t TDL_RECYCLE_DIR[]  = L"$RECYCLE";  /* 0x403020 */

/* -------------------------------------------------------------------------
 * .WNCRYT extension matcher — mirrors what the FindFirstFileW pattern
 * "<base>\*<ext>" matches: case-insensitive suffix ".WNCRYT" (NTFS pattern
 * matching semantics). 1 = match.
 * ---------------------------------------------------------------------- */
static int tdl_wncryt_match(const wchar_t *name)
{
    size_t nl, el, i;
    if (name == NULL)
        return 0;
    nl = wcslen(name);
    el = 7;  /* wcslen(L".WNCRYT") — fixed literal, no runtime dep */
    if (nl < el)
        return 0;
    {
        const wchar_t *tail = name + (nl - el);
        for (i = 0; i < el; i++) {
            wchar_t a = tail[i], b = TDL_STAGED_EXT[i];
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = (wchar_t)(b - L'A' + L'a');
            if (a != b)
                return 0;
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * Bounded wide append: writes s at out+*len, keeps NUL. 1 ok / 0 overflow.
 * (Replaces the binary's swprintf through IAT 0x40206C — format-free by
 * construction, so -Wformat can never disagree about %s/%C/%ls.)
 * ---------------------------------------------------------------------- */
static int tdl_wappend(wchar_t *out, size_t cap, size_t *len, const wchar_t *s)
{
    size_t sl = wcslen(s);
    if (*len + sl + 1 > cap)
        return 0;
    wmemcpy(out + *len, s, sl);
    *len += sl;
    out[*len] = L'\0';
    return 1;
}

/* [0x00401044] strip ONE trailing backslash (GetTempPathW always has one). */
static int tdl_copy_strip_trailing_bs(const wchar_t *src, wchar_t *out, size_t cap)
{
    size_t n = wcslen(src);
    if (n + 1 > cap)
        return 0;
    wmemcpy(out, src, n + 1);
    if (n > 0 && out[n - 1] == L'\\')
        out[n - 1] = L'\0';
    return 1;
}

/* -------------------------------------------------------------------------
 * [0x00401000] BuildScanBasePath — pure form. The API wrapper (taskdl.cpp)
 * feeds GetWindowsDirectoryW / GetTempPathW results; the decision is:
 *   Windows-dir drive == scanned drive -> %TEMP% lane (trailing '\' stripped;
 *     if the temp query failed the buffer still held the Windows dir — the
 *     binary keeps that as-is [0040103a jbe])
 *   otherwise -> "X:\$RECYCLE" [swprintf L"%C:\%s" @ 0040105e]
 * ---------------------------------------------------------------------- */
static int tdl_build_scan_base(int driveIdx, const wchar_t *winDir,
                               const wchar_t *tempPath,
                               wchar_t *out, size_t cap)
{
    size_t len = 0;
    out[0] = L'\0';

    if (winDir[0] != L'\0' && winDir[0] == (wchar_t)('A' + driveIdx)) {
        if (tempPath[0] != L'\0')
            return tdl_copy_strip_trailing_bs(tempPath, out, cap);
        /* GetTempPathW failure -> buffer keeps the Windows dir (faithful). */
        return tdl_copy_strip_trailing_bs(winDir, out, cap);
    }
    /* "X:\$RECYCLE" — mirrors swprintf(out, L"%C:\%s", 'A'+idx, L"$RECYCLE") */
    if (cap < 12)
        return 0;
    out[len++] = (wchar_t)('A' + driveIdx);
    out[len++] = L':';
    out[len++] = L'\\';
    if (!tdl_wappend(out, cap, &len, TDL_RECYCLE_DIR))
        return 0;
    return 1;
}

/* [FMT_DIR_PATTERN 0x403040] "<base>\*<ext>" */
static int tdl_build_pattern(const wchar_t *base, wchar_t *out, size_t cap)
{
    size_t len = 0;
    out[0] = L'\0';
    if (!tdl_wappend(out, cap, &len, base))    return 0;
    if (!tdl_wappend(out, cap, &len, L"\\*"))  return 0;
    if (!tdl_wappend(out, cap, &len, TDL_STAGED_EXT)) return 0;
    return 1;
}

/* [FMT_DIR_FILE 0x403034] "<base>\<name>" */
static int tdl_build_full_path(const wchar_t *base, const wchar_t *name,
                               wchar_t *out, size_t cap)
{
    size_t len = 0;
    out[0] = L'\0';
    if (!tdl_wappend(out, cap, &len, base))    return 0;
    if (!tdl_wappend(out, cap, &len, L"\\"))   return 0;
    if (!tdl_wappend(out, cap, &len, name))    return 0;
    return 1;
}

/* -------------------------------------------------------------------------
 * [0x004012c0] sweep plan — pure form of WinMain's drive loop:
 *   idx 25→2, keep only bits set in mask, skip DRIVE_REMOTE, in that order.
 * dtype[] must have 26 entries (index = drive letter - 'A'; absent drives
 * may carry any type — the bit test gates first).
 * ---------------------------------------------------------------------- */
typedef struct {
    int n;
    int idx[TDL_MAX_DRIVES];
} TdlSweepPlan;

static void tdl_plan_sweep(unsigned long mask, const unsigned char *dtype,
                           TdlSweepPlan *plan)
{
    int idx;
    plan->n = 0;
    for (idx = 25; idx >= 2; idx--) {                 /* [004012db..00401322] Z→C */
        if (((mask >> idx) & 1ul) == 0)               /* [004012f3] present?   */
            continue;
        if (dtype[idx] == TDL_DRIVE_REMOTE)           /* [00401305] skip net   */
            continue;
        plan->idx[plan->n++] = idx;
    }
}

/* -------------------------------------------------------------------------
 * Selftest — the exact benign no-arg run of taskdl.exe (build policy:
 * exit 0 on success, zero writes outside stdout).
 * ---------------------------------------------------------------------- */
static int tdl_run_selftest(void)
{
    int total = 0, fails = 0;
    wchar_t out[300];

#define TDL_CHECK(cond, label) \
    do { total++; if (cond) { printf("ok   %s\n", label); } \
         else { fails++; printf("FAIL %s\n", label); } } while (0)

    /* --- extension matcher [*<ext> pattern semantics] --- */
    TDL_CHECK(tdl_wncryt_match(L"00000000.wncryt") == 1, "ext: lowercase .wncryt");
    TDL_CHECK(tdl_wncryt_match(L"X.WNCRYT") == 1, "ext: exact case .WNCRYT");
    TDL_CHECK(tdl_wncryt_match(L".WNCRYT") == 1, "ext: bare .WNCRYT");
    TDL_CHECK(tdl_wncryt_match(L"WnCrYt") == 0, "ext: dotless near-name rejected");
    TDL_CHECK(tdl_wncryt_match(L"file.WNCRY") == 0, "ext: .WNCRY rejected");
    TDL_CHECK(tdl_wncryt_match(L"x.WNCRYTX") == 0, "ext: suffix not at end rejected");
    TDL_CHECK(tdl_wncryt_match(L"WNCRY") == 0, "ext: short name rejected");
    TDL_CHECK(tdl_wncryt_match(L"") == 0, "ext: empty rejected");
    TDL_CHECK(tdl_wncryt_match(L"readme.txt") == 0, "ext: unrelated rejected");

    /* --- scan-base decision [0x00401000] --- */
    TDL_CHECK(tdl_build_scan_base(2, L"C:\\Windows", L"C:\\Users\\u\\AppData\\Local\\Temp\\",
                                  out, 300) == 1 &&
              wcscmp(out, L"C:\\Users\\u\\AppData\\Local\\Temp") == 0,
              "base: Windows drive -> %TEMP% with trailing backslash stripped");
    TDL_CHECK(tdl_build_scan_base(2, L"C:\\Windows", L"C:\\Temp",
                                  out, 300) == 1 &&
              wcscmp(out, L"C:\\Temp") == 0,
              "base: %TEMP% without backslash kept as-is");
    TDL_CHECK(tdl_build_scan_base(2, L"C:\\Windows", L"",
                                  out, 300) == 1 &&
              wcscmp(out, L"C:\\Windows") == 0,
              "base: temp query failed -> buffer keeps Windows dir [0040103a]");
    TDL_CHECK(tdl_build_scan_base(25, L"C:\\Windows", L"C:\\Temp\\",
                                  out, 300) == 1 &&
              wcscmp(out, L"Z:\\$RECYCLE") == 0,
              "base: Z: -> Z:\\$RECYCLE");
    TDL_CHECK(tdl_build_scan_base(2, L"D:\\Windows", L"C:\\Temp\\",
                                  out, 300) == 1 &&
              wcscmp(out, L"C:\\$RECYCLE") == 0,
              "base: non-Windows drive -> X:\\$RECYCLE");
    TDL_CHECK(tdl_build_scan_base(3, L"C:\\Windows", L"C:\\Temp\\",
                                  out, 300) == 1 &&
              wcscmp(out, L"D:\\$RECYCLE") == 0,
              "base: D: -> D:\\$RECYCLE");
    TDL_CHECK(tdl_build_scan_base(2, L"C:\\Windows", L"C:\\Temp\\",
                                  out, 4) == 0,
              "base: capacity guard -> 0, no overflow");

    /* --- path building [0x403040 / 0x403034] --- */
    TDL_CHECK(tdl_build_pattern(L"C:\\$RECYCLE", out, 300) == 1 &&
              wcscmp(out, L"C:\\$RECYCLE\\*.WNCRYT") == 0,
              "pattern: <base>\\*.WNCRYT [FMT_DIR_PATTERN]");
    TDL_CHECK(tdl_build_full_path(L"C:\\$RECYCLE", L"0.wncryt", out, 300) == 1 &&
              wcscmp(out, L"C:\\$RECYCLE\\0.wncryt") == 0,
              "fullpath: <base>\\<name> [FMT_DIR_FILE]");
    TDL_CHECK(tdl_build_pattern(L"C:\\$RECYCLE", out, 10) == 0,
              "pattern: capacity guard -> 0");

    /* --- sweep plan [0x004012c0] --- */
    {
        unsigned char dtype[26];
        TdlSweepPlan plan;
        memset(dtype, 0, sizeof(dtype));
        dtype['C' - 'A'] = 3;   /* DRIVE_FIXED  */
        dtype['D' - 'A'] = 4;   /* DRIVE_REMOTE */
        dtype['Z' - 'A'] = 3;   /* DRIVE_FIXED  */
        tdl_plan_sweep((1ul << 2) | (1ul << 3) | (1ul << 25), dtype, &plan);
        TDL_CHECK(plan.n == 2 && plan.idx[0] == 25 && plan.idx[1] == 2,
                  "plan: Z→C order, remote D: skipped");
        memset(dtype, 0, sizeof(dtype));
        tdl_plan_sweep(0ul, dtype, &plan);
        TDL_CHECK(plan.n == 0, "plan: clear mask -> nothing swept");
        memset(dtype, 0, sizeof(dtype));
        dtype['C' - 'A'] = 4;
        tdl_plan_sweep(1ul << 2, dtype, &plan);
        TDL_CHECK(plan.n == 0, "plan: lone remote drive skipped");
        memset(dtype, 0, sizeof(dtype));
        dtype['C' - 'A'] = 2; dtype['Q' - 'A'] = 3; dtype['Z' - 'A'] = 5;
        tdl_plan_sweep((1ul << 2) | (1ul << 16) | (1ul << 25), dtype, &plan);
        TDL_CHECK(plan.n == 3 && plan.idx[0] == 25 && plan.idx[1] == 16 &&
                  plan.idx[2] == 2,
                  "plan: all drive types kept except REMOTE(4)");
    }

#undef TDL_CHECK

    printf("tdl selftest: %d checks, %d failure(s)\n", total, fails);
    return fails == 0 ? 0 : 1;
}

#endif /* TDL_LOGIC_H */
