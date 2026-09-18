// weaponized_stubs.cpp — harmful-path entry points, dead by default.
//
// POLICY (build/README.md, non-negotiable): every body below is wrapped in
// #ifdef ENABLE_WEAPONIZED_PATHS / #else stub / #endif. wcry_build.h (included
// via -I../common) raises #error if ENABLE_WEAPONIZED_PATHS is ever defined,
// so the real bodies are unreachable BY CONSTRUCTION — only the printf stub
// branch can ever compile. No harmful IO exists in this object file.
#include <stdio.h>
#include "wcry_build.h"
#include "weaponized_stubs.h"

// FUN_004020a0 DecryptWncryFile — file decrypt/restore IO.
int stub_decrypt_file_io(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): pCreateFileW(src) + container parse +
       RsaCtxCryptDecrypt(dky|embedded) + CRijndaelCrypt CBC 1 MB chunk loop
       to dst + SetFileTime restore + type-3 tail-swap via SetFilePointer. */
#else
    WCRY_STUBBED("DecryptWncryFileIO (file decrypt/restore)");
#endif
    return 0;
}

// FUN_0040c240 tail — .dky private-key blob write.
int stub_dky_write(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): on resp[0]==0x07 && len>0, fopen(dky,"wb")
       + fwrite(resp+1, len-1) so the paid key persists for import. */
#else
    WCRY_STUBBED("WriteDkyFile (%08X.dky fwrite)");
#endif
    return 0;
}

// FUN_0040b840 EnsureTorRunning — Tor bootstrap.
int stub_tor_bootstrap(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): UnzipToDir("TaskData", s.wnry) / Download-
       AndUnzip fallbacks, tor.exe -> taskhsvc.exe CopyFileA, CreateProcessA
       CREATE_NO_WINDOW, waits 5 s then 30 s. */
#else
    WCRY_STUBBED("TorBootstrap (s.wnry unzip / taskhsvc launch)");
#endif
    return 0;
}

// FUN_0040d8c0 / FUN_0040ba60 — SOCKS5 + onion network IO.
int stub_socks_connect(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): socket()/connect() to 127.0.0.1:9050,
       SOCKS5 greeting/CONNECT exchange against g_onion, reply validation. */
#else
    WCRY_STUBBED("SocksConnect (payment-check network IO)");
#endif
    return 0;
}

// FUN_00402560 / FUN_00402252 tails — rename/delete passes.
int stub_file_rename_pass(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): on decrypt success pDeleteFileW(src) and
       pMoveFileW(target, src); on failure pDeleteFileW(target). */
#else
    WCRY_STUBBED("FileRenamePass (MoveFile/DeleteFile)");
#endif
    return 0;
}

// MFC42 dialog layer (function_map.md S6) — summarized out.
int stub_mfc_gui(void)
{
#ifdef ENABLE_WEAPONIZED_PATHS
    /* REAL BODY (never compiled): AfxWinMain -> InitInstance, dialogs 0x66/
       0x8a/0x8d/0x89, ransom-note rich-edit, payment/contact UI. */
#else
    WCRY_STUBBED("MfcGui (Wana Decrypt0r 2.0 dialog app)");
#endif
    return 0;
}
