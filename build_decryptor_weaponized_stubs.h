// weaponized_stubs.h — dead-by-default entry points for every harmful path
// of the original u.wnry (build/README.md WEAPONIZATION POLICY).
// Each stub compiles ONLY its stub body: wcry_build.h #errors the moment
// ENABLE_WEAPONIZED_PATHS is defined, so the guarded real bodies are
// unreachable by construction.
#ifndef WCRY_WEAPONIZED_STUBS_H
#define WCRY_WEAPONIZED_STUBS_H

// FUN_004020a0 body: open src, parse container, RSA-recover the AES key,
// AES-128-CBC 1 MB chunk decrypt to dst, type-3 tail-swap restore,
// SetFileTime restore. ALL file IO.
int stub_decrypt_file_io(void);

// FUN_0040c240 tail: fwrite server-returned PRIVATEKEYBLOB to "%08X.dky".
int stub_dky_write(void);

// FUN_0040b840: s.wnry unzip / URLDownload fallback, tor.exe->taskhsvc.exe
// copy, CreateProcessA CREATE_NO_WINDOW launch + waits.
int stub_tor_bootstrap(void);

// FUN_0040d8c0/FUN_0040ba60: TCP connect to 127.0.0.1:9050, SOCKS5 CONNECT
// through Tor to the onion; all payment-check network IO.
int stub_socks_connect(void);

// FUN_00402560 tail + FUN_00402252: MoveFileW/DeleteFileW passes that remove
// the encrypted original and rename the decrypted target back.
int stub_file_rename_pass(void);

// MFC42 dialog layer (function_map.md S6): AfxWinMain, dialogs 0x66/0x8a/
// 0x8d/0x89, message pumps. Summarized out of this reconstruction.
int stub_mfc_gui(void);

#endif // WCRY_WEAPONIZED_STUBS_H
