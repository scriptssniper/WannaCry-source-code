# build/ — WannaCry reconstruction, build-ready tree

Derived 1:1 from `../reconstruction/` (validated, REVIEW.md per component).
Build gates: **every component compiles + links warning-free** under
`x86_64-w64-mingw32-g++` and `i686-w64-mingw32-g++` (see Makefile).

## WEAPONIZATION POLICY (non-negotiable)

This tree exists to prove the reconstruction is complete and correct — NOT to
produce a functioning ransomware. All harmful paths are dead by default:

```c
#include "common/wcry_build.h"   // defines ENABLE_WEAPONIZED_PATHS? NO — never defined
```

- File-encryption bodies, service install, registry persistence, SMB spread,
  DoublePulsar/exploit injection, Tor/payment networking, self-copy/deletion:
  wrapped in `#ifdef ENABLE_WEAPONIZED_PATHS` … `#else` stub (`return 0;`,
  `printf("[stubbed: %s]\n", __func__);`) … `#endif`.
- Exploit wire-byte blobs + DP shellcode remain **inert `const BYTE[]` data**
  (never written to any handle even in weaponized builds — they are reference
  data only, printed as length/MD5 in selftest).
- `--selftest` (default binary behavior with no args) runs benign checks only:
  AES-128 NIST vector, config parse, container-header parse on bundled test
  vectors, string tables, key-blob structure walk. Zero writes outside cwd.

`make` → all six components, both arches, zero warnings.
`make selftest` → Linux-native build of the selftest logic (runs on host, no wine needed).

## Components

| Dir | Source recon | Binary equivalent |
|---|---|---|
| `dropper/` | ../reconstruction/dropper | WannaCry.exe (ed01eb… installer) |
| `launcher/` | ../reconstruction/launcher | taskse.exe |
| `downloader/` | ../reconstruction/tor-downloader | taskdl.exe (staging cleaner) |
| `encryptor/` | ../reconstruction/encryptor | wcry_payload.dll (TaskStart) |
| `decryptor/` | ../reconstruction/decryptor | u.wnry → @WanaDecryptor@.exe |
| `worm/` | ../reconstruction/spreader | mssecsvc.exe (db349b97…) — **spread-research scope**: SMB protocol layer + MS17-010 probe/fingerprint + orchestration logic; exploit primitive + payload-drop linkage intentionally excised (payload linkage removed per operator directive 2026-09-18; wire-byte blobs live only in `../references/`) |
