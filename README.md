# WannaCry Source Code Reconstruction

Educational reverse-engineering reconstruction of the major WannaCry components, derived from analysis of the original Windows binaries. The project is intended for malware-analysis, incident-response, and defensive research—not for operating ransomware or reproducing a working worm.

> **Safety notice:** Do not build or execute the reconstructed malware components on a live system or network. Use an isolated, disposable analysis environment and follow your organization’s malware-research procedures.

## Scope

The repository covers the main components associated with the WannaCry execution chain:

- **Dropper / installer** — `dropper.cpp`
  - Selects a working directory and installs the payload as a Windows service.
  - Extracts the embedded toolkit and decrypts `t.wnry` in memory.
  - Uses a small in-memory PE loader to locate and invoke the payload’s `TaskStart` export.

- **Encryption payload** — `wcry_payload_dll.cpp`
  - Reconstructs RSA key setup and AES-CBC file-encryption behavior.
  - Models the staged `.WNCYR` and finalized `.WNCRY` file passes.
  - Documents persistence, ransom-note/UI launching, drive traversal, and payment-key polling.

- **Decryptor** — `decryptor.cpp`
  - Reconstructs RSA key-pair validation and the `WANACRY!` encrypted-file container format.
  - Includes AES-128-CBC decryption logic, free-decrypt handling, file traversal, and the original Tor/SOCKS/C2 protocol model.
  - The GUI layer is only summarized; it is not a complete MFC application.

- **Worm / spreader** — `worm.cpp`
  - Documents the killswitch, service lifecycle, SMB/MS17-010 detection, target acquisition, and DoublePulsar/EternalBlue orchestration.
  - Exploit and payload data are treated as inert reference material in the research build.

- **Supporting utilities**
  - `taskse.cpp` launches the decryptor in interactive user sessions.
  - `taskdl.cpp` removes leftover `.WNCRYT` staging files.

## Safety-oriented build layer

The `build_*` files provide smaller, testable, and more portable pieces of the reconstruction:

- `build_decryptor_aes128.cpp` — auditable AES-128 and CBC implementation.
- `build_decryptor_c2_protocol.cpp` — pure checksum, SOCKS5, rolling-XOR, and C2 frame builders; no socket or network I/O.
- `build_dropper_dropper_core.h` — portable parsing, constants, container-layout checks, and deterministic helper logic.
- `build_worm_worm_recon.h` — host-portable MS17-010 detection and lifecycle research harness with stub transport.
- `build_decryptor_weaponized_stubs.cpp` — explicit stubs for harmful file, network, Tor, rename, and GUI paths.
- `build_common_wcry_build.h` — shared build policy that rejects `ENABLE_WEAPONIZED_PATHS`.

`BUILD_POLICY.md` is the authoritative description of the safe-build policy. In particular, harmful paths are intended to remain disabled, exploit wire data is inert reference data, and self-tests should perform only benign parsing and cryptographic checks.

## Repository layout

```text
dropper.cpp                              Dropper / installer reconstruction
wcry_payload_dll.cpp                     Encryptor payload reconstruction
decryptor.cpp                             Decryptor and C2 reconstruction
worm.cpp                                  Worm / spreader reconstruction
taskse.cpp                                Interactive-session launcher
taskdl.cpp                                Staging-file cleanup utility

build_common_wcry_build.h                Safe-build policy header
build_dropper_dropper_core.h             Portable dropper logic
build_decryptor_aes128.cpp               AES-128 implementation
build_decryptor_c2_protocol.cpp          Pure C2/SOCKS5 frame logic
build_decryptor_weaponized_stubs.cpp     Harmful-path stubs
build_worm_worm_recon.h                  Safe worm research harness
BUILD_POLICY.md                          Build and safety policy
```

## Build status and limitations

This is a reconstruction and research codebase, not an original WannaCry source release. Some files are annotated renderings, pseudocode, or intentionally incomplete approximations of binary behavior. The GUI, embedded resources, exploit data, and some third-party/library portions are summarized or omitted.

The documented safe build targets MinGW-w64 cross-compilers for Windows and a native self-test build where available. The repository currently does not include a standard `README.md`-backed package manager configuration; consult `BUILD_POLICY.md` and the source comments for the intended build arrangement.

Do not assume that a successful compilation implies behavioral or forensic equivalence to the original binaries.

## Research topics

This repository is useful for studying:

- PE loading and in-memory module reconstruction
- Windows CryptoAPI RSA key blobs and AES-128-CBC
- WannaCry’s `WANACRY!` file-container format
- Multi-pass ransomware file staging
- Windows services, persistence, and interactive-session launching
- SMB protocol identification and MS17-010 fingerprinting
- Tor/SOCKS5-based malware C2 protocol structures
- Translating binary-analysis findings into portable self-tests

## Responsible use

Use this material only for authorized research, detection engineering, malware analysis, education, and incident response. Keep all experiments isolated, avoid real victims and production networks, and do not add or enable weaponized functionality.

## License

No license information is currently documented in the repository. Unless a license is added, standard copyright restrictions apply to the repository contents.
