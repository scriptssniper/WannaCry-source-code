// selftest_main.cpp — console entry point for the build-ready decryptor
// reconstruction (build/README.md component `decryptor`).
//
// Binary equivalent: u.wnry -> @WanaDecryptor@.exe (MD5 7bf2b57f2a205768755c07f
// 238fb32cc). The original is a VC6/MFC42 GUI dialog app ("Wana Decrypt0r 2.0");
// per the recon scope the MFC GUI layer is SUMMARIZED OUT — this deliverable is
// the console selftest binary proving the reconstructed core logic.
//
// No-arg run = benign selftest, exit 0. All harmful paths (file decrypt IO,
// .dky writes, Tor bootstrap, socket connects, rename/delete passes, MFC UI)
// are stubbed — see weaponized_stubs.cpp and build/README.md policy.
//
// Build (from build/decryptor/):
//   x86_64-w64-mingw32-g++ -Wall -Wextra -I../common -O1 *.cpp -o wdecryptor.exe
#include "wcry_build.h"
#include "selftest_core.h"
#include <stdio.h>

int main(void)
{
    printf("wdecryptor 0.1 — WannaCry decryptor reconstruction (research artifact)\n");
    printf("core: u.wnry @WanaDecryptor@.exe | policy: build/README.md\n");
    printf("running benign selftest (in-memory only, no writes outside cwd)...\n");
    return wcry_run_selftests();
}
