// wcry_types.h — shared fixed-width types for the decryptor reconstruction.
// Standalone (no <stdint.h>) so the tree compiles identically on mingw and
// native Linux (build/Makefile `make selftest`).
#ifndef WCRY_TYPES_H
#define WCRY_TYPES_H

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#endif // WCRY_TYPES_H
