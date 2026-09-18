// wcry_build.h — shared build policy for the reconstruction build tree.
// ENABLE_WEAPONIZED_PATHS is NEVER defined anywhere in this tree.
// See build/README.md. Keep this header tiny and stable.
#ifndef WCRY_BUILD_H
#define WCRY_BUILD_H

#ifdef ENABLE_WEAPONIZED_PATHS
#  error "ENABLE_WEAPONIZED_PATHS must not be defined. See build/README.md."
#endif

#define WCRY_STUBBED(name) printf("[stubbed: %s]\n", name)

#endif // WCRY_BUILD_H
