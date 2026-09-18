// selftest_core.h — benign selftest suite (default no-arg behavior).
// Runs only in-memory checks; zero writes, zero network, zero registry.
// Returns 0 when every check passes.
#ifndef WCRY_SELFTEST_CORE_H
#define WCRY_SELFTEST_CORE_H

int wcry_run_selftests(void);

#endif // WCRY_SELFTEST_CORE_H
