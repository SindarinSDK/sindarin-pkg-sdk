/* ============================================================================
 * sdk/os/os.sn.c - Operating System Detection for Sindarin
 * ============================================================================
 * Platform detection functions using compile-time preprocessor checks.
 * These functions are resolved at compile time on the target platform.
 * ============================================================================ */

#include <stdlib.h>
#include <string.h>
#include "runtime/runtime_arena.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/runtime_string_h.h"

/* ============================================================================
 * Platform Detection Functions
 * ============================================================================
 * These functions return 1 (true) or 0 (false) based on compile-time checks.
 * No runtime overhead - the compiler optimizes these to constant values.
 * ============================================================================ */

/**
 * Check if running on Windows.
 * Returns 1 on Windows (any version), 0 otherwise.
 */
int sn_os_is_windows(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Check if running on macOS (Darwin).
 * Returns 1 on macOS, 0 otherwise.
 */
int sn_os_is_macos(void)
{
#if defined(__APPLE__) && defined(__MACH__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Check if running on Linux.
 * Returns 1 on Linux, 0 otherwise.
 */
int sn_os_is_linux(void)
{
#if defined(__linux__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Check if running on a Unix-like system.
 * Returns 1 on Linux, macOS, BSD, etc. Returns 0 on Windows.
 */
int sn_os_is_unix(void)
{
#if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    return 1;
#else
    return 0;
#endif
}

/* ============================================================================
 * Platform Information Functions
 * ============================================================================ */

/**
 * Get the name of the current operating system.
 * Returns a string: "Windows", "macOS", "Linux", or "Unknown".
 */
RtHandle sn_os_name(RtManagedArena *arena)
{
    const char *name;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    name = "Windows";
#elif defined(__APPLE__) && defined(__MACH__)
    name = "macOS";
#elif defined(__linux__)
    name = "Linux";
#elif defined(__FreeBSD__)
    name = "FreeBSD";
#elif defined(__OpenBSD__)
    name = "OpenBSD";
#elif defined(__NetBSD__)
    name = "NetBSD";
#else
    name = "Unknown";
#endif

    return rt_managed_strdup(arena, RT_HANDLE_NULL, name);
}
