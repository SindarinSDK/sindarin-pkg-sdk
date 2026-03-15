/* ============================================================================
 * sdk/os/os.sn.c - Operating System Detection for Sindarin
 * ============================================================================
 * Minimal runtime version - no arena, uses strdup/malloc for allocations.
 * Platform detection functions using compile-time preprocessor checks.
 * ============================================================================ */

#include <stdlib.h>
#include <string.h>

/* Platform-specific includes for CPU count */
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
    #define SN_OS_WINDOWS 1
    #include <windows.h>
#else
    #include <unistd.h>
#endif

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
long long sn_os_is_windows(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Check if running on macOS (Darwin).
 * Returns 1 on macOS, 0 otherwise.
 */
long long sn_os_is_macos(void)
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
long long sn_os_is_linux(void)
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
long long sn_os_is_unix(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
    return 0;
#elif defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
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
 * Returns a strdup'd string: "Windows", "macOS", "Linux", or "Unknown".
 */
char *sn_os_name(void)
{
    const char *name;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
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

    return strdup(name);
}

/**
 * Get the number of logical CPU cores available.
 * Returns the number of processors/cores, or 1 if detection fails.
 */
long long sn_os_cpu_count(void)
{
#ifdef SN_OS_WINDOWS
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (long long)sysinfo.dwNumberOfProcessors;
#else
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) {
        return 1;  /* Fallback to 1 if detection fails */
    }
    return (long long)nprocs;
#endif
}
