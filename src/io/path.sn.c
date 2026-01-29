/* ==============================================================================
 * sdk/path.sn.c - Self-contained Path Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnPath type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#ifdef _WIN32
    #if defined(__MINGW32__) || defined(__MINGW64__)
    #include <sys/stat.h>
    #include <unistd.h>
    #else
    #include <sys/stat.h>
    #include <direct.h>
    #define getcwd _getcwd
    #ifndef PATH_MAX
    #define PATH_MAX _MAX_PATH
    #endif
    #endif
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Include runtime arena for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/runtime_array.h"
#include "runtime/arena/managed_arena.h"

/* ============================================================================
 * Path Type Definition (unused, just for namespace)
 * ============================================================================ */

typedef struct RtSnPath {
    int32_t _unused;
} RtSnPath;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Check if character is a path separator */
static int is_path_separator(char c)
{
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

/* Find the last path separator in a string */
static const char *find_last_separator(const char *path)
{
    const char *last = NULL;
    for (const char *p = path; *p; p++) {
        if (is_path_separator(*p)) {
            last = p;
        }
    }
    return last;
}

/* Check if a path is absolute */
static int is_absolute_path(const char *path)
{
    if (path == NULL || *path == '\0') return 0;

#ifdef _WIN32
    /* Windows: absolute if starts with drive letter (e.g., C:\) or UNC path (\\server) */
    if (strlen(path) >= 3 && path[1] == ':' && is_path_separator(path[2])) {
        return 1;  /* Drive letter path */
    }
    if (strlen(path) >= 2 && is_path_separator(path[0]) && is_path_separator(path[1])) {
        return 1;  /* UNC path */
    }
#endif
    /* Unix style: absolute if starts with / */
    return is_path_separator(path[0]);
}

/* ============================================================================
 * Path Manipulation Functions
 * ============================================================================ */

/* Extract directory portion of a path */
RtHandle sn_path_directory(RtManagedArena *arena, const char *path)
{
    if (path == NULL || *path == '\0') {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, ".");
    }

    const char *last_sep = find_last_separator(path);
    if (last_sep == NULL) {
        /* No separator found - return current directory */
        return rt_managed_strdup(arena, RT_HANDLE_NULL, ".");
    }

    /* Handle root path (/ or C:\) */
    if (last_sep == path) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "/");
    }

#ifdef _WIN32
    /* Handle Windows drive letter like C:\ */
    if (last_sep == path + 2 && path[1] == ':') {
        char buf[4];
        buf[0] = path[0];
        buf[1] = ':';
        buf[2] = '/';
        buf[3] = '\0';
        return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
    }
#endif

    /* Return everything up to (not including) the last separator */
    size_t dir_len = last_sep - path;
    return rt_managed_strndup(arena, RT_HANDLE_NULL, path, dir_len);
}

/* Extract filename (with extension) from a path */
RtHandle sn_path_filename(RtManagedArena *arena, const char *path)
{
    if (path == NULL || *path == '\0') {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    const char *last_sep = find_last_separator(path);
    if (last_sep == NULL) {
        /* No separator - the whole thing is the filename */
        return rt_managed_strdup(arena, RT_HANDLE_NULL, path);
    }

    /* Return everything after the last separator */
    return rt_managed_strdup(arena, RT_HANDLE_NULL, last_sep + 1);
}

/* Extract file extension (without dot) from a path */
RtHandle sn_path_extension(RtManagedArena *arena, const char *path)
{
    if (path == NULL || *path == '\0') {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    /* Get just the filename part first */
    const char *last_sep = find_last_separator(path);
    const char *filename = last_sep ? last_sep + 1 : path;

    /* Find the last dot in the filename */
    const char *last_dot = NULL;
    for (const char *p = filename; *p; p++) {
        if (*p == '.') {
            last_dot = p;
        }
    }

    /* No dot, or dot is at start (hidden file like .bashrc) */
    if (last_dot == NULL || last_dot == filename) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    /* Return extension without the dot */
    return rt_managed_strdup(arena, RT_HANDLE_NULL, last_dot + 1);
}

/* Join two path components */
RtHandle sn_path_join2(RtManagedArena *arena, const char *path1, const char *path2)
{
    if (path1 == NULL) path1 = "";
    if (path2 == NULL) path2 = "";

    size_t len1 = strlen(path1);
    size_t len2 = strlen(path2);

    /* If path2 is absolute, return it directly */
    if (len2 > 0 && is_path_separator(path2[0])) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, path2);
    }
#ifdef _WIN32
    /* Check for Windows absolute path like C:\ */
    if (len2 > 2 && path2[1] == ':' && is_path_separator(path2[2])) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, path2);
    }
#endif

    /* If path1 is empty, return path2 */
    if (len1 == 0) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, path2);
    }

    /* Check if path1 already ends with separator */
    int has_trailing_sep = is_path_separator(path1[len1 - 1]);

    /* Allocate: path1 + optional separator + path2 + null */
    size_t result_len = len1 + (has_trailing_sep ? 0 : 1) + len2 + 1;
    char *buf = (char *)malloc(result_len);
    if (buf == NULL) {
        fprintf(stderr, "sn_path_join2: allocation failed\n");
        exit(1);
    }

    memcpy(buf, path1, len1);
    size_t pos = len1;
    if (!has_trailing_sep) {
        buf[pos++] = '/';  /* Always use forward slash for consistency */
    }
    memcpy(buf + pos, path2, len2);
    buf[pos + len2] = '\0';

    RtHandle h = rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
    free(buf);
    return h;
}

/* Join three path components */
RtHandle sn_path_join3(RtManagedArena *arena, const char *path1, const char *path2, const char *path3)
{
    /* First join path1 and path2 */
    RtHandle temp_h = sn_path_join2(arena, path1, path2);

    /* Pin to get pointer for second join */
    char *temp = rt_managed_pin_str(arena, temp_h);

    /* Join temp with path3 */
    RtHandle result = sn_path_join2(arena, temp, path3);

    rt_managed_unpin(arena, temp_h);

    /* Mark temp as dead since we don't need it anymore */
    rt_managed_mark_dead(arena, temp_h);

    return result;
}

/* Join an array of path components (parts is a Sindarin str[] array) */
RtHandle sn_path_join_all(RtManagedArena *arena, char **parts)
{
    /* Get array length */
    size_t count = rt_array_length(parts);

    if (count == 0) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    if (count == 1) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, parts[0]);
    }

    /* Start with the first element */
    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, parts[0]);

    /* Join each subsequent part */
    for (size_t i = 1; i < count; i++) {
        char *current = rt_managed_pin_str(arena, result);

        RtHandle new_result = sn_path_join2(arena, current, parts[i]);

        rt_managed_unpin(arena, result);
        rt_managed_mark_dead(arena, result);

        result = new_result;
    }

    return result;
}

/* Resolve a path to its absolute form */
RtHandle sn_path_absolute(RtManagedArena *arena, const char *path)
{
    if (path == NULL || *path == '\0') {
        /* Empty path - return current working directory */
        char cwd[4096];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            return rt_managed_strdup(arena, RT_HANDLE_NULL, cwd);
        }
        /* Fallback if getcwd fails */
        return rt_managed_strdup(arena, RT_HANDLE_NULL, ".");
    }

#ifdef _WIN32
    char resolved[PATH_MAX];
    if (_fullpath(resolved, path, PATH_MAX) != NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, resolved);
    }
#else
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, resolved);
    }
#endif

    /* realpath/_fullpath fails if path doesn't exist - try to resolve manually */
    if (is_absolute_path(path)) {
        /* Already absolute */
        return rt_managed_strdup(arena, RT_HANDLE_NULL, path);
    }

    /* Prepend current working directory */
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        return sn_path_join2(arena, cwd, path);
    }

    /* Fallback - return as-is */
    return rt_managed_strdup(arena, RT_HANDLE_NULL, path);
}

/* ============================================================================
 * Path Query Functions
 * ============================================================================ */

/* Check if a path exists */
int sn_path_exists(const char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    return stat(path, &st) == 0;
}

/* Check if a path points to a regular file */
int sn_path_is_file(const char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

/* Check if a path points to a directory */
int sn_path_is_directory(const char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}
