/* ==============================================================================
 * sdk/path.sn.c - Self-contained Path Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses strdup/malloc for string returns.
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

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static int is_path_separator(char c)
{
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

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

static int is_absolute_path(const char *path)
{
    if (path == NULL || *path == '\0') return 0;

#ifdef _WIN32
    if (strlen(path) >= 3 && path[1] == ':' && is_path_separator(path[2])) {
        return 1;
    }
    if (strlen(path) >= 2 && is_path_separator(path[0]) && is_path_separator(path[1])) {
        return 1;
    }
#endif
    return is_path_separator(path[0]);
}

/* Helper: strndup (not available everywhere) */
static char *sn_strndup(const char *str, size_t n)
{
    char *result = (char *)malloc(n + 1);
    if (result == NULL) return NULL;
    memcpy(result, str, n);
    result[n] = '\0';
    return result;
}

/* ============================================================================
 * Path Manipulation Functions
 * ============================================================================ */

char *sn_path_directory(char *path)
{
    if (path == NULL || *path == '\0') {
        return strdup(".");
    }

    const char *last_sep = find_last_separator(path);
    if (last_sep == NULL) {
        return strdup(".");
    }

    if (last_sep == path) {
        return strdup("/");
    }

#ifdef _WIN32
    if (last_sep == path + 2 && path[1] == ':') {
        char buf[4];
        buf[0] = path[0];
        buf[1] = ':';
        buf[2] = '/';
        buf[3] = '\0';
        return strdup(buf);
    }
#endif

    size_t dir_len = last_sep - path;
    return sn_strndup(path, dir_len);
}

char *sn_path_filename(char *path)
{
    if (path == NULL || *path == '\0') {
        return strdup("");
    }

    const char *last_sep = find_last_separator(path);
    if (last_sep == NULL) {
        return strdup(path);
    }

    return strdup(last_sep + 1);
}

char *sn_path_extension(char *path)
{
    if (path == NULL || *path == '\0') {
        return strdup("");
    }

    const char *last_sep = find_last_separator(path);
    const char *filename = last_sep ? last_sep + 1 : path;

    const char *last_dot = NULL;
    for (const char *p = filename; *p; p++) {
        if (*p == '.') {
            last_dot = p;
        }
    }

    if (last_dot == NULL || last_dot == filename) {
        return strdup("");
    }

    return strdup(last_dot + 1);
}

char *sn_path_join2(char *path1, char *path2)
{
    if (path1 == NULL) path1 = "";
    if (path2 == NULL) path2 = "";

    size_t len1 = strlen(path1);
    size_t len2 = strlen(path2);

    if (len2 > 0 && is_path_separator(path2[0])) {
        return strdup(path2);
    }
#ifdef _WIN32
    if (len2 > 2 && path2[1] == ':' && is_path_separator(path2[2])) {
        return strdup(path2);
    }
#endif

    if (len1 == 0) {
        return strdup(path2);
    }

    int has_trailing_sep = is_path_separator(path1[len1 - 1]);
    size_t result_len = len1 + (has_trailing_sep ? 0 : 1) + len2 + 1;
    char *buf = (char *)malloc(result_len);
    if (buf == NULL) {
        fprintf(stderr, "sn_path_join2: allocation failed\n");
        exit(1);
    }

    memcpy(buf, path1, len1);
    size_t pos = len1;
    if (!has_trailing_sep) {
        buf[pos++] = '/';
    }
    memcpy(buf + pos, path2, len2);
    buf[pos + len2] = '\0';

    return buf;
}

char *sn_path_join3(char *path1, char *path2, char *path3)
{
    char *temp = sn_path_join2(path1, path2);
    char *result = sn_path_join2(temp, path3);
    free(temp);
    return result;
}

char *sn_path_join_all(SnArray *parts)
{
    long long count = sn_array_length(parts);

    if (count == 0) {
        return strdup("");
    }

    char **data = (char **)parts->data;

    if (count == 1) {
        return strdup(data[0]);
    }

    char *result = strdup(data[0]);

    for (long long i = 1; i < count; i++) {
        char *new_result = sn_path_join2(result, data[i]);
        free(result);
        result = new_result;
    }

    return result;
}

char *sn_path_absolute(char *path)
{
    if (path == NULL || *path == '\0') {
        char cwd[4096];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            return strdup(cwd);
        }
        return strdup(".");
    }

#ifdef _WIN32
    char resolved[PATH_MAX];
    if (_fullpath(resolved, path, PATH_MAX) != NULL) {
        return strdup(resolved);
    }
#else
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL) {
        return strdup(resolved);
    }
#endif

    if (is_absolute_path(path)) {
        return strdup(path);
    }

    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        return sn_path_join2(cwd, path);
    }

    return strdup(path);
}

/* ============================================================================
 * Path Query Functions
 * ============================================================================ */

long long sn_path_exists(char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    return stat(path, &st) == 0;
}

long long sn_path_is_file(char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

long long sn_path_is_directory(char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}
